import pike.crypto as crypto
import pike.ntstatus as ntstatus
import pike.nttime as nttime
import pike.smb2 as smb2
from pike import StateError
from pike.core import Future
from open import Open
from tree import Tree

import array
import contextlib
import random


class Channel(object):
    def __init__(self, connection, session, signing_key):
        object.__init__(self)
        self.connection = connection
        self.session = session
        self.signing_key = signing_key

    def cancel_request(self, future):
        if (future.response is not None):
            raise StateError("Cannot cancel completed request")

        smb_req = self.request()
        cancel_req = smb2.Cancel(smb_req)

        # Don't bother trying to sign cancel
        smb_req.flags &= ~smb2.SMB2_FLAGS_SIGNED

        # Use async id to cancel if applicable:
        if future.interim_response is not None:
            smb_req.async_id = future.interim_response.async_id
            smb_req.tree_id = None
            smb_req.flags |= smb2.SMB2_FLAGS_ASYNC_COMMAND
            smb_req.message_id = 0
        else:
            smb_req.message_id = future.request.message_id

        return cancel_req

    def cancel(self, future):
        cancel_req = self.cancel_request(future)
        return self.connection.submit(cancel_req.parent.parent)[0]

    def tree_connect_request(self, path):
        smb_req = self.request()
        neg_dialect = self.connection.negotiate_response.dialect_revision
        if neg_dialect >= smb2.DIALECT_SMB3_1_1:
            smb_req.flags |= smb2.SMB2_FLAGS_SIGNED
        tree_req = smb2.TreeConnectRequest(smb_req)
        tree_req.path = "\\\\" + self.connection.server + "\\" + path
        return tree_req

    def tree_connect_submit(self, tree_req):
        tree_future = Future()
        resp_future = self.connection.submit(tree_req.parent.parent)[0]
        resp_future.then(lambda f: tree_future.complete(Tree(self.session,
                                                             tree_req.path,
                                                             f.result())))
        return tree_future

    def tree_connect(self, path):
        return self.tree_connect_submit(
                self.tree_connect_request(
                    path)).result()

    def tree_disconnect_request(self, tree):
        smb_req = self.request(obj=tree)
        tree_req = smb2.TreeDisconnectRequest(smb_req)
        return tree_req

    def tree_disconnect(self, tree):
        return self.connection.transceive(
                self.tree_disconnect_request(tree).parent.parent)[0]

    def logoff_request(self):
        smb_req = self.request()
        logoff_req = smb2.LogoffRequest(smb_req)
        return logoff_req

    def logoff_submit(self, logoff_req):
        def logoff_finish(f):
            for channel in self.session._channels.itervalues():
                del channel.connection._sessions[self.session.session_id]
        logoff_future = self.connection.submit(logoff_req.parent.parent)[0]
        logoff_future.then(logoff_finish)
        return logoff_future

    def logoff(self):
        return self.logoff_submit(
                self.logoff_request()).result()

    def create_request(
            self,
            tree,
            path,
            access=smb2.GENERIC_READ | smb2.GENERIC_WRITE,
            attributes=smb2.FILE_ATTRIBUTE_NORMAL,
            share=0,
            disposition=smb2.FILE_OPEN_IF,
            options=0,
            maximal_access=None,
            oplock_level=smb2.SMB2_OPLOCK_LEVEL_NONE,
            lease_key=None,
            lease_state=None,
            durable=False,
            persistent=False,
            create_guid=None,
            app_instance_id=None,
            query_on_disk_id=False,
            extended_attributes=None,
            timewarp=None):

        prev_open = None

        smb_req = self.request(obj=tree)
        create_req = smb2.CreateRequest(smb_req)

        create_req.name = path
        create_req.desired_access = access
        create_req.file_attributes = attributes
        create_req.share_access = share
        create_req.create_disposition = disposition
        create_req.create_options = options
        create_req.requested_oplock_level = oplock_level

        if maximal_access:
            max_req = smb2.MaximalAccessRequest(create_req)
            if maximal_access is not True:
                max_req.timestamp = maximal_access

        if oplock_level == smb2.SMB2_OPLOCK_LEVEL_LEASE:
            lease_req = smb2.LeaseRequest(create_req)
            lease_req.lease_key = lease_key
            lease_req.lease_state = lease_state

        if isinstance(durable, Open):
            prev_open = durable
            if durable.durable_timeout is None:
                durable_req = smb2.DurableHandleReconnectRequest(create_req)
                durable_req.file_id = durable.file_id
            else:
                durable_req = smb2.DurableHandleReconnectV2Request(create_req)
                durable_req.file_id = durable.file_id
                durable_req.create_guid = durable.create_guid
                durable_req.flags = durable.durable_flags
        elif durable is True:
            durable_req = smb2.DurableHandleRequest(create_req)
        elif durable is not False:
            durable_req = smb2.DurableHandleV2Request(create_req)
            durable_req.timeout = durable
            if persistent:
                durable_req.flags = smb2.SMB2_DHANDLE_FLAG_PERSISTENT
            if create_guid is None:
                create_guid = array.array(
                        'B',
                        map(random.randint, [0]*16, [255]*16))
            durable_req.create_guid = create_guid

        if app_instance_id:
            app_instance_id_req = smb2.AppInstanceIdRequest(create_req)
            app_instance_id_req.app_instance_id = app_instance_id

        if query_on_disk_id:
            smb2.QueryOnDiskIDRequest(create_req)

        if extended_attributes:
            ext_attr_len = len(extended_attributes.keys())
            for name, value in extended_attributes.iteritems():
                ext_attr = smb2.ExtendedAttributeRequest(create_req)
                if ext_attr_len == 1:
                    next_entry_offset = 0
                else:
                    next_entry_offset = 10 + len(name) + len(value)
                ext_attr.next_entry_offset = next_entry_offset
                ext_attr.ea_name = name
                ext_attr.ea_name_length = len(name)
                ext_attr.ea_value = value
                ext_attr.ea_value_length = len(value)
                ext_attr_len = ext_attr_len - 1

        if timewarp:
            timewarp_req = smb2.TimewarpTokenRequest(create_req)
            timewarp_req.timestamp = nttime.NtTime(timewarp)

        open_future = Future(None)

        def finish(f):
            with open_future: open_future(
                    Open(
                        tree,
                        f.result(),
                        create_guid=create_guid,
                        prev=prev_open))
        create_req.open_future = open_future
        create_req.finish = finish

        return create_req

    def create_submit(self, create_req):
        open_future = create_req.open_future
        open_future.request_future = self.connection.submit(
                create_req.parent.parent)[0]
        open_future.request_future.then(create_req.finish)

        return open_future

    def create(
            self,
            tree,
            path,
            access=smb2.GENERIC_READ | smb2.GENERIC_WRITE,
            attributes=smb2.FILE_ATTRIBUTE_NORMAL,
            share=0,
            disposition=smb2.FILE_OPEN_IF,
            options=0,
            maximal_access=None,
            oplock_level=smb2.SMB2_OPLOCK_LEVEL_NONE,
            lease_key=None,
            lease_state=None,
            durable=False,
            persistent=False,
            create_guid=None,
            app_instance_id=None,
            query_on_disk_id=False,
            extended_attributes=None,
            timewarp=None):
        return self.create_submit(self.create_request(
                tree,
                path,
                access,
                attributes,
                share,
                disposition,
                options,
                maximal_access,
                oplock_level,
                lease_key,
                lease_state,
                durable,
                persistent,
                create_guid,
                app_instance_id,
                query_on_disk_id,
                extended_attributes,
                timewarp))

    def close_request(self, handle):
        smb_req = self.request(obj=handle)
        close_req = smb2.CloseRequest(smb_req)

        close_req.file_id = handle.file_id
        close_req.handle = handle
        return close_req

    def close_submit(self, close_req):
        resp_future = self.connection.submit(close_req.parent.parent)[0]
        resp_future.then(lambda f: close_req.handle.dispose())
        return resp_future

    def close(self, handle):
        return self.close_submit(
                self.close_request(handle)).result()

    def query_directory_request(
            self,
            handle,
            file_information_class=smb2.FILE_DIRECTORY_INFORMATION,
            flags=0,
            file_index=0,
            file_name='*',
            output_buffer_length=8192):
        smb_req = self.request(obj=handle)
        enum_req = smb2.QueryDirectoryRequest(smb_req)
        enum_req.file_id = handle.file_id
        enum_req.file_name = file_name
        enum_req.output_buffer_length = output_buffer_length
        enum_req.file_information_class = file_information_class
        enum_req.flags = flags
        enum_req.file_index = file_index
        return enum_req

    def query_directory(self,
                        handle,
                        file_information_class=smb2.FILE_DIRECTORY_INFORMATION,
                        flags=0,
                        file_index=0,
                        file_name='*',
                        output_buffer_length=8192):
        return self.connection.transceive(
                self.query_directory_request(
                    handle,
                    file_information_class,
                    flags,
                    file_index,
                    file_name,
                    output_buffer_length).parent.parent)[0][0]

    def enum_directory(self,
                       handle,
                       file_information_class=smb2.FILE_DIRECTORY_INFORMATION,
                       file_name='*',
                       output_buffer_length=8192):
        while True:
            try:
                for info in self.query_directory(
                        handle,
                        file_information_class=file_information_class,
                        file_name=file_name,
                        output_buffer_length=output_buffer_length):
                    yield info
            except smb2.ResponseError as e:
                if e.response.status == ntstatus.STATUS_NO_MORE_FILES:
                    return
                else:
                    raise

    def query_file_info_request(
            self,
            create_res,
            file_information_class=smb2.FILE_BASIC_INFORMATION,
            info_type=smb2.SMB2_0_INFO_FILE,
            output_buffer_length=4096,
            additional_information=None):
        smb_req = self.request(obj=create_res)
        query_req = smb2.QueryInfoRequest(smb_req)

        query_req.info_type = info_type
        query_req.file_information_class = file_information_class
        query_req.file_id = create_res.file_id
        query_req.output_buffer_length = output_buffer_length
        if additional_information:
            query_req.additional_information = additional_information
        return query_req

    def query_file_info(self,
                        create_res,
                        file_information_class=smb2.FILE_BASIC_INFORMATION,
                        info_type=smb2.SMB2_0_INFO_FILE,
                        output_buffer_length=4096,
                        additional_information=None):
        return self.connection.transceive(
                self.query_file_info_request(
                    create_res,
                    file_information_class,
                    info_type,
                    output_buffer_length,
                    additional_information).parent.parent)[0][0][0]

    def set_file_info_request(
            self,
            handle,
            file_information_class=smb2.FILE_BASIC_INFORMATION,
            info_type=smb2.SMB2_0_INFO_FILE,
            input_buffer_length=4096,
            additional_information=None):
        smb_req = self.request(obj=handle)
        set_req = smb2.SetInfoRequest(smb_req)
        set_req.file_id = handle.file_id
        set_req.file_information_class = file_information_class
        set_req.info_type = info_type
        set_req.input_buffer_length = input_buffer_length
        if additional_information:
            set_req.additional_information = additional_information
        return set_req

    @contextlib.contextmanager
    def set_file_info(self, handle, cls):
        info_type = file_information_class = None
        if hasattr(cls, "info_type"):
            info_type = cls.info_type
        if hasattr(cls, "file_information_class"):
            file_information_class = cls.file_information_class
        set_req = self.set_file_info_request(
                handle,
                file_information_class,
                info_type)
        yield cls(set_req)
        self.connection.transceive(set_req.parent.parent)[0]

    def change_notify_request(
            self,
            handle,
            completion_filter=smb2.SMB2_NOTIFY_CHANGE_CREATION,
            flags=0,
            buffer_length=4096):
        smb_req = self.request(obj=handle)
        cnotify_req = smb2.ChangeNotifyRequest(smb_req)
        cnotify_req.file_id = handle.file_id
        cnotify_req.buffer_length = buffer_length
        cnotify_req.flags = flags
        return cnotify_req

    def change_notify(
            self,
            handle,
            completion_filter=smb2.SMB2_NOTIFY_CHANGE_CREATION,
            flags=0,
            buffer_length=4096):
        return self.connection.submit(
                self.change_notify_request(
                    handle,
                    completion_filter,
                    flags,
                    buffer_length=4096).parent.parent)[0][0]

    def echo_request(self):
        smb_req = self.request()
        return smb2.EchoRequest(smb_req)

    def echo(self):
        self.connection.transceive(self.echo_request().parent.parent)[0][0]

    def flush_request(self, file):
        smb_req = self.request(obj=file)
        flush_req = smb2.FlushRequest(smb_req)
        flush_req.file_id = file.file_id
        return flush_req

    def flush(self, file):
        self.connection.transceive(self.flush_request(file).parent.parent)

    def read_request(
            self,
            file,
            length,
            offset,
            minimum_count=0,
            remaining_bytes=0):
        smb_req = self.request(obj=file)
        read_req = smb2.ReadRequest(smb_req)

        read_req.length = length
        read_req.offset = offset
        read_req.minimum_count = minimum_count
        read_req.remaining_bytes = remaining_bytes
        read_req.file_id = file.file_id
        return read_req

    def read(
            self,
            file,
            length,
            offset,
            minimum_count=0,
            remaining_bytes=0):
        return self.connection.transceive(
                self.read_request(
                    file,
                    length,
                    offset,
                    minimum_count,
                    remaining_bytes).parent.parent)[0][0].data

    def write_request(
            self,
            file,
            offset,
            buffer=None,
            remaining_bytes=0,
            flags=0):
        smb_req = self.request(obj=file)
        write_req = smb2.WriteRequest(smb_req)

        write_req.offset = offset
        write_req.file_id = file.file_id
        write_req.buffer = buffer
        write_req.remaining_bytes = remaining_bytes
        write_req.flags = flags
        return write_req

    def write(self,
              file,
              offset,
              buffer=None,
              remaining_bytes=0,
              flags=0):
        smb_res = self.connection.transceive(
                self.write_request(
                    file,
                    offset,
                    buffer,
                    remaining_bytes,
                    flags).parent.parent)

        return smb_res[0][0].count

    def lock_request(self, handle, locks, sequence=0):
        """
        create a L{LockRequest} packet

        @type handle: L{Open}
        @param handle: the file handle to lock
        @type locks: list of 3-tuples
        @param locks: each element of the list should be a 3-tuple of
            (offset, length, flags).
        @type sequence: integer
        @param sequence: lock sequence number
        """
        smb_req = self.request(obj=handle)
        lock_req = smb2.LockRequest(smb_req)

        lock_req.file_id = handle.file_id
        lock_req.locks = locks
        lock_req.lock_sequence = sequence
        return lock_req

    def lock(self, handle, locks, sequence=0):
        """
        send a L{LockRequest} and wait for the response

        
        @type handle: L{Open}
        @param handle: the file handle to lock
        @type locks: list of 3-tuples
        @param locks: each element of the list should be a 3-tuple of
            (offset, length, flags).
        @type sequence: integer
        @param sequence: lock sequence number
        """
        return self.connection.submit(
                self.lock_request(
                    handle,
                    locks,
                    sequence).parent.parent)[0]

    def validate_negotiate_info(self, tree):
        smb_req = self.request(obj=tree)
        ioctl_req = smb2.IoctlRequest(smb_req)
        vni_req = smb2.ValidateNegotiateInfoRequest(ioctl_req)
        client = self.session.client

        # Validate negotiate must always be signed
        smb_req.flags |= smb2.SMB2_FLAGS_SIGNED
        ioctl_req.flags = smb2.SMB2_0_IOCTL_IS_FSCTL
        vni_req.capabilities = client.capabilities
        vni_req.client_guid = client.client_guid
        vni_req.security_mode = client.security_mode
        vni_req.dialects = client.dialects

        res = self.connection.transceive(smb_req.parent)[0]

        return res

    def resume_key(self, file):
        smb_req = self.request(obj=file.tree)
        ioctl_req = smb2.IoctlRequest(smb_req)
        smb2.RequestResumeKeyRequest(ioctl_req)

        ioctl_req.file_id = file.file_id
        ioctl_req.flags |= smb2.SMB2_0_IOCTL_IS_FSCTL

        return self.connection.transceive(smb_req.parent)[0]

    def copychunk_request(self, source_file, target_file, chunks):
        """
        @param source_file: L{Open}
        @param target_file: L{Open}
        @param chunks: sequence of tuples (source_offset, target_offset, length)
        """
        resume_key = self.resume_key(source_file)[0][0].resume_key

        smb_req = self.request(obj=target_file.tree)
        ioctl_req = smb2.IoctlRequest(smb_req)
        copychunk_req = smb2.CopyChunkCopyRequest(ioctl_req)

        ioctl_req.max_output_response = 16384
        ioctl_req.file_id = target_file.file_id
        ioctl_req.flags |= smb2.SMB2_0_IOCTL_IS_FSCTL
        copychunk_req.source_key = resume_key
        copychunk_req.chunk_count = len(chunks)

        for source_offset, target_offset, length in chunks:
            chunk = smb2.CopyChunk(copychunk_req)
            chunk.source_offset = source_offset
            chunk.target_offset = target_offset
            chunk.length = length
        return ioctl_req

    def copychunk(self, source_file, target_file, chunks):
        """
        @param source_file: L{Open}
        @param target_file: L{Open}
        @param chunks: sequence of tuples (source_offset, target_offset, length)
        """
        return self.connection.transceive(
                self.copychunk_request(
                    source_file,
                    target_file,
                    chunks).parent.parent)[0]

    def set_symlink_request(self, file, target_name, flags):
        smb_req = self.request(obj=file.tree)
        ioctl_req = smb2.IoctlRequest(smb_req)
        set_reparse_req = smb2.SetReparsePointRequest(ioctl_req)
        symlink_buffer = smb2.SymbolicLinkReparseBuffer(set_reparse_req)

        ioctl_req.max_output_response = 0
        ioctl_req.file_id = file.file_id
        ioctl_req.flags |= smb2.SMB2_0_IOCTL_IS_FSCTL
        symlink_buffer.substitute_name = target_name
        symlink_buffer.flags = flags
        return ioctl_req

    def set_symlink(self, file, target_name, flags):
        return self.connection.transceive(
                self.set_symlink_request(
                    file,
                    target_name,
                    flags).parent.parent)[0]

    def get_symlink_request(self, file):
        smb_req = self.request(obj=file.tree)
        ioctl_req = smb2.IoctlRequest(smb_req)
        smb2.GetReparsePointRequest(ioctl_req)

        ioctl_req.file_id = file.file_id
        ioctl_req.flags |= smb2.SMB2_0_IOCTL_IS_FSCTL
        return ioctl_req

    def get_symlink(self, file):
        return self.connection.transceive(
                self.get_symlink_request(file).parent.parent)[0]

    def enumerate_snapshots_request(self, fh, max_output_response=16384):
        smb_req = self.request(obj=fh.tree)
        ioctl_req = smb2.IoctlRequest(smb_req)
        ioctl_req.max_output_response = max_output_response
        ioctl_req.file_id = fh.file_id
        ioctl_req.flags |= smb2.SMB2_0_IOCTL_IS_FSCTL
        enum_req = smb2.EnumerateSnapshotsRequest(ioctl_req)
        return enum_req

    def enumerate_snapshots(self, fh):
        return self.connection.transceive(
                self.enumerate_snapshots_request(fh).parent.parent.parent)[0]

    def enumerate_snapshots_list(self, fh):
        return self.enumerate_snapshots(fh)[0][0].snapshots

    def lease_break_acknowledgement(self, tree, notify):
        """
        @param tree: L{Tree} which the lease is taken against
        @param notify: L{Smb2} frame containing a LeaseBreakRequest
        return a LeaseBreakAcknowledgement with some fields pre-populated
        """
        lease_break = notify[0]
        smb_req = self.request(obj=tree)
        ack_req = smb2.LeaseBreakAcknowledgement(smb_req)
        ack_req.lease_key = lease_break.lease_key
        ack_req.lease_state = lease_break.new_lease_state
        return ack_req

    def oplock_break_acknowledgement(self, fh, notify):
        """
        @param fh: Acknowledge break on this L{Open}
        @param notify: L{Smb2} frame containing a OplockBreakRequest
        return a OplockBreakAcknowledgement with some fields pre-populated
        """
        oplock_break = notify[0]
        smb_req = self.request(obj=fh)
        ack_req = smb2.OplockBreakAcknowledgement(smb_req)
        ack_req.file_id = oplock_break.file_id
        ack_req.oplock_level = oplock_break.oplock_level
        return ack_req

    def frame(self):
        return self.connection.frame()

    def request(self, nb=None, obj=None, encrypt_data=None):
        smb_req = self.connection.request(nb)
        smb_req.session_id = self.session.session_id

        if isinstance(obj, Tree):
            smb_req.tree_id = obj.tree_id
        elif isinstance(obj, Open):
            smb_req.tree_id = obj.tree.tree_id

        # encryption unspecified, follow session/tree negotiation
        if encrypt_data is None:
            encrypt_data = self.session.encrypt_data
            if isinstance(obj, Tree):
                encrypt_data |= obj.encrypt_data
            elif isinstance(obj, Open):
                encrypt_data |= obj.tree.encrypt_data

        # a packet is either encrypted or signed
        if encrypt_data and self.session.encryption_context is not None:
            transform = crypto.TransformHeader(smb_req.parent)
            transform.encryption_context = self.session.encryption_context
            transform.session_id = self.session.session_id
        elif self.connection.negotiate_response.security_mode & smb2.SMB2_NEGOTIATE_SIGNING_REQUIRED or \
           self.connection.client.security_mode & smb2.SMB2_NEGOTIATE_SIGNING_REQUIRED:
            smb_req.flags |= smb2.SMB2_FLAGS_SIGNED

        return smb_req

    def let(self, **kwargs):
        return self.connection.let(**kwargs)
