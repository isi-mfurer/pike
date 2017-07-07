import pike.core as core
import pike.crypto as crypto
import pike.digest as digest
import pike.netbios as netbios
import pike.ntstatus as ntstatus
import pike.smb2 as smb2
import pike.transport as transport
from pike.core import Events, Future
from session import SessionSetupContext

import array
import contextlib
import random
import socket
import struct
import sys

Events.import_items(globals())
default_credit_request = 10
trace = False


class Connection(transport.Transport):
    """
    Connection to server.

    Represents a connection to a server and handles all socket operations
    and request/response dispatch.

    @type client: Client
    @ivar client: The Client object associated with this connection.
    @ivar server: The server name or address
    @ivar port: The server port
    """
    def __init__(self, client, server, port=445):
        """
        Constructor.

        This should generally not be used directly.  Instead,
        use L{Client.connect}().
        """
        super(Connection, self).__init__()
        self._no_delay = True
        self._in_buffer = array.array('B')
        self._watermark = 4
        self._out_buffer = None
        self._next_mid = 0
        self._mid_blacklist = set()
        self._out_queue = []
        self._future_map = {}
        self._sessions = {}
        self._binding = None
        self._binding_key = None
        self._settings = {}
        self._pre_auth_integrity_hash = array.array('B', "\0"*64)
        self.callbacks = {}
        self.connection_future = Future()
        self.credits = 0
        self.client = client
        self.server = server
        self.port = port
        self.remote_addr = None
        self.local_addr = None
        self.verify_signature = True

        self.error = None
        self.traceback = None

    def establish(self):
        for result in socket.getaddrinfo(self.server, self.port,
                                         0,
                                         socket.SOCK_STREAM,
                                         socket.IPPROTO_TCP):
            family, socktype, proto, canonname, sockaddr = result
            break
        self.create_socket(family, socktype)
        self.connect(sockaddr)
        return self

    @contextlib.contextmanager
    def callback(self, event, cb):
        """
        Register a callback function for the context block, then unregister it
        """
        self.register_callback(event, cb)
        try:
            yield
        finally:
            self.unregister_callback(event, cb)

    def register_callback(self, event, cb):
        """
        Registers a callback function, cb for the given event.
        When the event fires, cb will be called with the relevant top-level
        Netbios frame as the single paramter.
        """
        ev = Events(event)
        if ev not in self.callbacks:
            self.callbacks[ev] = []
        self.callbacks[ev].append(cb)

    def unregister_callback(self, event, cb):
        """
        Unregisters a callback function, cb for the given event.
        """
        ev = Events(event)
        if ev not in self.callbacks:
            return
        if cb not in self.callbacks[ev]:
            return
        self.callbacks[ev].remove(cb)

    def process_callbacks(self, event, obj):
        """
        Fire callbacks for the given event, passing obj as the parameter

        Connection-specific callbacks will be fired first, followed by client
        callbacks
        """
        ev = Events(event)
        all_callbacks = [self.callbacks]
        if hasattr(self.client, "callbacks"):
            all_callbacks.append(self.client.callbacks)
        for callbacks in all_callbacks:
            if ev not in callbacks:
                continue
            for cb in callbacks[ev]:
                cb(obj)

    def smb3_pa_integrity(self, packet, data=None):
        """ perform smb3 pre-auth integrity hash update if needed """
        if smb2.DIALECT_SMB3_1_1 not in self.client.dialects:
            # hash only applies if client requests 3.1.1
            return
        neg_resp = getattr(self, "negotiate_response", None)
        if (neg_resp is not None and
            neg_resp.dialect_revision < smb2.DIALECT_SMB3_1_1):
            # hash only applies if server negotiates 3.1.1
            return
        if packet[0].__class__ not in [smb2.NegotiateRequest,
                                       smb2.NegotiateResponse,
                                       smb2.SessionSetupRequest,
                                       smb2.SessionSetupResponse]:
            # hash only applies to pre-auth messages
            return
        if (packet[0].__class__ == smb2.SessionSetupResponse and
            packet.status == ntstatus.STATUS_SUCCESS):
            # last session setup doesn't count in hash
            return
        if data is None:
            data = packet.serialize()
        self._pre_auth_integrity_hash = digest.smb3_sha512(
                self._pre_auth_integrity_hash +
                data)

    def next_mid_range(self, length):
        """
        multicredit requests must reserve 1 message id per credit charged.
        the message id of the request should be the first id of the range.
        """
        if length < 1:
            length = 1
        start_range = self._next_mid
        while True:
            r = set(range(start_range, start_range+length))
            if not r.intersection(self._mid_blacklist):
                break
            start_range += 1
        self._next_mid = sorted(list(r))[-1] + 1
        return start_range

    def next_mid(self):
        return self.next_range(1)

    def reserve_mid(self, mid):
        self._mid_blacklist.add(mid)

    def handle_connect(self):
        self.client._connections.append(self)
        with self.connection_future:
            self.local_addr = self.socket.getsockname()
            self.remote_addr = self.socket.getpeername()

            self.client.logger.debug('connect: %s/%s -> %s/%s',
                                     self.local_addr[0], self.local_addr[1],
                                     self.remote_addr[0], self.remote_addr[1])
        self.connection_future(self)

    def handle_read(self):
        # Try to read the next netbios frame
        remaining = self._watermark - len(self._in_buffer)
        self.process_callbacks(EV_RES_PRE_RECV, remaining)
        data = array.array('B', self.recv(remaining))
        self.process_callbacks(EV_RES_POST_RECV, data)
        self._in_buffer.extend(data)
        avail = len(self._in_buffer)
        if avail >= 4:
            self._watermark = 4 + struct.unpack('>L', self._in_buffer[0:4])[0]
        if avail == self._watermark:
            nb = self.frame()
            self.process_callbacks(EV_RES_PRE_DESERIALIZE, self._in_buffer)
            nb.parse(self._in_buffer)
            self._in_buffer = array.array('B')
            self._watermark = 4
            self._dispatch_incoming(nb)

    def handle_write(self):
        # Try to write out more data
        while self._out_buffer is None and len(self._out_queue):
            self._out_buffer = self._prepare_outgoing()
            while self._out_buffer is not None:
                self.process_callbacks(EV_REQ_PRE_SEND, self._out_buffer)
                sent = self.send(self._out_buffer)
                del self._out_buffer[:sent]
                if len(self._out_buffer) == 0:
                    self._out_buffer = None
                self.process_callbacks(EV_REQ_POST_SEND, sent)

    def handle_close(self):
        self.close()

    def handle_error(self):
        (_, self.error, self.traceback) = sys.exc_info()
        self.close()

    def close(self):
        """
        Close connection.

        This unceremoniously terminates the connection and fails all
        outstanding requests with EOFError.
        """
        # If there is no error, propagate EOFError
        if self.error is None:
            self.error = EOFError("close")

        # if the connection hasn't been established, raise the error
        if self.connection_future.response is None:
            self.connection_future(self.error)

        # otherwise, ignore this connection since it's not associated with its client
        if self not in self.client._connections:
            return

        super(Connection, self).close()

        if self.remote_addr is not None:
            self.client.logger.debug("disconnect (%s/%s -> %s/%s): %s",
                                     self.local_addr[0], self.local_addr[1],
                                     self.remote_addr[0], self.remote_addr[1],
                                     self.error)

        self.client._connections.remove(self)

        for future in self._out_queue:
            future.complete(self.error, self.traceback)
        del self._out_queue[:]

        for future in self._future_map.itervalues():
            future.complete(self.error, self.traceback)
        self._future_map.clear()

        for session in self._sessions.values():
            session.delchannel(self)

        self.traceback = None

    def _prepare_outgoing(self):
        # Try to prepare an outgoing packet

        # Grab an outgoing smb2 request
        future = self._out_queue[0]

        result = None
        with future:
            req = future.request
            self.process_callbacks(EV_REQ_PRE_SERIALIZE, req.parent)

            if req.credit_charge is None:
                req.credit_charge = 0
                for cmd in req:
                    if isinstance(cmd, smb2.ReadRequest) and cmd.length > 0:
                        # special handling, 1 credit per 64k
                        req.credit_charge, remainder = divmod(cmd.length, 2**16)
                    elif isinstance(cmd, smb2.WriteRequest) and cmd.buffer is not None:
                        # special handling, 1 credit per 64k
                        if cmd.length is None:
                            cmd.length = len(cmd.buffer)
                        req.credit_charge, remainder = divmod(cmd.length, 2**16)
                    else:
                        remainder = 1       # assume 1 credit per command
                    if remainder > 0:
                        req.credit_charge += 1
            # do credit accounting based on our calculations (MS-SMB2 3.2.5.1)
            self.credits -= req.credit_charge

            if req.credit_request is None:
                req.credit_request = default_credit_request
                if req.credit_charge > req.credit_request:
                    req.credit_request = req.credit_charge      # try not to fall behind

            del self._out_queue[0]

            # Assign message id
            if req.message_id is None:
                req.message_id = self.next_mid_range(req.credit_charge)

            if req.is_last_child():
                # Last command in chain, ready to send packet
                # TODO: move smb pa integrity to callback
                self.smb3_pa_integrity(req)
                result = req.parent.serialize()
                self.process_callbacks(EV_REQ_POST_SERIALIZE, req.parent)
                if trace:
                    self.client.logger.debug('send (%s/%s -> %s/%s): %s',
                                             self.local_addr[0], self.local_addr[1],
                                             self.remote_addr[0], self.remote_addr[1],
                                             req.parent)
                else:
                    self.client.logger.debug('send (%s/%s -> %s/%s): %s',
                                             self.local_addr[0], self.local_addr[1],
                                             self.remote_addr[0], self.remote_addr[1],
                                             ', '.join(f[0].__class__.__name__ for f in req.parent))
            else:
                # Not ready to send chain
                result = None

            # Move it to map for response waiters (but not cancel)
            if not isinstance(req[0], smb2.Cancel):
                self._future_map[req.message_id] = future

        return result

    def _find_oplock_future(self, file_id):
        if file_id in self.client._oplock_break_map:
            return self.client._oplock_break_map.pop(file_id)
        return None

    def _find_lease_future(self, lease_key):
        lease_key = lease_key.tostring()
        if lease_key in self.client._lease_break_map:
            return self.client._lease_break_map.pop(lease_key)
        return None

    def _dispatch_incoming(self, res):
        if trace:
            self.client.logger.debug('recv (%s/%s -> %s/%s): %s',
                                     self.remote_addr[0], self.remote_addr[1],
                                     self.local_addr[0], self.local_addr[1],
                                     res)
        else:
            self.client.logger.debug('recv (%s/%s -> %s/%s): %s',
                                     self.remote_addr[0], self.remote_addr[1],
                                     self.local_addr[0], self.local_addr[1],
                                     ', '.join(f[0].__class__.__name__ for f in res))
        self.process_callbacks(EV_RES_POST_DESERIALIZE, res)
        for smb_res in res:
            # TODO: move smb pa integrity and credit tracking to callbacks
            self.smb3_pa_integrity(smb_res, smb_res.parent.buf[4:])
            self.credits += smb_res.credit_response

            # Verify non-session-setup-response signatures
            # session setup responses are verified in SessionSetupContext
            if not isinstance(smb_res[0], smb2.SessionSetupResponse):
                key = self.signing_key(smb_res.session_id)
                if key and self.verify_signature:
                    smb_res.verify(self.signing_digest(), key)

            if smb_res.message_id == smb2.UNSOLICITED_MESSAGE_ID:
                if isinstance(smb_res[0], smb2.OplockBreakNotification):
                    future = self._find_oplock_future(smb_res[0].file_id)
                    if future:
                        future.complete(smb_res)
                    else:
                        self.client._oplock_break_queue.append(smb_res)
                elif isinstance(smb_res[0], smb2.LeaseBreakNotification):
                    future = self._find_lease_future(smb_res[0].lease_key)
                    if future:
                        future.complete(smb_res)
                    else:
                        self.client._lease_break_queue.append(smb_res)
                else:
                    raise core.BadPacket()
            elif smb_res.message_id in self._future_map:
                future = self._future_map[smb_res.message_id]
                if smb_res.status == ntstatus.STATUS_PENDING:
                    future.interim(smb_res)
                elif isinstance(smb_res[0], smb2.ErrorResponse) or \
                     smb_res.status not in smb_res[0].allowed_status:
                    future.complete(smb2.ResponseError(smb_res))
                    del self._future_map[smb_res.message_id]
                else:
                    future.complete(smb_res)
                    del self._future_map[smb_res.message_id]

    def submit(self, req):
        """
        Submit request.

        Submits a L{netbios.Netbios} frame for sending.  Returns
        a list of L{Future} objects, one for each corresponding
        L{smb2.Smb2} frame in the request.
        """
        if self.error is not None:
            raise self.error, None, self.traceback
        futures = []
        for smb_req in req:
            if isinstance(smb_req[0], smb2.Cancel):
                # Find original future being canceled to return
                if smb_req.async_id is not None:
                    # Cancel by async ID
                    future = filter(lambda f: f.interim_response.async_id == smb_req.async_id, self._future_map.itervalues())[0]
                elif smb_req.message_id in self._future_map:
                    # Cancel by message id, already in future map
                    future = self._future_map[smb_req.message_id]
                else:
                    # Cancel by message id, still in send queue
                    future = filter(lambda f: f.request.message_id == smb_req.message_id, self._out_queue)[0]
                # Add fake future for cancel since cancel has no response
                self._out_queue.append(Future(smb_req))
                futures.append(future)
            else:
                future = Future(smb_req)
                self._out_queue.append(future)
                futures.append(future)

        # don't wait for the callback, send the data now
        if self._no_delay:
            self.handle_write()
        return futures

    def transceive(self, req):
        """
        Submit request and wait for responses.

        Submits a L{netbios.Netbios} frame for sending.  Waits for
        and returns a list of L{smb2.Smb2} response objects, one for each
        corresponding L{smb2.Smb2} frame in the request.
        """
        return map(Future.result, self.submit(req))

    def negotiate_request(self, hash_algorithms=None, salt=None, ciphers=None):
        smb_req = self.request()
        smb_req.credit_charge = 0       # negotiate requests are free
        neg_req = smb2.NegotiateRequest(smb_req)

        neg_req.dialects = self.client.dialects
        neg_req.security_mode = self.client.security_mode
        neg_req.capabilities = self.client.capabilities
        neg_req.client_guid = self.client.client_guid

        if smb2.DIALECT_SMB3_1_1 in neg_req.dialects:
            if ciphers is None:
                ciphers = [crypto.SMB2_AES_128_GCM,
                           crypto.SMB2_AES_128_CCM]
            if ciphers:
                encryption_req = crypto.EncryptionCapabilitiesRequest(neg_req)
                encryption_req.ciphers = ciphers

            preauth_integrity_req = smb2.PreauthIntegrityCapabilitiesRequest(neg_req)
            if hash_algorithms is None:
                hash_algorithms = [smb2.SMB2_SHA_512]
            preauth_integrity_req.hash_algorithms = hash_algorithms
            if salt is not None:
                preauth_integrity_req.salt = salt
            else:
                preauth_integrity_req.salt = array.array('B',
                    map(random.randint, [0]*32, [255]*32))
        return neg_req

    def negotiate_submit(self, negotiate_request):
        negotiate_future = self.submit(negotiate_request.parent.parent)[0]
        def assign_response(f):
            self.negotiate_response = f.result()[0]
        negotiate_future.then(assign_response)
        return negotiate_future

    def negotiate(self, hash_algorithms=None, salt=None, ciphers=None):
        """
        Perform dialect negotiation.

        This must be performed before setting up a session with
        L{Connection.session_setup}().
        """
        self.negotiate_submit(
                self.negotiate_request(
                    hash_algorithms,
                    salt,
                    ciphers
        )).result()
        return self

    def session_setup(self, creds=None, bind=None, resume=None):
        """
        Establish a session.

        Establishes a session, performing GSS rounds as necessary.  Returns
        a L{Channel} object which can be used for further requests on the given
        connection and session.

        @type creds: str
        @param creds: A set of credentials of the form '<domain>\<user>%<password>'.
                      If specified, NTLM authentication will be used.  If None,
                      Kerberos authentication will be attempted.
        @type bind: L{Session}
        @param bind: An existing session to bind.
        @type resume: L{Session}
        @param resume: An previous session to resume.
        """
        session_context = SessionSetupContext(self, creds, bind, resume)
        return session_context.submit().result()

    # Return a fresh netbios frame with connection as context
    def frame(self):
        return netbios.Netbios(context=self)

    # Return a fresh smb2 frame with connection as context
    # Put it in a netbios frame automatically if none given
    def request(self, parent=None):
        if parent is None:
            parent = self.frame()
        req = smb2.Smb2(parent, context=self)
        req.channel_sequence = self.client.channel_sequence

        for (attr,value) in self._settings.iteritems():
            setattr(req, attr, value)

        return req

    def let(self, **kwargs):
        return core.Let(self, kwargs)

    #
    # SMB2 context upcalls
    #
    def session(self, session_id):
        return self._sessions.get(session_id, None)

    def signing_key(self, session_id):
        if session_id in self._sessions:
            session = self._sessions[session_id]
            channel = session._channels[id(self)]
            return channel.signing_key
        elif self._binding and self._binding.session_id == session_id:
            return self._binding_key

    def encryption_context(self, session_id):
        if session_id in self._sessions:
            session = self._sessions[session_id]
            return session.encryption_context

    def signing_digest(self):
        assert self.negotiate_response is not None
        if self.negotiate_response.dialect_revision >= smb2.DIALECT_SMB3_0:
            return digest.aes128_cmac
        else:
            return digest.sha256_hmac

    def get_request(self, message_id):
        if message_id in self._future_map:
            return self._future_map[message_id].request
        else:
            return None
