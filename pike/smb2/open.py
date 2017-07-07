import pike.smb2 as smb2


class Open(object):
    def __init__(self, tree, smb_res, create_guid=None, prev=None):
        object.__init__(self)

        self.create_response = smb_res[0]

        self.tree = tree
        self.file_id = self.create_response.file_id
        self.oplock_level = self.create_response.oplock_level
        self.lease = None
        self.durable_timeout = None
        self.durable_flags = None
        self.create_guid = create_guid

        if prev is not None:
            self.durable_timeout = prev.durable_timeout
            self.durable_flags = prev.durable_flags

        if self.oplock_level != smb2.SMB2_OPLOCK_LEVEL_NONE:
            if self.oplock_level == smb2.SMB2_OPLOCK_LEVEL_LEASE:
                lease_res = filter(
                        lambda c: isinstance(c, smb2.LeaseResponse),
                        self.create_response)[0]
                self.lease = tree.session.client.lease(tree, lease_res)
            else:
                self.arm_oplock_future()

        durable_v2_res = filter(
                lambda c: isinstance(c, smb2.DurableHandleV2Response),
                self.create_response)
        if durable_v2_res != []:
            self.durable_timeout = durable_v2_res[0].timeout
            self.durable_flags = durable_v2_res[0].flags

    def arm_oplock_future(self):
        """
        (Re)arm the oplock future for this open. This function should be called
        when an oplock changes level to anything except SMB2_OPLOCK_LEVEL_NONE
        """
        self.oplock_future = self.tree.session.client.oplock_break_future(
                self.file_id)

    def on_oplock_break(self, cb):
        """
        Simple oplock break callback handler.
        @param cb: callable taking 1 parameter: the break request oplock level
                   should return the desired oplock level to break to
        """
        def simple_handle_break(op, smb_res, cb_ctx):
            """
            note that op is not used in this callback,
            since it already closes over self
            """
            notify = smb_res[0]
            if self.oplock_level != smb2.SMB2_OPLOCK_LEVEL_II:
                chan = self.tree.session.first_channel()
                ack = chan.oplock_break_acknowledgement(self, smb_res)
                ack.oplock_level = cb(notify.oplock_level)
                ack_res = chan.connection.transceive(ack.parent.parent)[0][0]
                if ack.oplock_level != smb2.SMB2_OPLOCK_LEVEL_NONE:
                    self.arm_oplock_future()
                    self.on_oplock_break(cb)
                self.oplock_level = ack_res.oplock_level
            else:
                self.oplock_level = notify.oplock_level
        self.on_oplock_break_request(simple_handle_break)

    def on_oplock_break_request(self, cb, cb_ctx=None):
        """
        Complex oplock break callback handler.
        @param cb: callable taking 3 parameters:
                        L{Open}
                        L{Smb2} containing the break request
                        L{object} arbitrary context
                   should handle breaking the oplock in some way
                   callback is also responsible for re-arming the future
                   and updating the oplock_level (if changed)
        """
        def handle_break(f):
            smb_res = f.result()
            cb(self, smb_res, cb_ctx)
        self.oplock_future.then(handle_break)

    def dispose(self):
        self.tree = None
        if self.lease is not None:
            self.lease.dispose()
            self.lease = None
