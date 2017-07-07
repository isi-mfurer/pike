import pike.smb2 as smb2


class Lease(object):
    def __init__(self, tree):
        self.tree = tree
        self.refs = 1
        self.future = None

    def update(self, lease_res):
        self.lease_key = lease_res.lease_key
        self.lease_state = lease_res.lease_state
        if self.future is None:
            self.arm_future()

    def arm_future(self):
        """
        (Re)arm the lease future for this Lease. This function should be called
        when a lease changes state to anything other than SMB2_LEASE_NONE
        """
        self.future = self.tree.session.client.lease_break_future(self.lease_key)

    def ref(self):
        self.refs += 1

    def dispose(self):
        self.refs -= 1
        if self.refs == 0:
            self.tree.session.client.dispose_lease(self)

    def on_break(self, cb):
        """
        Simple lease break callback handler.
        @param cb: callable taking 1 parameter: the break request lease state
                   should return the desired lease state to break to
        """
        def simple_handle_break(lease, smb_res, cb_ctx):
            """
            note that lease is not used in this callback,
            since it already closes over self
            """
            notify = smb_res[0]
            if notify.flags & smb2.SMB2_NOTIFY_BREAK_LEASE_FLAG_ACK_REQUIRED:
                chan = self.tree.session.first_channel()
                ack = chan.lease_break_acknowledgement(self.tree, smb_res)
                ack.lease_state = cb(notify.new_lease_state)
                ack_res = chan.connection.transceive(ack.parent.parent)[0][0]
                if ack_res.lease_state != smb2.SMB2_LEASE_NONE:
                    self.arm_future()
                    self.on_break(cb)
                self.lease_state = ack_res.lease_state
            else:
                self.lease_state = notify.new_lease_state
        self.on_break_request(simple_handle_break)

    def on_break_request(self, cb, cb_ctx=None):
        """
        Complex lease break callback handler.
        @param cb: callable taking 3 parameters:
                        L{Lease}
                        L{Smb2} containing the break request
                        L{object} arbitrary context
                   should handle breaking the lease in some way
                   callback is also responsible for re-arming the future
                   and updating the lease_state (if changed)
        """
        def handle_break(f):
            smb_res = f.result()
            cb(self, smb_res, cb_ctx)
        self.future.then(handle_break)
