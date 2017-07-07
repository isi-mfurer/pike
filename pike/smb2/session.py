import pike.auth as auth
import pike.core as core
import pike.crypto as crypto
import pike.digest as digest
import pike.ntstatus as ntstatus
import pike.smb2 as smb2

from channel import Channel


class SessionSetupContext(object):
    def __init__(self, conn, creds=None, bind=None, resume=None,
                 ntlm_version=None):
        assert conn.negotiate_response is not None

        self.conn = conn
        self.dialect_revision = conn.negotiate_response.dialect_revision
        self.bind = bind
        self.resume = resume

        if creds and auth.ntlm is not None:
            self.auth = auth.NtlmProvider(conn, creds)
            if ntlm_version is not None:
                self.auth.authenticator.ntlm_version = ntlm_version
        elif auth.kerberos is not None:
            self.auth = auth.KerberosProvider(conn, creds)
        else:
            raise ImportError("Neither ntlm nor kerberos authentication "
                              "methods are available")

        self._settings = {}
        self.prev_session_id = 0
        self.session_id = 0
        self.requests = []
        self.responses = []
        self.session_future = core.Future()
        self.interim_future = None

        if bind:
            assert conn.negotiate_response.dialect_revision >= 0x300
            self.session_id = bind.session_id
            conn._binding = bind
            # assume the signing key from the previous session
            conn._binding_key = bind.first_channel().signing_key
        elif resume:
            assert conn.negotiate_response.dialect_revision >= 0x300
            self.prev_session_id = resume.session_id

    def let(self, **kwargs):
        return core.Let(self, kwargs)

    def derive_signing_key(self, session_key=None, context=None):
        if session_key is None:
            session_key = self.session_key
        if self.dialect_revision >= smb2.DIALECT_SMB3_1_1:
            if context is None:
                context = self.conn._pre_auth_integrity_hash
            return digest.derive_key(
                    session_key,
                    'SMBSigningKey',
                    context)[:16]
        elif self.dialect_revision >= smb2.DIALECT_SMB3_0:
            if context is None:
                context = 'SmbSign\0'
            return digest.derive_key(session_key, 'SMB2AESCMAC', context)[:16]
        else:
            return session_key

    def derive_encryption_keys(self, session_key=None, context=None):
        if self.dialect_revision >= smb2.DIALECT_SMB3_1_1:
            if context is None:
                context = self.conn._pre_auth_integrity_hash
            for nctx in self.conn.negotiate_response:
                if isinstance(nctx, crypto.EncryptionCapabilitiesResponse):
                    try:
                        return crypto.EncryptionContext(
                            crypto.CryptoKeys311(
                                self.session_key,
                                context),
                            nctx.ciphers)
                    except crypto.CipherMismatch:
                        pass
        elif self.dialect_revision >= smb2.DIALECT_SMB3_0:
            if self.conn.negotiate_response.capabilities & smb2.SMB2_GLOBAL_CAP_ENCRYPTION:
                return crypto.EncryptionContext(
                    crypto.CryptoKeys300(self.session_key),
                    [crypto.SMB2_AES_128_CCM])

    def _send_session_setup(self, sec_buf):
        smb_req = self.conn.request()
        session_req = smb2.SessionSetupRequest(smb_req)

        smb_req.session_id = self.session_id
        session_req.previous_session_id = self.prev_session_id
        session_req.security_mode = smb2.SMB2_NEGOTIATE_SIGNING_ENABLED
        session_req.security_buffer = sec_buf
        if self.bind:
            smb_req.flags = smb2.SMB2_FLAGS_SIGNED
            session_req.flags = smb2.SMB2_SESSION_FLAG_BINDING

        for (attr, value) in self._settings.iteritems():
            setattr(session_req, attr, value)

        self.requests.append(smb_req)
        return self.conn.submit(smb_req.parent)[0]

    def _finish(self, smb_res):
        sec_buf = smb_res[0].security_buffer
        out_buf, self.session_key = self.auth.step(sec_buf)
        signing_key = self.derive_signing_key()
        encryption_context = self.derive_encryption_keys()

        # Verify final signature
        smb_res.verify(self.conn.signing_digest(), signing_key)

        if self.bind:
            self.conn._binding = None
            self.conn._binding_key = None
            session = self.bind
        else:
            session = Session(self.conn.client,
                              self.session_id,
                              self.session_key,
                              encryption_context,
                              smb_res)
            session.user = self.auth.username()

        return session.addchannel(self.conn, signing_key)

    def __iter__(self):
        return self

    def submit(self, f=None):
        """
        Submit rounds of SessionSetupRequests

        Returns a L{Future} object, for the L{Channel} object
        """
        try:
            res = self.next()
            res.then(self.submit)
        except StopIteration:
            pass
        return self.session_future

    def next(self):
        with self.session_future:
            res = self._process()
            if res is not None:
                return res
        raise StopIteration()

    def _process(self):
        out_buf = None
        if not self.interim_future and not self.responses:
            # send the initial request
            out_buf, self.session_key = self.auth.step(
                    self.conn.negotiate_response.security_buffer)

        elif self.interim_future:
            smb_res = self.interim_future.result()
            self.interim_future = None
            self.responses.append(smb_res)
            self.session_id = smb_res.session_id

            if smb_res.status == ntstatus.STATUS_SUCCESS:
                # session is established
                with self.session_future:
                    self.session_future(self._finish(smb_res))
                return self.session_future
            else:
                # process interim request
                session_res = smb_res[0]
                if self.bind:
                    # Need to verify intermediate signatures
                    smb_res.verify(self.conn.signing_digest(),
                                   self.conn._binding_key)
                out_buf, self.session_key = self.auth.step(
                        session_res.security_buffer)
        if out_buf:
            # submit additional requests if necessary
            self.interim_future = self._send_session_setup(out_buf)
            return self.interim_future


class Session(object):
    def __init__(self, client, session_id, session_key,
                 encryption_context, smb_res):
        object.__init__(self)
        self.client = client
        self.session_id = session_id
        self.session_key = session_key
        self.encryption_context = encryption_context
        self.encrypt_data = False
        if smb_res[0].session_flags & smb2.SMB2_SESSION_FLAG_ENCRYPT_DATA and \
                self.encryption_context is not None:
            self.encrypt_data = True
        self._channels = {}
        self._trees = {}
        self.user = None

    def addchannel(self, conn, signing_key):
        channel = Channel(conn, self, signing_key)
        self._channels[id(conn)] = channel
        conn._sessions[self.session_id] = self
        return channel

    def delchannel(self, conn):
        del conn._sessions[self.session_id]
        del self._channels[id(conn)]

    def first_channel(self):
        return self._channels.itervalues().next()

    def tree(self, tree_id):
        return self._trees.get(tree_id, None)
