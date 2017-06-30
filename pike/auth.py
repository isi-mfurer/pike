#
# Copyright (c) 2017, Dell Technologies
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice,
# this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright notice,
# this list of conditions and the following disclaimer in the documentation
# and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
# Module Name:
#
#        auth.py
#
# Abstract:
#
#        Authentication Plugins for Pike
#
# Authors: Masen Furer (masen.furer@dell.com)
#

"""
Authentication Plugins for Pike

This module contains wrappers around external authentication mechanisms and
APIs.
"""


import array
try:
    import kerberos
except ImportError:
    kerberos = None
try:
    import ntlm
except ImportError:
    ntlm = None


def split_credentials(creds):
    """
    Split samba-style credential string

    @type creds: string
    @param creds: credential in the format DOMAIN\\user%passwd (domain
        may be ommitted)
    @rtype: tuple of (string, string, string)
    @return: (domain, user, password). If domain is not specified it
        will be returned as the string "None"
    """
    user, password = creds.split('%')
    if '\\' in user:
        domain, user = user.split('\\')
    else:
        domain = "NONE"
    return (domain, user, password)


class GenericProvider(object):
    """
    Abstract base class for documentation purposes. Authentication providers
    should inherit from this class.
    """
    def step(self, sec_buf):
        """
        perform one authentication step

        @type sec_buf: array.array
        @param sec_buf: opaque security buffer

            sec_buf is typically the C{security_buffer} field of a
            L{NegotiateResponse} or L{SessionSetupResponse}
        @rtype: tuple of (array.array, array.array)
        @return: (opaque security buffer, session key) either of which may be
            None indicating that the field is not applicable to this step in
            the authentication process
        """
        raise NotImplementedError

    def username(self):
        """
        @rtype: string
        @return: the username that has authenticated against the provider.

            Note: this function may only be applicable after authentication
            steps have completed
        """
        raise NotImplementedError


class KerberosProvider(GenericProvider):
    """
    Leverage pykerb library to exchange multiple rounds of gssapi as necessary
    in order to perform Kerberos authentication.

    Depending on the gss mechanisms available in the kerberos library that
    pykerb was built against, this provider may also support NTLM. The only
    known kerberos library supporting NTLM is from likewise.

    This provider requires that pike has been built with pykerb/kerberos C
    extension.
    """
    def __init__(self, conn, creds=None):
        """
        Initialize the KerberosProvider instance

        @type conn: L{Connection}
        @param conn: the L{Connection} that the authentication is being
            performed against
        @type creds: string or None
        @param creds: if None, an externally acquired kerberos ticket will be
            used for authentication.

            Otherwise a string credential in the format DOMAIN\\user%passwd
            will trigger NTLM to be used (if supported by library)

            creds defaults to None
        """
        if creds:
            domain, user, password = split_credentials(creds)
            (self.result,
             self.context) = kerberos.authGSSClientInit(
                "cifs/" + conn.server,
                gssmech=2,
                user=user,
                password=password,
                domain=domain)
        else:
            (self.result,
             self.context) = kerberos.authGSSClientInit("cifs/" + conn.server,
                                                        gssmech=1)

    def step(self, sec_buf):
        self.result = kerberos.authGSSClientStep(
                self.context,
                sec_buf.tostring())
        if self.result == 0:
            return (array.array(
                    'B',
                    kerberos.authGSSClientResponse(self.context)),
                    None)
        else:
            kerberos.authGSSClientSessionKey(self.context)
            return (None,
                    array.array(
                        'B',
                        kerberos.authGSSClientResponse(self.context)[:16]))

    def username(self):
        return kerberos.authGSSClientUserName(self.context)


class NtlmProvider(GenericProvider):
    """
    Leverage L{ntlm} module to perform multiple rounds of NTLM authentication

    Both NTLMv1 and NTLMv2 are available
    """
    def __init__(self, conn, creds):
        """
        Initialize the NtlmProvider instance

        @type conn: L{Connection}
        @param conn: the L{Connection} that the authentication is being
            performed against
        @type creds: string
        @param creds: credential in the format DOMAIN\\user%passwd
        """
        self.authenticator = ntlm.NtlmAuthenticator(*split_credentials(creds))

    def step(self, sec_buf):
        if self.authenticator.negotiate_message is None:
            return (self.authenticator.negotiate(), None)
        elif self.authenticator.challenge_message is None:
            self.authenticator.authenticate(sec_buf)
        return (self.authenticator.authenticate_buffer,
                self.authenticator.exported_session_key)

    def username(self):
        return '{0}\{1}'.format(self.authenticator.domain,
                                self.authenticator.username)
