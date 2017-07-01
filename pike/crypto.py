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
#        crypto.py
#
# Abstract:
#
#        SMB3 Encryption
#
# Authors: Masen Furer (masen.furer@dell.com)
#
"""
SMB3 encryption support
"""
import core
import digest
import smb2

import array
import random

from Cryptodome.Cipher import AES


def pad_right(value, length, byte='\0'):
    """
    pad or truncate C{value} to C{length} bytes

    @type value: array.array
    @param value: the array to be padded
    @type length: integer
    @param length: the desired final length of the array
    @type byte: single character (string)
    @param byte: the byte value to pad with defaults to \0
    @rtype: array.array
    @return: C{length} byte copy of C{value} either truncated or filled to the
        right with the value of C{byte}
    """
    if len(value) > length:
        value = value[:length]
    elif len(value) < 16:
        value += array.array('B', byte*(length - len(value)))
    return value


class CipherMismatch(Exception):
    """
    Raised when the client and server do not have any ciphers in common
    """
    pass


class Ciphers(core.ValueEnum):
    """
    Enumeration of supported ciphers

    [MS-SMB2] 2.2.3.1.2 SMB2_ENCRYPTION_CAPABILITIES
    """
    SMB2_NONE_CIPHER = 0x0000
    SMB2_AES_128_CCM = 0x0001
    SMB2_AES_128_GCM = 0x0002

Ciphers.import_items(globals())

# mapping between the protocol cipher values tuple of (AES mode, nonce_length)
cipher_map = {
        SMB2_AES_128_CCM: (AES.MODE_CCM, 11),
        SMB2_AES_128_GCM: (AES.MODE_GCM, 12)
}


class EncryptionCapabilities(core.Frame):
    """
    [MS-SMB2] 2.2.3.1.2 SMB2_ENCRYPTION_CAPABILITIES

    @ivar ciphers: list of ciphers selected from L{Ciphers}
    @ivar ciphers_count: number of ciphers in the list. Set to None for auto
        calculation based on C{ciphers} list.
    """
    context_type = smb2.SMB2_ENCRYPTION_CAPABILITIES

    def __init__(self):
        self.ciphers = []
        self.ciphers_count = None

    def _encode(self, cur):
        if self.ciphers_count is None:
            self.ciphers_count = len(self.ciphers)
        cur.encode_uint16le(self.ciphers_count)
        for c in self.ciphers:
            cur.encode_uint16le(c)

    def _decode(self, cur):
        self.ciphers_count = cur.decode_uint16le()
        for ix in xrange(self.ciphers_count):
            self.ciphers.append(Ciphers(cur.decode_uint16le()))


class EncryptionCapabilitiesRequest(smb2.NegotiateRequestContext,
                                    EncryptionCapabilities):
    """
    EncryptionCapabilities frame wrapped in a NegotiateRequestContext for
    sending on the wire
    """
    def __init__(self, parent):
        smb2.NegotiateRequestContext.__init__(self, parent)
        EncryptionCapabilities.__init__(self)


class EncryptionCapabilitiesResponse(smb2.NegotiateResponseContext,
                                     EncryptionCapabilities):
    """
    EncryptionCapabilities frame wrapped in a NegotiateResponseContext for
    receiving on the wire
    """
    def __init__(self, parent):
        smb2.NegotiateResponseContext.__init__(self, parent)
        EncryptionCapabilities.__init__(self)


class TransformHeader(core.Frame):
    """
    [MS-SMB2] 2.2.41 SMB2 TRANSFORM_HEADER

    TransformHeader is designed to be a transparent slip attached to a
    L{Netbios} frame object (specified as parent). During serialization, if a
    L{Netbios} frame contains an attribute C{transform}, then that object's
    encode method will be called instead of each child frames' encode method.
    This frame is responsible for both encrypting and decrypting Smb2 frames
    according to an attached encryption context.

    If the C{encryption_context} is not explicitly specified, then it will be
    looked up based on C{session_id} from the parent L{Netbios} frame's
    connection reference

    @ivar protocol_id: the magic number indicating that this packet
        has been transformed
    @ivar signature: The 16-byte signature of the encrypted message generated
        by using C{encryption_context.encrypt(...)}
    @ivar nonce: An implementation-specific value assigned for every encrypted
        message. This MUST NOT be reused for all encrypted messages within a
        session. This value is always overwritten in the encryption routine
    @ivar wire_nonce: if wire_nonce is specified, it will be sent on the wire
        instead of the calculated nonce value (for negative testing)
    @ivar original_message_size: specifies the size of the message before being
        transformed
    @ivar flags: should always be set to 0x1
    @ivar session_id: Uniquely identifies the established session for the
        command.
    @ivar encryption_context: L{EncryptionContext} to be used for performing
        the encryption or decryption of the message buffer. If None, will be
        looked up based on the C{session_id}
    @ivar additional_authenticated_data_buf: used internally to calculate the
        signature
    """
    def __init__(self, parent):
        core.Frame.__init__(self, parent)
        self.protocol_id = array.array('B', "\xfdSMB")
        self.signature = None
        # the value of nonce is always used in the encryption routine
        self.nonce = array.array('B',
                                 map(random.randint, [0]*16, [255]*16))
        # if wire_nonce is set, it will be sent on the wire instead of nonce
        self.wire_nonce = None
        self.original_message_size = None
        self.reserved = None
        self.flags = 0x1
        self.session_id = None
        self.encryption_context = None
        self.additional_authenticated_data_buf = array.array('B')
        if parent is not None:
            parent.transform = self
        else:
            self._smb2_frames = []

    def _children(self):
        if self.parent is not None:
            return self.parent._children()
        else:
            return self._smb2_frames

    def append(self, smb2_frame):
        if self.parent is not None:
            self.parent.append(smb2_frame)
        else:
            self._smb2_frames.append(smb2_frame)

    def _encode(self, cur):
        self._encode_header(cur)
        self._encode_smb2(cur)

    def _encode_header(self, cur):
        # look up the encryption context if not specified
        if self.encryption_context is None and self.parent is not None:
            self.encryption_context = self.parent.conn.encryption_context(self.session_id)
        cur.encode_bytes(self.protocol_id)

        # the signature will be written in _encode_smb2
        self.signature_offset = cur.offset
        cur.advanceto(cur + 16)
        # the crypto header will be written in _encode_smb2
        self.crypto_header_offset = cur.offset
        # save a space for the wire nonce
        self.wire_nonce_hole = cur.hole.encode_bytes('\0'*16)
        cur.advanceto(cur + 16)

        # the following fields are part of AdditionalAuthenticatedData and are
        # used as inputs to the AES cipher
        aad_cur = core.Cursor(self.additional_authenticated_data_buf, 0)
        # nonce field size is 16 bytes right padded with zeros
        self.nonce = pad_right(self.nonce, 16)
        aad_cur.encode_bytes(self.nonce)
        self.original_message_size_hole = aad_cur.hole.encode_uint32le(0)
        if self.reserved is None:
            self.reserved = 0
        aad_cur.encode_uint16le(self.reserved)  # reserved
        aad_cur.encode_uint16le(self.flags)
        aad_cur.encode_uint64le(self.session_id)

    def _encode_smb2(self, cur):
        # serialize all chained Smb2 commands into one buffer
        original_message_buf = array.array('B')
        original_message_cur = core.Cursor(original_message_buf, 0)
        for smb_frame in self.parent:
            smb_frame.encode(original_message_cur)
        if self.original_message_size is None:
            self.original_message_size = len(original_message_buf)
        self.original_message_size_hole(self.original_message_size)
        (self.ciphertext,
         crypto_hmac) = self.encryption_context.encrypt(
                                original_message_buf,
                                self.additional_authenticated_data_buf,
                                self.nonce)
        cur.encode_bytes(self.ciphertext)

        # fill in the signature hole
        sig_cur = core.Cursor(cur.array, self.signature_offset)
        if self.signature is None:
            self.signature = crypto_hmac
        sig_cur.encode_bytes(self.signature)

        # fill in the header
        aad_cur = core.Cursor(cur.array, self.crypto_header_offset)
        aad_cur.encode_bytes(self.additional_authenticated_data_buf)

        # fill in the wire nonce
        if self.wire_nonce is None:
            self.wire_nonce = self.nonce
        self.wire_nonce_hole(pad_right(self.wire_nonce, 16))

    def _decode(self, cur):
        self._decode_header(cur)
        self._decode_smb2(cur)

    def _decode_header(self, cur):
        self.protocol_id = cur.decode_bytes(4)
        self.signature = cur.decode_bytes(16)
        # the following fields are part of AdditionalAuthenticatedData and are
        # used as inputs to the AES cipher
        self.crypto_header_start = cur.offset
        self.nonce = cur.decode_bytes(16)
        self.original_message_size = cur.decode_uint32le()
        self.reserved = cur.decode_uint16le()   # reserved
        self.flags = cur.decode_uint16le()
        self.session_id = cur.decode_uint64le()
        self.crypto_header_end = cur.offset
        if self.encryption_context is None and self.parent is not None:
            self.encryption_context = self.parent.conn.encryption_context(self.session_id)

    def _decode_smb2(self, cur):
        self.encrypted_data = cur.decode_bytes(self.original_message_size)
        crypto_header = cur.array[self.crypto_header_start:self.crypto_header_end]
        self.plaintext = self.encryption_context.decrypt(
                        self.encrypted_data,
                        self.signature,
                        crypto_header,
                        self.nonce)
        # scan through the plaintext for chained messages
        pt_cur = core.Cursor(self.plaintext, 0)
        end = pt_cur + len(self.plaintext)
        with pt_cur.bounded(pt_cur, end):
            while (pt_cur < end):
                start = pt_cur.offset
                message = smb2.Smb2(self.parent)
                message.decode(pt_cur)
                message.buf = pt_cur.array[start:pt_cur.offset]

    def verify(self, *args, **kwds):
        pass        # verification occurs at the point of decryption


class CryptoKeys300(object):
    """ Key generation for SMB 0x300 and 0x302 """
    def __init__(self, session_key, *args, **kwds):
        self.encryption = digest.derive_key(
            session_key, "SMB2AESCCM", "ServerIn \0")[:16].tostring()
        self.decryption = digest.derive_key(
            session_key, "SMB2AESCCM", "ServerOut\0")[:16].tostring()


class CryptoKeys311(object):
    """ Key generation for SMB 0x311 + """
    def __init__(self, session_key, pre_auth_integrity_hash, *args, **kwds):
        self.encryption = digest.derive_key(
            session_key, "SMBC2SCipherKey", pre_auth_integrity_hash)[:16].tostring()
        self.decryption = digest.derive_key(
            session_key, "SMBS2CCipherKey", pre_auth_integrity_hash)[:16].tostring()


class EncryptionContext(object):
    """
    Encapsulates all information needed to encrypt and decrypt messages.
    This context is associated with an SMB L{Session} object

    @ivar keys: L{CryptoKeys300} or L{CryptoKeys311} object
    """
    def __init__(self, keys, ciphers):
        self.keys = keys
        for c in ciphers:
            if c in cipher_map:
                self.aes_mode, self.nonce_length = cipher_map[c]
                self.cipher = c
                break
        else:
            raise CipherMismatch(
                    "Client did not recognize any ciphers returned by the "
                    "server: {0}".format(ciphers))

    def encrypt(self, plaintext, authenticated_data, nonce):
        """
        perform encryption according to the keys in C{self.keys}

        @type plaintext: array.array
        @type authenticated_data: array.array
        @param authenticated_data: extra data from header used in HMAC
            calculation
        @type nonce: array.array
        @param nonce: randomly generated nonce should be used for each message
        @rtype: tuple of (array.array, array.array)
        @return: (ciphertext, hmac signature)
        """
        enc_cipher = AES.new(self.keys.encryption,
                             self.aes_mode,
                             nonce=nonce[:self.nonce_length].tostring())
        enc_cipher.update(authenticated_data.tostring())
        ciphertext, signature = enc_cipher.encrypt_and_digest(plaintext.tostring())
        return array.array('B', ciphertext), array.array('B', signature)

    def decrypt(self, ciphertext, signature, authenticated_data, nonce):
        """
        perform decryption according to the keys in C{self.keys} and verify
        signature matches

        @type ciphertext: array.array
        @type signature: array.array
        @param signature: hmac signature received in the header
        @type authenticated_data: array.array
        @param authenticated_data: extra data from header used in HMAC
            calculation
        @type nonce: array.array
        @param nonce: randomly generated nonce received from sender
        @rtype: array.array
        @return: plaintext of message
        """
        dec_cipher = AES.new(self.keys.decryption,
                             self.aes_mode,
                             nonce=nonce[:self.nonce_length].tostring())
        dec_cipher.update(authenticated_data.tostring())
        return array.array(
                'B',
                dec_cipher.decrypt_and_verify(
                    ciphertext.tostring(),
                    signature.tostring()))
