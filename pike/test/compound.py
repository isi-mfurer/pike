#
# Copyright (c) 2013, EMC Corporation
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
#        compound.py
#
# Abstract:
#
#        Compound request tests
#
# Authors: Brian Koropoff (brian.koropoff@emc.com)
#

import pike.model
import pike.smb2
import pike.test
import random
import array

class CompoundTest(pike.test.PikeTest):

    # Compounded create/close of the same file, with maximal access request
    def test_create_close(self):
        chan, tree = self.tree_connect()

        # Manually assemble a chained request
        nb_req = chan.frame()
        smb_req1 = chan.request(nb_req, obj=tree)
        smb_req2 = chan.request(nb_req, obj=tree)
        create_req = pike.smb2.CreateRequest(smb_req1)
        close_req = pike.smb2.CloseRequest(smb_req2)

        create_req.name = 'hello.txt'
        create_req.desired_access = pike.smb2.GENERIC_READ | pike.smb2.GENERIC_WRITE
        create_req.file_attributes = pike.smb2.FILE_ATTRIBUTE_NORMAL
        create_req.create_disposition = pike.smb2.FILE_OPEN_IF

        max_req = pike.smb2.MaximalAccessRequest(create_req)

        close_req.file_id = pike.smb2.RELATED_FID
        smb_req2.flags |= pike.smb2.SMB2_FLAGS_RELATED_OPERATIONS

        chan.connection.transceive(nb_req)

    def test_create_read(self):
        fname = "compound_read.txt"
        buf = "\0\1\2\3\4\5\6\7"*784*4
        buflen = len(buf)
        filelen = buflen*32
        chan, tree = self.tree_connect()
        fh = chan.create(tree, fname).result()
        for ix in xrange(32):
            chan.write(fh, buflen*ix, buf)
        chan.close(fh)

        # Manually assemble a chained request
        nb_req = chan.frame()
        smb_req1 = chan.request(nb_req, obj=tree)
        smb_req2 = chan.request(nb_req, obj=tree)
        create_req = pike.smb2.CreateRequest(smb_req1)
        read_req = pike.smb2.ReadRequest(smb_req2)

        create_req.name = fname
        create_req.desired_access = pike.smb2.GENERIC_READ
        create_req.file_attributes = pike.smb2.FILE_ATTRIBUTE_NORMAL
        create_req.create_disposition = pike.smb2.FILE_OPEN

        read_req.file_id = pike.smb2.RELATED_FID
        read_req.length = filelen
        smb_req2.flags |= pike.smb2.SMB2_FLAGS_RELATED_OPERATIONS

        responses = chan.connection.transceive(nb_req)
        fh = pike.model.Open(tree, responses[0])
        chan.close(fh)

    def test_create_read_read(self):
        fname = "compound_read_read.txt"
        # 32*128 seems to be around the length that crashes the server
        buf = "\0\1\2\3\4\5\6\7"*4*128
        buflen = len(buf)
        filelen = buflen*32
        chan, tree = self.tree_connect()
        fh = chan.create(tree, fname).result()
        for ix in xrange(32):
            chan.write(fh, buflen*ix, buf)
        chan.close(fh)

        # Manually assemble a chained request
        nb_req = chan.frame()
        smb_req1 = chan.request(nb_req, obj=tree)
        smb_req2 = chan.request(nb_req, obj=tree)
        smb_req3 = chan.request(nb_req, obj=tree)
        create_req = pike.smb2.CreateRequest(smb_req1)
        read_req = pike.smb2.ReadRequest(smb_req2)
        read_req3 = pike.smb2.ReadRequest(smb_req3)

        create_req.name = fname
        create_req.desired_access = pike.smb2.GENERIC_READ
        create_req.file_attributes = pike.smb2.FILE_ATTRIBUTE_NORMAL
        create_req.create_disposition = pike.smb2.FILE_OPEN

        read_req.file_id = pike.smb2.RELATED_FID
        read_req.length = filelen
        smb_req2.flags |= pike.smb2.SMB2_FLAGS_RELATED_OPERATIONS

        read_req3.file_id = pike.smb2.RELATED_FID
        read_req3.length = filelen
        smb_req3.flags |= pike.smb2.SMB2_FLAGS_RELATED_OPERATIONS

        responses = chan.connection.transceive(nb_req)
        fh = pike.model.Open(tree, responses[0])
        chan.close(fh)
