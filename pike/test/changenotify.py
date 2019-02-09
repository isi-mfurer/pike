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
#        changenotify.py
#
# Abstract:
#
#        Change Notify tests
#
# Authors: Masen Furer <masen.furer@emc.com>
#

import pike.model
import pike.smb2
import pike.test

import time

class ChangeNotifyTest(pike.test.PikeTest):
    def test_change_notify_file_name(self):
        filename = "change_notify.txt"
        chan, tree = self.tree_connect()

        # connect to the root of the share
        root = chan.create(tree,
                           '',
                           access=pike.smb2.GENERIC_READ,
                           options=pike.smb2.FILE_DIRECTORY_FILE,
                           share=pike.smb2.FILE_SHARE_READ).result()

        # build a change notify request
        smb_req = chan.request(obj=root)
        notify_req = pike.smb2.ChangeNotifyRequest(smb_req)
        notify_req.file_id = root.file_id
        notify_req.completion_filter = pike.smb2.SMB2_NOTIFY_CHANGE_FILE_NAME
        # send the request async
        futures = chan.connection.submit(smb_req.parent)

        # create a file on the share to trigger the notification
        file = chan.create(tree,
                           filename,
                           access=pike.smb2.FILE_READ_DATA | pike.smb2.FILE_WRITE_DATA | pike.smb2.DELETE,
                           share=pike.smb2.FILE_SHARE_READ | pike.smb2.FILE_SHARE_WRITE | pike.smb2.FILE_SHARE_DELETE,
                           options=pike.smb2.FILE_DELETE_ON_CLOSE,
                           disposition=pike.smb2.FILE_SUPERSEDE).result()

        chan.close(file)

        # collect the change notify response
        result = futures[0].result()[0]

        # expect one notification, for the file add
        self.assertEqual(len(result.notifications), 1)
        self.assertEqual(result.notifications[0].filename, filename)
        self.assertEqual(result.notifications[0].action, pike.smb2.SMB2_ACTION_ADDED)

        chan.close(root)

    def test_change_notify_twice_w_compound(self):
        filename = "change_notify.txt"
        chan, tree = self.tree_connect()

        # connect to the root of the share
        root = chan.create(tree,
                           '',
                           access=pike.smb2.GENERIC_READ,
                           options=pike.smb2.FILE_DIRECTORY_FILE,
                           share=pike.smb2.FILE_SHARE_READ).result()

#        futures = chan.connection.submit(
#                        chan.change_notify_request(
#                            root,
#                            completion_filter=pike.smb2.SMB2_NOTIFY_CHANGE_FILE_NAME).parent.parent)
        # build a change notify request
        smb_req = chan.request(obj=root)
        notify_req = pike.smb2.ChangeNotifyRequest(smb_req)
        notify_req.file_id = root.file_id
        notify_req.completion_filter = pike.smb2.SMB2_NOTIFY_CHANGE_FILE_NAME
        # send the request async
        futures = chan.connection.submit(smb_req.parent)

        # build a 2nd change notify request chained with create
        nb_req = chan.frame()
        smb_req1 = chan.request(nb_req, obj=tree)
        smb_req2 = chan.request(nb_req, obj=tree)
        smb_req2.flags |= pike.smb2.SMB2_FLAGS_RELATED_OPERATIONS
        create_req = pike.smb2.CreateRequest(smb_req1)

        create_req.name = ''
        create_req.desired_access = pike.smb2.GENERIC_READ
        create_req.create_options = pike.smb2.FILE_DIRECTORY_FILE
        create_req.share_access = pike.smb2.FILE_SHARE_READ
        create_req.file_attributes = pike.smb2.FILE_ATTRIBUTE_NORMAL
        create_req.create_disposition = pike.smb2.FILE_OPEN_IF

        notify_req2 = pike.smb2.ChangeNotifyRequest(smb_req2)
        notify_req2.file_id = pike.smb2.RELATED_FID
        notify_req2.completion_filter = pike.smb2.SMB2_NOTIFY_CHANGE_FILE_NAME

        futures2 = chan.connection.submit(nb_req)
        pike.model.loop(count=1)

        time.sleep(2)

        def print_response(f):
            print(f.result())
        futures[0].then(print_response)
        futures2[0].then(print_response)
        futures2[1].then(print_response)

        # create a file on the share to trigger the notification
        chan2, tree2 = self.tree_connect()
        file = chan2.create(tree2,
                           filename,
                           access=pike.smb2.FILE_READ_DATA | pike.smb2.FILE_WRITE_DATA | pike.smb2.DELETE,
                           share=pike.smb2.FILE_SHARE_READ | pike.smb2.FILE_SHARE_WRITE | pike.smb2.FILE_SHARE_DELETE,
                           options=pike.smb2.FILE_DELETE_ON_CLOSE,
                           disposition=pike.smb2.FILE_SUPERSEDE).result()

        # collect the change notify response
        result = futures[0].result()
        create_result2 = futures2[0].result()
        notify_result2 = futures2[1].result()

        chan2.close(file)
        chan.close(root)

        # expect one notification, for the file add
        notify_resp = result[0]
        self.assertEqual(len(notify_resp.notifications), 1)
        self.assertEqual(notify_resp.notifications[0].filename, filename)
        self.assertEqual(notify_resp.notifications[0].action, pike.smb2.SMB2_ACTION_ADDED)

        # expect identical notification, for the separate handle
        notify_resp = notify_result2[0]
        self.assertEqual(len(notify_resp.notifications), 1)
        self.assertEqual(notify_resp.notifications[0].filename, filename)
        self.assertEqual(notify_resp.notifications[0].action, pike.smb2.SMB2_ACTION_ADDED)

    def test_change_notify_twice_w_compound_close_first_race(self):
        filename = "change_notify.txt"
        chan, tree = self.tree_connect()

        # connect to the root of the share
        root = chan.create(tree,
                           '',
                           access=pike.smb2.GENERIC_READ,
                           options=pike.smb2.FILE_DIRECTORY_FILE,
                           share=pike.smb2.FILE_SHARE_READ).result()

#        futures = chan.connection.submit(
#                        chan.change_notify_request(
#                            root,
#                            completion_filter=pike.smb2.SMB2_NOTIFY_CHANGE_FILE_NAME).parent.parent)
        # build a change notify request
        smb_req = chan.request(obj=root)
        notify_req = pike.smb2.ChangeNotifyRequest(smb_req)
        notify_req.file_id = root.file_id
        notify_req.completion_filter = pike.smb2.SMB2_NOTIFY_CHANGE_FILE_NAME
        # send the request async
        futures = chan.connection.submit(smb_req.parent)

        # build a 2nd change notify request chained with create
        nb_req = chan.frame()
        smb_req1 = chan.request(nb_req, obj=tree)
        smb_req2 = chan.request(nb_req, obj=tree)
        smb_req2.flags |= pike.smb2.SMB2_FLAGS_RELATED_OPERATIONS
        create_req = pike.smb2.CreateRequest(smb_req1)

        create_req.name = ''
        create_req.desired_access = pike.smb2.GENERIC_READ
        create_req.create_options = pike.smb2.FILE_DIRECTORY_FILE
        create_req.share_access = pike.smb2.FILE_SHARE_READ
        create_req.file_attributes = pike.smb2.FILE_ATTRIBUTE_NORMAL
        create_req.create_disposition = pike.smb2.FILE_OPEN_IF

        notify_req2 = pike.smb2.ChangeNotifyRequest(smb_req2)
        notify_req2.file_id = pike.smb2.RELATED_FID
        notify_req2.completion_filter = pike.smb2.SMB2_NOTIFY_CHANGE_FILE_NAME

        futures2 = chan.connection.submit(nb_req)
        pike.model.loop(count=1)

        time.sleep(2)

        def print_response(f):
            print(f.result())
        futures[0].then(print_response)
        futures2[0].then(print_response)
        futures2[1].then(print_response)

        # create a file on the share to trigger the notification
        chan2, tree2 = self.tree_connect()
        fh_future = chan2.create(tree2,
                           filename,
                           access=pike.smb2.FILE_READ_DATA | pike.smb2.FILE_WRITE_DATA | pike.smb2.DELETE,
                           share=pike.smb2.FILE_SHARE_READ | pike.smb2.FILE_SHARE_WRITE | pike.smb2.FILE_SHARE_DELETE,
                           options=pike.smb2.FILE_DELETE_ON_CLOSE,
                           disposition=pike.smb2.FILE_SUPERSEDE)
        pike.model.loop(count=1)
        #close_future = chan.connection.submit(
        #        chan.close_request(root).parent.parent)[0]

        chan.cancel(futures[0])
        file = fh_future.result()
        #close_future.result()

        # collect the change notify response
        result = futures[0].result()
        create_result2 = futures2[0].result()
        notify_result2 = futures2[1].result()

        chan2.close(file)
        chan.close(root)

        # expect one notification, for the file add
        notify_resp = result[0]
        self.assertEqual(len(notify_resp.notifications), 1)
        self.assertEqual(notify_resp.notifications[0].filename, filename)
        self.assertEqual(notify_resp.notifications[0].action, pike.smb2.SMB2_ACTION_ADDED)

        # expect identical notification, for the separate handle
        notify_resp = notify_result2[0]
        self.assertEqual(len(notify_resp.notifications), 1)
        self.assertEqual(notify_resp.notifications[0].filename, filename)
        self.assertEqual(notify_resp.notifications[0].action, pike.smb2.SMB2_ACTION_ADDED)

    def test_change_notify_twice_w_compound_2nd_create(self):
        filename = "change_notify.txt"
        chan, tree = self.tree_connect()

        # connect to the root of the share
        root = chan.create(tree,
                           '',
                           access=pike.smb2.GENERIC_READ,
                           options=pike.smb2.FILE_DIRECTORY_FILE,
                           share=pike.smb2.FILE_SHARE_READ).result()

#        futures = chan.connection.submit(
#                        chan.change_notify_request(
#                            root,
#                            completion_filter=pike.smb2.SMB2_NOTIFY_CHANGE_FILE_NAME).parent.parent)
        # build a change notify request
        smb_req = chan.request(obj=root)
        notify_req = pike.smb2.ChangeNotifyRequest(smb_req)
        notify_req.file_id = root.file_id
        notify_req.completion_filter = pike.smb2.SMB2_NOTIFY_CHANGE_FILE_NAME
        # send the request async
        futures = chan.connection.submit(smb_req.parent)

        # build a 2nd change notify request chained with create
        nb_req = chan.frame()
        smb_req1 = chan.request(nb_req, obj=tree)
        smb_req2 = chan.request(nb_req, obj=tree)
        smb_req2.flags |= pike.smb2.SMB2_FLAGS_RELATED_OPERATIONS
        create_req = pike.smb2.CreateRequest(smb_req1)

        create_req.name = ''
        create_req.desired_access = pike.smb2.GENERIC_READ
        create_req.create_options = pike.smb2.FILE_DIRECTORY_FILE
        create_req.share_access = pike.smb2.FILE_SHARE_READ
        create_req.file_attributes = pike.smb2.FILE_ATTRIBUTE_NORMAL
        create_req.create_disposition = pike.smb2.FILE_OPEN_IF

        notify_req2 = pike.smb2.ChangeNotifyRequest(smb_req2)
        notify_req2.file_id = pike.smb2.RELATED_FID
        notify_req2.completion_filter = pike.smb2.SMB2_NOTIFY_CHANGE_FILE_NAME

        futures2 = chan.connection.submit(nb_req)
        pike.model.loop(count=1)

        time.sleep(2)

        def print_response(f):
            print(f.result())
        futures[0].then(print_response)
        futures2[0].then(print_response)
        futures2[1].then(print_response)

        # create a file on the share to trigger the notification
        chan2, tree2 = self.tree_connect()
        create_close_req = chan2.frame()
        smb_req_crt = chan2.request(create_close_req, obj=tree2)
        smb_req_cls = chan2.request(create_close_req, obj=tree2)
        create_req = pike.smb2.CreateRequest(smb_req_crt)
        close_req = pike.smb2.CloseRequest(smb_req_cls)

        create_req.name = filename
        create_req.desired_access = pike.smb2.GENERIC_READ | pike.smb2.GENERIC_WRITE | pike.smb2.DELETE
        create_req.file_attributes = pike.smb2.FILE_ATTRIBUTE_NORMAL
        create_req.create_options=pike.smb2.FILE_DELETE_ON_CLOSE
        create_req.create_disposition = pike.smb2.FILE_SUPERSEDE
        create_req.share_access = pike.smb2.FILE_SHARE_READ | pike.smb2.FILE_SHARE_WRITE | pike.smb2.FILE_SHARE_DELETE

        close_req.file_id = pike.smb2.RELATED_FID
        smb_req_cls.flags |= pike.smb2.SMB2_FLAGS_RELATED_OPERATIONS

        fh1_futures = chan2.connection.submit(create_close_req)
        file = chan2.create(tree2,
                           filename,
                           access=pike.smb2.FILE_READ_DATA | pike.smb2.FILE_WRITE_DATA | pike.smb2.DELETE,
                           share=pike.smb2.FILE_SHARE_READ | pike.smb2.FILE_SHARE_WRITE | pike.smb2.FILE_SHARE_DELETE,
                           options=pike.smb2.FILE_DELETE_ON_CLOSE,
                           disposition=pike.smb2.FILE_OVERWRITE_IF).result()

        # collect the change notify response
        result = futures[0].result()
        create_result2 = futures2[0].result()
        notify_result2 = futures2[1].result()

        chan2.close(file)
        chan.close(root)

        # expect one notification, for the file add
        notify_resp = result[0]
        self.assertEqual(len(notify_resp.notifications), 1)
        self.assertEqual(notify_resp.notifications[0].filename, filename)
        self.assertEqual(notify_resp.notifications[0].action, pike.smb2.SMB2_ACTION_ADDED)

        # expect identical notification, for the separate handle
        notify_resp = notify_result2[0]
        self.assertEqual(len(notify_resp.notifications), 1)
        self.assertEqual(notify_resp.notifications[0].filename, filename)
        self.assertEqual(notify_resp.notifications[0].action, pike.smb2.SMB2_ACTION_ADDED)
