import pike.model as model
import pike.smb2 as smb2
import pike.test as test
import pike.ntstatus
from pike.model import Session
import random
import array
import time


class _testExcTimeoutResiliency(smb2.ExcuteTimeoutResiliencyRequest):

    def  _encode(self, cur):
        cur.encode_uint32le(self.Timeout)
        cur.encode_uint16le(self.Reserved)
# @pike.test.RequireCapabilities(pike.smb2.SMB2_GLOBAL_CAP_LEASING)
class TimeoutResiliency(test.PikeTest):
    share_all = pike.smb2.FILE_SHARE_READ | pike.smb2.FILE_SHARE_WRITE | pike.smb2.FILE_SHARE_DELETE

    lease1 = array.array('B',map(random.randint, [0]*16, [255]*16))
    lease2 = array.array('B',map(random.randint, [0]*16, [255]*16))
    r = pike.smb2.SMB2_LEASE_READ_CACHING
    rw = r | pike.smb2.SMB2_LEASE_WRITE_CACHING
    rh = r | pike.smb2.SMB2_LEASE_HANDLE_CACHING
    rwh = rw | rh
    def __init__(self, *args, **kwds):
        super(TimeoutResiliency, self).__init__(*args, **kwds)

    def create(self,chan, tree,durable,disposition=pike.smb2.FILE_SUPERSEDE,lease=rwh,lease_key=lease1):
        return chan.create(tree,
                         'resiliency07.txt',
                         access = pike.smb2.FILE_READ_DATA | pike.smb2.FILE_WRITE_DATA | pike.smb2.DELETE,
                         share=self.share_all,
                         disposition=disposition,
                         oplock_level=pike.smb2.SMB2_OPLOCK_LEVEL_LEASE,
                         lease_key=lease_key,
                         lease_state=lease,
                         durable=durable).result()

    # unix: ResponseError: (SMB2_IOCTL, STATUS_INVALID_PARAMETER)
    def test_timeout_ceiling_resiliency(self,durable=True):
        chan, tree = self.tree_connect()
        fh1 = self.create(chan,
                          tree,
                          durable=durable,
                          lease=self.rw)

        timeout = 300001
        with self.assert_error(pike.ntstatus.STATUS_INVALID_PARAMETER):
            a = chan.timeout_resiliency(fh1, timeout=timeout)

        self.assertEqual(fh1.lease.lease_state, self.rw)
        chan.connection.close()

        chan2, tree2 = self.tree_connect(client=pike.model.Client())
        fh2 = self.create(chan2,
                          tree2,
                          durable=durable,
                          lease=self.rw,
                          lease_key=self.lease2,
                          disposition=pike.smb2.FILE_OPEN)
        #
        self.assertEqual(fh2.lease.lease_state, self.rw)
        chan2.close(fh2)
        chan2.connection.close()

        chan3, tree3 = self.tree_connect()
        fh3 = self.create(chan3,tree3, durable=fh1)

        self.assertEqual(fh3.lease.lease_state, self.rwh)

    def test_resiliency(self,durable=True):
        chan, tree = self.tree_connect()
        fh1 = self.create(chan,
                          tree,
                          durable=durable,
                          lease=self.rw)

        timeout = 100
        a = chan.timeout_resiliency(fh1, timeout=timeout)
        self.assertEqual(fh1.lease.lease_state, self.rw)
        chan.connection.close()

        time.sleep((timeout-10)/1000)

        chan2, tree2 = self.tree_connect(client=pike.model.Client())
        fh2 = self.create(chan2,
                          tree2,
                          durable=durable,
                          lease=self.rw,
                          lease_key=self.lease2,
                          disposition=pike.smb2.FILE_OPEN)
        # resiliency invalidate, fh2 only read on win plat. but rw on onefs
        self.assertEqual(fh2.lease.lease_state, self.rw)
        chan2.close(fh2)
        chan2.connection.close()

        chan3, tree3 = self.tree_connect()
        fh3 = self.create(chan3,tree3, durable=fh1)
        # resiliency invalidate, fh3 get the fh1's lease, and only read on win plat, but rwh on onefs
        self.assertEqual(fh3.lease.lease_state, self.rwh)

    # test timeout win:AssertionError: No error raised when "STATUS_INVALID_PARAMETER" expected
    def test_timeout_resiliency(self,durable=True):
        chan, tree = self.tree_connect()
        fh1 = self.create(chan,
                          tree,
                          durable=durable,
                          lease=self.rw)

        timeout = 100
        self.assertEqual(fh1.lease.lease_state, self.rw)
        chan.connection.close()
        time.sleep(timeout/1000+5)


        chan2, tree2 = self.tree_connect(client=pike.model.Client())
        fh2 = self.create(chan2,
                          tree2,
                          durable=durable,
                          lease=self.rw,
                          lease_key=self.lease2,
                          disposition=pike.smb2.FILE_OPEN)

        self.assertEqual(fh2.lease.lease_state, self.rw)
        chan2.close(fh2)
        chan2.connection.close()

        chan3, tree3 = self.tree_connect()
        fh3 = self.create(chan3, tree3, durable=fh1)
        # win STATUS_OBJECT_NAME_NOT_FOUND,  but here rwh
        self.assertEqual(fh3.lease.lease_state, self.rwh)


    # test longth too small  windows:AssertionError: "STATUS_INVALID_PARAMETER" raised when "STATUS_BUFFER_TOO_SMALL" expected
    def test_buffer_too_small(self,durable=True):
        chan, tree = self.tree_connect()
        fh1 = self.create(chan,
                          tree,
                          durable=durable,
                          lease=self.rw)

        timeout = 5
        # with self.assert_error(pike.ntstatus.STATUS_BUFFER_TOO_SMALL):
        with self.assert_error(pike.ntstatus.STATUS_BUFFER_TOO_SMALL): # for onefs
            smb_req = chan.request(obj=fh1.tree)
            ioctl_req = smb2.IoctlRequest(smb_req)
            vni_req = _testExcTimeoutResiliency(ioctl_req)
            ioctl_req.file_id = fh1.file_id
            ioctl_req.flags = smb2.SMB2_0_IOCTL_IS_FSCTL
            vni_req.Timeout = timeout
            vni_req.Reserved = 0
            a = chan.connection.transceive(smb_req.parent)[0]
        self.assertEqual(fh1.lease.lease_state, self.rw)
        chan.connection.close()

        chan2, tree2 = self.tree_connect(client=pike.model.Client())
        fh2 = self.create(chan2,
                          tree2,
                          durable=durable,
                          lease=self.rw,
                          lease_key=self.lease2,
                          disposition=pike.smb2.FILE_OPEN)

        self.assertEqual(fh2.lease.lease_state, self.rw)
        chan2.close(fh2)
        chan2.connection.close()

        chan3, tree3 = self.tree_connect()
        fh3 = self.create(chan3, tree3, durable=fh1)
        # win STATUS_OBJECT_NAME_NOT_FOUND,  but here rwh
        self.assertEqual(fh3.lease.lease_state, self.rwh)


