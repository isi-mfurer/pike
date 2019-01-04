
import pike.model
import pike.smb2
import pike.test
import pike.ntstatus




class QueryFileSessionConnect(pike.test.PikeTest):

    def __init__(self, *args, **kwds):
        super(QueryFileSessionConnect, self).__init__(*args, **kwds)
        self.default_client.dialects = [
                pike.smb2.DIALECT_SMB3_0,
                pike.smb2.DIALECT_SMB3_0_2]
    def session_bind(self, chan):
        return chan.connection.client.connect(self.server).negotiate().session_setup(self.creds, bind=chan.session)

    # @pike.test.RequireDialect(pike.smb2.DIALECT_SMB3_0, pike.smb2.DIALECT_SMB3_0_2)
    def test_session_lock_device(self):
        chan, tree = self.tree_connect()
        fh1 = chan.create(tree,
                           'lock1222.txt',
                           access=pike.smb2.GENERIC_WRITE,
                           disposition=pike.smb2.FILE_OPEN_IF).result()


        bytes_written1 = chan.write(fh1,0,'test11111111')
        max_output_response = 8096
        print max_output_response
        try:
            with self.assert_error(pike.ntstatus.STATUS_INVALID_DEVICE_REQUEST):
                a = chan.queryfile_sessionconn(fh1, max_output_response)
        except:
            self.assertEqual(pike.ntstatus.STATUS_SUCCESS,a.status)
        chan.close(fh1)

    def test_session_lock_buffer_toosmall(self):
        chan, tree = self.tree_connect()
        fh1 = chan.create(tree,
                          'lock1222.txt',
                          access=pike.smb2.GENERIC_WRITE,
                          disposition=pike.smb2.FILE_OPEN_IF).result()
        bytes_written1 = chan.write(fh1,0, 'test11111111')
        max_output_response = 256
        with self.assert_error(pike.ntstatus.STATUS_BUFFER_TOO_SMALL):
            a = chan.queryfile_sessionconn(fh1, max_output_response)
        chan.close(fh1)
    def test_session_lock_buffer_enough(self):
        chan, tree = self.tree_connect()
        fh1 = chan.create(tree,
                          'lock1222.txt',
                          access=pike.smb2.GENERIC_WRITE,
                          disposition=pike.smb2.FILE_OPEN_IF).result()
        bytes_written1 = chan.write(fh1,0, 'test111111111111111111111')
        max_output_response = 8096
        a = chan.queryfile_sessionconn(fh1, max_output_response)
        self.assertEqual(pike.ntstatus.STATUS_SUCCESS,a.status)
        chan.close(fh1)

    def test_multchannel_sessionconn(self):
        data_first = 'merry christmas'
        data_second = 'happy new year'
        chan, tree = self.tree_connect()
        client = chan.connection.client

        fh2 = chan.create(tree, 'multchannelSessionConn.txt', access = pike.smb2.GENERIC_WRITE, disposition=pike.smb2.FILE_OPEN_IF).result()

        # Open a second channel
        chan2 = self.session_bind(chan)
        chan3 = self.session_bind(chan)
        chan3_write = chan3.write(fh2, 99, data_second)
        max_output_response = 8096
        b = chan3.queryfile_sessionconn(fh2,max_output_response)
        chan3.close(fh2)




