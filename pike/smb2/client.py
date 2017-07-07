import pike.smb2 as smb2
import pike.transport as transport
from pike.core import Events, Future
from connection import Connection
from lease import Lease

import array
import contextlib
import logging
import operator
import random


class Client(object):
    """
    Client

    Maintains all state associated with an SMB2/3 client.

    @type dialects: [number]
    @ivar dialects: A list of supported dialects
    @ivar capabilities: Capabilities flags
    @ivar security_mode: Security mode flags
    @ivar client_guid: Client GUID
    @ivar channel_sequence: Current channel sequence number
    """
    def __init__(self,
                 dialects=[smb2.DIALECT_SMB2_002,
                           smb2.DIALECT_SMB2_1,
                           smb2.DIALECT_SMB3_0,
                           smb2.DIALECT_SMB3_0_2,
                           smb2.DIALECT_SMB3_1_1],
                 capabilities=smb2.GlobalCaps(reduce(operator.or_,
                                                     smb2.GlobalCaps.values())),
                 security_mode=smb2.SMB2_NEGOTIATE_SIGNING_ENABLED,
                 client_guid=None):
        """
        Constructor.

        @type dialects: [number]
        @param dialects: A list of supported dialects.
        @param capabilities: Client capabilities flags
        @param security_mode: Client security mode flags
        @param client_guid: Client GUID. If None, generate random guid
        """
        if client_guid is None:
            client_guid = array.array(
                    'B',
                    map(random.randint, [0]*16, [255]*16))

        self.dialects = dialects
        self.capabilities = capabilities
        self.security_mode = security_mode
        self.client_guid = client_guid
        self.channel_sequence = 0
        self.callbacks = {}
        self._oplock_break_map = {}
        self._lease_break_map = {}
        self._oplock_break_queue = []
        self._lease_break_queue = []
        self._connections = []
        self._leases = {}

        self.logger = logging.getLogger('pike')

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

    def connect(self, server, port=445):
        """
        Create a connection.

        @param server: The server to connect to.
        @param port: The port to connect to.
        @rtype: L{Connection}
        @return: a new L{Connection} object connected to the given server and
        port.
        """
        return self.connect_submit(server, port).result()

    def connect_submit(self, server, port=445):
        """
        Create a connection.

        @type server: string
        @param server: The server to connect to.
        @type port: integer
        @param port: The port to connect to.
        @rtype: L{Future}
        @return: future for the L{Connection} being established
            asynchronously to the given server and port.
        """
        return Connection(self, server, port).establish().connection_future

    # Do not use, may be removed.  Use oplock_break_future.
    def next_oplock_break(self):
        while len(self._oplock_break_queue) == 0:
            transport.loop(count=1)
        return self._oplock_break_queue.pop()

    # Do not use, may be removed.  Use lease_break_future.
    def next_lease_break(self):
        while len(self._lease_break_queue) == 0:
            transport.loop(count=1)
        return self._lease_break_queue.pop()

    def oplock_break_future(self, file_id):
        """
        Create future for oplock break.

        Returns a L{Future} object which will be completed when
        an oplock break occurs.  The result will be the L{smb2.Smb2} frame
        of the break notification packet.

        @type file_id: (number, number)
        @param file_id: The file ID of the oplocked file.
        """

        future = Future(None)

        for smb_res in self._oplock_break_queue[:]:
            if smb_res[0].file_id == file_id:
                future.complete(smb_res)
                self._oplock_break_queue.remove(smb_res)
                break

        if future.response is None:
            self._oplock_break_map[file_id] = future

        return future

    def lease_break_future(self, lease_key):
        """
        Create future for lease break.

        Returns a L{Future} object which will be completed when
        a lease break occurs.  The result will be the L{smb2.Smb2} frame
        of the break notification packet.

        @param lease_key: The lease key for the lease.
        """

        future = Future(None)

        for smb_res in self._lease_break_queue[:]:
            if smb_res[0].lease_key == lease_key:
                future.complete(smb_res)
                self._lease_break_queue.remove(smb_res)
                break

        if future.response is None:
            self._lease_break_map[lease_key.tostring()] = future

        return future

    def oplock_break(self, file_id):
        """
        Wait for and return oplock break notification.

        Equivalent to L{oplock_break_future}(file_id).result()
        """

        return self.oplock_break_future(file_id).result()

    def lease_break(self, lease_key):
        """
        Wait for and return lease break notification.

        Equivalent to L{lease_break_future}(lease_key).result()
        """

        return self.lease_break_future(lease_key).result()

    def lease(self, tree, lease_res):
        """
        Create or look up lease object.

        Returns a lease object based on a L{Tree} and a
        L{smb2.LeaseResponse}.  The lease object is created
        if it does not already exist.

        @param tree: The tree on which the lease request was issued.
        @param lease_res: The lease create context response.
        """

        lease_key = lease_res.lease_key.tostring()
        if lease_key not in self._leases:
            lease = Lease(tree)
            self._leases[lease_key] = lease
        else:
            lease = self._leases[lease_key]
            lease.ref()

        lease.update(lease_res)
        return lease

    # Internal function to remove lease from table
    def dispose_lease(self, lease):
        del self._leases[lease.lease_key.tostring()]
