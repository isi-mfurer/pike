#
# Copyright (c) 2021, Dell Inc. or its subsidiaries.
# All rights reserved.
# See file LICENSE for licensing information.
#
# Module Name:
#
#       protocol.py
#
# Abstract:
#
#       python 3+ asyncio transport and protocol implementation
#
# Authors: Masen Furer (masen.furer@dell.com)
#

from collections import deque
try:
    import asyncio
except ImportError:
    raise ImportError("stdlib asyncio module is not available, use a newer version of python")

import attr

from .netbios import Netbios


@attr.s
class SMB2Protocol(asyncio.Protocol):
    connection = attr.ib()  # the pike.model.Connection object
    transport = attr.ib(default=None)
    next_mid = attr.ib(default=0)
    mid_blacklist = attr.ib(factory=set)
    future_map = attr.ib(factory=dict)
    _in_buffer = attr.ib(default=None)
    _out_buffer = attr.ib(factory=None)
    _next_packet_size = attr.ib(default=None)

    def connection_made(self, transport):
        self.transport = transport
        self.connection.socket = transport.get_extra_info("socket")
        # complete the connect_future
        self.connection.handle_connect()

    def connection_lost(self, exc):
        if exc:
            self.connection.error = exc
            self.connection.traceback = exc.__traceback__
        self.connection.close()

    def pause_writing(self):
        self._out_buffer = []

    def resume_writing(self):
        for item in self._out_buffer:
            self.transport.write(item)
        self._out_buffer = None

    def extract_netbios_frame(self, data):
        nb = self.frame()
        self.connection.process_callbacks(EV_RES_PRE_DESERIALIZE, data)
        nb.parse(data)
        self.connection._dispatch_incoming(nb)

    def data_received(self, data):
        self.connection.process_callbacks(EV_RES_POST_RECV, data)
        doffset = 0
        dlen = len(data)
        if self._in_buffer and self._next_packet_size:
            doffset = self._next_packet_size - len(self._in_buffer)
            if doffset > dlen:
                # not enough data, buffer and move on
                self._in_buffer.extend(data)
                return
            self.extract_netbios_frame(self._in_buffer + data[:doffset])
            self._in_buffer = None
            self._next_packet_size = None

        # deal with any left over data
        while doffset < dlen:
            nb_header = data[doffset:doffset+Netbios.HEADER_LENGTH]
            self._next_packet_size = Netbios.HEADER_LENGTH + struct.unpack(">L", nb_header)[0]
            start_offset = doffset
            doffset = start_offset + self._next_packet_size
            if doffset < dlen:
                # full packet available
                self.extract_netbios_frame(data[start_offset:doffset])
            else:
                # partial packet available, buffer and move on
                self._in_buffer = array.array('B', data[doffset:])

    def eof_received(self):
        self.connection.close()

    def send(self, b):
        if self._out_buffer is None:
            self.transport.write(b)
        else:
            self._out_buffer.append(b)
