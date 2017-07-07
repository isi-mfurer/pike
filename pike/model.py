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
#        model.py
#
# Abstract:
#
#        Transport and object model
#
# Authors: Brian Koropoff (brian.koropoff@emc.com)
#

"""
LEGACY: SMB2 Object Model. see L{pike.smb2}

This module contains an implementation of the SMB2 client object model,
allowing channels, sessions, tree connections, opens, and leases
to be established and tracked.  It provides convenience functions
for exercising common elements of the protocol without manually
constructing packets.
"""

import sys
import socket
import array
import struct
import random
import logging
import time
import operator
import contextlib

import auth
import core
import crypto
import netbios
import nttime
import smb2
import transport
import ntstatus
import digest

def loop(timeout=None, count=None):
    """
    wrapper for blocking on the underlying event loop for the given timeout
    or given count of iterations
    """
    if timeout is None:
        timeout = default_timeout
    transport.loop(timeout=timeout, count=count)

# These imports exist for compatability with old pike layout
from pike import TimeoutError
from smb2 import ResponseError
from core import Events
Events.import_items(globals())
from core import Future
from smb2.channel import Channel
from smb2.client import Client
from smb2.connection import Connection
from smb2.lease import Lease
from smb2.open import Open
from smb2.session import Session
from smb2.tree import Tree
