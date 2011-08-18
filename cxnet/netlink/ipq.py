# -*- coding: utf-8 -*-
"""
    cxnet.netlink.ipq
    ~~~~~~~~~~~~~~~~~

    Netlink IP Queue implementation.

    :copyright: (c) 2011 by Peter V. Saveliev, see AUTHORS for more details.
    :license: GPL, see LICENSE for more details.
"""

from __future__ import absolute_import

from ctypes import Structure, Union
from ctypes import c_byte, c_ubyte, c_char, c_ulong, c_long, c_uint, c_ushort

from ..common import cx_int
from .core import nl_socket, nlmsghdr, NETLINK_FIREWALL, NLM_F_REQUEST


# Types of IPQ messages
IPQM_BASE    = 0x10        # standard netlink messages below this
IPQM_MODE    = IPQM_BASE + 1    # Mode request from peer
IPQM_VERDICT = IPQM_BASE + 2    # Verdict from peer
IPQM_PACKET  = IPQM_BASE + 3    # Packet from kernel
IPQM_MAX     = IPQM_BASE + 4

IPQ_COPY_NONE    = 0        # Initial mode, packets are dropped
IPQ_COPY_META    = 1        # Copy metadata
IPQ_COPY_PACKET  = 2        # Copy metadata + packet (range)

IPQ_MAX_PAYLOAD  = 0x800

# Responses from hook functions
NF_DROP     = 0
NF_ACCEPT   = 1
NF_STOLEN   = 2
NF_QUEUE    = 3
NF_REPEAT   = 4
NF_STOP     = 5


class _ipq_mode_msg(Structure):
    _fields_ = [
        ("value",        c_ubyte),
        ("range",        cx_int),
    ]

class _ipq_packet_msg(Structure):
    _fields_ = [
        ("packet_id",        c_ulong),
        ("mark",             c_ulong),
        ("timestamp_sec",    c_long),
        ("timestamp_usec",   c_long),
        ("hook",             c_uint),
        ("indev_name",       c_char * 16),
        ("outdev_name",      c_char * 16),
        ("hw_protocol",      c_ushort),
        ("hw_type",          c_ushort),
        ("hw_addrlen",       c_ubyte),
        ("hw_addr",          c_ubyte * 8),
        ("data_len",         cx_int),
        ("payload",          c_byte * IPQ_MAX_PAYLOAD),
    ]

class _ipq_verdict_msg(Structure):
    _fields_ = [
        ("value",            c_uint),
        ("id",               c_ulong),
        ("data_len",         cx_int),
        ("payload",          c_ubyte),
    ]


class _ipq_peer_msg(Union):
    _fields_ = [
        ("mode",             _ipq_mode_msg),
        ("verdict",          _ipq_verdict_msg),
    ]

class ipq_peer_msg(Structure):
    _fields_ = [
        ("hdr",              nlmsghdr),
        ("data",             _ipq_peer_msg),
    ]

class ipq_packet_msg(Structure):
    _fields_ = [
        ("hdr",              nlmsghdr),
        ("data",             _ipq_packet_msg),
    ]

class ipq_socket(nl_socket):
    """
    IPQ socket
    """

    msg = ipq_packet_msg

    def __init__(self, mode=IPQ_COPY_PACKET):
        nl_socket.__init__(self, family=NETLINK_FIREWALL)

        msg = ipq_peer_msg()
        msg.hdr.type = IPQM_MODE
        msg.hdr.flags = NLM_F_REQUEST
        msg.data.mode.value = mode
        msg.data.mode.range = IPQ_MAX_PAYLOAD

        self.send(msg)

    def verdict(self, seq, v):

        msg = ipq_peer_msg()
        msg.hdr.type = IPQM_VERDICT
        msg.hdr.flags = NLM_F_REQUEST
        msg.data.verdict.value = v
        msg.data.verdict.id = seq
        msg.data.verdict.data_len = 0

        self.send(msg)
