# -*- coding: utf-8 -*-
"""
    cxnet.netlink.core
    ~~~~~~~~~~~~~~~~~~

    This module implements core Netlink classes.

    :copyright: (c) 2011 by ALT Linux, Peter V. Saveliev, see AUTHORS
                for more details.
    :license: GPL, see LICENSE for more details.
"""

from __future__ import absolute_import

import os
from ctypes import Structure
from ctypes import sizeof, addressof, byref
from ctypes import c_uint16, c_uint32, c_ushort, c_ubyte, c_byte
from socket import AF_NETLINK, SOCK_RAW

from ..common import libc, cx_int
from ..utils import export_by_prefix, hline
from .exceptions import NetlinkError


##  Netlink family
#
NETLINK_ROUTE            = 0    # Routing/device hook
NETLINK_UNUSED           = 1    # Unused number
NETLINK_USERSOCK         = 2    # Reserved for user mode socket protocols
NETLINK_FIREWALL         = 3    # Firewalling hook
NETLINK_INET_DIAG        = 4    # INET socket monitoring
NETLINK_NFLOG            = 5    # netfilter/iptables ULOG
NETLINK_XFRM             = 6    # ipsec
NETLINK_SELINUX          = 7    # SELinux event notifications
NETLINK_ISCSI            = 8    # Open-iSCSI
NETLINK_AUDIT            = 9    # auditing
NETLINK_FIB_LOOKUP       = 10
NETLINK_CONNECTOR        = 11
NETLINK_NETFILTER        = 12    # netfilter subsystem
NETLINK_IP6_FW           = 13
NETLINK_DNRTMSG          = 14    # DECnet routing messages
NETLINK_KOBJECT_UEVENT   = 15    # Kernel messages to userspace
NETLINK_GENERIC          = 16
# leave room for NETLINK_DM (DM Events)
NETLINK_SCSITRANSPORT    = 18    # SCSI Transports

## Netlink message flags values (nlmsghdr.flags)
#
NLM_F_REQUEST            = 1    # It is request message.
NLM_F_MULTI              = 2    # Multipart message, terminated by NLMSG_DONE
NLM_F_ACK                = 4    # Reply with ack, with zero or error code
NLM_F_ECHO               = 8    # Echo this request
# Modifiers to GET request
NLM_F_ROOT               = 0x100    # specify tree    root
NLM_F_MATCH              = 0x200    # return all matching
NLM_F_ATOMIC             = 0x400    # atomic GET
NLM_F_DUMP               = (NLM_F_ROOT|NLM_F_MATCH)
# Modifiers to NEW request
NLM_F_REPLACE            = 0x100    # Override existing
NLM_F_EXCL               = 0x200    # Do not touch, if it exists
NLM_F_CREATE             = 0x400    # Create, if it does not exist
NLM_F_APPEND             = 0x800    # Add to end of list


NLMSG_NOOP               = 0x1    # Nothing
NLMSG_ERROR              = 0x2    # Error
NLMSG_DONE               = 0x3    # End of a dump
NLMSG_OVERRUN            = 0x4    # Data lost
NLMSG_MIN_TYPE           = 0x10    # < 0x10: reserved control messages
NLMSG_MAX_LEN            = 0xffff# Max message length

NLMSG_ALIGNTO = 4
def NLMSG_ALIGN(l):
    return ( l + NLMSG_ALIGNTO - 1) & ~ (NLMSG_ALIGNTO - 1)

# 8<--------------------------------------------------------

class nlattr(Structure):
    """
    Netlink attribute header
    """
    _fields_ = [
        ("nla_len",     c_uint16),
        ("nla_type",    c_uint16),
    ]

class nlmsghdr(Structure):
    """
    Netlink message header
    """
    _fields_ = [
        ("length",             c_uint32),
        ("type",               c_uint16),
        ("flags",              c_uint16),
        ("sequence_number",    c_uint32),
        ("pid",                c_uint32),
    ]

class attr_msg(object):
    """
    Common routines to get and set Netlink attributes from/to a message.
    You can use this class as a base class along with ctypes'
    Structure/Union -- see nlattr and nlmsg classes
    """
    offset = None

    def size(self):
        return self.offset - addressof(self)

    def setup(self,offset,direct={},reverse={}):
        """
        Setup a message before parsing. One should provide the initial offset,
        direct and reverse attribute mappings.
        """
        self.offset = offset
        self.direct = direct
        self.reverse = reverse
        self.not_parsed_attrs = []

    def get_attr(self,type_map):
        """
        Get the next attribute. Raises an exception when there is no attributes
        left to read.

        TODO: turn it into a generator.
        """

        assert self.offset < addressof(self) + self.hdr.length

        hdr = nlattr.from_address(self.offset)
        ptr = self.offset
        self.offset += NLMSG_ALIGN(hdr.nla_len)

        if type_map.has_key(hdr.nla_type):
            return (type_map[hdr.nla_type][1],type_map[hdr.nla_type][0](ptr))
        else:
            if self.reverse.has_key(hdr.nla_type):
                self.not_parsed_attrs.append(self.reverse[hdr.nla_type])
            return None


    def set_attr(self,t,obj):
        """
        Set an attribute `obj` of type `t`. The type should be an integer
        that hdr.nla_type will be set to. Ths object should support ctypes'
        method sizeof()
        """
        class attr(Structure):
            pass

        # align block
        k = sizeof(nlattr) + sizeof(obj)
        align = NLMSG_ALIGN(k)
        pad = align - (sizeof(nlattr) + sizeof(obj))

        if pad:
            attr._fields_ = [("hdr",nlattr), ("data",type(obj)), ("pad",(c_ubyte * pad))]
        else:
            attr._fields_ = [("hdr",nlattr), ("data",type(obj))]


        if self.offset == None:
                self.offset = addressof(self.data)

        # prepare header
        a = attr.from_address(self.offset)
        a.hdr.nla_type = t
        a.hdr.nla_len = sizeof(attr)
        a.data = obj.value

        self.offset += sizeof(a)
        self.hdr.length = self.offset - addressof(self.hdr)

class nlmsg(Structure,attr_msg):
    """
    Netlink message structure
    """
    _fields_ = [
        ("hdr",         nlmsghdr),
        ("data",        c_byte * (NLMSG_MAX_LEN - sizeof(nlmsghdr))),
    ]


class nlmsgerr(Structure):
    """
    Error message structure
    """
    _fields_ = [
        ("code",        cx_int),
        ("hdr",         nlmsghdr),
    ]

class sockaddr(Structure):
    """
    Sockaddr structure, see bind(2)
    """
    _fields_ = [
        ("family", c_ushort),
        ("pad", c_ushort),
        ("pid", c_uint32),
        ("groups", c_uint32),
    ]

class nl_socket(object):
    """
    Netlink socket
    """
    fd = None    # socket file descriptor
    msg = nlmsg    # message pattern

    def __init__(self, family=NETLINK_GENERIC, groups=0):
        """
        Create and bind socket structure
        """
        self.fd = libc.socket(AF_NETLINK, SOCK_RAW, family)

        sa = sockaddr()
        sa.family = AF_NETLINK
        sa.pid = os.getpid()
        sa.groups = groups

        code = libc.bind(self.fd, byref(sa), sizeof(sa))
        if code:
            self.close()
            raise NetlinkError(code)

    def close(self):
        """
        Close the socket
        """
        libc.close(self.fd)

    def recv(self):
        """
        Receive a packet from Netlink socket (using recvfrom(2))
        """
        msg = self.msg()
        l = libc.recvfrom(self.fd, byref(msg), sizeof(msg), 0, 0, 0)

        if l == -1:
            msg = None
        else:
            if (msg.hdr.type == NLMSG_NOOP):
                msg = None
            elif (msg.hdr.type == NLMSG_ERROR):
                error = nlmsgerr.from_address(addressof(msg) + sizeof(nlmsghdr))
                raise NetlinkError(error.code, msg = "\nmsg dump:\n" + hline(msg,l), hdr=error.hdr)

        return (l,msg)

    def send(self, msg, size=0):
        """
        Send a packet through Netlink socket
        """

        if not size:
            size = sizeof(msg)

        sa = sockaddr()
        sa.family = AF_NETLINK
        sa.pid = 0

        self.prepare(msg, size)

        l = libc.sendto(self.fd, byref(msg), size, 0, byref(sa), sizeof(sa))
        return l

    def prepare(self, msg, size=0):
        """
        Adjust message header fields before sending
        """

        if not size:
            size = sizeof(msg)

        msg.hdr.length = size
        msg.hdr.pid = os.getpid()

__all__ = [
    "nlmsghdr",
    "nlmsg",
    "attr_msg",
    "nl_socket",
    "nlattr",
] + export_by_prefix("NL",globals()) + export_by_prefix("NETLINK",globals())
