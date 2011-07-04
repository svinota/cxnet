"""
Generic Netlink protocol implementation
"""

#     Copyright (c) 2007-2011 ALT Linux, Peter V. Saveliev
#
#     This file is part of Connexion project.
#
#     Connexion is free software; you can redistribute it and/or modify
#     it under the terms of the GNU General Public License as published by
#     the Free Software Foundation; either version 3 of the License, or
#     (at your option) any later version.
#
#     Connexion is distributed in the hope that it will be useful,
#     but WITHOUT ANY WARRANTY; without even the implied warranty of
#     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#     GNU General Public License for more details.
#
#     You should have received a copy of the GNU General Public License
#     along with Connexion; if not, write to the Free Software
#     Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA

from ctypes import *
from cxnet.common import *
from socket import AF_NETLINK, SOCK_RAW

from os import getpid

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
#
# structures for recvmsg(2) support
#
class iov(Structure):
    _fields_ = [
        ("buf",cx_int),
        ("size",cx_int),
    ]

class rmsg(Structure):
    _fields_ = [
        ("sa_addr",cx_int),
        ("sa_size",cx_int),
        ("iov_addr",cx_int),
        ("x1",cx_int),
        ("x2",cx_int),
        ("x3",cx_int),
        ("x4",cx_int),
    ]
# 8<--------------------------------------------------------

class nlattr(Structure):
    _fields_ = [
        ("nla_len",     c_uint16),
        ("nla_type",    c_uint16),
    ]

class nlmsghdr(Structure):
    """
    Generic Netlink message header
    """
    _fields_ = [
        ("length",             c_uint32),
        ("type",               c_uint16),
        ("flags",              c_uint16),
        ("sequence_number",    c_uint32),
        ("pid",                c_uint32),
    ]

class attr_msg(object):
    __offset = None

    def size(self):
        return self.__offset - addressof(self)

    def set_offset(self,offset):
        self.__offset = offset

    def get_offset(self):
        return self.__offset

    def get_attr(self,type_map):

        if self.__offset >= addressof(self) + self.hdr.length:
            return None

        hdr = nlattr.from_address(self.__offset)
        ptr = self.__offset
        self.__offset += NLMSG_ALIGN(hdr.nla_len)

        try:
            return (type_map[hdr.nla_type][1],type_map[hdr.nla_type][0](ptr))
        except KeyError:
            return (None,None)


    def set_attr(self,typ,obj):
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


        if self.__offset == None:
                self.__offset = addressof(self.data)

        # prepare header
        a = attr.from_address(self.__offset)
        a.hdr.nla_type = typ
        a.hdr.nla_len = sizeof(attr)
        a.data = obj.value

        self.__offset += sizeof(a)
        self.hdr.length = self.__offset - addressof(self.hdr)

class nlmsg(Structure,attr_msg):
    """
    Generic Netlink message structure
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
    Generic Netlink socket
    """
    fd = None    # socket file descriptor
    msg = nlmsg    # message pattern

    def __init__(self, family=NETLINK_GENERIC, groups=0):
        """
        Create and bind socket structure
        """
        self.fd = libc.socket(AF_NETLINK,SOCK_RAW,family)

        sa = sockaddr()
        sa.family = AF_NETLINK
        sa.pid = getpid()
        sa.groups = groups

        l = libc.bind(self.fd, byref(sa), sizeof(sa))
        if l != 0:
            self.close()
            raise Exception("libc.bind(): errcode %i" % (l))

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
                error = nlmsgerr.from_address(addressof(msg.data))
                raise Exception("Netlink error %i" % (error.code))

        return (l,msg)

    def recv2(self):
        """
        Receive a packet from Netlink socket (using recvmsg(2))
        """
        buf = self.msg()
        i = iov(addressof(buf),sizeof(buf))
        sa = sockaddr()
        msg = rmsg(addressof(sa),sizeof(sa),addressof(i),1,0,0,0)
        l = libc.recvmsg(self.fd, byref(msg), 0)
        if l == -1:
            msg = None

        return (l,buf)



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
        msg.hdr.pid = getpid()
