# -*- coding: utf-8 -*-
"""
    cxnet.netlink.generic
    ~~~~~~~~~~~~~~~~~~~~~

    This module implements generic Netlink socket object.

    :copyright: (c) 2011 by Peter V. Saveliev, see AUTHORS for more details.
    :license: GPL, see LICENSE for more details.
"""

from __future__ import absolute_import

import sys
from ctypes import Structure
from ctypes import sizeof, create_string_buffer, addressof
from ctypes import c_byte, c_ubyte, c_uint16
from .core import nlmsghdr, nl_socket, nlattr, attr_msg, NLM_F_REQUEST, \
    NLMSG_MAX_LEN, NLMSG_MIN_TYPE, NLMSG_ALIGN


class genlmsghdr(Structure):
    _fields_ = [
        ("cmd",         c_ubyte),
        ("version",     c_ubyte),
        ("reserved",    c_uint16),
    ]


class genlmsg(Structure, attr_msg):
    _fields_ = [
        ("hdr",         nlmsghdr),
        ("genlmsghdr",  genlmsghdr),
        ("data",        c_byte * (NLMSG_MAX_LEN - sizeof(nlmsghdr) - sizeof(genlmsghdr))),
    ]


GENL_NAMSIZ   = 16    # length of family name
GENL_MIN_ID   = NLMSG_MIN_TYPE
GENL_MAX_ID   = 1023

GENL_HDRLEN         = NLMSG_ALIGN(sizeof(genlmsghdr))
GENL_ADMIN_PERM     = 0x01
GENL_CMD_CAP_DO     = 0x02
GENL_CMD_CAP_DUMP   = 0x04
GENL_CMD_CAP_HASPOL = 0x08

#
# List of reserved static generic netlink identifiers:
#
GENL_ID_GENERATE    = 0
GENL_ID_CTRL        = NLMSG_MIN_TYPE

#
# Controller
#

CTRL_CMD_UNSPEC         = 0x0
CTRL_CMD_NEWFAMILY      = 0x1
CTRL_CMD_DELFAMILY      = 0x2
CTRL_CMD_GETFAMILY      = 0x3
CTRL_CMD_NEWOPS         = 0x4
CTRL_CMD_DELOPS         = 0x5
CTRL_CMD_GETOPS         = 0x6
CTRL_CMD_NEWMCAST_GRP   = 0x7
CTRL_CMD_DELMCAST_GRP   = 0x8
CTRL_CMD_GETMCAST_GRP   = 0x9 # unused


CTRL_ATTR_UNSPEC        = 0x0
CTRL_ATTR_FAMILY_ID     = 0x1
CTRL_ATTR_FAMILY_NAME   = 0x2
CTRL_ATTR_VERSION       = 0x3
CTRL_ATTR_HDRSIZE       = 0x4
CTRL_ATTR_MAXATTR       = 0x5
CTRL_ATTR_OPS           = 0x6
CTRL_ATTR_MCAST_GROUPS  = 0x7

CTRL_ATTR_OP_UNSPEC     = 0x0
CTRL_ATTR_OP_ID         = 0x1
CTRL_ATTR_OP_FLAGS      = 0x2

CTRL_ATTR_MCAST_GRP_UNSPEC  = 0x0
CTRL_ATTR_MCAST_GRP_NAME    = 0x1
CTRL_ATTR_MCAST_GRP_ID      = 0x2


class genl_socket(nl_socket):

    msg = genlmsg

    def get_protocol_id(self, name):
        if sys.version_info >= (3, 0):
            buf = create_string_buffer(name.encode("utf-8"))
        else:
            buf = create_string_buffer(name)

        self.send_cmd(GENL_ID_CTRL, CTRL_CMD_GETFAMILY,
                      CTRL_ATTR_FAMILY_NAME, buf)
        l, msg = self.recv()
        name = nlattr.from_address(addressof(msg.data))
        prid = nlattr.from_address(addressof(msg.data) +
                                   NLMSG_ALIGN(name.nla_len))
        assert prid.nla_type == CTRL_ATTR_FAMILY_ID
        return c_uint16.from_address(addressof(prid) + sizeof(prid)).value

    def send_cmd(self, prid, cmd, nla_type, nla_data, seq=0):
        msg = genlmsg()
        msg.hdr.type = prid
        msg.hdr.flags = NLM_F_REQUEST
        msg.hdr.sequence_number = seq
        msg.genlmsghdr.cmd = cmd
        msg.genlmsghdr.version = 0x1
        msg.set_attr(nla_type, nla_data)
        return self.send(msg, msg.size())
