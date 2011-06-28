"""
GeNetlink protocol
"""

#     Copyright (c) 2011 Peter V. Saveliev
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

from generic import *
import sys

GENL_NAMSIZ   = 16    # length of family name
GENL_MIN_ID   = NLMSG_MIN_TYPE
GENL_MAX_ID   = 1023

class genlmsghdr(Structure):
    _fields_ = [
        ("cmd",         c_ubyte),
        ("version",     c_ubyte),
        ("reserved",    c_uint16),
    ]

class genlmsg(Structure,attr_msg):
    _fields_ = [
        ("hdr",         nlmsghdr),
        ("genlmsghdr",  genlmsghdr),
        ("data",        c_byte * (NLMSG_MAX_LEN - sizeof(nlmsghdr) - sizeof(genlmsghdr))),
    ]

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

    def get_protocol_id(self,name):
        if sys.version_info >= (3,0):
            buf = create_string_buffer(bytes(name,"ascii"))
        else:
            buf = create_string_buffer(name)
        (l,msg) = self.send_cmd(GENL_ID_CTRL,CTRL_CMD_GETFAMILY,CTRL_ATTR_FAMILY_NAME,buf)
        name = nlattr.from_address(addressof(msg.data))
        prid = nlattr.from_address(addressof(msg.data) + NLMSG_ALIGN(name.nla_len))
        assert prid.nla_type == CTRL_ATTR_FAMILY_ID
        return c_uint16.from_address(addressof(prid) + sizeof(prid)).value


    def send_cmd(self,prid,cmd,nla_type,nla_data):
        msg = genlmsg()
        msg.hdr.type = prid
        msg.hdr.flags = NLM_F_REQUEST
        msg.hdr.seq = 0
        msg.genlmsghdr.cmd = cmd
        msg.genlmsghdr.version = 0x1
        msg.set_attr(nla_type,nla_data)
        self.send(msg,msg.size())
        return  self.recv()

