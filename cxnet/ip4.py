"""
IP definitions from linux/ip.h
"""

#     Copyright (c) 2008-2011 Peter V. Saveliev <peet@altlinux.ru>
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
from cxnet.generic import *
from cxnet.common import csum

#
# Type of service mask
#
IPTOS_TOS_MASK                  = 0x1E
IPTOS_LOWDELAY                  = 0x10
IPTOS_THROUGHPUT                = 0x08
IPTOS_RELIABILITY               = 0x04
IPTOS_MINCOST                   = 0x02
IPTOS_PREC_MASK                 = 0xE0
IPTOS_PREC_NETCONTROL           = 0xe0
IPTOS_PREC_INTERNETCONTROL      = 0xc0
IPTOS_PREC_CRITIC_ECP           = 0xa0
IPTOS_PREC_FLASHOVERRIDE        = 0x80
IPTOS_PREC_FLASH                = 0x60
IPTOS_PREC_IMMEDIATE            = 0x40
IPTOS_PREC_PRIORITY             = 0x20
IPTOS_PREC_ROUTINE              = 0x00

#
# IP options
#
IPOPT_COPY          = 0x80
IPOPT_CLASS_MASK    = 0x60
IPOPT_NUMBER_MASK   = 0x1f
IPOPT_CONTROL       = 0x00
IPOPT_RESERVED1     = 0x20
IPOPT_MEASUREMENT   = 0x40
IPOPT_RESERVED2     = 0x60

IPOPT_END       = (0 |IPOPT_CONTROL)
IPOPT_NOOP      = (1 |IPOPT_CONTROL)
IPOPT_SEC       = (2 |IPOPT_CONTROL|IPOPT_COPY)
IPOPT_LSRR      = (3 |IPOPT_CONTROL|IPOPT_COPY)
IPOPT_TIMESTAMP = (4 |IPOPT_MEASUREMENT)
IPOPT_CIPSO     = (6 |IPOPT_CONTROL|IPOPT_COPY)
IPOPT_RR        = (7 |IPOPT_CONTROL)
IPOPT_SID       = (8 |IPOPT_CONTROL|IPOPT_COPY)
IPOPT_SSRR      = (9 |IPOPT_CONTROL|IPOPT_COPY)
IPOPT_RA        = (20|IPOPT_CONTROL|IPOPT_COPY)
IPOPT_OPTVAL    = 0
IPOPT_OLEN      = 1
IPOPT_OFFSET    = 2
IPOPT_MINOFF    = 4
IPOPT_NOP       = IPOPT_NOOP
IPOPT_EOL       = IPOPT_END
IPOPT_TS        = IPOPT_TIMESTAMP
IPOPT_TS_TSONLY     = 0 # timestamps only
IPOPT_TS_TSANDADDR  = 1 # timestamps and addresses
IPOPT_TS_PRESPEC    = 3 # specified modules only
MAX_IPOPTLEN    = 40

#
#
#
IPVERSION           = 4
MAXTTL              = 255
IPDEFTTL            = 64
IPV4_BEET_PHMAXLEN  = 8


def iptos_tos(tos):
    return tos & IPTOS_TOS_MASK
def iptos_prec(tos):
    return tos & IPTOS_PREC_MASK
def ipopt_copied(o):
    return o & IPOPT_COPY
def ipopt_class(o):
    return o & IPOPT_CLASS_MASK
def ipopt_number(o):
    return o & IPOPT_NUMBER_MASK

class iphdr (BigEndianStructure):
    _fields_ = [
        ("version",    c_uint8,     4),    # first 4 bits
        ("ihl",        c_uint8,     4),    # ...
        ("tos",        c_uint8),
        ("tot_len",    c_uint16),
        ("id",         c_uint16),
        ("f_res",      c_uint16,    1),
        ("f_DF",       c_uint16,    1),
        ("f_MF",       c_uint16,    1),
        ("frag_off",   c_uint16,    13),
        ("ttl",        c_uint8),
        ("protocol",   c_uint8),
        ("check",      c_uint16),
        ("saddr",      c_uint32),
        ("daddr",      c_uint32),
    ]

    def __init__(self):
        BigEndianStructure.__init__(self)
        self.version = 4
        self.ttl = 64
        self.id = 0

class ip_auth_hdr (BigEndianStructure):
    _fields_ = [
        ("nexthdr",     c_uint8),
        ("hdrlen",      c_uint8),        # This one is measured in 32 bit units!
        ("reserved",    c_uint16),
        ("spi",         c_uint32),
        ("seq_no",      c_uint32),       # Sequence number
        ("auth_data",   c_uint8 * 4),    # Variable len but >=4. Mind the 64 bit alignment!
    ]

class ip_esp_hdr (BigEndianStructure):
    _fields_ = [
        ("spi",         c_uint32),
        ("seq_no",      c_uint32),       # Sequence number
        ("enc_data",    c_uint8 * 8),    # Variable len but >=8. Mind the 64 bit alignment!
    ]

class ip_comp_hdr (BigEndianStructure):
    _fields_ = [
        ("nexthdr",     c_uint8),
        ("flags",       c_uint8),
        ("cpi",         c_uint16),
    ]

class ip_beet_phdr (BigEndianStructure):
    _fields_ = [
        ("nexthdr",     c_uint8),
        ("hdrlen",      c_uint8),
        ("padlen",      c_uint8),
        ("reserved",    c_uint8),
    ]

class IPv4Protocol(GenericProtocol):

    def post(self,msg):
        msg.hdr.ihl = sizeof(msg.hdr) // 4
        msg.hdr.tot_len = sizeof(msg.payload) + sizeof(msg.hdr)
        msg.hdr.check = 0
        msg.hdr.check = csum(msg.hdr,sizeof(msg.hdr))
        return msg

