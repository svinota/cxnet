"""
RT Netlink protocol
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

from socket import htonl

from generic import *
from cxnet.common import *
from cxnet.arp import *
from cxnet.utils import dqn_to_int
import types

from os import listdir

##  RTnetlink multicast groups
RTNLGRP_NONE = 0x0
RTNLGRP_LINK = 0x1
RTNLGRP_NOTIFY = 0x2
RTNLGRP_NEIGH = 0x4
RTNLGRP_TC = 0x8
RTNLGRP_IPV4_IFADDR = 0x10
RTNLGRP_IPV4_MROUTE = 0x20
RTNLGRP_IPV4_ROUTE = 0x40
RTNLGRP_IPV4_RULE = 0x80
RTNLGRP_IPV6_IFADDR = 0x100
RTNLGRP_IPV6_MROUTE = 0x200
RTNLGRP_IPV6_ROUTE = 0x400
RTNLGRP_IPV6_IFINFO = 0x800
RTNLGRP_DECnet_IFADDR = 0x1000
RTNLGRP_NOP2 = 0x2000
RTNLGRP_DECnet_ROUTE = 0x4000
RTNLGRP_DECnet_RULE = 0x8000
RTNLGRP_NOP4 = 0x10000
RTNLGRP_IPV6_PREFIX = 0x20000
RTNLGRP_IPV6_RULE = 0x40000


## Types of messages
RTM_BASE         = 16
RTM_NEWLINK      = 16
RTM_DELLINK      = 17
RTM_GETLINK      = 18
RTM_SETLINK      = 19
RTM_NEWADDR      = 20
RTM_DELADDR      = 21
RTM_GETADDR      = 22
RTM_NEWROUTE     = 24
RTM_DELROUTE     = 25
RTM_GETROUTE     = 26
RTM_NEWNEIGH     = 28
RTM_DELNEIGH     = 29
RTM_GETNEIGH     = 30
RTM_NEWRULE      = 32
RTM_DELRULE      = 33
RTM_GETRULE      = 34
RTM_NEWQDISC     = 36
RTM_DELQDISC     = 37
RTM_GETQDISC     = 38
RTM_NEWTCLASS    = 40
RTM_DELTCLASS    = 41
RTM_GETTCLASS    = 42
RTM_NEWTFILTER   = 44
RTM_DELTFILTER   = 45
RTM_GETTFILTER   = 46
RTM_NEWACTION    = 48
RTM_DELACTION    = 49
RTM_GETACTION    = 50
RTM_NEWPREFIX    = 52
RTM_GETMULTICAST = 58
RTM_GETANYCAST   = 62
RTM_NEWNEIGHTBL  = 64
RTM_GETNEIGHTBL  = 66
RTM_SETNEIGHTBL  = 67


class rtnl_hdr(Structure):
    _fields_ = [
        ("length",  c_ushort),
        ("type",    c_ushort),
    ]

# 8<------------------------------------------------------------------------
class ifaddrmsg(Structure):
    _fields_ = [
        ("family",    c_ubyte),    # Address family
        ("prefixlen", c_ubyte),    # Address' prefix length
        ("flags",     c_ubyte),    # Address flags
        ("scope",     c_ubyte),    # Adress scope
        ("index",     c_int),      # Interface index
    ]

class ifinfmsg(Structure):
    _fields_ = [
        ("family",   c_ubyte),      # AF_UNSPEC (?)
        ("type",     c_uint16),     # Interface type
        ("index",    c_int),        # Interface index
        ("flags",    c_int),        # Interface flags (netdevice(7))
        ("change",   c_int),        # Change mask (reserved, always 0xFFFFFFFF)
    ]

class ndmsg(Structure):
    _fields_ = [
        ("family",   c_ubyte),    # 
        ("index",    c_int),      # Interface index
        ("state",    c_uint16),   # Neighbor entry state
        ("flags",    c_uint8),    # Neighbor entry flags
        ("type",     c_uint8),    #
    ]

class rtmsg(Structure):    # kernel://ipv4/route.c:2565 static int rt_fill_info(...)
    _fields_ = [
        ("family",   c_ubyte),    # Route address family
        ("dst_len",  c_ubyte),    # Destination address mask
        ("src_len",  c_ubyte),    # Source address mask
        ("tos",      c_ubyte),    # TOS filter
        ("table",    c_ubyte),    # Routing table id
        ("proto",    c_ubyte),    # Routing protocol
        ("scope",    c_ubyte),
        ("type",     c_ubyte),
        ("flags",    c_int32),
    ]

# 8<------------------------------------------------------------------------

class rtnl_payload(Union):
    _fields_ = [
        ("link",     ifinfmsg),
        ("address",  ifaddrmsg),
        ("route",    rtmsg),
        ("neigh",    ndmsg),
        ("raw",      (c_byte * NLMSG_MAX_LEN)),
    ]

class rtnl_msg(Structure,attr_msg):
    _fields_ = [
        ("hdr",      nlmsghdr),
        ("data",     rtnl_payload),
    ]


class rtnl_socket(nl_socket):
    """
    Netlink RT socket implementation
    """
    msg = rtnl_msg

    def __init__(self,groups = 0):
        nl_socket.__init__(self, family=NETLINK_ROUTE, groups=groups)


###
# attribute types
###

def t_ip4ad(address):
    r = (c_uint8 * 4).from_address(address + sizeof(nlattr))
    return "%u.%u.%u.%u" % (r[0], r[1], r[2], r[3])
def t_l2ad(address):
    r = (c_uint8 * 6).from_address(address + sizeof(nlattr))
    return "%x:%x:%x:%x:%x:%x" % (r[0], r[1], r[2], r[3], r[4], r[5])
def t_uint(address):
    return c_uint.from_address(address + sizeof(nlattr)).value
def t_uint8(address):
    return c_uint8.from_address(address + sizeof(nlattr)).value
def t_uint32(address):
    return c_uint32.from_address(address + sizeof(nlattr)).value
def t_asciiz(address):
    return string_at(address + sizeof(nlattr))
def t_state(address):
    return M_IF_OPER_REVERSE[c_uint8.from_address(address + sizeof(nlattr)).value][8:]
def t_ifmap(address):
    r = rtnl_link_ifmap.from_address(address + sizeof(nlattr))
    return str({
        "mem_start":    r.mem_start,
        "mem_end":      r.mem_end,
        "base_addr":    r.base_addr,
        "irq":          r.irq,
        "dma":          r.dma,
        "port":         r.port,
    })
def t_none(address):
    return None

def r_ip4ad(text):
    return c_uint32(htonl(dqn_to_int(text)))
def r_asciiz(text):
    return create_string_buffer(text)

## address attributes
#
# Important comment:
# IFA_ADDRESS is prefix address, rather than local interface address.
# It makes no difference for normally configured broadcast interfaces,
# but for point-to-point IFA_ADDRESS is DESTINATION address,
# local address is supplied in IFA_LOCAL attribute.
#
IFA_UNSPEC    = 0
IFA_ADDRESS    = 1
IFA_LOCAL    = 2
IFA_LABEL    = 3
IFA_BROADCAST    = 4
IFA_ANYCAST    = 5
IFA_CACHEINFO    = 6
IFA_MULTICAST    = 7

(M_IFA_MAP, M_IFA_REVERSE) = make_map("IFA_",globals())

t_ifa_attr = {
            IFA_UNSPEC:     (t_none,    "none"),
            IFA_ADDRESS:    (t_ip4ad,   "address"),
            IFA_LOCAL:      (t_ip4ad,   "local"),
            IFA_LABEL:      (t_asciiz,  "dev"),
            IFA_BROADCAST:  (t_ip4ad,   "broadcast"),
            IFA_ANYCAST:    (t_ip4ad,   "anycast"),
            IFA_CACHEINFO:  (t_none,    "cacheinfo"),
            IFA_MULTICAST:  (t_ip4ad,   "multycast"),
        }

r_ifa_attr = {
            "address":      (r_ip4ad,   IFA_ADDRESS),
            "local":        (r_ip4ad,   IFA_LOCAL),
            "dev":          (r_asciiz,  IFA_LABEL),
            "broadcast":    (r_ip4ad,   IFA_BROADCAST),
            "anycast":      (r_ip4ad,   IFA_ANYCAST),
            "multycast":    (r_ip4ad,   IFA_MULTICAST),
        }

## neighbor attributes
NDA_UNSPEC    = 0
NDA_DST        = 1
NDA_LLADDR    = 2
NDA_CACHEINFO    = 3
NDA_PROBES    = 4

(M_NDA_MAP, M_NDA_REVERSE) = make_map("NDA_",globals())

t_nda_attr = {
            NDA_UNSPEC:    (t_none,    "none"),
            NDA_DST:       (t_ip4ad,   "dest"),
            NDA_LLADDR:    (t_l2ad,    "lladdr"),
            NDA_CACHEINFO: (t_none,    "cacheinfo"),
            NDA_PROBES:    (t_none,    "probes"),
        }


## route attributes
RTA_UNSPEC     = 0
RTA_DST        = 1
RTA_SRC        = 2
RTA_IIF        = 3
RTA_OIF        = 4
RTA_GATEWAY    = 5
RTA_PRIORITY   = 6
RTA_PREFSRC    = 7
RTA_METRICS    = 8
RTA_MULTIPATH  = 9
RTA_PROTOINFO  = 10
RTA_FLOW       = 11
RTA_CACHEINFO  = 12    # FIXME: kernel://include/linux/rtnetlink.h:320, struct rta_cacheinfo
RTA_SESSION    = 13
RTA_MP_ALGO    = 14    # no longer used
RTA_TABLE      = 15

(M_RTA_MAP, M_RTA_REVERSE) = make_map("RTA_",globals())


## rtmsg.type
RTN_UNSPEC     = 0
RTN_UNICAST    = 1    # Gateway or direct route
RTN_LOCAL      = 2    # Accept locally
RTN_BROADCAST  = 3    # Accept locally as broadcast, send as broadcast
RTN_ANYCAST    = 4    # Accept locally as broadcast, but send as unicast
RTN_MULTICAST  = 5    # Multicast route
RTN_BLACKHOLE  = 6    # Drop
RTN_UNREACHABLE= 7    # Destination is unreachable
RTN_PROHIBIT   = 8    # Administratively prohibited
RTN_THROW      = 9    # Not in this table
RTN_NAT        = 10    # Translate this address
RTN_XRESOLVE   = 11    # Use external resolver

## rtmsg.proto
RTPROT_UNSPEC    = 0
RTPROT_REDIRECT  = 1    # Route installed by ICMP redirects; not used by current IPv4
RTPROT_KERNEL    = 2    # Route installed by kernel
RTPROT_BOOT      = 3    # Route installed during boot
RTPROT_STATIC    = 4    # Route installed by administrator
# Values of protocol >= RTPROT_STATIC are not interpreted by kernel;
# they are just passed from user and back as is.
# It will be used by hypothetical multiple routing daemons.
# Note that protocol values should be standardized in order to
# avoid conflicts.
RTPROT_GATED     = 8    # Apparently, GateD
RTPROT_RA        = 9    # RDISC/ND router advertisements
RTPROT_MRT       = 10    # Merit MRT
RTPROT_ZEBRA     = 11    # Zebra
RTPROT_BIRD      = 12    # BIRD
RTPROT_DNROUTED  = 13    # DECnet routing daemon
RTPROT_XORP      = 14    # XORP
RTPROT_NTK       = 15    # Netsukuku

## rtmsg.scope
RT_SCOPE_UNIVERSE    = 0
# User defined values
RT_SCOPE_SITE        = 200
RT_SCOPE_LINK        = 253
RT_SCOPE_HOST        = 254
RT_SCOPE_NOWHERE     = 255

## rtmsg.flags
RTM_F_NOTIFY    = 0x100    # Notify user of route change
RTM_F_CLONED    = 0x200    # This route is cloned
RTM_F_EQUALIZE  = 0x400    # Multipath equalizer: NI
RTM_F_PREFIX    = 0x800    # Prefix addresses

t_rta_attr = {
            RTA_UNSPEC:   (t_none,    "none"),
            RTA_DST:      (t_ip4ad,   "dst_prefix"),
            RTA_SRC:      (t_ip4ad,   "src_prefix"),
            RTA_IIF:      (t_uint,    "input_link"),
            RTA_OIF:      (t_uint,    "output_link"),
            RTA_GATEWAY:  (t_ip4ad,   "gateway"),
            RTA_PRIORITY: (t_uint,    "priority"),
            RTA_PREFSRC:  (t_ip4ad,   "prefsrc"),
            RTA_METRICS:  (t_uint,    "metric"),
            RTA_MULTIPATH:(t_none,    "mp"),
            RTA_PROTOINFO:(t_none,    "protoinfo"),
            RTA_FLOW:     (t_none,    "flow"),
            RTA_CACHEINFO:(t_none,    "cacheinfo"),
            RTA_SESSION:  (t_none,    "session"),
            RTA_MP_ALGO:  (t_none,    "mp_algo"), # no longer used
            RTA_TABLE:    (t_uint,    "table"),
        }



## link attributes
IFLA_UNSPEC     = 0
IFLA_ADDRESS    = 1
IFLA_BROADCAST  = 2
IFLA_IFNAME     = 3
IFLA_MTU        = 4
IFLA_LINK       = 5
IFLA_QDISC      = 6
IFLA_STATS      = 7
IFLA_COST       = 8
IFLA_PRIORITY   = 9
IFLA_MASTER     = 10
IFLA_WIRELESS   = 11 # Wireless Extension event - see iproute2:wireless.h 
IFLA_PROTINFO   = 12 # Protocol specific information for a link
IFLA_TXQLEN     = 13
IFLA_MAP        = 14
IFLA_WEIGHT     = 15
IFLA_OPERSTATE  = 16
IFLA_LINKMODE   = 17

IF_OPER_UNKNOWN         = 0
IF_OPER_NOTPRESENT      = 1
IF_OPER_DOWN            = 2
IF_OPER_LOWERLAYERDOWN  = 3
IF_OPER_TESTING         = 4
IF_OPER_DORMANT         = 5
IF_OPER_UP              = 6

(M_IF_OPER_MAP,  M_IF_OPER_REVERSE)   = make_map("IF_OPER_",globals())
(M_IFLA_MAP,     M_IFLA_REVERSE)      = make_map("IFLA_",globals())

class rtnl_link_ifmap(Structure):
    _fields_ = [
        ("mem_start",   c_uint64),
        ("mem_end",     c_uint64),
        ("base_addr",   c_uint64),
        ("irq",         c_uint16),
        ("dma",         c_uint8),
        ("port",        c_uint8),
    ]

t_ifla_attr = {
            IFLA_UNSPEC:    (t_none,        "none"),
            IFLA_ADDRESS:   (t_l2ad,        "hwaddr"),
            IFLA_BROADCAST: (t_l2ad,        "broadcast"),
            IFLA_IFNAME:    (t_asciiz,      "dev"),
            IFLA_MTU:       (t_uint,        "mtu"),
            IFLA_LINK:      (t_uint,        "link"),
            IFLA_QDISC:     (t_asciiz,      "qdisc"),
            IFLA_STATS:     (t_none,        "stats"),
            IFLA_OPERSTATE: (t_state,       "state"),
            IFLA_TXQLEN:    (t_uint32,      "txqlen"),
            IFLA_LINKMODE:  (t_uint8,       "linkmode"),
            IFLA_MAP:       (t_ifmap,       "ifmap"),
        }


## netdevice flags
iff = {}
iff["UP"]           = 0x1    # interface is up
iff["BROADCAST"]    = 0x2    # broadcast address valid
iff["DEBUG"]        = 0x4    # turn on debugging
iff["LOOPBACK"]     = 0x8    # is a loopback net
iff["POINTOPOINT"]  = 0x10    # interface is has p-p link
iff["NOTRAILERS"]   = 0x20    # avoid use of trailers
iff["RUNNING"]      = 0x40    # resources allocated
iff["NOARP"]        = 0x80    # no ARP protocol
iff["PROMISC"]      = 0x100    # receive all packets
iff["ALLMULTI"]     = 0x200    # receive all multicast packets
iff["MASTER"]       = 0x400    # master of a load balancer
iff["SLAVE"]        = 0x800    # slave of a load balancer
iff["MULTICAST"]    = 0x1000# supports multicast
iff["PORTSEL"]      = 0x2000# can set media type
iff["AUTOMEDIA"]    = 0x4000# auto media select active
iff["DYNAMIC"]      = 0x8000# dialup device with changing addresses



class rtnl_msg_parser(object):
    """
    Generic RT Netlink attribute parser
    """

    tmap = {
        "add":  {
            "address":  RTM_NEWADDR,
            },
        "del":  {
            "address":  RTM_DELADDR,
            }
    }


    def create(self,p):
        msg = rtnl_msg()
        t = msg.hdr.type = self.tmap[p["action"]][p["type"]]

        if \
            t <= RTM_DELLINK:
                raise NotImplemented()
        elif \
            t <= RTM_DELADDR:
                if len(p["local"].split(".")) == 4:
                    # FIXME! must NOT be hardcoded
                    msg.data.address.family = 0x2
                else:
                    raise NotImplemented()
                msg.data.address.prefixlen = p["mask"]
                msg.data.address.index = p["index"]
                if not p.has_key("scope") and p["address"][:3] == "127":
                    # FIXME! must NOT be hardcoded
                    msg.data.address.scope = 0xfe
                bias = ifaddrmsg
                at = r_ifa_attr
        else:
            raise NotImplemented()

        msg.setup( addressof(msg) + sizeof(nlmsghdr) + sizeof(bias) )

        b = dict(p)
        [ b.__delitem__(x) for x in ["action","type","mask","index"] ]

        [ msg.set_attr(at[i][1], at[i][0](k)) for i,k in b.items() ]

        return msg

    def parse(self,msg):
        r = {}
        t = msg.hdr.type

        aa = [RTM_NEWADDR,RTM_NEWLINK,RTM_NEWROUTE,RTM_NEWNEIGH]
        ad = [RTM_DELADDR,RTM_DELLINK,RTM_DELROUTE,RTM_DELNEIGH]

        direct = {}
        reverse = {}

        ## message type
        if \
            t <= RTM_DELLINK:
            r["type"] = "link"
            r["link_type"] = M_ARPHRD_REVERSE[msg.data.link.type]
            r["index"] = msg.data.link.index
            r["flags"] = []
            for (i,k) in iff.items():
                if k & msg.data.link.flags:
                    r["flags"].append(i)

            bias = ifinfmsg
            at = t_ifla_attr
            direct = M_IFLA_MAP
            reverse = M_IFLA_REVERSE
        elif \
            t <= RTM_DELADDR:
            r["type"] = "address"
            r["mask"] = msg.data.address.prefixlen
            r["index"] = msg.data.address.index
            bias = ifaddrmsg
            at = t_ifa_attr
            direct = M_IFA_MAP
            reverse = M_IFA_REVERSE
        elif \
            t <= RTM_DELROUTE:
            r["type"] = "route"
            r["dst_len"] = msg.data.route.dst_len
            r["src_len"] = msg.data.route.src_len
            r["t"] = msg.data.route.table
            bias = rtmsg
            at = t_rta_attr
        elif \
            t <= RTM_GETNEIGH:
            r["type"] = "neigh"
            r["index"] = msg.data.neigh.index
            bias = ndmsg
            at = t_nda_attr
        else:
            r["type"] = "fake"
            r["action"] = "fake"
            return r

        ## message action
        if t in aa:
            r["action"] = "add"
        elif t in ad:
            r["action"] = "del"

        msg.setup(addressof(msg) + sizeof(nlmsghdr) + sizeof(bias),direct,reverse)

        try:
            while True:
                ret = msg.get_attr(at)
                if ret is not None:
                    r[ret[0]] = ret[1]
        except:
            pass

        if len(msg.not_parsed_attrs):
            r["not_parsed"] = str(msg.not_parsed_attrs)

        if r.has_key('dev'):
            ###
            # find a PPP session for this device
            ###
            if r["dev"][:3] == "ppp":
                # list all PPP session files in /var/run
                # FIXME: see new FHS
                for i in listdir("/var/run"):
                    if (i[:3] == "ppp") and (i[-3:] == "pid"):
                        try:
                            fd = open("/var/run/%s" % (i),"r")
                            for m in fd.readlines():
                                m = m.strip()
                                if m == r["dev"]:
                                    r["session"] = i[4:-4]
                            fd.close()
                        except:
                            pass

        if r['type'] == 'link' and not r.has_key('dev'):
            r = None

        return r
