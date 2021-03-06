"""
ARP protocol primitives
"""

#     Copyright (c) 2008-2011 Peter V. Saveliev
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

from ctypes import BigEndianStructure
from ctypes import c_uint8, c_uint16
from cxnet.utils import make_map, export_by_prefix

## ARP protocol HARDWARE identifiers.
ARPHRD_NETROM        = 0    # from KA9Q: NET/ROM pseudo
ARPHRD_ETHER         = 1    # Ethernet 10Mbps
ARPHRD_EETHER        = 2    # Experimental Ethernet
ARPHRD_AX25          = 3    # AX.25 Level 2
ARPHRD_PRONET        = 4    # PROnet token ring
ARPHRD_CHAOS         = 5    # Chaosnet
ARPHRD_IEEE802       = 6    # IEEE 802.2 Ethernet/TR/TB
ARPHRD_ARCNET        = 7    # ARCnet
ARPHRD_APPLETLK      = 8    # APPLEtalk
ARPHRD_DLCI          = 15    # Frame Relay DLCI
ARPHRD_ATM           = 19    # ATM
ARPHRD_METRICOM      = 23    # Metricom STRIP (new IANA id)
ARPHRD_IEEE1394      = 24    # IEEE 1394 IPv4 - RFC 2734
ARPHRD_EUI64         = 27    # EUI-64
ARPHRD_INFINIBAND    = 32    # InfiniBand

## Dummy types for non ARP hardware
ARPHRD_SLIP          = 256
ARPHRD_CSLIP         = 257
ARPHRD_SLIP6         = 258
ARPHRD_CSLIP6        = 259
ARPHRD_RSRVD         = 260    # Notional KISS type
ARPHRD_ADAPT         = 264
ARPHRD_ROSE          = 270
ARPHRD_X25           = 271    # CCITT X.25
ARPHRD_HWX25         = 272    # Boards with X.25 in firmware
ARPHRD_PPP           = 512
ARPHRD_CISCO         = 513    # Cisco HDLC
ARPHRD_HDLC          = ARPHRD_CISCO
ARPHRD_LAPB          = 516    # LAPB
ARPHRD_DDCMP         = 517    # Digital's DDCMP protocol
ARPHRD_RAWHDLC       = 518    # Raw HDLC

ARPHRD_TUNNEL        = 768    # IPIP tunnel
ARPHRD_TUNNEL6       = 769    # IP6IP6 tunnel
ARPHRD_FRAD          = 770    # Frame Relay Access Device
ARPHRD_SKIP          = 771    # SKIP vif
ARPHRD_LOOPBACK      = 772    # Loopback device
ARPHRD_LOCALTLK      = 773    # Localtalk device
ARPHRD_FDDI          = 774    # Fiber Distributed Data Interface
ARPHRD_BIF           = 775    # AP1000 BIF
ARPHRD_SIT           = 776    # sit0 device - IPv6-in-IPv4
ARPHRD_IPDDP         = 777    # IP over DDP tunneller
ARPHRD_IPGRE         = 778    # GRE over IP
ARPHRD_PIMREG        = 779    # PIMSM register interface
ARPHRD_HIPPI         = 780    # High Performance Parallel Interface
ARPHRD_ASH           = 781    # Nexus 64Mbps Ash
ARPHRD_ECONET        = 782    # Acorn Econet
ARPHRD_IRDA          = 783    # Linux-IrDA
## ARP works differently on different FC media .. so
ARPHRD_FCPP          = 784    # Point to point fibrechannel
ARPHRD_FCAL          = 785    # Fibrechannel arbitrated loop
ARPHRD_FCPL          = 786    # Fibrechannel public loop
ARPHRD_FCFABRIC      = 787    # Fibrechannel fabric
## 787->799 reserved for fibrechannel media types
ARPHRD_IEEE802_TR    = 800    # Magic type ident for TR
ARPHRD_IEEE80211     = 801    # IEEE 802.11
ARPHRD_IEEE80211_PRISM     = 802    # IEEE 802.11 + Prism2 header
ARPHRD_IEEE80211_RADIOTAP  = 803    # IEEE 802.11 + radiotap header
ARPHRD_MPLS_TUNNEL         = 899    # MPLS Tunnel Interface

ARPHRD_VOID          = 0xFFFF    # Void type, nothing is known
ARPHRD_NONE          = 0xFFFE    # zero header length

(M_ARPHRD_MAP, M_ARPHRD_REVERSE) = make_map("ARPHRD_",globals())

## ARP protocol opcodes.
ARPOP_REQUEST        = 1    # ARP request
ARPOP_REPLY          = 2    # ARP reply
ARPOP_RREQUEST       = 3    # RARP request
ARPOP_RREPLY         = 4    # RARP reply
ARPOP_InREQUEST      = 8    # InARP request
ARPOP_InREPLY        = 9    # InARP reply
ARPOP_NAK            = 10    # (ATM)ARP NAK


## ARP Flag values.
ATF_COM         = 0x02    # completed entry (ha valid)
ATF_PERM        = 0x04    # permanent entry
ATF_PUBL        = 0x08    # publish entry
ATF_USETRAILERS = 0x10    # has requested trailers
ATF_NETMASK     = 0x20    # want to use a netmask (only for proxy entries)
ATF_DONTPUB     = 0x40    # don't answer this addresses

##
#    This structure defines an ethernet arp header.
##

class arphdr (BigEndianStructure):
    _fields_ = [
        ("hrd",    c_uint16),    # format of hardware address
        ("pro",    c_uint16),    # format of protocol address
        ("hln",    c_uint8),     # length of hardware address
        ("pln",    c_uint8),     # length of protocol address
        ("op",     c_uint16),    # ARP opcode (command)
    ]

__all__ = [
    "arphdr",
] + export_by_prefix("ARP",globals()) +\
    export_by_prefix("ATF",globals()) +\
    export_by_prefix("M_",globals())
