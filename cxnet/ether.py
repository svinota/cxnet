"""
Ethernet definitions from if_ether.h
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
from cxnet.utils import export_by_prefix

##
#    IEEE 802.3 Ethernet magic constants.  The frame sizes omit the preamble
#    and FCS/CRC (frame check sequence). 
##

ETH_ALEN        = 6        # Octets in one ethernet addr
ETH_HLEN        = 14        # Total octets in header
ETH_ZLEN        = 60        # Min. octets in frame sans FCS
ETH_DATA_LEN    = 1500        # Max. octets in payload
ETH_FRAME_LEN   = 1514        # Max. octets in frame sans FCS

##
#    These are the defined Ethernet Protocol ID's.
##

ETH_P_LOOP      = 0x0060    # Ethernet Loopback packet
ETH_P_PUP       = 0x0200    # Xerox PUP packet
ETH_P_PUPAT     = 0x0201    # Xerox PUP Addr Trans packet
ETH_P_IP        = 0x0800    # Internet Protocol packet
ETH_P_X25       = 0x0805    # CCITT X.25
ETH_P_ARP       = 0x0806    # Address Resolution packet
ETH_P_BPQ       = 0x08FF    # G8BPQ AX.25 Ethernet Packet    [ NOT AN OFFICIALLY REGISTERED ID ]
ETH_P_IEEEPUP   = 0x0a00    # Xerox IEEE802.3 PUP packet
ETH_P_IEEEPUPAT = 0x0a01    # Xerox IEEE802.3 PUP Addr Trans packet
ETH_P_DEC       = 0x6000    # DEC Assigned proto
ETH_P_DNA_DL    = 0x6001    # DEC DNA Dump/Load
ETH_P_DNA_RC    = 0x6002    # DEC DNA Remote Console
ETH_P_DNA_RT    = 0x6003    # DEC DNA Routing
ETH_P_LAT       = 0x6004    # DEC LAT
ETH_P_DIAG      = 0x6005    # DEC Diagnostics
ETH_P_CUST      = 0x6006    # DEC Customer use
ETH_P_SCA       = 0x6007    # DEC Systems Comms Arch
ETH_P_RARP      = 0x8035    # Reverse Addr Res packet
ETH_P_ATALK     = 0x809B    # Appletalk DDP
ETH_P_AARP      = 0x80F3    # Appletalk AARP
ETH_P_8021Q     = 0x8100    # 802.1Q VLAN Extended Header
ETH_P_IPX       = 0x8137    # IPX over DIX
ETH_P_IPV6      = 0x86DD    # IPv6 over bluebook
ETH_P_SLOW      = 0x8809    # Slow Protocol. See 802.3ad 43B
ETH_P_WCCP      = 0x883E    # Web-cache coordination protocol defined in draft-wilson-wrec-wccp-v2-00.txt
ETH_P_PPP_DISC  = 0x8863    # PPPoE discovery messages
ETH_P_PPP_SES   = 0x8864    # PPPoE session messages
ETH_P_MPLS_UC   = 0x8847    # MPLS Unicast traffic
ETH_P_MPLS_MC   = 0x8848    # MPLS Multicast traffic
ETH_P_ATMMPOA   = 0x884c    # MultiProtocol Over ATM
ETH_P_ATMFATE   = 0x8884    # Frame-based ATM Transport over Ethernet
ETH_P_AOE       = 0x88A2    # ATA over Ethernet
ETH_P_TIPC      = 0x88CA    # TIPC

##
#    Non DIX types. Won't clash for 1500 types.
##
 
ETH_P_802_3     = 0x0001    # Dummy type for 802.3 frames
ETH_P_AX25      = 0x0002    # Dummy protocol id for AX.25
ETH_P_ALL       = 0x0003    # Every packet (be careful!!!)
ETH_P_802_2     = 0x0004    # 802.2 frames
ETH_P_SNAP      = 0x0005    # Internal only
ETH_P_DDCMP     = 0x0006    # DEC DDCMP: Internal only
ETH_P_WAN_PPP   = 0x0007    # Dummy type for WAN PPP frames
ETH_P_PPP_MP    = 0x0008    # Dummy type for PPP MP frames
ETH_P_LOCALTALK = 0x0009    # Localtalk pseudo type
ETH_P_PPPTALK   = 0x0010    # Dummy type for Atalk over PPP
ETH_P_TR_802_2  = 0x0011    # 802.2 frames
ETH_P_MOBITEX   = 0x0015    # Mobitex (kaz@cafe.net)
ETH_P_CONTROL   = 0x0016    # Card specific control frames
ETH_P_IRDA      = 0x0017    # Linux-IrDA
ETH_P_ECONET    = 0x0018    # Acorn Econet
ETH_P_HDLC      = 0x0019    # HDLC frames
ETH_P_ARCNET    = 0x001A    # 1A for ArcNet :-)

##
#    This is an Ethernet frame header.
##
 
class ethhdr (BigEndianStructure):
    _pack_ = 1
    _fields_ = [
        ("dest",    c_uint8 * ETH_ALEN),    # destination eth addr
        ("source",  c_uint8 * ETH_ALEN),    # source ether addr
        ("proto",   c_uint16),              # packet type ID field 
    ]


__all__ = [
    "ethhdr",
] + export_by_prefix("ETH",globals())
