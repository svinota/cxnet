#!/usr/bin/python
"""
tarpit.py usage:

	# iptables -I ... -j QUEUE
	# ./tarpit.py

This script is not a production high-throughput program,
but just a proof-of-concept. It is provided as an
example of cxnet package usage.

Stop with Ctrl-C
"""

# 	Copyright (c) 2007-2008 ALT Linux, Peter V. Saveliev
#
# 	This file is part of Connexion project.
#
# 	Connexion is free software; you can redistribute it and/or modify
# 	it under the terms of the GNU General Public License as published by
# 	the Free Software Foundation; either version 3 of the License, or
# 	(at your option) any later version.
#
# 	Connexion is distributed in the hope that it will be useful,
# 	but WITHOUT ANY WARRANTY; without even the implied warranty of
# 	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# 	GNU General Public License for more details.
#
# 	You should have received a copy of the GNU General Public License
# 	along with Connexion; if not, write to the Free Software
# 	Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA

ignore_checksum = True

# use IPQ (-j QUEUE)
from cxnet.netlink.ipq import *
# use RT Netlink to get interfaces list
from cxnet.netlink.rtnl import *
# TCP protocol
from cxnet.tcp import *
# IPv4 protocol
from cxnet.ip4 import *
# Ethernet protocol
from cxnet.ether import *
# Generic IP protocol primitives
from cxnet.generic import *
# Misc ip-related utils, for IP int-to-string conversion etc.
from cxnet.utils import *
# IP checksum or packet dump
from cxnet.common import *
# Simple libpcap packet injector
from cxnet.libpcap import *
# CTypes :)
from ctypes import *

# get packets from -j QUEUE
s = ipq_socket()
# create a connexion to RT Netlink core
r = rtnl_socket()

# TCP connexions pool
connexions = {}

class hs (BigEndianStructure):
	"""
	A structure to be used as a hash for tracking TCP connexions
	"""
	_fields_ = [
		("saddr",	c_uint32),
		("daddr",	c_uint32),
		("sport",	c_uint16),
		("dport",	c_uint16),
	]


while True:
	# receive a packet from -j QUEUE
	(l,msg) = s.recv()

	if l <= 0:
		print "Discard a packet? with l == 0"
		continue

	# drop it at OS level
	s.verdict(msg.data.packet_id, NF_DROP)

	# pi == IP header
	# pt == TCP header
	# checksum == TCP connexion hash
	pi = iphdr.from_address(addressof(msg.data.payload))
	###
	# Check IP header
	###
	if c_uint16(csum(pi,sizeof(pi))).value != 0:
		print "Discard a packet with wrong IP checksum (source: %s)" % (int_to_dqn(pi.saddr))
		continue

	# if proto != TCP, drop a packet
	if pi.protocol != 6:
		print "Discard non-TCP packet (source: %s)" % (int_to_dqn(pi.saddr))
		continue

	###
	# Check TCP header: create pseudo-header and calculate checksum
	# FIXME: should be moved into a library sub-routine
	###
	pt = tcphdr.from_address(addressof(msg.data.payload) + pi.ihl * 4)
	tp = tcp_f_hdr()
	tp.daddr = pi.daddr
	tp.saddr = pi.saddr
	tp.tot_len = pt.hdrlen * 4
	if (c_uint16(csum_complement(csum_words(tp,sizeof(tp)) + csum_words(pt, pt.hdrlen * 4))).value != 0) and (not ignore_checksum):
		print "Discard a packet with wrong TCP checksum (%s:%s -> %s:%s)" % (int_to_dqn(pi.saddr),pt.sport,int_to_dqn(pi.daddr),pt.dport)
		continue

	###
	# A connexion key (FIXME: use more reliable hash)
	###
	checksum = csum(hs(pi.saddr,pi.daddr,pt.sport,pt.dport),sizeof(hs))

	###
	# TCP state machine
	###
	if pt.f_syn and not pt.f_ack:
		###
		# Connect: SYN = 1, ACK = 0
		###
		# create a connexion

		# a real TCP header
		t = tcphdr()
		t.sport = pt.dport
		t.dport = pt.sport
		t.f_ack = 1
		t.window = 0
		t.ack_num = pt.seq_num + 1
		# t.seq_num = pt.seq_num

		# TCP pseudo-header, used for checksum calculation
		tp = tcp_f_hdr()
		tp.daddr = pi.saddr
		tp.saddr = pi.daddr
		
		_t = connexions[checksum] = TCPProtocol(tp,t)
		print "Create connexion slot %x for %s:%s -> %s:%s" % (c_uint16(checksum).value,int_to_dqn(pi.saddr),pt.sport,int_to_dqn(pi.daddr),pt.dport)

	elif pt.f_fin or pt.f_rst:
		###
		# FIN or RST: just ignore
		###
		print "Ignore FIN = %x, RST = %x from %s:%s (slot %x, may be not connected)" % (pt.f_fin,pt.f_rst,int_to_dqn(pi.saddr),pt.sport,c_uint16(checksum).value)
		continue
	else:
		###
		# SYN = 0, ACK = 1: keep-alive or window ack
		###
		# if there is no such connexion, drop the packet
		if checksum not in connexions.keys():
			print "Ignore packet to a non-existent connexion from %s:%s (slot %x, not connected)" % (int_to_dqn(pi.saddr),pt.sport,c_uint16(checksum).value)
			continue

		# accept a handshake/keepalive packet
		if connexions[checksum].inack:
			connexions[checksum].inack = False
			connexions[checksum].hdr.seq_num = 1
			continue

		# seq == 0, ack == 0 (relative): keep-alive
		if (pt.seq_num + 1 == connexions[checksum].hdr.ack_num) and (pt.ack_num - 1 == connexions[checksum].hdr.seq_num ):
			connexions[checksum].inack = True

		# reply with window 0
		print "Send keep-alive for slot %x" % (c_uint16(checksum).value)


	# if it is a handshakeable packet, send SYN back (the handshake)
	connexions[checksum].hdr.f_syn = pt.f_syn
	# create an empty TCP packet
	p = connexions[checksum].inc(None)

	###
	# IP
	###
	i = iphdr()
	i.protocol = 6
	i.f_DF = 1
	i.saddr = pi.daddr
	i.daddr = pi.saddr
	p = IPv4Protocol(i).inc(p)

	###
	# Ethernet
	###
	e = ethhdr()
	# in the case of non-loopback connection, fill in MAC addresses
	if msg.data.hw_addrlen > 0:
		# ... a destination one
		e.dest = (c_ubyte * msg.data.hw_addrlen).from_address(addressof(msg.data.hw_addr))
		# ... and a source
		#
		# get all interfaces info via RT Netlink and get indev's hwaddr from it
		# FIXME: this code should be moved to a library sub-routine like get_by_name() or like that
		#
		end = False
		h = nlmsghdr()
		h.type = RTM_GETLINK
		h.flags = NLM_F_DUMP | NLM_F_REQUEST
		msgx = rtnl_msg()
		msgx.hdr = h
		r.send(msgx)
		while not end:
			bias = 0
			(l,msgx) = r.recv()
			while l >= 0:
				x = rtnl_msg.from_address(addressof(msgx) + bias)
				bias += x.hdr.length
				l -= bias
				parser = rtnl_msg_parser()
				parsed = parser.parse(x)
				if x.hdr.type == NLMSG_DONE:
					end = True
					break
				if (parsed["dev"] == msg.data.indev_name) or (parsed["dev"] == "wifi0"):
					e.source = parsed["raw_hwaddr"]
	e.proto = ETH_P_IP
	p = GenericProtocol(e).inc(p)


	# inject the packet with pcap
	p_int = pcap_interface(msg.data.indev_name)
	l = p_int.inject(p)
	if l == -1:
		p_int.perror()
	p_int.close()


