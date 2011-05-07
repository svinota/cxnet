"""
TCP protocol primitives
"""

# 	Copyright (c) 2008 Peter V. Saveliev
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

from ctypes import *
from cxnet.generic import *
from cxnet.common import csum, csum_words, csum_complement

class tcphdr(BigEndianStructure):
	_fields_ = [
		("sport",	c_uint16),
		("dport",	c_uint16),
		("seq_num",	c_uint32),	# Sequence number
		("ack_num",	c_uint32),	# Acknoledge number
		("hdrlen",	c_uint16,	4),
		("reserved",	c_uint16,	6),
		("f_urg",	c_uint16,	1),	# TCP flags
		("f_ack",	c_uint16,	1),	#
		("f_psh",	c_uint16,	1),	#
		("f_rst",	c_uint16,	1),	#
		("f_syn",	c_uint16,	1),	#
		("f_fin",	c_uint16,	1),	#
		("window",	c_uint16),
		("chksum",	c_uint16),
		("urgptr",	c_uint16),
	]

class tcp_f_hdr(BigEndianStructure):
	_fields_ = [
		("daddr",	c_uint32),
		("saddr",	c_uint32),
		("reserved",	c_uint8),
		("protocol",	c_uint8),
		("tot_len",	c_uint16),
	]

	def __init__(self):
		BigEndianStructure.__init__(self)
		self.protocol = 6

class tcp_f_comp(Structure):
	_fields_ = [
		("pseudo_hdr",	tcp_f_hdr),
		("real_hdr",	tcphdr),
	]

class TCPProtocol(GenericProtocol):

	seq = None
	p_hdr = None
	inack = None

	def __init__(self,p_hdr,hdr):
		GenericProtocol.__init__(self,hdr)
		self.p_hdr = p_hdr
		self.inack = True

	def seq(self):
		self.hdr.seq_num += 1

	def post(self,msg):
		self.p_hdr.tot_len = sizeof(msg)
		msg.hdr.hdrlen = sizeof(msg.hdr) // 4
		msg.hdr.chksum = 0
		#msg.hdr.chksum = csum(self.p_hdr,sizeof(self.p_hdr)) + csum(msg,sizeof(msg))
		msg.hdr.chksum = csum_complement(csum_words(self.p_hdr,sizeof(self.p_hdr)) + csum_words(msg,sizeof(msg)))
		return msg
