"""
Misc utils for IPv4 management
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

__all__ = [
	"dqn_to_bit",
	"bit_to_dqn",
	"dqn_to_int",
	"int_to_dqn",
	"mask_unknown",
	"get_mask",
	"get_base",
	"ip_range",
]

msk = []
for i in xrange(33):
	a = 0
	for k in xrange(i):
		a = a >> 1
		a |= 0x80000000
	msk.append(a)

def dqn_to_bit(st):
	"""
	Convert dotted quad notation to /xx mask
	"""
	return msk.index(int(dqn_to_int(st)))

def bit_to_dqn(st):
	"""
	Convert /xx mask to dotted quad notation
	"""
	return int_to_dqn(msk[int(st)])

def dqn_to_int(st):
	"""
	Convert dotted quad notation to integer
	"""
	st = st.split(".")
	###
	# That is not so elegant as 'for' cycle and
	# not extensible at all, but that works faster
	###
	return int("%02x%02x%02x%02x" % (int(st[0]),int(st[1]),int(st[2]),int(st[3])),16)

def int_to_dqn(st):
	"""
	Convert integer to dotted quad notation
	"""
	st = "%08x" % (st)
	###
	# The same issue as for `dqn_to_int()`
	###
	return "%i.%i.%i.%i" % (int(st[0:2],16),int(st[2:4],16),int(st[4:6],16),int(st[6:8],16))

def mask_unknown(st):
	"""
	Detect mask by zero bytes
	"""
	st = st.split(".")
	st.reverse()
	mask = 32
	c = [32]
	for i in st:
		mask -= 8
		if i == "0":
			c.append(mask)
	return c[-1]

def get_mask(st):
	"""
	Return int mask for IP
	"""
	st = st.split("/")
	if len(st) > 1:
		mask = st[1]
		if mask.find(".") > 0:
			mask = dqn_to_int(mask)
		else:
			mask = msk[int(mask)]
	else:
		mask = msk[mask_unknown(st[0])]

	return mask

def get_base(ip,mask):
	"""
	Return network for an ip
	"""
	return ((((1 << mask) - 1) << (32 - mask)) & ip)

def ip_range(st):
	"""
	Return IP list for a network
	"""
	mask = get_mask(st)
	st = st.split("/")
	ip = dqn_to_int(st[0])

	###
	#
	###
	net = ip & mask
	start = 0
	stop = msk[32] & ~mask
	result = []
	for i in xrange(start,stop + 1):
		result.append((
			hex(i),
			int_to_dqn(net | i),
		))

	return result
