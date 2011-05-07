"""
Generic IP protocol primitives
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

class GenericHeader (BigEndianStructure):
	_fields_ = [
		("len",		c_uint16),
		("saddr",	c_uint64),
		("daddr",	c_uint64),
	]

class GenericProtocol (object):
	"""
	Generic network protocol
	"""
	hdr = None
	res = None

	def __init__(self, hdr = GenericHeader):
		self.hdr = hdr
		self.init()

	def inc(self,msg):
		return self.post(self._inc(msg))

	def _inc(self,msg):
		"""
		Incapsulate a message as a payload
		"""
		if msg is None:
			class packet (Structure):
				_pack_ = 1
				_fields_ = [
					("hdr",         type(self.hdr)),
				]
		else:
			class packet (Structure):
				_pack_ = 1
				_fields_ = [
					("hdr",		type(self.hdr)),
					("payload",	type(msg)),
				]

		x = packet()
		x.hdr = self.hdr

		if not msg is None:
			x.payload = msg
		return x

	def post(self,msg):
		return msg

	def init(self):
		pass
