"""
Netlink utility functions
"""

# 	Copyright (c) 2008 ALT Linux, Peter V. Saveliev
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

from cxnet.netlink.rtnl import *
from cxnet.common import hprint
from cxnet.utils import *
from ctypes import *
# import socket as _s

from cxcore.thread import Thread
from threading import Lock
from Queue import Queue

import os

class py_iproute2(Thread):

	def __init__(self):
		Thread.__init__(self)
		self.setName("RT network subsystem interface")
		self.setDaemon(True)
		self.listeners = {
			0:	Queue(),
		}
		self.socket = rtnl_socket(groups = RTNLGRP_IPV4_IFADDR | RTNLGRP_IPV4_ROUTE | RTNLGRP_LINK | RTNLGRP_NEIGH)
		self.parser = rtnl_msg_parser()
		self.nonceLock = Lock()
		self.__nonce = 1
		self.__shutdown = False
		self.start()

	def nonce(self):

		self.nonceLock.acquire()
		if self.__nonce == 0xffffffff:
			self.__nonce = 1
		else:
			self.__nonce += 1
		self.nonceLock.release()

		return self.__nonce

	def status(self,key=0):
		assert key in self.listeners.keys()

		return self.listeners[key].qsize()

	def get(self,key=0):
		assert key in self.listeners.keys()

		end = False
		result = []
		while not end:
			bias = 0

			if self.listeners[key].empty():
				assert not self.__shutdown

			(l,msg) = self.listeners[key].get()
			while l > 0:
				x = rtnl_msg.from_address(addressof(msg) + bias)
				bias += x.hdr.length
				l -= x.hdr.length
				parsed = self.parser.parse(x)
				result.append(parsed)
				if not ((x.hdr.type > NLMSG_DONE) and (x.hdr.flags & NLM_F_MULTI)):
					end = True
					break
		return result

	def stop(self):
		self.__shutdown = True
		os.close(self.socket.fd)

	def run(self):
		while not self.__shutdown:

			try:
				(l,msg) = self.socket.recv()
				if msg.hdr.sequence_number in self.listeners.keys():
					key = msg.hdr.sequence_number
				else:
					key = 0
				###
				#
				# Enqueue message into appropriate decoder queue
				#
				###
				self.listeners[key].put((l,msg))
			except:
				pass


	def queryNL(self,msg,size=None):
		key = self.nonce()
		self.listeners[key] = Queue()
		msg.hdr.sequence_number = key
		self.socket.send(msg,size)
		ret = self.get(key)
		del self.listeners[key]
		return ret


	def getAllNeigh(self):
		msg = rtnl_msg()
		msg.hdr.type = RTM_GETNEIGH
		msg.hdr.flags = NLM_F_DUMP | NLM_F_REQUEST
		msg.data.neigh.family = 2
		ptr = addressof(msg) + sizeof(nlmsghdr) + sizeof(ndmsg)
		return self.queryNL(msg,ptr - addressof(msg))

	def getNeigh(self,addr=None):
		if addr is None:
			return self.getAllNeigh()
		for i in self.getAllNeigh():
			if "dest" in i.keys():
				if i["dest"] == addr:
					return i

		# no direct entries in the arp cache
		ret = self.getRoute(addr)[0]
		if "gateway" in ret.keys():
			return self.getNeigh(ret["gateway"])

		return None


	def getAllRoute(self):
		msg = rtnl_msg()
		msg.hdr.type = RTM_GETROUTE
		msg.hdr.flags = NLM_F_DUMP | NLM_F_REQUEST
		msg.data.route.family = 2
		msg.data.route.table = 254
		ptr = addressof(msg.data) + sizeof(msg.data.route)
		return self.queryNL(msg,ptr - addressof(msg))

	def getRoute(self,addr=None):
		if not addr:
			return self.getAllRoute()

		###
		#
		# it's unsafe for now
		#
		###

		#msg = rtnl_msg()
		#msg.hdr.type = RTM_GETROUTE
		#msg.hdr.flags = NLM_F_REQUEST
		#msg.data.route.family = 2
		#msg.data.route.table = 254
		#msg.data.route.dst_len = 32
		#msg.data.route.type = RTN_UNICAST
		#a = t_attr()
		#ptr = addressof(msg.data) + sizeof(msg.data.route)
		#ptr = a.set(ptr,RTA_DST,c_uint32(_s.htonl(dqn_to_int(addr))))
		#ptr = a.set(ptr,RTA_TABLE,c_uint32(254))

		#ret = self.queryNL(msg,ptr - addressof(msg))

		ret = self.getAllRoute()
		result = {}
		dst = dqn_to_int(addr)
		for i in ret:
			if ('dst_prefix' in i.keys()) and ('dst_len' in i.keys()):
				if dqn_to_int(i['dst_prefix']) == get_base(dst,i['dst_len']):
					result['static'] = i
			elif ('dst_len' in i.keys()) and ('src_len' in i.keys()):
				if i['dst_len'] == 0 and i['src_len'] == 0:
					result['default'] = i

		if 'static' in result.keys():
			ret = [result['static'],]
		elif 'default' in result.keys():
			ret = [result['default'],]
		else:
			ret = []
		return ret


	def getLink(self,num=None):
		if isinstance(num,int):
			key = "index"
		elif isinstance(num,str):
			key = "dev"
		else:
			return self.getAllLink()
		for i in self.getAllLink():
			if i[key] == num:
				return i

	def getAllLink(self):
		msg = rtnl_msg()
		msg.hdr.type = RTM_GETLINK
		msg.hdr.flags = NLM_F_DUMP | NLM_F_REQUEST
		return self.queryNL(msg)

	def getAddr(self,link=None,addr=None):
		ret = self.getAllAddr()
		if addr is None and link is None:
			return ret
		result = []
		for i in ret:
			if 'dev' in i.keys():
				if i['dev'] == link:
					result.append(i)
			elif 'address' in i.keys():
				if i['address'] == addr:
					result.append(i)
		return result

	def getAllAddr(self):
		msg = rtnl_msg()
		msg.hdr.type = RTM_GETADDR
		msg.hdr.flags = NLM_F_DUMP | NLM_F_REQUEST
		return self.queryNL(msg)
