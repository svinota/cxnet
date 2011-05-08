#!/usr/bin/python
"""
random.py usage:

	# iptables -I ... -j QUEUE
	# ./random.py

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
# create a connexion to RT Netlink core

from get_route import getLink, getRoute, getNeigh
from cxutil.ip import *
import time

from cxcore.thread import Thread, Timer
from threading import Lock,enumerate
from Queue import Queue

try:
	import rpdb2
	HAVE_DEBUG = True
except:
	HAVE_DEBUG = False
START_DEBUG = False

import traceback
from copy import deepcopy
from random import random

barrier = {
	"drop": [1,0],
	"dup": [1,0],
	"delay": [1,0],
}
delay_power = 1

class qdisc(Thread):

	_passed = 0
	_injected = 0
	lock = Lock()
	queue = Queue()
	s = ipq_socket()
	r = rtnl_socket()
	rt = getRoute(r)
	li = getLink(r)
	ne = getNeigh(r)

	def __init__(self):
		Thread.__init__(self)
		self.setDaemon(True)

	@classmethod
	def size(self):
		return self.queue.qsize()

	@classmethod
	def passed_inc(self):
		self.lock.acquire()
		self._passed += 1
		self.lock.release()

	@classmethod
	def injected_inc(self):
		self.lock.acquire()
		self._injected += 1
		self.lock.release()

	@classmethod
	def passed(self):
		return self._passed
	
	@classmethod
	def injected(self):
		return self._injected

class enqueue(qdisc):
	
	def run(self):
		while True:
			# receive a packet from -j QUEUE
			if START_DEBUG:
				rpdb2.start_embedded_debugger(password)
			(l,msg) = self.s.recv()
			# discard zero-sized packets
			if l <= 0: continue

			pi = iphdr.from_address(addressof(msg.data.payload))
			try:
				link = self.li.num(self.rt.to(int_to_dqn(pi.daddr))[0]["output_link"])["dev"]
			except:
				# print "allow packet from %s to %s as a fallback" % (int_to_dqn(pi.saddr),int_to_dqn(pi.daddr))
				self.s.verdict(msg.data.packet_id, NF_ACCEPT)
				qdisc.passed_inc()
				continue
			
			e = ethhdr()
			e.proto = ETH_P_IP
			try: e.source = self.ne.to(int_to_dqn(pi.saddr))["raw_lladdr"]
			except: pass
			try: e.dest = self.ne.to(int_to_dqn(pi.daddr))["raw_lladdr"]
			except: pass

			packet = GenericProtocol(e).inc(msg.data.payload)
			length = pi.tot_len + sizeof(e)


			self.queue.put((msg.data.packet_id,link,length,packet))

class dequeue(qdisc):

	filters = []
	p_int = {}

	def verdict(self, packet_id, verdict):
		if packet_id > 0:
			if verdict == NF_ACCEPT:
				self.s.verdict(packet_id, NF_ACCEPT)
				qdisc.passed_inc()
			else:
				self.s.verdict(packet_id, NF_DROP)

	def deq(self):
		if START_DEBUG:
			rpdb2.start_embedded_debugger(password)
		verdict = NF_DROP
		# receive a packet from internal queue
		(packet_id,link,length,packet) = self.queue.get()
		# filter it
		for k in self.filters:
			try:
				if random() > barrier[k.func_name[2:]][0]:
					barrier[k.func_name[2:]][1] += 1
					(_verdict,packet) = k(self,packet_id,link,length,packet)
					if _verdict is not None:
						verdict = _verdict
					if not packet:
						self.verdict(packet_id, NF_DROP)
						return
			except:
				pass

		if link not in self.p_int.keys():
			self.p_int[link] = pcap_interface(link)

		l = self.p_int[link].inject(packet,length)
		qdisc.injected_inc()
		if l == -1:
			self.p_int[link].perror()

		# print "injected packet from %s to %s" % (int_to_dqn(pi.saddr),int_to_dqn(pi.daddr))
		# drop it at OS level
		self.verdict(packet_id, verdict)

	def run(self):
		while True:
			self.deq()



def f_dup(d,packet_id,link,length,packet):
	return (NF_ACCEPT, packet)

def f_drop(d,packet_id,link,length,packet):
	return (None, None)

def f_delay(d,packet_id,link,length,packet):
	def delay(d,t):
		d.queue.put(t)
	Timer(random() * delay_power,delay,[d,(0,link,length,packet)]).start()
	return (None,None)

e = enqueue()
d = dequeue()
d.filters = [f_dup,f_drop,f_delay]
d.start()
e.start()

try:
	while True:
		text = raw_input(" ^ ")
		if not text: continue
		
		text = text.split()
		if text[0] == "q":
			break
		
		elif text[0] in ("drop","dup","delay"):
			barrier[text[0]][0] = float(text[1])

		elif text[0] == "s":
			def p():
				print "active queue size\t", qdisc.size()
				print "delay queue size\t", len(enumerate()) - 3
				print "passed\t\t\t", qdisc.passed()
				print "injected\t\t", qdisc.injected()
				print "--"
				for (i,(k,l)) in barrier.items():
					print "%s (%s):\t%s packets" % (i,k,l)
				print "--"
				print "delay_power\t", delay_power
			if len(text) > 1:
				while True:
					try:
						print "\n"
						p()
						time.sleep(float(text[1]))
					except:
						break
			else:
				p()
		
		elif text[0] == "delay_power":
			delay_power = int(text[1])

		elif (text[0] == "d"):
			if HAVE_DEBUG:
				password = raw_input("Enter password for debug connection: ")
				START_DEBUG = True
			else:
				print "no rpdb2 found, continuing w/o debugging"


except:
	traceback.print_exc()
