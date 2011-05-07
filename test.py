#!/usr/bin/python

from cxnet.netlink.ipq import *
from cxnet.ip4 import iphdr
import socket

s = ipq_socket()

while True:
	(l,msg) = s.recv()
	print dir(msg.data)
	print msg.data.packet_id
	s.verdict(msg.data.packet_id, NF_ACCEPT)

	pi = iphdr.from_address(addressof(msg.data.payload))
