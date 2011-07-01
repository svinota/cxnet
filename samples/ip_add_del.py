#!/usr/bin/env python

from cxnet.netlink.rtnl import *

p = rtnl_msg_parser()
a = {
    "action": "del",
    "type": "address",
    "mask": 24,
    "index": 2,
    "address": "192.168.0.1",
    "local": "192.168.0.1"
}
msg = p.create(a)
msg.hdr.flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL
msg.hdr.sequence_number = 13
hprint(msg,msg.hdr.length)

s = rtnl_socket(groups = RTNLGRP_IPV4_IFADDR | RTNLGRP_IPV4_ROUTE | RTNLGRP_LINK | RTNLGRP_NEIGH)
s.send(msg,msg.hdr.length)
(l,msg) = s.recv()
hprint(msg,l)
