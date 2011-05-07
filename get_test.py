#!/usr/bin/python

from cxnet.netlink.util import py_iproute2
from cxnet.netlink.rtnl import *

p = py_iproute2()

ne = p.getNeigh()
rt = p.getRoute()
print rt
li = p.getLink()
print li

for i in ne:
	try:
		if i["dest"] != "0.0.0.0":
			print "%-30s%-30s" % (i["dest"],i["lladdr"])
	except:
		pass
