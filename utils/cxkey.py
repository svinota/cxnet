#!/usr/bin/python

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

mode = "create"
keytype = "DSA"
bits = 2048
base = "cxkey"
fmode = {
	"create": "w+",
	"list": "r",
}

__doc__ = """
Public key management utility for Connexion project

Options:
	option	   |	default	   |	description

	-h				print this help

	-m <mode>	%s		operation mode (create, list)
	-t <type>	%s		key type (DSA,RSA,ElGamal,psk+AES)
	-b <bits>	%s		key size (int)
	-f <base>	%s		filename base for keys
""" % (mode,keytype,bits,base)

from getopt import getopt
import sys

try:
	(opts,left) = getopt(sys.argv[1:],"m:t:b:f:h")
except Exception, e:
	print e, __doc__
	sys.exit(255)

for (i,k) in opts:
	if i == "-h":
		print __doc__
		sys.exit(0)
	elif i == "-m":
		mode = k
	elif i == "-t":
		keytype = k
	elif i == "-b":
		bits = int(k)
	elif i == "-f":
		base = k

from cxutil.utils import RandomPool
rp = RandomPool(bits//8)

if keytype[:4] == "psk+":
	keytype = keytype[4:]
	policy = "psk"
else:
	policy = "pks"
	exec("from Crypto.PublicKey import %s as module" % (keytype))

if policy == "pks":
	key = module.generate(bits, rp.get_bytes)
else:
	from cxutil.utils import PSK
	key = PSK(keytype,bits)


if mode == "create":
	prk = open("%s.private" % (base),fmode[mode])
	from pickle import dumps
	from base64 import b64encode
	s = dumps(key)
	prk.write(b64encode(s))
	if policy == "pks":
		puk = open("%s.public" % (base),fmode[mode])
		s = dumps(key.publickey())
		puk.write(b64encode(s))

elif mode == "list":
	from pickle import loads
	from base64 import b64decode
	prk = open("%s" % (base),fmode[mode])
	s = loads(b64decode(prk.read()))
	print "key repr:",repr(s)
	print "key properties:\n\tcan encrypt:\t%s\n\tcan sign:\t%s\n\tprivate key:\t%s" % (s.can_encrypt(),s.can_sign(),s.has_private())
