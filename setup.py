#!/usr/bin/env python

from distutils.core import setup

setup(
	name="cxnet",
	version="0.7.0",
	url="http://www.radlinux.org/connexion/",
	author="Peter V. Saveliev",
	author_email="peet@altlinux.org",
	license="GPL",
	packages=[
		"cxnet",
		"cxnet.netlink",
	],
)
