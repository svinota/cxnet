#!/usr/bin/env python

from distutils.core import setup

setup(
    name="cxnet",
    version="0.7.1",
    url="http://projects.radlinux.org/cx/",
    author="Peter V. Saveliev",
    author_email="peet@altlinux.org",
    license="GPLv3",
    packages=[
        "cxnet",
        "cxnet.netlink",
    ],
    scripts=[
        "utils/cxkey",
    ]
)
