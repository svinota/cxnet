# -*- coding: utf-8 -*-
"""
    cxnet.netlink.exceptions
    ~~~~~~~~~~~~~~~~~~~~~~~~

    This module implements a number of Python exceptions, rasied by
    various :mod:`cxnet.netlink` objects.

    :copyright: (c) 2011 by Peter V. Saveliev, see AUTHORS for more details.
    :license: GPL, see LICENSE for more details.
"""

import os
import socket


class NetlinkError(socket.error):
    def __init__(self, code, msg=None, hdr=None):
        if not msg:
            msg = os.strerror(abs(code))

        super(NetlinkError, self).__init__(code, msg)

        # hdr (if not none) should contain the netlink
        # header that caused error
        self.hdr = hdr
        self.code = code


class NetlinkNoSuchProtocol(NetlinkError):
    def __init__(self,hdr=None):
        msg = "The protocol is not supported by your kernel"
        NetlinkError.__init__(self,-2,msg,hdr)
