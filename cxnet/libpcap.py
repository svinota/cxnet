"""
A simple libpcap injector
"""

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

__all__ = ["pcap_interface"]

from ctypes import *

PCAP_ERRBUF_SIZE = 256

libp = CDLL("libpcap.so.0.8")

class pcap_interface(object):

    error = None
    psock = None

    def __init__(self,name):
        self.error = create_string_buffer(PCAP_ERRBUF_SIZE)
        self.psock = libp.pcap_open_live(name,65535,0,1,byref(self.error))

    def inject(self,packet,size=None):
        if not size:
            size = sizeof(packet)
        return libp.pcap_inject(self.psock,byref(packet),size)

    def perror(self):
        print string_at(addressof(self.error))

    def close(self):
        libp.pcap_close(self.psock)
