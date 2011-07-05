"""
libc, csum etc.
"""

#     Copyright (c) 2008-2011 Peter V. Saveliev <peet@altlinux.ru>
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

__all__ = [
    "cx_int",
    "libc",
    "hdump",
    "hprint",
    "csum",
    "csum_words",
    "csum_complement",
]

from ctypes import *

from sys import maxint
if maxint == 2147483647:
    cx_int = c_uint32
else:
    cx_int = c_uint64

libc = CDLL("libc.so.6")


class NotImplemented(Exception):
    pass

def hdump(name,msg,size=0):
    """
    Dump a packet into a file
    """
    if not size:
        size = sizeof(msg)
    fd = libc.open(name,577,384)
    libc.write(fd,byref(msg),size)
    libc.close(fd)

def hline(msg,size=0):
    """
    Format packet into a string
    """
    if not size:
        size = sizeof(msg)
    length = size
    offset = 0
    ptr = addressof(msg)
    line = ""
    result = ""

    while offset < length:
        a = c_ubyte.from_address(ptr).value
        result += "%02x " % (a)
        if 31 < a and a < 127:
            line += chr(a)
        else:
            line += '.'

        if offset:
            if not (offset + 1) % 8:
                result += ": "
            if not (offset + 1) % 16:
                result += "\t %s\n" % (str(line))
                line = ""

        offset += 1
        ptr += 1

    if line:
        align = (( offset + 15 ) & ~ 15) - offset
        for i in range(align):
            if (not (offset + i) % 8) and (result[-2] != ":"):
                result += ": "
            result += "   "
        result += ":\t %s\n" % (str(line))
    return result


def hprint(msg,size=0):
    """
    Dump a packet onto stdout
    """
    print(hline(msg,size))

class be16 (BigEndianStructure):
    _fields_ = [
        ("c",    c_uint16),
    ]

def csum_words(msg,l):
    odd = False
    if (l%2):
        l -= 1
        odd = True

    # l is in bytes. We need 16-bit words
    a = addressof(msg)
    x = 0

    for i in range(0,l,2):
        c = be16.from_address(a + i)
        x += c.c

    if odd:
        last = c_uint16(c_uint8.from_address(a + l).value << 8)
        x += last.value

    return x

def csum_complement(x):
    x = c_uint32(x)
    x1 = c_uint16.from_address(addressof(x))
    x2 = c_uint16.from_address(addressof(x) + 2)
    return ~c_uint16(x1.value + x2.value).value

def csum(msg,l):
    ##
    # details: rfc 1071
    # a simple description: http://www.netfor2.com/checksum.html
    ##
    return csum_complement(csum_words(msg,l))
