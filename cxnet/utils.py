"""
Misc utils for IPv4 management
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

from cxnet.common import libc
from ctypes import BigEndianStructure
from ctypes import sizeof, addressof, byref
from ctypes import c_ubyte, c_uint8, c_uint16, c_uint32

__all__ = [
    "dqn_to_bit",
    "bit_to_dqn",
    "dqn_to_int",
    "int_to_dqn",
    "mask_unknown",
    "get_mask",
    "get_base",
    "ip_range",
    "UrandomPool",
    "PSK",
    "make_map",
    "export_by_prefix",
    "hdump",
    "hline",
    "hprint",
    "csum",
    "csum_words",
    "csum_complement",
]

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


def make_map(prefix,gs):
    """
    Create dictionary mapping for global constants with prefix.
    One MUST supply globals dictionary to work with.

    Assume we have a lot of constants with names CONST_* and integer
    values (1,2,3...):

    (direct,reverse) = make_map("CONST_",globals())

    The dictionaries will look like this:

    direct == {
        "CONST_A": 1,
        "CONST_B": 2,
        ...
    }

    reverse == {
        1: "CONST_A",
        2: "CONST_B",
        ...
    }

    It is useful to rapidly map constants by values from binary
    protocol structurs to Python dictionary objects.
    """
    d = dict( [ (x,y) for x,y in gs.items() if x[:len(prefix)] == prefix ] )
    r = dict( [ (y,x) for x,y in gs.items() if x[:len(prefix)] == prefix ] )
    return (d,r)

def export_by_prefix(prefix,gs):
    """
    Print all names with prefix
    """
    return [ x for x in gs.keys() if x[:len(prefix)] == prefix ]

msk = []
for i in range(33):
    a = 0
    for k in range(i):
        a = a >> 1
        a |= 0x80000000
    msk.append(a)

def dqn_to_bit(st):
    """
    Convert dotted quad notation to /xx mask
    """
    return msk.index(int(dqn_to_int(st)))

def bit_to_dqn(st):
    """
    Convert /xx mask to dotted quad notation
    """
    return int_to_dqn(msk[int(st)])

def dqn_to_int(st):
    """
    Convert dotted quad notation to integer
    """
    st = st.split(".")
    ###
    # That is not so elegant as 'for' cycle and
    # not extensible at all, but that works faster
    ###
    return int("%02x%02x%02x%02x" % (int(st[0]),int(st[1]),int(st[2]),int(st[3])),16)

def int_to_dqn(st):
    """
    Convert integer to dotted quad notation
    """
    st = "%08x" % (st)
    ###
    # The same issue as for `dqn_to_int()`
    ###
    return "%i.%i.%i.%i" % (int(st[0:2],16),int(st[2:4],16),int(st[4:6],16),int(st[6:8],16))

def mask_unknown(st):
    """
    Detect mask by zero bytes
    """
    st = st.split(".")
    st.reverse()
    mask = 32
    c = [32]
    for i in st:
        mask -= 8
        if i == "0":
            c.append(mask)
    return c[-1]

def get_short_mask(st):
    """
    Return short int mask in form /xx
    """
    st = st.split("/")
    if len(st) > 1:
        mask = st[1]
        if mask.find(".") > 0:
            mask = msk.index(dqn_to_int(mask))
    else:
        mask = mask_unknown(st[0])

    return int(mask)

def get_mask(st):
    """
    Return int mask for IP
    """
    st = st.split("/")
    if len(st) > 1:
        mask = st[1]
        if mask.find(".") > 0:
            mask = dqn_to_int(mask)
        else:
            mask = msk[int(mask)]
    else:
        mask = msk[mask_unknown(st[0])]

    return mask

def get_base(ip,mask):
    """
    Return network for an ip
    """
    return ((((1 << mask) - 1) << (32 - mask)) & ip)

def ip_range(st):
    """
    Return IP list for a network
    """
    mask = get_mask(st)
    st = st.split("/")
    ip = dqn_to_int(st[0])

    ###
    #
    ###
    net = ip & mask
    start = 0
    stop = msk[32] & ~mask
    result = []
    for i in range(start,stop + 1):
        result.append((
            hex(i),
            int_to_dqn(net | i),
        ))

    return result

class UrandomPool (object):

    size = None

    def __init__ (self,size):
        self.size = None

    def get_bytes(self,_size = None):
        global urandom
        try:
            fstat(urandom.fileno())
        except:
            urandom = open("/dev/urandom","r")

        if _size is None:
            size = self.size
        else:
            size = _size
        return urandom.read(size)

class PSK (object):
    def __init__(self,t,bits):
        rp = UrandomPool(bits//8)
        self.type = t
        self.bits = bits
        self.psk = rp.get_bytes(self.bits//8)
        if t == "AES":
            self.block = 16
        else:
            self.block = 8

    def __getstate__(self):
        o = self.__dict__.copy()
        if "key" in o.keys():
            del o["key"]
        return o

    def __setstate__(self,d):
        self.__dict__.update(d)
        exec("from Crypto.Cipher import %s as module" % (self.type))
        self.key = module.new(self.psk,module.MODE_CBC)
        self.rp = UrandomPool(self.bits//8)

    def randomize(self):
        while self.rp.entropy < self.bits:
            self.rp.add_event()

    def __repr__(self):
        return "<PSK instance for %s type key (%s bits)>" % (self.type,self.bits)

    def encrypt(self,s):
        return self.key.encrypt(self.rp.get_bytes(self.block) + s)

    def decrypt(self,s):
        return self.key.decrypt(s)[self.block:]

    def sign(self,h,p):
        return self.encrypt(h)

    def verify(self,h,s):
        return self.decrypt(s) == h

    def can_encrypt(self):
        return 1

    def can_sign(self):
        return 1

    def has_private(self):
        return True
