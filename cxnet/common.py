"""
Basic common objects, exceptions etc.
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
    "NotImplemented",
]

from ctypes import CDLL
from ctypes import c_uint32, c_uint64

from sys import maxint
if maxint == 2147483647:
    cx_int = c_uint32
else:
    cx_int = c_uint64

libc = CDLL("libc.so.6")


class NotImplemented(Exception):
    pass


