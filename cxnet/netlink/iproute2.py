"""
Python netlink based iproute2

Remember, that cxnet library contains very simplified and
very limited netlink implementation.

Also, it uses default Queue() objects, that leads to
low performance.

And it is under permanent development. So, there will be
new versions sometimes. Though (I hope) these versions
will be compatible.

Usage sample:

from cxnet.netlink.iproute2 import iproute2
iproute2.get_all_routes()
iproute2.get_route("1.2.3.4")
iproute2.get_neighbor("192.168.0.1")
iproute2.get_link(1)
iproute2.get_link("eth2")
[ (x["dev"],x["flags"]) for x in iproute2.get_all_links() ]
"""

# Copyright (c) 2008-2011 ALT Linux, Peter V. Saveliev
#
# This file is part of Connexion project.
#
# Connexion is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# Connexion is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Connexion; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA

#
# Version requirements:
#   epoll -> >= 2.6
#   Queue -> <  3.0
#
#   ...
#
import sys
import time
from threading import Thread,enumerate


token = "RT network subsystem interface"

assert (2,6) <= sys.version_info
assert token not in [ x.name for x in enumerate() ]

__all__ = [ "iproute2" ]
#
#
#
from cxnet.common import NotImplemented
from cxnet.netlink.rtnl import *
from cxnet.utils import dqn_to_int,get_base,get_short_mask
from ctypes import *
from select import epoll,EPOLLIN
try:
    from Queue import Queue
except:
    from queue import Queue

import os


class _iproute2(Thread):
    """
    There can be only one running RTNL socket at a time. We create
    it implicitly with _iproute2() at module import time. All
    communications and controls should be done with `iproute2'
    reference.
    """
    def __init__(self):
        Thread.__init__(self)
        self.setName(token)
        self.daemon = True
        self.e = epoll()
        (self.ctlr,self.ctl) = os.pipe()
        self.socket = None
        self.mask = RTNLGRP_IPV4_IFADDR | RTNLGRP_IPV4_ROUTE | RTNLGRP_LINK | RTNLGRP_NEIGH
        self.restart_socket()
        self.e.register(self.ctlr,EPOLLIN)
        self.e.register(self.socket.fd,EPOLLIN)
        self.listeners = {
            0:    Queue(),
        }
        self.cache = {}
        self.parser = rtnl_msg_parser()
        self.__nonce = 1
        self.__shutdown = False
        self.start()

    def restart_socket(self):
        """
        Start RTNL socket
        """
        if self.socket is not None:
            self.socket.close()
        self.socket = rtnl_socket(groups = self.mask)

    def set_groups(self,mask):
        """
        Set group mask for RTNL socket
        """
        # Please note, that (set|add|del)_groups? do not
        # use locking -- for simplicity.
        self.mask = mask
        os.write(self.ctl,"s")

    def add_group(self,group):
        """
        Add a group to the RTNL socket mask
        """
        self.mask |= group
        os.write(self.ctl,"s")

    def del_group(self,group):
        """
        Remove a group from the RTNL socket mask
        """
        self.mask ^= group
        os.write(self.ctl,"s")

    def shutdown(self):
        """
        Completely shutdown the thread
        """
        os.write(self.ctl,"q")

    def run(self):
        """
        This method should not be called directly, it is just
        a part of Thread() objects protocol in Python

        There is a control interface implemented with a pipe.
        You can write a command to _iproute2.ctl:
            q -- shutdown the thread and quit
            s -- restart RTNL socket
        """

        while not self.__shutdown:

            # wait for an incoming event
            fds = self.e.poll()
            for fd in fds:
                try:

                    # control interface
                    if fd[0] == self.ctlr:
                        # read a command
                        cmd = os.read(self.ctlr,1)
                        if cmd == "q":
                            # quit
                            self.__shutdown = True
                            self.e.unregister(self.socket.fd)
                            self.e.unregister(self.ctlr)
                            self.e.close()
                            self.socket.close()
                            return
                        elif cmd == "s":
                            # restart socket
                            self.e.unregister(self.socket.fd)
                            self.restart_socket()
                            self.e.register(self.socket.fd,EPOLLIN)

                    # receive and decode netlink message
                    elif fd[0] == self.socket.fd:
                        (l,msg) = self.socket.recv()
                        if msg.hdr.sequence_number in self.listeners.keys():
                            key = msg.hdr.sequence_number
                        else:
                            key = 0

                        # enqueue message into appropriate decoder queue
                        self.listeners[key].put((time.asctime(),l,msg))

                except:
                    pass

    def nonce(self):
        """
        Increment netlink protocol nonce (there is no need to call it directly)
        """
        if self.__nonce == 0xffffffff:
            self.__nonce = 1
        else:
            self.__nonce += 1

        return self.__nonce

    def status(self,key=None):
        """
        Return queue size for a listener [key] or for all listeners
        """
        if key is not None:
            assert key in self.listeners.keys()
            return self.listeners[key].qsize()
        else:
            return dict([ (key,self.listeners[key].qsize()) for key in self.listeners.keys() ])

    def get(self,key=0,blocking=True):
        """
        Get a message from a queue
        """
        assert key in self.listeners.keys()

        end = False
        result = []
        while not end:
            bias = 0

            if self.listeners[key].empty():
                assert not self.__shutdown
                if not blocking:
                    break

            (t,l,msg) = self.listeners[key].get()
            while l > 0:
                x = rtnl_msg.from_address(addressof(msg) + bias)
                bias += x.hdr.length
                l -= x.hdr.length
                parsed = self.parser.parse(x)
                if isinstance(parsed,dict):
                    parsed["timestamp"] = t
                    result.append(parsed)
                if not ((x.hdr.type > NLMSG_DONE) and (x.hdr.flags & NLM_F_MULTI)):
                    end = True
                    break
        return result


    def query_nl(self,msg,size=None,cache_key=None):
        """
        Send a message via netlink. Please note that it is the very
        internal method and you should not call it.
        """
        if cache_key is None:
            key_size = size or 128
            cache_key = string_at(addressof(msg),key_size)
        if self.cache.has_key(cache_key):
            if time.time() - self.cache[cache_key][0] <= 60:
                return self.cache[cache_key][1]
        key = self.nonce()
        self.listeners[key] = Queue()
        msg.hdr.sequence_number = key
        self.socket.send(msg,size)
        ret = self.get(key)
        del self.listeners[key]
        if cache_key is not None:
            self.cache[cache_key] = (time.time(),ret)
        return ret


    def get_all_neighbors(self):
        """
        Get all neighbors (ARP cache)
        """
        msg = rtnl_msg()
        msg.hdr.type = RTM_GETNEIGH
        msg.hdr.flags = NLM_F_DUMP | NLM_F_REQUEST
        msg.data.neigh.family = 2
        ptr = addressof(msg) + sizeof(nlmsghdr) + sizeof(ndmsg)
        return filter(lambda x: x['type'] == 'neigh', self.query_nl(msg,ptr - addressof(msg)))

    def get_neighbor(self,addr=None):
        """
        Get a neighbor from ARP cache, all neighbors (if addr == None),
        or the gateway record for the addr
        """
        if addr is None:
            return self.get_all_neighbors()

        try:
            return filter(lambda x: x['dest'] == addr, self.get_all_neighbors())[0]
        except:
            pass

        # no direct entries in the arp cache
        try:
            return self.get_neigh(self.get_route(addr)[0]["gateway"])
        except:
            pass

        return None


    def get_all_routes(self,table=254):
        """
        Get all routes. If no table number is specified, get records
        from the main routing table.

        Some default table numbers:
        0   -- unspec
        253 -- default
        254 -- main
        255 -- local
        """
        msg = rtnl_msg()
        msg.hdr.type = RTM_GETROUTE
        msg.hdr.flags = NLM_F_DUMP | NLM_F_REQUEST
        msg.data.route.family = 2
        msg.data.route.table = table
        ptr = addressof(msg.data) + sizeof(msg.data.route)
        return filter(lambda x: x['t'] == table, filter(lambda x: x['type'] == 'route', self.query_nl(msg,ptr - addressof(msg))))

    def get_route(self,addr=None,table=254):
        """
        Get a particular route.

        About implementation: there is a mechanism to retrieve only
        one record from the kernel; but it is unreliable, so get
        all records and filter it here
        """
        if addr is None:
            return self.get_all_routes(table)

        ret = self.get_all_routes(table)
        result = {}
        dst = dqn_to_int(addr)
        for i in ret:
            if ('dst_prefix' in i.keys()) and ('dst_len' in i.keys()):
                if dqn_to_int(i['dst_prefix']) == get_base(dst,i['dst_len']):
                    result['static'] = i
            elif ('dst_len' in i.keys()) and ('src_len' in i.keys()):
                if i['dst_len'] == 0 and i['src_len'] == 0:
                    result['default'] = i

        if 'static' in result.keys():
            ret = [result['static'],]
        elif 'default' in result.keys():
            ret = [result['default'],]
        else:
            ret = []
        return ret


    def get_link(self,num=None):
        """
        Get a link info. You can use link number or string id as a
        parameter to this method.
        """
        if isinstance(num,int):
            key = "index"
        elif isinstance(num,str):
            key = "dev"
        else:
            return self.get_all_links()
        for i in self.get_all_links():
            if i[key] == num:
                return i

    def get_all_links(self):
        """
        Get info on all links.
        """
        msg = rtnl_msg()
        msg.hdr.type = RTM_GETLINK
        msg.hdr.flags = NLM_F_DUMP | NLM_F_REQUEST
        return self.query_nl(msg,cache_key="links")


    def add_addr(self,link,addr):
        return self._del_add_addr(link,addr,"add")

    def del_addr(self,link,addr):
        return self._del_add_addr(link,addr,"del")

    def _del_add_addr(self,link,addr,action):
        """
        Add or delete an address to/from an interface
        """
        # get interface
        if isinstance(link,str):
            key = self.get_link(link)["index"]
        elif isinstance(link,int):
            key = link
        else:
            raise NotImplemented()

        # invalidate cache
        self.cache = {}

        ad = addr.split("/")
        request = {
            "index": key,
            "action": action,
            "type": "address",
            "mask": get_short_mask(addr),
            "address": ad[0],
            "local": ad[0],
        }
        msg = self.parser.create(request)
        msg.hdr.flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL
        return self.query_nl(msg)


    def get_addr(self,link=None,addr=None):
        """
        Get address[es] info for a link and|or for an address. If none
        supplied, get all adresses.
        """
        ret = self.get_all_addrs()
        if addr is None and link is None:
            return ret

        cache_key = 'addr:%s:%s' % (link,addr)
        if self.cache.has_key(cache_key):
            if time.time() - self.cache[cache_key][0] <= 60:
                return self.cache[cache_key][1]

        if link:
            result = [ y for y in [ x for x in ret if x.has_key('dev') ] if y['dev'] == link ]
        elif addr:
            result = [ y for y in [ x for x in ret if x.has_key('address') ] if y['address'] == addr ]

        self.cache[cache_key] = (time.time(), result)

        return result

    def get_all_addrs(self):
        """
        Get all addresses for all links.
        """
        msg = rtnl_msg()
        msg.hdr.type = RTM_GETADDR
        msg.hdr.flags = NLM_F_DUMP | NLM_F_REQUEST
        return self.query_nl(msg)

iproute2 = _iproute2()

def print_addr(addr):
    if addr["local"] != addr["address"]:
        # ppp/tunnel interface
        print("\tinet %s peer %s" % (addr["local"], addr["address"]))
    else:
        # local address
        print("\tinet %s/%i" % (addr["local"], addr["mask"]))

def print_link(link):
    print("%-5i%s: %s mtu %i qdisc %s" % (link["index"], link["dev"], link["flags"], link["mtu"], link["qdisc"]))
    if "hwaddr" in link.keys():
        print("\thwaddr %-17s broadcast %-17s" % (link["hwaddr"], link["broadcast"]))
    [ print_addr(addr) for addr in iproute2.get_addr(link["dev"]) ]
    print("")

def print_route(route):
    link = iproute2.get_link(int(route["output_link"]))
    if "dst_prefix" in route.keys():
        if "gateway" in route.keys():
            print("%15s/%-2s via %15s dev %s" % (route["dst_prefix"], route["dst_len"], route["gateway"], link["dev"]))
        else:
            print("%15s/%-2s                     dev %s" % (route["dst_prefix"], route["dst_len"], link["dev"]))
    else:
        print("           default via %15s" % (route["gateway"]))

def print_neighbor(neigh):
    if not "lladdr" in neigh.keys():
        neigh["lladdr"] = "incomplete"
    link = iproute2.get_link(int(neigh["index"]))
    print("%16s %15s %17s" % (link["dev"], neigh["dest"], neigh["lladdr"]))
if __name__ == "__main__":

    print("\nLinks:")
    [ print_link(x) for x in iproute2.get_all_links() ]
    print("\nRoutes in the table `main':")
    [ print_route(x) for x in iproute2.get_all_routes() ]
    print("\nRoutes in the table `local':")
    [ print_route(x) for x in iproute2.get_all_routes(table=255) ]
    print("\nARP cache:")
    [ print_neighbor(x) for x in iproute2.get_all_neighbors() ]

