"""
    cxnet.netlink.iproute2
    ~~~~~~~~~~~~~~~~~~~~~~

    Netlink-based iproute2 implementation.

    Quick example::

        >>> from cxnet.netlink.iproute2 import IpRoute2
        >>> iproute2 = IpRoute2()
        >>> iproute2.get_route("8.8.8.8")
        [{'action': 'add',
          'dst_len': 0,
          'gateway': '192.168.40.1',
          'output_link': 2L,
          'src_len': 0,
          'table': 254L,
          'timestamp': 'Thu Aug 18 14:12:05 2011',
          'type': 'route'}]

    .. warning::

       * :mod:`cxnet` library implement a significantly simplified
         Netlink version -- so don't expect much.
       * It also uses :class:`Queue.Queue` objects, which results in
         poor performance.

    :copyright: (c) 2011 by ALT Linux, Peter V. Saveliev, see AUTHORS
                for more details.
    :license: GPL, see LICENSE for more details.
"""

import sys
import time
from threading import Thread, Condition, enumerate



assert (2,5) <= sys.version_info

#
#
from cxnet.common import NotImplemented
from cxnet.netlink.core import NLM_F_DUMP, NLM_F_REQUEST, NLM_F_ACK, NLM_F_CREATE, NLM_F_EXCL, NLM_F_MULTI, NLMSG_DONE
from cxnet.netlink.core import nlmsghdr
from cxnet.netlink.rtnl import RTNLGRP_IPV4_IFADDR, RTNLGRP_IPV4_ROUTE, RTNLGRP_IPV6_IFADDR, RTNLGRP_IPV6_ROUTE, RTNLGRP_LINK, RTNLGRP_NEIGH
from cxnet.netlink.rtnl import RTM_GETADDR, RTM_GETLINK, RTM_GETNEIGH, RTM_GETROUTE
from cxnet.netlink.rtnl import rtnl_socket, rtnl_msg_parser, rtnl_msg, ndmsg
from cxnet.netlink.exceptions import NetlinkError
from cxnet.utils import dqn_to_int,get_base,get_short_mask
from ctypes import sizeof, addressof, string_at
from select import poll,POLLIN
try:
    from Queue import Queue
except:
    from queue import Queue

import os


class IpRoute2(Thread):
    """
    There can be only one running RTNL socket at a time. We create
    it implicitly with _iproute2() at module import time. All
    communications and controls should be done with `iproute2'
    reference.
    """
    def __init__(self):
        token = "RT network subsystem interface"
        assert token not in [ x.name for x in enumerate() if hasattr(x,"name") ]
        Thread.__init__(self)
        self.setName(token)
        if hasattr(self,"setDaemon"):
            self.setDaemon(True)
        else:
            self.daemon = True
        self.e = poll()
        (self.ctlr,self.ctl) = os.pipe()
        self.socket = None
        self.mask = RTNLGRP_IPV4_IFADDR | RTNLGRP_IPV4_ROUTE | RTNLGRP_IPV6_IFADDR | RTNLGRP_IPV6_ROUTE | RTNLGRP_LINK | RTNLGRP_NEIGH
        self.restart_socket()
        self.e.register(self.ctlr,POLLIN)
        self.e.register(self.socket.fd,POLLIN)
        self.listeners = {
            0:  Queue(),
        }
        self.sync = Condition()
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

    def send_ctl(self,command):
        """
        Send a command via internal ctl pipe and wait for response.
        """
        self.sync.acquire()
        os.write(self.ctl,"%c" % (command))
        self.sync.wait()
        self.sync.release()

    def set_groups(self,mask):
        """
        Set group mask for RTNL socket
        """
        self.mask = mask
        self.send_ctl('s')

    def add_group(self,group):
        """
        Add a group to the RTNL socket mask
        """
        self.mask |= group
        self.send_ctl('s')

    def del_group(self,group):
        """
        Remove a group from the RTNL socket mask
        """
        self.mask ^= group
        self.send_ctl('s')

    def shutdown(self):
        """
        Completely shutdown the thread
        """
        self.send_ctl('q')

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
                        self.sync.acquire()
                        cmd = os.read(self.ctlr,1)
                        if cmd == "q":
                            # quit
                            self.__shutdown = True
                            self.e.unregister(self.socket.fd)
                            self.e.unregister(self.ctlr)
                            self.e.close()
                            self.socket.close()
                            self.sync.notify()
                            self.sync.release()
                            return
                        elif cmd == "s":
                            # restart socket
                            self.e.unregister(self.socket.fd)
                            self.restart_socket()
                            self.e.register(self.socket.fd,POLLIN)

                        self.sync.notify()
                        self.sync.release()

                    # receive and decode netlink message
                    elif fd[0] == self.socket.fd:
                        try:
                            (l,msg) = self.socket.recv()
                        except NetlinkError,e:
                            msg = e
                            l = sizeof(e.hdr)
                        key = msg.hdr.sequence_number
                        if key in self.listeners.keys():
                            # enqueue message into appropriate decoder queue
                            self.listeners[key].put((time.asctime(),l,msg))
                        if key != 0:
                            # copy message to default queue
                            self.listeners[0].put((time.asctime(),l,msg))
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
            if isinstance(msg,NetlinkError):
                raise msg
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


    def query_nl(self,msg,size=None):
        """
        Send a message via netlink. Please note that it is the very
        internal method and you should not call it.
        """
        key = self.nonce()
        self.listeners[key] = Queue()
        msg.hdr.sequence_number = key
        self.socket.send(msg,size)
        ret = self.get(key)
        del self.listeners[key]
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
        msg.data.route.family = 0
        msg.data.route.table = table
        ptr = addressof(msg.data) + sizeof(msg.data.route)
        return filter(lambda x: x['table'] == table, filter(lambda x: x['type'] == 'route', self.query_nl(msg,ptr - addressof(msg))))

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
        if addr.count(":") > 0:
            base = 128
            family = 10
        else:
            base = 32
            family = 2
        dst = dqn_to_int(addr)
        for i in ret:
            if ('dst_prefix' in i.keys()) \
                and ('dst_len' in i.keys()) \
                and (i['family'] == family):
                if dqn_to_int(i['dst_prefix']) == get_base(dst,i['dst_len'],base):
                    result['static'] = i
            elif ('dst_len' in i.keys()) \
                and ('src_len' in i.keys()) \
                and (i['family'] == family):
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
        return self.query_nl(msg)


    def add_addr(self,link,addr):
        return self._del_add_addr(link,addr,"add")

    def del_addr(self,link,addr):
        return self._del_add_addr(link,addr,"remove")

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

        if link:
            result = [ y for y in [ x for x in ret if x.has_key('dev') ] if y['dev'] == link ]
        elif addr:
            result = [ y for y in [ x for x in ret if x.has_key('address') ] if y['address'] == addr ]

        return result

    def get_all_addrs(self):
        """
        Get all addresses for all links.
        """
        msg = rtnl_msg()
        msg.hdr.type = RTM_GETADDR
        msg.hdr.flags = NLM_F_DUMP | NLM_F_REQUEST
        return self.query_nl(msg)

