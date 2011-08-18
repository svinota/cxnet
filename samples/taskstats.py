#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    taskstats
    ~~~~~~~~~

    A minimal :mod:`cxnet.netlink.taskstats` usage example.

    :copyright: (c) 2011 by ALT Linux, Peter V. Saveliev, see AUTHORS
                for more details.
    :license: GPL, see LICENSE for more details.
"""

import sys
from ctypes import addressof, c_uint32, create_string_buffer, sizeof

from cxnet.netlink.core import nlattr, NLMSG_ALIGN
from cxnet.netlink.generic import genl_socket
from cxnet.netlink.taskstats import (
    TASKSTATS_CMD_GET, TASKSTATS_CMD_ATTR_PID,
    TASKSTATS_CMD_ATTR_REGISTER_CPUMASK,
    TASKSTATS_TYPE_PID, TASKSTATS_TYPE_AGGR_PID,

    taskstatsmsg
)
from cxnet.utils import hprint


if __name__ == "__main__":
    # 1. get TASKSTATS protocol id
    s = genl_socket()
    prid = s.get_protocol_id("TASKSTATS")

    # 2. get TASKSTATS structure for a pid or for own process
    pid, mask = None, None

    if len(sys.argv) > 1:
        try:
            pid = int(sys.argv[1])
        except ValueError:
            mask = sys.argv[1][1:]
    else:
        import os
        pid = os.getpid()

    if pid:
        s.send_cmd(prid, TASKSTATS_CMD_GET, TASKSTATS_CMD_ATTR_PID, c_uint32(pid))
        l, msg = s.recv()

    if mask:
        s.send_cmd(prid,
                   TASKSTATS_CMD_GET,
                   TASKSTATS_CMD_ATTR_REGISTER_CPUMASK,
                   create_string_buffer(mask, 8))
        l, msg = s.recv()

    a = nlattr.from_address(addressof(msg.data))
    assert a.nla_type == TASKSTATS_TYPE_AGGR_PID
    pid = nlattr.from_address(addressof(msg.data) + sizeof(a))
    assert pid.nla_type == TASKSTATS_TYPE_PID
    stats = taskstatsmsg.from_address(addressof(msg.data) + sizeof(a) +
                                      NLMSG_ALIGN(pid.nla_len) + sizeof(nlattr))

    print(stats)    # Taskstats structure.
    print("\n")
    hprint(msg, l)  # Raw packet dump.
