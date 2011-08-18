# -*- coding: utf-8 -*-
"""
    cxnet.netlink.taskstats
    ~~~~~~~~~~~~~~~~~~~~~~~

    This module implement Netlink taskstats protocol.

    .. seealso::

       `Linux Kernel Documentation on taskstats \
         <http://www.kernel.org/doc/Documentation/accounting/taskstats.txt>`_
         For details on protocol internals.
       `taskstats.h \
         <http://www.kernel.org/doc/Documentation/accounting/taskstats-struct.txt>`_
         For taskstats structure description.

    :copyright: (c) 2011 by ALT Linux, Peter V. Saveliev, see AUTHORS
                for more details.
    :license: GPL, see LICENSE for more details.
"""

from __future__ import absolute_import

from ctypes import Structure
from ctypes import c_uint8, c_uint16, c_uint32, c_uint64, c_char, c_ubyte


#: Taskstats structure description, taken from ``taskstats.h`` -- this
#: makes little PEP-8 cry >.<
TASKSTATS_DESCRIPTION = {
    "version" :                 "Taskstats protocol version",
    "ac_exitcode":              "Exit status",
    "ac_flag":                  "The accounting flags of a task (AFORK|ASU|ACOMPAT|ACORE|AXSIG) (linux/acct.h)",
    "ac_nice":                  "Task nice",
    "cpu_count":                "Number of CPU delay values recorded",
    "cpu_delay_total":          "CPU cumulative delay in nanoseconds (wraps on overflow)",
    "blkio_count":              "Number of delays waiting for synchronous block I/O to complete",
    "blkio_delay_total":        "Cumulative delay waiting for synchronous block I/O to complete",
    "swapin_count":             "Number of delays waiting for page fault I/O (swap in only)",
    "swapin_delay_total":       "Cumulative delay waiting for page fault I/O (swap in only)",
    "cpu_run_real_total":       "CPU `wall-clock' running time in nanoseconds, wraps on overflow",
    "cpu_run_virtual_total":    "CPU `virtual' running time (as seen by the kernel)",
    "ac_comm":                  "Command name",
    "ac_sched":                 "Scheduling discipline",
    "ac_uid":                   "User ID",
    "ac_gid":                   "Group ID",
    "ac_pid":                   "Process ID",
    "ac_ppid":                  "Parent process ID",
    "ac_btime":                 "Begin time [sec since 1970]",
    "ac_etime":                 "Elapsed time [usec]",
    "ac_utime":                 "User CPU time [usec]",
    "ac_stime":                 "System CPU time [usec]",
    "ac_minflt":                "Minor Page Fault Count",
    "ac_majflt":                "Major Page Fault Count",
    "coremem":                  "Accumulated RSS usage in MB-usec",
    "virtmem":                  "Accumulated VM  usage in MB-usec",
    "hiwater_rss":              "High-watermark of RSS usage, in KB",
    "hiwater_vm":               "High-water VM usage, in KB",
    "read_char":                "Bytes read",
    "write_char":               "Bytes written",
    "read_syscalls":            "Read syscalls",
    "write_syscalls":           "Write syscalls",
    "read_bytes":               "Bytes of read I/O",
    "write_bytes":              "Bytes of write I/O",
    "cancelled_write_bytes":    "Bytes of cancelled write I/O",
    "nvcsw":                    "Voluntary_ctxt_switches",
    "nivcsw":                   "Nonvoluntary_ctxt_switches",
    "ac_utimescaled":           "Utime scaled on frequency etc",
    "ac_stimescaled":           "Stime scaled on frequency etc",
    "cpu_scaled_run_real_total":"Scaled cpu_run_real_total",
}


TASKSTATS_VERSION = 6

#
# Commands sent from userspace
# Not versioned.

TASKSTATS_CMD_UNSPEC = 0      # Reserved
TASKSTATS_CMD_GET = 1         # user->kernel request/get-response
TASKSTATS_CMD_NEW = 2         # kernel->user event

TASKSTATS_TYPE_UNSPEC = 0     # Reserved
TASKSTATS_TYPE_PID = 1        # Process id
TASKSTATS_TYPE_TGID = 2       # Thread group id
TASKSTATS_TYPE_STATS = 3      # taskstats structure
TASKSTATS_TYPE_AGGR_PID = 4   # contains pid + stats
TASKSTATS_TYPE_AGGR_TGID = 5  # contains tgid + stats

TASKSTATS_CMD_ATTR_UNSPEC = 0
TASKSTATS_CMD_ATTR_PID = 1
TASKSTATS_CMD_ATTR_TGID = 2
TASKSTATS_CMD_ATTR_REGISTER_CPUMASK = 3
TASKSTATS_CMD_ATTR_DEREGISTER_CPUMASK = 4


class taskstatsmsg(Structure):
    _pack_ = 8
    _fields_ = [
        ("version", c_uint16),
        ("ac_exitcode", c_uint32),
        ("ac_flag", c_uint8),
        ("ac_nice", c_uint8),
        ("cpu_count", c_uint64),
        ("cpu_delay_total", c_uint64),
        ("blkio_count", c_uint64),
        ("blkio_delay_total", c_uint64),
        ("swapin_count", c_uint64),
        ("swapin_delay_total", c_uint64),
        ("cpu_run_real_total", c_uint64),
        ("cpu_run_virtual_total", c_uint64),

        ("ac_comm", c_char * 32),       # Command name
        ("ac_sched", c_ubyte),          # Scheduling discipline
        ("ac_pad", c_ubyte * 5),        # ! Alignment hack !
        ("ac_uid", c_uint32),           # User ID
        ("ac_gid", c_uint32),           # Group ID
        ("ac_pid", c_uint32),           # Process ID
        ("ac_ppid", c_uint32),          # Parent process ID
        ("ac_btime", c_uint32),         # Begin time [sec since 1970]
        ("ac_etime", c_uint64),         # Elapsed time [usec]
        ("ac_utime", c_uint64),         # User CPU time [usec]
        ("ac_stime", c_uint64),         # System CPU time [usec]
        ("ac_minflt", c_uint64),        # Minor Page Fault Count
        ("ac_majflt", c_uint64),        # Major Page Fault Count

        ("coremem", c_uint64),
        ("virtmem", c_uint64),
        ("hiwater_rss", c_uint64),
        ("hiwater_vm", c_uint64),

        ("read_char", c_uint64),
        ("write_char", c_uint64),
        ("read_syscalls", c_uint64),
        ("write_syscalls", c_uint64),

        ("read_bytes", c_uint64),
        ("write_bytes", c_uint64),
        ("cancelled_write_bytes", c_uint64),
        ("nvcsw", c_uint64),
        ("nivcsw", c_uint64),

        ("ac_utimescaled", c_uint64),
        ("ac_stimescaled", c_uint64),
        ("cpu_scaled_run_real_total", c_uint64),
    ]

    descriptions = TASKSTATS_DESCRIPTION

    def __str__(self):
        return "\n".join(
            "{0:<26}{1:<32}{2}".format(attr, getattr(self, attr), description)
            for attr, description in sorted(self.descriptions.items()))
