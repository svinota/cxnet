"""
Netlink Taskstats protocol implementation
"""

#     Copyright (c) 2008-2011 ALT Linux, Peter V. Saveliev
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

from generic import *
from genetlink import *
from cxnet.common import *


TASKSTATS_VERSION = 6
TS_COMM_LEN = 32

class taskstatsmsg(Structure):
    _pack_ = 8
    _fields_ = [

    # The version number of this struct. This field is always set to
    # TAKSTATS_VERSION, which is defined in <linux/taskstats.h>.
    # Each time the struct is changed, the value should be incremented.
    ("version",    c_uint16),
    ("ac_exitcode",c_uint32),    # Exit status

    # The accounting flags of a task as defined in <linux/acct.h>
    # Defined values are AFORK, ASU, ACOMPAT, ACORE, and AXSIG.
    ("ac_flag",    c_uint8),    # Record flags
    ("ac_nice",    c_uint8),    # task_nice

    # Delay accounting fields start
    #
    # All values, until comment "Delay accounting fields end" are
    # available only if delay accounting is enabled, even though the last
    # few fields are not delays
    #
    # xxx_count is the number of delay values recorded
    # xxx_delay_total is the corresponding cumulative delay in nanoseconds
    #
    # xxx_delay_total wraps around to zero on overflow
    # xxx_count incremented regardless of overflow

    # Delay waiting for cpu, while runnable
    # count, delay_total NOT updated atomically
    ("cpu_count",        c_uint64),    #__u64    cpu_count __attribute__((aligned(8)));
    ("cpu_delay_total",  c_uint64),


    # Following four fields atomically updated using task->delays->lock

    # Delay waiting for synchronous block I/O to complete
    # does not account for delays in I/O submission
    ("blkio_count",           c_uint64),
    ("blkio_delay_total",     c_uint64),

    # Delay waiting for page fault I/O (swap in only)
    ("swapin_count",          c_uint64),
    ("swapin_delay_total",    c_uint64),

    # cpu "wall-clock" running time
    # On some architectures, value will adjust for cpu time stolen
    # from the kernel in involuntary waits due to virtualization.
    # Value is cumulative, in nanoseconds, without a corresponding count
    # and wraps around to zero silently on overflow
    ("cpu_run_real_total",    c_uint64),

    # cpu "virtual" running time
    # Uses time intervals seen by the kernel i.e. no adjustment
    # for kernel's involuntary waits due to virtualization.
    # Value is cumulative, in nanoseconds, without a corresponding count
    # and wraps around to zero silently on overflow
    ("cpu_run_virtual_total", c_uint64),

    # Delay accounting fields end
    # version 1 ends here

    # Basic Accounting Fields start
    ("ac_comm",     (c_char * (TS_COMM_LEN))),    # Command name
    ("ac_sched",    c_ubyte),             # Scheduling discipline
    ("ac_pad",      (c_ubyte * 5)),       # ! Alignment hack !
    ("ac_uid",      c_uint32),            # User ID
    ("ac_gid",      c_uint32),            # Group ID
    ("ac_pid",      c_uint32),            # Process ID
    ("ac_ppid",     c_uint32),            # Parent process ID
    ("ac_btime",    c_uint32),            # Begin time [sec since 1970]
    ("ac_etime",    c_uint64),            # Elapsed time [usec]
    ("ac_utime",    c_uint64),            # User CPU time [usec]
    ("ac_stime",    c_uint64),            # System CPU time [usec]
    ("ac_minflt",   c_uint64),            # Minor Page Fault Count
    ("ac_majflt",   c_uint64),            # Major Page Fault Count
    # Basic Accounting Fields end

    # Extended accounting fields start
    # Accumulated RSS usage in duration of a task, in MBytes-usecs.
    # The current rss usage is added to this counter every time
    # a tick is charged to a task's system time. So, at the end we
    # will have memory usage multiplied by system time. Thus an
    # average usage per system time unit can be calculated.
    ("coremem",    c_uint64),            # accumulated RSS usage in MB-usec
    # Accumulated virtual memory usage in duration of a task.
    # Same as acct_rss_mem1 above except that we keep track of VM usage.
    ("virtmem",    c_uint64),            # accumulated VM  usage in MB-usec

    # High watermark of RSS and virtual memory usage in duration of
    # a task, in KBytes.
    ("hiwater_rss",   c_uint64),            # High-watermark of RSS usage, in KB
    ("hiwater_vm",    c_uint64),            # High-water VM usage, in KB

    # The following four fields are I/O statistics of a task.
    ("read_char",        c_uint64),        # bytes read
    ("write_char",       c_uint64),        # bytes written
    ("read_syscalls",    c_uint64),        # read syscalls
    ("write_syscalls",   c_uint64),        # write syscalls
    # Extended accounting fields end

    # Per-task storage I/O accounting starts
    ("read_bytes",             c_uint64),    # bytes of read I/O
    ("write_bytes",            c_uint64),    # bytes of write I/O
    ("cancelled_write_bytes",  c_uint64),    # bytes of cancelled write I/O
    ("nvcsw",                  c_uint64),    # voluntary_ctxt_switches
    ("nivcsw",                 c_uint64),    # nonvoluntary_ctxt_switches

    # time accounting for SMT machines
    ("ac_utimescaled",               c_uint64),    # utime scaled on frequency etc
    ("ac_stimescaled",               c_uint64),    # stime scaled on frequency etc
    ("cpu_scaled_run_real_total",    c_uint64),    # scaled cpu_run_real_total

    ]

    descriptions = {
        "version":                  "Taskstats protocol version",
        "ac_exitcode":              "Exit status",
        "ac_flag":                  "The accounting flags of a task (AFORK|ASU|ACOMPAT|ACORE|AXSIG) (linux/acct.h)",
        "ac_nice":                  "Task nice",
        # See taskstatsmsg structure description!
        "cpu_count":                "Number of CPU delay values recorded",
        "cpu_delay_total":          "CPU cumulative delay in nanoseconds (wraps on overflow)",
        "blkio_count":              "Number of delays waiting for synchronous block I/O to complete",
        "blkio_delay_total":        "Cumulative delay waiting for synchronous block I/O to complete",
        "swapin_count":             "Number of delays waiting for page fault I/O (swap in only)",
        "swapin_delay_total":       "Cumulative delay waiting for page fault I/O (swap in only)",
        # Following four fields atomically updated using task->delays->lock
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
        # The following four fields are I/O statistics of a task.
        "read_char":                "Bytes read",
        "write_char":               "Bytes written",
        "read_syscalls":            "Read syscalls",
        "write_syscalls":           "Write syscalls",
        # Per-task storage I/O accounting starts
        "read_bytes":               "Bytes of read I/O",
        "write_bytes":              "Bytes of write I/O",
        "cancelled_write_bytes":    "Bytes of cancelled write I/O",
        "nvcsw":                    "Voluntary_ctxt_switches",
        "nivcsw":                   "Nonvoluntary_ctxt_switches",
        # Time accounting for SMT machines
        "ac_utimescaled":           "Utime scaled on frequency etc",
        "ac_stimescaled":           "Stime scaled on frequency etc",
        "cpu_scaled_run_real_total":"Scaled cpu_run_real_total",
    }

    def pprint(self,attr):
        print("%-26s%-32s%s" % (attr,getattr(self,attr),self.descriptions[attr]))

#
# Commands sent from userspace
# Not versioned.

TASKSTATS_CMD_UNSPEC     = 0    # Reserved
TASKSTATS_CMD_GET        = 1    # user->kernel request/get-response
TASKSTATS_CMD_NEW        = 2    # kernel->user event

TASKSTATS_TYPE_UNSPEC     = 0    # Reserved
TASKSTATS_TYPE_PID        = 1    # Process id
TASKSTATS_TYPE_TGID       = 2    # Thread group id
TASKSTATS_TYPE_STATS      = 3    # taskstats structure
TASKSTATS_TYPE_AGGR_PID   = 4    # contains pid + stats
TASKSTATS_TYPE_AGGR_TGID  = 5    # contains tgid + stats

TASKSTATS_CMD_ATTR_UNSPEC             = 0
TASKSTATS_CMD_ATTR_PID                = 1
TASKSTATS_CMD_ATTR_TGID               = 2
TASKSTATS_CMD_ATTR_REGISTER_CPUMASK   = 3
TASKSTATS_CMD_ATTR_DEREGISTER_CPUMASK = 4




if __name__ == "__main__":
    ###
    #
    # 1. get TASKSTATS protocol id
    #
    s = genl_socket()
    prid = s.get_protocol_id("TASKSTATS")
    ###
    #
    # 2. get TASKSTATS structure for a pid or for own process
    #
    try:
        import sys
        pid = int(sys.argv[1])
    except:
        import os
        pid = os.getpid()

    (l,msg) = s.send_cmd(prid,TASKSTATS_CMD_GET,TASKSTATS_TYPE_PID,c_uint32(pid))
    a = nlattr.from_address(addressof(msg.data))
    assert a.nla_type == TASKSTATS_TYPE_AGGR_PID
    pid = nlattr.from_address(addressof(msg.data) + sizeof(a))
    assert pid.nla_type == TASKSTATS_TYPE_PID
    stats = taskstatsmsg.from_address(addressof(msg.data) + sizeof(a) + NLMSG_ALIGN(pid.nla_len) + sizeof(nlattr))

    print("Running task accounting (task is not finished yet!):\n")
    [ stats.pprint(s) for s in ("ac_comm","ac_uid","ac_gid","ac_pid","ac_ppid","ac_btime","ac_etime","ac_utime","ac_stime","read_char","write_char","read_syscalls","write_syscalls","cpu_run_real_total","cpu_run_virtual_total") ]
    print("\nraw packet dump:")
    hprint(msg,l)
