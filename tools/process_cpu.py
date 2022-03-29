#!/usr/bin/python

from __future__ import print_function
from bcc import BPF, PerfType, PerfSWConfig
from time import sleep, strftime
from tempfile import NamedTemporaryFile
from os import open, close, dup, unlink, O_WRONLY
import argparse

# arguments
examples = """examples:
    ./process_cpu -p $pid 5           
"""
parser = argparse.ArgumentParser(
    description="Summarize scheduler process running cpu as a histogram",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-T", "--timestamp", action="store_true",
                    help="include timestamp on output")
parser.add_argument("-p", "--pid", dest="pid",
                    help="filter pid", type=int)
parser.add_argument("interval", nargs="?", default=99999999,
                    help="output interval, in seconds")
parser.add_argument("count", nargs="?", default=99999999,
                    help="number of outputs")
parser.add_argument("--ebpf", action="store_true",
                    help=argparse.SUPPRESS)
args = parser.parse_args()
countdown = int(args.count)
debug = 0
frequency = 99

# Linux 4.15 introduced a new field runnable_weight
# in linux_src:kernel/sched/sched.h as
#     struct cfs_rq {
#         struct load_weight load;
#         unsigned long runnable_weight;
#         unsigned int nr_running, h_nr_running;
#         ......
#     }
# and this tool requires to access nr_running to get
# runqueue len information.
#
# The commit which introduces cfs_rq->runnable_weight
# field also introduces the field sched_entity->runnable_weight
# where sched_entity is defined in linux_src:include/linux/sched.h.
#
# To cope with pre-4.15 and 4.15/post-4.15 releases,
# we run a simple BPF program to detect whether
# field sched_entity->runnable_weight exists. The existence of
# this field should infer the existence of cfs_rq->runnable_weight.
#
# This will need maintenance as the relationship between these
# two fields may change in the future.
#


def check_runnable_weight_field():
    # Define the bpf program for checking purpose
    bpf_check_text = """
#include <linux/sched.h>
unsigned long dummy(struct sched_entity *entity)
{
    return entity->runnable_weight;
}
"""

    # Get a temporary file name
    tmp_file = NamedTemporaryFile(delete=False)
    tmp_file.close()

    # Duplicate and close stderr (fd = 2)
    old_stderr = dup(2)
    close(2)

    # Open a new file, should get fd number 2
    # This will avoid printing llvm errors on the screen
    fd = open(tmp_file.name, O_WRONLY)
    try:
        t = BPF(text=bpf_check_text)
        success_compile = True
    except:
        success_compile = False

    # Release the fd 2, and next dup should restore old stderr
    close(fd)
    dup(old_stderr)
    close(old_stderr)

    # remove the temporary file and return
    unlink(tmp_file.name)
    return success_compile


# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

// Declare enough of cfs_rq to find nr_running, since we can't #import the
// header. This will need maintenance. It is from kernel/sched/sched.h:
struct cfs_rq_partial {
    struct load_weight load;
    RUNNABLE_WEIGHT_FIELD
    unsigned int nr_running, h_nr_running;
};

typedef struct cpu_key {
    int cpu;
    unsigned int slot;
} cpu_key_t;
STORAGE

int do_perf_event()
{
    unsigned int len = 0;
    unsigned int cpu = 0;
    pid_t pid = 0;
    struct task_struct *task = NULL;
    struct cfs_rq_partial *my_q = NULL;

    // Fetch the run queue length from task->se.cfs_rq->nr_running. This is an
    // unstable interface and may need maintenance. Perhaps a future version
    // of BPF will support task_rq(p) or something similar as a more reliable
    // interface.
    task = (struct task_struct *)bpf_get_current_task();
    my_q = (struct cfs_rq_partial *)task->se.cfs_rq;

    FILTER

    cpu = bpf_get_smp_processor_id();


    STORE

    return 0;
}
"""


def generate_pid_filter():
    if args.pid:
        return "if(task->tgid != %d) return 0;" % args.pid
    else:
        return ""


# code substitutions
bpf_text = bpf_text.replace('STORAGE',
                            'BPF_HISTOGRAM(dist, unsigned int);')
bpf_text = bpf_text.replace('STORE', 'dist.increment(cpu);')
bpf_text = bpf_text.replace('FILTER', generate_pid_filter())

if check_runnable_weight_field():
    bpf_text = bpf_text.replace(
        'RUNNABLE_WEIGHT_FIELD', 'unsigned long runnable_weight;')
else:
    bpf_text = bpf_text.replace('RUNNABLE_WEIGHT_FIELD', '')

if debug or args.ebpf:
    print(bpf_text)
    if args.ebpf:
        exit()

# initialize BPF & perf_events
b = BPF(text=bpf_text)
b.attach_perf_event(ev_type=PerfType.SOFTWARE,
                    ev_config=PerfSWConfig.CPU_CLOCK, fn_name="do_perf_event",
                    sample_period=0, sample_freq=frequency)

print("Sampling pid running cpu ... Hit Ctrl-C to end.")

# output
exiting = 0 if args.interval else 1
dist = b.get_table("dist")
while (1):
    try:
        sleep(int(args.interval))
    except KeyboardInterrupt:
        exiting = 1

    print()
    if args.timestamp:
        print("%-8s\n" % strftime("%H:%M:%S"), end="")

    dist.print_linear_hist("cpu", "count")

    dist.clear()

    countdown -= 1
    if exiting or countdown == 0:
        exit()
