#!/usr/bin/python
import collections
import glob
import re
import sys
import time


"""
00400000-00401000 r-xp 00000000 fd:00 2147488032
/usr/bin/python2.7
Size:                  4 kB
Rss:                   4 kB
Pss:                   0 kB
Shared_Clean:          4 kB
Shared_Dirty:          0 kB
Private_Clean:         0 kB
Private_Dirty:         0 kB
Referenced:            4 kB
Anonymous:             0 kB
AnonHugePages:         0 kB
Swap:                  0 kB
KernelPageSize:        4 kB
MMUPageSize:           4 kB
Locked:                0 kB
VmFlags: rd ex mr mw me dw
"""
def parse_smaps(pid):
    f_smaps = open("/proc/%d/smaps" % pid, 'r')
    memrange = None
    ranges = collections.defaultdict(dict)
    for line in f_smaps:
        memval = re.search("(?P<key>\w+):[ \t]+(?P<kb>\d+) kB", line)
        if memval:
            ranges[memrange][memval.group('key')] = (
                int(memval.group('kb')))
        else:
            if not line.startswith('VmFlags: '):
                memrange = line.rstrip()
    return ranges

def report_pss(pid, verbose=False):
    ranges = parse_smaps(pid)
    total_pss = 0
    tuples = []
    for key in ranges.keys():
        total_pss += ranges[key]['Pss']
        tuples.append((ranges[key]['Pss'], key))

    if verbose:
        sorted_tuples = sorted(tuples, key=lambda tup: tup[0])
        for entry in sorted_tuples:
            print "%d kB\t%s" % (entry[0], entry[1])

        print time.strftime("%H:%M:%S") + " Total Pss (MB):", total_pss * 0.001

    return total_pss

def report_all_processes(expr):
    cmdlines = glob.glob('/proc/*/cmdline')
    total_pss = 0
    for cmdline in cmdlines:
        args = open(cmdline, 'r').read().split('\0')
        if expr in args[0] or ('python' in args[0] and expr in args[1]):
            pidinfo = re.search("/proc/(?P<pid>\d+)/cmdline", cmdline)
            if pidinfo:
                pid = int(pidinfo.group('pid'))
                pss = report_pss(pid)
                print "%d kB\t(pid %d) %s" % (pss, pid, " ".join(args[:3]))
                total_pss += pss

    print ""
    print time.strftime("%H:%M:%S") + " Total Pss (MB):", total_pss*0.001


def main():
    if sys.argv[1]=='pss':
        report_pss(int(sys.argv[2]), verbose=True)
    if sys.argv[1]=='all':
        report_all_processes(sys.argv[2])


if __name__ == '__main__':
    main()
