from __future__ import print_function
from __future__ import unicode_literals

import os
import string

import gdb
import pwndbg.commands
import re
import argparse
import subprocess
import sys

try:
    import psutil
except:
    psutil = None

def gef_execute_external(command, *args, **kwargs):
    res = subprocess.check_output(command, stderr=subprocess.STDOUT, shell=kwargs.get("shell", False))

    if kwargs.get("as_list", False) == True:
        return res.splitlines()

    if sys.version_info[0] == 3:
        return str(res, encoding="ascii" )

    return res


class ProcessAttachCommand:
    """List and filter process."""

    def __init__(self, args, follow_child=False):
        self.do_invoke(args, follow_child)

    def do_invoke(self, args, follow_child=False):
        processes = self.ps()

        do_attach  = True
        smart_scan = True
        child_process = 0
        process_name = ""
        pattern = re.compile("^.*$") if len(args)==0 else re.compile(args)

        for process in processes:
            pid = int(process["pid"])
            command = process['command']

            if not re.search(pattern, command):
                continue

            if smart_scan:
                if command.startswith("[") and command.endswith("]"): continue
                if command.startswith("socat "): continue
                if command.startswith("grep "): continue
                if command.startswith("gdb "): continue

            if len(args) and do_attach:
                if pid > child_process and follow_child:
                    process_name = process["command"]
                    child_process = pid 
                else:
                    print("Attaching to process='%s' pid=%d" % (process["command"], pid))
                    gdb.execute("attach %d" % pid)
                    return None

            line = [ process[i] for i in ("pid", "user", "cpu", "mem", "tty", "command") ]
            print ( '\t\t'.join(line) )
        if child_process != 0:
            print("Attaching to process='%s' pid=%d" % (process_name, child_process))
            gdb.execute("attach %d" % child_process)

        return None


    def ps(self):
        ps_command = "/bin/ps auxww"
        processes = []
        test = ps_command.split()
        output = gef_execute_external(test, True).splitlines()
        names = [x.lower().replace('%','') for x in output[0].split()]

        for line in output[1:]:
            fields = line.split()
            t = {}

            for i in range(len(names)):
                if i==len(names)-1:
                    t[ names[i] ] = ' '.join(fields[i:])
                else:
                    t[ names[i] ] = fields[i]

            processes.append(t)

        return processes



@pwndbg.commands.Command
def pg(regex_string):
    if regex_string and regex_string != "":
        ProcessAttachCommand(regex_string)

@pwndbg.commands.Command
def pgc(regex_string):
    if regex_string and regex_string != "":
        ProcessAttachCommand(regex_string, True)
