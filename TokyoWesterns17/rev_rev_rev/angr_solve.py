#!/usr/bin/env python3
import sys
import angr

################################################################################
# VERSION WITH FIND
################################################################################
project = angr.Project("./rev_rev_rev")
state = project.factory.entry_state()
simmgr = project.factory.simulation_manager(state)
find = 0x08048679
simmgr.explore(find=find)

if simmgr.found[0]:
    found = simmgr.found[0]
    print("Solution found!")
    print(found.posix.dumps(sys.stdin.fileno()))
