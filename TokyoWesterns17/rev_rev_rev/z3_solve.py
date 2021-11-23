#!/usr/bin/env python3
from z3 import *

alt_flag = [42, 234, 194, 42, 98, 222, 142, 14, 94, 150, 206, 158, 34, 118, 70, 182, 70, 246, 94, 236, 108, 246, 230, 54, 30, 14, 94, 154, 38, 214, 190]

inp = []
for i in range(len(alt_flag)):
    byte = BitVec(str(i), 16)
    inp.append(byte)

z = Solver()

for i in range(len(alt_flag)):
    curr = inp[i]
    curr = (curr >> 1) & 0x55 | (curr & 0x55) << 1
    curr = (curr >> 2) & 0x33 | (curr & 0x33) << 2
    curr = curr >> 4 | curr << 4
    curr &= 0xff
    z.add(curr == alt_flag[i])

if z.check() == sat:
    solution = z.model()
    flag = ""
    for i in range(len(alt_flag)):
        flag += chr(int(str(solution[inp[i]])))

    print(flag)
