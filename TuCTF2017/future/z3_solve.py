#!/usr/bin/env python3
from z3 import *

alt_flag = b"\x8b\xce\xb0\x89\x7b\xb0\xb0\xee\xbf\x92\x65\x9d\x9a\x99\x99\x94\xad\xe4\x00"

# auth[0] = mat[0][0] + mat[4][4];
# auth[1] = mat[2][1] + mat[0][2];
# auth[2] = mat[4][2] + mat[4][1];
# auth[3] = mat[1][3] + mat[3][1];
# auth[4] = mat[3][4] + mat[1][2];
# auth[5] = mat[1][0] + mat[2][3];
# auth[6] = mat[2][4] + mat[2][0];
# auth[7] = mat[3][3] + mat[3][2] + mat[0][3];
# auth[8] = mat[0][4] + mat[4][0] + mat[0][1];
# auth[9] = mat[3][3] + mat[2][0];
# auth[10] = mat[4][0] + mat[1][2];
# auth[11] = mat[0][4] + mat[4][1];
# auth[12] = mat[0][3] + mat[0][2];
# auth[13] = mat[3][0] + mat[2][0];
# auth[14] = mat[1][4] + mat[1][2];
# auth[15] = mat[4][3] + mat[2][3];
# auth[16] = mat[2][2] + mat[0][2];
# auth[17] = mat[1][1] + mat[4][1];

inp = []
for i in range(25):
    byte = BitVec(str(i), 16)
    inp.append(byte)

mat = [[0 for j in range(5)] for i in range(5)]
for i in range(25):
    m = (i * 2) % 25
    f = (i * 7) % 25
    mat[m//5][m%5] = inp[f]

z = Solver()

z.add((mat[0][0] + mat[4][4]) == alt_flag[0])
z.add((mat[2][1] + mat[0][2]) == alt_flag[1])
z.add((mat[4][2] + mat[4][1]) == alt_flag[2])
z.add((mat[1][3] + mat[3][1]) == alt_flag[3])
z.add((mat[3][4] + mat[1][2]) == alt_flag[4])
z.add((mat[1][0] + mat[2][3]) == alt_flag[5])
z.add((mat[2][4] + mat[2][0]) == alt_flag[6])
z.add((mat[3][3] + mat[3][2] + mat[0][3]) == alt_flag[7])
z.add((mat[0][4] + mat[4][0] + mat[0][1]) == alt_flag[8])
z.add((mat[3][3] + mat[2][0]) == alt_flag[9])
z.add((mat[4][0] + mat[1][2]) == alt_flag[10])
z.add((mat[0][4] + mat[4][1]) == alt_flag[11])
z.add((mat[0][3] + mat[0][2]) == alt_flag[12])
z.add((mat[3][0] + mat[2][0]) == alt_flag[13])
z.add((mat[1][4] + mat[1][2]) == alt_flag[14])
z.add((mat[4][3] + mat[2][3]) == alt_flag[15])
z.add((mat[2][2] + mat[0][2]) == alt_flag[16])
z.add((mat[1][1] + mat[4][1]) == alt_flag[17])

for i in range(25):
    z.add(inp[i] > 0x20)
    z.add(inp[i] < 0x7d)

z.add(inp[0] == ord('T'))
z.add(inp[1] == ord('U'))
z.add(inp[2] == ord('C'))
z.add(inp[3] == ord('T'))
z.add(inp[4] == ord('F'))
z.add(inp[5] == ord('{'))

if z.check() == sat:
    solution = z.model()

    flag = ""
    for i in range(25):
        try:
            flag += chr(int(str(solution[inp[i]])))
        except:
            pass

    print(flag)
