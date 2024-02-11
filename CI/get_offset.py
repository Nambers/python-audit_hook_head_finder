#!audit_hook_head_finder
from audit_hook_head_finder import get_interp_audit_hook_ptr_addr
import sys, ctypes

sys.addaudithook(lambda *_: None)

obj = ctypes.byref(ctypes.py_object(()))
print(get_interp_audit_hook_ptr_addr() - ctypes.cast(obj, ctypes.POINTER(ctypes.c_uint64)).contents.value)