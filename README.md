# python audit_hooks head finder

This POC intends to show how to find the audit hook and use `ctypes` to pop it (~~SMASH it~~).

The idea is inspired by `misc/diligent-auditor` and `misc/IRS` challeneges and their solve scripts from [dicectf-quals-2024 CTF](https://github.com/dicegang/dicectf-quals-2024-challenges/).

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
## TODO
- [ ] Use <https://bugs.python.org/issue43838>/<https://github.com/python/cpython/issues/91153> to smash it without `ctypes`