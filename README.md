# python-audit_hook_head_finder

This POC intends to show how to find the audit hook and use `ctypes` to pop it (~~SMASH it~~).

The idea is inspired by `misc/diligent-auditor` and `misc/IRS` challeneges and their solve scripts from [dicectf-quals-2024 CTF](https://github.com/dicegang/dicectf-quals-2024-challenges/).

## How to use
```bash
./build.sh
./POC.py
python POC2.py
```

## Output
```bash
> ./POC.py
PyInterpreterState_addr=0x7a9f12b1b830
PyRuntimeState_addr=0x7a9f12a40e90
PyInterpreterState.audit_hooks_ptr_addr=0x7a9f12a40df0

audit_hook_ptr_offset=0xe00
1
audit hook triggered!
test audit hook -- this will trigger hook
test audit hook -- this will not
> python ./POC2.py
audit hook triggered!
test audit hook -- this will trigger hook
test audit hook -- this will not
```

## TODO
- [ ] Use <https://bugs.python.org/issue43838> to smash it without `ctypes`