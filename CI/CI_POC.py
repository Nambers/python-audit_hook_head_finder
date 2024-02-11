import sys, ctypes, os

sys.addaudithook(lambda *x: print(x))

obj = ctypes.byref(ctypes.py_object(()))

os.system("echo 'test audit hook -- this will trigger hook'")

ctypes.cast(
    ctypes.cast(
        ctypes.cast(obj, ctypes.POINTER(ctypes.c_uint64)).contents.value + int(sys.argv[1]), ctypes.POINTER(ctypes.c_uint64)
    ).contents.value
    , ctypes.py_object
).value.pop()


os.system("echo 'test audit hook -- this will not'")