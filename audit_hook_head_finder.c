#include <stdint.h>
#define Py_BUILD_CORE 1
#include <Python.h>
#include <internal/pycore_interp.h>
#include <internal/pycore_runtime.h>

#define GET_RUNTIME_ADDR() &_PyRuntime
#define GET_INTERP_ADDR() _PyRuntime.interpreters.head
#define GET_INTERP_AUDIT_HOOK_PTR_ADDR() &GET_INTERP_ADDR()->audit_hooks
#if PY_MINOR_VERSION == 12
    #define GET_RUNTIME_AUDIT_HOOK_PTR_ADDR() &_PyRuntime.audit_hooks.head
#elif PY_MINOR_VERSION == 11
    #define GET_RUNTIME_AUDIT_HOOK_PTR_ADDR() &_PyRuntime.audit_hook_head
#else
    #define GET_RUNTIME_AUDIT_HOOK_PTR_ADDR() &_PyRuntime.audit_hook_head
#endif

static PyObject* get_runtime_addr(PyObject *self, PyObject *args) {
    return PyLong_FromSize_t((int64_t)GET_RUNTIME_ADDR());
}

static PyObject* get_interp_addr(PyObject *self, PyObject *args) {
    return PyLong_FromSize_t((int64_t)GET_INTERP_ADDR());
}

static PyObject* get_interp_audit_hook_ptr_addr(PyObject *self, PyObject *args){
    return PyLong_FromSize_t((int64_t)GET_INTERP_AUDIT_HOOK_PTR_ADDR());
}

static PyObject* get_runtime_audit_hook_ptr_addr(PyObject *self, PyObject *args){
    return PyLong_FromSize_t((int64_t)GET_RUNTIME_AUDIT_HOOK_PTR_ADDR());
}

static int audit(const char *event, PyObject *args, void *userData) {
	printf("C audit hook triggered!\n");
    fflush(stdout);
	return 0;
}

static PyObject* add_audit(PyObject *self, PyObject *args) {
	PySys_AddAuditHook(audit, NULL);
	Py_RETURN_NONE;
}

static PyObject* print_all(PyObject *self, PyObject *args) {
    printf("PyInterpreterState_addr=0x%lx\n", (int64_t)GET_INTERP_ADDR());
    printf("PyRuntimeState_addr=0x%lx\n", (int64_t)GET_RUNTIME_ADDR());
    printf("PyInterpreterState.audit_hooks_ptr_addr=0x%lx\n", (int64_t)GET_INTERP_AUDIT_HOOK_PTR_ADDR());
    printf("PyRuntimeState.audit_hooks_ptr_addr=0x%lx\n", (int64_t)GET_RUNTIME_AUDIT_HOOK_PTR_ADDR());
    printf("\n");
    fflush(stdout);
    Py_RETURN_NONE;
}

static PyMethodDef FinderMethods[] = {
	{"get_runtime_addr", get_runtime_addr, METH_VARARGS, ""},
    {"get_interp_addr", get_interp_addr, METH_VARARGS, ""},
    {"print_all", print_all, METH_VARARGS, ""},
    {"get_interp_audit_hook_ptr_addr", get_interp_audit_hook_ptr_addr, METH_VARARGS, ""},
    {"get_runtime_audit_hook_ptr_addr", get_runtime_audit_hook_ptr_addr, METH_VARARGS, ""},
    {"add_audit", add_audit, METH_VARARGS, ""},
	{NULL, NULL, 0, NULL}
};

static PyModuleDef FinderModule = {
	PyModuleDef_HEAD_INIT, "audit_hook_head_finder", NULL, -1, FinderMethods,
	NULL, NULL, NULL, NULL
};

static PyObject* PyInit_Finder(void) {
	return PyModule_Create(&FinderModule);
}

int main(int argc, char **argv) {
    assert(PY_MAJOR_VERSION == 3);
    if(PY_MINOR_VERSION != 11 && PY_MINOR_VERSION != 12){
        printf("[WARN] PY_MINOR_VERSION=%d is not tested\n", PY_MINOR_VERSION);
    }
	PyImport_AppendInittab("audit_hook_head_finder", &PyInit_Finder);
    Py_Initialize();
	return Py_BytesMain(argc, argv);
}
