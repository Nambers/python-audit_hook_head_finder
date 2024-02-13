#include <stdint.h>
#define Py_BUILD_CORE 1
#include <Python.h>
#include <internal/pycore_interp.h>
#include <internal/pycore_runtime.h>


static PyObject* get_runtime_addr(PyObject *self, PyObject *args) {
    return PyLong_FromSize_t((int64_t)&_PyRuntime);
}

static PyObject* get_interp_addr(PyObject *self, PyObject *args) {
    _PyRuntimeState *runtime = &_PyRuntime;
    PyInterpreterState *interp = runtime->interpreters.head;
    return PyLong_FromSize_t((int64_t)interp);
}

static PyObject* get_interp_audit_hook_ptr_addr(PyObject *self, PyObject *args){
    _PyRuntimeState *runtime = &_PyRuntime;
    PyInterpreterState *interp = runtime->interpreters.head;
    return PyLong_FromSize_t((int64_t)&interp->audit_hooks);
}

static PyObject* get_runtime_audit_hook_ptr_addr(PyObject *self, PyObject *args){
    _PyRuntimeState *runtime = &_PyRuntime;
    #if PY_MINOR_VERSION == 12
        return PyLong_FromSize_t((int64_t)&runtime->audit_hooks.head);
    #elif PY_MINOR_VERSION == 11
        return PyLong_FromSize_t((int64_t)&runtime->audit_hook_head);
    #else
        printf("[WARN] PY_MINOR_VERSION=$d is not tested\n", PY_MINOR_VERSION);
        return PyLong_FromSize_t((int64_t)&runtime->audit_hook_head);
    #endif
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
    printf("PyInterpreterState_addr=%p\n", get_interp_addr(self, args));
    printf("PyRuntimeState_addr=%p\n", get_runtime_addr(self, args));
    printf("PyInterpreterState.audit_hooks_ptr_addr=%p\n", get_interp_audit_hook_ptr_addr(self, args));
    printf("PyRuntimeState.audit_hooks_ptr_addr=%p\n", get_runtime_audit_hook_ptr_addr(self, args));
    printf("\n");
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
	PyImport_AppendInittab("audit_hook_head_finder", &PyInit_Finder);
    Py_Initialize();
	return Py_BytesMain(argc, argv);
}
