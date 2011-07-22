#include <Python.h>
#include <pcap.h>
#include <signal.h>

#define MAX_CAPTURE 2048

static __thread PyObject *py_callback_func = NULL; 

static void handleKeyboardInterrupt(int signal_num);
static void callbackWrapper(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet);
static void checkCallable(PyObject *cb);
static pcap_t* openPcapLive(char *device, char *errbuf);

static PyObject* capture(PyObject *self, PyObject *args);
static PyObject* check(PyObject *self, PyObject *args);
PyMODINIT_FUNC   initcYapcap(void);

static PyMethodDef YapcapMethods[] = {
    {"capture",  capture, METH_VARARGS, "Capture packets from the given interface."},
    {"check",  check, METH_VARARGS, "Check the given interface to ensure all is well."},
    {NULL, NULL, 0, NULL}        /* Sentinel */
};

static void
handleKeyboardInterrupt(int signal_num)
{
    Py_Exit(signal_num);
}

static void
callbackWrapper(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet)
{
    PyObject *summary = NULL;
    PyObject *pkt = NULL;

    summary = Py_BuildValue("llII", pkthdr->ts.tv_sec, pkthdr->ts.tv_usec,
        pkthdr->caplen, pkthdr->len);

    pkt = Py_BuildValue("s#", packet, pkthdr->caplen);

    if(PyEval_CallFunction(py_callback_func, "OO", summary, pkt) == NULL)
    {
        PyErr_Print();
        Py_Exit(-1);
    }
}

static void 
checkCallable(PyObject *cb)
{
    if (!PyCallable_Check(cb))
    {
        PyErr_SetString(PyExc_TypeError, "Callback must be a callable object.");
        Py_Exit(-1);
    }
}

static pcap_t*
openPcapLive(char *device, char *errbuf)
{
    pcap_t *handle = pcap_open_live(device, MAX_CAPTURE, 1, 512, errbuf);

    if (handle == NULL)
    {
        PyErr_SetString(PyExc_RuntimeError, "Can't find device, are you root?");
        Py_Exit(-1);
        return 0;
    }

    return handle;
}

static PyObject *
capture(PyObject *self, PyObject *args)
{
    int      datatype = 0;    /* Corresponds to a pcap/bpf.h value */
    char     *device  = NULL; /* Device we're capturing on */
    char     *errbuf  = NULL; /* Error information buffer */
    pcap_t   *handle  = NULL; /* pcap handle */
    PyObject *cb      = NULL; /* Callback for pcap_loop */

    errbuf = (char *) malloc (PCAP_ERRBUF_SIZE);
    memset(errbuf, 0, PCAP_ERRBUF_SIZE);

    (void) signal(SIGINT, handleKeyboardInterrupt);

    if (!PyArg_ParseTuple(args, "sO", &device, &cb))
    {
        return NULL;
    }

    checkCallable(cb);
    py_callback_func = cb;
    handle = openPcapLive(device, errbuf);
    pcap_loop(handle, -1, callbackWrapper, NULL);

    return Py_BuildValue("");
}

static PyObject *
check(PyObject *self, PyObject *args)
{
    int      datatype = 0;    /* Corresponds to a pcap/bpf.h value */
    char     *device  = NULL; /* Device we're capturing on */
    char     *errbuf  = NULL; /* Error information buffer */
    pcap_t   *handle  = NULL; /* pcap handle */

    errbuf = (char *) malloc (PCAP_ERRBUF_SIZE);
    memset(errbuf, 0, PCAP_ERRBUF_SIZE);

    if (!PyArg_ParseTuple(args, "s", &device))
    {
        return NULL;
    }

    handle = openPcapLive(device, errbuf);
    return Py_BuildValue("i", pcap_datalink(handle));
}

PyMODINIT_FUNC
initcyapcap(void)
{
    (void) Py_InitModule("cyapcap", YapcapMethods);
}
