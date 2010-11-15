#include <Python.h>
#include <pcap.h>
#include <signal.h>

#define MAX_CAPTURE 2048

/* Global thread-safe callback function */
static __thread PyObject *py_callback_func = NULL; 

/* Function prototypes */
static void handleKeyboardInterrupt(int signal_num);
static void callbackWrapper(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet);
static PyObject *capture(PyObject *self, PyObject *args);
PyMODINIT_FUNC initcYapcap(void);

/* List of functions available to Python */
static PyMethodDef YapcapMethods[] = {
    {"capture",  capture, METH_VARARGS, "Capture packets."},
    {NULL, NULL, 0, NULL}        /* Sentinel */
};

/* Function Definitions */
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

    PyEval_CallFunction(py_callback_func, "OO", summary, pkt);
}

static PyObject *
capture(PyObject *self, PyObject *args)
{
    char     *device = NULL;
    char     *errbuf = (char *) malloc (PCAP_ERRBUF_SIZE);
    pcap_t   *descr  = NULL;
    PyObject *cb     = NULL;

    memset(errbuf, 0, PCAP_ERRBUF_SIZE);

    /* Register signal handler */
    (void) signal(SIGINT, handleKeyboardInterrupt);

    /* Extract capture arguments */
    if (!PyArg_ParseTuple(args, "sO", &device, &cb)) 
    {
        return NULL;
    }

    fprintf(stderr, "Device: %s\n", device);

    /* Ensure cb is a callback */
    if (!PyCallable_Check(cb)) 
    {
        PyErr_SetString(PyExc_TypeError, "Callback must be a callable object.");
        return NULL;
    }

    py_callback_func = cb;

    //device = pcap_lookupdev(errbuf);
    descr  = pcap_open_live(device, MAX_CAPTURE, 1, 512, errbuf);

    if (descr == NULL)
    {
        PyErr_SetString(PyExc_RuntimeError, "Can't find device, are you root?");
        return NULL;
    }

    pcap_loop(descr, -1, callbackWrapper, NULL);

    return Py_BuildValue("");
}

PyMODINIT_FUNC
initcYapcap(void)
{
    (void) Py_InitModule("cYapcap", YapcapMethods);
}