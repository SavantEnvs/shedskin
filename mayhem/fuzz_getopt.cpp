// Harness: getopt and gnu_getopt over a fuzzed argv vector, short-option string and long-option list.
#include "common.hpp"
#include "getopt.hpp"

static list<str *> *strs(Rd &r, unsigned max) {
    list<str *> *l = new list<str *>();
    for (unsigned n = r.u8() % max; n > 0; n--) l->append(r.s());
    return l;
}

static void step(Rd &r) {
    list<str *> *args = strs(r, 10);
    str *shortopts = r.s();
    list<str *> *longopts = strs(r, 6);
    if (r.u8() & 1)
        __getopt__::getopt(args, shortopts, (pyiter<str *> *)longopts);
    else
        __getopt__::gnu_getopt(args, shortopts, (pyiter<str *> *)longopts);
}

extern "C" int LLVMFuzzerInitialize(int *, char ***) {
    __shedskin__::__init();
    __os__::__init();
    __getopt__::__init();
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    Arena arena;
    Rd r(data, size);
    SAFE(step(r));
    return 0;
}
