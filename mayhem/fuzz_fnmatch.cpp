// Harness: fnmatch (the glob pattern -> regex translator and its matchers: fnmatch, fnmatchcase, filter,
// filterfalse, translate) over fuzzed pattern and name strings.
#include "common.hpp"
#include "fnmatch.hpp"
#include "re.hpp"

static list<str *> *strs(Rd &r, unsigned max) {
    list<str *> *l = new list<str *>();
    for (unsigned n = r.u8() % max; n > 0; n--) l->append(r.s());
    return l;
}

static void step(Rd &r) {
    str *pat = r.s();
    switch (r.u8() % 5) {
    case 0: __fnmatch__::fnmatch(r.s(), pat); break;
    case 1: __fnmatch__::fnmatchcase(r.s(), pat); break;
    case 2: __fnmatch__::filter(strs(r, 8), pat); break;
    case 3: __fnmatch__::filterfalse(strs(r, 8), pat); break;
    default: __fnmatch__::translate(pat); break;
    }
}

extern "C" int LLVMFuzzerInitialize(int *, char ***) {
    __shedskin__::__init();
    __re__::__init();
    __os__::__init();
    __stat__::__init();
    __os__::__path__::__init();
    __fnmatch__::__init();
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    Arena arena;
    Rd r(data, size);
    // the compiled-pattern caches are process-global: start every input with empty ones, so its result
    // does not depend on earlier inputs (the fnmatch dict is rebuilt, as its buckets belong to the arena)
    __re__::purge();
    __fnmatch__::_cache = new dict<str *, __re__::Pattern *>();
    SAFE(step(r));
    return 0;
}
