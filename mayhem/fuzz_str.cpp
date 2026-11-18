// Harness: the runtime's `str` (a basic_string of code points): padding, search, count, replace,
// split, slicing, encode/decode and %-formatting driven by a stream of operations from the input.
#include "common.hpp"

static list<str *> *strs(Rd &r) {
    list<str *> *l = new list<str *>();
    size_t n = r.u8() % 6;
    for (size_t i = 0; i < n; i++) l->append(r.s());
    return l;
}

static void step(Rd &r, str *a, str *b, str *c) {
    switch (r.u8() % 24) {
    case 0: a->center(r.width(), c); break;
    case 1: a->ljust(r.width(), c); break;
    case 2: a->rjust(r.width(), c); break;
    case 3: a->count(b, r.num()); break;
    case 4: a->count(b, r.num(), r.num()); break;
    case 5: a->find(b, r.num(), r.num()); a->rfind(b, r.num(), r.num()); break;
    case 6: a->index(b, r.num(), r.num()); break;
    case 7: a->rindex(b, r.num()); break;
    case 8: a->replace(b, c, r.num()); break;
    case 9: a->split(b, r.num()); a->rsplit(b, r.num()); break;
    case 10: a->partition(b); a->rpartition(b); a->splitlines(r.num()); break;
    case 11: a->strip(b); a->lstrip(b); a->rstrip(b); break;
    case 12: a->startswith(b, r.num(), r.num()); a->endswith(b, r.num()); break;
    case 13: a->join(strs(r)); break;
    case 14: {
        static const char *enc[] = {"utf-8", "latin-1", "ascii", "utf-16", "utf-32", "utf8"};
        static const char *err[] = {"strict", "ignore", "replace", "backslashreplace", "surrogateescape", "xmlcharrefreplace"};
        bytes *e = a->encode(new str(enc[r.u8() % 6]), new str(err[r.u8() % 6]));
        e->decode(new str(enc[r.u8() % 6]), new str(err[r.u8() % 6]));
        break;
    }
    case 15: a->__slice__(r.u8() & 7, r.num(), r.num(), r.num()); break;
    case 16: a->upper(); a->lower(); a->title(); a->capitalize(); a->casefold(); a->swapcase(); break;
    case 17: a->expandtabs(r.small(40)); a->zfill(r.width()); break;
    case 18: a->translate(str::maketrans(b, c)); break;
    case 19:
        a->isalpha(); a->isdigit(); a->isalnum(); a->isspace(); a->isupper(); a->islower();
        a->istitle(); a->isprintable(); a->isnumeric(); a->isdecimal(); a->isidentifier(); a->__ss_isascii();
        break;
    case 20: a->__repr__(); a->__hash__(); a->__cmp__(b); a->__contains__(b); break;
    case 21: __int(a, r.small(40)); a->__int__(); break;
    case 22: a->removeprefix(b); a->removesuffix(c); a->__mul__(r.small(8)); a->__add__(b); break;
    case 23: {
        // the fuzzed string as a %-format with a mix of argument types
        switch (r.u8() % 4) {
        case 0: __mod6(a, 1, b); break;
        case 1: __mod6(a, 2, r.num(), b); break;
        case 2: __mod6(a, 2, (__ss_float)r.u32() / 7.0, r.num()); break;
        default: __mod6(a, 3, b, c, r.num()); break;
        }
        break;
    }
    }
}

extern "C" int LLVMFuzzerInitialize(int *, char ***) {
    __shedskin__::__init();
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    Arena arena;
    Rd r(data, size);
    str *a = r.s(), *b = r.s(), *c = r.s();
    for (int i = 0; i < 24 && r.more(); i++) SAFE(step(r, a, b, c));
    return 0;
}
