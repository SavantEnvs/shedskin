// Harness: the runtime's `bytes` / `bytearray`: padding, search, count, replace, split, slicing and
// in-place mutation, driven by a stream of operations from the input.
#include "common.hpp"

static void step(Rd &r, bytes *a, bytes *b, bytes *c, bytes *m) {
    if (m->unit.size() > 4096) m->unit.resize(4096);
    switch (r.u8() % 22) {
    case 0: a->center(r.width(), c); break;
    case 1: a->ljust(r.width(), c); break;
    case 2: a->rjust(r.width(), c); break;
    case 3: a->count(b, r.num()); a->count(b, r.num(), r.num()); break;
    case 4: a->count((__ss_int)r.num(), r.num()); break;
    case 5: a->find(b, r.num(), r.num()); a->rfind(b, r.num(), r.num()); break;
    case 6: a->find((__ss_int)r.num(), r.num(), r.num()); a->rfind((__ss_int)r.num(), r.num()); break;
    case 7: a->index(b, r.num(), r.num()); a->rindex(b, r.num()); break;
    case 8: a->replace(b, c, r.num()); break;
    case 9: a->split(b, r.num()); a->rsplit(b, r.num()); break;
    case 10: a->partition(b); a->rpartition(b); a->splitlines(r.num()); break;
    case 11: a->strip(b); a->lstrip(b); a->rstrip(b); break;
    case 12: a->startswith(b, r.num(), r.num()); a->endswith(b, r.num()); break;
    case 13: a->__slice__(r.u8() & 7, r.num(), r.num(), r.num()); break;
    case 14: a->hex(0, r.num()); a->decode(); a->__repr__(); break;
    case 15: a->translate(b, c); a->upper(); a->lower(); a->title(); a->swapcase(); a->capitalize(); break;
    case 16: a->expandtabs(r.small(40)); a->zfill(r.width()); a->removeprefix(b); a->removesuffix(c); break;
    // bytearray mutation
    case 17: m->append(r.num()); m->insert(r.num(), r.num()); m->pop(r.num()); break;
    case 18: m->__setslice__(r.u8() & 7, r.num(), r.num(), r.num(), b); break;
    case 19: m->__delete__(r.u8() & 7, r.num(), r.num(), r.num()); m->__delitem__(r.num()); break;
    case 20: m->extend(m); m->extend(b); m->__iadd__(m); m->resize(r.width()); break;
    case 21: m->__setitem__(r.num(), r.num()); m->remove(r.num()); m->reverse(); m->__imul__(r.small(4)); break;
    }
}

extern "C" int LLVMFuzzerInitialize(int *, char ***) {
    __shedskin__::__init();
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    Arena arena;
    Rd r(data, size);
    bytes *a = r.b(), *b = r.b(), *c = r.b(), *m = r.b(0);
    for (int i = 0; i < 24 && r.more(); i++) SAFE(step(r, a, b, c, m));
    return 0;
}
