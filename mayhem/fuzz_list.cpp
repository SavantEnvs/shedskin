// Harness: list, dict, set, heapq and bisect: in-place mutation (extend/insert/slices/sort/remove),
// aliasing (a list extended or sliced by itself), and the heap/bisect helpers.
#include "common.hpp"
#include "heapq.hpp"
#include "bisect.hpp"

static list<__ss_int> *ints(Rd &r) {
    list<__ss_int> *l = new list<__ss_int>();
    size_t n = r.u8() % 24;
    for (size_t i = 0; i < n; i++) l->append(r.num());
    return l;
}

static void step(Rd &r, list<__ss_int> *a, list<__ss_int> *b, list<str *> *s, dict<__ss_int, __ss_int> *d, set<__ss_int> *st) {
    // self-extension doubles a list: keep the containers small enough to stay fast
    if (a->units.size() > 2048) a->units.resize(2048);
    if (s->units.size() > 256) s->units.resize(256);
    switch (r.u8() % 24) {
    case 0: a->extend(a); break;
    case 1: a->extend(b); break;
    case 2: a->insert(r.num(), r.num()); break;
    case 3: a->__setslice__(r.u8() & 7, r.num(), r.num(), r.num(), b); break;
    case 4: a->__setslice__(r.u8() & 7, r.num(), r.num(), r.num(), a); break;
    case 5: a->__delete__(r.u8() & 7, r.num(), r.num(), r.num()); break;
    case 6: a->__slice__(r.u8() & 7, r.num(), r.num(), r.num()); break;
    case 7: a->sort((__ss_int)0, (__ss_int)0, r.small(2)); a->reverse(); break;
    case 8: a->remove(r.num()); a->pop(r.num()); break;
    case 9: a->index(r.num()); a->count(r.num()); break;
    case 10: a->__setitem__(r.num(), r.num()); a->__delitem__(r.num()); break;
    case 11: a->__mul__(r.small(5)); a->__imul__(r.small(5)); a->__add__(b); a->__iadd__(a); break;
    case 12: s->sort((__ss_int)0, (__ss_int)0, r.small(2)); s->extend(s); s->append(r.s()); break;
    case 13: __heapq__::heapify(a); __heapq__::heappush(a, r.num()); break;
    case 14: __heapq__::heappop(a); break;
    case 15: __heapq__::heapreplace(a, r.num()); __heapq__::heappushpop(a, r.num()); break;
    case 16: __heapq__::nlargest(r.num(), (pyiter<__ss_int> *)a, 0L); __heapq__::nsmallest(r.num(), (pyiter<__ss_int> *)b, 0L); break;
    case 17: __bisect__::bisect_left(0L, a, r.num(), r.num(), r.num()); __bisect__::bisect_right(0L, a, r.num(), r.num()); break;
    case 18: __bisect__::insort_left(0L, a, r.num(), r.num(), r.num()); __bisect__::insort_right(0L, a, r.num(), r.num()); break;
    case 19: d->__setitem__(r.num(), r.num()); d->__delitem__(r.num()); d->pop(r.num()); break;
    case 20: d->update(d); d->setdefault(r.num(), r.num()); d->popitem(); break;
    case 21: st->add(r.num()); st->discard(r.num()); st->remove(r.num()); break;
    case 22: st->update(1, b); st->update(1, st); st->intersection_update(1, b); st->__sub__(st); st->__or__(st); st->__and__(st); st->__xor__(st); break;
    case 23: a->__repr__(); d->__repr__(); st->__repr__(); a->__hash__(); break;
    }
}

extern "C" int LLVMFuzzerInitialize(int *, char ***) {
    __shedskin__::__init();
    __heapq__::__init();
    __bisect__::__init();
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    Arena arena;
    Rd r(data, size);
    list<__ss_int> *a = ints(r), *b = ints(r);
    list<str *> *s = new list<str *>();
    dict<__ss_int, __ss_int> *d = new dict<__ss_int, __ss_int>();
    set<__ss_int> *st = new set<__ss_int>();
    for (int i = 0; i < 32 && r.more(); i++) SAFE(step(r, a, b, s, d, st));
    return 0;
}
