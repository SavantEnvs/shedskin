// Harness: the `datetime` module: ISO-8601 and strptime parsing of fuzzed text, construction from
// fuzzed numbers, formatting (isoformat/strftime/ctime), and date/time/timedelta arithmetic.
#include "common.hpp"
#include "time.hpp"
#include "datetime.hpp"

using namespace __datetime__;

static timedelta *delta(Rd &r) {
    return new timedelta((__ss_int)r.num(), (__ss_int)r.num(), (__ss_int)r.num());
}

static void show(date *d, Rd &r) {
    if (!d) return;
    d->isoformat(); d->__str__(); d->__repr__(); d->ctime(); d->toordinal(); d->weekday();
    d->isocalendar(); d->__hash__(); d->strftime(r.s()); d->__format__(r.s());
}

static void step(Rd &r, str *a, str *b) {
    switch (r.u8() % 16) {
    case 0: show(date::fromisoformat(a), r); break;
    case 1: show(datetime::fromisoformat(a), r); break;
    case 2: { __datetime__::time *t = __datetime__::time::fromisoformat(a); if (t) { t->isoformat(b); t->__repr__(); t->strftime(b); t->utcoffset(); t->tzname(); t->__format__(b); } break; }
    case 3: show(datetime::strptime(a, b), r); break;
    case 4: show(date::strptime(a, b), r); break;
    case 5: { __datetime__::time *t = __datetime__::time::strptime(a, b); if (t) t->isoformat(); break; }
    case 6: show(new date(r.num(), r.num(), r.num()), r); break;
    case 7: show(new datetime(r.num(), r.num(), r.num(), r.num(), r.num(), r.num(), r.num()), r); break;
    case 8: new __datetime__::time(r.num(), r.num(), r.num(), r.num()); break;
    case 9: show(date::fromordinal(r.num()), r); datetime::fromordinal(r.num()); date::fromisocalendar(r.num(), r.num(), r.num()); break;
    case 10: show(datetime::fromtimestamp((double)r.num() * 997.0, 0), r); datetime::utcfromtimestamp((double)r.num()); break;
    case 11: { timedelta *t = delta(r); t->__str__(); t->__repr__(); t->__neg__(); t->__mul__(r.num()); t->__truediv__((__ss_float)r.num()); t->__floordiv__(r.num()); t->__add__(delta(r)); break; }
    case 12: { date *d = date::fromisoformat(a); d->__add__(delta(r)); d->__sub__(delta(r)); d->replace(3, r.num(), r.num(), r.num()); break; }
    case 13: { datetime *d = datetime::fromisoformat(a); d->__add__(delta(r)); d->__sub__(datetime::fromisoformat(b)); d->replace(7, r.num(), r.num(), r.num(), r.num(), r.num(), r.num(), r.num()); d->astimezone(0); d->timestamp(); break; }
    case 14: { datetime *d = datetime::fromisoformat(a); d->isoformat(b, r.s()); d->timetuple(); d->utctimetuple(); d->tzname(); break; }
    case 15: { datetime *d = datetime::fromisoformat(a); d->__cmp__(datetime::fromisoformat(b)); d->_date(); d->timetz(); break; }
    }
}

extern "C" int LLVMFuzzerInitialize(int *, char ***) {
    __shedskin__::__init();
    __time__::__init();
    __datetime__::__init();
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    Arena arena;
    Rd r(data, size);
    str *a = r.s(), *b = r.s();
    for (int i = 0; i < 12 && r.more(); i++) SAFE(step(r, a, b));
    return 0;
}
