// Harness: %-formatting, format specs and number parsing: __mod6/__modtuple with fuzzed format
// strings (str and bytes) and mixed argument types, __format(value, spec), int()/float() of text.
#include "common.hpp"

static void step(Rd &r, str *a, str *b, bytes *fb) {
    switch (r.u8() % 12) {
    case 0: __mod6(a, 1, b); break;
    case 1: __mod6(a, 1, r.num()); break;
    case 2: __mod6(a, 1, (__ss_float)((double)r.u32() * (double)r.u32() / 3.0)); break;
    case 3: __mod6(a, 2, r.num(), b); break;
    case 4: __mod6(a, 3, b, r.num(), (__ss_float)r.u32()); break;
    case 5: __mod6(a, 4, r.num(), r.num(), r.num(), r.num()); break;
    case 6: __mod6(a, 0); break;
    case 7: __modtuple(a, new tuple2<__ss_int, __ss_int>(2, r.num(), r.num())); break;
    case 8: __mod6(fb, 1, r.b()); __mod6(fb, 2, r.num(), (__ss_float)r.u16()); break;
    case 9: __format(r.num(), a); __format((__ss_float)((double)r.u32() / 7.0), a); break;
    case 10: __format(b, a); __format((__ss_bool)(r.u8() & 1), a); break;
    case 11: __int(a, r.small(40)); __float(a); __int(fb, r.small(40)); break;
    }
}

extern "C" int LLVMFuzzerInitialize(int *, char ***) {
    __shedskin__::__init();
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    Arena arena;
    Rd r(data, size);
    str *a = r.s(), *b = r.s();
    bytes *fb = r.b();
    for (int i = 0; i < 24 && r.more(); i++) SAFE(step(r, a, b, fb));
    return 0;
}
