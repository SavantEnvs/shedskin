// Harness: the array module (array.array). The input picks a typecode, then drives raw-buffer
// construction (frombytes), fromlist/extend, element access, slicing, byteswap and the
// tolist/tobytes round trips, for the integer, float and unicode element types.
#include "common.hpp"
#include "array.hpp"

template <class T> static T item(Rd &r);
template <> __ss_int item<__ss_int>(Rd &r) { return r.num(); }
template <> __ss_float item<__ss_float>(Rd &r) {
    switch (r.u8() % 4) {
    case 0: return (__ss_float)r.num();
    case 1: { uint32_t v = r.u32(); float f; memcpy(&f, &v, 4); return f; }
    case 2: { uint64_t v = (uint64_t)r.u32() << 32 | r.u32(); double d; memcpy(&d, &v, 8); return d; }
    default: return (__ss_float)r.num() / 7.0;
    }
}
template <> str *item<str *>(Rd &r) {
    if (r.u8() % 8 == 0) return r.s();  // usually a single character; sometimes a wrong-length str
    __ss_char c = r.u8() & 1 ? (__ss_char)r.u16() : (__ss_char)r.u8();
    return new str(&c, 1);
}

template <class T> static __array__::array<T> *build(str *tc, Rd &r, size_t maxn) {
    __array__::array<T> *a = new __array__::array<T>(tc);
    list<T> *l = new list<T>();
    for (size_t i = r.u8() % maxn; i > 0; i--) l->append(item<T>(r));
    a->fromlist(l);
    return a;
}

template <class T> static void run(str *tc, Rd &r) {
    __array__::array<T> *a = new __array__::array<T>(tc);
    for (int i = 0; i < 12 && r.more(); i++) {
        switch (r.u8() % 20) {
        case 0: {
            size_t n = (size_t)(r.u8() % 16) * (size_t)a->itemsize + (r.u8() % 8 == 0 ? r.u8() % 4 : 0);
            std::string t;
            for (size_t k = 0; k < n; k++) t.push_back((char)r.u8());
            a->frombytes(new bytes(t.data(), t.size(), 1));
            break;
        }
        case 1: a->fromlist(build<T>(tc, r, 16)->tolist()); break;
        case 2: a->byteswap(); break;
        case 3: a->tolist(); break;
        case 4: a->tobytes(); break;
        case 5: a->__getitem__(r.num()); break;
        case 6: a->__setitem__(r.num(), item<T>(r)); break;
        case 7: a->append(item<T>(r)); break;
        case 8: a->insert(r.num(), item<T>(r)); break;
        case 9: a->pop(r.num()); break;
        case 10: a->remove(item<T>(r)); break;
        case 11: a->index(item<T>(r), r.num()); break;
        case 12: a->count(item<T>(r)); break;
        case 13: { __ss_int x = r.u8() & 7, l = r.num(), u = r.num(), s = r.num(); a->__slice__(x, l, u, s); break; }
        case 14: { __ss_int x = r.u8() & 7, l = r.num(), u = r.num(), s = r.num(); a->__setslice__(x, l, u, s, build<T>(tc, r, 12)); break; }
        case 15: { __ss_int x = r.u8() & 7, l = r.num(), u = r.num(), s = r.num(); a->__delete__(x, l, u, s); break; }
        case 16: a->__delete__(r.num()); break;
        case 17: a->__mul__(r.small(5)); a->__iadd__(build<T>(tc, r, 8)); break;
        case 18: a->reverse(); a->__eq__(a->__copy__()); a->buffer_info(); break;
        default: a->__repr__(); if (a->typechar == 'u' || a->typechar == 'w') a->tounicode(); break;
        }
    }
}

static void step(Rd &r) {
    static const char codes[] = "bBhHiIlLqQfduwx";
    char c = codes[r.u8() % (sizeof codes - 1)];
    str *tc = new str(&c, 1);
    switch (c) {
    case 'f': case 'd': run<__ss_float>(tc, r); break;
    case 'u': case 'w': run<str *>(tc, r); break;
    default: run<__ss_int>(tc, r); break;
    }
}

extern "C" int LLVMFuzzerInitialize(int *, char ***) {
    __shedskin__::__init();
    __array__::__init();
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    Arena arena;
    Rd r(data, size);
    SAFE(step(r));
    return 0;
}
