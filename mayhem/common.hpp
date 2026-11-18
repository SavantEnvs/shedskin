// Shared helpers for the shedskin runtime harnesses: a byte reader that builds the runtime's
// own str/bytes values from the fuzz input, and the per-input arena hooks (see arena.cpp).
#pragma once
#include "builtin.hpp"
#include <cstddef>
#include <cstdint>
#include <new>

using namespace __shedskin__;

void arena_begin();  // from here on, new'd objects belong to the current input
void arena_end();    // free them all, so each input is independent and memory stays flat
struct Arena {
    Arena() { arena_begin(); }
    ~Arena() { arena_end(); }
};

// Read the input as a stream of choices; an exhausted input yields zeros.
struct Rd {
    const uint8_t *p, *e;
    Rd(const uint8_t *d, size_t n) : p(d), e(d + n) {}
    bool more() const { return p < e; }
    uint8_t u8() { return p < e ? *p++ : 0; }
    uint16_t u16() { unsigned a = u8(); return (uint16_t)(a | (unsigned)u8() << 8); }
    uint32_t u32() { uint32_t a = u16(); return a | (uint32_t)u16() << 16; }
    // a small length (mostly short, sometimes a few hundred), never huge
    size_t len() {
        unsigned b = u8();
        return b < 224 ? b % 40 : (size_t)(b - 224) * 64;
    }
    // an index/count: small values around zero most of the time, plus edge values
    __ss_int num() {
        unsigned c = u8();
        switch (c >> 5) {
        case 4: return (int8_t)u8();
        case 5: return (int16_t)u16();
        case 6: return (__ss_int)(int32_t)u32();
        case 7: {
            static const int64_t e[] = {INT32_MIN, INT32_MAX, INT32_MIN + 1, -65536, 65535, 255, -256, 1 << 30};
            return (__ss_int)e[u8() & 7];
        }
        default: return (__ss_int)(c & 0x1f) - 8;
        }
    }
    __ss_int small(unsigned mod) { return (__ss_int)(u8() % mod); }
    size_t width() { return u16() % 600; }  // a size we are willing to allocate
    str *s() {
        unsigned b = u8();
        size_t n = (b & 0x7f) % 64;
        if ((b & 0x7f) >= 120) n = (size_t)(b & 7) * 96;
        __GC_STR u;
        for (size_t i = 0; i < n; i++) {
            unsigned c;
            if (b & 0x80) {
                c = u16();
                if ((c >> 12) == 0xF) c = 0x10000 + (c & 0xFFF) * 17;
            } else
                c = u8();
            u.push_back((__ss_char)c);
        }
        return new str(u);
    }
    bytes *b(int frozen = 1) {
        size_t n = len();
        std::string t;
        for (size_t i = 0; i < n; i++) t.push_back((char)u8());
        return new bytes(t.data(), t.size(), frozen);
    }
    std::string raw(size_t maxn) {
        size_t n = len();
        if (n > maxn) n = maxn;
        std::string t;
        for (size_t i = 0; i < n; i++) t.push_back((char)u8());
        return t;
    }
    std::string rest() { std::string t((const char *)p, (size_t)(e - p)); p = e; return t; }
};

// Run one runtime call; a Python-level exception (thrown as a pointer) is a normal outcome.
#define SAFE(...) \
    do { try { __VA_ARGS__; } catch (Exception *) {} catch (std::bad_alloc &) {} } while (0)
