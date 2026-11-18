// Harness: binary encodings: struct (format parsing, pack, and unpack the way shedskin's compiler
// expands it), binascii (uu/base64/base85/base32/qp/hex/crc) and base64 encoders and decoders.
#include "common.hpp"
#include "struct.hpp"
#include "binascii.hpp"
#include "base64.hpp"
#include <string>
#include <vector>

using namespace __struct__;

static void pack_some(Rd &r, str *fmt) {
    switch (r.u8() % 9) {
    case 0: pack(1, fmt, r.num()); break;
    case 1: pack(1, fmt, (__ss_float)r.u32() / 3.0); break;
    case 2: pack(1, fmt, r.b()); break;
    case 3: pack(2, fmt, r.num(), r.num()); break;
    case 4: pack(2, fmt, r.b(), r.num()); break;
    case 5: pack(3, fmt, r.num(), (__ss_float)r.u16(), r.b()); break;
    case 6: pack(4, fmt, r.num(), r.num(), r.num(), r.num()); break;
    case 7: pack(0, fmt); break;
    case 8: pack_into(1, fmt, r.b(0), r.num(), r.num()); break;
    }
}

// shedskin expands struct.unpack(fmt, data) at translation time into a size check plus one
// __struct__::unpack_<type> call per item; do the same for a fuzzed format.
static void unpack_some(Rd &r, str *fmt, bytes *data) {
    struct It { char c; char t; int d; };
    std::vector<It> items;
    size_t n = fmt->unit.size(), i = 0;
    char o = '@';
    if (n && fmt->unit[0] > 0 && fmt->unit[0] < 128 && strchr("@=<>!", (int)fmt->unit[0])) { o = (char)fmt->unit[0]; i = 1; }
    while (i < n && items.size() < 24) {
        int cnt = -1;
        while (i < n && fmt->unit[i] >= '0' && fmt->unit[i] <= '9') {
            cnt = (cnt < 0 ? 0 : cnt) * 10 + (int)(fmt->unit[i] - '0');
            if (cnt > 64) cnt = 64;
            i++;
        }
        if (i >= n) break;
        __ss_char ch = fmt->unit[i++];
        if (ch >= 128 || !strchr("xcbB?hHiIlLqQnNPefdFDsp", (int)ch) || ch == 0) continue;
        char c = (char)ch, t = 'i';
        if (c == 'x') t = 'p';
        else if (c == 'c' || c == 's' || c == 'p') t = 'b';
        else if (c == '?') t = 'o';
        else if (c == 'e' || c == 'f' || c == 'd') t = 'f';
        else if (c == 'F' || c == 'D') t = 'c';
        if (c == 's' || c == 'p') items.push_back({c, t, cnt < 0 ? 1 : cnt});
        else if (c == 'x') items.push_back({c, t, cnt < 0 ? 1 : cnt});
        else for (int k = 0, m = cnt < 0 ? 1 : (cnt > 8 ? 8 : cnt); k < m; k++) items.push_back({c, t, 1});
    }
    std::string canon(1, o);
    for (auto &it : items) canon += std::to_string(it.d) + it.c;
    bool from = r.u8() & 1;
    __ss_int pos = from ? unpack_from_pos(canon.c_str(), data, r.num()) : unpack_pos(canon.c_str(), data);
    __ss_int base = from ? pos : 0;
    for (auto &it : items) {
        switch (it.t) {
        case 'i': unpack_int(o, it.c, it.d, data, base, &pos); break;
        case 'b': unpack_bytes(o, it.c, it.d, data, base, &pos); break;
        case 'o': unpack_bool(o, it.c, it.d, data, base, &pos); break;
        case 'f': unpack_float(o, it.c, it.d, data, base, &pos); break;
        case 'c': unpack_complex(o, it.c, it.d, data, base, &pos); break;
        default: unpack_pad(o, it.c, it.d, data, base, &pos); break;
        }
    }
}

static void codecs(Rd &r, bytes *b, bytes *c) {
    using namespace __binascii__;
    switch (r.u8() % 20) {
    case 0: a2b_uu(b); b2a_uu(b, (__ss_bool)(r.u8() & 1)); break;
    case 1: a2b_base64(b, __ss_void, (__ss_bool)(r.u8() & 1), (bytes *)0, c, (__ss_bool)(r.u8() & 1)); break;
    case 2: a2b_base64(b, (__ss_bool)(r.u8() & 1)); b2a_base64(b, (__ss_bool)(r.u8() & 1), r.small(80), (__ss_bool)(r.u8() & 1), (bytes *)0); break;
    case 3: a2b_ascii85(b, (__ss_bool)(r.u8() & 1), (__ss_bool)(r.u8() & 1), c, (__ss_bool)(r.u8() & 1)); break;
    case 4: b2a_ascii85(b, (__ss_bool)(r.u8() & 1), r.small(80), (__ss_bool)(r.u8() & 1), (__ss_bool)(r.u8() & 1)); break;
    case 5: a2b_base85(b, (bytes *)0, c, (__ss_bool)(r.u8() & 1)); b2a_base85(b, (bytes *)0, r.small(80), (__ss_bool)(r.u8() & 1)); break;
    case 6: a2b_base32(b, (__ss_bool)(r.u8() & 1), (bytes *)0, c, (__ss_bool)(r.u8() & 1)); b2a_base32(b, (__ss_bool)(r.u8() & 1), (bytes *)0, r.small(80)); break;
    case 7: a2b_qp(b, (__ss_bool)(r.u8() & 1)); break;
    case 8: b2a_qp(b, (__ss_bool)(r.u8() & 1), (__ss_bool)(r.u8() & 1), (__ss_bool)(r.u8() & 1)); break;
    case 9: crc_hqx(b, r.num()); crc32(b, r.num()); break;
    case 10: hexlify(b, (str *)0, r.num()); hexlify(b, r.s(), r.num()); break;
    case 11: unhexlify(b, c); break;
    case 12: __base64__::b64decode(b, (bytes *)0, __ss_void, (__ss_bool)(r.u8() & 1), c, (__ss_bool)(r.u8() & 1)); break;
    case 13: __base64__::urlsafe_b64decode(b, (__ss_bool)(r.u8() & 1)); __base64__::standard_b64decode(b); break;
    case 14: __base64__::b64encode(b, c, (__ss_bool)(r.u8() & 1), r.small(80)); break;
    case 15: __base64__::b32decode(b, (__ss_bool)(r.u8() & 1), c, (__ss_bool)(r.u8() & 1), (bytes *)0, (__ss_bool)(r.u8() & 1)); break;
    case 16: __base64__::b32hexdecode(b, (__ss_bool)(r.u8() & 1)); __base64__::b16decode(b, (__ss_bool)(r.u8() & 1), c); break;
    case 17: __base64__::a85decode(b, (__ss_bool)(r.u8() & 1), (__ss_bool)(r.u8() & 1), c); __base64__::b85decode(b, c); __base64__::z85decode(b, c); break;
    case 18: __base64__::decodebytes(b); __base64__::encodebytes(b); break;
    case 19: {
        __base64__::b32encode(b, (__ss_bool)(r.u8() & 1), r.small(80)); __base64__::b16encode(b, r.small(80));
        __base64__::a85encode(b, (__ss_bool)(r.u8() & 1), r.small(80)); __base64__::b85encode(b, (__ss_bool)(r.u8() & 1), r.small(80));
        __base64__::z85encode(b, (__ss_bool)(r.u8() & 1), r.small(80)); __base64__::b32hexencode(b);
        break;
    }
    }
}

static void step(Rd &r, str *fmt, bytes *data, bytes *c) {
    switch (r.u8() % 6) {
    case 0: calcsize(fmt); calcitems(fmt); break;
    case 1: pack_some(r, fmt); break;
    case 2: case 3: unpack_some(r, fmt, data); break;
    default: codecs(r, data, c); break;
    }
}

extern "C" int LLVMFuzzerInitialize(int *, char ***) {
    __shedskin__::__init();
    __struct__::__init();
    __binascii__::__init();
    __base64__::__init();
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    Arena arena;
    Rd r(data, size);
    str *fmt = r.s();
    bytes *d = r.b(), *c = r.b();
    for (int i = 0; i < 12 && r.more(); i++) SAFE(step(r, fmt, d, c));
    return 0;
}
