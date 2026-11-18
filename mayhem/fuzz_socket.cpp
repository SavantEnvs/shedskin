// Harness: the socket module's address handling: inet_aton/ntoa/pton/ntop/htons helpers and the
// AF_UNIX path -> sockaddr_un conversion (bind/connect). Paths are forced into the Linux abstract
// namespace (leading NUL) so nothing touches the filesystem.
#include "common.hpp"
#include "socket.hpp"

static str *abstract_path(Rd &r) {
    str *s = r.s();
    __GC_STR p(1, 0);
    p += s->unit;
    return new str(p);
}

// the bytes overload of bind(): the path is forced into the abstract namespace the same way, or left
// empty (which the runtime also treats as abstract: the kernel autobinds a name)
static bytes *abstract_bytes(Rd &r) {
    bytes *b = r.b();
    if (r.u8() & 1) return new bytes();
    std::string p(1, '\0');
    p.append(b->unit.data(), b->unit.size());
    return new bytes(p.data(), p.size(), 1);
}

static void step(Rd &r) {
    switch (r.u8() % 8) {
    case 0: __socket__::inet_aton(r.s()); break;
    case 1: __socket__::inet_ntoa(r.b()); break;
    case 2: __socket__::inet_pton(r.u8() & 1 ? __socket__::__ss_AF_INET : __socket__::__ss_AF_INET6, r.s()); break;
    case 3: __socket__::inet_ntop(r.u8() & 1 ? __socket__::__ss_AF_INET : __socket__::__ss_AF_INET6, r.b()); break;
    case 4: __socket__::__ss_ntohs(__socket__::__ss_htons(r.num())); break;
    case 5: {
        __socket__::socket *s = new __socket__::socket(__socket__::__ss_AF_UNIX, __socket__::__ss_SOCK_STREAM, 0);
        try { s->bind(abstract_path(r)); } catch (...) { s->close(); throw; }
        s->close();
        break;
    }
    case 6: {
        __socket__::socket *s = new __socket__::socket(__socket__::__ss_AF_UNIX, __socket__::__ss_SOCK_STREAM, 0);
        try { s->connect(abstract_path(r)); } catch (...) { s->close(); throw; }
        s->close();
        break;
    }
    default: {
        __socket__::socket *s = new __socket__::socket(__socket__::__ss_AF_UNIX, __socket__::__ss_SOCK_DGRAM, 0);
        try { s->bind(abstract_bytes(r)); } catch (...) { s->close(); throw; }
        s->close();
        break;
    }
    }
}

extern "C" int LLVMFuzzerInitialize(int *, char ***) {
    __shedskin__::__init();
    __socket__::__init();
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    Arena arena;
    Rd r(data, size);
    for (int i = 0; i < 8 && r.more(); i++) SAFE(step(r));
    return 0;
}
