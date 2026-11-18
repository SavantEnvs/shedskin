// Global operator new/delete for the harnesses. The runtime is built with -D__SS_NOGC (plain
// `new`), so ASan sees every object. Objects allocated while one input runs (between arena_begin and arena_end) are chained and freed
// by arena_end(), which keeps memory flat across millions of inputs while a stale pointer into
// the previous input's objects still trips ASan's use-after-free check.
#include <cstdlib>
#include <cstddef>
#include <new>

namespace {
struct Hdr {
    Hdr *prev, *next;
    bool linked;
    char pad[7];
    size_t size;
};
static_assert(sizeof(Hdr) == 32, "keep 16-byte alignment");
Hdr head = {&head, &head, false, {}, 0};
bool on = false;

void link(Hdr *h) {
    h->prev = &head;
    h->next = head.next;
    head.next->prev = h;
    head.next = h;
    h->linked = true;
}
void unlink(Hdr *h) {
    h->prev->next = h->next;
    h->next->prev = h->prev;
    h->linked = false;
}
void *alloc(size_t n) {
    if (n > ((size_t)1 << 28)) throw std::bad_alloc();
    Hdr *h = (Hdr *)std::malloc(sizeof(Hdr) + n);
    if (!h) throw std::bad_alloc();
    h->size = n;
    h->linked = false;
    if (on) link(h);
    return h + 1;
}
void release(void *p) {
    if (!p) return;
    Hdr *h = (Hdr *)p - 1;
    if (h->linked) unlink(h);
    std::free(h);
}
}  // namespace

void arena_begin() { on = true; }

void arena_end() {
    on = false;
    for (Hdr *h = head.next; h != &head;) {
        Hdr *n = h->next;
        std::free(h);
        h = n;
    }
    head.next = head.prev = &head;
}

void *operator new(size_t n) { return alloc(n); }
void *operator new[](size_t n) { return alloc(n); }
void *operator new(size_t n, const std::nothrow_t &) noexcept { try { return alloc(n); } catch (...) { return nullptr; } }
void *operator new[](size_t n, const std::nothrow_t &) noexcept { try { return alloc(n); } catch (...) { return nullptr; } }
void operator delete(void *p) noexcept { release(p); }
void operator delete[](void *p) noexcept { release(p); }
void operator delete(void *p, size_t) noexcept { release(p); }
void operator delete[](void *p, size_t) noexcept { release(p); }
void operator delete(void *p, const std::nothrow_t &) noexcept { release(p); }
void operator delete[](void *p, const std::nothrow_t &) noexcept { release(p); }
