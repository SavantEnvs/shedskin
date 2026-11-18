// Harness: the `re` module (its own sre engine port): compile a fuzzed pattern and run every
// matching, splitting and substitution entry point over a fuzzed subject.
#include "common.hpp"
#include "re.hpp"

using namespace __re__;

static str *upper_group(Match *m) { return m->group(0)->upper(); }

static void walk(Match *m, Rd &r) {
    if (!m) return;
    m->group(0);
    m->start(r.small(4)); m->end(r.small(4)); m->span(r.small(4));
    m->groups(); m->groupdict(); m->__repr__();
    (void)m->lastindex; m->expand(r.s());
    m->group(r.small(4), r.small(4));
    m->__getitem__(r.small(4));
}

static void step(Rd &r, Pattern *p, str *subj, str *repl) {
    switch (r.u8() % 9) {
    case 0: walk(p->search(subj, r.num(), r.num()), r); break;
    case 1: walk(p->match(subj, r.num(), r.num()), r); break;
    case 2: walk(p->fullmatch(subj, r.num()), r); break;
    case 3: p->findall(subj, r.num(), r.num()); break;
    case 4: {
        __iter<Match *> *it = p->finditer(subj, r.num(), r.num());
        for (int i = 0; i < 64; i++) walk(it->__next__(), r);
        break;
    }
    case 5: p->split(subj, r.num()); break;
    case 6: p->sub(repl, subj, r.num()); break;
    case 7: p->subn(repl, subj, r.num()); p->subn(upper_group, subj, r.num()); break;
    case 8: p->__repr__(); p->__hash__(); p->__eq__(p); escape(subj); break;
    }
}

extern "C" int LLVMFuzzerInitialize(int *, char ***) {
    __shedskin__::__init();
    __re__::__init();
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    Arena arena;
    Rd r(data, size);
    __ss_int flags = r.u8() & 0x7f;
    str *pat = r.s(), *subj = r.s(), *repl = r.s();
    if (pat->unit.size() > 96) pat->unit.resize(96);
    if (subj->unit.size() > 64) subj->unit.resize(64);
    SAFE({
        Pattern *p = compile(pat, flags);
        for (int i = 0; i < 12 && r.more(); i++) SAFE(step(r, p, subj, repl));
    });
    purge();
    return 0;
}
