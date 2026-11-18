// Harness: text and container formats read from untrusted data: csv (reader, DictReader, Sniffer),
// configparser (parse, then read every value through interpolation) and gzip (decompress and the
// streaming GzipFile reader over an in-memory buffer).
#include "common.hpp"
#include "csv.hpp"
#include "configparser.hpp"
#include "gzip.hpp"
#include "io.hpp"

static str *one_char(Rd &r) {
    static const char c[] = {',', ';', '\t', '|', '"', '\'', '\\', ' ', '\n', 'a', ':', 0};
    return new str(&c[r.u8() % sizeof c], 1);
}

static list<str *> *lines(str *text) {
    list<str *> *l = new list<str *>();
    __GC_STR cur;
    for (size_t i = 0; i < text->unit.size(); i++) {
        cur.push_back(text->unit[i]);
        if (text->unit[i] == '\n') { l->append(new str(cur)); cur.clear(); }
    }
    if (!cur.empty()) l->append(new str(cur));
    return l;
}

static void do_csv(Rd &r, str *text) {
    str *delim = one_char(r), *quote = one_char(r), *esc = r.u8() & 1 ? one_char(r) : (str *)0;
    __ss_int dq = r.u8() & 1, skip = r.u8() & 1, quoting = r.small(6), strict = r.u8() & 1;
    switch (r.u8() % 4) {
    case 0: {
        __csv__::reader *rd = new __csv__::reader(lines(text), __ss_void, delim, quote, dq, skip, __ss_void, quoting, esc ? esc : (str *)__csv__::__csv_none, strict);
        for (int i = 0; i < 64; i++) rd->__next__();
        break;
    }
    case 1: {
        __csv__::DictReader *rd = new __csv__::DictReader(lines(text), (pyiter<str *> *)0, (str *)0, (str *)0, __ss_void, delim, quote, dq, skip, __ss_void, quoting, __ss_void, strict);
        for (int i = 0; i < 64; i++) rd->__next__();
        break;
    }
    case 2: (new __csv__::Sniffer())->sniff(text, r.u8() & 1 ? r.s() : (str *)0); break;
    default: (new __csv__::Sniffer())->has_header(text); break;
    }
}

static void do_config(Rd &r, str *text) {
    __configparser__::RawConfigParser *p;
    switch (r.u8() % 3) {
    case 0: p = new __configparser__::ConfigParser(new dict<str *, str *>(), r.u8() & 1, (tuple<str *> *)0, (tuple<str *> *)0, (tuple<str *> *)0, r.u8() & 1, r.u8() & 1, (str *)0, __ss_void, r.u8() & 1); break;
    case 1: p = new __configparser__::ConfigParser(new dict<str *, str *>(), 1, (tuple<str *> *)0, (tuple<str *> *)0, (tuple<str *> *)0, 0, 1, (str *)0, new __configparser__::ExtendedInterpolation(), 0); break;
    default: p = new __configparser__::RawConfigParser(new dict<str *, str *>()); break;
    }
    p->read_string(text, (str *)0);
    list<str *> *secs = p->sections();
    for (size_t i = 0; i < secs->units.size() && i < 8; i++) {
        SAFE(p->items(secs->units[i], 0, (dict<str *, str *> *)0));
        list<str *> *opts = p->options(secs->units[i]);
        for (size_t j = 0; j < opts->units.size() && j < 16; j++) {
            SAFE(p->get(secs->units[i], opts->units[j], 0, (dict<str *, str *> *)0, (str *)0));
            SAFE(p->getint(secs->units[i], opts->units[j], 0, (dict<str *, str *> *)0, (__ss_int)0));
            SAFE(p->getboolean(secs->units[i], opts->units[j], 0, (dict<str *, str *> *)0, (__ss_int)0));
        }
    }
}

static void do_gzip(Rd &r, bytes *data) {
    if (r.u8() & 1) {
        __gzip__::decompress(data);
        return;
    }
    __gzip__::GzipFile *g = new __gzip__::GzipFile((str *)0, new str("rb"), 9, new __io__::BytesIO(data));
    for (int i = 0; i < 8; i++) {
        switch (r.u8() % 6) {
        case 0: g->read(r.num()); break;
        case 1: g->readline(r.num()); break;
        case 2: g->peek(r.num()); break;
        case 3: g->read1(r.num()); break;
        case 4: g->seek(r.num(), r.small(3)); break;
        default: g->readlines(r.num()); break;
        }
    }
}

extern "C" int LLVMFuzzerInitialize(int *, char ***) {
    __shedskin__::__init();
    __re__::__init();
    __io__::__init();
    __csv__::__init();
    __configparser__::__init();
    __gzip__::__init();
    return 0;
}

// Input layout: [format selector][16 parameter bytes][the document itself, to the end].
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    Arena arena;
    Rd r(data, size);
    unsigned which = r.u8() % 3;
    uint8_t params[16];
    for (auto &b : params) b = r.u8();
    Rd pr(params, sizeof params);
    std::string doc = r.rest();
    if (which == 0) {
        SAFE(do_csv(pr, new str(doc.data(), doc.size())));
    } else if (which == 1) {
        SAFE(do_config(pr, new str(doc.data(), doc.size())));
    } else {
        SAFE(do_gzip(pr, new bytes(doc.data(), doc.size())));
    }
    __re__::purge();
    return 0;
}
