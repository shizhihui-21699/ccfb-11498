// vuln_app.cpp -- freestanding x86-64 Linux demo target for bcdiff.
//
// This single source models a vendor patch: built without PATCHED it is the
// vulnerable release, with -DPATCHED it is the security update.
//
// Vulnerable build:
//   * parse_record copies the name field into Record::name (32 bytes) with no
//     length check -> stack smash for records whose name field is >= 32 bytes.
//   * copy_token copies n bytes into dst without consulting dstcap.
//   * legacy_decode exists and is unused by the fixed release.
// Patched build:
//   * parse_record gains a bounds check and an error-report path.
//   * copy_token gains a capacity check.
//   * new helper validate_range(), called from dispatch().
//   * legacy_decode is removed.
//
// Build with tools/build_samples.sh (clang + lld, static, no libc).

#include <stdint.h>
#include <stddef.h>

#define NOINLINE __attribute__((noinline, used))
#define NODISCARD __attribute__((warn_unused_result))

struct Record {
    char name[32];
    uint32_t id;
    uint32_t score;
};

// ---------------------------------------------------------------------------
// tiny syscall layer (no libc in freestanding static binaries)
// ---------------------------------------------------------------------------

static inline long sc3(long n, long a, long b, long c) {
    long r;
    __asm__ __volatile__("syscall"
                         : "=a"(r)
                         : "a"(n), "D"(a), "S"(b), "d"(c)
                         : "rcx", "r11", "memory");
    return r;
}

extern "C" __attribute__((noreturn)) void die(int code) {
    sc3(60, code, 0, 0);
    for (;;) {
    }
}

extern "C" void write_fd(int fd, const char* s, unsigned n) {
    if (n != 0) {
        (void)sc3(1, fd, (long)s, n);
    }
}

// ---------------------------------------------------------------------------
// string / hashing helpers (unchanged between releases)
// ---------------------------------------------------------------------------

extern "C" NOINLINE unsigned slen(const char* s) {
    unsigned n = 0;
    while (s[n] != 0) {
        ++n;
    }
    return n;
}

extern "C" NOINLINE int find_char(const char* s, char c) {
    for (unsigned i = 0; s[i] != 0; ++i) {
        if (s[i] == c) {
            return (int)i;
        }
    }
    return -1;
}

extern "C" NOINLINE uint32_t hash32(const char* s) {
    uint32_t h = 2166136261u;
    for (unsigned i = 0; s[i] != 0; ++i) {
        h ^= (uint32_t)(uint8_t)s[i];
        h *= 16777619u;
        h ^= h >> 13;
    }
    return h;
}

extern "C" NOINLINE uint32_t checksum32(const uint8_t* p, unsigned n) {
    uint32_t a = 0x12345678u;
    uint32_t b = 0x9e3779b9u;
    for (unsigned i = 0; i < n; ++i) {
        a = (a + (uint32_t)p[i]) * 31u;
        b ^= (uint32_t)p[i] << (i & 7u);
        if ((i & 15u) == 15u) {
            a ^= b >> 3;
        }
    }
    return a ^ b;
}

extern "C" NOINLINE unsigned clamp_u32(unsigned v, unsigned lo, unsigned hi) {
    if (v < lo) {
        return lo;
    }
    if (v > hi) {
        return hi;
    }
    return v;
}

// ---------------------------------------------------------------------------
// output helpers (unchanged between releases)
// ---------------------------------------------------------------------------

static const char* const kTags[] = {"alpha", "beta", "gamma", "delta", "omega"};
static const char kPrompt[] = "record ";
static const char kIdTag[] = " id=";
static const char kScoreTag[] = " score=";
static const char kTagTag[] = " tag=";

extern "C" NOINLINE int format_u32(char* out, unsigned v) {
    char tmp[12];
    int n = 0;
    if (v == 0) {
        out[0] = '0';
        out[1] = 0;
        return 1;
    }
    while (v != 0 && n < 10) {
        tmp[n++] = (char)('0' + (v % 10u));
        v /= 10u;
    }
    for (int i = 0; i < n; ++i) {
        out[i] = tmp[n - 1 - i];
    }
    out[n] = 0;
    return n;
}

extern "C" NOINLINE void emit_summary(const Record* recs, int n) {
    char num[16];
    for (int i = 0; i < n; ++i) {
        if (recs[i].id == 0 && recs[i].score == 0) {
            continue;
        }
        write_fd(1, kPrompt, sizeof(kPrompt) - 1);
        int k = format_u32(num, (unsigned)i);
        write_fd(1, num, (unsigned)k);
        write_fd(1, kIdTag, sizeof(kIdTag) - 1);
        k = format_u32(num, recs[i].id);
        write_fd(1, num, (unsigned)k);
        write_fd(1, kScoreTag, sizeof(kScoreTag) - 1);
        k = format_u32(num, recs[i].score);
        write_fd(1, num, (unsigned)k);
        write_fd(1, kTagTag, sizeof(kTagTag) - 1);
        const char* tag = kTags[recs[i].id % 5u];
        write_fd(1, tag, slen(tag));
        write_fd(1, "\n", 1);
    }
}

extern "C" NOINLINE void sort_scores(Record* recs, int n) {
    for (int i = 0; i < n; ++i) {
        for (int j = 0; j + 1 < n - i; ++j) {
            if (recs[j].score > recs[j + 1].score) {
                Record t = recs[j];
                recs[j] = recs[j + 1];
                recs[j + 1] = t;
            }
        }
    }
}

extern "C" NOINLINE void report_bad_record(const char* why) {
    write_fd(2, "bad record: ", 12);
    write_fd(2, why, slen(why));
    write_fd(2, "\n", 1);
}

// ---------------------------------------------------------------------------
// parsing -- the security-relevant area
// ---------------------------------------------------------------------------

extern "C" NOINLINE int copy_token(char* dst, unsigned cap, const char* src, unsigned n) {
#ifdef PATCHED
    if (n > cap) {
        return -2;
    }
#endif
    for (unsigned i = 0; i < n; ++i) {
        dst[i] = src[i];
    }
    return (int)n;
}

extern "C" NOINLINE int parse_record(const char* in, unsigned inlen, Record* out) {
    if (in == 0 || out == 0 || inlen == 0) {
        return -1;
    }
    int sep = find_char(in, '|');
    if (sep < 0) {
        return -1;
    }
    unsigned name_len = (unsigned)sep;
#ifdef PATCHED
    if (name_len + 1u > sizeof(out->name)) {
        report_bad_record("name field exceeds record capacity");
        return -2;
    }
#endif
    for (unsigned i = 0; i < name_len; ++i) {
        out->name[i] = in[i];
    }
    out->name[name_len] = 0;
    out->id = hash32(in) & 0xffffu;
    out->score = checksum32((const uint8_t*)in, inlen & 0xffu);
    return (int)name_len;
}

#ifdef PATCHED
// New helper introduced by the security update.
extern "C" NOINLINE unsigned validate_range(unsigned v, unsigned lo, unsigned hi) {
    if (lo > hi) {
        return lo;
    }
    if (v < lo) {
        v = lo;
    } else if (v > hi) {
        v = hi;
    }
    return v;
}
#endif

extern "C" NOINLINE int dispatch(const char* cmd, Record* r) {
    if (cmd == 0 || r == 0) {
        return -1;
    }
    switch (cmd[0]) {
    case 'a':
        r->score = (r->score + hash32(cmd)) & 0xffffu;
        return 1;
    case 'b':
        r->score = (r->score ^ checksum32((const uint8_t*)cmd, slen(cmd) & 31u)) & 0xffffu;
        return 2;
    case 'c':
        r->id = clamp_u32(r->id, 0, 4095);
        return 3;
    case 'd':
        return (int)slen(cmd);
    case 'e':
        r->score = (r->score + checksum32((const uint8_t*)r->name, slen(r->name))) & 0xffffu;
        return 5;
    case 'f':
        return find_char(cmd, ',');
    case 'g':
        r->id = (r->id + 7u) & 0xffu;
        return 7;
    case 'h':
#ifdef PATCHED
        r->score = validate_range((r->score * 33u + 17u) & 0xffffu, 0, 60000);
#else
        r->score = (r->score * 33u + 17u) & 0xffffu;
#endif
        return 8;
    case 'i':
        r->id ^= hash32(r->name);
        return 9;
    default:
        return 0;
    }
}

#ifndef PATCHED
// Present in the vulnerable release only.
extern "C" NOINLINE int legacy_decode(const char* s, unsigned n) {
    uint32_t acc = 0;
    for (unsigned i = 0; i < n; ++i) {
        acc = (acc << 5) - acc + (uint8_t)s[i];
        if ((acc & 0xffu) == 0x7fu) {
            acc ^= 0xdeadbeefu;
        }
    }
    return (int)(acc & 0x7fffffffu);
}
#endif

extern "C" NOINLINE int process(const char* buf, unsigned len, Record* recs, int cap) {
    if (buf == 0 || recs == 0 || cap <= 0) {
        return -1;
    }
    Record tmp;
    for (unsigned i = 0; i < sizeof(Record); ++i) {
        ((char*)&tmp)[i] = 0;
    }
    int rc = parse_record(buf, len, &tmp);
    if (rc < 0) {
        return rc;
    }
    rc = dispatch(buf, &tmp);
    if (rc < 0) {
        return rc;
    }
    if (rc != 0) {
        char tok[24];
        unsigned take = (unsigned)rc;
        if (take > sizeof(tok)) {
            take = (unsigned)sizeof(tok);
        }
        int n = copy_token(tok, sizeof(tok), buf, take);
        if (n > 0) {
            tmp.score = (tmp.score + checksum32((const uint8_t*)tok, (unsigned)n)) & 0xffffu;
        }
    }
    recs[0] = tmp;
    if (cap > 1) {
        recs[1] = tmp;
        recs[1].id ^= 0x5a5au;
        recs[1].score = (tmp.score + 11u) & 0xffffu;
    }
    return 0;
}

// ---------------------------------------------------------------------------
// runtime shims (freestanding; the compiler may emit calls to these)
// ---------------------------------------------------------------------------

extern "C" void* memcpy(void* dst, const void* src, size_t n) {
    unsigned char* d = (unsigned char*)dst;
    const unsigned char* s = (const unsigned char*)src;
    for (size_t i = 0; i < n; ++i) {
        d[i] = s[i];
    }
    return dst;
}

extern "C" void* memset(void* dst, int c, size_t n) {
    unsigned char* d = (unsigned char*)dst;
    for (size_t i = 0; i < n; ++i) {
        d[i] = (unsigned char)c;
    }
    return dst;
}

// ---------------------------------------------------------------------------
// entry point
// ---------------------------------------------------------------------------

extern "C" void _start(void) {
    static char inbuf[512];
    long n = sc3(0, 0, (long)inbuf, (long)(sizeof(inbuf) - 1));
    if (n <= 0) {
        die(2);
    }
    unsigned len = (unsigned)n;
    if (inbuf[len - 1] == '\n') {
        inbuf[len - 1] = 0;
        --len;
    } else {
        inbuf[len] = 0;
    }
    Record recs[4];
    int rc = process(inbuf, len, recs, 4);
    if (rc != 0) {
        write_fd(2, "process failed\n", 15);
        die(1);
    }
    emit_summary(recs, 4);
    sort_scores(recs, 4);
    emit_summary(recs, 4);
    die(0);
}
