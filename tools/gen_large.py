#!/usr/bin/env python3
"""gen_large.py -- generate a large synthetic C++ source pair for scale testing.

Writes two translation units with N near-identical functions, where a handful
carry real patches. This exercises function discovery and the O(n*m) candidate
stage on a binary far bigger than the demo app.

usage: gen_large.py OUTDIR [N] [--same]
"""
import os
import sys

outdir = sys.argv[1] if len(sys.argv) > 1 else "build/large"
n = int(sys.argv[2]) if len(sys.argv) > 2 else 400
same = "--same" in sys.argv

os.makedirs(outdir, exist_ok=True)

HEADER = """#include <stdint.h>
#include <stddef.h>
#define NOINLINE __attribute__((noinline, used))
struct Rec { char name[32]; uint32_t id; uint32_t score; };
extern "C" void write_fd(int, const char*, unsigned);
"""


def body(i):
    """A distinct but structurally similar function."""
    ops = ["+", "^", "*", "-"]
    op = ops[i % 4]
    iv = i
    mask = (i % 15) + 1
    konst = (i * 7) % 65536
    if i % 3 == 0:
        loop = (f"for (unsigned k = 0; k < n; ++k) {{ acc = (acc {op} p[k]) ^ 0x{iv:x}u; "
                f"if (acc & 0x{mask:x}u) acc ^= 0x{konst:x}u; }}")
    elif i % 3 == 1:
        loop = (f"for (unsigned k = 0; k < n; ++k) {{ acc = acc {op} "
                f"(uint32_t)(p[k] << (k & 7u)); if ((k & 0x{mask:x}u) == 0) "
                f"acc += 0x{konst:x}u; }}")
    else:
        loop = (f"while (n--) {{ acc ^= (uint32_t)p[n] {op} 0x{konst:x}u; "
                f"acc = (acc << 3) | (acc >> 29); }}")
    seed = (i * 2654435761) % 0xffffffff
    return f"""
extern "C" NOINLINE uint32_t fn_{i}(const uint8_t* p, unsigned n) {{
    uint32_t acc = 0x{seed:x}u;
    {loop}
    return acc;
}}
"""


def patched_body(i):
    """fn_137 and friends get a bounds check."""
    return f"""
extern "C" NOINLINE uint32_t fn_{i}(const uint8_t* p, unsigned n) {{
    if (n > 4096u) {{
        return 0u;
    }}
    uint32_t acc = 0x{i*2654435761 % 0xffffffff:x}u;
    for (unsigned k = 0; k < n; ++k) {{
        acc = (acc + p[k]) ^ 0x{i:x}u;
        if (acc & 0x{i%255+1:x}u) acc ^= 0x{i*7 % 65536:x}u;
    }}
    return acc;
}}
"""


PATCHED = {137, 219, 330}

with open(os.path.join(outdir, "large_v1.cpp"), "w") as f:
    f.write(HEADER)
    for i in range(n):
        f.write(body(i))
    f.write('\nextern "C" void _start(void) { for (;;) {} }\n')

with open(os.path.join(outdir, "large_v2.cpp"), "w") as f:
    f.write(HEADER)
    for i in range(n):
        if not same and i in PATCHED:
            f.write(patched_body(i))
        else:
            f.write(body(i))
    f.write('\nextern "C" void _start(void) { for (;;) {} }\n')

print(f"wrote {outdir}/large_v1.cpp and large_v2.cpp ({n} functions)")
