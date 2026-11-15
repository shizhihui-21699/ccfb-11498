// reorder_shim.cpp -- builds the same vuln_app logic with functions emitted in a
// different order and at different addresses, to test that pairing is structural
// rather than address-based.
//
// The trick: each release includes vuln_app.cpp under a different set of
// preceding definitions, which changes symbol order and the address of every
// function without changing any function body.

#include <stdint.h>

extern "C" {
// Forward the two entry points the harness needs; the rest of the file is
// included below with the same source, so bodies are identical between the two
// orderings.
}

#define NOINLINE __attribute__((noinline, used))

#if defined(SHIFT_A)
// Padding functions emitted before the real code shift every address.
NOINLINE int shift_pad_1(int x) { return x * 3 + 1; }
NOINLINE int shift_pad_2(int x) { return x ^ 0x55; }
NOINLINE int shift_pad_3(int x) { return x - 7; }
#endif

#include "vuln_app.cpp"

#if defined(SHIFT_B)
// Padding emitted *after* the real code instead.
NOINLINE int tail_pad_1(int x) { return x * 3 + 1; }
NOINLINE int tail_pad_2(int x) { return x ^ 0x55; }
NOINLINE int tail_pad_3(int x) { return x - 7; }
#endif
