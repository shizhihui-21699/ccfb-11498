#!/usr/bin/env bash
# build_extra.sh -- build the "noisy rebuild" variants used by the test suite.
#
#   vuln_app_v1_O1.elf             vulnerable code at -O1 (vendor rebuilt)
#   vuln_app_v1_reordered.elf      vulnerable code, functions shifted in memory
#   vuln_app_v2_reordered.elf      patched code, same shift, same relative order
#
# These exercise the pairing algorithm on inputs where addresses and code
# layout differ far more than in the minimal patch.
set -euo pipefail

cd "$(dirname "$0")/.."
ROOT=$PWD
OUT=$ROOT/samples
mkdir -p "$OUT"

CXX=${CXX:-}
TARGET_ARGS=()
LDFLAGS=()

if [[ -z "$CXX" ]]; then
    if [[ "$(uname -s)" == "Darwin" ]]; then
        if [[ -x /opt/homebrew/opt/llvm@23/bin/clang++ ]]; then
            CXX=/opt/homebrew/opt/llvm@23/bin/clang++
        elif [[ -x /usr/local/opt/llvm/bin/clang++ ]]; then
            CXX=/usr/local/opt/llvm/bin/clang++
        else
            CXX=clang++
        fi
        TARGET_ARGS=(--target=x86_64-unknown-linux-gnu)
        LLD=$(command -v ld.lld || true)
        [[ -n "$LLD" ]] || { echo "error: ld.lld not found" >&2; exit 1; }
        LDFLAGS=(-fuse-ld="$LLD")
    else
        CXX=${CXX:-g++}
    fi
fi

BASE=(
    -std=c++17
    -ffreestanding -fno-exceptions -fno-rtti -fno-stack-protector
    -fno-asynchronous-unwind-tables -fno-unwind-tables
    -nostdlib -nostdinc++ -static -w
    "${TARGET_ARGS[@]}"
    "${LDFLAGS[@]}"
)

echo "CC/CXX: $CXX"
# Vulnerable release rebuilt at -O1.
"$CXX" "${BASE[@]}" -O1 -o "$OUT/vuln_app_v1_O1.elf" "$ROOT/samples/vuln_app.cpp"

# Reordered builds: identical function bodies, different emission order, so
# every address differs between the two releases.
"$CXX" "${BASE[@]}" -O2 -DSHIFT_A -include stdint.h \
    -o "$OUT/vuln_app_v1_reordered.elf" "$ROOT/samples/reorder_shim.cpp"
"$CXX" "${BASE[@]}" -O2 -DSHIFT_B -include stdint.h -DPATCHED \
    -o "$OUT/vuln_app_v2_reordered.elf" "$ROOT/samples/reorder_shim.cpp"

ls -l "$OUT"/vuln_app_v1_O1.elf "$OUT"/*reordered.elf
