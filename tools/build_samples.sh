#!/usr/bin/env bash
# Build the two demo releases (vulnerable + patched) as static x86-64 ELF
# executables. Works on macOS/arm64 by cross-compiling with clang + lld, and on
# x86-64 Linux natively.
#
#   samples/vuln_app_v1.elf   vulnerable release (unstripped)
#   samples/vuln_app_v1.stripped.elf
#   samples/vuln_app_v2.elf   patched release (unstripped)
#   samples/vuln_app_v2.stripped.elf
#
# On macOS the binaries are kept, not run (the host is arm64). On x86-64 Linux
# the script also executes a smoke test of both releases.
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
        # Homebrew LLVM provides a working clang driver with all backends.
        if [[ -x /opt/homebrew/opt/llvm@23/bin/clang++ ]]; then
            CXX=/opt/homebrew/opt/llvm@23/bin/clang++
        elif [[ -x /usr/local/opt/llvm/bin/clang++ ]]; then
            CXX=/usr/local/opt/llvm/bin/clang++
        else
            CXX=clang++
        fi
        TARGET_ARGS=(--target=x86_64-unknown-linux-gnu)
        LLD=$(command -v ld.lld || true)
        [[ -n "$LLD" ]] || { echo "error: ld.lld not found (brew install lld)" >&2; exit 1; }
        LDFLAGS=(-fuse-ld="$LLD")
    else
        CXX=${CXX:-g++}
    fi
fi

STRIP=$(command -v llvm-strip || true)
if [[ -z "$STRIP" ]]; then
    for c in /opt/homebrew/opt/llvm@23/bin/llvm-strip /opt/homebrew/opt/llvm/bin/llvm-strip; do
        [[ -x $c ]] && { STRIP=$c; break; }
    done
fi
[[ -n "$STRIP" ]] || STRIP=$(command -v strip || true)

COMMON=(
    -std=c++17
    -O2
    -ffreestanding
    -fno-exceptions
    -fno-rtti
    -fno-stack-protector
    -fno-asynchronous-unwind-tables
    -fno-unwind-tables
    -nostdlib
    -nostdinc++
    -static
    -Wall
    -Wextra
    "${TARGET_ARGS[@]}"
    "${LDFLAGS[@]}"
)

echo "CC/CXX: $CXX"
"$CXX" "${COMMON[@]}" -o "$OUT/vuln_app_v1.elf" "$ROOT/samples/vuln_app.cpp"
"$CXX" "${COMMON[@]}" -DPATCHED -o "$OUT/vuln_app_v2.elf" "$ROOT/samples/vuln_app.cpp"

cp "$OUT/vuln_app_v1.elf" "$OUT/vuln_app_v1.stripped.elf"
cp "$OUT/vuln_app_v2.elf" "$OUT/vuln_app_v2.stripped.elf"
if [[ -n "$STRIP" ]]; then
    "$STRIP" --strip-all "$OUT/vuln_app_v1.stripped.elf"
    "$STRIP" --strip-all "$OUT/vuln_app_v2.stripped.elf"
else
    echo "warning: no strip tool found, stripped variants keep symbols" >&2
fi

ls -l "$OUT"/*.elf

if [[ "$(uname -s)" == "Linux" && "$(uname -m)" == "x86_64" ]]; then
    echo "smoke test:"
    printf 'alice|7\n' | "$OUT/vuln_app_v1.elf" || true
    printf 'alice|7\n' | "$OUT/vuln_app_v2.elf" || true
fi
