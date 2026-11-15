#!/usr/bin/env bash
# gen_large.sh -- build the 400-function scale fixture.
set -euo pipefail
cd "$(dirname "$0")/.."
N=${1:-400}
CXX=/opt/homebrew/opt/llvm@23/bin/clang++
command -v "$CXX" >/dev/null || CXX=$(command -v clang++)
python3 tools/gen_large.py build/large "$N"
LD=$(command -v ld.lld)
for v in 1 2; do
    "$CXX" --target=x86_64-unknown-linux-gnu -std=c++17 -O2 -ffreestanding \
        -fno-exceptions -fno-rtti -nostdlib -nostdinc++ -static \
        -fuse-ld="$LD" -w -o "build/large/v$v.elf" "build/large/large_v$v.cpp"
done
ls -l build/large/*.elf
