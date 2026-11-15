#!/usr/bin/env bash
# run_tests.sh -- regression suite for bcdiff.
#
# Every case is an assertion about the *reported result*, not about internals:
# which function pairs change, whether the known patch sites are found, and
# whether clean (equivalent) rebuilds produce no false positives.
set -uo pipefail

cd "$(dirname "$0")/.."
ROOT=$PWD
BIN=$ROOT/build/bcdiff
SAMPLES=$ROOT/samples
OUT=$ROOT/build/test
mkdir -p "$OUT"

PASS=0
FAIL=0
declare -a FAILED

ok() { PASS=$((PASS + 1)); printf '  ok   %s\n' "$1"; }
bad() {
    FAIL=$((FAIL + 1))
    FAILED+=("$1")
    printf '  FAIL %s\n' "$1"
    [[ -n "${2:-}" ]] && printf '       %s\n' "$2"
}

# json_query FILE PYTHON_EXPR -- prints a python expression's value from report
json_query() {
    python3 -c "
import json,sys
d=json.load(open('$1'))
print($2)
"
}

# assert_eq NAME ACTUAL EXPECTED
assert_eq() {
    if [[ "$2" == "$3" ]]; then ok "$1"; else bad "$1" "got '$2', want '$3'"; fi
}

# assert_contains NAME HAYSTACK NEEDLE
assert_contains() {
    if [[ "$2" == *"$3"* ]]; then ok "$1"; else bad "$1" "'$3' not in output"; fi
}

expect_rc() {  # NAME EXPECTED_RC cmd...
    local name=$1 want=$2
    shift 2
    "$@" >/dev/null 2>&1
    local rc=$?
    if [[ $rc -eq $want ]]; then ok "$name"; else bad "$name" "exit $rc, want $want"; fi
}

section() { printf '\n%s\n' "$1"; }

# ---------------------------------------------------------------------------
section "1. tool builds and reports on the demo patch (symbols present)"
# ---------------------------------------------------------------------------
if [[ ! -x $BIN ]]; then
    bad "bcdiff binary exists" "$BIN missing; run make"
    echo; echo "aborting: no binary"; exit 1
fi
ok "bcdiff binary exists"

$BIN "$SAMPLES/vuln_app_v1.elf" "$SAMPLES/vuln_app_v2.elf" \
     --json "$OUT/sym.json" -o "$OUT/sym.html" >/dev/null 2>&1
RC=$?

assert_eq "exit status says 'differences found'" "$RC" "1"
assert_eq "functions recovered, old" \
    "$(json_query "$OUT/sym.json" "d['old_binary']['functions']")" "19"
assert_eq "functions recovered, new" \
    "$(json_query "$OUT/sym.json" "d['new_binary']['functions']")" "19"
assert_eq "all old functions paired" \
    "$(json_query "$OUT/sym.json" "sum(1 for f in d['functions'] if f['old'])")" "19"
assert_eq "exactly one function removed" \
    "$(json_query "$OUT/sym.json" "sum(1 for f in d['functions'] if f['status']=='removed')")" "1"
assert_eq "exactly one function added" \
    "$(json_query "$OUT/sym.json" "sum(1 for f in d['functions'] if f['status']=='added')")" "1"
assert_eq "removed function is legacy_decode" \
    "$(json_query "$OUT/sym.json" "[f['name'] for f in d['functions'] if f['status']=='removed'][0]")" \
    "legacy_decode"
assert_eq "added function is validate_range" \
    "$(json_query "$OUT/sym.json" "[f['name'] for f in d['functions'] if f['status']=='added'][0]")" \
    "validate_range"
assert_eq "parse_record is matched as modified" \
    "$(json_query "$OUT/sym.json" "[f['status'] for f in d['functions'] if f['name']=='parse_record'][0]")" \
    "modified"
assert_eq "unchanged function hash32 stays identical" \
    "$(json_query "$OUT/sym.json" "[f['status'] for f in d['functions'] if f['name']=='hash32'][0]")" \
    "identical"

# ---------------------------------------------------------------------------
section "2. the three real patch sites are identified"
# ---------------------------------------------------------------------------
KINDS=$(json_query "$OUT/sym.json" \
    "sorted(f['kind'] for f in d['findings'] if f['category']=='security')")
assert_contains "bounds check in parse_record reported" "$KINDS" "bounds-check-added"
assert_contains "capacity check in copy_token reported" "$KINDS" "capacity-check-added"
assert_contains "new validation helper reported" "$KINDS" "validator-introduced"
assert_eq "exactly 3 security findings (no noise)" \
    "$(json_query "$OUT/sym.json" "len([f for f in d['findings'] if f['category']=='security'])")" "3"
assert_eq "bounds check names the constant 0x1f" \
    "$(json_query "$OUT/sym.json" "[f['detail'] for f in d['findings'] if f['kind']=='bounds-check-added'][0].find('0x1f') >= 0")" \
    "True"
assert_eq "bounds check is attributed to parse_record" \
    "$(json_query "$OUT/sym.json" "[f['new_func'] for f in d['findings'] if f['kind']=='bounds-check-added'][0]")" \
    "parse_record"
assert_eq "capacity check is attributed to copy_token" \
    "$(json_query "$OUT/sym.json" "[f['new_func'] for f in d['findings'] if f['kind']=='capacity-check-added'][0]")" \
    "copy_token"
assert_eq "new validator is attributed to validate_range" \
    "$(json_query "$OUT/sym.json" "[f['new_func'] for f in d['findings'] if f['kind']=='validator-introduced'][0]")" \
    "validate_range"
assert_eq "the benign pre-existing guard in process is NOT a security finding" \
    "$(json_query "$OUT/sym.json" "any(f['kind']=='range-check-added' for f in d['findings'])")" \
    "False"
assert_eq "no spurious removed-check risk findings" \
    "$(json_query "$OUT/sym.json" "len([f for f in d['findings'] if f['kind']=='check-removed'])")" "0"

# ---------------------------------------------------------------------------
section "3. identical input produces an empty diff"
# ---------------------------------------------------------------------------
$BIN "$SAMPLES/vuln_app_v1.elf" "$SAMPLES/vuln_app_v1.elf" \
     --json "$OUT/same.json" -o "$OUT/same.html" >/dev/null 2>&1
RC=$?
assert_eq "exit status 0 for identical binaries" "$RC" "0"
assert_eq "no findings at all" \
    "$(json_query "$OUT/same.json" "len(d['findings'])")" "0"
assert_eq "every function identical" \
    "$(json_query "$OUT/same.json" "sum(1 for f in d['functions'] if f['status']=='identical')")" \
    "$(json_query "$OUT/same.json" "len(d['functions'])")"

# ---------------------------------------------------------------------------
section "4. stripped binaries: recovery and pairing still work"
# ---------------------------------------------------------------------------
$BIN "$SAMPLES/vuln_app_v1.stripped.elf" "$SAMPLES/vuln_app_v2.stripped.elf" \
     --json "$OUT/strip.json" -o "$OUT/strip.html" >/dev/null 2>&1
RC=$?
assert_eq "stripped run finds differences" "$RC" "1"
assert_eq "stripped: same function count as symbol build (old)" \
    "$(json_query "$OUT/strip.json" "d['old_binary']['functions']")" "19"
assert_eq "stripped: same function count as symbol build (new)" \
    "$(json_query "$OUT/strip.json" "d['new_binary']['functions']")" "19"
assert_eq "stripped: mode flagged" \
    "$(json_query "$OUT/strip.json" "d['mode']")" "stripped"
assert_eq "stripped: 3 security findings" \
    "$(json_query "$OUT/strip.json" "len([f for f in d['findings'] if f['category']=='security'])")" "3"
assert_eq "stripped: security kinds match symbol mode" \
    "$(json_query "$OUT/strip.json" "sorted(f['kind'] for f in d['findings'] if f['category']=='security')")" \
    "$(json_query "$OUT/sym.json" "sorted(f['kind'] for f in d['findings'] if f['category']=='security')")"
assert_eq "stripped: modified functions match symbol mode" \
    "$(json_query "$OUT/strip.json" "sorted(f['old']['addr'] for f in d['functions'] if f['status']=='modified' and f['old'])")" \
    "$(json_query "$OUT/sym.json" "sorted(f['old']['addr'] for f in d['functions'] if f['status']=='modified' and f['old'])")"

# ---------------------------------------------------------------------------
section "5. noisy rebuild: -O2 vs -O1, reordered functions"
# ---------------------------------------------------------------------------
# A vendor may hand out a rebuild that is not a minimal patch. The matcher must
# still pair by structure and not drown the real fix in false positives.
if [[ -f $SAMPLES/vuln_app_v1_O1.elf && -f $SAMPLES/vuln_app_v2.elf ]]; then
    $BIN "$SAMPLES/vuln_app_v1_O1.elf" "$SAMPLES/vuln_app_v2.elf" \
         --json "$OUT/o1.json" -o "$OUT/o1.html" >/dev/null 2>&1
    assert_eq "-O1 old still pairs all functions" \
        "$(json_query "$OUT/o1.json" "sum(1 for f in d['functions'] if f['old'])")" "19"
    # The only legitimate add/remove here is the patch itself: legacy_decode is
    # deleted and validate_range is new. Anything else would mean pairing broke
    # under the optimisation-level change.
    assert_eq "-O1 vs -O2: only the real add/remove pair" \
        "$(json_query "$OUT/o1.json" "sorted(f['name'] for f in d['functions'] if f['status'] in ('added','removed'))")" \
        "['legacy_decode', 'validate_range']"
    assert_eq "-O1 vs -O2: every non-patch function paired" \
        "$(json_query "$OUT/o1.json" "sum(1 for f in d['functions'] if f['old'] and f['new'])")" "18"
    assert_eq "-O1 vs -O2: bounds check still found in parse_record" \
        "$(json_query "$OUT/o1.json" "any(f['kind']=='bounds-check-added' and f.get('new_func')=='parse_record' for f in d['findings'])")" \
        "True"
else
    printf '  skip -O1 variant not built\n'
fi

# Reordered: same code, functions emitted in a different order and shifted.
if [[ -f $SAMPLES/vuln_app_v1_reordered.elf && -f $SAMPLES/vuln_app_v2_reordered.elf ]]; then
    $BIN "$SAMPLES/vuln_app_v1_reordered.elf" "$SAMPLES/vuln_app_v2_reordered.elf" \
         --json "$OUT/reord.json" -o "$OUT/reord.html" >/dev/null 2>&1
    # 22 functions per side (19 real + 3 layout padding helpers). Only the
    # patch pair is unmatched; everything else must pair despite the shift.
    assert_eq "reordered: every non-patch function paired" \
        "$(json_query "$OUT/reord.json" "sum(1 for f in d['functions'] if f['old'] and f['new'])")" "21"
    assert_eq "reordered: only the real add/remove pair is unmatched" \
        "$(json_query "$OUT/reord.json" "sorted(f['name'] for f in d['functions'] if f['status'] in ('added','removed'))")" \
        "['legacy_decode', 'validate_range']"
    # Eight functions moved to a different address yet still paired: the three
    # leading pad helpers and the five bodies that follow the inserted
    # validate_range / deleted legacy_decode.
    assert_eq "reordered: shifted functions are not paired by address" \
        "$(json_query "$OUT/reord.json" "sum(1 for f in d['functions'] if f['old'] and f['new'] and f['old']['addr'] != f['new']['addr'])")" \
        "8"
    assert_eq "reordered: 3 security findings survive reordering" \
        "$(json_query "$OUT/reord.json" "len([f for f in d['findings'] if f['category']=='security'])")" "3"
    assert_eq "reordered: pairing is not just address order" \
        "$(json_query "$OUT/reord.json" "any(abs(f['old']['addr']-f['new']['addr']) > 0x100 for f in d['functions'] if f['old'] and f['new'])")" \
        "True"
else
    printf '  skip reordered variant not built\n'
fi

# ---------------------------------------------------------------------------
section "6. weight tuning changes the score monotonically"
# ---------------------------------------------------------------------------
$BIN "$SAMPLES/vuln_app_v1.elf" "$SAMPLES/vuln_app_v2.elf" \
     --weights "name=0.9,seq=0.02,cfg=0.02,strings=0.02,imms=0.02,calls=0.02,size=0.02,mnem=0.02" \
     --json "$OUT/w_name.json" -o /dev/null >/dev/null 2>&1
$BIN "$SAMPLES/vuln_app_v1.elf" "$SAMPLES/vuln_app_v2.elf" \
     --weights "name=0.0,seq=0.5,cfg=0.2,strings=0.1,imms=0.1,calls=0.05,size=0.05,mnem=0.05" \
     --json "$OUT/w_seq.json" -o /dev/null >/dev/null 2>&1
assert_eq "weights are recorded in the report" \
    "$(json_query "$OUT/w_name.json" "round(d['weights']['name'],2)")" "0.9"
assert_eq "name-only weighting still separates the changed function" \
    "$(json_query "$OUT/w_name.json" "[f['status'] for f in d['functions'] if f['name']=='parse_record'][0]")" \
    "modified"
assert_eq "structure-only weighting still pairs parse_record" \
    "$(json_query "$OUT/w_seq.json" "[f['status'] for f in d['functions'] if f['name']=='parse_record'][0]")" \
    "modified"
assert_eq "structure-only weighting still finds the bounds check" \
    "$(json_query "$OUT/w_seq.json" "any(f['kind']=='bounds-check-added' for f in d['findings'])")" \
    "True"

# ---------------------------------------------------------------------------
section "7. scale: 400-function binary, 3 planted bounds checks"
# ---------------------------------------------------------------------------
if [[ -x $SAMPLES/../build/large/v1.elf && -f $ROOT/build/large/v2.elf ]]; then
    START=$(date +%s%N 2>/dev/null || python3 -c 'import time;print(int(time.time()*1e9))')
    $BIN "$ROOT/build/large/v1.elf" "$ROOT/build/large/v2.elf" \
         --json "$OUT/large.json" -o /dev/null >/dev/null 2>&1
    END=$(date +%s%N 2>/dev/null || python3 -c 'import time;print(int(time.time()*1e9))')
    ELAPSED_MS=$(( (END - START) / 1000000 ))
    assert_eq "large: all 401 functions recovered per side" \
        "$(json_query "$OUT/large.json" "d['old_binary']['functions']")" "401"
    assert_eq "large: exactly 3 functions changed" \
        "$(json_query "$OUT/large.json" "sum(1 for f in d['functions'] if f['status']=='modified')")" "3"
    assert_eq "large: all 3 planted bounds checks found" \
        "$(json_query "$OUT/large.json" "sum(1 for f in d['findings'] if f['kind']=='bounds-check-added')")" "3"
    assert_eq "large: the checks name the 0x1000 bound" \
        "$(json_query "$OUT/large.json" "all('0x1000' in f['detail'] for f in d['findings'] if f['kind']=='bounds-check-added')")" \
        "True"
    assert_eq "large: no security noise from 398 untouched functions" \
        "$(json_query "$OUT/large.json" "len([f for f in d['findings'] if f['category']=='security'])")" "3"
    if [[ $ELAPSED_MS -lt 30000 ]]; then
        ok "large: completes in ${ELAPSED_MS}ms (< 30s)"
    else
        bad "large: completes in ${ELAPSED_MS}ms (< 30s)"
    fi
else
    printf '  skip large inputs not built (run tools/gen_large.sh)
'
fi

# ---------------------------------------------------------------------------
section "8. HTML report structure"
# ---------------------------------------------------------------------------
H=$OUT/sym.html
if [[ -f $H ]]; then
    assert_contains "report is a complete HTML document" "$(head -c 200 "$H")" "<!doctype html>"
    SVGS=$(grep -o '<svg class="cfg"' "$H" | wc -l | tr -d ' ')
    if [[ ${SVGS:-0} -ge 2 ]]; then ok "CFG SVGs rendered ($SVGS)"; else bad "CFG SVGs rendered" "found $SVGS"; fi
    if grep -q 'marker-end' "$H"; then ok "CFG has control-flow edges"; else bad "CFG has control-flow edges"; fi
    if grep -q 'ins-add' "$H" && grep -q 'ins-del' "$H"; then
        ok "instruction diff shows added and removed lines"
    else
        bad "instruction diff shows added and removed lines"
    fi
    if grep -q 'Length/bounds check added' "$H"; then ok "finding present in HTML"; else bad "finding present in HTML"; fi
    if grep -q '0x1f' "$H"; then ok "constant shown in HTML"; else bad "constant shown in HTML"; fi
    if grep -qE 'NaN|undefined' "$H"; then bad "no NaN/undefined in report"; else ok "no NaN/undefined in report"; fi
    # CFG node counts must reflect real blocks, not zero.
    NODES=$(grep -o 'class="node"' "$H" | wc -l | tr -d ' ')
    if [[ ${NODES:-0} -gt 100 ]]; then ok "CFG nodes rendered ($NODES)"; else bad "CFG nodes rendered" "found $NODES"; fi
else
    bad "HTML report exists"
fi

# ---------------------------------------------------------------------------
section "9. error handling"
# ---------------------------------------------------------------------------
expect_rc "missing file -> exit 2" 2 $BIN /nonexistent.elf "$SAMPLES/vuln_app_v2.elf" -o /dev/null
expect_rc "non-ELF input -> exit 2" 2 $BIN "$ROOT/Makefile" "$SAMPLES/vuln_app_v2.elf" -o /dev/null
expect_rc "bad weight key -> exit 2" 2 $BIN "$SAMPLES/vuln_app_v1.elf" "$SAMPLES/vuln_app_v2.elf" --weights "bogus=1" -o /dev/null
expect_rc "help exits 0" 0 $BIN --help
printf '' > "$OUT/empty.bin"
expect_rc "empty file -> exit 2" 2 $BIN "$OUT/empty.bin" "$SAMPLES/vuln_app_v2.elf" -o /dev/null

# ---------------------------------------------------------------------------
printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
if [[ $FAIL -gt 0 ]]; then
    printf 'failures:\n'
    for f in "${FAILED[@]}"; do printf '  - %s\n' "$f"; done
    exit 1
fi
exit 0
