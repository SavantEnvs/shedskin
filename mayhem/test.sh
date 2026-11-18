#!/usr/bin/env bash
#
# mayhem/test.sh — RUN this repo's OWN functional test suite (already built by mayhem/build.sh).
# exit 0 = pass. EDIT per repo. PATCH-grade oracle: after an agent patches the source, the grader
# rebuilds (build.sh) then runs this. DELETE this file if the repo has no meaningful tests.
#
# IMPORTANT:
#  * Must assert BEHAVIOR/OUTPUT, not just exit status. The oracle has to check asserted values /
#    golden-output diffs / known-answer results — so a PATCH that "fixes" a bug by making the program
#    exit(0) (or any no-op) FAILS here. Running inputs and checking only "exit 0 / didn't crash" is
#    NOT a functional test (it's trivially reward-hackable) — use the project's real assertion suite.
#  * Do NOT build here — mayhem/build.sh already compiled the test suite (with the project's normal
#    flags). This script only RUNS the pre-built tests and reports counts. If the test runner is
#    missing, that's a build.sh bug — fail loudly rather than silently rebuilding.
#  * REQUIRED OUTPUT — a CTRF (https://ctrf.io) summary so Mayhem/the PATCH grader reads the counts:
#      - writes a CTRF JSON report to ${CTRF_REPORT:-$SRC/ctrf-report.json}, and
#      - prints a one-line `CTRF {...}` marker to stdout (same JSON, compact).
#    Only `results.summary` (with tests/passed/failed/pending/skipped/other) is required.
#    Use the emit_ctrf helper below; it computes tests = passed+failed+skipped and sets the exit
#    code (0 iff failed==0). Map your framework's output to passed/failed/skipped.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"   # build parallelism; env-overridable, falls back to nproc (use -j"$MAYHEM_JOBS")
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
# Writes a CTRF report (file + stdout `CTRF {...}` marker) and returns non-zero iff failed>0.
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

# Two oracles, both required:
#  1) Upstream's own suite: tests/test_*/test_*.py (the programs upstream CI runs with `shedskin runtests`),
#     each translated by shedskin and built against the runtime by build.sh (mayhem/build/tests), run
#     here with ctest. Each test is a program full of asserts and signals only by its exit status.
#  2) A known-answer diff: mayhem/kat.py, translated and linked the same way (mayhem/oracle/kat), prints
#     one line per runtime feature; mayhem/kat.expected is CPython's own output for the same program.
#     It is what catches a patch that makes programs exit early with status 0: that prints nothing.
TB="$SRC/mayhem/build/tests"
KAT="$SRC/mayhem/oracle/kat"
EXPECTED="$SRC/mayhem/kat.expected"
[ -x "$KAT" ] || { echo "missing $KAT: mayhem/build.sh did not build the oracle" >&2; emit_ctrf "shedskin" 0 1 0; exit 1; }
[ -f "$TB/CTestTestfile.cmake" ] || { echo "missing $TB: mayhem/build.sh did not build tests/" >&2; emit_ctrf "shedskin" 0 1 0; exit 1; }

passed=0; failed=0

# 1) upstream suite
ctest_log="$(mktemp)"
ctest --test-dir "$TB" --parallel "$MAYHEM_JOBS" --output-on-failure >"$ctest_log" 2>&1
summary="$(grep -E 'tests passed, [0-9]+ tests? failed out of [0-9]+' "$ctest_log" | tail -1)"
if [[ "$summary" =~ ([0-9]+)\ tests?\ failed\ out\ of\ ([0-9]+) ]]; then
  t_failed="${BASH_REMATCH[1]}"; t_total="${BASH_REMATCH[2]}"
  passed=$((passed + t_total - t_failed)); failed=$((failed + t_failed))
  [ "$t_failed" -eq 0 ] || { grep -E '\*\*\*|Failed|Not Run' "$ctest_log" >&2; }
  [ "$t_total" -gt 0 ] || failed=$((failed + 1))
else
  echo "FAIL: no ctest summary" >&2; tail -50 "$ctest_log" >&2; failed=$((failed + 1))
fi
echo "upstream tests/: $summary"
rm -f "$ctest_log"

# 1b) upstream's translator error/warning-message suite: `shedskin runtests --run-errs` translates each
#     tests/errs/<N>.py (into its own temp dir) and checks the expected `#*` messages appear. It only runs
#     the translator, no compiler. It chdir()s into ./errs, so run it from a mktemp copy to keep the tree clean.
skipped=0
errs_dir="$(mktemp -d)"; errs_log="$(mktemp)"
cp -r "$SRC/tests/errs" "$errs_dir/errs"
(cd "$errs_dir" && PYTHONPATH="$SRC" python3 -m shedskin runtests --run-errs) >"$errs_log" 2>&1
e_total="$(grep -c '^\*\*\* test:' "$errs_log")"
e_ok="$(grep -cE '^\*\*\* .*SUCCESS.*: [0-9]+\.py$' "$errs_log")"
e_fail="$(grep -cE '^\*\*\* .*FAILURE.*: [0-9]+\.py$' "$errs_log")"
e_skip="$(grep -cE '^\*\*\* .*SKIPPED.*: [0-9]+\.py ' "$errs_log")"
passed=$((passed + e_ok)); failed=$((failed + e_fail)); skipped=$((skipped + e_skip))
[ "$e_fail" -eq 0 ] || grep -E '^\*\*\* .*FAILURE' "$errs_log" >&2
if [ "$e_total" -eq 0 ] || [ $((e_ok + e_fail + e_skip)) -ne "$e_total" ] || ! grep -q 'NO FAILURES' "$errs_log"; then
  echo "FAIL: tests/errs: $e_total tests, $e_ok ok, $e_fail failed, $e_skip skipped" >&2; tail -30 "$errs_log" >&2
  failed=$((failed + 1))
fi
echo "upstream tests/errs: $e_ok passed, $e_fail failed, $e_skip skipped of $e_total"
rm -rf "$errs_dir" "$errs_log"

# 2) known-answer diff
mapfile -t want < "$EXPECTED"
mapfile -t got < <("$KAT" 2>&1)
for i in "${!want[@]}"; do
  if [ "${got[$i]-}" = "${want[$i]}" ]; then
    passed=$((passed + 1))
  else
    failed=$((failed + 1))
    echo "FAIL kat line $((i + 1)): want [${want[$i]}] got [${got[$i]-}]" >&2
  fi
done
if [ "${#got[@]}" -ne "${#want[@]}" ]; then
  failed=$((failed + 1))
  echo "FAIL: kat got ${#got[@]} lines, want ${#want[@]}" >&2
fi
emit_ctrf "shedskin" "$passed" "$failed" "$skipped"
