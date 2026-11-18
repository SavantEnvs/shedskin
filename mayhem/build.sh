#!/usr/bin/env bash
#
# mayhem/build.sh — build this repo's fuzz harness(es). EDIT per repo.
#
# Runs inside the commit image (mayhem/Dockerfile) as `mayhem` in /mayhem. The base image
# (ghcr.io/savantenvs/base) already exports the build contract — use these, don't redefine:
#   CC, CXX             stock clang / clang++
#   LIB_FUZZING_ENGINE  -fsanitize=fuzzer   (link into each harness that has a LLVMFuzzer entry)
#   SANITIZER_FLAGS     -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer
#                       (ASan + UBSan, both set to HALT — so Mayhem catches memory AND UB defects)
#   DEBUG_FLAGS         -g -gdwarf-3   (DWARF debug info — always on for fuzz/standalone builds,
#                       independent of the sanitizer off-switch; DWARF version must be < 4)
#   RUST_DEBUG_FLAGS    -C debuginfo=2 -C force-frame-pointers=yes -C llvm-args=-gdwarf-3
#                       (thread through RUSTFLAGS on every cargo-fuzz build)
#   GO_DEBUG_FLAGS      -gcflags=all=-N -l
#                       (thread through go build / go-fuzz-build so the linked ELF keeps symbols)
#   SRC                 /mayhem (the repo source)
#
# Contract: build EVERYTHING here — one runnable binary per fuzz harness, AND the project's test
# suite (so mayhem/test.sh only has to RUN it, never compile). Keep it ADDITIVE (build upstream as
# upstream documents; don't edit upstream files). IMPORTANT: build the PROJECT ITSELF with
# $SANITIZER_FLAGS and $DEBUG_FLAGS (not just the harness) so the fuzzed code is instrumented
# AND carries DWARF < 4 symbols — otherwise ASan/UBSan only see the harness, not the library
# you're trying to find bugs in, and backtraces won't resolve project source lines. Build the TEST
# suite with the project's NORMAL flags (a clean, independent build) so test.sh stays an honest
# functional oracle and won't false-fail on benign UB. Leave the test binary/runner where test.sh
# expects it.
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' (empty) — it must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

# Build knobs come from the ENVIRONMENT (overridable), with sane defaults — no if-statements,
# just parameter-expansion fallbacks. Default sanitizers are the base's ASan+UBSan (halting); override
# per build via the Dockerfile's `--build-arg SANITIZER_FLAGS="..."`.
# NB: SANITIZER_FLAGS uses `=` (no colon) on purpose — `=` only fills when the var is UNSET, so an
# explicit EMPTY value (`--build-arg SANITIZER_FLAGS=`) is honored and builds with NO sanitizers
# (useful when you want the program's natural crash / full backtrace, not an ASan report). The other
# knobs use `:=` (default on empty too). MAYHEM_JOBS sets build parallelism (falls back to nproc).
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
# DEBUG_FLAGS carries DWARF debug info INDEPENDENTLY of the sanitizer off-switch (so an empty
# SANITIZER_FLAGS still yields DWARF symbols). DWARF MUST be < 4 (Mayhem triage can't read >=4); clang-19's
# plain `-g` emits DWARF-5, so `-gdwarf-3` is explicit. Apply $DEBUG_FLAGS to the fuzz/harness/standalone
# builds (NOT the test/oracle build). Rust/Go carry the same intent via their language flags below.
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${RUST_DEBUG_FLAGS:=-C debuginfo=2 -C force-frame-pointers=yes -C llvm-args=-gdwarf-3}"
: "${GO_DEBUG_FLAGS:=-gcflags=all=-N -l}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
# COVERAGE_FLAGS: empty by default → no effect on the normal oracle build. Set it via the Dockerfile's
# `--build-arg COVERAGE_FLAGS="-fprofile-instr-generate -fcoverage-mapping"` to instrument the TEST
# build for source-coverage measurement (how much of the project the test suite actually exercises —
# a quality signal for the oracle; complements the anti-reward-hack sabotage check). APPEND it to the
# test build's compile+link flags in step 3 (NOT the fuzz build); after `test.sh` runs, merge with
# `llvm-profdata` and report with `llvm-cov`. Empty value is honored (`=`, not `:=`).
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS RUST_DEBUG_FLAGS GO_DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"

# shedskin is a Python-to-C++ compiler plus a C++ runtime (shedskin/lib). The runtime is what parses
# untrusted data, so it is what gets fuzzed: it is built here from source with the runtime's own no-GC
# mode (-D__SS_NOGC, plain new/delete instead of Boehm, so ASan sees every allocation) and
# $SANITIZER_FLAGS, then linked into one libFuzzer binary per harness.
export PYTHONDONTWRITEBYTECODE=1
LIB="$SRC/shedskin/lib"
MY="$SRC/mayhem"
MODS="builtin re datetime struct binascii base64 csv configparser gzip heapq bisect socket time io"
# further runtime modules for the array/fnmatch/getopt harnesses (os is what fnmatch and getopt call into)
FUZZ_MODS="$MODS array fnmatch getopt os/__init__ os/path sys stat"
CXXSTD="-std=c++20 -D__SS_NOGC"

# 1) The runtime, sanitized, in two flavours: with SanCov for libFuzzer, and plain for -standalone.
FZ="$MY/build/fuzz"; SA="$MY/build/standalone"
rm -rf "$FZ" "$SA"; mkdir -p "$FZ" "$SA"
compile() { # <outdir> <extra flags> <src> <obj>
  "$CXX" $CXXSTD -D_GLIBCXX_ASSERTIONS -O1 $SANITIZER_FLAGS $DEBUG_FLAGS $2 -I"$LIB" -I"$MY" -c "$3" -o "$1/$4"
}
export -f compile; export CXX CXXSTD SANITIZER_FLAGS DEBUG_FLAGS LIB MY
{
  for m in $FUZZ_MODS; do o="${m//\//_}.o"; echo "$FZ|-fsanitize=fuzzer-no-link|$LIB/$m.cpp|$o"; echo "$SA||$LIB/$m.cpp|$o"; done
  echo "$FZ|-fsanitize=fuzzer-no-link|$MY/arena.cpp|arena.o"; echo "$SA||$MY/arena.cpp|arena.o"
  echo "$FZ||$MY/lsan_off.cc|lsan.o";                         echo "$SA||$MY/lsan_off.cc|lsan.o"
} | xargs -P "$MAYHEM_JOBS" -I{} bash -c 'IFS="|" read -r d f s o <<<"{}"; compile "$d" "$f" "$s" "$o"'

# 2) One fuzzer and one standalone reproducer per harness.
"$CC" $SANITIZER_FLAGS $DEBUG_FLAGS -x c -c "$STANDALONE_FUZZ_MAIN" -o "$MY/build/standalone-main.o"
TARGETS="fuzz_str fuzz_bytes fuzz_format fuzz_list fuzz_re fuzz_datetime fuzz_binary fuzz_text fuzz_socket fuzz_array fuzz_fnmatch fuzz_getopt"
build_target() {
  t="$1"
  "$CXX" $CXXSTD -D_GLIBCXX_ASSERTIONS -O1 $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE -I"$LIB" -I"$MY" \
      "$MY/$t.cpp" "$FZ"/*.o -o "/mayhem/$t"
  "$CXX" $CXXSTD -D_GLIBCXX_ASSERTIONS -O1 $SANITIZER_FLAGS $DEBUG_FLAGS -I"$LIB" -I"$MY" \
      "$MY/$t.cpp" "$MY/build/standalone-main.o" "$SA"/*.o -o "/mayhem/$t-standalone"
}
export -f build_target; export CC LIB_FUZZING_ENGINE FZ SA
printf '%s\n' $TARGETS | xargs -P "$MAYHEM_JOBS" -I{} bash -c 'build_target {}'

# 3) The oracle, built with normal flags (no sanitizers, no fuzzer): mayhem/kat.py is translated to C++
#    by the shedskin compiler itself and linked against the runtime, so test.sh exercises both halves.
OR="$MY/oracle"
rm -rf "$OR"; mkdir -p "$OR/obj"
for m in $MODS; do
  echo "$m"
done | xargs -P "$MAYHEM_JOBS" -I{} "$CXX" $CXXSTD -O1 $COVERAGE_FLAGS -I"$LIB" -c "$LIB/{}.cpp" -o "$OR/obj/{}.o"
cp "$MY/kat.py" "$OR/kat.py"
(cd "$OR" && PYTHONPATH="$SRC" python3 -m shedskin translate kat.py >translate.log 2>&1 || { cat translate.log >&2; exit 1; })
(cd "$OR" && "$CXX" $CXXSTD -O1 $COVERAGE_FLAGS -I"$LIB" -I"$OR" kat.cpp obj/*.o -o kat)

# 4) Upstream's own test suite (tests/test_*/test_*.py, ~14k asserts), configured and built the way
#    upstream CI's `shedskin runtests --build-type Release` does, with normal flags and the real GC.
#    Offline: bdwgc comes from the bundled shedskin/ext/bdwgc.zip (upstream's --local-deps path), built
#    once into a cache under mayhem/build/. The -ext (Python extension module) variants are disabled:
#    they run the same test code through the CPython binding layer, which is not fuzzed, and would
#    double the build time. test.sh runs the result with ctest.
SSHOME="$MY/build/shedskin-home"; TB="$MY/build/tests"
mkdir -p "$MY/build/bin" "$SSHOME"
printf '#!/bin/sh\nexec python3 -m shedskin "$@"\n' > "$MY/build/bin/shedskin"; chmod +x "$MY/build/bin/shedskin"
(
  export HOME="$SSHOME" PATH="$MY/build/bin:$PATH" PYTHONPATH="$SRC"
  python3 -c 'from shedskin.cmake import LocalDependencyManager as L; L().install_all()' >"$MY/build/bdwgc.log" 2>&1 \
    || { cat "$MY/build/bdwgc.log" >&2; exit 1; }
  cmake -S "$SRC/tests" -B "$TB" -DCMAKE_BUILD_TYPE=Release -DBUILD_EXECUTABLE=ON -DDISABLE_EXTENSIONS=ON \
      -DENABLE_LOCAL_DEPS=ON -DLOCAL_DEPS_DIR="$SSHOME/.cache/shedskin" -DENABLE_WARNINGS=OFF \
      -DPython_EXECUTABLE="$(command -v python3)" \
      -DCMAKE_CXX_FLAGS="$COVERAGE_FLAGS" -DCMAKE_EXE_LINKER_FLAGS="$COVERAGE_FLAGS" >"$MY/build/tests-cfg.log" 2>&1 \
    || { cat "$MY/build/tests-cfg.log" >&2; exit 1; }
  cmake --build "$TB" --parallel "$MAYHEM_JOBS" >"$MY/build/tests-build.log" 2>&1 \
    || { tail -100 "$MY/build/tests-build.log" >&2; exit 1; }
)
