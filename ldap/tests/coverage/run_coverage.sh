#!/usr/bin/env bash
# Coverage report for jhetz::ldap with Clang source-based coverage: builds
# BUILD_DIR with -DJHETZ_LDAP_COVERAGE=ON (our targets only, no sanitizers),
# runs the whole ctest suite (and the slapd integration tests when SLAPD is
# set), merges the profiles and reports on ldap/src and ldap/include:
#
#   ldap/tests/coverage/run_coverage.sh [--run-only] [BUILD_DIR]
#
#   BUILD_DIR/llvm-cov/summary.txt    llvm-cov report (also printed)
#   BUILD_DIR/llvm-cov/html/index.html line, region and branch details
#   BUILD_DIR/llvm-cov/summary.json   llvm-cov export -summary-only
#
# BUILD_DIR defaults to build/coverage at the repository root; an existing
# build directory configured without JHETZ_LDAP_COVERAGE=ON is refused.
# --run-only builds and runs the tests and leaves the .profraw files in
# BUILD_DIR/llvm-cov/profraw, without llvm-profdata / llvm-cov.
# When a test fails the report is still written, and the script exits with
# the first failing step's status.
#
# Linux, bash >= 4.4, GNU coreutils (realpath -m), like check_install.sh.
#
# Environment:
#   CXX                          Clang C++ compiler        (clang++)
#   LLVM_PROFDATA, LLVM_COV      the tools, matching CXX   (from PATH)
#   FETCHCONTENT_SOURCE_DIR_CAPY / _COROSIO / _CATCH2      local checkouts
#   SLAPD, SLAPD_SCHEMA_DIR, SLAPD_MODULE_PATH             see run_slapd.sh;
#                                setting SLAPD runs the integration tests
set -euo pipefail

run_only=""
if [[ "${1:-}" == "--run-only" ]]; then
	run_only=1
	shift
fi
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ldap="$(cd "$here/../.." && pwd)"
build="$(realpath -m "${1:-$ldap/../build/coverage}")"
out="$build/llvm-cov"
cxx="${CXX:-clang++}"

# Any type: a first configure that failed in project() (before
# option(JHETZ_LDAP_COVERAGE)) leaves JHETZ_LDAP_COVERAGE:UNINITIALIZED=ON.
if [[ -f "$build/CMakeCache.txt" ]] &&
	! grep -qixE 'JHETZ_LDAP_COVERAGE:[A-Z]+=(ON|TRUE|YES|Y|1)' "$build/CMakeCache.txt"; then
	echo "error: $build is not a coverage build (its CMakeCache.txt lacks" \
		"JHETZ_LDAP_COVERAGE=ON); refusing to reconfigure it: pass a new or" \
		"coverage BUILD_DIR" >&2
	exit 1
fi

if ! command -v "$cxx" >/dev/null 2>&1; then
	echo "error: C++ compiler $cxx not found (set CXX to a Clang C++ compiler," \
		"e.g. CXX=clang++-23)" >&2
	exit 1
fi

find_tool() { # VAR NAME: the tool's path, from $VAR or PATH
	local tool="${!1:-$2}"
	if ! command -v "$tool" >/dev/null 2>&1; then
		echo "error: $2 not found (set $1, or install LLVM: apt install llvm," \
			"pacman -S llvm); it must match $cxx's version" >&2
		exit 1
	fi
	command -v "$tool"
}
if [[ -z "$run_only" ]]; then
	profdata="$(find_tool LLVM_PROFDATA llvm-profdata)"
	cov="$(find_tool LLVM_COV llvm-cov)"
fi

step() { echo "== $*"; }
fetch_args=()
for dep in CAPY COROSIO CATCH2; do
	var="FETCHCONTENT_SOURCE_DIR_$dep"
	if [[ -n "${!var:-}" ]]; then fetch_args+=("-D$var=${!var}"); fi
done

step "configure and build $build"
cmake -S "$ldap" -B "$build" -G Ninja -DCMAKE_BUILD_TYPE=Debug -DCMAKE_CXX_COMPILER="$cxx" \
	-DJHETZ_LDAP_COVERAGE=ON -DJHETZ_LDAP_SANITIZE=OFF -DJHETZ_LDAP_BUILD_FUZZERS=OFF \
	${fetch_args[@]+"${fetch_args[@]}"} >/dev/null
cmake --build "$build"

# %m: one profile per instrumented binary (the tests also run
# jhetz-ldapsearch), merged online across that binary's processes; %p is
# optional and only splits them per process, the merge below sums them.
rm -rf "$out"
mkdir -p "$out/profraw"
export LLVM_PROFILE_FILE="$out/profraw/%p-%m.profraw"

# A failing test still leaves its profile: report anyway, then exit with
# the first failing step's status.
status=0
step "ctest"
ctest --test-dir "$build" --output-on-failure -j "$(nproc 2>/dev/null || echo 2)" || status=$?
if [[ -n "${SLAPD:-}" ]]; then
	step "integration tests against $SLAPD"
	"$ldap/tests/integration/run_slapd.sh" ctest --test-dir "$build" -L integration --output-on-failure ||
		{ rc=$?; if [[ $status -eq 0 ]]; then status=$rc; fi; }
else
	echo "(SLAPD not set: integration tests skipped, see tests/integration/run_slapd.sh)"
fi

shopt -s nullglob
profiles=("$out"/profraw/*.profraw)
echo "${#profiles[@]} profiles in $out/profraw"
if [[ $status -ne 0 ]]; then
	echo "warning: tests failed (status $status); the report covers the runs so far" >&2
fi
if [[ -n "$run_only" ]]; then exit "$status"; fi
if [[ ${#profiles[@]} -eq 0 ]]; then
	echo "error: no profiles in $out/profraw" >&2
	exit 1
fi

step "report"
# --failure-mode=all: skip (with a warning) a profile a killed process left
# truncated, e.g. on a ctest timeout or a child the test kills on purpose
# (which need not fail the test), rather than lose the whole report; it
# still fails when no profile is readable.
"$profdata" merge -sparse --failure-mode=all "${profiles[@]}" -o "$out/ldap.profdata"
# Every ELF executable: our targets are the only ones built with
# -fprofile-instr-generate, so the rest (Catch2, Corosio) has no mapping.
# Only ELF files: llvm-cov rejects anything else (e.g. an executable script).
# llvm-cov takes the first as a positional argument, the rest with -object.
objects=()
while IFS= read -r exe; do
	if ! cmp -s -n 4 "$exe" <(printf '\177ELF'); then continue; fi
	if [[ ${#objects[@]} -gt 0 ]]; then objects+=(-object); fi
	objects+=("$exe")
done < <(find "$build" -path "$build/_deps" -prune -o -path "*/CMakeFiles" -prune -o \
	-type f -perm -u+x -print | sort)
if [[ ${#objects[@]} -eq 0 ]]; then
	echo "error: no ELF executables in $build" >&2
	exit 1
fi
# "N functions have mismatched data" is expected: hash-0 placeholder records
# of inline / constexpr functions a binary never emitted (e.g. ldap::detail::
# is_dn, used at compile time); the emitted copy carries the counts.
# The source paths alone select our files (no -ignore-filename-regex: it
# matches the absolute path, so a checkout under e.g. ~/src/examples/ would
# drop everything).
filters=(-instr-profile "$out/ldap.profdata" "${objects[@]}"
	"$ldap/src" "$ldap/include")
"$cov" report "${filters[@]}" | tee "$out/summary.txt"
"$cov" show "${filters[@]}" -format=html -output-dir "$out/html" \
	-show-branches=count -show-line-counts-or-regions
"$cov" export "${filters[@]}" -summary-only -format=text >"$out/summary.json"
echo "HTML report: $out/html/index.html"
exit "$status"
