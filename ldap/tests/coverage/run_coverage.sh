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
# BUILD_DIR defaults to build/coverage at the repository root.
# --run-only builds and runs the tests and leaves the .profraw files in
# BUILD_DIR/llvm-cov/profraw, without llvm-profdata / llvm-cov.
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

find_tool() { # VAR NAME: the tool's path, from $VAR or PATH
	local tool="${!1:-$2}"
	if ! command -v "$tool" >/dev/null 2>&1; then
		echo "error: $2 not found (set $1, or install LLVM: apt install llvm," \
			"pacman -S llvm, brew install llvm); it must match $cxx's version" >&2
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
	"${fetch_args[@]}" >/dev/null
cmake --build "$build"

# One profile per process (%p): the tests also run jhetz-ldapsearch.
rm -rf "$out"
mkdir -p "$out/profraw"
export LLVM_PROFILE_FILE="$out/profraw/%p-%m.profraw"

step "ctest"
ctest --test-dir "$build" --output-on-failure -j "$(nproc 2>/dev/null || echo 2)"
if [[ -n "${SLAPD:-}" ]]; then
	step "integration tests against $SLAPD"
	"$ldap/tests/integration/run_slapd.sh" ctest --test-dir "$build" -L integration --output-on-failure
else
	echo "(SLAPD not set: integration tests skipped, see tests/integration/run_slapd.sh)"
fi

shopt -s nullglob
profiles=("$out"/profraw/*.profraw)
echo "${#profiles[@]} profiles in $out/profraw"
if [[ -n "$run_only" ]]; then exit 0; fi

step "report"
"$profdata" merge -sparse "${profiles[@]}" -o "$out/ldap.profdata"
# Every instrumented executable: our targets are the only ones built with
# -fprofile-instr-generate, so the rest (Catch2, Corosio) has no mapping.
# llvm-cov takes the first as a positional argument, the rest with -object.
objects=()
while IFS= read -r exe; do
	if [[ ${#objects[@]} -gt 0 ]]; then objects+=(-object); fi
	objects+=("$exe")
done < <(find "$build" -path "$build/_deps" -prune -o -path "*/CMakeFiles" -prune -o \
	-type f -perm -u+x -print | sort)
# "N functions have mismatched data" is expected: hash-0 placeholder records
# of inline / constexpr functions a binary never emitted (e.g. ldap::detail::
# is_dn, used at compile time); the emitted copy carries the counts.
filters=(-instr-profile "$out/ldap.profdata" "${objects[@]}"
	-ignore-filename-regex '/(_deps|tests|fuzz|bench|examples)/'
	"$ldap/src" "$ldap/include")
"$cov" report "${filters[@]}" | tee "$out/summary.txt"
"$cov" show "${filters[@]}" -format=html -output-dir "$out/html" \
	-show-branches=count -show-line-counts-or-regions
"$cov" export "${filters[@]}" -summary-only -format=text >"$out/summary.json"
echo "HTML report: $out/html/index.html"
