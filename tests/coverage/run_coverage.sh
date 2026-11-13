#!/usr/bin/env bash
# Clang coverage report on src and include (docs/DEVELOPMENT.md "Coverage"):
#   tests/coverage/run_coverage.sh [--run-only] [BUILD_DIR]
set -euo pipefail

run_only=""
if [[ "${1:-}" == "--run-only" ]]; then
	run_only=1
	shift
fi
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../.." && pwd)"
build="$(realpath -m "${1:-$root/build/coverage}")"
out="$build/llvm-cov"
cxx="${CXX:-clang++}"

# Any cache type, UNINITIALIZED included.
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
	if [[ "$cxx" == *[[:space:]]* ]]; then
		echo "hint: CXX is one command; for a launcher such as ccache set" \
			"CMAKE_CXX_COMPILER_LAUNCHER=ccache CXX=clang++" >&2
	fi
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
cmake -S "$root" -B "$build" -G Ninja -DCMAKE_BUILD_TYPE=Debug -DCMAKE_CXX_COMPILER="$cxx" \
	-DJHETZ_LDAP_COVERAGE=ON -DJHETZ_LDAP_SANITIZE=OFF -DJHETZ_LDAP_BUILD_FUZZERS=OFF \
	${fetch_args[@]+"${fetch_args[@]}"} >/dev/null
cmake --build "$build"

rm -rf "$out"
mkdir -p "$out/profraw"
export LLVM_PROFILE_FILE="$out/profraw/%p-%m.profraw"

# Exit status: the first failing test step's.
status=0
step "ctest"
ctest --test-dir "$build" --output-on-failure -j "$(nproc 2>/dev/null || echo 2)" || status=$?
if [[ -n "${SLAPD:-}" ]]; then
	step "integration tests against $SLAPD"
	"$root/tests/integration/run_slapd.sh" ctest --test-dir "$build" -L integration --output-on-failure ||
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
# Truncated profiles are skipped, one warning each.
merge_rc=0
"$profdata" merge -sparse --failure-mode=all "${profiles[@]}" -o "$out/ldap.profdata" \
	2>"$out/profdata.err" || merge_rc=$?
cat "$out/profdata.err" >&2
if [[ $merge_rc -ne 0 ]]; then exit "$merge_rc"; fi
skipped="$(grep -c 'warning:' "$out/profdata.err" || true)"
if [[ $skipped -gt 0 ]]; then
	echo "warning: $skipped profiles skipped; the report omits them" >&2
fi
# Every ELF executable: the first positional, the rest after -object.
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
filters=(-instr-profile "$out/ldap.profdata" "${objects[@]}"
	"$root/src" "$root/include")
"$cov" report "${filters[@]}" | tee "$out/summary.txt"
"$cov" show "${filters[@]}" -format=html -output-dir "$out/html" \
	-show-branches=count -show-line-counts-or-regions
"$cov" export "${filters[@]}" -summary-only -format=text >"$out/summary.json"
echo "HTML report: $out/html/index.html"
exit "$status"
