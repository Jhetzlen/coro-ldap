#!/bin/sh
# Installs Capy, Corosio and jhetz_ldap, full and codec-only, and builds a
# consumer against each (docs/DEVELOPMENT.md "Installing"):
#   tests/install/check_install.sh WORK_DIR
set -eu
work=$(realpath -m "${1:?usage: check_install.sh WORK_DIR}")
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
rm -rf "$work/prefix" "$work/prefix-codec" "$work/build"
mkdir -p "$work/build"
gen="-G Ninja -DCMAKE_BUILD_TYPE=Release -DCMAKE_CXX_SCAN_FOR_MODULES=OFF"
filter="$root/cmake/source_group_tree_filter.cmake"

# source_of NAME URL COMMIT OVERRIDE
source_of() {
	if [ -n "$4" ]; then echo "$4"; return; fi
	src="$work/src-$1"
	if [ -d "$src" ] && [ "$(git -C "$src" rev-parse HEAD 2>/dev/null)" != "$3" ]; then
		rm -rf "$src"
	fi
	if [ ! -d "$src" ]; then
		git clone -q "$2" "$src"
		git -C "$src" checkout -q "$3"
	fi
	echo "$src"
}
pin() { sed -n "/FetchContent_Declare($1/,/)/s/.*GIT_TAG \([0-9a-f]*\).*/\1/p" "$root/CMakeLists.txt"; }
capy=$(source_of capy https://github.com/cppalliance/capy.git "$(pin capy)" "${FETCHCONTENT_SOURCE_DIR_CAPY:-}")
corosio=$(source_of corosio https://github.com/cppalliance/corosio.git "$(pin corosio)" "${FETCHCONTENT_SOURCE_DIR_COROSIO:-}")

step() { echo "== $*"; }
step "Capy"
cmake -S "$capy" -B "$work/build/capy" $gen -DCMAKE_INSTALL_PREFIX="$work/prefix" \
	-DCMAKE_PROJECT_boost_capy_INCLUDE_BEFORE="$filter" \
	-DBOOST_CAPY_BUILD_TESTS=OFF -DBOOST_CAPY_BUILD_EXAMPLES=OFF -DBOOST_CAPY_BUILD_BENCH=OFF >/dev/null
cmake --build "$work/build/capy" >/dev/null
cmake --install "$work/build/capy" >/dev/null
step "Corosio"
cmake -S "$corosio" -B "$work/build/corosio" $gen -DCMAKE_INSTALL_PREFIX="$work/prefix" \
	-DCMAKE_PREFIX_PATH="$work/prefix" -DCMAKE_PROJECT_INCLUDE="$here/corosio_with_installed_capy.cmake" \
	-DCMAKE_PROJECT_boost_corosio_INCLUDE_BEFORE="$filter" \
	-DBOOST_COROSIO_BUILD_TESTS=OFF -DBOOST_COROSIO_BUILD_EXAMPLES=OFF \
	-DBOOST_COROSIO_BUILD_BENCH=OFF >/dev/null
cmake --build "$work/build/corosio" >/dev/null
cmake --install "$work/build/corosio" >/dev/null
step "jhetz_ldap with networking"
cmake -S "$root" -B "$work/build/ldap" $gen -DCMAKE_INSTALL_PREFIX="$work/prefix" \
	-DCMAKE_PREFIX_PATH="$work/prefix" -DJHETZ_LDAP_BUILD_TESTS=OFF -DJHETZ_LDAP_BUILD_EXAMPLES=OFF >/dev/null
cmake --build "$work/build/ldap" >/dev/null
cmake --install "$work/build/ldap" >/dev/null
step "consumer with jhetz::ldap_net"
cmake -S "$here/consumer" -B "$work/build/consumer" $gen -DCMAKE_PREFIX_PATH="$work/prefix" >/dev/null
cmake --build "$work/build/consumer" >/dev/null
"$work/build/consumer/consumer"

step "jhetz_ldap codec only"
cmake -S "$root" -B "$work/build/ldap-codec" $gen -DCMAKE_INSTALL_PREFIX="$work/prefix-codec" \
	-DJHETZ_LDAP_BUILD_NET=OFF -DJHETZ_LDAP_BUILD_TESTS=OFF >/dev/null
cmake --build "$work/build/ldap-codec" >/dev/null
cmake --install "$work/build/ldap-codec" >/dev/null
# The net-only headers, as excluded in the root CMakeLists.txt's install().
for h in net cancel.hpp client.hpp connection.hpp connection_options.hpp directory.hpp extended_operations.hpp paged_search.hpp referral_chase.hpp run.hpp search_stream.hpp \
	sasl_ntlm.hpp sasl_scram.hpp sasl_gssapi.hpp repository.hpp sync.hpp sync_extended_operations.hpp sync_repository.hpp transaction.hpp ad/dirsync.hpp ad/discover.hpp ad/password.hpp ad/ranged_values.hpp ad/sync.hpp; do
	if [ -e "$work/prefix-codec/include/jhetz/ldap/$h" ]; then
		echo "unexpected: $h installed without jhetz::ldap_net"
		exit 1
	fi
done
step "consumer with jhetz::ldap only"
cmake -S "$here/consumer" -B "$work/build/consumer-codec" $gen -DCMAKE_PREFIX_PATH="$work/prefix-codec" \
	-DWITH_NET=OFF >/dev/null
cmake --build "$work/build/consumer-codec" >/dev/null
"$work/build/consumer-codec/consumer"
step "a net consumer of the codec-only package fails to configure"
if cmake -S "$here/consumer" -B "$work/build/consumer-missing" $gen -DCMAKE_PREFIX_PATH="$work/prefix-codec" \
	>/dev/null 2>&1; then
	echo "unexpected: COMPONENTS net found in a codec-only install"
	exit 1
fi
step "COMPONENTS ad alone fails to configure on the codec-only package"
mkdir -p "$work/build/ad-only-src"
cat >"$work/build/ad-only-src/CMakeLists.txt" <<'EOF2'
cmake_minimum_required(VERSION 3.25)
project(jhetz_ldap_ad_only LANGUAGES CXX)
find_package(jhetz_ldap 0.1 REQUIRED COMPONENTS ad)
EOF2
if cmake -S "$work/build/ad-only-src" -B "$work/build/consumer-ad-missing" $gen \
	-DCMAKE_PREFIX_PATH="$work/prefix-codec" >/dev/null 2>&1; then
	echo "unexpected: COMPONENTS ad found in a codec-only install"
	exit 1
fi
echo "install check passed"
