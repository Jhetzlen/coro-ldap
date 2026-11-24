#!/bin/sh
# Builds tests/install/vcpkg_consumer in manifest mode with the overlay ports
# in packaging/vcpkg/ports, jhetz-ldap taken from this source tree, and runs it
# (docs/DEVELOPMENT.md "vcpkg"):
#   tests/install/check_vcpkg.sh WORK_DIR [TRIPLET]
# The vcpkg is build/tools/vcpkg (JHETZ_LDAP_VCPKG overrides it, VCPKG_ROOT
# is ignored); the binary cache and the downloads default to
# build/tools/vcpkg-cache and build/tools/vcpkg-downloads.
set -eu
work=$(realpath -m "${1:?usage: check_vcpkg.sh WORK_DIR [TRIPLET]}")
triplet=${2:-x64-linux}
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
vcpkg_root=${JHETZ_LDAP_VCPKG:-$root/build/tools/vcpkg}
unset VCPKG_ROOT
export VCPKG_DEFAULT_BINARY_CACHE="${VCPKG_DEFAULT_BINARY_CACHE:-$root/build/tools/vcpkg-cache}"
export VCPKG_DOWNLOADS="${VCPKG_DOWNLOADS:-$root/build/tools/vcpkg-downloads}"
mkdir -p "$VCPKG_DEFAULT_BINARY_CACHE" "$VCPKG_DOWNLOADS"
if [ ! -x "$vcpkg_root/vcpkg" ]; then
	echo "no vcpkg in $vcpkg_root: clone https://github.com/microsoft/vcpkg there and run bootstrap-vcpkg.sh"
	exit 1
fi

step() { echo "== $*"; }
step "overlay ports, jhetz-ldap from $root"
rm -rf "$work/ports" "$work/build"
mkdir -p "$work"
cp -rf "$root/packaging/vcpkg/ports" "$work/ports"
# The tree's content goes into the portfile, so a changed tree changes the
# port's ABI hash and is not served from the binary cache.
tree=$(cd "$root" && {
	git rev-parse HEAD
	git diff HEAD
	git ls-files --others --exclude-standard | xargs -r cat
} | sha256sum | cut -d' ' -f1)
portfile="$work/ports/jhetz-ldap/portfile.cmake"
{
	echo "set(JHETZ_LDAP_SOURCE_PATH \"$root\") # tree $tree"
	cat "$root/packaging/vcpkg/ports/jhetz-ldap/portfile.cmake"
} >"$portfile"

step "vcpkg install ($triplet)"
"$vcpkg_root/vcpkg" install --vcpkg-root="$vcpkg_root" --triplet "$triplet" --x-manifest-root="$here/vcpkg_consumer" \
	--overlay-ports="$work/ports" --x-install-root="$work/vcpkg_installed" --clean-after-build

step "consumer"
cmake -S "$here/vcpkg_consumer" -B "$work/build" -G Ninja -DCMAKE_BUILD_TYPE=Release \
	-DCMAKE_TOOLCHAIN_FILE="$vcpkg_root/scripts/buildsystems/vcpkg.cmake" -DVCPKG_TARGET_TRIPLET="$triplet" \
	-DVCPKG_MANIFEST_INSTALL=OFF -DVCPKG_INSTALLED_DIR="$work/vcpkg_installed" >/dev/null
cmake --build "$work/build" >/dev/null
"$work/build/consumer"
echo "vcpkg check passed"
