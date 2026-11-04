#!/usr/bin/env bash
# Starts two throwaway Samba Active Directory domain controllers in Docker
# for the Samba AD integration tests, runs a command with the
# JHETZ_LDAP_IT_SAMBA_* variables set, and removes the containers:
#
#   tests/integration/run_samba_ad.sh ctest --test-dir build -L samba_ad --output-on-failure
#
# The image (coro-ldap-samba-ad, from samba-ad/Dockerfile: Debian's Samba,
# the domain CORO.TEST and its test users provisioned at build time) is
# built first, from Docker's cache after the first time, and kept. The two
# containers differ only in `ldap server require strong auth`, which is
# global in Samba:
#
#   strict   yes: simple binds and SASL binds only over TLS, the latter
#            with correct TLS channel bindings; on plain ldap:// only SASL
#            binds with signing or sealing (Windows' "LDAP server signing
#            requirements" = require signing and LdapEnforceChannelBinding
#            = 2, "Always"). Samba's default.
#   relaxed  no: any bind on any transport, channel bindings not checked
#            (signing not required, LdapEnforceChannelBinding = 0, "Never").
#
# Each serves LDAP and LDAPS on 127.0.0.1 only: the strict one on
# $PORT and $((PORT+1)), the relaxed one on $((PORT+2)) and $((PORT+3)).
# Their TLS certificate is the one Samba generated for itself (CN
# DC1.coro.test, no subjectAltName: the tests connect to 127.0.0.1 and
# match that name, JHETZ_LDAP_IT_SAMBA_TLS_NAME, against the subject CN);
# its CA is copied to a temporary directory under the repository's build/.
#
# No privileges or capabilities are needed (see the Dockerfile). Without a
# working docker the command runs without Samba, so the tests are skipped.
#
# Environment:
#   JHETZ_LDAP_IT_SAMBA_PORT  first host port  (4389)
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
port="${JHETZ_LDAP_IT_SAMBA_PORT:-4389}"
image=coro-ldap-samba-ad

if ! command -v docker > /dev/null || ! docker info > /dev/null 2>&1; then
	echo "run_samba_ad.sh: docker not available: running without Samba" >&2
	exec "$@"
fi

docker build -q -t "$image" "$here/samba-ad" > /dev/null

mkdir -p "$repo/build"
dir="$(mktemp -d "$repo/build/samba-ad.XXXXXX")"
containers=()
cleanup() {
	if ((${#containers[@]})); then
		docker rm -f "${containers[@]}" > /dev/null 2>&1 || true
	fi
	rm -rf "$dir"
}
trap cleanup EXIT

# start NAME STRONG_AUTH LDAP_PORT LDAPS_PORT
start() {
	local name="coro-ldap-samba-ad-$$-$1"
	docker run -d --rm --name "$name" --hostname dc1.coro.test \
		-p "127.0.0.1:$3:389" -p "127.0.0.1:$4:636" "$image" \
		samba --foreground --no-process-group --debug-stdout \
		"--option=ldap server require strong auth = $2" > /dev/null
	containers+=("$name")
}
start strict yes "$port" $((port + 1))
start relaxed no $((port + 2)) $((port + 3))

# Until each DC answers a root DSE search, inside and through the
# published port.
for name in "${containers[@]}"; do
	ready=""
	for _ in $(seq 300); do
		if docker exec "$name" ldbsearch -H ldap://127.0.0.1 -s base -b "" dnsHostName > /dev/null 2>&1; then
			ready=1
			break
		fi
		sleep 0.1
	done
	if [[ -z "$ready" ]]; then
		echo "run_samba_ad.sh: $name did not start:" >&2
		docker logs "$name" >&2 || true
		exit 1
	fi
done
for p in "$port" $((port + 1)) $((port + 2)) $((port + 3)); do
	for _ in $(seq 100); do
		if (exec 3<> "/dev/tcp/127.0.0.1/$p") 2> /dev/null; then break; fi
		sleep 0.1
	done
done
docker cp -q "${containers[0]}:/var/lib/samba/private/tls/ca.pem" "$dir/ca.pem"

export JHETZ_LDAP_IT_SAMBA_LDAP="ldap://127.0.0.1:$port"
export JHETZ_LDAP_IT_SAMBA_LDAPS="ldaps://127.0.0.1:$((port + 1))"
export JHETZ_LDAP_IT_SAMBA_RELAXED_LDAP="ldap://127.0.0.1:$((port + 2))"
export JHETZ_LDAP_IT_SAMBA_RELAXED_LDAPS="ldaps://127.0.0.1:$((port + 3))"
export JHETZ_LDAP_IT_SAMBA_CA="$dir/ca.pem"
export JHETZ_LDAP_IT_SAMBA_TLS_NAME=DC1.coro.test
"$@"
