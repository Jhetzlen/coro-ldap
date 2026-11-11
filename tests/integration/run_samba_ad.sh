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
# $PORT and $((PORT+1)), the relaxed one on $((PORT+2)) and $((PORT+3));
# the strict one's KDC (TCP) on $((PORT+4)). Both DCs come from one
# provisioned image, so they share their Kerberos keys: a ticket from
# that KDC is good on either.
#
# Kerberos, when MIT's kinit is installed: a krb5.conf for CORO.TEST
# (KRB5_CONFIG) in the temporary directory, and alice's ticket in a
# credential cache there (KRB5CCNAME); JHETZ_LDAP_IT_SAMBA_KRB5_TARGET
# names the DC's LDAP service (ldap@dc1.coro.test) for the GSSAPI tests,
# which are skipped without it.
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

# A signal ends the script once the docker command it interrupted returns
# (the CLI catches SIGINT and may exit as if it had failed).
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

if ! command -v docker > /dev/null || ! docker info > /dev/null 2>&1; then
	echo "run_samba_ad.sh: docker not available: running without Samba" >&2
	exec "$@"
fi

# The cleanup removes the containers with this run's label. docker run
# and docker exec run in their own session (setsid), out of the
# terminal's process group: Ctrl-C does not reach them (the CLI would
# cancel a container still being created, leaving it behind, and both
# catch SIGINT, so the script would go on), and the trap, which bash runs
# once they return, ends the script. No signal cuts the cleanup short.
label="coro-ldap-it=samba-ad-$$-$RANDOM$RANDOM"
dir=""
cleanup() {
	trap '' INT TERM HUP
	docker ps -aq --filter "label=$label" | xargs -r docker rm -f > /dev/null 2>&1 || true
	if [[ -n "$dir" ]]; then rm -rf "$dir"; fi
}
trap cleanup EXIT

docker build -q -t "$image" "$here/samba-ad" > /dev/null

mkdir -p "$repo/build"
dir="$(mktemp -d "$repo/build/samba-ad.XXXXXX")"
containers=()

# start NAME STRONG_AUTH LDAP_PORT LDAPS_PORT [KDC_PORT]
start() {
	local name="coro-ldap-samba-ad-$$-$1"
	containers+=("$name")
	setsid -w docker run -d --rm --name "$name" --label "$label" --hostname dc1.coro.test \
		-p "127.0.0.1:$3:389" -p "127.0.0.1:$4:636" ${5:+-p "127.0.0.1:$5:88"} "$image" \
		samba --foreground --no-process-group --debug-stdout \
		"--option=ldap server require strong auth = $2" > /dev/null
}
start strict yes "$port" $((port + 1)) $((port + 4))
start relaxed no $((port + 2)) $((port + 3))

# Until each DC answers a root DSE search, inside and through the
# published port.
for name in "${containers[@]}"; do
	ready=""
	for _ in $(seq 300); do
		if setsid -w docker exec "$name" ldbsearch -H ldap://127.0.0.1 -s base -b "" dnsHostName > /dev/null 2>&1; then
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
for p in "$port" $((port + 1)) $((port + 2)) $((port + 3)) $((port + 4)); do
	ready=""
	for _ in $(seq 100); do
		if (exec 3<> "/dev/tcp/127.0.0.1/$p") 2> /dev/null; then
			ready=1
			break
		fi
		sleep 0.1
	done
	if [[ -z "$ready" ]]; then
		echo "run_samba_ad.sh: nothing accepts on 127.0.0.1:$p (JHETZ_LDAP_IT_SAMBA_PORT=$port)" >&2
		exit 1
	fi
done
docker cp -q "${containers[0]}:/var/lib/samba/private/tls/ca.pem" "$dir/ca.pem"

export JHETZ_LDAP_IT_SAMBA_LDAP="ldap://127.0.0.1:$port"
export JHETZ_LDAP_IT_SAMBA_LDAPS="ldaps://127.0.0.1:$((port + 1))"
export JHETZ_LDAP_IT_SAMBA_RELAXED_LDAP="ldap://127.0.0.1:$((port + 2))"
export JHETZ_LDAP_IT_SAMBA_RELAXED_LDAPS="ldaps://127.0.0.1:$((port + 3))"
export JHETZ_LDAP_IT_SAMBA_CA="$dir/ca.pem"
export JHETZ_LDAP_IT_SAMBA_TLS_NAME=DC1.coro.test

if command -v kinit > /dev/null; then
	cat > "$dir/krb5.conf" <<CONF
[libdefaults]
	default_realm = CORO.TEST
	dns_lookup_realm = false
	dns_lookup_kdc = false
	dns_canonicalize_hostname = false
	rdns = false
	udp_preference_limit = 1
[realms]
	CORO.TEST = {
		kdc = 127.0.0.1:$((port + 4))
	}
[domain_realm]
	.coro.test = CORO.TEST
	coro.test = CORO.TEST
CONF
	export KRB5_CONFIG="$dir/krb5.conf"
	export KRB5CCNAME="FILE:$dir/ccache"
	ticket=""
	for _ in $(seq 50); do
		if echo 'Al1ce-Passw0rd' | kinit alice@CORO.TEST > /dev/null 2>&1; then
			ticket=1
			break
		fi
		sleep 0.2
	done
	if [[ -z "$ticket" ]]; then
		echo "run_samba_ad.sh: kinit alice@CORO.TEST failed against 127.0.0.1:$((port + 4))" >&2
		exit 1
	fi
	export JHETZ_LDAP_IT_SAMBA_KRB5_TARGET=ldap@dc1.coro.test
else
	echo "run_samba_ad.sh: kinit not found (MIT krb5): running without Kerberos" >&2
fi
"$@"
