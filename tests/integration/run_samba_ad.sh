#!/usr/bin/env bash
# Runs a command with two throwaway Samba AD DCs in Docker
# (docs/DEVELOPMENT.md "Samba Active Directory"):
#   tests/integration/run_samba_ad.sh ctest --test-dir build/main -L samba_ad
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
port="${JHETZ_LDAP_IT_SAMBA_PORT:-4389}"
image=coro-ldap-samba-ad

# A signal exits once the interrupted docker command returns.
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

if ! command -v docker > /dev/null || ! docker info > /dev/null 2>&1; then
	echo "run_samba_ad.sh: docker not available: running without Samba" >&2
	exec "$@"
fi

# docker runs in its own session (setsid), out of Ctrl-C's reach.
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

# Wait for a root DSE answer inside each DC, then for each published port.
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
