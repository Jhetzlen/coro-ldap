#!/usr/bin/env bash
# Runs run_slapd.sh in a Docker container, with Debian's OpenLDAP, and a
# command on the host with the JHETZ_LDAP_IT_* variables it sets; then
# removes the container:
#
#   tests/integration/run_openldap.sh ctest --test-dir build/main -L integration --output-on-failure
#
# The image (coro-ldap-openldap, from openldap/Dockerfile: Debian's slapd
# with its modules, cyrus-sasl's plugins including SCRAM and GSSAPI,
# openssl and python3) is built first, from Docker's cache after the
# first time, and kept. The slapd configuration, certificates and fixture
# are run_slapd.sh's own, with its Debian defaults: the container runs
# that script with a host directory mounted at the same path as its
# TMPDIR, so the certificates and the ldapi:// socket have the same paths
# on both sides, and runs as the calling user (files owned by them, the
# socket theirs to connect to, SASL EXTERNAL over ldapi:// sees their uid).
# It shares the host's network: slapd listens on 127.0.0.1 only, as
# without Docker, and reaches run_kdc.sh's KDC there.
#
# Under run_kdc.sh, slapd offers SASL GSSAPI: KRB5_CONFIG, KRB5_KTNAME,
# KRB5RCACHEDIR and JHETZ_LDAP_IT_KRB5_REALM are passed on, the
# directories they name mounted at the same paths:
#
#   tests/integration/run_kdc.sh tests/integration/run_openldap.sh \
#       ctest --test-dir build/gssapi -L integration --output-on-failure
#
# Without a working docker the command runs without slapd, so the tests
# are skipped.
#
# Environment:
#   JHETZ_LDAP_IT_PORT  first port  (3389, see run_slapd.sh)
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
image=coro-ldap-openldap

if ! command -v docker > /dev/null || ! docker info > /dev/null 2>&1; then
	echo "run_openldap.sh: docker not available: running without slapd" >&2
	exec "$@"
fi

docker build -q -t "$image" "$here/openldap" > /dev/null

dir="$(mktemp -d /tmp/jldap-docker.XXXXXX)"
name="coro-ldap-openldap-$$"
started=""
# SIGINT ends the script even during a command that survives it (docker run
# catches it), and no signal cuts the cleanup short.
cleanup() {
	trap '' INT TERM HUP
	if [[ -n "$started" ]]; then
		docker rm -f "$name" > /dev/null 2>&1 || true
	fi
	rm -rf "$dir"
}
trap cleanup EXIT
trap 'exit 130' INT

args=(--name "$name" --network host --user "$(id -u):$(id -g)"
	-v "$here:$here:ro" -v "$dir:$dir" -e "TMPDIR=$dir")
pass_env() { if [[ -n "${!1:-}" ]]; then args+=(-e "$1=${!1}"); fi; }
mounted=("$dir")
# add_mount DIR: once, at the same path.
add_mount() {
	local m
	for m in "${mounted[@]}"; do [[ "$m" == "$1" ]] && return; done
	mounted+=("$1")
	args+=(-v "$1:$1")
}
pass_env JHETZ_LDAP_IT_PORT
if [[ -n "${JHETZ_LDAP_IT_KRB5_REALM:-}" ]]; then
	pass_env JHETZ_LDAP_IT_KRB5_REALM
	for var in KRB5_CONFIG KRB5_KTNAME KRB5RCACHEDIR; do
		[[ -n "${!var:-}" ]] || continue
		pass_env "$var"
		path="${!var#FILE:}"
		if [[ "$var" != KRB5RCACHEDIR ]]; then path="$(dirname "$path")"; fi
		add_mount "$path"
	done
fi

# run_slapd.sh's command writes its variables to env, then waits to be
# removed.
started=1
docker run -d "${args[@]}" "$image" "$here/run_slapd.sh" sh -c \
	'env | grep "^JHETZ_LDAP_IT_" > "$TMPDIR/env.new" && mv -f "$TMPDIR/env.new" "$TMPDIR/env" && exec sleep infinity' \
	> /dev/null
for _ in $(seq 300); do
	if [[ -s "$dir/env" ]] || [[ "$(docker inspect -f '{{.State.Running}}' "$name" 2> /dev/null)" != true ]]; then
		break
	fi
	sleep 0.1
done
if [[ ! -s "$dir/env" ]]; then
	echo "run_openldap.sh: slapd did not start:" >&2
	docker logs "$name" >&2 || true
	exit 1
fi
while IFS='=' read -r var value; do
	export "$var=$value"
done < "$dir/env"
"$@"
