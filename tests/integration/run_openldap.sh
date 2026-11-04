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

# A signal ends the script once the docker command it interrupted returns
# (the CLI catches SIGINT and may exit as if it had failed).
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

if ! command -v docker > /dev/null || ! docker info > /dev/null 2>&1; then
	echo "run_openldap.sh: docker not available: running without slapd" >&2
	exec "$@"
fi

# The cleanup removes the containers with this run's label. docker run
# runs in its own session (setsid), out of the terminal's process group:
# Ctrl-C does not reach it (the CLI would cancel a container still being
# created, leaving it behind), and the trap, which bash runs once it
# returns, ends the script. No signal cuts the cleanup short.
label="coro-ldap-it=openldap-$$-$RANDOM$RANDOM"
dir=""
cleanup() {
	trap '' INT TERM HUP
	docker ps -aq --filter "label=$label" | xargs -r docker rm -f > /dev/null 2>&1 || true
	if [[ -n "$dir" ]]; then rm -rf "$dir"; fi
}
trap cleanup EXIT

docker build -q -t "$image" "$here/openldap" > /dev/null

dir="$(mktemp -d /tmp/jldap-docker.XXXXXX)"
name="coro-ldap-openldap-$$"
args=(--name "$name" --label "$label" --network host --user "$(id -u):$(id -g)"
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
setsid -w docker run -d "${args[@]}" "$image" "$here/run_slapd.sh" sh -c \
	'env | grep "^JHETZ_LDAP_IT_" > "$TMPDIR/env.new" && mv -f "$TMPDIR/env.new" "$TMPDIR/env" && exec sleep infinity' \
	> /dev/null
for _ in $(seq 300); do
	if [[ -s "$dir/env" ]] || [[ "$(docker inspect -f '{{.State.Running}}' "$name" 2> /dev/null)" != true ]]; then
		break
	fi
	sleep 0.1
done
if [[ ! -s "$dir/env" ]]; then
	# slapd logs to syslog only, which the container has not (run_slapd.sh
	# starts it with -s 0): its exit status and a busy port say more.
	state="$(docker inspect -f '{{if .State.Running}}still running after 30 s{{else}}run_slapd.sh exit status {{.State.ExitCode}}{{end}}' "$name" 2> /dev/null || echo "no container")"
	echo "run_openldap.sh: slapd did not start ($state):" >&2
	docker logs "$name" >&2 || true
	first="${JHETZ_LDAP_IT_PORT:-3389}"
	for p in "$first" $((first + 1)); do
		if (exec 3<> "/dev/tcp/127.0.0.1/$p") 2> /dev/null; then
			echo "run_openldap.sh: port $p is in use (set JHETZ_LDAP_IT_PORT)" >&2
		fi
	done
	exit 1
fi
while IFS='=' read -r var value; do
	export "$var=$value"
done < "$dir/env"
"$@"
