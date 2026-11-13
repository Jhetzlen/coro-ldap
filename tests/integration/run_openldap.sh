#!/usr/bin/env bash
# Runs a command with run_slapd.sh's slapd in Docker (docs/DEVELOPMENT.md
# "Integration tests"):
#   tests/integration/run_openldap.sh ctest --test-dir build/main -L integration
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
image=coro-ldap-openldap

# A signal exits once the interrupted docker command returns.
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

if ! command -v docker > /dev/null || ! docker info > /dev/null 2>&1; then
	echo "run_openldap.sh: docker not available: running without slapd" >&2
	exec "$@"
fi

# docker runs in its own session (setsid), out of Ctrl-C's reach.
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
# add_mount DIR: at the same path, once.
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

# The container writes its JHETZ_LDAP_IT_* variables to $dir/env.
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
