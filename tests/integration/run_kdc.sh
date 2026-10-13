#!/usr/bin/env bash
# Starts a throwaway MIT Kerberos KDC for the SASL GSSAPI integration
# tests, runs a command with the Kerberos environment set, and stops the
# KDC. Wrap run_slapd.sh with it, so slapd offers GSSAPI:
#
#   tests/integration/run_kdc.sh tests/integration/run_slapd.sh \
#       ctest --test-dir build -L integration --output-on-failure
#
# Realm EXAMPLE.ORG on 127.0.0.1:$JHETZ_LDAP_IT_KDC_PORT, with the
# service principal ldap/localhost (its keytab in KRB5_KTNAME, for slapd)
# and two users matching make_fixture.py's entries, user007 and jörg,
# whose tickets are in a DIR: credential cache collection (KRB5CCNAME),
# user007's the default. Nothing outside a temporary directory is used:
# KRB5_CONFIG and KRB5_KDC_PROFILE point into it.
#
# Needs MIT krb5's KDC tools (krb5kdc, kdb5_util, kadmin.local, kinit),
# and for slapd cyrus-sasl's gssapi plugin (Debian:
# libsasl2-modules-gssapi-mit, Arch: cyrus-sasl-gssapi). A plugin outside
# cyrus-sasl's directory is found through SASL_PATH, which replaces that
# directory: it must hold the other plugins too (SCRAM's).
#
# Environment:
#   JHETZ_LDAP_IT_KDC_PORT  KDC port, UDP and TCP  (3750)
set -euo pipefail

port="${JHETZ_LDAP_IT_KDC_PORT:-3750}"
realm=EXAMPLE.ORG
for tool in krb5kdc kdb5_util kadmin.local kinit; do
	if ! command -v "$tool" > /dev/null; then
		echo "run_kdc.sh: $tool not found (MIT krb5's KDC tools)" >&2
		exit 1
	fi
done

dir="$(mktemp -d /tmp/jkdc.XXXXXX)"
pid=""
cleanup() {
	if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
		kill "$pid"
		for _ in $(seq 50); do kill -0 "$pid" 2>/dev/null || break; sleep 0.1; done
	fi
	rm -rf "$dir"
}
trap cleanup EXIT

cat > "$dir/krb5.conf" <<CONF
[libdefaults]
	default_realm = $realm
	dns_lookup_realm = false
	dns_lookup_kdc = false
	dns_canonicalize_hostname = false
	rdns = false
	qualify_shortname = ""
[realms]
	$realm = {
		kdc = 127.0.0.1:$port
	}
[domain_realm]
	localhost = $realm
CONF
cat > "$dir/kdc.conf" <<CONF
[kdcdefaults]
	kdc_ports = $port
	kdc_tcp_ports = $port
[realms]
	$realm = {
		database_name = $dir/principal
		key_stash_file = $dir/stash
		acl_file = $dir/kadm5.acl
	}
[logging]
	kdc = FILE:$dir/kdc.log
CONF
export KRB5_CONFIG="$dir/krb5.conf"
export KRB5_KDC_PROFILE="$dir/kdc.conf"

kdb5_util create -s -r "$realm" -P "master-$RANDOM$RANDOM" > /dev/null
admin() { kadmin.local -r "$realm" -q "$1" > /dev/null; }
admin "addprinc -clearpolicy -randkey ldap/localhost"
admin "ktadd -k $dir/ldap.keytab ldap/localhost"
admin "addprinc -clearpolicy -pw pw-user007 user007"
admin "addprinc -clearpolicy -pw pässwörd jörg"

krb5kdc -r "$realm" -P "$dir/kdc.pid"
for _ in $(seq 100); do
	if [[ -s "$dir/kdc.pid" ]] && (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then break; fi
	sleep 0.1
done
pid="$(cat "$dir/kdc.pid")"

# One cache per principal in the collection; the last kinit's is the default.
export KRB5CCNAME="DIR:$dir/ccache"
mkdir "$dir/ccache"
echo "pässwörd" | kinit "jörg@$realm" > /dev/null
echo "pw-user007" | kinit "user007@$realm" > /dev/null

export KRB5_KTNAME="FILE:$dir/ldap.keytab"
export JHETZ_LDAP_IT_KRB5_REALM="$realm"
"$@"
