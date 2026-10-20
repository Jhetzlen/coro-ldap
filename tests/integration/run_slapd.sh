#!/usr/bin/env bash
# Starts a throwaway OpenLDAP slapd for the integration tests, runs a
# command with the JHETZ_LDAP_IT_* variables set, and stops slapd:
#
#   tests/integration/run_slapd.sh ctest --test-dir build -L integration --output-on-failure
#
# slapd listens on ldap://127.0.0.1:$PORT, ldaps://localhost:$((PORT+1))
# and an ldapi:// socket in a temporary directory, with a test CA, a
# server certificate (localhost, 127.0.0.1) and a client certificate for
# SASL EXTERNAL, and authz-regexp for SASL SCRAM-SHA-256; the data is
# make_fixture.py's. Needs slapd and openssl. Under run_kdc.sh (a
# throwaway Kerberos KDC), slapd also offers SASL GSSAPI as
# ldap/localhost, with its keytab (KRB5_KTNAME) and realm.
#
# Environment (defaults suit Debian / Ubuntu's slapd package):
#   SLAPD              slapd binary              (/usr/sbin/slapd)
#   SLAPD_SCHEMA_DIR   directory of *.schema     (/etc/ldap/schema)
#   SLAPD_MODULE_PATH  slapd modules, if any     (/usr/lib/ldap; back_mdb and the sssvlv
#                                                 and syncprov overlays are loaded if
#                                                 found there)
#   JHETZ_LDAP_IT_PORT first port                (3389)
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
slapd="${SLAPD:-/usr/sbin/slapd}"
schema_dir="${SLAPD_SCHEMA_DIR:-/etc/ldap/schema}"
module_path="${SLAPD_MODULE_PATH:-/usr/lib/ldap}"
port="${JHETZ_LDAP_IT_PORT:-3389}"
tls_port=$((port + 1))

dir="$(mktemp -d /tmp/jldap.XXXXXX)"
pid=""
cleanup() {
	if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
		kill "$pid"
		for _ in $(seq 50); do kill -0 "$pid" 2>/dev/null || break; sleep 0.1; done
	fi
	rm -rf "$dir"
}
trap cleanup EXIT

# ---- certificates
cd "$dir"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 \
	-subj "/CN=jhetz-ldap integration CA" -keyout ca.key -out ca.pem 2>/dev/null
cat > server.ext <<EXT
basicConstraints = CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = DNS:localhost, IP:127.0.0.1
EXT
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj "/CN=localhost" \
	-keyout server.key -out server.csr 2>/dev/null
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 2 \
	-extfile server.ext -out server.pem 2>/dev/null
cat > client.ext <<EXT
basicConstraints = CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = clientAuth
EXT
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj "/DC=org/DC=example/CN=client" \
	-keyout client.key -out client.csr 2>/dev/null
openssl x509 -req -in client.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 2 \
	-extfile client.ext -out client.pem 2>/dev/null

# ---- configuration and data
mkdir data
modules=""
overlays=""
has_module() { [[ -e "$module_path/$1.so" || -e "$module_path/$1.la" ]]; }
if has_module back_mdb; then
	modules="moduleload back_mdb"
fi
# Server side sorting (RFC 2891) needs the sssvlv overlay; the sort test is
# skipped without it (JHETZ_LDAP_IT_SORT unset).
sort_available=""
if has_module sssvlv; then
	modules="$modules
moduleload sssvlv"
	overlays="overlay sssvlv"
	sort_available=1
fi
# Content synchronization (RFC 4533) needs the syncprov overlay; the
# syncrepl test is skipped without it (JHETZ_LDAP_IT_SYNCREPL unset). The
# session log lets a refresh from a cookie send only the changes.
syncrepl_available=""
if has_module syncprov; then
	modules="$modules
moduleload syncprov"
	overlays="$overlays
overlay syncprov
syncprov-checkpoint 100 10
syncprov-sessionlog 100"
	syncrepl_available=1
fi
# SASL GSSAPI (run_kdc.sh sets JHETZ_LDAP_IT_KRB5_REALM and KRB5_KTNAME;
# cyrus-sasl's gssapi plugin must be installed, or on SASL_PATH): the
# service principal is ldap/localhost, and a principal of the realm maps
# to the entry of the same uid.
gssapi=""
if [[ -n "${JHETZ_LDAP_IT_KRB5_REALM:-}" ]]; then
	gssapi="sasl-host localhost
sasl-realm $JHETZ_LDAP_IT_KRB5_REALM
authz-regexp \"^uid=([^,]+)(,cn=[^,]+)?,cn=gssapi,cn=auth\$\" \"uid=\$1,ou=people,dc=example,dc=org\""
fi
if [[ -n "$modules" ]]; then
	modules="modulepath $module_path
$modules"
fi
cat > slapd.conf <<CONF
include $schema_dir/core.schema
include $schema_dir/cosine.schema
include $schema_dir/inetorgperson.schema
include $schema_dir/nis.schema
$modules
pidfile $dir/slapd.pid
TLSCACertificateFile $dir/ca.pem
TLSCertificateFile $dir/server.pem
TLSCertificateKeyFile $dir/server.key
TLSVerifyClient try
sizelimit 1000
# SASL SCRAM-SHA-256 (cyrus-sasl's scram plugin, if installed): the
# username is a uid, checked against the entry's cleartext userPassword.
authz-regexp "^uid=([^,]+)(,cn=[^,]+)?,cn=scram-sha-256,cn=auth\$" "uid=\$1,ou=people,dc=example,dc=org"
$gssapi

# cn=config, writable by cn=config / secret: a test toggles settings at
# run time (olcDisallows) and restores them.
database config
rootpw secret

database mdb
maxsize 268435456
suffix "dc=example,dc=org"
rootdn "cn=admin,dc=example,dc=org"
rootpw secret
directory $dir/data
index objectClass eq
index uid eq
index entryCSN,entryUUID eq
access to * by * read
$overlays
CONF
python3 "$here/make_fixture.py" > fixture.ldif
"$slapd" -T add -f slapd.conf -l fixture.ldif -q

# ---- start and wait until it accepts connections
socket="$dir/ldapi"
socket_url="ldapi://$(python3 -c 'import sys, urllib.parse; print(urllib.parse.quote(sys.argv[1], safe=""))' "$socket")"
"$slapd" -f slapd.conf -h "ldap://127.0.0.1:$port/ ldaps://127.0.0.1:$tls_port/ $socket_url" -s 0
for _ in $(seq 100); do
	if [[ -S "$socket" ]] && (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then break; fi
	sleep 0.1
done
pid="$(cat "$dir/slapd.pid")"
cd - > /dev/null

export JHETZ_LDAP_IT_LDAP="ldap://127.0.0.1:$port"
export JHETZ_LDAP_IT_LDAPS="ldaps://localhost:$tls_port"
export JHETZ_LDAP_IT_LDAPI="$socket_url"
export JHETZ_LDAP_IT_CA="$dir/ca.pem"
export JHETZ_LDAP_IT_CLIENT_CERT="$dir/client.pem"
export JHETZ_LDAP_IT_CLIENT_KEY="$dir/client.key"
if [[ -n "$sort_available" ]]; then export JHETZ_LDAP_IT_SORT=1; fi
if [[ -n "$syncrepl_available" ]]; then export JHETZ_LDAP_IT_SYNCREPL=1; fi
"$@"
