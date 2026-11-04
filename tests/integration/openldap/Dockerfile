# OpenLDAP's slapd for the integration tests (tests/integration/run_openldap.sh
# builds it and runs run_slapd.sh in it). Debian's own packages on a pinned
# Debian image, nothing configured here: run_slapd.sh writes slapd's
# configuration, certificates and data at run time, with its defaults
# (/usr/sbin/slapd, /etc/ldap/schema, /usr/lib/ldap), which are Debian's.
#
# - slapd: 2.6.10, back_mdb and the sssvlv and syncprov overlays as
#   modules;
# - cyrus-sasl's plugins: libsasl2-modules (EXTERNAL is slapd's own;
#   SCRAM-SHA-256 and -PLUS from libscram) and libsasl2-modules-gssapi-mit
#   (GSSAPI, with MIT krb5's libraries, for run_kdc.sh's KDC);
# - openssl and python3, for run_slapd.sh's certificates and fixture.
#
# The package's own configuration (/etc/ldap/slapd.d) and database are not
# used.
FROM debian:trixie-20261027-slim

RUN apt-get update \
	&& DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
		slapd libsasl2-modules libsasl2-modules-gssapi-mit openssl python3 \
	&& rm -rf /var/lib/apt/lists/*
