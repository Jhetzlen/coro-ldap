# Changelog

The version comes from `project(jhetz_ldap VERSION ...)` in `CMakeLists.txt`.
While it is 0.x, a minor version may break the API, and the installed
package matches only the same minor version (`find_package(jhetz_ldap 0.1)`,
`SameMinorVersion`).

## 0.1.0

First release.

- `jhetz::ldap_core`: the codec (BER, LDAP messages and controls, DN, filter, URL,
  schema, RFC 4517/4518 matching rules, the entry-to-struct mapping), ICU only.
- `jhetz::ldap`: the async `ldap::connection` on Corosio and Capy, with
  TLS (ldaps://, StartTLS), ldapi://, SASL EXTERNAL, SCRAM-SHA-256 and
  optionally GSSAPI, plus the blocking `ldap::sync::connection`.
- `jhetz::ldap_ad`: Active Directory operations over the connection.
- CMake targets `jhetz::ldap` (the client), `jhetz::ldap_core` (the codec)
  and `jhetz::ldap_ad`; before this release the client was `jhetz::ldap_net`
  and the codec `jhetz::ldap`.
- CMake package `jhetz_ldap` (components `net`, the default, `core`, `ad`,
  `gssapi`) and vcpkg overlay ports in `packaging/vcpkg/` (`jhetz-ldap[core]`
  for the codec only).

The API changes made before this release are the "Breaking" lines in
[docs/API.md](docs/API.md); later releases list theirs here.
