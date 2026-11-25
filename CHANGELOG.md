# Changelog

The version comes from `project(jhetz_ldap VERSION ...)` in `CMakeLists.txt`.
While it is 0.x, a minor version may break the API, and the installed
package matches only the same minor version (`find_package(jhetz_ldap 0.1)`,
`SameMinorVersion`).

## Unreleased

- SASL GSSAPI on Windows through SSPI's Kerberos package (`secur32`):
  the same `ldap::sasl_gssapi`, the logged-on user's credentials by
  default, the RFC 4752 security layers and tls-server-end-point channel
  bindings. `JHETZ_LDAP_WITH_GSSAPI` is on by default on Windows; the
  vcpkg `gssapi` feature and the Conan `gssapi` option build it there.
- `sasl_gssapi(principal, password, options)`: Kerberos credentials from
  a password (`gss_acquire_cred_with_password`, or SSPI's
  `SEC_WINNT_AUTH_IDENTITY_W`).

## 0.1.0

First release.
