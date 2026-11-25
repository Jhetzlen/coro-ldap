# Changelog

The version comes from `project(jhetz_ldap VERSION ...)` in `CMakeLists.txt`.
While it is 0.x, a minor version may break the API, and the installed
package matches only the same minor version (`find_package(jhetz_ldap 0.1)`,
`SameMinorVersion`).

## Unreleased

- Shared libraries: `BUILD_SHARED_LIBS=ON` builds `jhetz_ldap_core`,
  `jhetz_ldap` and `jhetz_ldap_ad` shared (SONAME `.so.0.1`; DLLs on
  Windows, every function exported), and fetched Capy and Corosio with
  them; all three always have the same linkage. The vcpkg ports follow the
  triplet's linkage and support Linux and Windows (not MinGW); the Conan
  recipe accepts `shared=True` and passes it to `capy` and `corosio`.
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
