# Changelog

The version comes from `project(jhetz_ldap VERSION ...)` in `CMakeLists.txt`.
While it is 0.x, a minor version may break the API, and the installed
package matches only the same minor version (`find_package(jhetz_ldap 0.2)`,
`SameMinorVersion`).

## Unreleased

### Added

- ICU and OpenSSL that are not installed are built once with a pinned vcpkg in the build tree, as static libraries (`JHETZ_LDAP_FETCH_DEPS`, on by default; Linux and MSVC), so a FetchContent or CPM build needs nothing installed.
- README: a CPM.cmake snippet.

### Changed

- The vcpkg `gssapi` feature uses vcpkg's `krb5` port on Linux, and the Conan `gssapi` option ConanCenter's `krb5` recipe, instead of the system GSS-API library.
- The vcpkg port and the Conan recipes are in the form microsoft/vcpkg and conan-center-index accept (no local-source hook in the portfile, no system packages, `url` set to conan-center-index); they are not submitted.

- `tls_options::cert_pem` and `key_pem`: the TLS client certificate (then its chain) and its unencrypted key as PEM text, instead of `cert_file` and `key_file`.

## 0.2.0 (2026-11-25)

### Breaking

- Binds and StartTLS (`simple_bind`, `sasl_bind`, `start_tls`) return the connection handle (`task<result<connection>>`; sync: `result<sync::connection>`) instead of `void`.
- `ntlm_message.hpp`, the NTLM internals of `sasl_ntlm.hpp` and `detail::same_policy_plan` are no longer installed headers or API.

### Added

- Shared libraries with `BUILD_SHARED_LIBS=ON` (SONAME `.so.0.2`; DLLs on Windows).
- SASL GSSAPI on Windows through SSPI; `JHETZ_LDAP_WITH_GSSAPI` is on by default there.
- `sasl_gssapi(principal, password, options)`: Kerberos credentials from a password.
- `examples/chain.cpp`: a blocking `and_then` chain of connect, bind and search.
- vcpkg ports declare `supports` (Linux and Windows, not MinGW) and follow the triplet's linkage.
- The Conan recipe accepts `shared=True` and passes it to Capy and Corosio.

### Fixed

- Tests and examples are off when coro-ldap is a subproject (FetchContent, `add_subdirectory`).
- Windows: OpenSSL no longer gets a copy of the ROOT store; CryptoAPI alone decides on the system chain.
- Schema: a reported object class is named by a NAME that finds it.

### Changed

- One `tests/` tree: `tests/unit/`, `tests/fuzz/` and `tests/support/`.
- The benchmarks (`bench/`, `JHETZ_LDAP_BUILD_BENCH`) are removed.

## 0.1.0

First release.
