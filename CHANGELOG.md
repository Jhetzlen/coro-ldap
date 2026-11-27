# Changelog

The version comes from `project(jhetz_ldap VERSION ...)` in `CMakeLists.txt`.
While it is 0.x, a minor version may break the API, and the installed
package matches only the same minor version (`find_package(jhetz_ldap 0.3)`,
`SameMinorVersion`).

## Unreleased

## 0.3.0 (2026-11-27)

### Breaking

- RFC 4511/4512 names for attributes: `attribute_values` is now `ldap::attribute` (a description with its values; `entry::attributes` is a vector of them), and the name-only `attribute` is now `ldap::attribute_description`. `attribute::name()` is the type without options (`"cn"` for `"cn;lang-de"`); the whole description is `text()`.
- Referrals: `referral_policy` -> `referral_limits`, `max_attempts` -> `max_listed_attempts`, `skipped_policy` -> `refused`, `referral_target()` -> `referred_request()`, `referral_binding` -> `referral_access`, `allowed_host_suffixes` -> `allowed_domains`; search and compare results' `referrals` / `unlisted` -> `referral_attempts` / `unlisted_attempts`.
- `response` (add, modify, delete, modify DN) -> `update_result`.
- `filter::raw()` -> `filter::parse()`.
- `ldap::schema<T>` (the struct mapping) -> `ldap::mapping<T>`.
- `compare_result::value` -> `matched`.
- `object_class_type` -> `object_class_description` (RFC 4512).
- Counts: `connections()` -> `connection_count()`, `outstanding()` -> `outstanding_count()`, `pages()` -> `page_count()`.
- `client_options::idle_check` -> `probe_idle_after`.
- Connection and transport `name()` -> `endpoint()`.

### Added

- `tls_options::cert_pem` and `key_pem`: the TLS client certificate (then its chain) and its unencrypted key as PEM text, instead of `cert_file` and `key_file`.

### Fixed

- Windows DLLs: `on_strand()` recognises the connection's strand when the caller is in another module, so a stopped bind is no longer sent.
- Referrals: an anonymous chase drops the PEM client certificate too.

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
