# coro-ldap

[![linux](https://img.shields.io/github/actions/workflow/status/Jhetzlen/coro-ldap/ci.yml?branch=main&label=linux)](https://github.com/Jhetzlen/coro-ldap/actions/workflows/ci.yml)
[![linux tests](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/Jhetzlen/coro-ldap/badges/tests-linux.json)](https://github.com/Jhetzlen/coro-ldap/actions/workflows/ci.yml)
[![windows](https://img.shields.io/github/actions/workflow/status/Jhetzlen/coro-ldap/windows.yml?branch=main&label=windows)](https://github.com/Jhetzlen/coro-ldap/actions/workflows/windows.yml)
[![windows tests](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/Jhetzlen/coro-ldap/badges/tests-windows.json)](https://github.com/Jhetzlen/coro-ldap/actions/workflows/windows.yml)
[![coverage](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/Jhetzlen/coro-ldap/badges/coverage.json)](https://github.com/Jhetzlen/coro-ldap/actions/workflows/ci.yml)

An asynchronous LDAP client library for C++23, built on coroutines over
[Corosio](https://github.com/cppalliance/corosio) and
[Capy](https://github.com/cppalliance/capy), with a blocking facade for code
that is not coroutine-based. It covers TLS, StartTLS and `ldapi://`, SASL
EXTERNAL, SCRAM-SHA-256 and optionally GSSAPI, a connection pool, typed
entry mapping, and full UTF-8 with RFC 4518 matching.

Windows (MSVC) builds and passes the unit tests in CI; macOS is not supported.
Windows is ported but unverified; macOS is not supported.

## Features

- Many concurrent operations on one connection, each cancellable or timed out on its own
- `ldap://`, `ldaps://`, StartTLS and `ldapi://`, with certificate verification on by default
- Simple bind and SASL EXTERNAL, SCRAM-SHA-256(-PLUS) and GSSAPI (optional)
- Search (all at once, streamed or paged), add, modify, delete, rename, compare, extended operations
- A connection pool (`ldap::client`) with failover, plus opt-in referral chasing
- Typed filters, compile-time-checked DN literals, and entries mapped to your structs (`repository<T>`)
- Controls, transactions (RFC 5805) and syncrepl (RFC 4533)
- UTF-8 everywhere, with server-like matching rules (RFC 4517, RFC 4518 string preparation)
- Errors as values: every operation returns `ldap::result<T>` (a `std::expected`)
- A codec part (BER, messages, DN, filter, URL) usable on its own, whose only dependency is ICU

## Example

Asynchronous, on a Corosio `io_context`:

```cpp
#include "jhetz/ldap/connection.hpp"

#include <iostream>

namespace ldap = jhetz::ldap;

auto search(boost::corosio::io_context &ioc, std::string url) -> boost::capy::task<int>
{
	auto c = co_await ldap::connect(ioc, url, { .start_tls = true });
	if (!c || !co_await c->simple_bind(ldap::dn{ "cn=admin,dc=example,dc=org" }, "secret")) co_return 1;
	auto people = co_await c->search({
	  .base = ldap::dn{ "ou=people,dc=example,dc=org" },
	  .filter = ldap::filters::attr("uid").starts_with("user00"),
	  .attributes = { "cn" },
	});
	if (!people) co_return 1;
	for (const ldap::entry &person : people->entries) std::cout << person.dn << '\n';
	co_return 0;
}

auto main() -> int { return ldap::run(search, "ldap://localhost"); }
```

Blocking, with `ldap::sync::connection`:

```cpp
#include "jhetz/ldap/sync.hpp"

#include <iostream>

namespace ldap = jhetz::ldap;

auto main() -> int
{
	auto people = ldap::sync::connect("ldap://localhost", { .start_tls = true })
	  .and_then([](ldap::sync::connection c) {
		  return c.simple_bind(ldap::dn{ "cn=admin,dc=example,dc=org" }, "secret");
	  })
	  .and_then([](ldap::sync::connection c) {
		  return c.search({
			.base = ldap::dn{ "ou=people,dc=example,dc=org" },
			.filter = ldap::filters::attr("uid").starts_with("user00"),
			.attributes = { "cn" },
		  });
	  });
	if (!people) return 1;
	for (const ldap::entry &person : people->entries) std::cout << person.dn << '\n';
}
```

Real error handling (`error().message()`, `is_complete()` for partial
results) is in [`examples/`](examples/), one small program per task.

## Requirements

- CMake 3.25+
- GCC 16+, or Clang 23+ with libstdc++ 16+ (MSVC 19.40+ / clang-cl on Windows)

| Dependency | Why | How |
|---|---|---|
| [Corosio](https://github.com/cppalliance/corosio) | Async sockets, timers, DNS, and the `io_context` the client runs on | fetched by CMake |
| [Capy](https://github.com/cppalliance/capy) | The coroutine `task` type, executors and strands | fetched by CMake |
| OpenSSL | TLS for `ldaps://` and StartTLS (through Corosio), and the hashing for SASL SCRAM and NTLM | install it |
| ICU 60+ | UTF-8 handling and Unicode string preparation (RFC 4518, SASLprep) | install it |
| GSS-API from the OS: MIT krb5 or Heimdal (optional); SSPI on Windows | SASL GSSAPI / Kerberos, with `-DJHETZ_LDAP_WITH_GSSAPI=ON` (pkg-config `krb5-gssapi` or `heimdal-gssapi`); on Windows SSPI (`secur32`), on by default | install it; Windows: built in |
| Catch2 | Tests only | fetched by CMake |

Debian: `apt install libicu-dev libssl-dev`, plus `libkrb5-dev pkg-config` for
GSSAPI (Fedora `krb5-devel`, Arch `krb5`). The vcpkg `gssapi` feature and the
Conan `gssapi` option use that system library too. On Windows GSSAPI is
SSPI's Kerberos, part of the OS, and binds as the logged-on user by
default.

## Build and use

```sh
cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build
ctest --test-dir build
```

Link the CMake target `jhetz::ldap` for the client (connections, TLS, SASL,
the sync API). `jhetz::ldap_core` alone is the codec (BER, DN, filters) with no
networking, and `jhetz::ldap_ad` adds the Active Directory operations. These
are CMake target names only: the C++ namespace is `jhetz::ldap` in every case
(with `ldap::sync`, `ldap::ad` and `ldap::net`).

Static and shared libraries are both supported: static by default,
shared (DLLs on Windows) with `-DBUILD_SHARED_LIBS=ON`, a dynamic vcpkg
triplet or Conan's `shared=True`. Capy and Corosio must have the same
linkage, which the build and the packages see to.

## Install

**vcpkg**, with this repository as a git registry: next to your `vcpkg.json`
(`"dependencies": ["jhetz-ldap"]`; feature `gssapi`, or
`{"name": "jhetz-ldap", "default-features": false}` for the codec alone), a
`vcpkg-configuration.json`:

```json
{
  "default-registry": { "kind": "git", "repository": "https://github.com/microsoft/vcpkg",
                        "baseline": "432d982fb917e1d9b032197b01572b83bcb02a75" },
  "registries": [ { "kind": "git", "repository": "https://github.com/Jhetzlen/coro-ldap",
                    "baseline": "c2e04287c17ed4da38029553d147aae192df2812",
                    "packages": [ "jhetz-ldap", "capy", "corosio" ] } ]
}
```

**Conan 2**, with a clone of this repository as a local recipes index
(options `net`, `gssapi`):

```sh
git clone https://github.com/Jhetzlen/coro-ldap
conan remote add coro-ldap ./coro-ldap/packaging/conan --type=local-recipes-index
```

and `jhetz-ldap/0.2.0` under `[requires]` in your `conanfile.txt` (with the
`CMakeDeps` and `CMakeToolchain` generators). Both give the CMake package:

```cmake
find_package(jhetz_ldap 0.2 REQUIRED)
target_link_libraries(app PRIVATE jhetz::ldap)  # or jhetz::ldap_core, jhetz::ldap_ad
```

**CMake FetchContent** (or `add_subdirectory`), which fetches Capy and Corosio:

```cmake
include(FetchContent)
FetchContent_Declare(coro_ldap GIT_REPOSITORY https://github.com/Jhetzlen/coro-ldap.git GIT_TAG v0.2.0)
FetchContent_MakeAvailable(coro_ldap)
target_link_libraries(app PRIVATE jhetz::ldap)
```

## Documentation

- [`docs/API.md`](docs/API.md): what each header provides
- [`docs/DESIGN.md`](docs/DESIGN.md): design notes and rationale
- [`docs/DEVELOPMENT.md`](docs/DEVELOPMENT.md): build options, Windows, integration tests, fuzzing
- [`examples/`](examples/): one small program per task

## License

Boost Software License 1.0, see [`LICENSE`](LICENSE).
