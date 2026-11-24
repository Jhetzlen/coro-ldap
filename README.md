# coro-ldap

[![ldap](https://github.com/Jhetzlen/coro-ldap/actions/workflows/ci.yml/badge.svg)](https://github.com/Jhetzlen/coro-ldap/actions/workflows/ci.yml)

An asynchronous LDAP client library for C++23, built on coroutines over
[Corosio](https://github.com/cppalliance/corosio) and
[Capy](https://github.com/cppalliance/capy), with a blocking facade for code
that is not coroutine-based. It covers TLS, StartTLS and `ldapi://`, SASL
EXTERNAL, SCRAM-SHA-256 and optionally GSSAPI, a connection pool, typed
entry mapping, and full UTF-8 with RFC 4518 matching.

Status: pre-1.0, the API may still change. Linux is the tested platform;
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
- A codec library (`jhetz::ldap`: BER, messages, DN, filter, URL) whose only dependency is ICU

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
	auto conn = ldap::sync::connect("ldap://localhost", { .start_tls = true });
	if (!conn || !conn->simple_bind(ldap::dn{ "cn=admin,dc=example,dc=org" }, "secret")) return 1;
	auto people = conn->search({
	  .base = ldap::dn{ "ou=people,dc=example,dc=org" },
	  .filter = ldap::filters::attr("uid").starts_with("user00"),
	  .attributes = { "cn" },
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
- ICU 60+ development files
- OpenSSL, for `jhetz::ldap_net`
- MIT krb5 (`libgssapi_krb5`, via pkg-config), only with `-DJHETZ_LDAP_WITH_GSSAPI=ON`

Capy, Corosio and Catch2 are fetched by CMake. Debian: `apt install libicu-dev libssl-dev`.

## Build and use

```sh
cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build
ctest --test-dir build
```

From your project, with FetchContent (or `add_subdirectory`):

```cmake
include(FetchContent)
FetchContent_Declare(coro_ldap GIT_REPOSITORY https://github.com/Jhetzlen/coro-ldap.git GIT_TAG main)
FetchContent_MakeAvailable(coro_ldap)
target_link_libraries(app PRIVATE jhetz::ldap_net)   # jhetz::ldap: the codec only
```

Or, after `cmake --install` (the `net` component needs Capy and Corosio installed too):

```cmake
find_package(jhetz_ldap 0.1 REQUIRED COMPONENTS net)
target_link_libraries(app PRIVATE jhetz::ldap_net)
```

vcpkg and Conan packages are planned.

## Documentation

- [`docs/API.md`](docs/API.md): what each header provides
- [`docs/DESIGN.md`](docs/DESIGN.md): design notes and rationale
- [`docs/DEVELOPMENT.md`](docs/DEVELOPMENT.md): build options, Windows, integration tests, fuzzing
- [`examples/`](examples/): one small program per task

## License

Boost Software License 1.0, see [`LICENSE`](LICENSE).
