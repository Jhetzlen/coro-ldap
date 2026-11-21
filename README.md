# coro-ldap

A modern C++23 LDAP client library built on coroutines.

> **Requirement: Corosio's `io_context`.** The asynchronous API
> (`ldap::connect`, `ldap::connection`, `ldap::client`, `net::connect`)
> runs on a `boost::corosio::io_context` and its executor. It does not run
> on Boost.Asio's or standalone Asio's `io_context`, nor on another
> executor; a custom byte stream can be plugged in (any Capy stream, through
> `net::transport::wrap`), but the connection still runs on a Corosio
> `io_context`. Code without Corosio can use the blocking facades
> (`ldap::sync::connection`, `ldap::sync::client`), which own their
> `io_context` and I/O thread, or the codec library alone (`jhetz::ldap`:
> BER, messages, DN, filter, URL), which has no networking dependency.

## Goal

coro-ldap aims to be the LDAP client you would want to use from modern C++:

- **Asynchronous.** Operations are coroutines on
  [Corosio](https://github.com/cppalliance/corosio) /
  [Capy](https://github.com/cppalliance/capy). One connection carries any
  number of concurrent operations, and each one can be cancelled or timed
  out without dropping the connection. Blocking facades
  (`ldap::sync::connection`, and `ldap::sync::client` for the pool)
  cover code that is not coroutine-based.
- **Type-safe.** Filters are built as typed trees (`attr("uid") == v`), not
  pasted strings, DN literals are checked at compile time, and entries map
  to your own structs. Many mistakes fail to compile.
- **Secure by default.** TLS certificate and host name verification are on,
  passwords never appear in errors, and every input from the server is
  bounded and decoded defensively (the codec is fuzzed).
- **Unicode-correct.** UTF-8 everywhere: DNs, filters, values, SASL user
  names and passwords (SASLprep through ICU), and server-like value and DN
  comparison (LDAPprep, RFC 4518).
- **Errors as values.** Every operation returns `ldap::result<T>`, a
  `std::expected` with the error and a readable context, and error
  conditions group causes by meaning (`ldap::cond::auth_failed`, `timeout`,
  ...).

## Features

- `ldap://`, `ldaps://`, StartTLS and `ldapi://` (Unix sockets), with Happy
  Eyeballs connection racing
- Simple bind and SASL EXTERNAL, SCRAM-SHA-256, SCRAM-SHA-256-PLUS (TLS
  channel binding: tls-exporter, tls-server-end-point) and GSSAPI
  (Kerberos, optional; tls-server-end-point channel binding over TLS, for
  Active Directory's LDAP channel binding policy); the server's TLS
  certificate is available
- Search (all at once, streamed or paged), add, modify, delete, modify DN
  (rename / move), compare, extended operations, Who am I?, and RFC 3062
  Password Modify with password change / reset conveniences; Active
  Directory's unicodePwd change / reset in the separate ldap::ad layer
- Opt-in referral chasing for search and compare: continuation references
  and referral results followed through a connector you control (host
  allow-list, no TLS downgrade, your own bind), with loop detection, hop
  limits and a per-URL report; partial results are flagged, never a plain
  success
- A connection pool, `ldap::client`: several servers with failover and
  jittered backoff, connections opened lazily and shared by leases (one
  multiplexed connection by default) or held exclusively, a bind (or any
  setup) replayed on every new connection, an idle check, observer
  hooks, and opt-in referral chasing for its reads (an authorize callback
  decides which servers get which binding)
- Transactions (RFC 5805): group updates so they apply all together or not
  at all, with `ldap::transaction` (commit, abort, aborted on destruction)
- Controls: paged results, server-side sort, virtual list view,
  assertion, pre-/post-read, matched values, proxied authorization,
  ManageDsaIT, Relax Rules, transaction specification, each accepted only on the operations its RFC
  allows (pre-read on an add does not compile)
- Content synchronization (RFC 4533, "syncrepl"): follow a directory's
  changes with refreshOnly or refreshAndPersist and resume from a cookie
- Struct mapping, runtime schema validation, Active Directory time types
- Matching rules as a server applies them (RFC 4517 with RFC 4518 string
  preparation: case folding, NFKC, insignificant spaces): caseIgnoreMatch,
  caseExactMatch and the other string, integer and octet rules,
  objectIdentifierMatch, uniqueMemberMatch, generalizedTimeMatch,
  caseIgnoreListMatch, uuidMatch (RFC 4530), and DN
  comparison by each attribute's equality rule from the server schema
  (`ldap::dn`'s own `==` stays exact)
- `std::pmr` allocators throughout, so a response can be decoded into an
  arena
- A codec library (BER, messages, DN, filter, URL, matching rules) usable on
  its own; its only dependency is ICU

Linux is the tested platform. Windows (MSVC, clang-cl, MinGW-w64) is ported
in the code but not yet built or tested by us; see
[docs/DEVELOPMENT.md](docs/DEVELOPMENT.md#windows) for its status, a vcpkg
recipe and what stays Linux only. macOS is not supported.

## Example

```cpp
#include "jhetz/ldap/connection.hpp"

#include <boost/corosio/io_context.hpp>

#include <iostream>

namespace ldap = jhetz::ldap;

auto search(boost::corosio::io_context &ioc) -> boost::capy::task<int>
{
	auto c = co_await ldap::connect(ioc, "ldap://localhost", { .start_tls = true });
	if (!c) {
		std::cerr << c.error().message() << '\n';
		co_return 1;
	}
	auto bound = co_await c->simple_bind(ldap::dn{ "cn=admin,dc=example,dc=org" }, "secret");
	if (!bound) {
		std::cerr << bound.error().message() << '\n';
		co_return 1;
	}
	auto people = co_await c->search({
	  .base = ldap::dn{ "ou=people,dc=example,dc=org" },
	  .filter = ldap::filters::attr("uid").starts_with("user00"),
	  .attributes = { "cn" },
	});
	if (!people) {
		std::cerr << people.error().message() << '\n';
		co_return 1;
	}
	if (!people->is_complete()) {
		std::cerr << "the result is partial: result code " << people->result_code << '\n';
	}
	for (const ldap::entry &person : people->entries) {
		std::cout << person.dn << ": " << person.find("cn")->front() << '\n';
	}
	co_return 0;
}

auto main() -> int
{
	return ldap::run(search);
}
```

A search that hits a server limit (sizeLimitExceeded, timeLimitExceeded, adminLimitExceeded) still
succeeds with the entries received so far, so `is_complete()` tells a partial answer apart; Active
Directory's default limit of 1000 entries is the common case, and `ldap::search_paged` gets past it.

More in [`examples/`](examples/): one small program per task (connect,
search, add, modify, delete, transactions, password reset, StartTLS, cancellation, paged
search, following referrals, following changes with syncrepl, the blocking API, Kerberos), and `ldapsearch.cpp`, a small
command-line tool.

## Build

Requirements: CMake 3.25+, GCC 16+ or Clang 23+ with libstdc++ 16+, the ICU
60+ development files, and for the network library OpenSSL's (Debian:
`libicu-dev libssl-dev`, Arch: `icu openssl`). Catch2, Corosio and Capy are
fetched by CMake. On Windows: MSVC 19.40+ (or clang-cl) with ICU and
OpenSSL from vcpkg ([recipe](docs/DEVELOPMENT.md#build-with-vcpkg)).

```sh
cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build
ctest --test-dir build
```

## Use it from CMake

```cmake
find_package(jhetz_ldap 0.1 REQUIRED COMPONENTS net)
target_link_libraries(app PRIVATE jhetz::ldap_net)   # jhetz::ldap: codec only
```

or add it with `add_subdirectory` / FetchContent and link the same targets.

## Documentation

- [`docs/API.md`](docs/API.md): what each header provides, in detail
- [`docs/DESIGN.md`](docs/DESIGN.md): design notes and rationale
- [`docs/DEVELOPMENT.md`](docs/DEVELOPMENT.md): build options, Windows,
  installing, integration tests against slapd, coverage, fuzzing, benchmark
