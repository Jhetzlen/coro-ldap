# jhetz::ldap

C++23 LDAP client library, in progress. Design: [`docs/ldap/DESIGN.md`](../docs/ldap/DESIGN.md).

## What exists

- `jhetz/ldap/error.hpp`: `ldap::error`, `ldap::result<T>` (`std::expected`),
  `ldap::errc` (RFC 4511 result codes, category `ldap.result`) and
  `ldap::client_errc` (category `ldap.client`).
- `jhetz/ldap/ber.hpp`: the restricted BER codec LDAP uses (RFC 4511 section 5.1):
  `ber::writer`, `ber::reader` (non-owning, depth-bounded, safe on untrusted
  input) and the framer `ber::complete_message_size`.
- `jhetz/ldap/message.hpp`: RFC 4511 `LDAPMessage` as a wire model
  (`ldap::message`, `protocol_op` = every request and response, `control`,
  `ldap_result` with `to_error()`), `encode()` / `decode()`, and the paged
  results control (RFC 2696). Wire strings stay `std::string`; see the header
  for the decoding rules (RFC 4511 section 4 extensibility, range checks).
  `decode_options` limits what a peer may send: `from = origin::server`
  (a client connection) rejects request operations, `origin::client` (a
  server) rejects responses, before anything is decoded; plus the reader
  depth and the filter limits.
- `jhetz/ldap/filter.hpp`: `ldap::filter` (RFC 4515 text), escaping builders in
  `ldap::filters` (`attr("uid") == v && !attr("x").present()`), the RFC 4515
  parser to BER (`encode_filter`) and BER back to canonical text
  (`decode_filter`). Filters nest at most `max_filter_depth` (24) levels and
  have at most `max_filter_elements` (10,000) elements, both configurable
  with `filter_limits`. `&&`, `||` and `!` wrap a `filter::raw` operand that
  is not one parenthesized group, and mark it invalid if wrapping does not
  make it one, so malformed raw text never turns into a different valid
  filter.
- `jhetz/ldap/dn.hpp`: `ldap::dn` (RFC 4514 parse / `to_string`, multi-valued
  RDNs, `parent()`, `child()`, compile-time checked literals). Syntax only: no
  matching-rule normalization of values.
- `jhetz/ldap/attribute.hpp`: `ldap::attribute`, an attribute description with
  case-insensitive equality, ordering and `std::hash`.
- `jhetz/ldap/entry.hpp`: `ldap::entry`, the untyped search result entry
  (DN text + attributes, case-insensitive `find`).
- `jhetz/ldap/url.hpp`: `ldap::url`, RFC 4516 LDAP URLs (`ldap://`,
  `ldaps://`, `ldapi://` with a percent-encoded socket path): host (name,
  IPv4, bracketed IPv6 with optional zone), port (explicit or scheme
  default), DN, attributes, scope, filter and extensions (with the critical
  `!` marker), all percent-decoded; `parse()` / `to_string()` round-trip.
  Absent and empty DN / scope / filter stay distinct, as referrals need.
  Allocator-aware (`std::pmr`, see below).

### `jhetz::ldap_net`: transports and connecting

A second library (target `jhetz::ldap_net`, option `JHETZ_LDAP_BUILD_NET`,
on by default) with the network parts. It depends on Corosio and Capy
(fetched with FetchContent at the same pinned commits as
`examples/corosio/`) and OpenSSL; `jhetz::ldap` itself stays dependency-free.

- `jhetz/ldap/net/transport.hpp`: `net::transport`, the one byte stream a
  connection uses: plain TCP (`ldap://`), TLS over TCP (`ldaps://`), a Unix
  domain socket (`ldapi://`), or any `capy::Stream` (`transport::wrap`, used by
  the tests with Capy's mock streams). Reads and writes go through a
  `capy::any_stream`. The TCP socket is owned separately from the TLS layer,
  which wraps it in reference mode, so StartTLS (step 7) can later add TLS to
  a plain connection in place; the header describes how.
- `jhetz/ldap/net/connect.hpp`: `co_await net::connect(ioc, url, options)`
  returns `result<net::transport>`: resolves the host, tries each address,
  sets TCP_NODELAY, and for `ldaps://` runs the TLS handshake with
  certificate and host name verification, SNI and TLS 1.2+ by default
  (`tls_options`: CA file / directory / PEM, client certificate, `server_name`,
  and `certificate_verification::insecure_accept_any` as the explicit
  opt-out). One `timeout` (default 30 s) bounds the whole connect. Errors keep
  the system / TLS `error_code` and name the stage:
  `connect ldaps://h:636: tls handshake: server certificate: hostname mismatch ...`.
  `ldapi://` is tested on Linux (should work wherever Corosio has
  `local_stream_socket`).
- `jhetz/ldap/net/message_io.hpp`: `read_message(transport, read_buffer,
  options)` returns the next complete `ldap::message`, decoded with
  `origin::server` by default; bytes of the following PDUs stay in the
  `read_buffer`. A PDU that is not a SEQUENCE or declares more than
  `max_message_size` (16 MiB default) is rejected from its header, before its
  body is read; the buffer grows to one PDU (or 16 KiB) at most.
  `write_message` / `write_bytes` send.

Memory: new public types use `std::pmr` containers (DESIGN.md section 8):
`url` is allocator-aware (`url::parse(text, &resource)`, allocator-extended
copies) and `read_buffer` takes a `memory_resource*`; the defaults use the
default resource, i.e. the heap. The step 3 types (message, filter, dn,
attribute, entry, error) are converted in step 4b.

LDAP resultCode 0 (success) has no `errc` value: success is the absence of
an error; `ldap_result::is_success()` checks for it.

No LDAP operations over the network yet (bind, search: step 5). The
`ldap::cond` error conditions from DESIGN.md section 5 are deferred.

## Build and test

Standalone CMake project (CMake 3.25+, GCC 13+ or Clang 19+). Catch2 v3,
and for `jhetz::ldap_net` Corosio and Capy, are fetched from GitHub;
`jhetz::ldap_net` also needs the OpenSSL development files (`libssl-dev`).

```sh
cmake -S ldap -B build/ldap -G Ninja -DCMAKE_BUILD_TYPE=Debug -DJHETZ_LDAP_SANITIZE=ON
cmake --build build/ldap
ctest --test-dir build/ldap --output-on-failure
ctest --test-dir build/ldap -R '^net\.'     # just the transport / connect tests
```

To build against local checkouts instead of downloading, pass
`-DFETCHCONTENT_SOURCE_DIR_CAPY=/path/to/capy -DFETCHCONTENT_SOURCE_DIR_COROSIO=/path/to/corosio`.

The `net.*` tests need no LDAP server and no fixed ports: they run TCP, TLS
and Unix socket servers in-process on loopback, with a throwaway CA and
certificates generated at run time through the OpenSSL API.

| Option | Default | |
|---|---|---|
| `JHETZ_LDAP_BUILD_TESTS` | `ON` | unit tests and the `*_fuzz_replay` tests |
| `JHETZ_LDAP_BUILD_NET` | `ON` (`OFF` with fuzzers) | `jhetz::ldap_net` and its tests; fetches Corosio + Capy, needs OpenSSL |
| `JHETZ_LDAP_BUILD_FUZZERS` | `OFF` | libFuzzer targets (Clang only) |
| `JHETZ_LDAP_SANITIZE` | `OFF` | ASan + UBSan on every target |
| `JHETZ_LDAP_WERROR` | `OFF` | warnings are errors in our code (CI turns it on) |

## Fuzz

| Target | Input | Properties |
|---|---|---|
| `ber_fuzz` | bytes | framer and reader agree; every element walks; values re-encode consistently |
| `message_fuzz` | bytes | a message that decodes encodes, decodes to an equal message and re-encodes to the same bytes |
| `filter_fuzz` | text / bytes | filter text -> BER -> text -> identical BER; every builder output parses and `attr("cn") == v` carries `v` exactly; decodable BER filters round-trip |
| `dn_fuzz` | text | `parse(to_string(d)) == d`; the literal validator agrees with `parse` |
| `url_fuzz` | text | `parse(to_string(u)) == u` and `to_string` is canonical; printed URLs contain only RFC 3986 characters |

```sh
cmake -S ldap -B build/ldap-fuzz -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo \
      -DCMAKE_CXX_COMPILER=clang++ -DJHETZ_LDAP_BUILD_FUZZERS=ON -DJHETZ_LDAP_BUILD_TESTS=OFF
cmake --build build/ldap-fuzz
mkdir -p corpus && cp ldap/fuzz/corpus/message_fuzz/* corpus/
UBSAN_OPTIONS=halt_on_error=1 build/ldap-fuzz/fuzzers/message_fuzz -max_total_time=60 corpus
```

`fuzz/corpus/<target>/` holds the seed inputs (the same ones
`<target>_replay` mutates). Regenerate them after changing the seeds with
`<target>_replay --write-seeds ldap/fuzz/corpus/<target>`.

Sanitized and fuzz builds use `-fno-sanitize-recover=all`, so any UBSan
finding aborts and fails the test or fuzz run.

With Clang 18 and libstdc++ 13 the build adds
`-D__cpp_concepts=202002L -Wno-builtin-macro-redefined`, otherwise
`<expected>` is unavailable. It is a PUBLIC option of `jhetz_ldap`, so it
reaches our libraries, tests and fuzzers (everything that includes our
headers) but not the Corosio, Capy and Catch2 sources, which do not need it;
a Clang 18 build with `JHETZ_LDAP_BUILD_NET=ON` compiles and passes the tests.
A fuzz build leaves `JHETZ_LDAP_BUILD_NET` off by default: the fuzzers only
cover the codec and URLs.

Without libFuzzer, the `<target>_replay` tests (part of `ctest`) run the same
entry points on deterministic generated and mutated inputs (about 300,000 for
`ber_fuzz`, 200,000 for `message_fuzz` and `url_fuzz`, 150,000 for `dn_fuzz`
and 45,000 for the slower `filter_fuzz`).

## Golden vectors

`tests/message_golden_tests.cpp` compares the codec with encodings produced
by an independent implementation (ldap3 2.9.1 / pyasn1 0.6.4); the generating
script is in the file.
