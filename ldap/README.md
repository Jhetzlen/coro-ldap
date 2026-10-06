# jhetz::ldap

C++23 LDAP client library, in progress. Design: [`docs/ldap/DESIGN.md`](../docs/ldap/DESIGN.md).

## What exists

- `jhetz/ldap/error.hpp`: `ldap::error`, `ldap::result<T>` (`std::expected`),
  `ldap::errc` (RFC 4511 result codes, category `ldap.result`) and
  `ldap::client_errc` (category `ldap.client`), and the error conditions
  `ldap::cond` (category `ldap.cond`: `not_found`, `auth_failed`, `timeout`,
  `canceled`, `connection_lost`, `tls_failure`, `protocol_error`,
  `busy_or_unavailable`, `access_denied`, `already_exists`,
  `invalid_input`) that group LDAP, client, system, Capy and TLS codes by
  meaning: `if (r.error().code == ldap::cond::auth_failed)`. The mapping
  table is in DESIGN.md section 5.
- `jhetz/ldap/ber.hpp`: the restricted BER codec LDAP uses (RFC 4511 section 5.1):
  `ber::writer` (its buffer on a `memory_resource`, reusable), `ber::reader`
  (non-owning, depth-bounded, safe on untrusted input) and the framer
  `ber::complete_message_size`.
- `jhetz/ldap/message.hpp`: RFC 4511 `LDAPMessage` as a wire model
  (`ldap::message`, `protocol_op` = every request and response, `control`,
  `ldap_result` with `to_error()`), `encode()` / `decode()`, and the paged
  results control (RFC 2696). Wire strings are `std::pmr::string` holding the
  octets as sent; the search filter is an `ldap::filter` tree; see the header
  for the decoding rules (RFC 4511 section 4 extensibility, range checks).
  `decode(encode(m)) == m` exactly, and re-encoding is byte-identical.
  `decode_options` limits what a peer may send: `from = origin::server`
  (a client connection) rejects request operations, `origin::client` (a
  server) rejects responses, before anything is decoded; plus the reader
  depth and the filter limits; `memory` is the resource everything decoded
  is allocated from. The types have constructors taking the fields in order
  (`message{1, search_request{base, search_scope::whole_subtree, f, {"cn"}}}`);
  they are not aggregates, so designated initializers do not work on them.
- `jhetz/ldap/filter.hpp`: `ldap::filter`, a typed tree (and / or / not,
  equality, substrings, >=, <=, present, approx, extensible match) holding
  unescaped values. Built by the builders in `ldap::filters`
  (`attr("uid") == v && !attr("x").present()`), which make nodes directly
  (never text), or parsed once from RFC 4515 text by `filter::raw(text)`,
  which returns `result<filter>` (malformed text fails there, with
  `invalid_filter`). `encode_filter` writes BER straight from the tree;
  `decode_filter` builds a tree from BER (for a mock server);
  `to_string()` prints canonical RFC 4515 text for logs; `root()` gives a
  read-only view of the nodes. Equality compares trees. `&&`, `||` and `!`
  only add nodes (AND / OR chains are flattened), so combining parsed
  filters cannot change their meaning. Filters nest at most
  `max_filter_depth` (24) levels and have at most `max_filter_elements`
  (10,000) elements (`filter_limits`): `raw` and `decode_filter` check while
  reading, and a builder-made filter beyond them fails with `invalid_filter`
  when encoded. Nodes live in one vector and the strings in one pool (two
  allocations per filter); combining reuses rvalue operands, so a chain
  built in one expression (nested either way) or in a loop as
  `f = std::move(f) || x` is linear (`f = f || x` copies `f` each time), and
  nothing but encoding recurses.
- `jhetz/ldap/dn.hpp`: `ldap::dn` (RFC 4514 parse / `to_string`, multi-valued
  RDNs, `parent()`, `child()`, compile-time checked literals). Syntax only: no
  matching-rule normalization of values.
- `jhetz/ldap/attribute.hpp`: `ldap::attribute`, an attribute description with
  case-insensitive equality, ordering and `std::hash`.
- `jhetz/ldap/entry.hpp`: `ldap::entry`, the untyped search result entry
  (DN text + attributes, case-insensitive `find`); `entry::from` takes the
  strings of a decoded `search_result_entry` and keeps its resource.
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
- `jhetz/ldap/net/connect.hpp`: `co_await net::connect(ioc, url, options, mr)`
  returns `result<net::transport>`: resolves the host, tries each address,
  sets TCP_NODELAY, and for `ldaps://` runs the TLS handshake with
  certificate and host name verification, SNI and TLS 1.2+ by default
  (`tls_options`: CA file / directory (`std::filesystem::path`) / PEM, client
  certificate, `server_name`, and `certificate_verification::insecure_accept_any`
  as the explicit opt-out). TLS configuration (files, certificates, `ca_dir`,
  `server_name`) is checked before any network traffic.
  - Timeout: `std::optional<milliseconds> timeout` (default 30 s) bounds the
    whole connect; `nullopt` means no limit, zero or negative fails at once
    with `capy::error::timeout`. The name lookup runs detached because
    getaddrinfo cannot be interrupted, so the timeout holds while it blocks
    (the io_context stays busy until it returns). With several addresses each
    TCP attempt gets `min(remaining, max(remaining / addresses left, 1 s))`.
  - Host name checks are OpenSSL's defaults, which Corosio does not let us
    change: subjectAltName DNS entries, the subject CN only when there is no
    subjectAltName, wildcards (also partial, `ld*.example.org`) in the
    leftmost label; IP literals against iPAddress entries, without an IPv6
    zone.
  - Errors keep the system / TLS `error_code` and name the stage:
    `connect ldaps://h:636: tls handshake: server certificate: hostname mismatch ...`.
  - `ldapi://` is tested on Linux (should work wherever Corosio has
    `local_stream_socket`).
  - `mr` holds the transport's own block and name.
- `jhetz/ldap/net/message_io.hpp`: `read_message(transport, read_buffer,
  options)` returns the next complete `ldap::message`, decoded with
  `origin::server` by default; bytes of the following PDUs stay in the
  `read_buffer`. A PDU that is not a SEQUENCE or declares more than
  `max_message_size` (16 MiB default) is rejected from its header, before its
  body is read; the buffer grows to one PDU (or 16 KiB) at most. A TLS peer
  closing without close_notify between PDUs reads as a close. After any
  error the connection must be dropped. `read_options::decode.memory` is the
  resource the message is decoded into (e.g. a per-response arena).
  `write_message(t, m, mr)` encodes into a buffer on `mr`;
  `write_message(t, m, writer)` reuses the caller's `ber::writer`;
  `write_bytes` sends raw bytes.

- `jhetz/ldap/connection.hpp` (steps 5a, 5b): `ldap::connection`, the
  client API. `co_await ldap::connect(ioc, url, connection_options, mr)`
  wraps `net::connect` (`connection_options`: connect `timeout`, `tls`,
  `tcp_no_delay`, `max_message_size` (16 MiB by default),
  `operation_timeout`); a connection can also be built on any
  `net::transport` with `connection(ioc, transport, options, mr)`.
  Operations: `simple_bind(dn, password)` (an empty name and password is
  anonymous; a name with an empty password is refused with
  `client_errc::unauthenticated_bind`, RFC 4513 section 5.1.2),
  `search(search_params, mr)` returning `result<std::pmr::vector<entry>>`,
  `search_stream(search_params, mr)` whose `co_await s.next()` yields one
  entry at a time (and keeps the search references and the done controls),
  and `unbind()`. `search_params` is a plain aggregate for designated
  initializers (`.base`, `.scope`, `.filter`, `.attributes`, `.deref`,
  `.size_limit`, `.time_limit`, `.types_only`, `.controls`, `.timeout`).
  Multiplexed: any number of operations may be outstanding (concurrent
  tasks on the connection's executor); one writer sends the PDUs in order
  and one reader, running only while something is outstanding, routes
  each response by message id and decodes it straight into that
  operation's memory resource. Each operation honours its task's stop
  token and its timeout: it then fails with `capy::error::canceled` /
  `timeout` and is abandoned (AbandonRequest; late responses dropped), and
  the connection stays usable; so does a stream destroyed before its end.
  Every response is decoded with `origin::server` and must answer an
  outstanding request (else `client_errc::unexpected_response`);
  IntermediateResponses are skipped; a Notice of Disconnection fails every
  outstanding operation. A server result error fails one operation; a
  transport or protocol error fails all of them once and closes the
  connection, and later operations fail with `client_errc::not_connected`
  naming the first error. The header documents the memory, threading and
  lifetime rules.
  Step 6 adds the other operations: `add`, `modify` (changes from
  `ldap::mod::add / remove / replace / increment`), `del`, `modify_dn`
  (rename and / or move), `compare` (`result<bool>`), `extended` and
  `who_am_i` (RFC 4532), each taking a params aggregate with `.controls`
  and `.timeout`; `search_paged(params, page_size)` follows the Simple
  Paged Results cookie across pages. Referrals are returned (in
  `error::referrals` and `search_stream::references()`), never chased;
  `url::parse_list` parses them.
- `jhetz/ldap/controls.hpp`: typed request controls (`ldap::paged`,
  `manage_dsa_it`, `proxied_authorization`, or a raw `ldap::control`) in a
  `std::variant`, `to_control` / `append_controls` to encode them and
  `find_paged` to read a response's paged results control.
- `jhetz/ldap/mapping.hpp` (#9): typed struct mapping. A descriptor
  (`ldap::schema<T> = ldap::describe(ldap::object_class(...),
  ldap::field<&T::m>("attr", ldap::read_only)...)`) maps members to
  attributes; the member type decides cardinality (`T`,
  `std::optional<T>`, `std::vector<T>`); `value_traits<T>` converts values
  (strings, integers, bool, `dn`, `binary`, `sys_seconds` as
  GeneralizedTime, enums with an `enum_names` table). `decode<T>(entry)`,
  `to_attributes(value)`, typed changes `replace / add / remove<&T::m>(v)`,
  typed filters `filters::field<&T::m>() == v`, and on the connection
  `search_as<T>`, `modify<T>(dn, changes)` and `add(dn, value)`. Mistakes
  (unmapped or read_only member, wrong value type, invalid names) fail to
  compile; `tests/compile/` checks each.
- `net::read_frame` and `peek_message_header` (message.hpp) are the pieces
  the reader uses: wait for one complete PDU without decoding it, then read
  only its message id and operation tag.
- `examples/ldapsearch.cpp` (target `jhetz_ldapsearch`, binary `ldapsearch`,
  option `JHETZ_LDAP_BUILD_EXAMPLES`): connect, optional simple bind,
  search, LDIF output, unbind; `ldapsearch -D dn -w pw URL [filter [attrs]]`.

Memory (DESIGN.md section 8): the public types use `std::pmr` containers
and are allocator-aware: the message model (every operation, `ldap_result`,
`control`, `partial_attribute`, `message`, `paged_results`), `filter`,
`dn` / `rdn` / `ava`, `attribute`, `entry` / `attribute_values`, `url` /
`url_extension` and `ber::writer` have `allocator_type`, `get_allocator()`,
an allocator constructor, allocator-extended copy and move constructors, and
assignment that keeps the target's resource (also for their `std::optional`
and `std::variant` members). Parsing and decoding take the resource:
`decode_options::memory`, `filter::raw(text, mr)`, `decode_filter(r, limits,
mr)`, `dn::parse(text, mr)`, `attribute::parse(text, mr)`,
`url::parse(text, mr)`, `filters::attr(name, alloc)`, `encode(m, mr)`.
`read_buffer`, `connect` and `transport::wrap` take a `memory_resource*` too.
The defaults are the default resource, i.e. the heap, so nothing changes
unless a resource is given.
- Lifetime rule: an object decoded into (or built on) a caller-supplied
  resource, such as a per-response `std::pmr::monotonic_buffer_resource`,
  must not outlive it. A plain copy uses the default resource, so copying out
  is always safe.
- `ldap::error` holds `std::pmr` strings but is not allocator-aware: errors
  are always built on the default resource, never in a caller's arena, even
  when decoding into one fails, because they outlive the operation (they go
  up the call stack and into logs). Errors are the cold path.
- Decoding is tested to allocate only from `decode_options::memory` for every
  sample message (a large entry included), and a builder-made filter plus
  `encode` only from the resource given, with a counting resource and with a
  `monotonic_buffer_resource` over a fixed buffer with a null upstream while
  the default resource is `null_memory_resource()` (`tests/pmr_tests.cpp`).
- `tls_options` is a plain aggregate (configuration, not a hot path).

LDAP resultCode 0 (success) has no `errc` value: success is the absence of
an error; `ldap_result::is_success()` checks for it.

Not yet: StartTLS, SASL, schema validation.

## Build and test

Standalone CMake project (CMake 3.25+, GCC 13+ or Clang 19+). Catch2 v3,
and for `jhetz::ldap_net` Corosio and Capy, are fetched from GitHub;
`jhetz::ldap_net` also needs the OpenSSL development files (`libssl-dev`).

```sh
cmake -S ldap -B build/ldap -G Ninja -DCMAKE_BUILD_TYPE=Debug -DJHETZ_LDAP_SANITIZE=ON
cmake --build build/ldap
ctest --test-dir build/ldap --output-on-failure
ctest --test-dir build/ldap -R '^net\.'     # just the transport / connect / connection tests
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
| `JHETZ_LDAP_BUILD_BENCH` | `OFF` | `jhetz_ldap_decode_bench` (see below; not run by ctest or CI) |

## Fuzz

| Target | Input | Properties |
|---|---|---|
| `ber_fuzz` | bytes | framer and reader agree; every element walks; values re-encode consistently |
| `message_fuzz` | bytes | a message that decodes encodes, decodes to an equal message (exactly) and re-encodes to the same bytes; decoding into a `monotonic_buffer_resource` (with `null_memory_resource()` as the default resource meanwhile) gives an equal message, and a copy taken before the arena is released stays valid (ASan); filter text in a search request round-trips exactly |
| `filter_fuzz` | text / bytes | `filter::raw` text -> BER -> equal tree -> same BER, and `to_string` -> `raw` -> equal tree (a fixed point); every builder's text parses back to its tree (escaping) and `attr("cn") == v` carries `v` exactly; decodable BER filters round-trip; `!f` holds exactly `f`'s BER |
| `dn_fuzz` | text | `parse(to_string(d)) == d`; the literal validator agrees with `parse` |
| `url_fuzz` | text | `parse(to_string(u)) == u` and `to_string` is canonical; printed URLs contain only RFC 3986 characters |

```sh
cmake -S ldap -B build/ldap-fuzz -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo \
      -DCMAKE_CXX_COMPILER=clang++ -DJHETZ_LDAP_BUILD_FUZZERS=ON -DJHETZ_LDAP_BUILD_TESTS=OFF
cmake --build build/ldap-fuzz
mkdir -p corpus && cp ldap/fuzz/corpus/message_fuzz/* corpus/
UBSAN_OPTIONS=halt_on_error=1 build/ldap-fuzz/fuzzers/message_fuzz -max_total_time=60 corpus
# url_fuzz has a dictionary: add -dict=ldap/fuzz/url.dict
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

## Benchmark

`bench/decode_bench.cpp` (option `JHETZ_LDAP_BUILD_BENCH`) decodes a stream
of 1,000 SearchResultEntry PDUs, 30 attributes x 3 values (10-60 bytes) each,
plus a 64 KiB `jpegPhoto` and a 4 KiB `userCertificate` in every 20th entry
(7.1 MiB, 90,100 values), with the default resource and with one
`monotonic_buffer_resource` `release()`d after each message, with and
without a 256 KiB initial buffer. Heap allocations are counted with a
counting default resource in a separate pass.

```sh
cmake -S ldap -B build/ldap-bench -G Ninja -DCMAKE_BUILD_TYPE=Release \
      -DJHETZ_LDAP_BUILD_BENCH=ON -DJHETZ_LDAP_BUILD_TESTS=OFF -DJHETZ_LDAP_BUILD_NET=OFF
cmake --build build/ldap-bench && build/ldap-bench/jhetz_ldap_decode_bench
```

GCC 13.3, Release (`-O3`), one core of a shared 4-core VM, best / median of
15 runs (three invocations agreed within 2%):

| Mode | Best | Median | Heap allocations | per entry | Heap MiB |
|---|---:|---:|---:|---:|---:|
| default resource (heap) | 14.8 ms | 15.1 ms | 111,662 | 111.7 | 11.8 |
| monotonic arena, 256 KiB buffer, `release()` | 10.7 ms | 10.9 ms | 0 | 0 | 0 |
| monotonic arena, no buffer, `release()` | 11.1 ms | 11.3 ms | 5,100 | 5.1 | 17.4 |

A reused arena with a buffer that holds a typical response removes every
heap allocation and saves about 28% of the decode time here; without a
buffer, `release()` hands the chunks back and each message fetches them
again (about 5 per entry, larger ones for the photos). Decoding reserves the
attribute and value vectors exactly (counting the elements first), which
took the heap mode from 177 to 112 allocations per entry and the arena
without buffer from 24.6 to 17.4 MiB, at the price of reading the element
headers twice (the arena modes were about 1 ms faster without it).
For reference, the step 4 decoder (`std::string` / `std::vector`, before
this change) took 13.6 ms for the same stream (ported benchmark, heap only):
the default-resource path is now about 9% slower (the virtual
`memory_resource` calls and the counting pass), the arena paths about 20%
faster.

## Golden vectors

`tests/message_golden_tests.cpp` compares the codec with encodings produced
by an independent implementation (ldap3 2.9.1 / pyasn1 0.6.4); the generating
script is in the file.
