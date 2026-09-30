# LDAP client: API design

Status: steps 1–4b implemented under `ldap/` (errors, BER codec, message model,
typed filters, DN/attribute/entry, URLs, transports and connect, `std::pmr`
throughout). Sections 3–7 describe the API still to be built;
"Implemented" notes say where the code differs from the original plan.
Remaining work is tracked as GitHub issues, indexed in `ROADMAP.md`.
`api_prototype.cpp` next to this file checks that the type-safety parts of
section 4 compile as C++23 (GCC 13).

## Goals

- **Type safety.** LDAP concepts have their own types; entries map to user
  structs; misspelled attributes and unmapped members are compile errors.
- **Pass data around safely.** Public types own their data, are regular
  (copyable, movable, comparable), and can cross threads.
- **Modern API.** Coroutines (Corosio/Capy), designated-initializer requests,
  `std::expected` results, no exceptions for expected failures.

## Decisions

| # | Topic | Decision |
|---|-------|----------|
| 1 | Struct ↔ entry mapping | Hand-written `constexpr` descriptor now; C++26 reflection later on a separate branch, same user-facing API |
| 2 | Errors | Rich `ldap::error` struct inside `std::expected` |
| 3 | Schema checking | Both compile-time (descriptor) and optional runtime validation against the server schema |
| 4 | Sync API | Async core; thin blocking facade in its own header (see below) |
| 5 | Language | C++23. A C++26 upgrade happens on a branch |

Namespace is `jhetz::ldap`; examples below assume `namespace ldap = jhetz::ldap;`.

## 1. Vocabulary types

No raw strings for LDAP concepts. Each type validates when it is built.

```cpp
ldap::dn        base{"ou=people,dc=example,dc=org"};  // literal: checked at compile time
ldap::attribute mail{"mail"};                         // case-insensitive equality and hashing
auto            url = ldap::url::parse("ldaps://ldap.example.org");  // result<url>

ldap::result<ldap::dn> d = ldap::dn::parse(user_text);  // runtime text: never throws
```

- `dn`: parsed RDN sequence (RFC 4514), `parent()`, `child(rdn)`, `rdns()`,
  `to_string()`. Comparison is syntactic: attribute types case-insensitive,
  values exact after unescaping, AVA order inside a multi-valued RDN not
  significant. No matching-rule normalization (so `cn=A` ≠ `cn=a`), and no
  hash yet. Parsing is lenient like OpenLDAP: spaces around `,` `+` `=` are
  ignored and unescaped trailing spaces dropped.
- `attribute`: attribute description, compared and hashed case-insensitively.
  `attribute::parse()` is strict RFC 4512; `attribute::unchecked()` keeps names
  as servers send them (Active Directory's `member;range=0-1499`).
- `entry`: untyped search result (DN text + ordered attributes) with
  case-insensitive `find()`; duplicate attributes from the server are merged.
- `url`: RFC 4516 (`ldap://`, `ldaps://`, `ldapi://`, IPv6 with RFC 6874
  zones, dn/attributes/scope/filter/extensions with the critical `!`).
  `parse(text, mr)` never throws; `to_string()` is canonical and
  `parse(to_string()) == *this`. Absent and empty dn/scope/filter are kept
  apart (referral chasing needs "absent = same as the original request").
  Allocator-aware (`std::pmr`), including its extensions. No literal
  constructor: use `parse`.
- `bytes`: not implemented; wire values are `std::pmr::string` holding raw
  octets (see section 10).
- Literals go through `consteval` helper types (`dn::literal`,
  `attribute::literal`) that run the same scanner as `parse()`, so an invalid
  literal is a compile error. A runtime `const char*` does not compile there:
  runtime text must go through `parse()` returning `result<T>`.

## 2. Filters

A filter is a typed tree (implemented in step 4b). The builders create nodes
directly and hold values unescaped, so a value can never change the filter's
structure; the encoder writes BER straight from the tree, so builder-made
filters are never parsed.

```cpp
using namespace ldap::filters;
auto f = attr("objectClass") == "person"
      && (attr("uid") == user_input || attr("mail").starts_with(prefix))
      && !attr("disabled").present();

auto g = attr("uidNumber") >= "1000" && attr("sn").approx("smith");

// Text from config or users: parsed once, here.
ldap::result<ldap::filter> h = ldap::filter::raw("(&(uid=jdoe)(mail=*))");
if (h) f = std::move(f) && *h;

f.to_string();   // "(&(objectClass=person)...)" for logs
```

| Builder | Node (`to_string()`) |
|---|---|
| `attr(a) == v` | equality `(a=v)` |
| `attr(a) >= v`, `<= v` | `(a>=v)`, `(a<=v)` |
| `attr(a).approx(v)` | `(a~=v)` |
| `attr(a).present()` | `(a=*)` |
| `attr(a).starts_with(v)` / `ends_with(v)` / `contains(v)` | substrings `(a=v*)` / `(a=*v)` / `(a=*v*)` |
| `starts_with("")`, `ends_with("")`, `contains("")` | present `(a=*)` (same meaning) |
| `f && g`, `f \|\| g`, `!f` | and / or / not; chains are flattened, so `f && g && h` is one and-node |
| `filter::raw(text)` | parsed once → `result<filter>`; malformed text fails here with `invalid_filter` |

- Combining is adding a node: a parsed filter keeps its exact meaning inside
  a larger one (there is no text concatenation, so no wrapping rules).
- Attribute names given to `attr()` are validated (literals at compile time),
  so names cannot inject filter syntax either.
- The combining operators live in namespace `ldap` (found by ADL for any
  filter) and are re-exported in `ldap::filters`.
- Storage: one flat `std::pmr::vector` of small nodes linked by indices plus
  one pooled string, so a filter is two allocations, copies are cheap and
  nothing recurses on destruction, equality or printing, at any depth.
- Chains: combining reuses an rvalue operand's storage, so `a && b && c` and
  `f = std::move(f) || x` in a loop are linear; `f = f || x` in a loop copies
  and is quadratic. Combining a filter with itself (`std::move(f) && f`)
  copies instead of reusing, so it gives the same result as `f && f`.
- Limits: `max_filter_depth` = 24 (so a search request with the deepest
  filter fits the BER reader's depth limit of 32) and `max_filter_elements`
  = 10,000. Parsing and decoding enforce them while reading; builders never
  throw or truncate, and an over-limit (or empty, default-constructed) filter
  fails at encode with `invalid_filter`.
- Parser (only for `raw`): full RFC 4515 including extensible match
  (`attr:dn:rule:=value`, only reachable through `raw` for now), RFC 4526
  `(&)` / `(|)`, and text without a leading `(` is wrapped like `ldapsearch`.
- `to_string()` is canonical (escapes `* ( ) \ NUL` as lower-case `\xx`,
  `:dn` lower case); equality compares trees, so
  `raw("cn=x") == raw("(cn=x)")`. Decoding BER rebuilds the exact tree
  (needed by the mock server).

## 3. Requests

Plain aggregates with defaults, filled with designated initializers.

```cpp
auto r = co_await conn.search({
    .base       = base,
    .scope      = ldap::scope::subtree,
    .filter     = f,
    .attributes = {"uid", "mail"},
    .size_limit = 500,
    .time_limit = std::chrono::seconds(10),
    .controls   = {ldap::paged{.page_size = 100}},
});
```

Controls are typed (`ldap::paged`, `ldap::sort`, …) in a `std::variant`, with
`ldap::raw_control{oid, critical, bytes}` as the escape hatch.

The designated-initializer style above is for the step 5 request structs,
which stay aggregates. The wire model of section 10 is allocator-aware and
uses constructors instead (`message{1, search_request{base, scope, f, {"cn"}}}`).

Implemented so far: only the wire-level `control {type, criticality, value}`
plus `encode_paged_results` / `decode_paged_results` helpers; the typed
variant comes with the request API (step 5).

## 4. Mapping entries to structs

```cpp
struct person {
    std::string                 uid;        // required, single-valued
    std::string                 cn;
    std::optional<std::string>  mail;       // optional
    std::vector<ldap::dn>       member_of;  // multi-valued
    std::chrono::sys_seconds    created;    // GeneralizedTime
};

template<> constexpr auto ldap::schema<person> = ldap::describe(
    ldap::object_class("inetOrgPerson"),          // optional, see below
    ldap::field<&person::uid>("uid"),
    ldap::field<&person::cn>("cn"),
    ldap::field<&person::mail>("mail"),
    ldap::field<&person::member_of>("memberOf"),
    ldap::field<&person::created>("createTimestamp", ldap::read_only));
```

`object_class(...)` is optional. When present:
- `search_as<T>` ANDs `(objectClass=…)` into the filter, so a `person` search
  only returns person entries;
- `add(dn, T{...})` writes those values to `objectClass` (a new entry cannot be
  created without them);
- runtime validation checks the classes exist on the server.

Without it, `search_as<T>` uses your filter unchanged and `add` requires an
`objectClass` field in the descriptor.

Field shape decides cardinality:

| Member type | Meaning | Error when |
|---|---|---|
| `T` | required, single value | missing, or more than one value |
| `std::optional<T>` | optional, single value | more than one value |
| `std::vector<T>` | zero or more values | a value fails to convert |

Value conversion is an extension point, like `std::formatter`:

```cpp
template<> struct ldap::value_traits<my_enum> {
    static constexpr auto syntaxes = {ldap::syntax::directory_string};  // for runtime validation
    static ldap::result<my_enum> decode(std::span<const std::byte>);
    static ldap::bytes encode(my_enum);
};
```

Built-in: `std::string`, integers, `bool`, `ldap::dn`, `ldap::bytes`,
`std::chrono::sys_seconds` (GeneralizedTime), enums via a name table.

Usage:

```cpp
// Attribute list is derived from the descriptor.
ldap::result<std::vector<person>> people = co_await conn.search_as<person>({.base = base, .filter = f});

co_await conn.modify<person>(dn, {
    ldap::replace(&person::mail, "new@example.org"),
    ldap::add(&person::member_of, group_dn),
});
co_await conn.add(dn, person{...});   // read_only fields are skipped
```

Compile-time guarantees (prototype-checked):
- the attribute list and names come only from the descriptor;
- `modify` on a member that is not in the descriptor is a `static_assert`
  failure;
- Planned: member type and value type must match
  (`replace(&person::created, "x")` does not compile).
- Planned: `modify` on a `read_only` field is a compile error.

The untyped `ldap::entry` (dn + attribute → values) stays available for
exploring unknown data; `ldap::decode<T>(entry)` converts one explicitly.

**C++26 path:** reflection generates `ldap::schema<T>` from the struct, with
an annotation to rename (`[[=ldap::name("memberOf")]]`). The descriptor stays
supported, so user code does not change.

## 5. Errors

```cpp
namespace jhetz::ldap {

struct error {
    std::error_code         code;        // see categories below
    std::string             diagnostic;  // server's diagnosticMessage, if any
    std::optional<dn>       matched_dn;  // server's matchedDN, if any
    std::vector<url>        referrals;   // from a referral result
    std::string             context;     // client-side path, e.g.
                                         // "search ou=people: entry uid=x: attribute uidNumber"
    std::string message() const;         // everything above, human readable
};

template<class T> using result = std::expected<T, error>;
}
```

Error-code categories:

| Category | Enum | Examples |
|---|---|---|
| `ldap.result` | `ldap::errc` — RFC 4511 resultCode values, numbers kept | `invalid_credentials` (49), `no_such_object` (32), `size_limit_exceeded` (4) |
| `ldap.client` | `ldap::client_errc` | codec: `decode_error`, `message_too_large`, `nesting_too_deep`, `unsupported_tag`, `unexpected_tag`, `integer_overflow`, `unsupported_operation`, `encode_error`; input: `invalid_filter`, `invalid_dn`, `invalid_attribute`, `invalid_url`; mapping: `missing_attribute`, `too_many_values`, `conversion_failed`, `schema_mismatch`; facade: `would_deadlock` |
| system / TLS | from Corosio / Capy | `connection_refused`; `capy::error::timeout`, `canceled`, `stream_truncated`; TLS errors in the `corosio.openssl` category |

`error`'s strings are `std::pmr::string` but always on the default
resource, never an arena, even when decoding into one fails: errors outlive
the operation (they go up the stack and into logs) and are the cold path.
They use whatever the default resource is when they are built, so an
application that replaces the default resource must keep it alive as long
as its errors.

LDAP result code 0 (success) is not an `errc` value: a successful result is
the absence of an error. `matched_dn` and `referrals` are still strings;
step 5 switches them to `dn` / `url`.

Plus an `ldap::cond` error condition (not implemented yet) for grouping across categories
(`cond::not_found`, `cond::auth_failed`, `cond::timeout`, …), so callers write
`if (r.error().code == ldap::cond::auth_failed)`.

Nothing on the normal path throws: network, protocol, server and mapping
failures all come back as `ldap::error`. Only programming errors (bad
literal, allocation failure) may throw.

## 6. Schema validation

**Compile time:** section 4.

**Runtime (optional):** read the server's subschema entry (RFC 4512) once per
connection and check descriptors against it.

Parsing is minimal, only what the checks below need:
- `attributeTypes`: `NAME` (all aliases), `SUP`, `SYNTAX`, `SINGLE-VALUE`,
  `NO-USER-MODIFICATION`. `SUP` is followed to inherit `SYNTAX`, because many
  common attributes (`cn`, `sn`, …) only declare `SUP name`.
- `objectClasses`: `NAME` only.
- Everything else (matching rules, `MUST`/`MAY`, DIT content rules, extensions)
  is skipped. Unparseable definitions are skipped, not fatal.

```cpp
ldap::result<ldap::server_schema> s = co_await conn.load_schema();
ldap::schema_report rep = ldap::validate<person>(*s);
if (!rep.ok()) std::println("{}", rep);   // lists every issue, not just the first

// or automatically:
ldap::connection_options{.schema_check = ldap::schema_check::on_first_use};
```

Checks:
- object classes from `object_class(...)` exist;
- attribute exists on the server (name or alias);
- cardinality: `T` / `optional<T>` mapped to a multi-valued attribute is
  reported (it only fails at runtime if an entry really has several values);
- syntax: the attribute's SYNTAX OID is in `value_traits<T>::syntaxes`
  (for example an `int` field on a DirectoryString attribute);
- writability: a non-`read_only` field on a `NO-USER-MODIFICATION`
  attribute (`createTimestamp`) is reported.

With `schema_check::on_first_use`, the first typed operation for `T` runs
`validate<T>` and fails with `client_errc::schema_mismatch` if the report has
errors. Results are cached per connection.

## 7. Async core and blocking facade

Decision: **async-first**. The coroutine API is the library; the blocking API
is a thin layer that cannot drift from it.

```cpp
// async (primary)
ldap::connection conn = co_await ldap::connect(ioc, url, {.timeout = 5s});
co_await conn.simple_bind(bind_dn, password);
auto stream = co_await conn.search_stream_as<person>({...});
while (auto p = co_await stream.next()) { ... }   // result<std::optional<person>>

// blocking (jhetz/ldap/sync.hpp)
ldap::sync::client c{url};                         // owns an io_context + 1 I/O thread
auto people = c.search_as<person>({...});          // same request/result types
```

Implemented under it (step 4, `jhetz_ldap_net`, namespace `ldap::net`):
- `net::connect(ctx, url, connect_options, mr)` returns a `net::transport`
  over TCP, TLS or a Unix socket. One deadline (`timeout`, an
  `optional<milliseconds>`, default 30 s; `nullopt` = no limit; zero or
  negative fails at once) covers name lookup, every TCP attempt and the TLS
  handshake. The lookup runs detached so a slow DNS server cannot hold
  `connect` past the deadline (the io_context itself stays busy until the
  lookup thread returns). Each address gets
  `min(remaining, max(remaining / addresses left, 1 s))`, so one
  black-holed address does not starve the others. Errors name the stage:
  `connect ldaps://h:636: tls handshake: ...`.
- TLS: verification is on by default (Corosio's own default is off), with
  the system trust store, SNI, host name checks (IP literals against iPAddress
  entries, zone stripped) and TLS 1.2 minimum. Options: `ca_file`, `ca_dir`,
  `ca_pem`, client `cert_file` + `key_file`, `server_name`; the only opt-out
  is `certificate_verification::insecure_accept_any`. Configuration errors
  (bad or mismatched PEM certificates and keys, missing `ca_dir`) fail before
  any network traffic. Host matching
  follows OpenSSL defaults, which Corosio does not let us change: CN fallback
  when there is no SAN, and partial wildcards in the leftmost label.
  CA bundles are split by us because Corosio loads only the first
  certificate of a bundle (worth reporting upstream).
- StartTLS readiness: TLS is a reference-mode `openssl_stream` over the
  socket the transport owns; step 7 builds it on a live plain transport with
  the same `detail::make_tls_setup` / `detail::tls_handshake`. The read
  buffer must be empty at the upgrade.
- `net::read_message` / `write_message`: rejects a PDU whose first octet is
  not SEQUENCE or whose declared size exceeds `read_options::max_message_size`
  (16 MiB) from the header alone; decodes with `origin::server`; a TLS close
  without close_notify between PDUs reads as a normal close. After any error
  the caller drops the connection (header errors repeat, they are not
  consumed). No timeout of its own: step 5 cancels with stop tokens.

- `sync::client` methods start the coroutine on its internal I/O thread with
  `spawn_future` and wait on the `result_future` (see
  `examples/corosio/result_future.hpp`), so any number of caller threads can
  share one client.
- Calling a blocking method from inside the client's own I/O thread would
  deadlock; it returns `client_errc::would_deadlock` instead.
- The facade exposes exactly the same request, entry, error and mapping types;
  only the calling convention differs.

## 8. Ownership and threading

- Public types (`dn`, `entry`, `error`, user structs, requests) own their data
  and are regular. Nothing returned to the user points into a receive buffer.
- Zero-copy views exist only inside the BER decoder.
- `std::pmr` status (step 4b: done). Every public type that owns strings is
  allocator-aware (`allocator_type`, allocator-extended copy/move, assignment
  keeps the target's resource): the message model, `filter`, `dn`,
  `attribute`, `entry`, `url`, `ber::writer`. `error` is the deliberate
  exception (section 5). `decode_options::memory` sets where decoding
  allocates (`read_options.decode.memory` for the network path);
  `encode(m, mr)` and `write_message(t, m, mr | ber::writer&)` let callers
  pool write buffers. `tls_options` stays a plain aggregate with
  `std::filesystem::path` for files.

**`std::pmr` (implemented, step 4b).**
- Rule: an object decoded into a caller-supplied arena must not outlive it.
  Copies of pmr containers use the default resource, so copying out is always
  safe, and results decoded with default options are always safe.
- BER parsing itself never allocates (`ber::reader` returns views into the
  receive buffer). Decoded values are copied into the chosen resource, so
  there is one owning message type; a zero-copy view model (values pointing
  into the receive buffer, like OpenLDAP's `berval`) was considered and
  rejected for now, since it needs a second message type with stricter
  lifetimes.
- Coroutine frames already accept a memory resource via Capy's
  `run_async(ex, mr)`.
- Benchmark (`ldap/bench`, GCC 13 Release; 1,000 SearchResultEntry PDUs of
  30 attributes x 3 values, every 20th with 68 KiB of binaries, 7.1 MiB):
  default heap 15.1 ms and 111.7 allocations per entry; per-message
  monotonic arena with a 256 KiB buffer 10.9 ms and 0 heap allocations. The
  arena path is about 20% faster than step 4; the default heap path is about
  9% slower than step 4 (virtual resource calls plus an element-counting pass
  that reserves vectors exactly).

## 9. Toolchain

- C++23: `std::expected`, deducing `this`, `std::print` where available.
- Compilers: GCC 13+; Clang 19+ (Clang 18 cannot use libstdc++ 13's
  `<expected>`); MSVC 17.8+.
- Corosio and Capy pinned by commit, as in `examples/corosio/`, used only by
  `jhetz_ldap_net` (option `JHETZ_LDAP_BUILD_NET`, off in fuzz builds);
  it also needs OpenSSL. The codec library `jhetz_ldap` has no dependencies.
- The Clang < 19 `<expected>` workaround is scoped to our own targets.
- C++26 (reflection, `std::execution` interop) on a separate branch.

## 10. Message model (implemented, step 3)

`jhetz/ldap/message.hpp` is a faithful wire model of RFC 4511: an
`ldap::message {id, op, controls}` where `op` is a `std::variant` of every
protocol operation, requests and responses. Covering both directions lets the
same codec serve the client and a mock server for tests.

- Wire fields (LDAPDN, LDAPString, attribute values) are `std::string` holding
  raw octets, so a server sending an odd DN never breaks decoding; the
  vocabulary types of section 1 are for the API layer.
- Types are allocator-aware with value constructors (not aggregates); wire
  strings are `std::pmr::string`, lists `std::pmr::vector` (`string_list`).
- `encode(const message&, mr)` returns `result<std::pmr::vector<std::byte>>`.
  It fails with `invalid_filter` (empty or over-limit filter) or
  `encode_error` (values the wire
  format cannot carry: negative ids or limits, out-of-range enums, an add
  with no values), and all checks run before any byte is written. The decoder
  rejects the same empty adds, so both sides accept the same messages.
  `decode(encode(m)) == m` exactly (filters are trees), and
  `encode(decode(encode(m)))` is byte-identical to `encode(m)`.
- `decode(bytes, decode_options)` takes exactly one framed message.
  `decode_options::from` restricts which side sent it (default `origin::any`,
  used by tests and round trips). The connection layer (step 5) must pass
  `origin::server` explicitly; it rejects request operations, so a hostile server
  cannot make the client parse client-only structures such as search filters.
  Depth and filter-element limits are also options.
- Leniency toward real servers: unknown trailing SEQUENCE elements are ignored
  (RFC 4511 section 4); scope 3 (subordinateSubtree) and modify operation 3
  (increment, RFC 4525) are accepted; unknown result codes are kept; lists
  RFC 4511 declares non-empty are accepted when empty (empty means absent),
  except attribute values in an AddRequest (RFC 4511 `SIZE(1..MAX)`) and in a
  modify `add` change. The latter is server policy (OpenLDAP rejects it), not
  an RFC rule; both sides refuse it so encode and decode accept the same set.
- `ldap_result::to_error()` turns a result into `ldap::error` with the
  server's diagnostic, matched DN and referrals.

## Resolved

- Filters: a typed tree built by operators; only `filter::raw` parses (section 2).
- Descriptors: optional `object_class(...)` (section 4).
- Schema: minimal parsing (section 6).

## Open questions

- Default-heap decode is about 9% slower than before step 4b; the
  element-counting pass (exact `reserve`) costs about 1 ms per 1,000 entries
  in arena mode but saves a third of heap allocations. Revisit with real
  workloads.

- Happy Eyeballs (RFC 8305) instead of sequential per-address attempts.
- Stricter TLS host matching (no CN fallback, no partial wildcards) needs
  Corosio to expose the OpenSSL check flags.
- Step 5 (connection): the maximum message size is configurable
  (`read_options::max_message_size`, 16 MiB default); decide whether to lower
  the default or add per-entry limits. A
  16 MiB SearchResultEntry of empty values legitimately decodes to about
  300 MB (linear, about 12-18x the message size).
- Filter element cap counts filter nodes, not substring parts: one
  `(a=*x*x*…)` with millions of parts is not capped. Harmless for the client
  (`origin::server` never decodes filters); count parts if a mock server or
  proxy ever decodes untrusted requests.

- Should `MUST` attributes of the declared object classes be checked against
  required (`T`) fields? Needs `MUST`/`MAY` parsing, so deferred.
