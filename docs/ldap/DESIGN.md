# LDAP client: API design

Status: steps 1–3 implemented under `ldap/` (errors, BER codec, message model,
filters, DN/attribute/entry). Sections 3–7 describe the API still to be built;
"Implemented" notes say where the code differs from the original plan.
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
ldap::url       url{"ldaps://ldap.example.org"};      // not implemented yet

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
- `url`: `ldap://`, `ldaps://`, `ldapi://` (step 4, not implemented yet).
- `bytes`: not implemented; wire values are `std::string` holding raw octets
  for now (see section 10).
- Literals go through `consteval` helper types (`dn::literal`,
  `attribute::literal`) that run the same scanner as `parse()`, so an invalid
  literal is a compile error. A runtime `const char*` does not compile there:
  runtime text must go through `parse()` returning `result<T>`.

## 2. Filters

A filter is its RFC 4515 text (`ldap::filter` wraps a `std::string`).
Operators build it and escape every value, so filter injection is impossible
when filters are built this way (prototype: `x)(uid=*` becomes
`x\29\28uid=\2a`).

```cpp
using namespace ldap::filters;
auto f = attr("objectClass") == "person"
      && (attr("uid") == user_input || attr("mail").starts_with(prefix))
      && !attr("disabled").present();

auto g = attr("uidNumber") >= "1000" && attr("sn").approx("smith");

// Text from config or users: passed through as is.
auto h = ldap::filter::raw("(&(uid=jdoe)(mail=*))");
```

| Builder | Produces |
|---|---|
| `attr(a) == v` | `(a=v)` |
| `attr(a) >= v`, `<= v` | `(a>=v)`, `(a<=v)` |
| `attr(a).approx(v)` | `(a~=v)` |
| `attr(a).present()` | `(a=*)` |
| `attr(a).starts_with(v)` / `ends_with(v)` / `contains(v)` | `(a=v*)` / `(a=*v)` / `(a=*v*)` |
| `f && g`, `f \|\| g`, `!f` | `(&fg)`, `(\|fg)`, `(!f)`; chains are flattened, so `f && g && h` is `(&fgh)` |
| `starts_with("")`, `ends_with("")`, `contains("")` | `(a=*)` (same meaning, and `(a=**)` is not valid) |
| `filter::raw(text)` | `text`, unchanged |

When a `raw` operand of `&&`, `||` or `!` is not exactly one parenthesized
group, it is wrapped in parentheses if that makes it one group, so
`raw("cn=x") && f` works. Otherwise (for example `raw("a=1)(|(b=*)")`, where
wrapping would produce a valid but different filter) a NUL byte is inserted,
which the parser always rejects: malformed raw text stays malformed instead of
merging into a different valid query. Attribute names given to `attr()` are validated too, so names cannot
inject filter syntax either.

No separate validation step. LDAP sends filters in binary (BER) form, so the
text is parsed once when the request is encoded; a malformed filter (only
possible through `raw`) fails that operation with `client_errc::invalid_filter`.

Parser details:
- full RFC 4515: and/or/not, equality, substrings, `>=`, `<=`, `~=`, present,
  extensible match (`attr:dn:rule:=value`); builders cover all but extensible
  match, which is only reachable through `raw` for now;
- RFC 4526 absolute true/false `(&)` and `(|)` are accepted;
- text that does not start with `(` is wrapped, like `ldapsearch` does;
- limits: nesting depth `max_filter_depth` = 24, so a search request with the
  deepest allowed filter still fits the BER reader's depth limit of 32; and a
  maximum number of filter elements (default 10,000) on both encode and
  decode, so a hostile message cannot make decoding use gigabytes.

Decoded filters come back as canonical text (escapes normalized to lower-case
`\xx` for `* ( ) \ NUL` only, `:dn` lower case, empty substring parts dropped),
which has the same meaning as the original but may differ textually.

**Planned change (step 4b, after step 4, before step 5): typed filter tree.**
Today `filter` stores text and the whole text is parsed again when a request
is encoded, which also forces the raw-operand wrapping above. The builders
will instead produce a small typed tree (and/or/not/equality/substring/
ordering/present/approx/extensible nodes holding unescaped values); the
encoder writes BER straight from the tree, so builder-made filters are never
parsed. `filter::raw(text)` becomes the only parsing path, runs once when
called and returns `result<filter>`; combining a raw filter is just adding a
node, so the wrapping/NUL logic goes away. `to_string()` renders RFC 4515
text for logging; decoding BER back to a filter tree stays for the mock
server. The builder syntax (`attr("sAMAccountName").starts_with("emp") && ...`)
does not change.

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
| `ldap.client` | `ldap::client_errc` | codec: `decode_error`, `message_too_large`, `nesting_too_deep`, `unsupported_tag`, `unexpected_tag`, `integer_overflow`, `unsupported_operation`, `encode_error`; input: `invalid_filter`, `invalid_dn`, `invalid_attribute`; mapping: `missing_attribute`, `too_many_values`, `conversion_failed`, `schema_mismatch`; facade: `would_deadlock` |
| system / TLS | from Corosio | `connection_refused`, timeouts, certificate errors |

LDAP result code 0 (success) is not an `errc` value: a successful result is
the absence of an error. Until `dn`/`url` exist, `matched_dn` and `referrals`
are strings.

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
- One `connection` runs on one executor. Starting operations from other
  threads is done by posting to that executor (the sync facade does this for
  you).

## 9. Toolchain

- C++23: `std::expected`, deducing `this`, `std::print` where available.
- Compilers: GCC 13+; Clang 19+ (Clang 18 cannot use libstdc++ 13's
  `<expected>`); MSVC 17.8+.
- Corosio and Capy pinned by commit, as in `examples/corosio/`.
- C++26 (reflection, `std::execution` interop) on a separate branch.

## 10. Message model (implemented, step 3)

`jhetz/ldap/message.hpp` is a faithful wire model of RFC 4511: an
`ldap::message {id, op, controls}` where `op` is a `std::variant` of every
protocol operation, requests and responses. Covering both directions lets the
same codec serve the client and a mock server for tests.

- Wire fields (LDAPDN, LDAPString, attribute values) are `std::string` holding
  raw octets, so a server sending an odd DN never breaks decoding; the
  vocabulary types of section 1 are for the API layer.
- `encode(const message&)` returns `result<std::vector<std::byte>>`. It fails
  with `invalid_filter` (bad `raw` filter) or `encode_error` (values the wire
  format cannot carry: negative ids or limits, out-of-range enums, an add
  with no values), and all checks run before any byte is written. The decoder
  rejects the same empty adds, so both sides accept the same messages.
  `decode(encode(m)) == m` except that the filter comes back as canonical
  text, and `encode(decode(encode(m)))` is byte-identical to `encode(m)`.
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

- Filters: string-based with builder operators; no validation step (section 2).
- Descriptors: optional `object_class(...)` (section 4).
- Schema: minimal parsing (section 6).

## Open questions

- Step 5 (connection): make the maximum message size configurable (16 MiB
  default today) and decide whether to lower it or add per-entry limits. A
  16 MiB SearchResultEntry of empty values legitimately decodes to about
  300 MB (linear, about 12-18x the message size).
- Filter element cap counts filter nodes, not substring parts: one
  `(a=*x*x*…)` with millions of parts is not capped. Harmless for the client
  (`origin::server` never decodes filters); count parts if a mock server or
  proxy ever decodes untrusted requests.

- Should `MUST` attributes of the declared object classes be checked against
  required (`T`) fields? Needs `MUST`/`MAY` parsing, so deferred.
