# LDAP client: API design

Status: agreed direction, not implemented yet. `api_prototype.cpp` next to this
file checks that the type-safety parts compile as C++23 (GCC 13).

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
ldap::dn        base{"ou=people,dc=example,dc=org"};  // throws only on literal misuse, see below
ldap::attribute mail{"mail"};                         // case-insensitive equality and hashing
ldap::url       url{"ldaps://ldap.example.org"};

ldap::result<ldap::dn> d = ldap::dn::parse(user_text);  // runtime text: never throws
```

- `dn`: parsed RDN sequence (RFC 4514), normalized comparison, `parent()`,
  `child(rdn)`, `to_string()`.
- `attribute`: attribute description, compared case-insensitively.
- `url`: `ldap://`, `ldaps://`, `ldapi://`.
- `bytes` (`std::vector<std::byte>`) for binary values such as `jpegPhoto` or
  `objectGUID`.
- Constructors taking `const char*` are for literals and are `consteval` where
  the check can run at compile time; everything built from runtime text goes
  through `parse()` returning `result<T>`.

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
| `f && g`, `f \|\| g`, `!f` | `(&fg)`, `(\|fg)`, `(!f)` |
| `filter::raw(text)` | `text`, unchanged |

No separate validation step. LDAP sends filters in binary (BER) form, so the
text is parsed once when the request is encoded; a malformed filter (only
possible through `raw`) fails that operation with `client_errc::invalid_filter`.
Extensible match (`:=`) is only available through `raw` for now.

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
| `ldap.client` | `ldap::client_errc` | `missing_attribute`, `too_many_values`, `conversion_failed`, `decode_error`, `message_too_large`, `schema_mismatch`, `would_deadlock` |
| system / TLS | from Corosio | `connection_refused`, timeouts, certificate errors |

Plus an `ldap::cond` error condition for grouping across categories
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

## Resolved

- Filters: string-based with builder operators; no validation step (section 2).
- Descriptors: optional `object_class(...)` (section 4).
- Schema: minimal parsing (section 6).

## Open questions

- Should `MUST` attributes of the declared object classes be checked against
  required (`T`) fields? Needs `MUST`/`MAY` parsing, so deferred.
