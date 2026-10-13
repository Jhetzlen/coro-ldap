# LDAP client: API design

Status: implemented in this repository (codec, connection with multiplexing,
every RFC 4511 operation, StartTLS, SASL, typed mapping, runtime schema
checks, blocking facade, `ldapsearch`). The original roadmap (GitHub
tickets #2 to #20, done by 2026-10-07) and the pre-implementation API
sketch `api_prototype.cpp` were removed once finished; see the git history.
"Implemented" notes say where the code differs from the original plan.
Remaining work is tracked in beads (`bd list`).

Definition of done for a change: GCC 16 Debug with
`-DJHETZ_LDAP_SANITIZE=ON -DJHETZ_LDAP_WERROR=ON` builds without warnings
and `ctest` is green (network tests also under `--repeat until-fail:10
-j8`); new parsers of untrusted input get a fuzz target, seeds and a GCC
replay test; `clang-format --dry-run --Werror` (clang-format 23) is clean;
this document is updated.

## Goals

- **Type safety.** LDAP concepts have their own types; entries map to user
  structs; misspelled attributes and unmapped members are compile errors.
- **Pass data around safely.** Public types own their data, are regular
  (copyable, movable, comparable), and can cross threads.
- **Modern API.** Coroutines (Corosio/Capy), designated-initializer requests,
  `std::expected` results, no exceptions for expected failures.
- **Unicode.** Text is UTF-8 everywhere: the string forms of DNs and
  filters, values of string syntaxes (Directory String and the like), SASL
  usernames and passwords, error contexts. No ASCII-only restriction,
  documented or not: text is prepared as the RFCs say (SASLprep, RFC 4013,
  for SASL; LDAPprep, RFC 4518, for matching), and invalid UTF-8 in text is
  a clear error. Binary values (`ldap::binary`, `jpegPhoto`, `;binary`) and
  `\xx`-escaped octets stay raw bytes.

## Decisions

| # | Topic | Decision |
|---|-------|----------|
| 1 | Struct ↔ entry mapping | Hand-written `constexpr` descriptor now; C++26 reflection later on a separate branch, same user-facing API |
| 2 | Errors | Rich `ldap::error` struct inside `std::expected` |
| 3 | Schema checking | Both compile-time (descriptor) and optional runtime validation against the server schema |
| 4 | Sync API | Async core; thin blocking facade in its own header (see below) |
| 5 | Language | C++23. A C++26 upgrade happens on a branch |
| 6 | Unicode | Full UTF-8; ICU (normalization, stringprep profiles) is the Unicode dependency |

Namespace is `jhetz::ldap`; examples below assume `namespace ldap = jhetz::ldap;`.

## 1. Vocabulary types

No raw strings for LDAP concepts. Each type validates when it is built.

```cpp
ldap::dn        base{"ou=people,dc=example,dc=org"};  // literal: checked at compile time
ldap::attribute mail{"mail"};                         // case-insensitive equality and hashing
auto            url = ldap::url::parse("ldaps://ldap.example.org");  // result<url>

ldap::result<ldap::dn> d = ldap::dn::parse(user_text);  // runtime text: never throws
```

- `dn`: parsed RDN sequence (RFC 4514), `parent()`, `child(rdn)` /
  `child(dn)` (prepend one RDN or a relative DN: `base.child(ldap::rdn{"uid=x"})`
  is `uid=x,<base>`), `rdns()`, `to_string()`. Comparison is syntactic:
  attribute types case-insensitive, values exact after unescaping, AVA order
  inside a multi-valued RDN not significant. No matching-rule normalization
  (so `cn=A` ≠ `cn=a`), and no hash yet. Parsing is lenient like OpenLDAP:
  spaces around `,` `+` `=` are ignored and unescaped trailing spaces dropped.
- `rdn`: one (possibly multi-valued) RDN, with its own literal
  (`ldap::rdn{"uid=x"}`), `rdn::parse()` and `to_string()`; text holding more
  than one RDN is rejected.
- `attribute`: attribute description, compared and hashed case-insensitively
  (the hash is seeded at random per process, so a server cannot send names
  that collide; its values differ between runs).
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
  `rdn::literal`, `attribute::literal`) that run the same scanner as
  `parse()`, so an invalid literal is a compile error. A runtime
  `const char*` does not compile there: runtime text must go through
  `parse()` returning `result<T>`.

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
| `attr(a).matches(rule, v)`, `matches(rule, v, true)` | extensible match `(a:rule:=v)`, `(a:dn:rule:=v)`; empty rule gives `(a:=v)` |
| `rule_matches(rule, v)`, `rule_matches(rule, v, true)` | `(:rule:=v)`, `(:dn:rule:=v)` (rule required) |
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
  = 10,000 (substring parts count as elements). Parsing and decoding enforce them while reading; builders never
  throw or truncate, and an over-limit (or empty, default-constructed) filter
  fails at encode with `invalid_filter`.
- Parser (only for `raw`): full RFC 4515 including extensible match
  (`attr:dn:rule:=value`), RFC 4526
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

Controls are typed (`ldap::paged`, `ldap::server_side_sort`, …) in a
`std::variant` (`ldap::request_control`), with the wire
`ldap::control{type, criticality, value}` as the escape hatch.

The designated-initializer style above is for the step 5 request structs,
which stay aggregates. The wire model of section 10 is allocator-aware and
uses constructors instead (`message{1, search_request{base, scope, f, {"cn"}}}`).

Implemented (steps 5a and 6, `connection.hpp`): one aggregate per
operation — `search_params`, `add_params`, `modify_params` (changes built
with `ldap::mod::add / remove / replace / increment`), `del_params`,
`modify_dn_params` (`new_rdn` as an `ldap::rdn`, optional `new_superior`),
`compare_params`, `extended_params` — each with `.controls` and a
client-side `.timeout`. Values are checked when the request is encoded,
before anything is sent.

Typed controls (step 6, `controls.hpp`): `request_control` is
`std::variant<control, paged, manage_dsa_it, proxied_authorization,
server_side_sort, assertion, pre_read, post_read>`, so the raw wire
`control {type, criticality, value}` stays the escape hatch and existing
code that passes raw controls compiles unchanged. They are encoded on the
connection's resource when the request is sent; an invalid one (a sort
without keys, an empty assertion filter) fails before anything is sent.
Response controls stay wire-level (`std::pmr::vector<control>`, in
`response`, `extended_result`, `search_stream::controls()`,
`paged_search::controls()`), and a `find_*` function reads each typed one
from such a vector: nullopt when absent, an error when malformed, so a
server's bad control fails only the caller who asks for it.

- Server side sorting (RFC 2891): `server_side_sort{.keys = {{.attribute,
  .ordering_rule, .reverse}}, .critical}`; the SearchResultDone's
  SortResult is `find_sort_result()` -> `sort_result{result_code,
  attribute_type}`. RFC 2891 section 2 says a server that cannot sort
  SHOULD fail a critical request and should return the entries unsorted
  otherwise, attaching a SortResult, though scenario 6 lets it omit the
  SortResult when the search fails or returns no entries (a server
  without sort support ignores a non-critical control and attaches
  none). A server may accept only one key. Servers deviate: OpenLDAP
  2.7's sssvlv fails an unsortable search with inappropriateMatching (18)
  and no SortResult even when the control is not critical, and answers
  every multi-key sort with protocolError (2) "decoding error" and no
  SortResult, even when not critical, libldap's own included. So callers
  check the search's result, and `find_sort_result()` returning nullopt
  is a normal answer meaning "not known to be sorted", which they must
  handle. Named `server_side_sort`, not `sort`: a class named
  `sort` in `jhetz::ldap` would hide `std::sort` from unqualified calls
  there (and in code that uses the namespace).
- Assertion (RFC 4528): `assertion{.filter, .critical = true}`, the value
  being the Filter itself. Critical by default, because a server that
  ignored the condition would apply an update the caller meant to be
  conditional. A false assertion fails the operation with
  `errc::assertion_failed` (122).
- Pre-read / post-read (RFC 4527): `pre_read{.attributes}` on modify /
  delete / modify DN, `post_read{.attributes}` on add / modify / modify DN
  (sections 3.1 and 3.2: nothing to pre-read before an add, nothing to
  post-read after a delete);
  `find_pre_read()` / `find_post_read()` decode the returned
  SearchResultEntry into an `ldap::entry`, with the message decoder's
  depth and element limits.

The response codecs (`encode_` / `decode_sort_result`,
`encode_` / `decode_read_entry`) live in `message.hpp` next to the paged
results one, so mock servers and the fuzzers use them too. Request controls
are only encoded (no decoder: the client never reads them). Errors from
inside a response control's value name the control (`post-read: ber: ...
at offset 9`), since their offsets are relative to the value; request
encoding errors name the control too (`server side sort: key 2 has no
attribute`, `assertion: filter: empty`), after the operation's context.
Text in these controls (assertion values, sort result attribute, the read
entries' DN and values) is UTF-8 passed through unchanged. The unit tests
pin the encodings and decodings against bytes captured between OpenLDAP
2.7's ldapsearch / ldapmodify and slapd (sssvlv overlay), with UTF-8
values, and the integration tests run them against slapd.

Results (step 6): success returns the operation's value — `response`
(the response controls) for add / modify / delete / modify DN, `bool` for
compare, `extended_result` for extended operations, the authzId string for
`who_am_i()` (RFC 4532), the generated password (if any) for
`password_modify()` (RFC 3062; passwords never appear in error contexts).
Any other result code is an error. compareTrue /
compareFalse map to `true` / `false` (a compare answered with success is
an error: it is not a valid answer). referral (10) is an error with the
URIs in `error::referrals`; saslBindInProgress (14) is an error for a
simple bind and the "continue" signal of `sasl_bind` (#11).

`change_password()` / `reset_password()` pick RFC 3062 or Active
Directory's `unicodePwd` Modify from the root DSE (`password_method`,
connection.hpp), cached per connection and dropped by `start_tls()` like
the schema; the AD path refuses a connection without TLS before sending
(`client_errc::tls_required`). A root DSE the server refuses to read
fails with the server's own error (e.g. insufficientAccessRights); one
that returns no entry, or advertises neither method, fails with
`client_errc::no_password_method`. Both errors name the option that skips
the lookup. Password memory is not wiped on these paths, nor in simple
binds and `password_modify()`: the password passes through `std::string`
copies (the caller's, the request's values, the encoded PDU in the
connection's pmr buffers) that cannot all be reached, and wiping one of
them would suggest a protection the library does not give. Only SCRAM
wipes its key material (below).

SASL (implemented, #11, `sasl.hpp`): `connection::sasl_bind(mechanism,
name)` sends one BindRequest per step while the server answers
saslBindInProgress (at most 32 steps). A mechanism implements
`sasl_mechanism`: `name()`, `start()` (first credentials; also resets),
`step(challenge)` and `complete(final server creds)`, which lets a
mechanism such as SCRAM verify the server. `sasl_external` (RFC 4422
appendix A) is provided, with an optional authorization identity; the
identity comes from a TLS client certificate (`tls_options::cert_file`) or
an ldapi:// socket. A server or mechanism error fails the bind and leaves
the connection usable, except a `complete()` that refuses the server's
success: the server then considers the connection bound, so `sasl_bind`
closes it. An end-to-end EXTERNAL test needs a real server
(#14). Before `start()`, `sasl_bind` calls `prepare(sasl_bind_context)`
(default: ignored) with the URL's host (empty for ldapi:// and wrapped
transports), which GSSAPI needs for its default target.

`start()`, `step()` and `complete()` run on the I/O thread. A mechanism
whose steps may block (GSSAPI: the KDC) overrides `offload_start()` /
`offload_step(challenge)`, which `sasl_bind` calls in their place: they
return a `sasl_work` (`std::move_only_function` returning the step's
`result<std::optional<std::string>>`), empty for "call start() / step()
here" (the default, so EXTERNAL and SCRAM are unchanged). Non-empty work
runs on a `std::thread` of its own and wakes the bind through
a `capy::async_waker` (zero-allocation, `wake()` from any thread, the
resumption posted to the waiter's executor); the bind waits on it with
`corosio::timeout` (`operation_timeout`) and its stop token, like a
response. Giving up (timeout, cancellation, the task destroyed) leaves
the work running: it shares a `shared_ptr` block (the work, its result,
the waker) with the wait, so nothing it touches dies under it, and its
late `wake()` only latches a token nobody reads. The work owns or shares
everything it uses (the mechanism may be destroyed, or start another
bind, meanwhile): GSSAPI's work holds the handles' block by `shared_ptr`,
marked busy while it runs (`step()` and `complete()` refuse it,
`offload_start()` makes a new block), so no handle is used from two
threads at once. The thread holds a `capy::work_guard` on the
connection's io_context and drops it last, so `run()` returns only after
the work. Dropping it is not the thread's end, though: Corosio's
`work_finished()` decrements the count and then calls `stop()`, which
locks the scheduler's mutex, and in between the I/O thread can see no
work left, return from `run()` and let the owner destroy the io_context
(a heap-use-after-free under ASan, coro-ldap-2px.1.1); and the thread
still runs its own teardown (the closure, libkrb5's thread-local
destructors) after that. So the threads are not detached: a Capy
service of the io_context (`offload_threads`, `src/connection.cpp`) owns
them and joins them in its `shutdown()`. Capy shuts services down, then
deletes them, newest first (`execution_context::shutdown()` /
`destroy()` walk a list that `use_service()` pushes onto the front), and
the scheduler is the io_context's first service (made by its
constructor, `Backend::construct`), so the join runs while the scheduler
is alive and nothing of the thread outlives the io_context. The cost:
destroying the io_context (and so `sync::connection`'s destructor)
waits for a step still running, as long as krb5's own timeouts. A
thread that has ended is joined when the next one starts, so they do
not pile up. The posts from the worker need
Corosio's default `locking_mode::safe`: under `unsafe` (no scheduler
locking) `run_offloaded` fails with `std::errc::operation_not_supported`
before starting the thread, as Corosio's resolver does
(`detail::scheduler::scheduler_locking_disabled()`); `unsafe_io` keeps
scheduler locking but io_uring then skips the cross-thread wakeup, and
Corosio exposes nothing to tell it from `safe`, so it is documented as
unsupported. A thread per call rather than a
pool: Capy's system pool (`get_system_context()`) is shared and sized for
CPU work, and a KDC call can block one of its threads for many seconds;
Corosio's blocking-call pool (used for getaddrinfo) is
`corosio::detail::thread_pool`, not public, with one thread per
io_context by default that name lookups would then wait behind. Creating
a thread costs little next to a Kerberos exchange. Failing to create one
fails the bind with its `std::system_error` code. Timing out before the
first BindRequest sends nothing (the connection stays usable); later the
exchange is aborted as for a mechanism error (a cancellation also cancels
that abort, which closes the connection).

SCRAM-SHA-256 (`sasl_scram.hpp`, RFC 5802 / RFC 7677, in jhetz::ldap_net
since it needs OpenSSL): `sasl_scram_sha256(username, password,
authz_id)`. `start()` sends the client-first-message with a fresh
18-byte random nonce; `step()` checks the server-first-message (the nonce
must extend ours, iteration count in [4096, 1'000'000]: PBKDF2 runs on the
event loop thread, unknown "m="
extensions refused), runs PBKDF2-HMAC-SHA-256 and returns the
client-final-message with the proof; `complete()` (or `step()`, when the
server sends its final message as a challenge) compares the "v=" server
signature with `CRYPTO_memcmp`. A missing or wrong signature, or a server
"e=" error, fails the bind (`client_errc::unexpected_response`) even if
the server reported success (then the connection is closed): the server
is not authenticated. The
username and password are UTF-8 and prepared with SASLprep (RFC 4013,
ICU's usprep): B.1 mapped to nothing, non-ASCII spaces to U+0020, NFKC,
prohibited characters and bidi violations refused, unassigned code points
(Unicode 3.2) refused in the password (a stored string) and allowed in the
username (a query), as RFC 5802 sections 2.2 and 5.1 say; invalid UTF-8 is
refused. The authz_id must be valid UTF-8 and is not prepared. The
prepared username and the authz_id are escaped ("=2C", "=3D"). cyrus-sasl
(slapd) does not SASLprep the userPassword it derives the keys from, so
only passwords stored in SASLprep form match there. No
channel binding (GS2 header "n,,"; no -PLUS variant). Key material is
wiped with `OPENSSL_cleanse` (the password when the object is destroyed;
its prepared form, our preparation buffers and the derived keys as soon as
the proof is built; ICU's internal buffers cannot be). Server text quoted
in error contexts stays UTF-8: only control characters, ill-formed
sequences, the bidi controls (Bidi_Control: "Trojan Source" reordering)
and U+2028/U+2029 (line breaks in some log viewers) are replaced (U+FFFD),
and it is cut on a code point boundary. Contexts do not name the
mechanism (`sasl_bind` prefixes "sasl bind SCRAM-SHA-256"). Tested with the RFC 7677 vector and against
slapd with cyrus-sasl's scram plugin.

GSSAPI (`sasl_gssapi.hpp`, RFC 4752, Kerberos V5; in jhetz::ldap_net only
with the CMake option `JHETZ_LDAP_WITH_GSSAPI`, off by default): an
optional dependency on the GSS-API C library (MIT krb5's
`libgssapi_krb5`), found with pkg-config (`krb5-gssapi`, or Heimdal's
`heimdal-gssapi`, untested) and linked privately; the installed package
config finds it again (component `gssapi`). `sasl_gssapi(options)` with
`target` (a host-based service name, default `ldap@<host>`, the host
from `prepare()`), `principal` (default: the default credentials of the
ccache; otherwise `gss_acquire_cred` for that name, which looks through
the cache collection) and `authz_id`. `start()` and `step()` run
`gss_init_sec_context` (Kerberos OID 1.2.840.113554.1.2.2, written out
so the code builds against MIT and Heimdal headers; mutual authentication
and sequencing requested; no channel bindings) until the context is
established, the last output token sent even if empty; a context without
mutual authentication is refused. The next challenge is the server's
wrapped security layer offer (`gss_unwrap`, exactly 4 octets: layer mask,
max size); the client always answers "no security layer" (`0x01`), max
size 0, then the authz_id, wrapped without confidentiality (`gss_wrap`,
conf_flag 0), as RFC 4752 section 3.1 says. An offer without the "none"
bit fails with `client_errc::security_layer_required` (the exchange is
aborted, the connection stays usable). `complete()` refuses a success
that comes before that reply (the server was not authenticated, so
`sasl_bind` closes the connection), and releases the context: with no
layer nothing uses it after the bind. The layer messages are pure
functions (`detail::parse_gssapi_layer_offer`, `gssapi_layer_reply`),
unit tested without Kerberos. GSS-API handles (names, credentials,
context, buffers) are owned by small RAII types; `gssapi.h` stays out of
the public header (pimpl). `gss_acquire_cred` and every
`gss_init_sec_context` call run off the I/O thread (`offload_start`,
`offload_step`, above): with MIT krb5 the first one resolves the KDC
(DNS SRV, possibly canonicalizing the host) and sends the TGS-REQ,
with a fixed retry schedule (several passes over the KDCs, with
backoff), bounded in total only by `[libdefaults] request_timeout` (MIT
1.22 and later, default 0: no maximum; `kdc_timeout` and `max_retries`
are Heimdal's, MIT has neither), and its DNS lookups by `resolv.conf`'s
`timeout` and `attempts`; the bind's timeout and cancellation do not
interrupt that call, they stop waiting for it. `gss_unwrap` / `gss_wrap`
(local) stay on the I/O thread.
Failures are `client_errc::gssapi_failure`
(`cond::auth_failed`) with the call's name and `gss_display_status`'s
major and minor messages (sanitized, as server text is), never tokens.
Names are UTF-8, checked (well-formed, no control characters) and given
to GSS-API as is. Security layers (integrity, confidentiality: wrapping
every LDAP PDU) are not provided; TLS is the protection. Active Directory
notes: its "LDAP server signing requirements" policy, when it requires
signing, refuses no-layer SASL binds over plain LDAP
(strongerAuthRequired, 00002028), so use TLS there; its "LDAP channel
binding" policy, when "Always", refuses them over TLS too, since no
channel bindings (tls-server-end-point) are sent. Tested without a KDC
(the layer messages, input checks, GSS-API errors before anything is
sent) and end to end against slapd (cyrus-sasl's gssapi plugin) and a
throwaway MIT KDC (`tests/integration/run_kdc.sh`).

Referrals and continuation references are returned, never chased:
`error::referrals` and `search_stream::references()` keep the URIs as
sent; `url::parse_list()` / `reference_urls()` parse them, leaving out
those that are not LDAP URLs.

Paged search (step 6): `connection::search_paged(params, page_size)`
returns a `paged_search` that yields entries across pages, requesting the
next page with the server's cookie when one ends, until the cookie is
empty. A server that ignores the (non-critical) control returns
everything as one page, which works the same. Each page is a separate
search on the wire (its own message id and timeout). Destroying the
`paged_search` early abandons the current page if it is still running,
then sends RFC 2696's release (section 3): the same search with page size
0 and the last cookie the server returned (the current page's when its
SearchResultDone was already received, else the previous page's; none
while the first page runs). The destructor cannot wait, so the release is
fire-and-forget, like an AbandonRequest: it is queued and its id joins the
abandoned requests. Unlike an abandoned request it is always answered, so
its answer is counted as due: the reader runs until it arrives and drops
it, and `outstanding()` counts it meanwhile, so `start_tls()` waits for it
(RFC 4513 section 3.1.1: no outstanding responses). An abandoned request
is not counted, since it may never be answered. A due answer has the
deadline a page of the same search would have (`search_params::timeout`,
else `operation_timeout`; none without either): the release often follows
a page that timed out on a slow or hung server, and without a deadline
the reader would stay parked (`io_context::run()` would not return while
the connection lives) and StartTLS would wait forever. A watcher
coroutine sleeps until the earliest deadline (`corosio::timeout` on an
event, like an operation's wait) and runs only while a due answer has
one; on expiry the answer stops being counted, so the reader can stop and
StartTLS proceeds, but its entry stays among the abandoned requests, so a
late answer is still dropped (once the StartTLS response has arrived, it
would be bytes before the handshake, which close the connection). When
more than 1024 requests are listed, the oldest whose answer is not due is
forgotten first. Nothing is sent after the last page (empty cookie),
after an error that ended the search (the server's result, a malformed
paged results control, a connection error), during a StartTLS exchange,
or once the connection is closed; during a bind it is held until the
bind ends, like any request. After a timeout or cancellation (the page
was abandoned) or a next page that could not be sent, the last cookie is
kept and the destructor releases it (`capy::cond`, not
`ldap::cond::timeout`, decides: the latter also matches the server's
timeLimitExceeded, which ended the search). There is no awaitable
`release()`: the destructor does everything that needs no waiting, and
waiting for the server's answer would tell the caller nothing it could
act on.
`sync::connection::search_paged` keeps the `paged_search` on the I/O thread
and either reads every page or destroys it after an error, so it needs
nothing more.

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

(A value that fails to convert is `conversion_failed` for every shape.)

Value conversion is an extension point, like `std::formatter`:

```cpp
template<> struct jhetz::ldap::value_traits<my_type> {
    static ldap::result<my_type> decode(std::string_view raw);  // conversion_failed on bad input
    static std::string encode(const my_type &v);
};
```

Built-in: `std::string`, `std::pmr::string`, integers (decimal, range
checked), `bool` (TRUE / FALSE), `ldap::dn`, `ldap::binary`
(`std::vector<std::byte>`, a single binary value; `std::vector<ldap::binary>`
for several), `std::chrono::sys_seconds` (GeneralizedTime: every RFC 4517
form decodes — minutes and seconds optional, fractions of the last unit,
`Z` or an offset; it encodes as `YYYYMMDDHHMMSSZ`), and enums with an
`ldap::enum_names<E>` table. A `syntaxes` member for runtime validation
comes with #13.

Active Directory's Large Integer syntax (`1.2.840.113556.1.4.906`, `ad.hpp`)
holds FILETIME dates (accountExpires, pwdLastSet, lastLogonTimestamp,
lastLogon, badPasswordTime, lockoutTime: a signed 64-bit count of 100 ns
ticks since 1601-01-01 00:00:00 UTC, in decimal), intervals (maxPwdAge,
minPwdAge, lockoutDuration, lockOutObservationWindow: negative tick counts)
and counters (uSNChanged). The schema cannot tell them apart, so the member
type decides:

- `std::int64_t`: the raw number, for any 906 attribute.
- `ldap::ad::filetime_clock::time_point`: a date. `ad::filetime_clock` is a
  C++20 Clock (`rep` int64, period 100 ns, epoch 1601-01-01 UTC, not steady)
  with `to_sys` / `from_sys`, so `std::chrono::clock_cast` converts to
  `system_clock` (offset 11644473600 s) and on to `utc_clock`; a
  `zoned_time` is built from the `sys_time` it returns. `from_sys` rounds
  down to a tick. `std::chrono::file_clock` is not usable: its epoch and
  period are implementation-defined (libstdc++: 2174-01-01, nanoseconds).
  Values decode and encode as the plain tick count. 9223372036854775807 is
  `ad::never` (`time_point::max()`). 0 is tick 0 (`time_point{}`,
  1601-01-01, never a real AD date), which sorts before every date; its
  meaning depends on the attribute:
  - accountExpires: 0 and 9223372036854775807 both mean "never expires";
    `ad::is_never(t)` is true for either.
  - lastLogon, lastLogonTimestamp, badPasswordTime: 0 is "never
    happened". It sorts before every date, so a stale-account check
    `last_logon < cutoff` includes accounts that never logged on.
  - lockoutTime: 0 is "not currently locked out". AD writes 0 when an
    account is unlocked, so it does not mean "never locked out".
  - pwdLastSet: 0 equals `ad::pwd_must_change`.

  Date arithmetic on tick 0 stays defined for ordinary intervals, but not
  with `ad::forever`: `lockout_time - lockout_duration` overflows when
  lockoutDuration is `ad::forever` (see below).

  Values below -1 fail to decode (`conversion_failed`): AD writes no date
  before 1601, -1 is kept because it is the `ad::pwd_set_now` command (every
  constant decodes back), and below `time_point::min() + unix_epoch_offset`
  `to_sys` would overflow. So every decoded date converts; `ad::never` does
  too, to year 30828, which is no real date (test `ad::is_never` first).
  Converting is safe, arithmetic is not: decode accepts every date up to
  9223372036854775807, and adding or subtracting an interval from a date
  near the top of the range overflows like on any `std::chrono` value (an
  untrusted lockoutTime 9223372036854775806 minus a 30-minute
  lockoutDuration is undefined). Check `ad::is_never` / `ad::forever`
  first and keep the result in range.
  `to_sys` keeps 100 ns ticks: converting its result to nanoseconds
  (`system_clock::time_point`) overflows after 2262. `from_sys` is defined
  up to year 30828, which covers every `system_clock::time_point`.

  pwdLastSet takes two commands when written: `ad::pwd_must_change` (0,
  change at next logon) and `ad::pwd_set_now` (-1, AD stores the current
  time); they are plain tick counts, so the typed `replace<&T::m>(...)`
  writes them with no special case, and a pwdLastSet of 0 read back
  compares equal to `ad::pwd_must_change`.
- `ldap::ad::filetime_clock::duration`: an interval, sign kept (maxPwdAge
  -36288000000000 is `-days(42)`); `ad::forever` (`duration::min()`,
  -9223372036854775808) is "passwords never expire" / "locked until an
  administrator unlocks". Negating it, or subtracting it from a date
  (`lockout_time - lockout_duration`), overflows: test for `ad::forever`
  first.

Typed filters encode these like any value
(`filters::field<&user::account_expires>() <= t`); on an untyped attribute,
use `value_traits<ad::filetime_clock::time_point>::encode(t)`. AD compares
the numbers, so "never" as 0 sorts below every date: expired accounts are
`(&(accountExpires>=1)(accountExpires<=now))`. An equality filter on
`ad::never` encodes 9223372036854775807 only and misses accounts stored as
0: "never expires" is `expires == ad::never || expires == time_point{}`,
`(|(accountExpires=9223372036854775807)(accountExpires=0))`.

Usage (implemented, #9, `mapping.hpp` and `connection.hpp`):

```cpp
// Attribute list from the descriptor; filter narrowed to its object classes.
ldap::result<std::vector<person>> people = co_await conn.search_as<person>({.base = base, .filter = f});

co_await conn.modify<person>(dn, {
    ldap::replace<&person::mail>("new@example.org"),
    ldap::add<&person::member_of>(group_dn),
    ldap::remove<&person::mail>(),
});
co_await conn.add(dn, person{...});   // read_only fields skipped, objectClass written
auto f = ldap::filters::field<&person::uid_number>() >= 1000;   // typed value
ldap::result<person> p = ldap::decode<person>(entry);
```

The member is a template argument (`replace<&person::mail>(v)`), not a
function argument as first sketched (`replace(&person::mail, v)`): a member
pointer passed as an argument is a runtime value, so "not in the descriptor"
and "read_only" could not be compile errors.

Compile-time guarantees (all implemented, each with a compile test in
`tests/compile/`):
- the attribute list and names come only from the descriptor, and names
  are validated (`field<&T::m>("not valid!")` does not compile);
- every field of a descriptor belongs to the same struct;
- a member type without `value_traits` does not compile;
- a change to a member that is not in the descriptor is a `static_assert`;
- a change to a `read_only` member is a `static_assert`;
- the value type must match the member (`replace<&person::created>("x")`
  and `field<&person::uid_number>() == "x"` do not compile), and a
  single-valued member takes no range of values;
- changes of another struct cannot be passed to `modify<person>`;
- `add` needs `object_class(...)` or an `objectClass` member.

Errors name the entry and attribute: `search ou=people,dc=example,dc=org:
entry uid=b,ou=people,dc=example,dc=org: attribute uidNumber: not an
integer: "x"`. A mapping error fails `search_as` but not the connection.

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
| `ldap.client` | `ldap::client_errc` | codec: `decode_error`, `message_too_large`, `nesting_too_deep`, `unsupported_tag`, `unexpected_tag`, `integer_overflow`, `unsupported_operation`, `encode_error`; input: `invalid_filter`, `invalid_dn`, `invalid_attribute`, `invalid_url`; connection: `unexpected_response`, `not_connected`, `operation_in_progress`, `unauthenticated_bind`, `tls_required`, `no_password_method`, `gssapi_failure`, `security_layer_required`; mapping: `missing_attribute`, `too_many_values`, `conversion_failed`, `schema_mismatch`; facade: `would_deadlock` |
| system / TLS | from Corosio / Capy | `connection_refused`; `capy::error::timeout`, `canceled`, `stream_truncated`; TLS errors in the `corosio.openssl` category |

`error`'s strings are `std::pmr::string` but always on the default
resource, never an arena, even when decoding into one fails: errors outlive
the operation (they go up the stack and into logs) and are the cold path.
They use whatever the default resource is when they are built, so an
application that replaces the default resource must keep it alive as long
as its errors.

`message()` shows the server's text (diagnostic, matched DN, referrals)
sanitized: valid UTF-8 is kept, control characters (C0, DEL, C1), bidi
controls (Bidi_Control), U+2028/U+2029 and ill-formed UTF-8 become U+FFFD,
each string is cut at 256 bytes on a character boundary and at most 8
referrals are listed, so a hostile server cannot inject log lines, terminal
escapes or Trojan Source reordering, or make every message huge. The fields
keep the text exactly as sent. Server text the library quotes in a
`context` (a value that failed to convert, an entry's DN, a SCRAM server
error, a control type, an AddRequest attribute, the text
`attribute::parse` rejected, the root DSE's subschemaSubentry, an
attribute type's SYNTAX) gets the same treatment, cut at 64 or 256 bytes.
So does the DN an operation names (`search <base>`, `modify <DN>`, ...)
and a password modify's user: the caller's, but often a DN the server
returned. Likewise the host `connect()` quotes decoded (`resolve <host>`,
an ldapi:// `connect <path>`), and its encoded URL, cut: often a
referral's.

LDAP result code 0 (success) is not an `errc` value: a successful result is
the absence of an error.

`message()` is `<context>: <code's message> [<category>:<value>]` followed
by the server's parts, so the context says where and with what (operation,
entry DN, attribute, offending value), never the code's own text again: a
missing required attribute reads `entry uid=x,ou=people,dc=example,dc=org:
attribute uid: required attribute missing [ldap.client:7]`.

`matched_dn` and `referrals` stay strings, exactly as the server sent them
(decided in step 5a, instead of `std::optional<dn>` / `std::vector<url>` as
sketched above): a server's matchedDN or referral URI may not parse (servers
send odd DNs, and referral URIs with unknown critical extensions), and an
error must neither lose them nor fail to be built. Callers parse on demand
with `dn::parse` / `url::parse`. `dn.hpp` and `url.hpp` also include
`error.hpp` for `result<T>`, so the switch would need a header split.

Connection errors (step 5a, `client_errc`): `unexpected_response` (a
response with another message id or an operation that does not answer the
request), `not_connected` (closed by `unbind`, `close` or an earlier
failure, which the context names), `operation_in_progress` (the connection
is busy; nothing is queued), `unauthenticated_bind` (a name with an empty
password), `tls_required` (an Active Directory password change on a
connection without TLS), `no_password_method` (the root DSE advertises
no password-change method this library knows), `gssapi_failure` (a GSS-API
call failed in a SASL GSSAPI bind: the context quotes GSS-API's major and
minor status messages), `security_layer_required` (the server accepts a
SASL GSSAPI bind only with a security layer, which the client does not
provide). Server errors carry the operation as context
(`search ou=people,dc=example,dc=org`) and leave the connection usable;
transport and protocol errors close it.

**Error conditions (implemented, #15).** `ldap::cond` (category
`ldap.cond`, an `is_error_condition_enum`) groups codes by meaning across
categories, so callers write `if (r.error().code == ldap::cond::auth_failed)`.
Each code matches at most one condition; codes without a clear meaning for
a caller match none, deliberately (test them by exact code).

| Condition | `ldap.result` (`errc`) | `ldap.client` (`client_errc`) | system / Capy / TLS |
|---|---|---|---|
| `not_found` | `no_such_object`, `no_such_attribute` | | |
| `auth_failed` | `invalid_credentials`, `inappropriate_authentication`, `auth_method_not_supported` | `unauthenticated_bind`, `gssapi_failure` | |
| `timeout` | `time_limit_exceeded` | | `timed_out`, `capy::error::timeout` |
| `canceled` | | | `operation_canceled`, `capy::error::canceled` |
| `connection_lost` | | `not_connected` | `connection_reset`, `connection_aborted`, `broken_pipe`, `not_connected`; Capy `eof`, `stream_truncated` |
| `tls_failure` | | | any `corosio.openssl` (or `corosio.wolfssl`) code |
| `protocol_error` | `protocol_error` | `decode_error`, `message_too_large`, `nesting_too_deep`, `unsupported_tag`, `integer_overflow`, `unexpected_tag`, `unsupported_operation`, `unexpected_response` | |
| `busy_or_unavailable` | `busy`, `unavailable` | | `connection_refused`, `host_unreachable`, `network_unreachable`, `network_down` |
| `access_denied` | `insufficient_access_rights`, `stronger_auth_required`, `confidentiality_required` | `tls_required`, `security_layer_required` | `permission_denied` |
| `already_exists` | `entry_already_exists`, `attribute_or_value_exists` | | |
| `invalid_input` | `undefined_attribute_type`, `inappropriate_matching`, `constraint_violation`, `invalid_attribute_syntax`, `invalid_dn_syntax`, `naming_violation`, `object_class_violation` | `invalid_filter`, `invalid_dn`, `invalid_attribute`, `encode_error`, `invalid_url` | `invalid_argument`, `no_such_file_or_directory`, `not_a_directory`, `filename_too_long` (TLS configuration) |
| none | `operations_error`, `size_limit_exceeded`, `compare_false`, `compare_true`, `referral`, `admin_limit_exceeded`, `unavailable_critical_extension`, `sasl_bind_in_progress`, `alias_problem`, `alias_dereferencing_problem`, `unwilling_to_perform`, `loop_detect`, `not_allowed_on_non_leaf`, `not_allowed_on_rdn`, `object_class_mods_prohibited`, `affects_multiple_dsas`, `other`, `assertion_failed`, unknown codes | `missing_attribute`, `too_many_values`, `conversion_failed`, `schema_mismatch`, `would_deadlock`, `operation_in_progress`, `no_password_method` | everything else |

Choices worth knowing: `unauthenticated_bind` is `auth_failed` (an empty
password on a login form is a failed login); `stronger_auth_required` and
`confidentiality_required` are `access_denied` (the credentials may be fine,
the session is not good enough); `unwilling_to_perform` matches nothing
(servers use it for unrelated refusals); `size_limit_exceeded` matches
nothing (it comes with partial results); `operation_in_progress` matches
nothing (it is a usage error, not a busy server); file errors from TLS
configuration are `invalid_input`, not `not_found`, which is for directory
entries. System codes match through their generic condition, so both the
system and generic categories work. `jhetz::ldap` does not link Capy or
Corosio, so their codes are matched by category name (`boost.capy` values
`eof` = 1 and `stream_truncated` = 4; `canceled` and `timeout` already map
to generic conditions); a Capy upgrade that renumbers them must update
`error.cpp` (the net tests check the real eof, canceled, timeout and TLS codes).

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

Implemented (#13, `schema.hpp`): `parse_attribute_type` /
`parse_object_class` (a small RFC 4512 lexer: parentheses, quoted strings
with `\27` / `\5C` escapes, bare words; keywords without an argument are
known flags, every other keyword takes one value or a `( a $ b )` list).
Lenient with real servers (quoted OIDs as Active Directory sends them,
keywords in any case, no space before `)`); a definition whose OID is not
an OID, or whose `SYNTAX` is not a numeric OID with an optional `{len}` of
digits right after it (RFC 4512 `noidlen`: `1.2.3{64}`; it could never
match, and would put the server's text in a report), is skipped, and so is
one with a keyword that is not a keystring or `X-` extension name: a
`{len}` written apart from the OID (`1.2.3 {64}`, against the grammar;
OpenLDAP and Active Directory attach it) would otherwise be read as a
keyword taking the next one (`SINGLE-VALUE`) as its value.
NAMEs that are not descriptors are dropped (they could never be looked
up). `server_schema` indexes names and OIDs
case-insensitively, ignores attribute options on lookup and follows SUP for
the syntax (depth-limited against cycles). A member whose syntax cannot be
determined because a SUP on the chain is not defined, was skipped for its
SYNTAX, or loops is a `syntax_mismatch` error ("syntax unknown: ..."), not
a silent pass; the names of definitions skipped for their SYNTAX are
remembered, so a member mapped to one is told so rather than "not
defined on the server". The cardinality check is a
warning (`schema_issue::is_error() == false`), the others are errors.
Syntaxes per type come from `value_syntaxes<T>` (built in: integers →
INTEGER / NumericString, and also AD Large Integer
(`syntax::ad_large_integer`, 1.2.840.113556.1.4.906) for signed integers of
64 bits or more: a 32-bit or unsigned member could not hold its values, so
it gets a `syntax_mismatch` rather than a conversion failure on the first
large or negative value; `ad::filetime_clock` time points and durations →
AD Large Integer only; bool → Boolean, dn → DN / NameAndOptionalUID,
sys_seconds → GeneralizedTime; strings and binary accept any syntax), or a
`syntaxes` member of `value_traits<T>`. `connection::load_schema()` reads
the root DSE's `subschemaSubentry` (default `cn=Subschema`). The parser
has a fuzz target (`schema_fuzz`) with OpenLDAP and AD seeds.

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
ldap::sync::connection c{url};                     // owns an io_context + 1 I/O thread
auto people = c.search_as<person>({...});          // same request/result types
```

Implemented under it (step 4, `jhetz_ldap_net`, namespace `ldap::net`):
- `net::connect(ctx, url, connect_options, mr)` returns a `net::transport`
  over TCP, TLS or a Unix socket. One deadline (`timeout`, an
  `optional<milliseconds>`, default 30 s; `nullopt` = no limit; zero or
  negative fails at once) covers name lookup, every TCP attempt and the TLS
  handshake. The lookup runs detached so a slow DNS server cannot hold
  `connect` past the deadline (the io_context itself stays busy until the
  lookup thread returns). Several addresses are raced with Happy Eyeballs
  (RFC 8305, #18): families interleaved (first family first), each attempt
  started when the previous one fails or after `attempt_delay` (250 ms),
  the first connection wins and the others are cancelled (Capy's
  `when_any`, one socket per attempt). A black-holed address costs
  `attempt_delay`, not the budget. Errors name the stage:
  `connect ldaps://h:636: tls handshake: ...`, and for TCP the last
  failure with `(N of M addresses tried)`.
- Closing: `transport::close()` is immediate (no close_notify).
  `transport::shutdown(timeout)` sends close_notify and waits, bounded, for
  the peer's (#18); `connection::unbind()` uses it after the UnbindRequest
  is written and the reader has stopped, with
  `connection_options::tls_shutdown_timeout` (1 s), best effort.
  `transport::wrap()` owns the custom stream on the transport's resource and
  forwards `close()` / `cancel()` to it when the stream has them.
- IPv6: tested end to end over `[::1]` and over a link-local address with a
  zone (`[fe80::...%25eth0]`, skipped without one). glibc accepts a zone
  only on link-local and multicast addresses, so `[::1%25lo]` fails to
  resolve.
- TLS: verification is on by default (Corosio's own default is off), with
  the system trust store, SNI, host name checks (IP literals against iPAddress
  entries, zone stripped) and TLS 1.2 minimum. Options: `ca_file`, `ca_dir`,
  `ca_pem`, client `cert_file` + `key_file`, `server_name`; the only opt-out
  is `certificate_verification::insecure_accept_any`. Configuration errors
  (bad or mismatched PEM certificates and keys, missing `ca_dir`) fail before
  any network traffic. Host matching is strict by default (RFC 6125, RFC
  4513 section 3.1.3): subjectAltName DNS names only, no subject CN
  fallback, wildcards only as a whole leftmost label. Corosio has no option
  for OpenSSL's check flags, so our verify callback redoes the check on the
  leaf (X509_check_host with NEVER_CHECK_SUBJECT | NO_PARTIAL_WILDCARDS)
  after OpenSSL's lenient one; `tls_options::host_matching = legacy` keeps
  OpenSSL's defaults for old certificates.
  CA bundles are split by us because Corosio loads only the first
  certificate of a bundle (worth reporting upstream).
- StartTLS (implemented, step 7): `net::start_tls(transport, read_buffer,
  tls_options, timeout)` builds a reference-mode `openssl_stream` over the
  socket the transport owns, with the same `detail::make_tls_setup` /
  `detail::tls_handshake` as ldaps:// (the name checked is
  `server_name`, else the URL host the transport now records). It refuses
  a transport that is not plain TCP and a non-empty read buffer (bytes that
  arrived before the handshake were not protected: CVE-2011-0411).
  `connection::start_tls(options, timeout)` refuses at once while
  operations are outstanding, during a bind or a StartTLS exchange, or on
  a transport that is not plain TCP, waits (within `timeout`, cancellable;
  giving up sends nothing and keeps the connection) until no paged search
  release's answer is due and checks again (so of two StartTLS waiting,
  one is sent and the other refused), sends the ExtendedRequest and waits
  for its response within a fresh `timeout` (a wait that used most of the
  first would otherwise leave StartTLS to time out, which closes the
  connection; with the handshake's, start_tls may take up to three times
  `timeout`), blocks new requests until done (RFC 4511 section 4.14.1),
  waits for the reader and writer to stop, then upgrades. A refusal by
  the server leaves the connection usable in clear; injected bytes or a
  failed handshake close it. `connection::is_tls()` is true only once
  start_tls has succeeded, and only while the connection is open: it is
  false while start_tls runs, its handshake included (the transport holds
  the TLS layer from before the handshake, so `transport::is_tls()` alone
  would say true too early). A release's answer that comes after its
  deadline is dropped if it comes before the StartTLS response; after it,
  it counts as injected bytes (or breaks the handshake) and closes the
  connection.
  `connection_options::start_tls` makes `ldap::connect` upgrade right away
  (ldap:// only).
- `net::read_message` / `write_message`: rejects a PDU whose first octet is
  not SEQUENCE or whose declared size exceeds `read_options::max_message_size`
  (16 MiB) from the header alone; decodes with `origin::server`; a TLS close
  without close_notify between PDUs reads as a normal close. After any error
  the caller drops the connection (header errors repeat, they are not
  consumed). No timeout of its own: step 5 cancels with stop tokens.

Implemented (steps 5a and 5b, `ldap::connection`, also in `jhetz_ldap_net`):
- `ldap::connect(ioc, url, connection_options, mr)` wraps `net::connect`;
  `connection(ioc, net::transport, options, mr)` runs over any transport
  whose I/O runs on `ioc` (the tests use a Unix socket pair with a scripted
  server that decodes with `origin::client`). `simple_bind`, `search`,
  `search_stream`, `unbind`, `close()`.
- Multiplexed (5b): any number of operations outstanding, matched by
  message id. Ids are per connection, from 1, wrapping at maxInt; after a
  wrap, ids of outstanding or recently abandoned requests are skipped (RFC
  4511 section 4.1.1: the server may still be servicing them). A request
  that fails to encode sends nothing and does not use up an id. Sending is
  synchronous for the operation: it encodes, registers itself under its id
  (before the write, since the answer may come first) and queues the PDU.
- One writer coroutine drains the queue, one PDU at a time, so PDUs never
  interleave; it runs without a stop token, so a PDU is never cut in half.
  A single queue-draining writer does what an async mutex around each write
  would, without parking every operation in a mutex wait.
- One reader coroutine reads frames (`net::read_frame`), peeks at the
  message id and protocolOp tag (`peek_message_header`) and decodes the PDU
  straight into the memory resource of the operation it belongs to, so
  entries reach a caller's arena without a copy. It runs only while some
  operation is outstanding (or a paged search release's answer is due,
  until its deadline): when the last one finishes it is stopped through
  its stop token (bytes already received stay in the read buffer), so an
  idle connection holds no pending read and `io_context::run()` can
  return. A notice arriving while idle is seen by the next operation.
- Search responses are queued per search (on the search's resource) until
  its stream takes them. The queue is unbounded: a bound would make the
  reader wait for one slow consumer and stall every other operation, and a
  caller who waits on another operation before draining a stream would
  deadlock. Abandoning (destroying the stream) is the way to stop a search.
- Cancellation (5b): operations wait on a `capy::async_event`, wrapped in
  `corosio::timeout` when a deadline applies (`search_params::timeout`,
  else `connection_options::operation_timeout`; a search's deadline covers
  the whole search). A stop request or the deadline fails the operation
  with `capy::error::canceled` / `timeout` (`cond::canceled` / `cond::timeout`),
  unregisters it and queues an AbandonRequest. Abandon is best effort
  (RFC 4511 section 4.11): the server may have finished first, so an
  update (add, modify, delete, modify DN) that timed out, was stopped or
  lost a race (`raceable`, `with_stop`) may still have been applied;
  callers that need certainty re-read the entry. Late responses for the
  last 1024 abandoned requests are dropped (a search's until its
  SearchResultDone); a response for an id nobody waits for is a protocol
  error. A search_stream destroyed early abandons its search; a task
  destroyed while waiting abandons its operation (operations never wait on
  I/O themselves, so this is safe). Bind and StartTLS cannot be abandoned
  (RFC 4511 section 4.11): giving up on one closes the connection instead,
  since its outcome is unknown; so a bind or StartTLS whose stop token is
  already set when it starts is not sent at all (it fails with
  `capy::error::canceled`, the connection stays open).
- Cancelling from a coroutine (header-only helpers in `connection.hpp`):
  `capy::when_any` races only awaitables returning `io_result`, so
  `ldap::raceable(op)` makes an operation's `result<T>` the payload of one.
  Its error code is set only when the operation failed with
  `cond::canceled` while its stop token was set (it lost, or the awaiting
  task was stopped), so any completion, a server error included, wins and
  a cancelled operation never does. `ldap::with_stop(token, op)` awaits an
  operation with a fresh `std::stop_source` that both `token` and the
  caller's own token stop through `std::stop_callback`s; `capy::run(token)`
  alone would replace the caller's token. The stop callbacks run on the
  thread that requests the stop. What they reach: Capy's waits
  (`async_event`, `async_waker`), whose cancellation posts the resumption
  to the executor; the Corosio timer of `corosio::timeout` when the
  operation has a deadline (`operation_timeout`, `.timeout`, connect's
  timeout), cancelled under the timer service's own mutex and then posted;
  and, when `with_stop` wraps `ldap::connect()`, the sockets of the TCP
  connect and the ldaps:// TLS handshake, cancelled under Corosio's I/O
  lock (per descriptor on the reactors, the ring lock on io_uring). The
  resolver is not: the stop wakes the wait for the lookup, and
  `resolver::cancel()` then runs on the executor. An open connection's
  reader, writer and StartTLS handshake run under their own stop tokens.
  So a stop from any thread is safe only with Corosio's default
  `locking_mode::safe`. Under `unsafe_io` and `unsafe` the stop must come
  from the thread running the io_context: both tiers forbid a post from
  another thread (`unsafe` has no scheduler lock; `unsafe_io` drops the I/O
  locks, and on io_uring it also skips the eventfd wake, so a `run()`
  blocked in the ring never sees the posted resumption). Neither helper
  owns anything beyond its coroutine frame, which outlives the operation it
  awaits.
- Bind sequencing (RFC 4511 section 4.2.1: no PDU while a BindRequest is
  outstanding): a bind exchange (every step of a SASL bind) marks the
  connection as binding. Requests started meanwhile are encoded, registered
  and held, then sent in order when the exchange ends; one cancelled while
  held is dropped (never sent, so no AbandonRequest). Binds are serialized:
  a second one waits for the first. `unbind()` during a bind closes without
  an UnbindRequest; `start_tls()` during one is refused. `unbind()` once StartTLS
  is sent closes the same way (RFC 4511 section 4.14.1) and fails it.
- Every response is decoded with `origin::server` and checked against the
  request it answers (the operation, by id). IntermediateResponses are
  skipped without decoding; id 0 is an unsolicited notification: a Notice of
  Disconnection fails every outstanding operation with its result code
  (`unavailable` if it claims success) and closes the connection; other
  extended responses are ignored.
- Failure model: a server result error, an encode error, a cancellation or
  a timeout fails one operation and the connection stays usable (except a
  cancelled or timed-out Bind or StartTLS, which closes it). A
  transport error, a malformed or oversized PDU, an unexpected response or
  a Notice of Disconnection fails every outstanding operation exactly once
  (each with its own context) and closes the transport; the error is
  remembered, so later operations fail with `not_connected` naming it.
  `unbind()` fails the outstanding operations with `not_connected` (the
  server abandons them too), waits until the UnbindRequest is written even
  if cancelled, then closes. Nothing may follow the UnbindRequest (RFC 4511
  section 4.3): while it is written, the connection is still open but
  every new request, a StartTLS (including one whose wait for due answers
  ends then) and another `unbind()` fail with `not_connected`.
  An allocation that fails where no exception can go (a destructor sending
  an AbandonRequest or the requests a bind held; the writer, reader or due
  watcher task) closes the connection: what was to be sent or read is
  lost, and the outstanding operations fail with
  `std::errc::not_enough_memory` (remembered, like any failure). Elsewhere
  `std::bad_alloc` propagates from the operation's task; from StartTLS's
  handshake or its setup it first closes the connection the same way (the
  server expects a handshake, so the session cannot go on in clear). Known
  limitations, where an allocation failing ends the program:
  `capy::run_async` allocates its own frame in a `noexcept` constructor;
  `corosio::timeout` builds its timer (growing the timer heap) and starts
  its timeout coroutine (a frame) in `await_suspend`, which capy's task
  calls from a `noexcept` wrapper, so in every wait with a deadline (an
  operation's timeout, StartTLS's wait for due answers, the due watcher,
  and connect, the TLS handshake and the TLS shutdown with a deadline)
  those allocations failing end the program instead of throwing. The
  timeout awaitable's own `std::stop_source`, made before `await_suspend`,
  throws `std::bad_alloc` as usual: the due watcher catches it (and closes
  the connection), the operations let it propagate.
- Lifetime: the state is one reference-counted block on the connection's
  resource, held by the connection, each outstanding operation, each
  stream, and the reader and writer frames. Moving a connection or stream
  is a pointer move; destroying the connection closes it and the others
  finish with `not_connected` and release the block.
- Threading: everything runs on the executor of the connection's
  io_context (`connection::executor()`); from another thread, start the
  operation there (`capy::run_async(conn.executor())(task)`). The one
  exception is a SASL step a mechanism offloads (GSSAPI's calls to the
  KDC, section 3): it runs on a thread of its own and wakes the bind
  through the executor; the io_context counts it as outstanding work,
and its destructor joins the thread.

- Implemented (#12, `jhetz/ldap/sync.hpp`): `sync::connection` owns an
  io_context and one I/O thread (kept alive by a work guard). Each method
  posts a wrapper coroutine to that thread, which builds and awaits the
  matching `ldap::connection` operation, and the caller waits on a
  `std::promise` holding the same `ldap::result<T>` (an exception thrown
  by the operation is rethrown in the caller). The connection is touched
  only on the I/O thread, so any number of caller threads can share one
  `sync::connection`, their operations multiplexed. `result_future` from
  the (since removed) Corosio examples was not reused: it flattens errors
  to `std::error_code`, losing `ldap::error`'s diagnostic and context. The destructor closes the
  connection on the I/O thread, drops the work guard and joins, which
  waits for a detached getaddrinfo, or an offloaded SASL step (GSSAPI),
  still running; destroying the io_context then joins that step's
  thread. No connection pool yet.
- Calling a blocking method from inside the facade's own I/O thread would
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
- Benchmark (`bench`, GCC 16 Release; 1,000 SearchResultEntry PDUs of
  30 attributes x 3 values, every 20th with 68 KiB of binaries, 7.1 MiB):
  default heap 10.0 ms and 111.7 allocations per entry; per-message
  monotonic arena with a 256 KiB buffer 7.6 ms and 0 heap allocations.
  Decoding counts list elements first to reserve vectors exactly (a third
  fewer heap allocations); with the BER header fast path (#19) that costs
  nothing measurable, so it is unconditional.
- Decoded memory is bounded by `decode_options::max_elements` (decoded
  strings per message, 1,000,000 by default; `connection_options::
  max_elements`), not only by the PDU size: a 16 MiB PDU of empty values
  stops at 38 MiB instead of decoding to 320 MiB. Vectors are reserved
  within that budget too.

## 9. Toolchain

- C++23: `std::expected`, deducing `this`, `std::print`, the C++23 ranges
  additions.
- Compilers: GCC 16+; Clang 23+ with libstdc++ 16+ (CMake checks all three
  at configure time); MSVC 17.8+. No workarounds for older compilers.
- Corosio and Capy pinned by commit (FetchContent), used only by
  `jhetz_ldap_net` (option `JHETZ_LDAP_BUILD_NET`, off in fuzz builds);
  it also needs OpenSSL. The codec library `jhetz_ldap` has no dependencies.
- ICU (decision 6; `find_package(ICU COMPONENTS uc data)`) for Unicode
  normalization and the stringprep profiles. Today only `jhetz_ldap_net`
  links it (SASLprep for SCRAM), privately; the installed package config
  finds it as a dependency of `net`.
- Optional: the GSS-API library (MIT krb5) for SASL GSSAPI, with
  `JHETZ_LDAP_WITH_GSSAPI` (pkg-config `krb5-gssapi`), privately linked
  by `jhetz_ldap_net`. LDAPprep matching (RFC 4518) in the
  codec will make it a dependency of `jhetz_ldap` too.
- Coverage: Clang source-based coverage (`JHETZ_LDAP_COVERAGE`, llvm-cov),
  scoped to our own targets like the warnings; `tests/coverage/run_coverage.sh`
  runs it (README.md, "Coverage"). Local only, not in CI.
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
  with no values, a request with message id 0, which RFC 4511 section 4.1.1
  reserves for unsolicited notifications), and all checks run before any
  byte is written. The decoder rejects the same empty adds and id-0
  requests, so both sides accept the same messages.
  `decode(encode(m)) == m` exactly (filters are trees), and
  `encode(decode(encode(m)))` is byte-identical to `encode(m)`.
- `decode(bytes, decode_options)` takes exactly one framed message.
  `decode_options::from` restricts which side sent it (default `origin::any`,
  used by tests and round trips). The connection layer (step 5a) passes
  `origin::server` for everything it reads; it rejects request operations, so a hostile server
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

- Message size (#19): `max_message_size` stays 16 MiB (one entry of a
  large group, or with photos and certificates, can legitimately take
  several MiB); the decoded size is bounded separately by `max_elements`.

- Filters: a typed tree built by operators; only `filter::raw` parses (section 2).
- Descriptors: optional `object_class(...)` (section 4).
- Schema: minimal parsing (section 6).

## Open questions

- Per-search memory limits (across many entries) are left to the caller:
  `search_stream` hands entries over one at a time, and `max_message_size`
  with `max_elements` bound each one.

- Should `MUST` attributes of the declared object classes be checked against
  required (`T`) fields? Needs `MUST`/`MAY` parsing, so deferred.
