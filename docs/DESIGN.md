# LDAP client: API design

Status: implemented in this repository (codec, connection with multiplexing,
every RFC 4511 operation, StartTLS, SASL, typed mapping, runtime schema
checks, blocking facade, `ldapsearch`). The original roadmap (GitHub
tickets #2 to #20, done by 2026-10-07) and the pre-implementation API
sketch `api_prototype.cpp` were removed once finished; see the git history.
"Implemented" notes say where the code differs from the original plan.
Remaining work is tracked in beads (`bd list`).

Definition of done for a change: GCC 16 Debug with
`-DJHETZ_LDAP_SANITIZE=ON` (warnings are errors by default) builds without warnings
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
  a clear error. For attribute values the check is where they become text:
  the struct mapping decodes a value into `std::string` or
  `std::pmr::string` only if it is well-formed UTF-8, else
  `conversion_failed` ("not valid UTF-8 (ill-formed sequence at offset
  N)", N counted from 0, the value is not quoted), and `validate<T>`
  reports a string member on a binary syntax; the wire layer (`ldap::entry`,
  `partial_attribute`) keeps values as raw octets (section 10). Binary
  values (`ldap::binary`, `jpegPhoto`, `;binary`) and `\xx`-escaped octets
  stay raw bytes. Other server text is checked the same way where the API
  turns it into a string: `who_am_i()` fails with `conversion_failed` on
  an authzId that is not UTF-8 (an LDAPString), and a schema definition
  that is not UTF-8 (RFC 4512 qdstrings) is skipped like any other that
  does not parse. The genPasswd of `password_modify` is an OCTET STRING
  and stays raw.

## Decisions

| # | Topic | Decision |
|---|-------|----------|
| 1 | Struct ↔ entry mapping | Hand-written `constexpr` descriptor now; C++26 reflection later on a separate branch, same user-facing API |
| 2 | Errors | Rich `ldap::error` struct inside `std::expected` |
| 3 | Schema checking | Both compile-time (descriptor) and optional runtime validation against the server schema |
| 4 | Sync API | Async core; thin blocking facade in its own header (see below) |
| 5 | Language | C++23. A C++26 upgrade happens on a branch |
| 6 | Unicode | Full UTF-8; ICU (UTF-8 decoding, character properties, normalization, stringprep profiles) is the Unicode dependency, of the codec too: no hand-rolled Unicode code at run time |

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
  is `uid=x,<base>`), `rdns()`, `to_string()`. `operator==` is syntactic
  and stays so: attribute types case-insensitive, values exact after
  unescaping, AVA order inside a multi-valued RDN not significant, so
  `cn=A` ≠ `cn=a` there; no hash yet. Server-like comparison is explicit,
  in `matching.hpp` (below). Parsing is lenient like OpenLDAP: spaces
  around `,` `+` `=` are ignored and unescaped trailing spaces dropped.
- Matching rules (`matching.hpp`): RFC 4517 rules named after the RFC
  (`case_ignore_match`, `case_exact_match`, the IA5, numericString,
  telephoneNumber, ordering, substrings, integer, boolean, octetString,
  bitString, objectIdentifier, uniqueMember, generalizedTime (exact UTC
  instants, sharing mapping.cpp's GeneralizedTime parser through
  `src/generalized_time.hpp`), caseIgnoreList and RFC 4530 uuid rules,
  and `match(rule, value, assertion)` by NAME or OID) on values
  prepared by LDAPprep (RFC 4518, `prepare_string`): UTF-8 decoding, then
  ICU's RFC 4518 StringPrep profiles for map (with table B.2 case folding
  for the case-ignore rules), NFKC, prohibit (Unicode 3.2 unassigned, private
  use, non-characters, surrogates, table C.8; U+FFFD, which ICU's profiles
  let through, is checked by the library) and bidi (ignored), then the
  insignificant space, numericString or telephoneNumber handling of section
  2.6 (errata 1757 and 1758 applied), with Appendix A's combining marks.
  Results are `match_result` (TRUE, FALSE, Undefined): a value that fails
  preparation or the rule's syntax gives Undefined, never FALSE. Syntaxes
  are checked on the value as given, before preparation (an empty
  Directory String, a fullwidth digit in a Numeric String are Undefined).
  `distinguished_name_match(a, b)` (RFC 4517 section 4.2.15) compares DNs
  with each attribute's equality rule: caseIgnoreMatch for all, the server
  schema's EQUALITY (inherited through SUP), or a caller's per-attribute
  lookup (which must return text it does not own: a lookup returning a
  `std::string` by value does not compile), caseIgnoreMatch when none is
  known; `#hex` values are BER-decoded and transcoded (BMPString,
  UniversalString; INTEGER of any magnitude) first, and DN-valued AVAs are
  compared as DNs with the same rules (nesting bounded). Types are resolved
  to OIDs through the schema, then RFC 4519's names (`cn`, `commonName` and
  `2.5.4.3` are one type without a schema too); RDNs that differ only in a
  name nothing resolves are Undefined, not FALSE. Each RDN's AVAs are
  sorted by resolved type and merged, so a large multi-valued RDN costs
  n log n. `dn`'s `==` is not affected: it stays byte-exact, cheap and
  independent of a schema.
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
if (h) {
    f = std::move(f) && *h;
}

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

Controls are typed (`ldap::paged`, `ldap::server_side_sort`, …), with the
wire `ldap::control{type, criticality, value}` as the escape hatch. Each
operation takes only the typed controls its specification allows there:
`.controls` is a per-operation list (`search_controls`, `add_controls`, …),
so `pre_read` on an add does not compile.

The designated-initializer style above is for the step 5 request structs,
which stay aggregates. The wire model of section 10 is allocator-aware and
uses constructors instead (`message{1, search_request{base, scope, f, {"cn"}}}`).

Implemented (steps 5a and 6, `operations.hpp`): one aggregate per
operation — `search_params`, `add_params`, `modify_params` (changes built
with `ldap::mod::add / remove / replace / increment`), `del_params`,
`modify_dn_params` (`new_rdn` as an `ldap::rdn`, optional `new_superior`),
`compare_params`, `extended_params` — each with `.controls` and a
client-side `.timeout`. Values are checked when the request is encoded,
before anything is sent.

Typed controls (step 6, `controls.hpp`): `paged`, `manage_dsa_it`,
`relax_rules`, `proxied_authorization`, `server_side_sort`, `assertion`,
`pre_read`, `post_read`, `sync_request`, `matched_values`,
`virtual_list_view` and `transaction_specification`, plus the raw wire
`control {type, criticality, value}` as the escape hatch. Where each may be
sent is fixed by its specification, so it is checked at compile time
(goal 1) from one table, `control_rule_of<T>` (name, source, operations;
`applies_to<T>(operation_kind)` reads it):

| control | operations | source |
|---|---|---|
| `paged` | search | RFC 2696 section 2 |
| `server_side_sort` | search | RFC 2891 section 1.1 |
| `sync_request` | search | RFC 4533 section 2.2 |
| `matched_values` | search | RFC 3876 section 2 |
| `virtual_list_view` | search | draft-ietf-ldapext-ldapv3-vlv-09 section 6.1 |
| `pre_read` | modify, modify DN, delete | RFC 4527 section 3.1 |
| `post_read` | add, modify, modify DN | RFC 4527 section 3.2 |
| `relax_rules` | add, modify, modify DN, delete | draft-zeilenga-ldap-relax-03 section 2 |
| `transaction_specification` | add, modify, modify DN, delete | RFC 5805 section 2.2 (Password Modify too, but `extended_controls` is shared by every extended operation: a raw control there) |
| `assertion` | all but extended | RFC 4528 section 3 (other operations only where their document says how; RFC 3062 and RFC 4532 do not) |
| `manage_dsa_it` | all but extended | RFC 3296 section 3 (an extended operation only "for which the control is defined") |
| `proxied_authorization` | all seven | RFC 4370 section 3 (not StartTLS-like extensions) |
| raw `control` | all seven | the caller's responsibility, not checked |

The seven are search, add, modify, modify DN, delete, compare and extended
(`operation_kind`); bind takes no typed control, and `extended()` refuses
the StartTLS name (encode_error before sending; `start_tls()` sends no
control), so no typed control goes on StartTLS. A raw control is never
checked, even with the OID of a typed one (`pre_read_oid` on an add is
sent as given). Each params struct's
`.controls` is its operation's list, `search_controls`, `add_controls`,
`modify_controls`, `modify_dn_controls`, `del_controls`, `compare_controls`
or `extended_controls` (also `password_modify_params` and `who_am_i`): a
named struct deriving from `std::vector<std::variant<control, allowed...>>`,
so a misplaced control is a compile error naming the list. Static asserts in
the header check that each list holds exactly what the table allows, so
they cannot drift apart. A list built once for several operations is a
`request_controls` (a vector of `request_control`, every alternative), and
`controls_for<add_controls>(list)` converts it, failing with encode_error
("pre_read is not valid on add (RFC 4527 section 3.1)") instead. Rejected:
one variant everywhere with a run-time check before sending (smaller, but
misuse stays a run-time error). Each typed control has its own non-template
`to_control` overload; `append_controls` visits a list. Controls are encoded
on the connection's resource when the request is sent; an invalid one (a
sort without keys, an empty assertion filter) fails before anything is
sent.
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
- Matched values (RFC 3876): `matched_values{.values_return_filter,
  .critical}`, the ValuesReturnFilter as a `std::vector<ldap::filter>`,
  one filter per SimpleFilterItem. Reusing `ldap::filter` keeps one
  builder, parser and encoder for the assertion grammar: a
  SimpleFilterItem has the Filter CHOICE's tags, and its
  SimpleMatchingAssertion is a MatchingRuleAssertion without dnAttributes,
  so each item is written by `encode_filter`. What RFC 3876 excludes (and,
  or, not, dnAttributes) is refused when the control is encoded
  (invalid_filter "matched values: item 2 is (&...), not a simple filter
  item (RFC 3876 section 2)"), as is an empty item, and an empty list
  (encode_error: the ASN.1 allows one, but it would select no value at
  all, like `server_side_sort` without keys). A dedicated item type was
  rejected: it would duplicate the filter builders for no stronger check
  than the run-time one. `parse_values_return_filter()` reads the string
  form of RFC 3876 section 5 (`((mail=*@example.org)(cn=*))`, or one item
  alone), item by item with `filter::raw`, and `decode_matched_values()`
  reads the control back for mock servers (the items share one
  `max_filter_elements` budget). OpenLDAP implements it in slapd itself;
  it leaves out an attribute with no matching value, where RFC 3876 returns
  it with an empty set.
- Virtual List View (draft-ietf-ldapext-ldapv3-vlv-09):
  `virtual_list_view{.before_count, .after_count, .target, .context_id,
  .critical}`, the target a `std::variant` of `vlv_by_offset{.offset,
  .content_count}` and `vlv_greater_than_or_equal{.value}` (the CHOICE
  byOffset / greaterThanOrEqual; the default is offset 1 of an unknown
  count, the first entry). The contextID is a `std::optional<std::string>`:
  the server's value goes back unchanged, an empty one included. Section
  6.1 requires a sort control on the same SearchRequest, so
  `append_controls` refuses a typed `virtual_list_view` without a sort
  request control among the encoded ones (typed or raw), encode_error
  before sending; a raw VLV control is not checked, as raw controls never
  are. The SearchResultDone's VirtualListViewResponse is
  `find_vlv_response()` -> `vlv_response{target_position, content_count,
  result_code, context_id}` (the codec `encode_` / `decode_vlv_response`
  is in `message.hpp` next to the sort result one), and resultCode 76 is
  `errc::virtual_list_view_error` (section 6.2.1, no condition), whose
  reason is the response's `result_code`. Unknown virtualListViewResult
  values are kept: OpenLDAP 2.7 reports an offset beyond the list as 77,
  not offsetRangeError (61). There is no connection helper (a
  `search_paged`-like `search_vlv`): a window is one ordinary search,
  stateless on the client, and what a caller needs besides the entries is
  the response control, also when the search fails with 76, which
  `search_stream` already gives (`controls()` keeps the SearchResultDone's
  controls after an error); a helper would add a result type for no new
  behaviour. OpenLDAP's sssvlv keeps each list's state until the
  connection closes and refuses a new list past `sssvlv-maxperconn`
  (default 5) per connection with busy (51), so a client scrolling one
  list sends the contextID back.
- Transactions (RFC 5805): primitives first, a thin helper on top. The
  primitives are the typed control `transaction_specification{.identifier}`
  (always critical, section 2.2), `connection::start_transaction(controls)`
  -> `result<std::pmr::string>` (the identifier, section 2.1) and
  `end_transaction(identifier, commit = true)` ->
  `result<end_transaction_result>` (section 2.3), whose `updates_controls`
  are the decoded txnEndRes updatesControls, `{message_id, controls}` each,
  looked up with `find_update_controls(message_id)`. That id is the
  update's own: `response` gained `message_id` (breaking: `response` is no
  longer `{controls}` alone, so positional `response{controls}` must
  become `{.controls = ...}`), since a deferred update's pre-/post-read
  controls only come back at the End Transaction, matched by id. Decoding
  is strict where the RFC is: a Start or End Transaction response with a
  responseName, or a successful Start without an identifier, fails with
  decode_error; commit DEFAULT TRUE is left out when encoding and accepted
  either way. Section 4.4 makes proxied authorization on an update of a
  transaction a protocol error: `append_controls` refuses a typed
  `transaction_specification` next to a proxied authorization control
  (typed or raw) with encode_error before sending (it goes on Start
  Transaction instead); a raw control with the specification's OID is not
  checked there (the helper refuses it like a typed one). A refused End
  Transaction carries the server's
  code, its context naming the update at fault (txnEndRes.messageID, "end
  transaction: update message 5"); no structured field was added to
  `ldap::error` for it, as the helper reads the id itself. The helper,
  `ldap::transaction` (`transaction.hpp`, move-only, made
  by `connection::begin_transaction()`), is built only from those
  primitives: its `add` / `modify` / `del` / `modify_dn` append the control
  and record each accepted update's context by message id, so `commit()`
  (-> `commit_result`, i.e. `end_transaction_result`) names the failing
  operation ("commit transaction: update message 3 (modify DN uid=...)");
  `abort()` sends commit FALSE. Both settle the transaction (the API
  state) whatever the outcome, but the state keeps a separate "needs
  abort" flag, cleared only once the server answered an End Transaction:
  an End Transaction that was never sent (task stopped before it started,
  StartTLS in progress) or was given up on leaves the server's transaction
  alive, and OpenLDAP holds one per connection. Destroyed while that flag
  holds, it queues a fire-and-forget End Transaction (abort) on the writer
  queue, its answer counted as due and dropped like a paged search's
  release; `sync::transaction` aborts synchronously in its destructor
  instead (queued, from the I/O thread), racing the answer against a
  five-second delay so that it returns without a default timeout too.
  The helper counts its updates in flight and `commit()` refuses with
  `operation_in_progress` while any is: the End Transaction could
  otherwise reach the server before an update it should cover.
  The transaction state holds a counted reference to the connection's
  state (a pool lease can own it later, 3pf). Not in v1: routing the
  Aborted Transaction Notice (section 2.4; it is ignored like other
  unsolicited notifications, and the next use fails, section 3.3), and a
  `with_transaction(fn)` helper. A cancelled or timed-out update in a
  transaction may or may not be part of it, so the caller aborts; a commit
  whose answer is lost has an unknown outcome. The txnEndReq and txnEndRes
  codecs (`encode_` / `decode_end_transaction_request` / `_response`) are
  in `message.hpp` for mock servers and the message fuzzer. OpenLDAP 2.7's
  slapd supports transactions on back-mdb without configuration; the
  integration tests run them there.
- Pre-read / post-read (RFC 4527): `pre_read{.attributes}` on modify /
  delete / modify DN, `post_read{.attributes}` on add / modify / modify DN
  (sections 3.1 and 3.2: nothing to pre-read before an add, nothing to
  post-read after a delete);
  `find_pre_read()` / `find_post_read()` decode the returned
  SearchResultEntry into an `ldap::entry`, with the message decoder's
  depth and element limits.
- Content synchronization (RFC 4533, `content_sync.hpp`): the request
  control `sync_request{.mode, .cookie, .reload_hint, .critical = true}`
  (critical by default: RFC 4533 allows either, and a server without
  syncprov would otherwise run a plain search the caller would take for a
  sync); the Sync State control of each entry (`find_sync_state()` ->
  `sync_state{state, entry_uuid, cookie}`), the Sync Done control of the
  SearchResultDone (`find_sync_done()` -> `sync_done{cookie,
  refresh_deletes}`), and the Sync Info Message, an IntermediateResponse
  (`decode_sync_info()` -> `sync_info`). The four syncInfoValue
  alternatives are one flat `sync_info` with a `type`, not a
  `std::variant`: the cookie, which is what a consumer keeps, is in one
  place whatever the alternative, and the struct stays allocator-aware
  (a variant is not). Cookies are `std::optional`: RFC 4533 makes them
  OPTIONAL and an empty cookie is still sent. Defaults (reloadHint,
  refreshDone, refreshDeletes) are left out when encoding and accepted
  either way. `errc::e_sync_refresh_required` (4096) ends a sync search
  the server cannot continue, typically one whose cookie is too old to
  resume from (RFC 4533 section 3.8): the search is resent with the cookie
  of that SearchResultDone's Sync Done control if it has one (the stream
  keeps the controls of an error result), otherwise with no cookie, a full
  reload that replaces the local copy. See section 7 for the streaming
  side.

The response codecs (`encode_` / `decode_sort_result`,
`encode_` / `decode_vlv_response`, `encode_` / `decode_read_entry`) live
in `message.hpp` next to the paged
results one, so mock servers and the fuzzers use them too (the RFC 4533
ones are in `content_sync.hpp`, with the request control's decoder for
mock servers, and so are the matched values and VLV ones, in
`controls.hpp`).
Other request controls are only encoded (no decoder: the client never
reads them). Errors from
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
(the request's message id and the response controls) for add / modify /
delete / modify DN, `bool` for
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
connection_options.hpp), cached per connection and dropped by `start_tls()` like
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
transports), which GSSAPI needs for its default target, and
`can_offload`: false under `locking_mode::unsafe`, where an offloaded
step fails, so that a mechanism for which offloading is optional (SCRAM)
runs the step inline there rather than fail.

`start()`, `step()` and `complete()` run on the I/O thread. A mechanism
whose steps may block (GSSAPI: the KDC) overrides `offload_start()` /
`offload_step(challenge)`, which `sasl_bind` calls in their place: they
return a `sasl_work` (`std::move_only_function` returning the step's
`result<std::optional<std::string>>`), empty for "call start() / step()
here" (the default, so EXTERNAL is unchanged; SCRAM offloads only
its costly PBKDF2, below). Non-empty work
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
service of the io_context (`offload_threads`, `src/connection/sasl_offload.cpp`) owns
them and joins them in its `shutdown()`. Capy shuts services down, then
deletes them, newest first (`execution_context::shutdown()` /
`destroy()` walk a list that `use_service()` pushes onto the front), and
the io_context's constructor makes the scheduler (`Backend::construct`)
and the services it needs before any `offload_threads`: oldest first,
the timer service (which the scheduler's constructor makes), the
scheduler, the thread pool, then the services made on use, such as
`offload_threads`. So the join runs while the scheduler is alive and
nothing of the thread outlives the io_context. The cost:
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
authz_id)` or `(username, password, sasl_scram_options)`. `start()` sends the client-first-message with a fresh
18-byte random nonce; `step()` checks the server-first-message (the nonce
must extend ours, iteration count in [4096, `max_iterations`],
1'000'000 by default and configurable in `sasl_scram_options`, unknown
"m=" extensions refused), runs PBKDF2-HMAC-SHA-256 and returns the
client-final-message with the proof; PBKDF2's cost is the server's
choice (about 0.45 µs per iteration on a current x86-64 core: 2 ms at
4096, 0.45 s at 1'000'000), so above `offload_above_iterations` (16'384,
about 7 ms) `offload_step()` hands it to `sasl_bind` to run on a thread
of its own (coro-ldap-zzz). Up to it, a thread start (tens of µs) and the
two extra hops through the scheduler are not worth it, the common server
defaults (4096, cyrus-sasl's 10'000) stay inline, and with them binds
under `locking_mode::unsafe_io` (undetectable, where the offloaded
wakeup may be lost under io_uring); under `unsafe` (`can_offload` false)
PBKDF2 always runs inline, so SCRAM keeps working there. The offloaded
work owns a `shared_ptr` block (`derivation`: the prepared password
moved in, the salt, the count, the AuthMessage; out: the SaltedPassword
and the ServerSignature) and sets its atomic `done` (release) last; the
mechanism reads the outputs only once it sees `done` (acquire), in
`verify()` (the server signature) or the next `start()`, and otherwise
just drops its reference (a step `sasl_bind` gave up on runs on alone,
and its block is wiped by whoever releases it last). The SaltedPassword
is cached per (salt, iteration count) in the object, from either path, so
a rebind to the same server skips PBKDF2 (and needs no thread); it is
wiped when replaced and in the destructor, like the password it stands
for; `complete()` (or `step()`, when the
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
only passwords stored in SASLprep form match there. Channel binding
(RFC 5802 sections 6 and 7, below) is opt-in: by default the GS2 header
is "n,,", as before. Key material is
wiped with `OPENSSL_cleanse` (the password when the object is destroyed;
its prepared form, our preparation buffers and the derived keys as soon as
the proof is built, but the cached SaltedPassword; ICU's internal buffers cannot be). Server text quoted
in error contexts stays UTF-8: only control characters, ill-formed
sequences, the bidi controls (Bidi_Control: "Trojan Source" reordering)
and U+2028/U+2029 (line breaks in some log viewers) are replaced (U+FFFD),
and it is cut on a code point boundary. Contexts do not name the
mechanism (`sasl_bind` prefixes "sasl bind SCRAM-SHA-256"). Tested with the RFC 7677 vector and against
slapd with cyrus-sasl's scram plugin.

TLS channel bindings and SCRAM-SHA-256-PLUS (coro-ldap-cm2;
`channel_binding.hpp`, RFC 5056). Corosio's `openssl_stream` does not
expose its `SSL`, so `tls_handshake()` (src/net/tls.cpp) installs a
verify callback in both verification modes (in the insecure mode it
accepts everything, so that OpenSSL walks down to the leaf whatever is
wrong higher up) which records the session from the X509 store's
ex_data; once the handshake succeeded, `record_tls_session()`
(src/net/channel_binding.cpp) reads from it the peer certificate (DER),
tls-server-end-point (RFC 5929 section 4.1, hash from
`X509_get_signature_info`: MD5 and SHA-1 become SHA-256, no single hash
function (Ed25519, Ed448) means none) and tls-exporter (RFC 9266 section
2: `SSL_export_keying_material`, label "EXPORTER-Channel-Binding", a
zero-length context, which differs from no context in TLS 1.2, 32 bytes;
only on TLS 1.3 or with the extended master secret), and the pointer is
dropped. The bytes live in the transport's block (pmr vectors, cleared
with the TLS layer), and `transport::peer_certificate()` /
`channel_bindings()` and their `connection` counterparts return views,
empty unless `is_tls()`. Computing them eagerly costs a hash and an HKDF
per handshake and keeps no `SSL*` around. Default type: tls-exporter on
TLS 1.3 (RFC 9266 section 3); on TLS 1.2 tls-server-end-point (RFC 5802
names tls-unique, which this library does not implement: undefined for
TLS 1.3 and open to the triple handshake attack without the extended
master secret; tls-server-end-point is what servers support widely), or
tls-exporter when the certificate has no tls-server-end-point (Ed25519,
Ed448) and the extended master secret was negotiated. The
caller chooses the type with `sasl_scram_options::binding_type`.
`sasl_bind` passes `tls` and the bindings in `sasl_bind_context`;
`sasl_scram_sha256::prepare()` copies the chosen type's bytes (the
context is valid during the call only). RFC 9266 section 4.1:
tls-exporter MUST NOT be used for more than one authentication mechanism
instance on a TLS connection. Enforced fail-closed in `sasl_bind`: after
a successful `start()`, a mechanism whose `channel_binding_used()` (a
virtual of `sasl_mechanism`, last in its vtable) is tls_exporter, while
the bind was given tls-exporter data, sets `tls_exporter_used` in the transport's block,
whatever the bind's outcome (each attempt is an instance); later binds
get the bindings from `authentication_channel_bindings()`, with
tls-exporter empty and the default type tls-server-end-point or none, so
SCRAM-PLUS falls back to tls-server-end-point or fails `start()` with
`tls_required` before sending anything. The default
`channel_binding_used()` returns tls_exporter: a mechanism that reads the
bindings but does not say what it used (a third-party -PLUS mechanism, a
wrapper around `sasl_scram_sha256` that does not forward it) consumes
tls-exporter rather than bypass the rule. The library's mechanisms report
exactly what they used: SCRAM, with `scram_channel_binding::plus` once
`start()` succeeded, the type it actually bound to ("p=<type>": the
explicit `binding_type` option, or else the connection's default type),
nullopt otherwise;
EXTERNAL nullopt, GSSAPI tls-server-end-point when it sends channel
bindings (nullopt otherwise). The flag is cleared with the TLS
session (`clear_tls_session()`). `channel_bindings()` (transport and
connection) still reports tls-exporter: it describes the connection, and
the accessor is not an authentication; a caller that authenticates with
it by other means owns the rule. The GS2 flag comes from
`sasl_scram_options::channel_binding`: `none` ("n", default, unchanged
behaviour), `plus` (mechanism name SCRAM-SHA-256-PLUS, "p=<type>",
c= = base64(GS2 header + data); without TLS or data `start()` fails with
`client_errc::tls_required` before anything is sent and before the
password is prepared) and `not_offered` ("y" over TLS with binding data,
"n" otherwise): the client cannot learn the server's mechanisms inside
the mechanism (no I/O there), so the caller says what the server
advertised; `scram_channel_binding_for(supportedSASLMechanisms)` maps the
root DSE's list. Reading that list in clear is fine: a man in the middle
that removes -PLUS makes the client send "y", which a server supporting
-PLUS refuses (checked against slapd). OpenLDAP (libldap and slapd's
`sasl-cbinding`, 2.5 through 2.7) does not follow RFC 5802 here: its
cyrus-sasl channel binding is named "ldap" and its data is
"tls-server-end-point:<hash>" (RFC 5056's prefixed form, what GSS-API
takes), so slapd refuses "p=tls-server-end-point" ("Unsupported channel
bindings type") and expects "p=ldap,," with c= covering the prefixed
data; `sasl_scram_options::binding_form =
scram_channel_binding_form::openldap` is an opt-in for that form, the RFC
form stays the default. slapd knows tls-endpoint and tls-unique, not
tls-exporter, so the openldap form implies tls-server-end-point (an
explicit tls_exporter fails `start()` with `encode_error`), and its hash
follows libldap's `tlso_session_endpoint`: the digest named by the
signature algorithm's OID (`OBJ_find_sigid_algs`), SHA-256 when it names
none or a weak one, so SHA-256 for RSASSA-PSS, Ed25519 and Ed448, where
RFC 5929 takes the PSS hash or has none. `prepare()` computes it from
`sasl_bind_context::peer_certificate`
(`openldap_tls_server_end_point()`). Renegotiation: `record_tls_session()`
sets `SSL_OP_NO_RENEGOTIATION` on the session (a no-op on TLS 1.3), so a
server's TLS 1.2 HelloRequest gets a no_renegotiation alert; RFC 9266
section 4.2 leaves tls-exporter undefined where renegotiation is enabled,
and a renegotiation could change the certificate recorded at the
handshake. The session comes from the verify callback, which every
certificate-based handshake runs; a handshake that succeeded without it
fails (`client_errc::internal_error`, "the certificate verify callback
did not run") rather than go on without peer data, renegotiation
protection or, under full verification, the strict host check (no
deterministic test covers that branch: the race below cannot be forced,
and every certificate-based handshake runs the callback). Corosio
race (coro-ldap-cx0, to be reported upstream): `openssl_native_context`
allocates its process-wide SSL_CTX ex_data slot (`sni_ctx_data_index`)
lazily and unsynchronised when the first SSL_CTX is built, so two
threads handshaking for the first time at once can each allocate one;
the context whose slot lost then has no data, and Corosio's verify
trampoline skips our callback. `make_tls_setup()` first calls
`prime_corosio_openssl()` (src/net/tls.cpp), which runs one throwaway client handshake over a stream that fails at
once, on a thread of its own, which builds an SSL_CTX and so allocates
the slot before any of our contexts can; concurrent callers wait for it
under a mutex, and a warm-up that could not run (no thread) is retried by
the next caller.
Other threads of the process that use Corosio's OpenSSL streams directly
are not covered unless they call it too (the tests' threaded servers
do). Compatibility:
this applies to every ldaps:// and StartTLS connection, channel binding
used or not, so a server that renegotiates TLS 1.2 (e.g. to ask for a
client certificate after the handshake) fails the connection with an
error comparing equal to `cond::tls_failure`. The OpenSSL calls there and
in the end-point hashes bracket their work with `ERR_set_mark()` /
`ERR_pop_to_mark()`, so the application's thread error queue is left as
it was. GSSAPI channel bindings (coro-ldap-ipb, below) use the same
`sasl_bind_context::bindings` (tls-server-end-point, prefixed, as
`application_data`). Tested: the hash choice for ECDSA (SHA-224/256/384,
SHA-1), RSA (SHA-512, SHA-1, MD5), RSASSA-PSS (SHA-384), Ed25519;
deterministic SCRAM-PLUS exchanges with Python-computed values; ldaps://
against an in-process server (TLS 1.3 and 1.2) whose own SSL gives the
expected tls-exporter; slapd over ldaps:// and StartTLS.

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
and sequencing requested; channel bindings over TLS, below) until the
context is
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
binding" policy (LdapEnforceChannelBinding), when "Always", refuses them
over TLS without channel bindings. Channel bindings (coro-ldap-ipb):
`prepare()` computes the `gss_channel_bindings_struct`'s application data
once per bind (`detail::gssapi_channel_binding_data`, a pure function):
over TLS, "tls-server-end-point:" followed by the connection's RFC 5929
hash (`sasl_bind_context::bindings`, the hash SCRAM-PLUS uses), or with
`gssapi_channel_binding_form::openldap` OpenLDAP's hash of
`peer_certificate` (`openldap_tls_server_end_point()`, as SCRAM's openldap
form); the prefix is `prefixed_channel_binding()` (channel_binding.hpp,
RFC 5056 section 2.1: "channel bindings MUST start with the channel
binding unique prefix followed by a colon"). The addresses are
GSS_C_AF_UNSPEC and empty (RFC 2744 section 3.11), and every
`gss_init_sec_context` call of the exchange gets the same struct. Why
this form: Windows' clients pass Schannel's
SECPKG_ATTR_ENDPOINT_BINDINGS, whose data "begins with
tls-server-end-point:" (Microsoft's SEC_CHANNEL_BINDINGS documentation),
and AD checks that; OpenLDAP's libldap builds the same bytes
(`ldap_pvt_sasl_cbinding`, "tls-server-end-point:" + hash); OpenJDK's
JDK-8245527 (AD channel binding for JNDI/GSS) does the same. slapd does
not check them (coro-ldap-2hr): cyrus-sasl's gssapi plugin passes
GSS_C_NO_CHANNEL_BINDINGS to `gss_accept_sec_context` and
`gss_init_sec_context` in 2.1.28, its latest release (Arch's package
too); its unreleased master (commit 8735185, "don't enable GSSAPI
channel bindings by default") passes the SASL channel binding as
`application_data`, addresses zeroed, only when the security flags hold
SASL_SEC_NONSTD_CBIND (OpenLDAP's secprops `nonstdcbind`, compiled in
only against a sasl.h that defines it; Arch's libldap 2.7 does not know
it, and slapd refuses a `sasl-secprops` it cannot parse). That same
master's `mech_permitted` (lib/server.c, and lib/client.c on the client
side) refuses a mechanism whose plugin lacks a requested flag, and no
plugin declares SASL_SEC_NONSTD_CBIND, so, read from the sources, a
slapd with `nonstdcbind` offers no SASL mechanism at all (not run).
run_slapd.sh therefore does not set it, and no integration test can see
slapd refuse a wrong binding. The bindings are checked end to end against
an in-process MIT acceptor instead (`kerberos.channel_binding`, below).
Kerberos then carries the MD5 of the struct in the authenticator checksum
(RFC 4121 section 4.1.1.2). On by default (`gssapi_channel_binding::
tls_server_end_point`): an acceptor given no bindings (slapd, AD with the
policy "Never") ignores the client's, and the opt-out
`gssapi_channel_binding::none` is for a server whose acceptor holds
other bindings (a TLS-terminating proxy in front). No bindings without
TLS. Over TLS a connection without a tls-server-end-point hash fails
`start()` with `client_errc::tls_required` before anything is sent (as
SCRAM-PLUS, coro-ldap-2y3), never an unbound bind. The RFC form has no
hash for a certificate whose signature algorithm has no single hash
function (Ed25519, Ed448, ML-DSA and SLH-DSA in OpenSSL 3.5+) or that
OpenSSL does not know (`X509_get_signature_info` fails), the openldap
form none for a certificate it cannot parse or whose signature algorithm
`OBJ_find_sigid_algs` does not know, and neither when the server sent no
certificate. The certificate is chosen by whoever terminates TLS, so a
man in the middle that the certificate check let through could present
an Ed25519 one and relay the unbound AP-REQ, which an acceptor given
bindings still accepts (MIT accept_sec_context.c process_checksum and
Heimdal's _gsskrb5_verify_8003_checksum take an all-zero binding
checksum without KERB_AP_OPTIONS_CBT; AD with "When supported" too).
`none` is the explicit opt-out; there is no lenient "if available"
value, since a certificate without a hash is an EdDSA or post-quantum
one (`none`, or for EdDSA the openldap form, which hashes it with
SHA-256) or one OpenSSL cannot handle. Not tls-exporter: neither AD nor
slapd takes it for GSSAPI. With bindings the client also asserts them
(coro-ldap-52i): `gss_init_sec_context` gets GSS_C_CHANNEL_BOUND_FLAG
(2048, spelled out like the mechanism OID: MIT declares it in
gssapi_ext.h, which Heimdal lacks), and MIT krb5 1.19+
(init_sec_context.c, `cbt_flag` to AP_OPTS_CBT_FLAG) then puts
KERB_AP_OPTIONS_CBT in the authenticator, as krb5.conf's
`client_aware_channel_bindings` does for every request; Heimdal does the
same since 2024 (master), and older libraries mask the bit out. It is a
signal, not a protection: an acceptor refuses a wrong non-zero binding
with or without it (process_checksum, _gsskrb5_verify_8003_checksum;
checked with MIT 1.22), and it changes the outcome only for an initiator
that sends no bindings, which this one never asserts it for. On a match
AD and MIT report the context as channel bound (MIT sets
GSS_C_CHANNEL_BOUND_FLAG in the acceptor's `ret_flags`); an acceptor
given none ignores it, and `none` sends neither, so a server behind a
TLS-terminating proxy still binds. GSS-SPNEGO is not implemented (it
would take the same bindings: MIT passes them through SPNEGO since
1.19). Tested without a
KDC (the layer messages, input checks, GSS-API errors before anything is
sent, the bindings' bytes, `gss_init_sec_context` accepting the struct)
and end to end against slapd (cyrus-sasl's gssapi plugin, which ignores
the bindings: the binds over TLS only show that sending them does no
harm) and a throwaway MIT KDC (`tests/integration/run_kdc.sh`). The
bindings are checked end to end without slapd (`kerberos.channel_binding`,
under run_kdc.sh only, coro-ldap-oil): `start()`'s AP-REQ goes straight
to `gss_accept_sec_context`, which accepts it when given no bindings or
the same ones (then with GSS_C_CHANNEL_BOUND_FLAG in its `ret_flags`),
refuses it with GSS_S_BAD_BINDINGS when given others, and accepts
`none`'s while given bindings (no CBT asserted). Against AD itself it is
not tested (coro-ldap-c2u).

Referrals and continuation references are returned, never chased by a
connection: `error::referrals` and `search_stream::references()` keep the
URIs as sent; `url::parse_list()` / `reference_urls()` parse them, leaving
out those that are not LDAP URLs.

Referral chasing is opt-in (coro-ldap-d8n), in three layers:

- `referral_target(url, request)` (`referral.hpp`, the codec) builds the
  request that progresses an operation at a referral's target, for a search,
  a compare and each update; it sends nothing. RFC 4511 section 4.1.10: an
  absent DN, scope or filter keeps the original's. An empty DN
  (`ldap://host/`) counts as absent too: RFC 4516 section 3 defaults a
  missing DN to "", which 4.1.10 overrides; a referral to the root DSE
  makes no sense for these operations. The URL's attribute list is ignored (4.1.10 names
  only DN, scope and filter as taken from the URL). Section 4.5.3: a
  continuation reference must carry a DN (refused otherwise, since the
  original base would search the same subtree again elsewhere), and
  without a scope it keeps the original's ("the scope of the original
  Search request is assumed"; the server, which knows the search was
  singleLevel, is the one to write "base" in the URL). RFC 4516 section 2: a
  critical extension refuses the URL (none is implemented), others are
  ignored.
- `chase_search` / `chase_compare` (`referral_chase.hpp`, `jhetz::ldap_net`)
  run the operation on a connection and follow what it returned through a
  caller-supplied `referral_connector` (URL and depth to `connection *`;
  null skips): the library never decides on its own whom to trust or which
  credentials to present. One reference's URIs are alternatives (RFC
  4511: "any supported URI may be used"), tried in order until one is
  followed. A referral result is chased depth first, with fallback to the
  next alternative; continuation references breadth first and
  sequentially (no fan-out: one connection at a time, deterministic
  order). The hop limit defaults to 10, not lower: RFC 4511 requires a
  counting client to handle at least ten nested referrals. Loop detection
  is on (scheme, host in ASCII form, port, DN by distinguishedNameMatch,
  scope, filter), seeded with the origin's request when its `name()` is a
  URL, and checked before the connector is asked (RFC 4511: never contact
  the same server for the same request twice). The request's timeout is
  the budget of the whole chase: the connector's task runs under it
  (`corosio::timeout`, so a pending connect or setup bind is cancelled
  when it is spent) and each request to a target gets what is left after
  the connector returned. A server's references cost little to send, so
  the chase keeps its own cost per reference small: the queue holds the
  URIs and a shared pointer to the request that got them (built for a URI
  only when it is tried), once `max_targets` or the budget is spent the
  references still waiting are counted (`unlisted`) without being parsed,
  and the attempt list is capped (`max_attempts`). Results: every URI considered gets a
  `referral_attempt` (followed, skipped_policy, skipped_loop,
  limit_reached, unparseable, failed with the error). A continuation
  reference that cannot be followed never fails the search but clears
  `chased_search::complete` (partial results are never a plain success;
  one skipped only as a loop does not, its server already answered that
  search; loops are checked before `max_targets` and the budget, but
  references over `max_hops`, which are not parsed at all, and those left
  unexamined once the chase stopped clear it). A referral result that
  cannot be followed fails the call (the last failure, else the referral
  itself): there is nothing partial to return; the error's context counts
  the attempts' outcomes, the list itself is not returned. A cancellation stops the chase. Writes are never chased: a
  referral result means the update was not performed (4.1.10), and
  re-sending it elsewhere is the caller's decision (`referral_target`
  builds it).
- `make_same_policy_connector(ioc, origin, options, allowed_hosts, setup)`
  is the connector most callers want: ldapi:// refused (a server must not
  point the client at a local socket), hosts outside the allow-list
  refused (empty by default: nothing is followed until hosts are named; a
  name matches an entry or its subdomains, IP addresses only themselves,
  IDNs compared in ASCII form as RFC 4513 section 3.1.3.1 asks; a host
  with a decoded control, space, '%' or '/' is refused before any lookup),
  only the scheme's default port or the origin's unless an entry names the
  port (`host:port`, which allows it on the hosts the entry matches, its
  subdomains included: the setup's credentials go to whatever listens on the
  port a server names, so another port of an allowed host is opt-in), no TLS
  downgrade (a TLS origin makes ldap:// targets use StartTLS, and a failed
  StartTLS fails the URI), the certificate checked against the referred
  host (RFC 4513 section 3.1.3: `server_name` cleared, IDNs connected to
  in ASCII form), and binding only through the caller's `session_setup`
  (anonymous without one, the TLS client certificate of `options` left
  out too). Its connections are kept per server for later
  URIs and closed with the connector.

The pool's policy, `client_options::referrals` (3pf.1), is built on the
same pieces: see section 11, "Referrals". The plain types of a chase
(`referral_policy`, `referral_outcome`, `referral_attempt`,
`chased_search`, `chased_compare`) live in `referral.hpp` (codec) so that
`client.hpp` can name them; `referral_chase.hpp` includes `client.hpp`
for `session_setup`, so the other way round would be circular.

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

(A value that fails to convert is `conversion_failed` for every shape:
for `std::vector<T>` the first bad value fails the whole member. One bad
value fails the whole `decode<T>`, and so the whole `search_as<T>`: the
first entry that does not decode fails the call.)

Value conversion is an extension point, like `std::formatter`:

```cpp
template<> struct jhetz::ldap::value_traits<my_type> {
    static auto decode(std::string_view raw) -> ldap::result<my_type>;  // conversion_failed on bad input
    static auto encode(const my_type &v) -> std::string;               // or ldap::result<std::string>
};
```

`encode` returns `std::string` (or a type convertible to it) when every
value can be written, and `ldap::result<std::string>` when some cannot
(`encode_error`). Both forms satisfy `mapped_value<T>`, so a trait written
for the infallible form compiles unchanged; `detail::encode_value(v)`
normalizes either to `result<std::string>`, and the library calls only
that. A value that does not encode stops the typed write before anything
is sent:

- `replace / add / remove<&T::m>(v)` still return `change<T>`, so brace
  lists compose; its `wire` is a `result<modify_change>` holding the error,
  with the change as context (`replace mail: not valid UTF-8 (...)`).
  `modify<T>` returns the first such error, prefixed with `modify <dn>`,
  before the schema check and before sending.
- `to_attributes(value)` returns `result<std::pmr::vector<partial_attribute>>`
  (context `attribute mail`), and `add(dn, T)` returns its error prefixed
  with `add <dn>`, again before anything is sent.
- The typed filter operators (`==`, `>=`, `<=`, `approx`) keep returning
  `filter`: on an encode failure they return the empty filter, which is
  already poison (section 2: it stays empty through `&&`, `||` and `!`, and
  encoding it fails with `invalid_filter` before sending). There is no
  `result<filter>` overload; the encode error's text is not carried, only
  the failure.

This was a breaking change (coro-ldap-vcp): before it `encode` returned
`std::string` only, `to_attributes` returned the vector itself, and
`change<T>::wire` was a plain `modify_change`, so ill-formed UTF-8 in a
string member went to the server (which answered
`invalidAttributeSyntax`), an enum value without a name went out as its
number, and an out-of-range `sys_seconds` threw `std::out_of_range`.

Built-in: `std::string`, `std::pmr::string` (the value must be
well-formed UTF-8, RFC 3629 as RFC 4512's UTF8 rule: no overlong forms,
surrogates, code points above U+10FFFF, truncated sequences or stray
continuation octets, else `conversion_failed`; encoding checks the same
and fails with `encode_error`, "not valid UTF-8 (ill-formed sequence at
offset N)"), integers
(decimal, range checked), `bool` (TRUE / FALSE), `ldap::dn`, `ldap::binary`
(`std::vector<std::byte>`, a single binary value; `std::vector<ldap::binary>`
for several), `std::chrono::sys_seconds` (GeneralizedTime: every RFC 4517
form decodes — minutes and seconds optional, fractions of the last unit,
`Z` or an offset; it encodes as `YYYYMMDDHHMMSSZ`, and a time outside
years 0000-9999 is `encode_error`), and enums with an
`ldap::enum_names<E>` table (a value not in the table is `encode_error`,
so what is written always decodes back). The string, `sys_seconds` and
enum traits return `result<std::string>`; integers, `bool`, `dn`,
`binary` and the AD FILETIME traits return `std::string`. Map binary
attributes (userPassword and the
other Octet String attributes, jpegPhoto, userCertificate, objectGUID,
objectSid) to `ldap::binary`: a string member fails on their values, and
`validate<T>` reports it on a binary syntax (section 6).

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
use `value_traits<ad::filetime_clock::time_point>::encode(t)`, which returns
a plain `std::string` (every tick count encodes). AD compares
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
Encode errors read the same way: `modify uid=jdoe,ou=people,dc=example,dc=org:
replace mail: not valid UTF-8 (ill-formed sequence at offset 4)`, `add
uid=jdoe,...: attribute uid: ...`.


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
    auto message() const -> std::string; // everything above, human readable
};

template<class T> using result = std::expected<T, error>;
}
```

Error-code categories:

| Category | Enum | Examples |
|---|---|---|
| `ldap.result` | `ldap::errc` — RFC 4511 resultCode values, numbers kept | `invalid_credentials` (49), `no_such_object` (32), `size_limit_exceeded` (4) |
| `ldap.client` | `ldap::client_errc` | codec: `decode_error`, `message_too_large`, `nesting_too_deep`, `unsupported_tag`, `unexpected_tag`, `integer_overflow`, `unsupported_operation`, `encode_error`; input: `invalid_filter`, `invalid_dn`, `invalid_attribute`, `invalid_url`, `string_prep_failed`; connection: `unexpected_response`, `not_connected`, `not_sent`, `operation_in_progress`, `unauthenticated_bind`, `tls_required`, `no_password_method`, `gssapi_failure`, `security_layer_required`; mapping: `missing_attribute`, `too_many_values`, `conversion_failed`, `schema_mismatch`; facade: `would_deadlock`; environment: `internal_error` |
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
failure, which the context names), `not_sent` (the connection closed
before the request reached the writer: the server never saw it, see
"Sent or not" in section 7), `operation_in_progress` (the connection
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
| `connection_lost` | | `not_connected`, `not_sent` | `connection_reset`, `connection_aborted`, `broken_pipe`, `not_connected`; Capy `eof`, `stream_truncated` |
| `tls_failure` | | | any `corosio.openssl` (or `corosio.wolfssl`) code |
| `protocol_error` | `protocol_error` | `decode_error`, `message_too_large`, `nesting_too_deep`, `unsupported_tag`, `integer_overflow`, `unexpected_tag`, `unsupported_operation`, `unexpected_response` | |
| `busy_or_unavailable` | `busy`, `unavailable` | | `connection_refused`, `host_unreachable`, `network_unreachable`, `network_down` |
| `access_denied` | `insufficient_access_rights`, `stronger_auth_required`, `confidentiality_required` | `tls_required`, `security_layer_required` | `permission_denied` |
| `already_exists` | `entry_already_exists`, `attribute_or_value_exists` | | |
| `invalid_input` | `undefined_attribute_type`, `inappropriate_matching`, `constraint_violation`, `invalid_attribute_syntax`, `invalid_dn_syntax`, `naming_violation`, `object_class_violation` | `invalid_filter`, `invalid_dn`, `invalid_attribute`, `encode_error`, `invalid_url`, `string_prep_failed` | `invalid_argument`, `no_such_file_or_directory`, `not_a_directory`, `filename_too_long` (TLS configuration) |
| none | `operations_error`, `size_limit_exceeded`, `compare_false`, `compare_true`, `referral`, `admin_limit_exceeded`, `unavailable_critical_extension`, `sasl_bind_in_progress`, `alias_problem`, `alias_dereferencing_problem`, `unwilling_to_perform`, `loop_detect`, `not_allowed_on_non_leaf`, `not_allowed_on_rdn`, `object_class_mods_prohibited`, `affects_multiple_dsas`, `other`, `virtual_list_view_error`, `assertion_failed`, `e_sync_refresh_required`, unknown codes | `missing_attribute`, `too_many_values`, `conversion_failed`, `schema_mismatch`, `would_deadlock`, `operation_in_progress`, `no_password_method`, `internal_error` | everything else |

Choices worth knowing: `unauthenticated_bind` is `auth_failed` (an empty
password on a login form is a failed login); `stronger_auth_required` and
`confidentiality_required` are `access_denied` (the credentials may be fine,
the session is not good enough); `unwilling_to_perform` matches nothing
(servers use it for unrelated refusals); `size_limit_exceeded` matches
nothing (it comes with partial results); `operation_in_progress` matches
nothing (it is a usage error, not a busy server); `internal_error` (a
library the client uses failed: OpenSSL in SCRAM, ICU in SASLprep or
`ad_password_value`, e.g. out of memory or ICU data without the SASLprep
profile) matches nothing: it is neither the caller's input (`invalid_input`
would make an application prompt for the password again) nor the server's
doing, and no retry or fix is implied; file errors from TLS
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
- `attributeTypes`: `NAME` (all aliases), `SUP`, `EQUALITY`, `SYNTAX`,
  `SINGLE-VALUE`, `NO-USER-MODIFICATION`. `SUP` is followed to inherit
  `SYNTAX` and `EQUALITY`, because many common attributes (`cn`, `sn`, …)
  only declare `SUP name`. `EQUALITY` drives
  `distinguished_name_match(a, b, schema)` (section 1).
- `objectClasses`: `NAME` only.
- Everything else (`ORDERING`, `SUBSTR`, matching rule definitions,
  `MUST`/`MAY`, DIT content rules, extensions)
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
SYNTAX, or loops, or because no definition on the chain declares a SYNTAX
(against RFC 4512 4.1.2; slapd refuses one), is a `syntax_mismatch` error ("syntax unknown: ..."), not
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
sys_seconds → GeneralizedTime; binary accepts any syntax), or a
`syntaxes` member of `value_traits<T>`. A type that accepts any syntax
can refuse some with `value_rejected_syntaxes<T>`: `std::string` and
`std::pmr::string` refuse the binary syntaxes, whose values are octets
rather than UTF-8 text and would fail to decode (section 4). They are
Octet String (`syntax::octet_string`, 1.3.6.1.4.1.1466.115.121.1.40, the
syntax of userPassword), Fax (.23) and JPEG (.28) from RFC 4517,
Certificate (.8), Certificate List (.9) and Certificate Pair (.10) from
RFC 4523, and Audio (.4) and Binary (.5) from RFC 2252 (dropped by RFC
4517, still declared by servers). A string member on one of them is a
`syntax_mismatch` ("syntax ... is one the member's type refuses: its
values are binary, map the member to ldap::binary"); a string member
whose syntax cannot be determined is not reported. This is a breaking
change: string members used to pass validation on any syntax, so a
descriptor that maps userPassword to `std::string` now fails
`validate<T>` and `schema_check::on_first_use`; map it to `ldap::binary`. `connection::load_schema()` reads
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
  the system trust store (OpenSSL's; on Windows the filtered CryptoAPI ROOT
  store, copied into OpenSSL per connection: roots fetched on demand by
  AuthRoot are missed and a NotBefore date on serverAuth drops the root;
  CryptoAPI chain verification is coro-ldap-1q5), SNI, host name checks (IP literals against iPAddress
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
  since its outcome is unknown. No operation whose stop token is already
  set when it starts is sent at all: it fails with `capy::error::canceled`
  and the connection stays open (sending it would only abandon it at once,
  and an update might be applied). The check is right before the request
  is submitted (for a bind, after the wait for an earlier bind; later steps
  of a SASL exchange are sent, since the server waits for them; for a paged
  search, before each page). unbind() and AbandonRequests, which end or
  give up on work, and a paged search's release are sent regardless.
- Cancelling from a coroutine (header-only helpers in `cancel.hpp`):
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
  skipped without decoding unless the request opted in
  (`intermediate_responses` in `search_params` / `extended_params`): then
  they are decoded into the operation's resource and queued with its other
  responses (for `search_stream::next_item()` or
  `extended_result::intermediates`). Late ones to an abandoned request are
  dropped; only its final response ends the wait for them. Id 0 is an
  unsolicited notification: a Notice of
  Disconnection fails every outstanding operation with its result code
  (`unavailable` if it claims success) and closes the connection; other
  extended responses are ignored.
- Content synchronization (RFC 4533) is a thin layer over
  `search_stream::next_item()`, not a stream type of its own: the search
  carries a `sync_request` and `.intermediate_responses = true`, each
  `search_entry`'s controls give its Sync State (`find_sync_state()`),
  each `intermediate` is a Sync Info Message (`decode_sync_info()`), and
  `search_stream::controls()` gives the Sync Done at the end of a
  refreshOnly search. The codec functions are what a wrapper would call
  anyway, they work the same with a mock server, and the consumer (a
  cache, a replica) decides how to apply present / add / modify / delete
  and which cookie to persist; a typed-event wrapper can be added later
  without changing them. Two consequences of riding on an ordinary search:
  - Timeout: `search_params::timeout` covers the whole stream, and nullopt
    means the connection's `operation_timeout`, so a refreshAndPersist
    search would end at that deadline. `ldap::no_timeout`
    (`milliseconds::max()`) says "no limit for this operation" without
    changing what nullopt means; the deadline computations saturate (a
    timeout that would overflow the clock is no deadline), which makes
    `no_timeout` valid for every operation's `.timeout`, StartTLS and the
    connect, SASL and TLS shutdown timeouts too. Persist searches end by
    a stop token or by destroying the stream (an AbandonRequest).
  - Memory and backpressure: entries are decoded into the search's
    resource and queued on it until `next_item()` takes them. Nothing
    bounds that queue (a bound would stall every other operation on the
    connection, since one reader serves them all), so a consumer slower
    than the server's changes grows it, and a persist search on a
    `std::pmr::monotonic_buffer_resource` never gives anything back: give
    a long-lived persist search the default resource (or a pool resource),
    keep up with `next_item()`, and use an arena only for a refreshOnly
    search whose results die with it. `references()` also keeps every
    reference the search returns, for its whole life.
- Failure model: a server result error, an encode error, a cancellation or
  a timeout fails one operation and the connection stays usable (except a
  cancelled or timed-out Bind or StartTLS, which closes it). A
  transport error, a malformed or oversized PDU, an unexpected response or
  a Notice of Disconnection fails every outstanding operation exactly once
  (each with its own context) and closes the transport; the error is
  remembered, so later operations fail with `not_sent` naming it.
  Sent or not (for `ldap::client`'s retry rule, 3pf): each pending
  operation has a `sent` bit, set when the writer takes its PDU from the
  outbox (it may then have reached the server). An operation still queued
  in the outbox or held behind a bind when the connection closes, or
  refused by `submit` because it is closed already (StartTLS's checks too),
  fails with `client_errc::not_sent` instead of the failure's code, with the
  failure's context and diagnostic: the server never saw it, so an update
  may be retried elsewhere. `not_sent` matches `cond::connection_lost` like
  `not_connected`, so callers testing the condition are unaffected.
  A behaviour change of 3pf.2: a request held behind a bind when a Notice
  of Disconnection closes the connection used to fail with the notice's
  code (`unavailable` or `busy`, `cond::busy_or_unavailable`); it now
  fails with `not_sent` (`cond::connection_lost`). Requests the writer
  had taken keep the notice's code.
  Exceptions: an allocation failure stays `not_enough_memory`; `unbind()`'s
  abandoned operations get `not_connected` (their requests were written
  or queued before the UnbindRequest, which follows them out, so the
  server may have seen them); a default-constructed or moved-from
  connection keeps `not_connected`. An `unbind()` during a bind or
  StartTLS exchange sends nothing and just closes (below), so the requests
  held behind that bind fail with `not_sent`.
  `unbind()` fails the outstanding operations with `not_connected` (the
  server abandons them too), waits until the UnbindRequest is written even
  if cancelled, then closes. Nothing may follow the UnbindRequest (RFC 4511
  section 4.3): while it is written, the connection is still open but
  every new request and a StartTLS (including one whose wait for due
  answers ends then) fail with `not_sent`, another `unbind()` with
  `not_connected`.
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
  thread. The connection pool is `ldap::client` (section 11); its
  blocking facade is `sync::client` (section 11).
- The machinery is shared (3pf.5): `sync::detail::io_thread` (the
  io_context, the work guard, the thread, and `run(make_task)`, the
  post-and-wait with the would_deadlock check) and
  `sync::detail::connection_api<Derived>`, a CRTP base holding every
  blocking `connection` operation in terms of `Derived::call(make_task)`.
  `sync::connection` and `sync::lease` derive from it, so the two cannot
  drift apart; `sync::transaction` holds the `io_thread` it runs on (a
  `shared_ptr`, owning the client's core when made by a `sync::lease`,
  so that it cannot dangle once the lease and the client are gone, as a
  lease outliving its client cannot; not owning when made by a
  `sync::connection`, which it must not outlive).
- The noexcept paths that end objects of the I/O thread (the
  destructors of `sync::connection` and of the client's core,
  `sync::transaction`'s abort, `sync::lease::release()`) go through
  `io_thread::hand_over(make_task, what)` (3pf.18): if the post fails
  (out of memory) before `make_task` ran on the I/O thread, it writes
  `what` to stderr and terminates. Falling back to the calling thread
  would race the I/O thread on the `ldap::client` or `ldap::connection`
  (undefined behaviour), and joining with the connection still open
  would hang (its reader keeps the io_context busy). A failure once
  `make_task` ran is left to the I/O thread and ignored.
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
- Compilers: GCC 16+; Clang 23+ with libstdc++ 16+; MSVC 19.40+ (Visual
  Studio 2022 17.10), or clang-cl on that toolset (CMake checks each at
  configure time). No workarounds for older compilers.
- Platforms: Linux is tested. Windows is ported in the code only (no
  Windows build has run yet; docs/DEVELOPMENT.md, "Windows"): Winsock and
  AF_UNIX (Windows 10 1803+) through Corosio, the CryptoAPI ROOT store as
  the default trust anchors (`src/net/trust_store_win.cpp`, the only
  Windows-specific source; CMake picks it instead of
  `trust_store_default.cpp`), file names through `std::filesystem::path`.
  Linux only: abstract ldapi:// sockets, SASL GSSAPI (no SSPI), the
  integration tests, coverage and the fuzzers. `/WX` is off by default on
  MSVC and clang-cl until the first clean build (coro-ldap-2we). macOS is
  not supported.
- Corosio and Capy pinned by commit (FetchContent), used only by
  `jhetz_ldap_net` (option `JHETZ_LDAP_BUILD_NET`, off in fuzz builds);
  it also needs OpenSSL.
- ICU (decision 6; `find_package(ICU COMPONENTS uc data)`) for Unicode,
  linked privately by both libraries (the public headers do not include
  ICU's); the installed package config always finds it. The codec
  (`jhetz_ldap`) decodes and validates UTF-8 with it (`U8_NEXT`) and asks
  it for character properties (General_Category, Bidi_Control: what
  `ldap::error::message()` replaces); `jhetz_ldap_net` uses its stringprep
  (SASLprep for SCRAM). One hand-rolled piece is left on purpose: the
  UTF-8 check of compile-time DN literals (`detail::scan_dn` in constant
  evaluation, `constexpr_utf8_sequence_length` in attribute.hpp), since ICU's
  functions cannot run there and its `U8_NEXT` macro would need ICU's
  headers in the public ones; a test checks it answers as ICU does.
- Optional: the GSS-API library (MIT krb5) for SASL GSSAPI, with
  `JHETZ_LDAP_WITH_GSSAPI` (pkg-config `krb5-gssapi`), privately linked
  by `jhetz_ldap_net`.
- Coverage: Clang source-based coverage (`JHETZ_LDAP_COVERAGE`, llvm-cov),
  scoped to our own targets like the warnings; `tests/coverage/run_coverage.sh`
  runs it (docs/DEVELOPMENT.md, "Coverage"). Local only, not in CI.
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

## 11. Connection pool (`ldap::client`, implemented, 3pf)

`jhetz/ldap/client.hpp`, `src/client/client.cpp`. Decided 2026-10-25 (the
3pf notes); this section records what was built and the choices the
decision left open.

- One type, `ldap::client` (the name `naming-connection` reserved), built
  from `client_options{servers, connection, setup, max_connections = 1,
  idle_check = 60 s, probe_timeout = 5 s, max_lifetime, acquire_timeout =
  30 s, backoff, failback_after = 5 min, observer, referrals}` on one io_context,
  whose executor everything runs on, as for `connection`. Connections are
  opened lazily by `acquire()`, up to `max_connections`; nothing runs in
  the background (no timer keeps `io_context::run()` alive).
- **Leases share connections by default** (the open choice of the
  decision: "exclusive or shared"; the 3pf.6 review kept shared as the
  default and added exclusive). `acquire(acquire_options{.exclusive})
  -> task<result<lease>>`; a lease
  gives the whole `connection` API, and several leases may hold the same
  connection, their operations multiplexed on it. Why: the decision's
  default of one connection rests on multiplexing covering throughput,
  which exclusive leases would defeat (every concurrent task would queue
  for the one connection); and N connections are for isolation, which
  `acquire()` provides by preferring, in order, an idle connection (no
  lease; the highest-priority server, then the most recently used), a new
  connection while fewer than `max_connections` exist, and only then the
  open connection with the fewest leases. The price: what a lease changes
  on its connection, the others see. A bind changes their identity (hence
  the rule below), StartTLS fails with `operation_in_progress` while
  another lease has an operation outstanding, `unbind()` / `close()` end
  it for all; a failed bind silently drops them all to anonymous. Hence
  `acquire({.exclusive = true})`: an idle connection, else a new one
  while a slot is free, else it waits; no other acquire (shared or
  exclusive) gets that connection while the exclusive lease holds it.
  While an exclusive acquire waits (`client_state::exclusive_waiting`),
  shared acquires never take an idle connection: they share one already
  shared, else open a new one (a slot free, a server to try) or wait, so
  shared load cannot starve it (3pf.7; 3pf.9 for the case with no other
  shared connection, e.g. `max_connections = 1`). With every server
  excluded such a shared acquire waits too rather than fail while the
  idle connection exists (`waits_for_exclusive`), and an exclusive
  acquire that waited and ends without a lease (stopped, timed out,
  destroyed) calls `notify()`, so the shared ones it held back look
  again at once (3pf.11).
  Bind, `start_tls()` and `unbind()` belong on exclusive leases. The
  header says to use one client per identity and keep binds to the
  setup; per-identity sub-pools are a later bead. (`acquire()` is not a
  coroutine: it copies the shared state into the task, so the client may
  be moved or destroyed before the task runs.)
- Servers, in priority order. A connection attempt tries every server
  whose backoff has ended, in order. Connect, StartTLS (`connect` does it
  for `connection_options::start_tls`) and `session_setup` together are
  the attempt: any failure counts against the server. Backoff per server,
  full jitter: uniform in `[0, d]`, `d = min(max, initial *
  multiplier^(failures - 1))` (`detail::backoff_delay`; a multiplier below
  1 counts as 1), reset by a success. A failure episode counts once: an
  attempt that fails after a concurrent attempt to the same server
  recorded a failure since it began (`server_state::episode`) adds
  nothing to the backoff; a success bumps the episode too, and once the
  failures are reset any failure is recorded (3pf.7). `acquire()` loops:
  when no server can be tried, a shared acquire shares an open connection
  if there is one (3pf.7: sharing beats failing while servers back off,
  or after an auth failure while bound connections live), else it waits
  for the earliest backoff to end (or for a change: a connection pooled,
  returned, removed or closed, an attempt ending, `close()`; and, while
  it waits for a slot, the first `max_lifetime` expiry), bounded by
  `acquire_timeout`. A pooled connection reports its closing, however it
  happens, through `detail::set_close_hook` (a hook the connection runs
  once from `shut()`), so a waiter wakes when a leased connection dies.
  When the earliest backoff ends after the deadline it fails at once with
  the last error (or the backing-off server's last error, its context
  marked "backing off"). With no
  `acquire_timeout` it retries until it succeeds, is stopped, or the
  client closes. Nothing starts after the deadline: no attempt, no probe,
  and so no server is penalised for an acquire that ran out of time. An
  attempt or probe the deadline cuts short is excused (no backoff, no
  `on_connect`; the probed connection stays, no `on_probe`) only if it
  began with less than half of `acquire_timeout` left
  (`client_state::begun_late`): the acquire spent the rest waiting or on
  other servers. One that had more and still did not finish is the
  server's failure (backoff, `on_connect`) or the connection's (retired,
  `probe_failed`). 3pf.8: excusing every cut-short attempt (1d48497) let
  a hung primary block failover for ever, since the defaults (connect
  timeout 30 s = `acquire_timeout`, no `operation_timeout`) make the
  deadline fire first on every acquire; likewise a probe with
  `acquire_timeout < probe_timeout` was always cut short, so a dead idle
  connection was never replaced. The half is scale-free and leans to
  penalising: with `acquire_timeout` below the connect or operation
  timeouts, the first attempt of an acquire always counts. The one attempt
  let through after an authentication backoff (`auth_retry` in
  `try_servers`) that ends without the server's verdict on the
  credentials proves nothing about them: cut short (late or not), stopped
  by the acquire's stop token, or failed otherwise (`operation_timeout`
  on the bind, a reset). That backoff then starts again (auth delay,
  stored auth error kept, `auth_failures` unchanged; no `on_connect` when
  the attempt was excused or stopped), so a slow server or a caller
  bounding `acquire()` itself cannot turn the one-bind-per-backoff limit
  into one bind per acquire (3pf.10; 3pf.8 covered only an attempt cut
  short early). `on_retry` then gets the stored auth error, the reason
  the server backs off, not the cancellation or timeout that ended the
  bind: an observer classifying failures by cause sees an auth backoff,
  not a server fault (3pf.12). An acquire task destroyed (not stopped)
  during that bind restarts the backoff too, from the `try_servers`
  scope guard (`restart_auth_backoff`: noexcept, no observer hook,
  jitter failure taken as 1), so the next acquire does not bind again at
  once; so does `server_failed()` throwing for it (a throwing jitter
  source, an allocation): `settled` is set only once it has returned
  (3pf.15).
- `cond::invalid_input` (a bad URL, a setup that cannot work) excludes the
  server for the rest of that `acquire()`. `cond::auth_failed` does more,
  against a lockout storm (3pf.6): its backoff is `max(auth_failure_min =
  5 s, backoff_delay(..., 0.5 + 0.5 * jitter))` (equal jitter: never
  below half the cap); each server counts its auth failures
  (`server_state::auth_failures`), and an acquire that sees the count
  change since it began, or starts while the server backs off after an
  auth failure, excludes that server with the stored error. So
  concurrent acquires waiting for the failed attempt fail fast, and new
  ones fail at once, instead of binding again when the backoff ends; the
  first acquire after the backoff binds once, and while it runs
  (`server_state::auth_retrying`) the others fail with the stored error.
  A wrong password costs at most one bind per server per backoff period,
  plus, the first time, the attempts already in flight (up to
  `max_connections`). After the password is fixed on the server, the
  client's acquires still fail fast until the backoff ends (at least
  `auth_failure_min`). That limits the rate; a password that stays wrong
  can still lock an AD account in the end. Every server
  excluded: `acquire()` fails at once with the last (or stored) error.
- Return to the primary: an idle connection to a lower-priority server
  that is `failback_after` old, while a higher-priority server's backoff
  has ended (and that this acquire has not excluded), is closed when
  `acquire()` finds it, and the new attempt starts from the primary again
  (falling back again if it still fails).
  Only idle connections: closing a leased one would cut its operations,
  and keeping it retired would hold a slot with nothing to replace it.
- Health: `acquire()` first retires every connection, leased or not,
  found closed, re-bound (below) or older than `max_lifetime`, and drops
  the retired ones no lease holds; then it probes the idle connection it
  picked if unused for `idle_check` or longer: a root DSE base search for
  `1.1`, within `probe_timeout` (default 5 s; `no_timeout` for none)
  capped by what is left of `acquire_timeout`. An answer, a server error
  included, passes; a transport failure or timeout retires and replaces
  the connection. A connection is "unused" since its setup or its last
  lease's return. So under constant load an expired connection is
  replaced, not shared on for ever.
- Bind identity: `connection::bind_count()` (new, public: bind exchanges
  begun, whatever their outcome, since a failed bind leaves the connection
  anonymous) is recorded after the setup; once the count differs (a bind
  done, failed, or still in progress on some lease) the connection is
  retired (`disconnect_reason::rebound`): never handed out again, closed
  once its last lease returns.
- Retired connections (any reason) do not count against
  `max_connections`: a replacement opens at once, so the pool may hold
  more connections than the limit while retired ones drain. Counting them
  would let one lease sitting on a dead connection block every acquire
  until it returns.
- Leaving the pool: an open connection no lease holds is unbound by a
  detached `unbind()` task on the executor (so the server sees a clean
  UnbindRequest), one still leased (only at `close()`) is closed.
  `close()` (and the destructor) closes every pooled connection, leased
  ones included (their outstanding operations fail with `not_connected`,
  or `not_sent` for requests not yet written), stops the attempts in
  progress (each runs under its own stop source, `with_stop`) and the
  referral chases running (`chases_running`, their stop sources, 3pf.22:
  the chase fails with `not_connected` and is not retried, the authorizer
  is not asked again, and no referred server is connected to or set up
  after it; the connector re-checks the stop token after its chooser, so
  this holds when the authorizer itself calls `close()`), fails waiting
  and later `acquire()` calls with `not_connected`, and then drops the
  observer: no
  hook runs after `close()`, so the observer need only outlive it (a hook
  may itself call `close()`; acquire re-checks after each hook). Leases
  may outlive the client (they hold the shared state), but their
  connections are closed with it; they return to nothing. The detached
  unbind tasks may outlive the client and its leases: the memory
  resource must outlive the io_context's pending work. Once the
  io_context is stopped (`io_context::stopped()`: its `run()` returned,
  no `restart()` since), a connection leaving the pool is closed, not
  unbound (3pf.13): a task posted then would never run, and a client
  destroyed after `run()` returned (in `main()`, say) leaked it, its
  connection and socket (LeakSanitizer, `examples/pool.cpp` with the
  client in `main()`). Closed is what a `connection` or a
  `sync::connection` does when destroyed: no UnbindRequest, nothing left
  on the io_context. Unbinding cleanly at `close()` still works while
  the executor runs (from a task, as `examples/pool.cpp` does).
- `client_observer`: virtual hooks, no-ops by default, called
  synchronously on the executor: `on_connect(server, outcome)` after each
  attempt, `on_retry(server, error, delay)` when a server enters backoff,
  `on_disconnect(server, reason)` when a connection leaves the pool,
  `on_probe(server, outcome)`, `on_acquire_wait(waited)` once per acquire
  that had to wait. None after `close()`. No logging dependency.
- Setup helpers: `simple_bind_setup(dn, password)` and
  `sasl_bind_setup(factory, dn)`, the factory making a fresh mechanism per
  connection (a null one fails with `invalid_argument`, so the server is
  not retried in that acquire).
- Read forwarders (3pf.4): `client::search`, `search_stream`, `compare`
  and `who_am_i`, the `connection` names and shapes. Each acquires a
  shared lease, runs the operation, and retries once after
  `cond::connection_lost` (`not_sent` included) or
  `cond::busy_or_unavailable` (result codes busy and unavailable, a
  Notice of Disconnection). The retry runs on another connection: the
  failed one, if still open (busy, unavailable), is retired with the new
  `disconnect_reason::busy_or_unavailable`, so the retry's `acquire()`
  opens a new one even with `max_connections = 1`, where avoiding it
  without retiring it would leave nothing to retry on. After busy or
  unavailable the retry's `acquire()` also avoids that server (3pf.14),
  since a server-wide refusal (AD MaxActiveQueries, a backend down, a
  shutdown) would fail the same way after a reconnect and bind:
  `pick_avoiding` takes a connection to another server, else opens one
  while another server may be tried now (`try_servers` tries the avoided
  server last, `nth_server`), else falls back to `pick` with that server
  included. The avoidance is for that one acquire only: the server's
  backoff and failure count are untouched (it answered), and
  `should_fail_back` does not count it as a server to return to. With a
  single server the retry reconnects to it as before (slapd answers busy
  per connection, past `conn_max_pending`, so a fresh connection does
  help there). A lost connection is retried in the usual order.
  Anything else (a server result code, a timeout, a cancellation) and
  the retry's own outcome are returned as is; an `acquire()` failure is returned (each is bounded by
  `acquire_timeout`, so the worst case is two acquires plus two
  operation timeouts). `search` collects the entries before handing any
  over, so it is retried whatever it received. `search_stream` returns
  once the search has a first message or has ended
  (`detail::first_outcome`: waits on the pending op without taking the
  message, honouring the search's deadline and the stop token), retried
  only when the search failed retryably before any message; the stream
  then owns the lease (`search_stream::state::owner`, released after the
  abandon when the stream is destroyed), and errors from its `next()` are
  never retried, so nothing is retried once an entry may have been
  delivered. Cost: it waits for the first message, so a refreshAndPersist
  search with nothing to send returns at its first change. Writes and
  extended operations stay lease-only and are never retried by the
  client: one failing with `client_errc::not_sent` was never seen by the
  server (section 7, "Sent or not") and the caller may retry it. The
  observer has no hook for an operation's retry (the retirement shows as
  `on_disconnect`, a new connection as `on_connect`). Each call may land
  on any pooled connection, so connection-bound request controls (a
  paged-results cookie from an earlier page, anything tied to the
  session) need a lease (3pf.15).
- Tests (`tests/net/client_tests.cpp`): loopback servers each running one
  script per accepted connection; backoff on real delays of 30 to 60 ms
  with the jitter fixed by `detail::set_jitter` (tests only). One slapd
  test drops a connection through a relay and acquires again.
- Blocking facade (3pf.5, `jhetz/ldap/sync.hpp`): `sync::client(options,
  mr)` owns a `detail::client_core`, the `io_thread` (section 7) and the
  `ldap::client` made, used and destroyed on it, shared through a
  `shared_ptr` by the facade and its `sync::lease`s (each holding an
  aliasing pointer to the core's `io_thread`, its `ldap::lease`, touched
  only on that thread, and a copy of its server URL). `acquire()` and the
  read forwarders `search`, `compare`, `who_am_i` post to the I/O thread
  and wait, as `sync::connection` does; the retry is `ldap::client`'s.
  `sync::lease` exposes `sync::connection`'s operations
  (`detail::connection_api`) on the leased connection. No blocking
  `search_stream`: `sync::connection` has no blocking stream either.
  Lifetime: the destructor closes the `ldap::client` on the I/O thread
  and drops its share of the core. The last owner (the client, or the
  last lease alive) destroys the `ldap::client` there and joins: the
  work guard dropped, the detached unbinds of the idle connections run
  before `run()` returns, so destruction unbinds cleanly (the io_context
  is never stopped while the client lives: 3pf.13's close-instead path
  does not apply). A lease outliving its client therefore stays safe,
  like an `ldap::lease` outliving its `ldap::client`: its connection was
  closed (operations fail with `cond::connection_lost`), and destroying
  or releasing it later joins the thread. Rejected: making the client's
  destructor invalidate the leases (a registry and a lock, and a
  dangling `sync::lease` on a use after destruction), or forbidding
  leases to outlive the client (a crash for an easy mistake). `close()`
  from the I/O thread closes at once (it is not blocking there), so an
  observer hook or a coroutine on `executor()` may call it, and
  `connections()` reads the count at once there. The last owner of the
  core (the client, or the last lease or lease-made transaction) must not
  be destroyed on the I/O thread: it would join itself, and
  `io_thread::join()` terminates with a message on stderr instead of
  `std::thread::join()` throwing inside a noexcept destructor; the same
  holds for `sync::connection` (3pf.19). A non-last lease released or
  destroyed there returns its connection without waiting.
- Referrals (3pf.1): `client_options::referrals` (`referral_options{
  follow_referrals, follow_references, authorize, limits}`), off by
  default: an authorizer alone chases nothing, and the read forwarders
  behave as before (a referral result is an error, `search()` drops
  continuation references). Separate switches, because following
  continuation references sends the search to more servers on every call,
  while a referral result is one redirection of a call that would
  otherwise fail. With a switch on, `search()` and `compare()` run
  `detail::chase_search` / `chase_compare` (the free functions' code with
  `chase_settings`: the two switches and an `on_attempt` hook) on the
  shared lease; `client::chase_search()` / `chase_compare()` always do,
  and return the chase (`complete`, `referrals`, `unlisted`): `search()`
  returns only the entries, as `connection::search()` drops references,
  so the forwarder that hides partial results is the one that already
  did. A reference not followed because `follow_references` is off is
  counted in `unlisted` and clears `complete`, without an attempt entry
  or a parse.
  `authorize(referral_hop{target, depth, origin}) -> referral_binding
  {refuse, anonymous, same_setup}` decides per URI; empty refuses all.
  It is asked only for URLs that pass the connector's fixed rules (no
  ldapi://, a plausible host), and `same_setup` is the only way the
  client's credentials reach a referred server: its TLS client
  certificate (`tls.cert_file` / `key_file`) included, which an
  `anonymous` connection does not present (`referral_identity::
  client_certificate`, applied by `detail::referral_plan`), since a
  server may authenticate a TLS connection by its certificate alone
  (mutual TLS, certificate mapping, SASL EXTERNAL); the mapping is
  `detail::client_referral_identity`. `make_same_policy_connector` follows the same rule with its own setup
  (3pf.27, `detail::same_policy_identity`): its options' certificate is
  presented only when a setup is given, so an empty setup is anonymous at
  the TLS layer too, even with the origin's options passed as they are
  (the header's own example); a caller who wants the certificate alone
  (SASL EXTERNAL implied by TLS) passes a setup, `sasl_bind_setup` with
  EXTERNAL or `no_bind_setup()` (does nothing). `same_setup_for_domains(
  domains)` applies `make_same_policy_connector`'s allow-list rules
  (`detail::referral_server_allowed`, the port rule against the pooled
  connection's server). An enum rather than a returned setup: the
  identities a chase can use are the client's own or none, which keeps
  the "the library never forwards credentials on its own" rule easy to
  audit; another identity per domain is a later extension. The connector
  is `detail::make_policy_connector`, `make_same_policy_connector` with a
  chooser in place of the allow-list (both share the fixed rules, the
  TLS policy and the per-server reuse, keyed by server and binding), from
  `client_options::connection` and the pooled connection's `is_tls()`: no
  downgrade. Referred connections are per call, not pooled (the
  conservative choice): they are opened by the chase, set up as chosen,
  reused within it, and closed (no UnbindRequest) when it ends; `close()`
  stops the chases running (see "Leaving the pool": `not_connected`, not
  retried, no authorizer call or referred connection after it). Pooling
  them would mean pools per referred server and identity, with their own
  backoff and auth guard, for servers the client was never configured
  with; the cost of not doing so is a connect and bind per chase that
  reaches a server, and no backoff for a referred server refusing the
  credentials (bounded by `max_targets` per call). Retry: only a
  retryable failure of the pooled connection's own operation is retried
  (`chase_result::origin_failed`); a referred server's failure (busy
  there, a lost referred connection) or the chase's is returned as is,
  and the pooled connection is not retired for it (it answered). Writes:
  no `follow_writes` in v1. The client has no write forwarders (writes
  run on leases, whose `connection` returns a referral result as is), so
  a switch would have nothing to apply to; a referral result means the
  update was not performed (RFC 4511 4.1.10), and `referral_target(url,
  add_params ...)` builds the request for a caller who decides to resend
  it. `search_stream()` and `who_am_i()` never chase: a stream hands its
  references out as they come, and merging chased entries into it would
  change what `next()` means. `client_observer::on_referral(server,
  attempt)` is called for each attempt as it is decided (also beyond
  `max_attempts`), never for references left unexamined or switched off.
  `sync::client` mirrors `chase_search()` / `chase_compare()`; its
  `search()` and `compare()` chase through `ldap::client`'s.
- Later (beads): a background prober, DNS SRV, weighted or round-robin
  selection, per-identity sub-pools, pooled referred connections.

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
