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
  `std::expected` results, no exceptions for expected failures (the few
  left are listed in API.md "What throws").
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
ldap::url       server{"ldaps://ldap.example.org"};    // server URL literal: checked at compile time
auto            url = ldap::url::parse(user_text);     // result<url>

ldap::result<ldap::dn> d = ldap::dn::parse(user_text);  // runtime text: never throws
```

- `dn`: parsed RDN sequence (RFC 4514), `parent()`, `child(rdn)` /
  `child(dn)` (prepend one RDN or a relative DN: `base.child(ldap::rdn{"uid=x"})`
  is `uid=x,<base>`; `child(rdn)` is a `result<dn>`, as an RDN built from
  its AVAs can be invalid), `rdns()`, `to_string()`. `operator==` is syntactic
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
  The DN stays the text the server sent (RFC 4511 objectName);
  `parsed_dn()` gives the `ldap::dn` for a follow-up request.
- `url`: RFC 4516 (`ldap://`, `ldaps://`, `ldapi://`, IPv6 with RFC 6874
  zones, dn/attributes/scope/filter/extensions with the critical `!`).
  `parse(text, mr)` never throws; `to_string()` is canonical and
  `parse(to_string()) == *this`. Absent and empty dn/scope/filter are kept
  apart (referral chasing needs "absent = same as the original request").
  Allocator-aware (`std::pmr`), including its extensions. Server URLs
  (what `client_options::servers` holds) follow a server rule,
  `check_server()`: a non-empty host (or ldapi socket path) without
  control characters, a well-formed UTF-8 host (an ldapi path stays
  bytes), no critical extension, and no DN (an empty one
  aside), attributes, scope or filter. `parse_server(text, mr)` and
  `parse_servers(texts, mr)` (a range or braced list of strings; the
  error names the index) apply it after `parse`; the explicit literal
  `ldap::url{"ldaps://ldap.example.org"}` checks `scheme://host[:port]`
  (optional trailing `/`) at compile time, a subset of what
  `parse_server` takes. `net::connect` shares the host and extension half
  (`detail::check_server_address`) and ignores the DN and later parts, so
  `connect(ioc, "ldap://host/dc=x")` still works; the client checks every
  entry of `servers` when it is built, and a refused one makes every
  `acquire()` fail at once (a typo is not hidden until failover). Its
  `server_urls` takes the same servers as text, parsed with
  `parse_server` when the client is built and tried after `servers`; the
  client constructor never fails, so an unparsable one is reported the
  same way.
- `bytes`: not implemented; wire values are `std::pmr::string` holding raw
  octets (see section 10).
- Literals go through `consteval` helper types (`dn::literal`,
  `rdn::literal`, `attribute::literal`, `url::literal`) that run the same
  scanner as `parse()` (for `url`, a constexpr scanner accepting a subset
  of `parse_server()`), so an invalid literal is a compile error. A runtime
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
  `raw("cn=x") == raw("(cn=x)")`. Decoding BER (`testing::decode_filter`,
  section 10) rebuilds the exact tree.

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
which stay aggregates. The wire model of section 10 uses constructors
instead (`message{1, search_request{base, scope, f, {"cn"}}}`); its decoded
types are allocator-aware.

Implemented (steps 5a and 6, `operations.hpp`): one aggregate per
operation — `search_params`, `add_params`, `modify_params` (changes built
with `ldap::mod::add / remove / replace / increment`, from a braced list
or an `ldap::string_range` of values), `del_params`,
`modify_dn_params` (`new_rdn` as an `ldap::rdn`, optional `new_superior`),
`compare_params`, `extended_params` — each with `.controls` and a
client-side `.timeout`. Values are checked when the request is encoded,
before anything is sent.

`search_params::base` has no default: its type, `search_base`, is an
`ldap::dn` without a default constructor (implicitly made from one), so a
designated initializer that leaves `.base` out does not compile
(`compile/search_without_base.cpp`), and a search of the whole server names
the empty DN (`.base = ldap::dn{}`). An empty default with whole_subtree
scope searched the whole server whenever `.base` was forgotten; libldap,
UnboundID, go-ldap and .NET take the base as a required argument too. A
run-time refusal of an empty base was rejected: the empty DN is a valid
base (the root DSE, or a server whose naming context is ""), and the
compiler catches the omission earlier. `ldap::root_dse(attributes)` builds
the root DSE read (RFC 4512 section 5.1: the empty DN, base_object,
`(objectClass=*)`, `"*"` and `"+"` by default), so it stays one call:
`co_await c.search(ldap::root_dse({"namingContexts"}))`. The other
defaults stay (whole_subtree, `(objectClass=*)`).

`search()` returns a `search_result`: `entries`, `references` (the URIs of
the SearchResultReferences, unfollowed), then the SearchResultDone's
LDAPResult in RFC 4511's names (`result_code`, `matched_dn`,
`diagnostic_message`; its `referral` is empty on the codes returned) and
the done message's `controls` (paged results, sort result, ...). It is a
value for success and for sizeLimitExceeded, timeLimitExceeded and
adminLimitExceeded, the codes that end a search with part of its entries
(`is_success()` false), and an error for every other code. A size limit
is routine (Active Directory's MaxPageSize is 1000), and every library
compared keeps those entries (libldap returns LDAP_SIZELIMIT_EXCEEDED with
the entries in the result chain, go-ldap the partial SearchResult with
the error, UnboundID `LDAPSearchException.getSearchEntries()`, .NET
`DirectoryOperationException.Response`); returning the limit codes as an
error lost them. Alternatives rejected: the partial entries inside the
error (an `ldap::error` would carry entries for one operation only), and
a success with a flag (the result code, matched DN and diagnostic would be
lost). The same holds for a repository's `search` (`typed_search_result<record<T>>`,
the same fields with `std::vector` entries), `client::search`, the sync
facades' `search` and `search_paged` (the pages collected: the last
page's done), and `chase_search` (the done fields are the origin's or
the referral target's, and when that is success the result code,
matched DN and diagnostic of the first followed continuation reference
whose search ended with a limit code, the controls staying the
origin's; any search of the chase ending with a limit code, the
origin's included, keeps its entries, and `is_complete()` is false). The streams (`search_stream`, `paged_search`) are
unchanged: `next()` reports the code as an error after the entries it
already handed out.

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
  alone), item by item with `filter::raw`, and
  `testing::decode_matched_values()` reads the control back (the items
  share one `max_filter_elements` budget). OpenLDAP implements it in slapd itself;
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
  result_code, context_id}` (`decode_vlv_response` is in `message.hpp`
  next to the sort result one), and resultCode 76 is
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
  (always critical, section 2.2), the non-members
  `ldap::start_transaction(connection &, controls)` -> `result<std::string>`
  (the identifier, section 2.1) and
  `ldap::end_transaction(connection &, identifier, commit = true)` ->
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
  `ldap::error` for it, as the helper reads the id itself. The primitives
  are non-members beside the helper, not connection members, so the
  connection lists one transaction API. The helper,
  `ldap::transaction` (`transaction.hpp`, move-only, made
  by the static `transaction::begin(connection &, extended_controls)`), is built only from those
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
  Start Transaction (`start_exchange`, used by `transaction::begin` and
  `start_transaction`) first waits for the answers due
  (`core::wait_due_answers`, StartTLS's mechanism, no counter of its own)
  within the default timeout, then sends anyway: slapd 2.6.10 answered
  busy (51) "Too many transactions" to about one Start in 50 sent right
  after a destroyed transaction, whose abort it had not processed yet. The
  wait also covers a destroyed paged search's release, one round trip.
  On a timeout a busy is then a real error. The entry point is a static
  factory on the class rather than a constructor: an async constructor
  cannot co_await, so `transaction t(conn)` would need a lazy start (the
  Start sent inside the first update: hidden I/O, an identifier the caller
  never sees leaked when that update times out, identity drift across a
  bind) or a two-step `t.begin()` with a not-started state to check; an
  `in_transaction(conn, fn)` helper was rejected too (a coroutine lambda
  capturing by reference dangles, it needs a sync twin, and it saves one
  `co_await t.commit()`). `connection::begin_transaction()` was removed
  so there is one spelling.
  The helper counts its updates in flight and `commit()` refuses with
  `operation_in_progress` while any is: the End Transaction could
  otherwise reach the server before an update it should cover.
  The transaction state holds a counted reference to the connection's
  state (a pool lease can own it later, 3pf). Not in v1: routing the
  Aborted Transaction Notice (section 2.4; it is ignored like other
  unsolicited notifications, and the next use fails, section 3.3), and a
  `with_transaction(fn)` helper. A cancelled or timed-out update in a
  transaction may or may not be part of it, so the caller aborts; a commit
  whose answer is lost has an unknown outcome. The client's txnEndReq
  encoder and txnEndRes decoder are in `message.hpp`, the server's
  halves in the testing target (section 10). OpenLDAP 2.7's
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

The response control decoders (`decode_sort_result`,
`decode_vlv_response`, `decode_read_entry`) live in `message.hpp` next
to the paged results one (the RFC 4533 ones are in `content_sync.hpp`).
Request controls are only encoded: the client never reads them. A
server's side (their encoders, and the decoders of the matched values,
VLV, Transaction Specification, Sync Request and DirSync request
controls) is in the testing target (section 10). Errors from
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
(the request's message id, the LDAPResult's matchedDN and
diagnosticMessage, which a server may use for a warning on success, and
the response controls) for add / modify /
delete / modify DN, `compare_result` for
compare (the same LDAPResult tail and controls, and the referral chase's
report, empty where nothing chases: one result type for compare on
connection, client, chase_compare and the sync facades, so compare is part
of the `directory` concept), `extended_result` for extended operations; the free
`ldap::who_am_i()` (RFC 4532) returns the authzId string, and
`ldap::password_modify()` (RFC 3062) the generated password, if any
(passwords never appear in error contexts).
Any other result code is an error. compareTrue /
compareFalse map to `compare_result::value` `true` / `false` (a compare answered with success is
an error: it is not a valid answer). referral (10) is an error with the
URIs in `error::referrals`; saslBindInProgress (14) is an error for a
simple bind and the "continue" signal of `sasl_bind` (#11).

Layering (coro-ldap-aw4): `connection`, `client` and the sync facades
keep only the protocol operations. Who am I? and Password Modify, with
`change_password()` / `reset_password()` over it, are free functions over
`ldap::extended_directory` (extended_operations.hpp), written once for
every source; their requests and results are I/O-free steps in `detail`.
The blocking forms (sync_extended_operations.hpp) run these same
functions on the facade's I/O thread with `sync::run` (section 7). The
transactions stay members: a refused End Transaction's txnEndRes (the
update at fault) never reaches the public `extended()`, which turns any
other result code into an error, and the transaction's abort on
destruction needs the internal fire-and-forget send.
`change_password()` / `reset_password()` are RFC 3062 only: conveniences
over `password_modify()` (the user as userIdentity, nothing generated),
next to it and not instead of it. Active Directory's `unicodePwd` Modify is
`ad::change_password()` / `ad::reset_password()` in the AD layer (section
12). The call picks the protocol; nothing reads the root DSE to choose, so
there is no method option, no per-connection cache and no "no method"
error. Tested against the scripted mock (`tests/net/password_tests.cpp`)
and slapd (`integration`). The copies the library makes are wiped
(`detail::wipe_string` and `wipe_vector`, src/wipe_util.hpp, volatile
stores so that the codec needs no OpenSSL) before they are freed: the
by-value password parameters in the coroutine frames (the detail
requests take the caller's strings by reference and wipe them, so a
moved-from short string leaves nothing behind), the Password Modify
encoder's buffer (reserved once so that it does not reallocate), the
request message (`request_response` wipes a simple bind's password,
Password Modify's value and the `unicodePwd` / `userPassword` values of a
ModifyRequest, also on paths that never send it) and the encoded PDU
(`detail::pdu_bytes`, wiped when the writer is done with it or the queue
drops it). The caller's strings, a generated password, OpenSSL's record
buffers and a SASL security layer's wrapped output are out of reach.

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
the scheduler, the thread pool, then the services made on use, such as
the timer service (made with the first timer) and `offload_threads`. So
the join runs while the scheduler is alive and nothing of the thread
outlives the io_context. The cost:
destroying the io_context (and so `sync::connection`'s destructor)
waits for a step still running, as long as krb5's own timeouts. A
thread that has ended is joined when the next one starts, so they do
not pile up. The posts from the worker need the scheduler lock
(Corosio's default `locking_mode::safe`, or `unsafe_io`): under `unsafe` (no scheduler
locking) `run_offloaded` fails with `std::errc::operation_not_supported`
before starting the thread, as Corosio's resolver does
(`detail::scheduler::scheduler_locking_disabled()`); `unsafe_io` keeps
scheduler locking, which is all the worker's post and work-guard release
need, and Corosio wakes a `run()` blocked in epoll or io_uring for it
(tested on both backends: `sasl: offloaded steps under
locking_mode::unsafe_io`), so offloading works there as under `safe`. A thread per call rather than a
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

SCRAM-SHA-256 (`sasl_scram.hpp`, RFC 5802 / RFC 7677, in jhetz::ldap
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
defaults (4096, cyrus-sasl's 10'000) stay inline; under `unsafe_io` an
offloaded PBKDF2 works as under `safe`; under `unsafe` (`can_offload` false)
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
(RFC 5802 sections 6 and 7, below) is opt-in: by default
(`not_offered`) the GS2 header is "y,," over TLS with binding data, so
that a -PLUS server detects a stripped -PLUS, and "n,," otherwise. Key material is
wiped (the password when the object is destroyed;
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

GSSAPI (`sasl_gssapi.hpp`, RFC 4752, Kerberos V5; in jhetz::ldap only
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
max size); the client answers with the layer it selects
(`detail::gssapi_select_layer` for `sasl_gssapi_options::security_layer`,
default none), its maximum buffer size (0 without a layer, else
`max_receive_size`), then the authz_id, wrapped without confidentiality
(`gss_wrap`, conf_flag 0), as RFC 4752 section 3.1 says. With the
default, an offer without the "none" bit fails with
`client_errc::security_layer_required`, and a layer asked for but not
offered fails with `security_layer_unavailable` (the exchange is
aborted, the connection stays usable). `require_tls` (default true, as
NTLM's) refuses no layer without TLS: `start()` fails with `tls_required`
before anything is sent when the options ask for none, and the selection
fails the same way when `best_offered` finds only "none" (Kerberos
authenticates the bind, not the PDUs after it). `complete()` refuses a success
that comes before that reply (the server was not authenticated, so
`sasl_bind` closes the connection), and releases the context; with a
layer, the context went to the layer (`take_security_layer()`) at the
reply. The layer messages are pure functions
(`detail::parse_gssapi_layer_offer`, `gssapi_select_layer`,
`gssapi_layer_reply`), unit tested without Kerberos. GSS-API handles (names, credentials,
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
to GSS-API as is. Security layers (coro-ldap-c83, opt-in: the default
stays "none", TLS being the recommended protection): with
`security_layer` integrity, confidentiality or best_offered (the
strongest offered; over TLS none when offered, TLS protecting the
connection already), `gss_init_sec_context` also asks for
GSS_C_INTEG_FLAG and GSS_C_CONF_FLAG, the selected layer and
GSS_C_SEQUENCE_FLAG must be in the context's ret_flags (RFC 4752 section
3.1 has a client requesting a layer set sequence_req_flag; without
sequence detection `gss_unwrap` would report no replayed or reordered
buffer for the layer to refuse), and `gss_wrap_size_limit` turns the
server's maximum buffer size into the most plaintext per buffer (0 fails
the bind). The layer (`sasl_security_layer` in sasl.hpp, generic: a
DIGEST-style mechanism could give its own) wraps with conf_flag set for
confidentiality and refuses, on unwrap, a buffer that fails, one with a
sequence status (duplicate, old, unsequenced, gap: GSS_C_SEQUENCE_FLAG
is requested) and, on a confidentiality layer, one not encrypted (a
downgrade). The seam is the transport: `sasl_bind` takes the layer from
the mechanism after each step (`take_security_layer()`) and arms the
connection with it; the reader, routing the next BindResponse, installs
it if that is a success (`net::detail::install_security_layer`) before
it reads another byte, moving whatever followed the response in the
read_buffer into the layer (RFC 4513 section 5.2.1.4: the layer starts
at the first octet after it), and drops it otherwise. From then on
`transport::stream()` returns a `sasl_layer_stream` over the old stream
(TLS-decrypted, so the layer sits on top of TLS, RFC 4513 section
5.2.1.6): `read_frame`, `write_bytes`, unbind and everything else are
unchanged. A write in flight keeps the stream it began on (the bind
holds every other request, so only a BindRequest can be). The stream
frames each buffer with a four-octet big-endian length (RFC 4422 section
3.7), cuts writes to `max_wrap_input()`, refuses a length above
`max_received()` before reading the body (`message_too_large`: RFC 4422
"SHOULD close the connection"), keeps a partial buffer across a
cancelled read (its received bytes in a `read_buffer` that, as in
`read_frame`, asks for exactly the rest of a buffer once its length is
in: it grows at most once per buffer, with no copy or zero-fill per
short read, and no front erase per buffer), fails a write on a layer
whose `max_wrap_input()` is 0 (`encode_error`, rather than loop), and
its failures keep their context, each direction its own ("read <name>:
SASL security layer: gss_unwrap: ...", "write <name> (N of M bytes
written): SASL security layer: a protected buffer cut after K of its L
octets": the count is in plaintext octets whose buffers went out whole).
The knowledge cached from the server is forgotten (RFC 4513 section
5.2.1.6). `start_tls()` with a layer fails (`security_layer_in_effect`:
TLS would have to go below the layer, which this library does not do),
and so does a second layer (a bind that negotiates one; one without a
layer leaves it in place, RFC 4513 section 5.2.1.4). Tested with a
made-up XOR layer through socket pairs (framing, chunking, oversized and
broken buffers, bytes after the BindResponse, a refused bind) and end to
end against an in-process MIT acceptor speaking LDAP
(`kerberos.security_layer`: integrity, confidentiality with a 64-octet
server maximum, best_offered, a layer not offered). Active Directory
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
TLS-terminating proxy still binds. Kerberos through GSS-SPNEGO is not
implemented (it would take the same bindings: MIT passes them through
SPNEGO since 1.19); `sasl_ntlm` (below) sends raw NTLMSSP under that
mechanism name. Tested without a
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
`none`'s while given bindings (no CBT asserted). Against Samba AD
(`integration.samba_ad.gssapi`, run_samba_ad.sh with the strict DC's
KDC): a bind without a layer on plain ldap:// is refused by the strict DC
and accepted by the relaxed one, integrity and confidentiality are
accepted by the strict DC (a search then runs through the layer), and
over ldaps:// both DCs accept the tls-server-end-point bindings, the
strict one checking them. Against Windows AD it is not tested.

NTLM (`sasl_ntlm.hpp`, coro-ldap-ite; MS-NLMP is the authority for the
names, the field order and the flags): an NTLMv2 password bind for
Active Directory where Kerberos is not available, as Samba's libads,
python-ldap3 and Rust's ldap3 do it. The SASL mechanism is GSS-SPNEGO
carrying raw NTLMSSP messages, not SPNEGO tokens, which AD accepts
(MS-ADTS section 3.1.1.3.4.5.2): two BindRequests, NEGOTIATE_MESSAGE then
AUTHENTICATE_MESSAGE, the CHALLENGE_MESSAGE in the saslBindInProgress
between them. The messages and MD4 are in the codec
(src/ntlm_message.hpp, internal, so the CHALLENGE_MESSAGE
parser is fuzzed with the others: `ntlm_fuzz`; a server's
CHALLENGE_MESSAGE encoder and AUTHENTICATE_MESSAGE parser are in the
testing target, section 10); the mechanism is in
jhetz::ldap, with HMAC-MD5, MD5 and `RAND_bytes` from OpenSSL. MD4 is
a self-contained RFC 1320 implementation, since OpenSSL 3 has it only in
its legacy provider, often not loaded. The NEGOTIATE_MESSAGE asks for
Unicode, the target name, NTLM with extended session security,
TargetInfo, a Version and 128-bit keys (flags 0x22880205); without a
security layer (the default) no SIGN, SEAL, ALWAYS_SIGN nor KEY_EXCH, and
the exported session key is the SessionBaseKey (KeyExchangeKey for
NTLMv2, no key exchange, MS-NLMP section 3.4.5.1), which keys the MIC
without RC4 (the wire bytes are those of the bind before the layer
existed). NTLMv2 only: a CHALLENGE_MESSAGE without
NTLMSSP_NEGOTIATE_UNICODE, NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY or
a TargetInfo is refused (`unexpected_response`) before any response is
computed. The parser checks every field's offset and length against the
message (64-bit sums, so no wraparound), the AV_PAIR list up to MsvAvEOL
(what follows it is ignored), each pair within the field, and the sizes
and uniqueness of MsvAvFlags and MsvAvTimestamp (`decode_error`
otherwise). The client's TargetInfo is the server's AV_PAIRs without any
MsvAvChannelBindings or MsvAvTargetName, MsvAvFlags with the MIC bit
(0x2) or'ed in (appended when the server sent none), then
MsvAvChannelBindings, then MsvAvTargetName (the SPN,
`sasl_ntlm_options::target`, default "ldap/<host>", none without a
host). NTOWFv2, the NTProofStr, the LmChallengeResponse and the
SessionBaseKey follow MS-NLMP section 3.3.2; the time is the server's
MsvAvTimestamp, and then the LmChallengeResponse is Z(24) (section
3.1.5.1.2), else the current FILETIME with the LMv2 response. The MIC is
HMAC-MD5 over the three messages with its own field zero, written into
the encoded AUTHENTICATE_MESSAGE at offset 72 (the Version is always
sent, so the MIC is always there; its flags are those both sides set,
plus NTLMSSP_NEGOTIATE_VERSION). Channel binding over TLS:
MsvAvChannelBindings is the MD5 of a gss_channel_bindings_struct with no
addresses and the application data "tls-server-end-point:<hash>"
(`prefixed_channel_binding`, the hash SCRAM-PLUS and GSSAPI use),
flattened as Windows hashes its SEC_CHANNEL_BINDINGS (five little-endian
32-bit words, the last the data's length, then the data); Z(16) without
TLS; with `ntlm_channel_binding::none` over TLS no MsvAvChannelBindings at
all (Samba's NTLMSSP server, with channel binding optional, lets only an
exchange without the pair through: "explicit 16 zeros in
MsvChannelBindings are not enough", auth/ntlmssp/ntlmssp_server.c; found
by `integration.samba_ad`, coro-ldap-ite.2). Over TLS without a hash,
`start()` fails with `tls_required` (as GSSAPI, coro-ldap-2y3: never an
unbound bind a man in the middle could pick). `channel_binding_used()`
says tls_server_end_point when the exchange carried bindings, never
tls-exporter. `require_tls` (true by default) fails `start()` with
`tls_required` on a connection without TLS, before anything is sent:
NTLM does not authenticate the server (the client gets no proof that the
server knows the hash), and after an unsigned bind on plain ldap:// every
PDU is in clear and the bound connection can be taken over; AD with
"LDAP server signing requirements" set to require signing refuses it
(`stronger_auth_required`, 00002028). Text is UTF-8, sent as UTF-16LE
(ill-formed UTF-8 refused); NTOWFv2 hashes the password's UTF-16 as is
(no normalization, as Windows) and uppercases the user name code point
by code point with ICU's `u_toupper` (simple mappings) in the BMP only,
as Windows' RtlUpcaseUnicodeString maps each UTF-16 unit on its own; the
domain is not uppercased. "DOMAIN\user" is split at its first
backslash, a UPN goes as the user name with no domain, and
`sasl_ntlm_options::domain` overrides both. The password is wiped with
`OPENSSL_cleanse` in the destructor (the constructor's by-value
parameter once copied into the member, as in `sasl_scram_sha256`), its
UTF-16 form, the NT hash and NTOWFv2 once used (NTOWFv2 is computed in `start()` and wiped in
`step()`, the SessionBaseKey after the MIC). None of them is returned or
moved by value, which would leave an unwiped copy in the callee's frame
or in a moved-from short string: `ntlm_unicode(utf8, out)` converts the
password into its wiped string (reserved once, never reallocated),
`detail::ntowfv2`, `ntlm_hmac_md5` and `ntlm_compute_response` write
NTOWFv2 and the SessionBaseKey into their caller's buffers, and
`detail::md4` writes the NT hash straight into its caller's wiped
buffer and zeroes its own working memory (the chaining state, each
block's message words, the padded tail) through volatile stores, the
codec having no `OPENSSL_cleanse`; OpenSSL's HMAC working state and
what the compiler keeps in registers or spill slots are beyond its
reach, as in any C or C++ hash. Tested: the MS-NLMP section 4.2.4
NTLMv2 vectors (NTOWFv2, the NTProofStr and temp, SessionBaseKey,
LMv2) and the section 4.2.4.3 CHALLENGE_MESSAGE, RFC 1320's MD4 suite,
malformed CHALLENGE_MESSAGEs, and binds against the scripted mock server
that recomputes the NTProofStr and the MIC as a domain controller would,
with Unicode names and passwords, the channel bindings (against a
Python-computed hash) and the refusals; and against Samba AD DCs
(`integration.samba_ad`, run_samba_ad.sh): UPN, DOMAIN\user and
non-ASCII binds with a non-BMP password over ldaps:// and StartTLS,
channel binding required and optional, and plain ldap://. Not tested
against Windows AD itself.

NTLM's security layer (coro-ldap-ite.1; MS-NLMP section 3.4, with
extended session security, key exchange and 128-bit keys only) is opt-in:
`sasl_ntlm_options::security_layer` is a `sasl_protection`, none by
default, integrity (signing) or confidentiality (signing and sealing),
for AD's "LDAP server signing requirements" on plain ldap://. It adds
NTLMSSP_NEGOTIATE_SIGN, KEY_EXCH and ALWAYS_SIGN (which MS-NLMP 2.2.2.5
says MUST be set in the NEGOTIATE_MESSAGE, SIGN overriding it;
0x62888215), and SEAL for confidentiality (0x62888235); a
CHALLENGE_MESSAGE that does not grant SIGN, KEY_EXCH and 128 (and SEAL)
fails `step()` with `security_layer_unavailable` before the
AUTHENTICATE_MESSAGE, as GSSAPI's selection does. The client then picks a random ExportedSessionKey
(`RAND_bytes`), sends RC4K(SessionBaseKey, it) as
EncryptedRandomSessionKey, keys the MIC with it, and derives the four
keys (SIGNKEY, SEALKEY: MD5 of the key and the magic constant with its
NUL, client-to-server and server-to-client; with NEGOTIATE_128 SEALKEY
starts from the whole key), which `detail::ntlm_security_layer`
(`take_security_layer()` after the AUTHENTICATE step) keeps with two RC4
handles initialized with the sealing keys, and two sequence numbers from
0, each kept across buffers. wrap() is MS-NLMP's SEAL (section 3.4.3):
the checksum HMAC_MD5(SigningKey, ConcatenationOf(SeqNum, Message))[0..7]
over the plaintext, the message RC4-sealed, then the checksum
RC4-encrypted with the same handle (key exchange). `ntlm_security_layer`
also has MS-NLMP's integrity only, the message in clear and only the
checksum through RC4, but `sasl_ntlm` always builds the sealing one: over
LDAP a DC treats a negotiated SIGN as SEAL (Samba's
GENSEC_FEATURE_LDAP_STYLE, `force_wrap_seal` in
auth/ntlmssp/ntlmssp_server.c, which says it follows Windows) and refuses
a buffer that is only signed ("NTLMSSP NTLM2 packet check failed due to
invalid signature", the connection closed after the bind); found by
`integration.samba_ad` (coro-ldap-ite.9). So `security_layer =
integrity` negotiates SIGN without SEAL and still seals, and
`connection::security_layer()` reports confidentiality. Samba before the
fix of its bug 13427 (4.7/4.8, 2018) also expects SEAL in the negotiated
flags, so integrity fails there after the bind. The
protected buffer is the 16-octet NTLMSSP_MESSAGE_SIGNATURE (Version 1,
Checksum, SeqNum, section 2.2.2.9.2) followed by the message, inside the
four-octet SASL length of `sasl_layer_stream`: MS-ADTS section 5.1.2.1
says AD processes the data "into buffers of protected data as per
[RFC2222]", and the signature-then-data order is Samba's (`ntlmssp_wrap`
in auth/ntlmssp/ntlmssp_sign.c), what Windows' wldap32 sends through
EncryptMessage with its token buffer first. The SeqNum field ends the
signature, so in the buffer the MAC's input (SeqNum then the message) is
contiguous and wrap() hashes it in place; unwrap() hashes the expected
SeqNum and the unsealed message, and compares the checksum with
`CRYPTO_memcmp`: a buffer with another sequence number (replayed,
reordered, dropped) or a checksum that does not verify fails with
`unexpected_response`, a malformed one with `decode_error`, and the
connection closes; past 2^32 buffers in a direction it refuses rather
than let the sequence number wrap. GSS-SPNEGO has no RFC 4752 layer
negotiation, so no maximum buffer size is exchanged: the client accepts
buffers up to `max_receive_size` (16 MiB by default; AD's MaxReceiveBuffer
is 10 MB) and sends at most 128 KiB per buffer (Samba's
`gensec_max_input_size` default), longer PDUs cut across buffers as for
GSSAPI (against Samba: buffers of at most 128 KiB both ways, a PDU cut
across them accepted, `integration.samba_ad`). AD refuses a SASL layer
over TLS (MS-ADTS section 5.1.1.1.2), so with TLS `start()` fails with
`security_layer_unavailable` before anything is sent; and the layer stands
in for TLS, so `require_tls` is not consulted with one (one option to set,
not two; the PDUs are sealed with either level, see above). AD may refuse
a later bind on a layered connection (unwillingToPerform without
LDAP_CAP_ACTIVE_DIRECTORY_LDAP_INTEG_OID, MS-ADTS section 5.1.1.1.2); the
library's rule (a bind without a layer leaves it in place, a second layer
is `security_layer_in_effect`) is unchanged. RC4 is self-contained in the
codec (`detail::ntlm_rc4`, RFC 6229's vectors), as MD4 is, because OpenSSL
3 keeps it in the legacy provider; its state is zeroed through volatile
stores when it goes. The
ExportedSessionKey is drawn into a wiped buffer, the
EncryptedRandomSessionKey encrypted in place from a copy, the four
derived keys go into a wiped `ntlm_session_keys` (their MD5 input in a
wiped string) and are copied into the layer, which wipes its signing keys
and RC4 states when the connection drops it; each MAC is wiped after
use (unwrap()'s computed one and the server's, once decrypted). The
protected buffer's signature parser is in the codec and fuzzed (`ntlm_fuzz`,
with RC4); the checksum, sequence and unsealing checks need OpenSSL's
HMAC-MD5, in jhetz::ldap: `ntlm_layer_fuzz` (built when the fuzz
build turns `JHETZ_LDAP_BUILD_NET` on, its replay with the net tests)
fuzzes unwrap() and the round trip both ways. Tested: MS-NLMP 4.2.4.2.3 (the
EncryptedRandomSessionKey) and 4.2.4.4 (the client-to-server sealing and
signing keys, the sealed "Plaintext" and its signature), a golden exchange
and three buffers (two client buffers through one handle, the server's
through the other) from `tests/net/ntlm_golden.py`, tampered, replayed,
dropped and malformed buffers, the flags-not-granted and TLS refusals,
and a bind and search through the in-process mock domain controller,
whose own layer (written in the test from MS-NLMP and OpenSSL) decrypts
the EncryptedRandomSessionKey, checks the MIC and unwraps the client's
buffers. Not tested against AD itself.

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
- `chase_search` / `chase_compare` (`referral_chase.hpp`, `jhetz::ldap`)
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
  reference that cannot be followed never fails the search but stays in
  `search_result::references`, so `is_complete()` is false (partial
  results are never a plain success; one skipped only as a loop is not
  kept, its server already answered that search; loops are checked
  before `max_targets` and the budget, but references over `max_hops`,
  which are not parsed at all, and those left unexamined once the chase
  stopped are kept). A referral result that
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
  downgrade (a protected origin, TLS, ldapi:// or a SASL confidentiality
  layer, makes ldap:// targets use StartTLS, and a failed
  StartTLS fails the URI), the certificate checked against the referred
  host (RFC 4513 section 3.1.3: `server_name` cleared, IDNs connected to
  in ASCII form), and binding only through the caller's `session_setup`
  (anonymous without one, the TLS client certificate of `options` left
  out too). Its connections are kept per server for later
  URIs and closed with the connector.

The pool's policy, `client_options::referrals` (3pf.1), is built on the
same pieces: see section 11, "Referrals". A chase returns the types every
search and compare does: `search_result` carries the report
(`referrals`, one `referral_attempt` per URI, and `unlisted`; empty
without a chase), and `is_complete()` (`is_success() &&
references.empty()`) says whether the entries are all there are, for a
chase and a plain search alike, so no flag has to be kept in step with
`references`; `compare_result{value, referrals, unlisted}` is what
`client::compare` and `chase_compare` return. One result type means
`client::search()` reports its chase without a second call (the
separate `client::chase_search` / `chase_compare` were removed, API
review #8). `referral_attempt` and `referral_outcome` are in
`operations.hpp` with `search_result`, `referral_policy` in
`referral.hpp` (codec), so that `client.hpp` can name them;
`referral_chase.hpp` includes `client.hpp` for `session_setup`, so the
other way round would be circular. A request's `follow_referrals`
(`search_params`, `compare_params`) turns referral-result chasing on or
off for one call (UnboundID's per-request `followReferrals`): on
`ldap::client` it overrides `referral_options::follow_referrals`, in the
free functions `false` stops it; `connection::search` ignores it, since a
connection never chases. `connection::compare` still returns `bool`: only
a chase has more to report.

Paged search (step 6): `ldap::search_paged_stream(connection &, params,
page_size)` returns a `paged_search` that yields entries across pages,
requesting the next page with the server's cookie when one ends, until the
cookie is empty; `ldap::search_paged` returns
`task<result<search_result>>` with every page collected. `search_paged_stream` is a free function, not a connection member (the aw4
rule: core types keep only the protocol operations): each page is a
`connection::search_stream()` (the same task, run on the connection's
shared state, so that the `paged_search`, like a stream, does not depend
on the connection object staying where it is) with the paged control. Against
the internal search start it replaced, the stream task and the copy of the
search_params cost a few µs per page, nothing against a network round
trip. `search_paged_stream(client &, ...)` runs it on one shared lease, which
the `paged_search` holds until destroyed (the cookies are bound to that
connection), and requests the first page again on a new lease when it
fails with `cond::connection_lost` or `cond::busy_or_unavailable` before
its first message, as `client::search_stream()` does (the same loop in
client.cpp, `search_paged_stream` being the client's friend): the
connection it failed on is set aside, and after busy or unavailable the
retry prefers the other servers. A page size that is not positive, or a
`max_pages` of 0, fails before a lease is acquired.

A paged search is bounded by `max_pages` (default
`search_paged_default_max_pages` = 10000, about a million entries at a
page size of 100; `search_paged` and the repositories' paged searches use
it too), as `ad::dirsync` is by `max_rounds`: a server that keeps answering
with a cookie, an empty page or not, would otherwise keep the search, and
the sync facade's collected result, growing without end. Once page
`max_pages` ends with a cookie, `next()` fails with
`std::errc::value_too_large` (context "search <base>: more than max_pages
(N) pages") and the paged_search keeps the cookie, so its destruction
releases the server's paging state. An error, not DirSync's success with
`more_results`: a paged search cannot be resumed by a later call (the
cookie is bound to the connection and the paged_search). `max_pages == 0`
fails with `std::errc::invalid_argument` before anything is sent, as
DirSync's `max_rounds == 0` does. Unlike DirSync there is no repeated-
cookie check: an RFC 2696 cookie is the server's opaque handle on its
paging state (section 3), not a resume point, and the RFC does not
require a new one per page: a server may return the same one for every
page, so a repeat proves no cycle. The bound alone ends a search that
does not end. A server that ignores the (non-critical) control returns
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
`ldap::search_paged` (collecting) reads every page of its `paged_search`
on the connection's strand, or destroys it there after an error, so the
paged_search ends before the result is delivered; `sync::search_paged`
runs it on the I/O thread and needs nothing more.

The names follow one rule in every layer (coro-ldap-bhe.5): `search_paged`
returns every page collected (the async free function, `sync::search_paged`,
both repositories), `search_paged_stream` returns the stream (async only,
as `search_stream` is), so a name never means a stream in one mode and a
collected result in the other. The arguments are the search (the request,
or the repository's filter), the page size, then the defaulted rest; the
repository's filter has no default there, since the page size follows it.

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
- a repository's `search` and `get` AND `(objectClass=…)` into the filter, so a
  `person` search only returns person entries;
- `to_attributes` (a repository's `add`) writes those values to `objectClass` (a
  new entry cannot be created without them);
- runtime validation checks the classes exist on the server.

Without it, a repository uses your filter unchanged and `add` requires an
`objectClass` field in the descriptor.

`auxiliary_class(...)`, after `object_class(...)` (a static_assert
otherwise), declares auxiliary classes (RFC 4512 section 2.4.3), such as
`posixAccount` on an `inetOrgPerson`:

```cpp
template<> constexpr auto ldap::schema<posix_user> = ldap::describe(
    ldap::object_class("inetOrgPerson"),
    ldap::auxiliary_class("posixAccount", "shadowAccount"),
    ldap::field<&posix_user::uid>("uid"), ...);
```

They are written on add after the object classes, and validated like
them (they must exist, their MUSTs and their superclasses' are checked,
and one the server defines as STRUCTURAL or ABSTRACT is the warning
`not_auxiliary`), but a repository's `search` and `get` AND only the
`object_class(...)` ones into the filter: an entry is found whether or
not it carries the auxiliary classes, and decoding it then fails if a
required member's attribute is missing. Classes listed in `object_class`
are all ANDed, auxiliary or not, as before. `auxiliary_classes_of<T>()`
lists them; `object_classes_of<T>()` does not.

Field shape decides cardinality:

| Member type | Meaning | Error when |
|---|---|---|
| `T` | required, single value | missing, or more than one value |
| `std::optional<T>` | optional, single value | more than one value |
| `std::vector<T>` | zero or more values | a value fails to convert |

(A value that fails to convert is `conversion_failed` for every shape:
for `std::vector<T>` the first bad value fails the whole member. One bad
value fails the whole `decode<T>`, and so the whole repository search: the
first entry that does not decode fails the call.)

An entry holding a mapped attribute with a range option (Active
Directory answers a large multi-valued attribute as
`member;range=0-1499`, MS-ADTS 3.1.1.3.1.3.3, possibly next to a
value-less `member`) fails `decode<T>` with
`client_errc::incomplete_values` for every shape, the context naming
`ldap::ad::read_all_values`: `entry::find` compares the description
with its options, so the member would otherwise decode empty, and a
repository's reads and `update_if`/`diff` would work on wrong data. Any
range option counts, `range=0-*` included: the check needs no
knowledge of whether the window is the whole set, and a repository has no
business reading ranged values. A range option on another attribute,
and other options of the mapped one (`;lang-fr`), are ignored.

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
  A repository's `modify` returns the first such error, prefixed with `modify <dn>`,
  before the schema check and before sending.
- `to_attributes(value)` returns `result<std::pmr::vector<partial_attribute>>`
  (context `attribute mail`), and a repository's `add` returns its error prefixed
  with `add <dn>`, again before anything is sent.
- The typed filter operators (`==`, `>=`, `<=`, `approx`) keep returning
  `filter`: on an encode failure they return `filter::failed(error)`, an
  empty filter, which is already poison (section 2: it stays empty through
  `&&`, `||` and `!`), holding the encode error (code and context, `filter
  <attribute>: ...`). The operators keep the first failed operand's error,
  and encoding the filter or a repository search fails with it before
  sending. There is no `result<filter>` overload, so composing typed
  filters stays an expression.

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

Active Directory's Large Integer syntax (`1.2.840.113556.1.4.906`,
`ad/filetime.hpp`) holds FILETIME dates (accountExpires, pwdLastSet, lastLogonTimestamp,
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

Usage (implemented, #9, `mapping.hpp`; the I/O in `repository.hpp`, below):

```cpp
ldap::repository people(conn, base, ldap::named_by<&person::uid>);
// Attribute list from the descriptor; filter narrowed to its object classes.
auto found = co_await people.search(f);   // found->entries: std::vector<record<person>>

co_await people.modify("jdoe", {
    ldap::replace<&person::mail>("new@example.org"),
    ldap::add<&person::member_of>(group_dn),
    ldap::remove<&person::mail>(),
});
co_await people.add(person{...});   // read_only fields skipped, objectClass written
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
- changes of another struct cannot be passed to a `person` repository's `modify`;
- `add` needs `object_class(...)` or an `objectClass` member.

Errors name the entry and attribute: `search ou=people,dc=example,dc=org:
entry uid=b,ou=people,dc=example,dc=org: attribute uidNumber: not an
integer: "x"`. A mapping error fails the repository's search but not the
connection.
Encode errors read the same way: `modify uid=jdoe,ou=people,dc=example,dc=org:
replace mail: not valid UTF-8 (ill-formed sequence at offset 4)`, `add
uid=jdoe,...: attribute uid: ...`.


The untyped `ldap::entry` (dn + attribute → values) stays available for
exploring unknown data; `ldap::decode<T>(entry)` converts one explicitly.

### Typed CRUD: `ldap::repository` (repository.hpp)

Layering rule: the codec (descriptor, `value_traits`, `decode<T>`,
`to_attributes`, typed changes and filters) is in the core; I/O
conveniences are layers that call only the public protocol operations,
over the `ldap::directory` concept (directory.hpp: `search`, `add`,
`modify`, `del`, `modify_dn` with `connection`'s signatures), which
`connection` and `client` satisfy. The same rule as the `ldap::ad` layer (section 12).

```cpp
ldap::repository people(pool, ldap::dn{"ou=people,dc=example,dc=org"}, ldap::named_by<&person::uid>);
co_await people.add(person{.uid = "jdoe", ...});        // uid=jdoe,ou=people,dc=example,dc=org
auto p = co_await people.get("jdoe");                   // result<std::optional<person>>
co_await people.modify("jdoe", {ldap::replace<&person::mail>("j@example.org")});
person q = **p; q.mail.reset();
co_await people.update(**p, q);                          // only mail: delete
co_await people.update_if(**p, q);                       // the same, if the entry still has p's values
auto all = co_await people.search(ldap::filters::field<&person::mail>().present());
co_await people.remove("jdoe");
```

- Naming: `named_by<&T::m>` is a tag carrying the member pointer as a
  template argument, so class template argument deduction gets both the
  struct and the source type (`repository<&person::uid, ldap::client>`) and
  the naming field is checked at compile time: listed in `schema<T>`,
  required and single-valued (an RDN value), not `read_only` (`add`
  writes it). An entry is `<attribute>=<escaped value>,<base>`;
  `dn_of(key)` builds it, and the `_at(dn)` forms take entries that do
  not follow the pattern.
- `get` is a base-object search for T's attributes, narrowed to T's
  object classes, and returns `std::optional<T>`: noSuchObject, or an
  entry of other classes, is "not there", not an error. Other result
  codes stay errors.
- Writes return `response`, as the core operations, so response
  controls (post-read, ...) stay reachable; each takes its operation's
  controls.
- `search(filter, scope = whole_subtree)` returns
  `typed_search_result<record<T>>`, `record<T>{dn, value}`: the DN as the
  server sent it, parsed, so entries named otherwise are returned too,
  and the limit codes are values, as `search()`.
- `update(original, changed)` sends one modify built by `ldap::diff`
  (mapping.hpp), to `original.dn` for a `record<T>` or to `dn_of` the
  naming member for a `T`: a single-valued member that differs is
  replaced, or deleted once empty; a multi-valued one deletes the values
  it lost, then adds the new ones (RFC 4511 section 4.6, applied in
  order, so a value that changed only in case under a caseIgnore rule is
  deleted, then added again); values compare as encoded, exactly. A
  cleared multi-valued member deletes the values `original` held, not the
  attribute, so a value another client added since stays; the server
  removes the attribute with its last value. A value another client
  removed since fails the modify with noSuchAttribute (16), a partial
  edit or a clear alike. A `std::vector<ldap::binary>` member is the
  exception: it is replaced with its new set (no values when cleared), so
  a value another client added since is lost. The usual such attributes
  (jpegPhoto, RFC 2798) have no EQUALITY rule, a server answers a value
  add or delete on those with inappropriateMatching (18, RFC 4511 section
  4.6 needs equality to find the values), and `diff` has no schema to ask.
  A member of another type on an attribute without EQUALITY gets that 18:
  map it as `ldap::binary`, or send `ldap::replace<&T::m>(values)` through
  `modify`. Only members T maps are touched, read_only ones
  never. Nothing differs: nothing is sent, no schema check either, and
  the result is `std::optional<response>{}`. A naming member that
  differs is `naming_value_changed` (cond `invalid_input`) before
  anything is sent: the entry would need a new DN, which is `rename`'s
  job, not a hidden modify DN. `original` is the caller's: no read
  before the write, so a concurrent change between the read and the
  update is not detected (`update_if` detects it). A member empty in
  `original` is written with replace, not add: empty in the struct is
  not absent on the server. A read returns no value for an attribute the
  reader may not see (RFC 4511 section 4.5.1.8: a userPassword under
  slapd's `by self =xw`, AD's unicodePwd, AD confidential attributes), so
  an add would leave the old password next to the new one (or be refused
  on unicodePwd). One diff serves `ldap::diff`, `update` and `update_if`,
  with no internal mode. Map members by the name the server returns: a
  member named by an alias (`surname`) or OID decodes empty, since the
  server answers with the primary name (`sn`) and decode matches names
  exactly; a repository read (`get`, `search`, the streams) fails with
  `schema_mismatch` ("attribute sn returned for no member") when the
  answer holds an attribute that decode does not read: one whose
  description is none of the names it requested (RFC 4512 2.5: options
  are a set, so `userCertificate;binary;lang-en` is the member
  `userCertificate;lang-en;binary`, and decode, through `entry::find`,
  compares them the same way) and is no subtype of a name without
  options (`cn;lang-en` for a member `cn` passes and is ignored, while
  `cn;lang-en;x-foo` for a member `cn;lang-en` fails, even with `cn`
  mapped too, since decode would leave the member empty and an update
  would overwrite values the read never showed); an AD range option is
  left out, so decode reports `incomplete_values`. `validate<T>` warns
  with `not_primary_name`. Plain `decode<T>` does not check.
- `update_if(original, changed)` is `update` with a critical Assertion
  control (RFC 4528), so the server applies the modify only if the
  entry still matches `original`, atomically, and otherwise answers
  assertionFailed (122), returned as the error. Critical because a
  server ignoring the control would apply an update the caller made
  conditional. Two conditions:
  - By default exactly `ldap::unchanged_filter(original)`: `(a=v)` for
    each value of each member, true while every value of `original` is
    still held by its attribute, subtypes and tagged values included (RFC
    4511 section 4.5.1.7, RFC 4512 section 2.5). There is no absence term
    for an empty member: no filter can test the exact description alone,
    so `(!(description=*))` is false on an entry holding only
    `description;lang-fr` (or AD's `member;range=0-1499`) and failed
    every update with 122 with nobody racing (verified on slapd 2.6.10:
    a replace on description or displayName leaves the `;lang-fr`
    siblings intact). So the default guard does not see a value added to
    a member empty in `original`: a concurrent fill is overwritten by the
    replace. The filter does not see added values nor a plain value
    replaced while a tagged or subtype sibling holds the same text;
    `versioned_by` is the exact check. An `original` with no values gives
    the empty filter, and `update_if` fails with `invalid_filter` before
    sending (unreachable for a repository, whose naming member is not
    read_only). read_only members are skipped, as in `diff`:
    the server changes those on its own (a `lastLogon` would refuse
    updates nobody raced with), and a type that truncates (`sys_seconds`
    drops fractions) could never match. A filter cannot count values, so
    a value added to a non-empty multi-valued member, and any attribute T
    does not map, go unnoticed. A 122 from this filter can also mean
    Undefined, which RFC 4528 section 3 answers as assertionFailed (RFC
    4511 section 4.5.1.7), and is then permanent, so retry loops on 122
    must be bounded. Three cases, probed on slapd 2.6.10: the attribute
    has no equality rule (jpegPhoto, audio), refused up front with
    `schema_check::on_first_use` (`client_errc::no_equality_rule` before
    anything is sent, the default guard only, an empty member included:
    the struct's next value would be asserted); the equality rule's
    assertion syntax is not the attribute's (userCertificate's
    certificateExactMatch); the bound identity may not read the
    attribute. An extensible `:2.5.13.17:` match or a negation is
    Undefined too, so neither is a way out. The criterion is the rule,
    not `ldap::binary`: userPassword, with octetStringMatch, asserts fine.
    An empty member adds no term, so tests without values hide the
    problem. `versioned_by` is the fix, on a member that has an equality
    rule. Samba and AD do not support the Assertion control (not in
    supportedControl): Samba answers the critical control with an
    ExtendedResponse carrying the modify's message id, no responseName and
    unavailableCriticalExtension (12), applies nothing and keeps the
    connection; with criticality FALSE it ignores the control and applies
    the modify. The check
    reuses the repository's schema check (`validate<T>` reports the warning
    `no_equality_rule`; the repository keeps a second outcome beside the
    first, no extra request, no stored schema), and a real
    `schema_mismatch` takes precedence. A filter holds at most `max_filter_elements` (10,000)
    elements, the enclosing AND and one per value, so a
    struct with more (a large group's `member`) fails every call with
    `invalid_filter` before anything is sent; `versioned_by` is the way
    out.
  - `ldap::versioned_by<&T::m>`: `(m=<original's value>)` on one
    single-valued member, usually a read_only one, which covers the whole
    entry and has none of those limits. A tag argument, as `named_by`, so
    the member is checked at compile time. entryCSN is exact;
    modifyTimestamp has a resolution of one second, so two changes in the
    same second look like one; map it as a string on a server whose
    timestamps have fractions. An empty optional is
    `missing_attribute` before anything is sent, since `(!(m=*))` would be
    true on a server without the attribute, a check that never fails.

  Nothing differs: nothing is sent and the condition is not tested. An
  Assertion control already in the `controls` argument is `encode_error`
  before anything is sent: slapd refuses a repeated control with
  protocolError, and combining the two is not `update_if`'s to decide
  (`update(original, changed, {ldap::assertion{...}})` sends any
  condition).
- `rename(from, to)` is a modify DN to the RDN `<naming attribute>=<to>`
  with deleteoldrdn TRUE, so the naming member follows; `move(key,
  new_base)` (or `move(key, other_repository)`, its base) keeps the RDN and
  sets newSuperior. Unlike the `move`/`rename` the connection and client
  used to have (dropped: `modify_dn` with designated initializers is the
  one call there), these build both DNs from the naming member, escaping
  included, which is the repository's job.
- `search_stream(filter, scope)` and `search_paged_stream(filter, page_size,
  scope)` return a `record_stream<T, Stream>` over the source's
  `search_stream()` or `ldap::search_paged_stream` (on a client: one shared lease,
  held by the stream). Its `next()` decodes one entry at a time. A decode
  error is handled as in `search()`, where the first entry that does not
  decode fails the call: it ends the stream, and `next()` returns it again
  from then on (the alternative, skipping the entry and going on, would
  make a stream accept what `search()` refuses). `stream()` gives the
  underlying stream (references, controls, pages). `search_paged(filter,
  page_size, scope)` collects every page into a
  `typed_search_result<record<T>>`, in both modes (a repository over a
  blocking facade has no streams).
- No ORM traps: no whole-object save, no hidden reads, no relationships,
  no entry cache. One request per call, plus the schema load once.
- `repository_options::schema_check = on_first_use` loads the schema with the
  free `ldap::load_schema(directory &)` on the first operation and keeps
  the outcome: a mismatch fails every later operation with
  `schema_mismatch`, a load failure is retried by the next operation.
  Over a client that is one check for the whole pool (section 6).
- One `ldap::repository<Naming, D>` serves both modes (coro-ldap-3jj.5):
  each public member is written once and forwards to a private member
  coroutine (`get_on`, `modify_on`, ...) over an async directory `s`,
  through a private `call(make_task)`. Over an async `D`, `call` returns
  `make_task(source)`, the task; over a blocking facade,
  `detail::blocking_facade<D>::run(source, make_task)` runs it with
  `sync::run` (section 7) on the facade's `ldap::connection` or
  `ldap::client`, one task on the I/O thread per call, the schema check
  included, and returns its result. The member's return type is
  `returns<T>`: `result<T>` when `blocking_facade<D>::value`, else
  `task<result<T>>`. The trait's primary template (false) is in
  directory.hpp and sync.hpp specializes it for `sync::directory`, so
  repository.hpp never includes sync.hpp, and the mode is a property of
  the source type, not a second class. The streams are `requires
  (!blocking)`: a member never changes meaning between the modes, it is
  absent where it cannot work (a stream lives on the I/O thread). The
  trait carries both the flag and the run hook, rather than a flag plus
  an ADL `run_on` overload: one customization point, found without ADL
  (the facades live in `ldap::sync`, so an ADL hook would have had to be
  declared there, not in `detail`). Parameters are by value in both
  modes, as a task needs its own copies; a blocking call pays the same
  moves. Each operation on one entry takes a `result<dn>`: the key forms
  pass `dn_of(key)`, whose error the operation gets its context. The
  requests and results without the I/O are
  `detail::repository_codec<Naming>`. The rejected alternatives: a
  separate `sync::repository` over a shared core (two member lists,
  every signature and default written twice, and `search_paged` meaning a
  stream on one side and a collected result on the other), and a CRTP
  base (the two lists' return types differ, and inherited members change
  `&repository::member`'s type).

**C++26 path:** reflection generates `ldap::schema<T>` from the struct, with
an annotation to rename (`[[=ldap::name("memberOf")]]`). The descriptor stays
supported, so user code does not change.

## 5. Errors

```cpp
namespace jhetz::ldap {

struct error {
    std::error_code         code;        // see categories below
    std::string             matched_dn;  // server's matchedDN; empty: none
    std::string             diagnostic_message; // server's diagnosticMessage; empty: none
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
| `ldap.client` | `ldap::client_errc` | codec: `decode_error`, `message_too_large`, `nesting_too_deep`, `unsupported_tag`, `unexpected_tag`, `integer_overflow`, `unsupported_operation`, `encode_error`; input: `invalid_filter`, `invalid_dn`, `invalid_attribute`, `invalid_url`, `string_prep_failed`; connection: `unexpected_response`, `not_connected`, `not_sent`, `bind_failed`, `operation_in_progress`, `unauthenticated_bind`, `tls_required`, `gssapi_failure`, `security_layer_required`, `security_layer_unavailable`, `security_layer_in_effect`; mapping: `missing_attribute`, `too_many_values`, `conversion_failed`, `schema_mismatch`, `naming_value_changed`, `incomplete_values`, `no_equality_rule`; facade: `would_deadlock`; environment: `internal_error` |
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
"Sent or not" in section 7), `bind_failed` (a request held behind a bind
that did not succeed, never sent), `operation_in_progress` (the connection
is busy; nothing is queued), `unauthenticated_bind` (a name with an empty
password), `tls_required` (channel binding on a connection without TLS,
or an Active Directory password change on one with neither TLS nor a
SASL confidentiality layer), `gssapi_failure` (a GSS-API
call failed in a SASL GSSAPI bind: the context quotes GSS-API's major and
minor status messages), `security_layer_required` (the server accepts a
SASL GSSAPI bind only with a security layer, which the options do not
ask for), `security_layer_unavailable` (the server does not offer the
layer asked for), `security_layer_in_effect` (StartTLS or a second layer
while a SASL layer is in effect). Server errors carry the operation as context
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
| `auth_failed` | `invalid_credentials`, `inappropriate_authentication`, `auth_method_not_supported` | `unauthenticated_bind`, `gssapi_failure`, `bind_failed` | |
| `timeout` | `time_limit_exceeded` | | `timed_out`, `capy::error::timeout` |
| `canceled` | | | `operation_canceled`, `capy::error::canceled` |
| `connection_lost` | | `not_connected`, `not_sent` | `connection_reset`, `connection_aborted`, `broken_pipe`, `not_connected`; Capy `eof`, `stream_truncated` |
| `tls_failure` | | | any `corosio.openssl` (or `corosio.wolfssl`) code |
| `protocol_error` | `protocol_error` | `decode_error`, `message_too_large`, `nesting_too_deep`, `unsupported_tag`, `integer_overflow`, `unexpected_tag`, `unsupported_operation`, `unexpected_response` | |
| `busy_or_unavailable` | `busy`, `unavailable` | | `connection_refused`, `host_unreachable`, `network_unreachable`, `network_down` |
| `access_denied` | `insufficient_access_rights`, `stronger_auth_required`, `confidentiality_required` | `tls_required`, `security_layer_required`, `security_layer_unavailable` | `permission_denied` |
| `already_exists` | `entry_already_exists`, `attribute_or_value_exists` | | |
| `invalid_input` | `undefined_attribute_type`, `inappropriate_matching`, `constraint_violation`, `invalid_attribute_syntax`, `invalid_dn_syntax`, `naming_violation`, `object_class_violation` | `invalid_filter`, `invalid_dn`, `invalid_attribute`, `encode_error`, `invalid_url`, `string_prep_failed`, `naming_value_changed`, `no_equality_rule` | `invalid_argument`, `no_such_file_or_directory`, `not_a_directory`, `filename_too_long` (TLS configuration) |
| none | `operations_error`, `size_limit_exceeded`, `compare_false`, `compare_true`, `referral`, `admin_limit_exceeded`, `unavailable_critical_extension`, `sasl_bind_in_progress`, `alias_problem`, `alias_dereferencing_problem`, `unwilling_to_perform`, `loop_detect`, `not_allowed_on_non_leaf`, `not_allowed_on_rdn`, `object_class_mods_prohibited`, `affects_multiple_dsas`, `other`, `virtual_list_view_error`, `assertion_failed`, `e_sync_refresh_required`, unknown codes | `missing_attribute`, `too_many_values`, `conversion_failed`, `schema_mismatch`, `would_deadlock`, `operation_in_progress`, `internal_error`, `incomplete_values` | everything else |

Choices worth knowing: `unauthenticated_bind` is `auth_failed` (an empty
password on a login form is a failed login); `stronger_auth_required` and
`confidentiality_required` are `access_denied` (the credentials may be fine,
the session is not good enough); `unwilling_to_perform` matches nothing
(servers use it for unrelated refusals); `size_limit_exceeded` matches
nothing (it comes with partial results, which `search()` returns as a
`search_result`, not as an error: section 3); `operation_in_progress` matches
nothing (it is a usage error, not a busy server); `internal_error` (a
library the client uses failed: OpenSSL in SCRAM, ICU in SASLprep or
`ad::password_value`, e.g. out of memory or ICU data without the SASLprep
profile) matches nothing: it is neither the caller's input (`invalid_input`
would make an application prompt for the password again) nor the server's
doing, and no retry or fix is implied; file errors from TLS
configuration are `invalid_input`, not `not_found`, which is for directory
entries. System codes match through their generic condition, so both the
system and generic categories work. `jhetz::ldap_core` does not link Capy or
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
  `SINGLE-VALUE`, `NO-USER-MODIFICATION`, `USAGE`. `SUP` is followed to inherit
  `SYNTAX` and `EQUALITY`, because many common attributes (`cn`, `sn`, …)
  only declare `SUP name`. `EQUALITY` drives
  `distinguished_name_match(a, b, schema)` (section 1).
- `objectClasses`: `NAME`, `SUP`, the kind (`ABSTRACT`, `STRUCTURAL`,
  `AUXILIARY`; STRUCTURAL when none is given, RFC 4512 4.1.1), `MUST` and
  `MAY` (`object_class_type`, in the RFC's field order). `SUP` is followed
  to inherit `MUST` (RFC 4512 2.4); entries that are not oids are dropped,
  like NAMEs that are not descriptors.
- `dITContentRules` (RFC 4512 4.1.6): the OID (the structural class's),
  `NAME`, `AUX`, `MUST`, `MAY` and `NOT` (`dit_content_rule`, `NOT` as
  `precluded`), indexed by OID. `load_schema` asks for them with the
  other two.
- Everything else (`ORDERING`, `SUBSTR`, matching rule definitions,
  extensions)
  is skipped. Unparseable definitions are skipped, not fatal.

```cpp
ldap::result<ldap::server_schema> s = co_await ldap::load_schema(conn);   // directory.hpp
ldap::schema_report rep = ldap::validate<person>(*s);
if (!rep.ok()) std::println("{}", rep);   // lists every issue, not just the first

// or automatically, in a repository:
ldap::repository people(conn, base, ldap::named_by<&person::uid>, {.schema_check = ldap::schema_check::on_first_use});
```

Checks:
- object classes from `object_class(...)` and `auxiliary_class(...)`
  exist; an auxiliary one the server defines with another kind is the
  warning `not_auxiliary`;
- equality (warning): a writable member whose attribute has no EQUALITY
  on its SUP chain is `no_equality_rule` (an assertion on it is always
  Undefined, so `update_if`'s default guard cannot succeed), reported
  only when the schema declares EQUALITY for some attribute type, so an
  AD or Samba schema, which declares none, reports nothing;
- attribute exists on the server (name or alias); a member named by an
  alias or numeric OID rather than the attribute's first NAME is the
  warning `not_primary_name` (servers answer with the primary name, so
  the member would decode empty and a repository read fails with
  `schema_mismatch`; an attribute with no NAME mapped by its OID gets
  none);
- one attribute per name: a member mapping the attribute type of an
  earlier member with the same option set under another name (`sn` and
  `surname`, `cn` and `2.5.4.3`, the type resolved through the schema's
  names and OIDs) is the error `duplicate_attribute`: `ldap::diff` and
  `update` would write the attribute twice and a read decodes only the
  member named as the server answers. Different option sets (`cn` and
  `cn;lang-en`) are distinct attributes, and one name mapped twice (two
  representations of one attribute) decodes into both;
- cardinality: `T` / `optional<T>` mapped to a multi-valued attribute is
  reported (it only fails at runtime if an entry really has several values);
- syntax: the attribute's SYNTAX OID is in `value_traits<T>::syntaxes`
  (for example an `int` field on a DirectoryString attribute);
- writability: a non-`read_only` field on a `NO-USER-MODIFICATION`
  attribute (`createTimestamp`) is reported.
- required attributes (warnings): with declared object classes, each
  `MUST` attribute of those classes, of the auxiliary classes, and of
  their superclasses (every `SUP`
  followed, breadth first, each class once, so a cycle ends; ABSTRACT,
  STRUCTURAL and AUXILIARY alike) must be mapped by a required (`T`),
  writable member. One that no member maps is
  `must_attribute_not_mapped`; one mapped only by `std::optional`,
  `std::vector` or `read_only` members (a repository's add sends nothing for an
  empty one, never a read_only one) is `must_attribute_not_required`; a
  superclass the server does not define is `unknown_superclass` (its
  MUSTs cannot be checked). Each attribute is reported once, for the first
  class that requires it. Matching resolves both sides through the schema:
  an alias (`surname` for `sn`), the OID, or an option (`cn;lang-en`)
  maps the attribute, a subtype does not (`cn` does not map a MUST `name`;
  RFC 4512 requires the type itself). Not reported: `objectClass`, by any
  of its names or its OID 2.5.4.0 (`top`'s MUST: add sends the declared
  classes) and NO-USER-MODIFICATION
  attributes (RFC 4511 4.7: a client must not send them, the server
  provides them). These are warnings, not errors, so
  `schema_check::on_first_use` never fails on them: a descriptor may be a
  read projection with classes only to narrow a search; at add time the
  entry's RDN supplies its attribute values (RFC 4511 4.7: the attributes
  "along with those from the RDN" make up the entry), which a check per
  type cannot see; and Active Directory fills in MUSTs of its own (`top`
  requires instanceType, nTSecurityDescriptor and objectCategory, which a
  client does not send).
- allowed attributes (warning): with declared object classes, a writable
  member whose attribute is in no `MUST` or `MAY` of those classes, the
  auxiliary classes and their superclasses is `attribute_not_allowed`, the
  mistake of forgetting `auxiliary_class("posixAccount")` on a `uidNumber`
  member, which would otherwise surface as objectClassViolation on add.
  Matching is the one above: aliases, OIDs and options count, a subtype
  does not. Not reported: `objectClass`, read_only members, operational
  attributes (`USAGE` other than userApplications, which object classes
  do not govern), attributes the server does not define (already
  `unknown_attribute`), and no member at all when a class is
  extensibleObject (RFC 4512 section 4.3) or a class or superclass is
  undefined, since that class might allow it. The DIT content rule
  (RFC 4512 sections 2.6 and 4.1.6) of the entry's structural class
  widens the set by its own `MUST` and `MAY`, and its `NOT` precludes
  attributes (reported as `attribute_not_allowed` even when a class
  allows them). The structural class is each declared STRUCTURAL class
  that no reached class has as a superclass: a rule governs the entries
  of its own class, not of its subclasses. The attributes of the rule's
  `AUX` classes do not count: an entry has them only once its
  objectClass lists the class, which `auxiliary_class(...)` declares.
  Active Directory needs the rule: `user` does not list `sAMAccountName`
  (it comes from `securityPrincipal`, a system auxiliary class AD adds
  implicitly, without naming it in objectClass); Samba publishes the
  rule with that class's attributes already in its `MUST` and `MAY`
  (`( 1.2.840.113556.1.5.9 NAME 'user' AUX ( ... securityPrincipal ... )
  MUST ( sAMAccountName $ objectSid $ cn ) MAY ( ... ) )`), as AD does;
  the classSchema entries' `systemAuxiliaryClass` / `auxiliaryClass`
  are not read. A rule's `MUST` are not checked as unmapped (AD's
  include `objectSid`, which the server assigns). Still a warning: a
  server may allow more than its subschema says.
- allowed auxiliary classes (warning): with a DIT content rule for the
  structural class, each declared AUXILIARY class (by `object_class` or
  `auxiliary_class`) that the rule's `AUX` does not list, by name or
  OID, is `auxiliary_class_not_allowed` (RFC 4512 section 2.6: an entry
  may only belong to the auxiliary classes its governing rule lists); a
  server enforcing rules (slapd does) refuses the add with
  objectClassViolation. Without a rule nothing is reported (any
  auxiliary class is allowed). An OBSOLETE rule is not active (RFC 4512
  section 2.6: a rule governs only "if present and active") and counts
  for neither check.

With `schema_check::on_first_use`, a repository's first operation runs
`validate<T>` and fails with `client_errc::schema_mismatch` if the report has
errors. The outcome is kept by the repository, and checked again once its
source's `is_tls()` or `security_layer()` changed (RFC 4513 sections
3.1.5 and 5.2.1.6: what was read unprotected is read again). From the
same report the repository keeps a second outcome: with a `no_equality_rule`
warning, `update_if` with its default guard fails with
`client_errc::no_equality_rule` (cond `invalid_input`; context
"attribute jpegPhoto: no equality rule, an assertion on it is always
Undefined (use ldap::versioned_by)") before sending; `versioned_by`,
`update` and the other operations are not affected. The
connection itself caches nothing about the server (coro-ldap-aw4.1: its
schema cache and `connection_options::schema_check` are gone).

Over an `ldap::client` the repository checks once, not per pooled connection
or server (coro-ldap-2cx.2.2): a client reports no `is_tls()` or
`security_layer()`, so the outcome is never checked again, and the
operations that follow may run on any server of the pool, failover
included. So every server of a pool must serve the same schema; for a
check per connection, the source is a lease's connection (`*lease`).
The schema itself is read consistently: `ldap::load_schema(client &)`
(which `sync::load_schema` runs on a `sync::client`), non-template overloads that
overload resolution prefers to the `directory` template, run the root
DSE and the subschema searches on one shared lease, so the subschema
read is the one that server's root DSE names, never another server's.
Both searches are idempotent reads: after `cond::connection_lost` the
pair runs once more on a new lease; busy and unavailable are not
retried (unlike the read forwarders), and nor is anything else.

Implemented (#13, `schema.hpp`): `parse_attribute_type` /
`parse_object_class` (a small RFC 4512 lexer: parentheses, quoted strings
with `\27` / `\5C` escapes, bare words; keywords without an argument are
known flags, every other keyword takes one value or a `( a $ b )` list).
Lenient with real servers (quoted OIDs as Active Directory sends them,
keywords in any case, no space before `)` or around a list's `$`, and an
object class's `SUP`, `MUST` or `MAY` list written without parentheses,
`MUST cn$sn` read as `MUST ( cn $ sn )`: RFC 4512 parenthesises a list,
no known server omits them, and reading the words apart would fail the
class, which `validate<T>` then reports as an unknown class); a `$`
outside parentheses and quotes anywhere else (`NAME`, an `X-` value, an
attribute type's single-oid `SUP`) fails the definition; a definition whose OID is not
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
defined on the server". The cardinality and MUST checks are
warnings (`schema_issue::is_error() == false`), the others are errors.
Syntaxes per type come from `value_syntaxes<T>` (built in: integers →
INTEGER / NumericString, and also AD Large Integer
(`ad::large_integer_syntax`, 1.2.840.113556.1.4.906) for signed integers of
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
`validate<T>` and `schema_check::on_first_use`; map it to `ldap::binary`. `ldap::load_schema()` reads
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
auto c = ldap::sync::connect(url, {.timeout = 5s}); // owns an io_context + 1 I/O thread
auto people = c->search({...});                    // same request/result types
```

Starting the async side from `main()` is `ldap::run(f, args...)` or
`ldap::run(ioc, task)` (`run.hpp`,
header-only, included by `connection.hpp`): it starts the task on the
io_context's executor with `capy::run_async`, runs the io_context on the
calling thread until it has no work left, and returns the task's value or
rethrows its exception. Running until no work is left, rather than until the
task ends, lets what the task leaves behind finish (a connection destroyed
off its strand posts its close, a detached name lookup), so the io_context
can be destroyed right after. A stopped io_context is restarted first, so
`run` may be called again on the same one. If `io_context::run()` returns
without the task having ended (stopped, or the task abandoned; the
trampoline's work guard keeps `run()` going while the task waits), `run` throws `std::system_error` with `capy::error::canceled`,
as Capy's `run_blocking` does; the completion handlers share their state
through a `shared_ptr`, so a task that ends later (the io_context run
again) writes into that state, not into `run`'s frame. `ldap::run(f,
args...)` makes the io_context itself and passes it to `f(ioc, args...)`,
mirroring `sync::run(d, make_task, args...)`: the library hands the task
the io_context it drives, so a task that needs one (every `connect`) has
it, and the owning `run(task)`, which could only run tasks needing none,
was removed. The call `f(ioc, args...)` and the run are one
full-expression, so conversion temporaries bound to the task's reference
parameters (a `const char *` for a `const std::string &`) live until the
run ends; the io_context is destroyed before `f` and the arguments. A
result bound to that io_context (connection, client, stream, lease,
transaction: `detail::io_context_bound`, `io_thread_bound` plus the
connection and client) would dangle, so it fails a static_assert; no
ambient `connect(url)` finding the io_context at run time was added (a
run-time error instead of a compile-time one, and unlike `client` and the
connectors). The connection's strand changes
nothing here: operations hop to the strand and resume the task on the
io_context's executor. `ldap::run` is not `sync::run` (which runs a free
async function on a blocking facade's I/O thread).

Entry points follow one rule: what opens eagerly is a free `connect()`
returning `result<...>` (`ldap::connect`, `ldap::sync::connect`), what
opens lazily is a constructor (`ldap::client`, `ldap::sync::client`,
pools that connect on first use). So `sync::connection` has no options
constructor and no member `connect()`: it is made by `sync::connect()`,
reconnecting is assigning a new one, and its noexcept default
constructor makes one with no I/O thread whose operations fail with
`not_connected`. The I/O thread and the `ldap::connection` live in one
heap core (`sync::detail::connection_core`) shared by the handles: a
`sync::connection` is copyable like `ldap::connection`, the last handle
closes the connection and joins the thread, and moves and copies leave a
`sync::transaction` made by it valid.

Implemented under it (step 4, `jhetz_ldap`, namespace `ldap::net`):
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
  the system trust store (OpenSSL's; on Windows CryptoAPI's verdict on the
  chain, below), SNI, host name checks (IP literals against iPAddress
  entries, zone stripped; a DNS name's trailing dot dropped, as RFC 6066
  section 3 sends SNI and as OpenSSL 4.1's X509_VERIFY_PARAM_set1_host
  requires) and TLS 1.2 minimum. Options: `ca_file`, `ca_dir`,
  `ca_pem`, client `cert_file` + `key_file`, `server_name`; the only opt-out
  is `certificate_verification::insecure_accept_any`. Configuration errors
  (bad or mismatched PEM certificates and keys, missing `ca_dir`) fail before
  any network traffic. Host matching is strict by default (RFC 6125, RFC
  4513 section 3.1.3): subjectAltName DNS names only, no subject CN
  fallback, wildcards only as a whole leftmost label. Corosio has no option
  for OpenSSL's check flags, so our verify callback redoes the check on the
  leaf after OpenSSL's lenient one, with NEVER_CHECK_SUBJECT |
  NO_PARTIAL_WILDCARDS. X509_check_host is deprecated in OpenSSL 4.1, so
  the check runs OpenSSL's own matcher through the X509_VERIFY_PARAM host
  API (in OpenSSL 3 too): the leaf alone is verified against an empty store
  with those host flags, the verify callback accepting every error but
  HOSTNAME_MISMATCH. `tls_options::host_matching = legacy` keeps OpenSSL
  3's defaults for old certificates: partial wildcards, and the subject CN
  when the certificate has no subjectAltName DNS name. OpenSSL 4 dropped
  that CN fallback from its default check, so under legacy the callback
  accepts a HOSTNAME_MISMATCH on such a leaf whose CN matches (the same
  matcher with ALWAYS_CHECK_SUBJECT). With OpenSSL 3 that error comes only
  when OpenSSL's own CN fallback did not match, so this one does not match
  either. The fallback is for DNS names at depth 0 only: an IP literal
  never matches a CN, and a leaf whose chain or validity fails still fails.
  A CA bundle (`ca_file`, `ca_pem`) goes to Corosio whole: it trusts every
  certificate of it, but parses them only when the handshake starts and
  then reports a bad one as a setup failure. So the bundle is read first
  as Corosio reads it (certificates up to the first text without a PEM
  block), and a certificate that does not parse is named by its position
  ("certificate 2 does not parse") before any network traffic.
- Windows default verification (coro-ldap-1q5; unverified, no Windows
  build yet): with no `ca_file`, `ca_dir` or `ca_pem`, the verify
  callback hands the server's chain (the leaf, then what the server sent)
  to CryptoAPI as wldap32 does: `CertGetCertificateChain` for serverAuth
  with the sent certificates in a memory store, then
  `CertVerifyCertificateChainPolicy(CERT_CHAIN_POLICY_SSL,
  AUTHTYPE_SERVER)`. CryptoAPI's verdict replaces OpenSSL's on the chain
  rather than adding to it: the point is the roots AuthRoot fetches on
  demand, which OpenSSL (with the filtered ROOT store copied into it) does
  not have, so requiring both would keep that gap; and Windows applies
  its own root program rules (distrust, NotBefore dates, name
  constraints) itself. The ROOT anchors copied into OpenSSL leave out a
  root with a NotBefore restriction on serverAuth: OpenSSL cannot trust a
  root only for certificates issued before a date, so it fails closed
  (`ca_file` trusts it anyway). So OpenSSL's errors are let through, except a host
  name or IP address mismatch and the two checks on the leaf alone, which
  no chain CryptoAPI builds can change and the SSL policy does not redo
  (or not all of): the leaf's key below the security level
  (`EE_KEY_TOO_SMALL`) and its purpose (`INVALID_PURPOSE` at depth 0:
  OpenSSL's sslserver purpose also checks the keyUsage and nsCertType,
  the SSL policy only the extended key usage, and the TLS stack here is
  OpenSSL, not Schannel, which would check the keyUsage itself). The
  leaf's final callback (OpenSSL calls it after the chain build, the
  purpose, security level and host name checks, and the signature and
  validity checks; only the name constraint, RFC 3779 and policy checks
  come later, and CryptoAPI does those itself) asks CryptoAPI; a
  handshake that never reached it fails closed. On acceptance the store's
  error, still the last one let through, is reset to `X509_V_OK`, so
  `SSL_get_verify_result()` does not report a verified connection as
  failed. An exception in the callback (bad_alloc) fails verification
  rather than unwinding through OpenSSL's C frames. OpenSSL's security level (`SSL_get_security_level`, 2 by
  default since OpenSSL 3.2) also checks the CA keys and the signature
  hashes (`CA_KEY_TOO_SMALL`, `CA_MD_TOO_WEAK`), which depend on the
  chain built, and CryptoAPI checks neither by default; so the callback
  passes the level on, and `CertGetCertificateChain` gets a
  `CERT_STRONG_SIGN_PARA` with the same floor
  (`detail::strong_sign_for_level`): level n needs OpenSSL's
  `minbits_table` bits b (80, 112, 128, 192, 256), so RSA keys of 1024,
  2048, 3072, 7680 or 15360 bits (the sizes OpenSSL rates at b), ECDSA
  curves of 2b bits and SHA-2 hashes of 2b bits (SHA-1 is below every
  level, as in OpenSSL 3). Level 2 is `RSA/2048;ECDSA/224` with RSA or
  ECDSA over SHA-256, SHA-384 or SHA-512; a chain the engine flags
  `CERT_TRUST_HAS_WEAK_SIGNATURE` is rejected ("a signature or key below
  OpenSSL's security level 2"). Parity is exact for RSA and ECDSA with
  SHA-2 at OpenSSL's standard sizes; Windows is stricter for what the
  lists leave out (SHA-224 and SHA-3 hashes, which OpenSSL rates at half
  the digest size, so SHA3-256 passes level 2; DSA signatures, which CNG
  names but the lists omit; EdDSA) and for RSA sizes between the standard
  ones, which OpenSSL rates by formula (RSA-2040 is 112 bits, level 2)
  but `RSA/2048` refuses, the leaf's key included although OpenSSL's
  `EE_KEY_TOO_SMALL` would pass it; never weaker. CRL and OCSP signatures are not held to it
  (OpenSSL checks no revocation). The host
  name stays OpenSSL's, with `host_matching` as on Linux (the SSL policy
  gets SECURITY_FLAG_IGNORE_CERT_CN_INVALID and no server name): one
  matching rule on every platform, no second UTF-16 or IDN conversion of
  the name. Revocation: CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT,
  soft-fail (CERT_CHAIN_POLICY_IGNORE_ALL_REV_UNKNOWN_FLAGS: an
  unreachable CRL or OCSP responder is accepted, a revoked certificate
  is not): stricter than OpenSSL, which checks none, without making
  offline networks fail. Only the revocation retrieval is bounded, every
  CRL and OCSP URL together (CERT_CHAIN_REVOCATION_ACCUMULATIVE_TIMEOUT
  with `dwUrlRetrievalTimeout`): by what is left of the connect's or
  StartTLS's deadline, and at most 20 s (`max_revocation_retrieval`),
  with a deadline or without, since soft-fail makes a longer wait
  pointless. Microsoft documents `CERT_CHAIN_PARA::dwUrlRetrievalTimeout`
  for revocation only: the intermediates fetched from AIA URLs and the
  AuthRoot roots and lists are fetched with the chain engine's own
  per-URL timeout (Windows' default), so a connect can overrun its
  deadline by that much per such URL. Bounding them would take a chain
  engine of our own per call (`CERT_CHAIN_ENGINE_CONFIG::
  dwUrlRetrievalTimeout`, also per URL), losing the shared
  `HCCE_CURRENT_USER` engine whose AuthRoot behaviour is the point;
  `CERT_CHAIN_DISABLE_AIA` or cache-only retrieval would refuse the
  servers that rely on AIA or a root not fetched yet. The whole call
  blocks the io thread, and so every other operation on that io_context,
  as CryptoAPI has no asynchronous interface and the OpenSSL verify
  callback cannot suspend (moving it to a worker thread would need the
  verdict computed before the callback asks). `tls_options` says so.
  Custom anchors
  stay OpenSSL's alone (they replace the system store), and
  `insecure_accept_any` never asks CryptoAPI. A rejection reads
  `tls handshake: server certificate: Windows certificate chain:
  <reason> (0x<HRESULT>)`. The callback logic is tested on Linux with a
  stand-in for CryptoAPI (`verify_state::system_chain`).
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
  (16 MiB) from the header alone; decodes with `ldap::decode`, which rejects
  request operations; a TLS close
  without close_notify between PDUs reads as a normal close. After any error
  the caller drops the connection (header errors repeat, they are not
  consumed). No timeout of its own: step 5 cancels with stop tokens.

Implemented (steps 5a and 5b, `ldap::connection`, also in `jhetz_ldap`):
- `ldap::connect(ioc, url, connection_options, mr)` wraps `net::connect`;
  `connection(ioc, net::transport, options, mr)` runs over any transport
  whose I/O runs on `ioc` (the tests use a Unix socket pair with a scripted
  server that reads with `testing::read_message`). `simple_bind`, `search`,
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
  `capy::when_any` races only awaitables returning `results`, so
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
  from the thread running the io_context: `unsafe_io` keeps the scheduler
  lock (another thread may post, and Corosio wakes a `run()` blocked in
  epoll or the ring) but drops the I/O locks the socket cancellations
  above take; `unsafe` has no scheduler lock, so no post from another
  thread at all. Neither helper
  owns anything beyond its coroutine frame, which outlives the operation it
  awaits.
- Bind sequencing (RFC 4511 section 4.2.1: no PDU while a BindRequest is
  outstanding): a bind exchange (every step of a SASL bind) marks the
  connection as binding. Requests started meanwhile are encoded, registered
  and held, then sent in order when the exchange succeeds; one cancelled
  while held is dropped (never sent, so no AbandonRequest). An exchange
  that fails, is stopped with none of its BindRequests outstanding or ends
  without an outcome (its frame destroyed) fails the held requests with
  `client_errc::bind_failed` quoting its error, unsent (one stopped while
  a BindRequest is outstanding closes the connection, since a bind cannot
  be abandoned, and they fail with `not_sent`): sending them would run them anonymously, or
  without the security layer the bind was to install. Held requests nothing
  waits for are still sent, their answers still due: AbandonRequests, a
  destroyed transaction's abort and a paged results release carry no
  authority and only discard server state, which would otherwise stay
  allocated (OpenLDAP allows one transaction per connection). Binds are
  serialized:
  a second one waits for the first. `unbind()` during a bind closes without
  an UnbindRequest; `start_tls()` during one is refused. `unbind()` once StartTLS
  is sent closes the same way (RFC 4511 section 4.14.1) and fails it.
- Every response is decoded with `ldap::decode` (requests rejected) and checked against the
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
  cancelled or timed-out Bind or StartTLS, which closes it). So does a
  non-success ExtendedResponse without a responseName answering a request
  other than a Bind (Samba's reply to an unsupported critical control):
  the request fails with its result. A
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
  A destructor or `close()` called off the strand posts its work with
  `capy::run_async`, whose frame failing to allocate ends the program
  too (they are `noexcept`; running the work on the calling thread
  instead would race the strand).
- Lifetime: the state is one reference-counted block on the connection's
  resource, held by the connection handles, each outstanding operation,
  each stream, paged search and transaction, and the reader and writer
  frames. Moving a connection or stream is a pointer move. A connection is
  copyable (coro-ldap-vk8, like Rust ldap3's `Ldap`): the block also counts
  the handles, apart from the other references, so the last handle's
  destruction closes the connection while streams and tasks still hold the
  block; they finish with `not_connected` and release it. The handle count
  is an atomic decremented with acq_rel, so exactly one handle sees it
  reach zero, whatever threads drop the handles; a new handle is only made
  from a live one, so the count never rises from zero. `close()` and
  `unbind()` act on the shared state, so through any handle they end the
  session for every copy. A separate `shared_connection` type was dropped
  (coro-ldap-tfn): the connection itself is the shared handle. The public handles
  (`connection`, `net::transport`, the streams, `transaction`) hold their
  state by pointer for shared lifetime and address stability, not as a
  compilation firewall: the connection's `detail::core_ref` is shared
  with its tasks, and the transport's block is self-referential (a
  reference-mode TLS stream over its socket, views of both).
- Threading (coro-ldap-nj9): the usual deployment is one io_context run
  by a thread pool, so thread safety is built in, not a convention. The
  connection's state runs on a `capy::strand` over the io_context's
  executor (`connection::executor_type`, `executor()`): the writer, the
  reader and the due watcher are started on it, and every public
  operation (of `connection`, `search_stream`, `paged_search`,
  `transaction`) enters it through `detail::on_strand`
  (`src/strand_util.hpp`): inline when the awaiting task already runs
  there (its executor compares equal to the strand), else through
  `capy::run(strand)`, which posts the operation's task there and resumes
  the caller on its own executor. Waits inside it (async_event, timers,
  socket I/O) resume through the strand, their task's executor. Corosio's
  `tls_stream` requires exactly this (all operations on one stream within
  one strand on a multi-threaded context). On one thread the price is two
  posts per operation started from a task of the plain io_context
  executor (onto the strand, and back); none when the caller runs on the
  strand. Since run_async dispatches, a writer or reader started on the
  strand runs at once, up to its first suspension.
  - Accessors (`is_open()`, `outstanding()`, `is_tls()`,
    `security_layer()`, `bind_count()`, `detail::accepts_requests()`) read
    atomic snapshots that the strand publishes after each change
    (`core::publish()`); `close()` clears the open snapshot at once,
    before its posted work runs, and the others but `bind_count()` read
    as closed while it is cleared (a publish racing close() cannot bring
    them back).
    `transaction::is_open()` is an atomic. A second concurrent `next()` on
    a `search_stream` or `paged_search` fails with `operation_in_progress`
    (checked on the strand). A stream's other accessors (`done()`,
    `references()`, `controls()`) read what its `next()` calls wrote:
    not while one runs.
  - capy::strand cannot be entered synchronously (its lock is private), so
    the noexcept paths called off it, `connection::close()`, the
    destructors (connection, `search_stream`, `paged_search`,
    `transaction`) and `detail::set_close_hook`, post their work
    (`detail::run_on_strand`), unless the calling thread runs the strand,
    or the io_context is stopped and the calling thread is not inside its
    `run()`: then the work runs inline. `stopped()` is true from `stop()`
    on, while other threads may still finish a handler on the strand, and
    nothing public tells whether one does, so the inline path is
    documented as needing those threads joined first: an interim
    precondition, stated once in API.md (the connection.hpp entry's
    "Threading"; the client.hpp entry refers to it), that cannot be
    detected today (the strand's lock is private, and `stopped()` says
    nothing about threads still in a handler; TSan reports a violation).
    The way out
    is upstream: a synchronous try-enter on `capy::strand` (coro-ldap-nj9.11
    tracks it; nj9.10 has the proposal), after which `run_on_strand`
    runs the work inline when the strand is idle and posts it otherwise.
    Rejected meanwhile: always posting (after `run()` returns from a stop,
    destroying a connection would no longer close it; the cleanup waits
    for a restart and is dropped with the io_context, leaking the stream
    and transaction states); an `ldap::run(ioc)` wrapper counting the
    threads inside `run()` (still a convention, nothing stops a direct
    `ioc.run()`, and `run_one`, `run_for`, `poll` to mirror) or a counting
    executor bracketing every resume (a frame per hop, a new
    `executor_type`: option B by another name); and a patched Capy (the
    build prefers an installed Capy through `FIND_PACKAGE_ARGS`, where a
    fork-only API would not compile). The
    `std::jthread` declaration-order pitfall is in API.md's threading
    section. Called from inside
    `run()` after `stop()`, the work is posted: a strand busy on another
    thread runs it before that thread leaves `run()` (capy's strand
    invoker empties its queue whatever `stop()` says), an idle one when
    the io_context is restarted and run. Breaking rule (user decision, option A of nj9):
    after destroying a stream, paged search or transaction off the strand,
    the memory resource of its entries must outlive the next run of the
    io_context, which runs the posted cleanup, and `close()` takes effect
    then. An own strand-like executor whose lock could be taken
    synchronously (option B) would have kept the synchronous semantics; it
    was not chosen.
  - `ldap::client` has a strand of its own for the pool state
    (`client::executor()`); acquire(), the forwarders, `close()` and a
    lease's release enter it the same way. Its connections keep their own
    strands, so operations on different pooled connections run in
    parallel; the close hook a connection runs on its strand posts the
    pool's `notify()` to the client's strand, and the pool reads a
    connection's state through the snapshots. A forwarded operation thus
    hops client strand, connection strand, client strand.
  - `repository<T>` keeps its schema-check outcome in a mutex-guarded
    `detail::schema_check_cache`, so one repository may be used from several
    threads, in both modes.
  - Out of scope, documented: value types (`entry`, `dn`,
    `search_result`) follow the standard library's rules; a memory
    resource the caller passes for a search's entries must allow the
    strand allocating while the caller frees entries on another thread;
    `locking_mode::unsafe_io` and `unsafe` opt out of cross-thread use.
  - A SASL step a mechanism offloads (GSSAPI's calls to the KDC, section
    3) runs on a thread of its own and wakes the bind through the strand;
    the io_context counts it as outstanding work, and its destructor joins
    the thread.
  - Tests: `tests/net/thread_tests.cpp` runs a connection, a client and a
    repository from 16 tasks on a 4-thread io_context against an answering
    in-process server (every operation, concurrent `next()`s, the
    connection and the client destroyed with operations of other threads
    outstanding), clean under TSan (Clang, `build/tsan`); the integration
    test `[threads]` runs a connection, a client, a repository and streams
    against slapd the same way.
  - An io_context destroyed before it runs a posted cleanup again drops
    it (the state is leaked): the tests' `draining_context` polls before
    it is destroyed.

- Implemented (#12, `jhetz/ldap/sync.hpp`): a connected `sync::connection`
  owns an io_context and one I/O thread (kept alive by a work guard). Each method
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
  `sync::connection`, whose core it must not outlive: a move keeps the
  core, a reconnect `c = sync::connect(...)` destroys it).
- Free functions run through one generic entry (coro-ldap-aw4.5): the
  facades re-declare only the protocol operations (`connection_api`, the
  client's forwarders); every convenience over `ldap::connection` or
  `ldap::client` runs on them with `sync::run(d, make_task, args...)`,
  which calls `make_task(a, args...)` on the I/O thread, `a` being the
  facade's `ldap::connection` (a `sync::connection`'s, a lease's) or
  `ldap::client`, and waits for the task it returns. `sync::directory` is
  the concept of the four facades it takes. The library's own blocking
  conveniences are written that way, each a line over the async function
  (`sync::who_am_i` and the password calls, `sync::load_schema`,
  `sync::search_paged`, `ad::change_password` / `reset_password` in
  ad/sync.hpp), and so is `ldap::repository` over a facade, each call one `sync::run`. A
  whole convenience is one task on the I/O thread, not one round trip
  per protocol call, and it behaves exactly as the async one (the
  client's retries, AD's protection check on the connection the modify
  goes to). The alternative, a `sync::directory` adapter giving the
  blocking facades async-looking members so that the async templates
  instantiate over them, would have made every operation a blocking call
  dressed as a task and would not cover the non-template `client &`
  overloads. `sync::run` reaches the facades' private `call(make_task)`
  through `detail::facade_access`. The task must end what it creates on
  the I/O thread before it returns (`ldap::search_paged` reads every page
  of its `paged_search` on the connection's strand, or destroys it
  there): `sync::run` hands out no streams; the facades' own
  `search_stream()` returns a `sync::search_stream`, which keeps the
  `ldap::search_stream` on the I/O thread behind a `unique_ptr`, runs
  each `next()` there and destroys it there (`hand_over`), as
  `sync::transaction` does with its `ldap::transaction`. A `static_assert` on the
  `detail::io_context_bound` trait rejects a task whose result is (or
  wraps, in `result`, `std::optional` or a smart pointer) a stream, a
  `paged_search`, a lease, a transaction, an `ldap::connection` or an
  `ldap::client`: a returned copy of the facade's connection handle
  would outlive the I/O thread's io_context, and its destruction (the
  last handle closing the core) would run on a destroyed io_context.
  A copy smuggled out through a capture by reference is not caught.
- The noexcept paths that end objects of the I/O thread (the
  destructors of `sync::connection`'s core and of the client's core,
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
  keeps the target's resource): the decoded message model (`message`, the
  responses, `ldap_result`, `control`, `partial_attribute`, the typed
  response controls), `filter`, `dn`, `attribute`, `entry`, `url`,
  `ber::writer`. `error` is the deliberate exception (section 5), and so
  are the request operations (3jj.2): built once per operation and never
  bulk-decoded, they are plain values with `std::pmr` members on the default
  resource. Their allocator-aware special members were about 300 lines of
  constructors and assignments the decode path never used; the connection
  copies results off its arena anyway. Dropping them did not affect
  decoding: the decoded types keep their allocator awareness. `decode_options::memory` sets where decoding
  allocates (`read_options.decode.memory` for the network path);
  `encode(m, mr)` and `write_message(t, m, mr | ber::writer&)` let callers
  pool write buffers. `tls_options` stays a plain aggregate with
  `std::filesystem::path` for files.
- String types (mcb): a call that takes a `memory_resource *` returns
  `std::pmr` strings on it (`dn::to_string(mr)`, `url::to_string(mr)`);
  the members of allocator-aware types are `std::pmr` (entry values,
  `extended_result`, the message model); every other returned string is
  `std::string` (`who_am_i()`, `password_modify()`'s generated password,
  `start_transaction()`'s identifier, `sync::transaction::identifier()`).
  `ldap::error` (pmr members, default resource) is the documented
  exception. String parameters of a coroutine (task) are taken by value,
  so the frame owns them (`end_transaction(std::string identifier)`).

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
- A per-message monotonic arena with a buffer that holds a typical
  response decodes with no heap allocations, and faster than the default
  heap resource. Decoding counts list elements first to reserve vectors
  exactly (a third fewer heap allocations); with the BER header fast path
  (#19) that costs nothing measurable, so it is unconditional.
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
  AF_UNIX (Windows 10 1803+) through Corosio, CryptoAPI for default
  verification (`src/net/trust_store_win.cpp`, the only Windows-specific
  source; CMake picks it instead of `trust_store_default.cpp`; below),
  file names through `std::filesystem::path`.
  Linux only: abstract ldapi:// sockets, SASL GSSAPI (no SSPI), the
  integration tests, coverage and the fuzzers. `/WX` is on by default with
  MSVC (built clean with 19.44), off on clang-cl (not built yet). macOS is
  not supported.
- Corosio and Capy pinned by commit (FetchContent), used only by
  `jhetz_ldap` (option `JHETZ_LDAP_BUILD_NET`, off by default in fuzz builds);
  it also needs OpenSSL.
- ICU (decision 6; `find_package(ICU COMPONENTS uc data)`) for Unicode,
  linked privately by both libraries (the public headers do not include
  ICU's); the installed package config always finds it. The codec
  (`jhetz_ldap_core`) decodes and validates UTF-8 with it (`U8_NEXT`) and asks
  it for character properties (General_Category, Bidi_Control: what
  `ldap::error::message()` replaces); `jhetz_ldap` uses its stringprep
  (SASLprep for SCRAM). One hand-rolled piece is left on purpose: the
  UTF-8 check of compile-time DN literals (`detail::scan_dn` in constant
  evaluation, `constexpr_utf8_sequence_length` in attribute.hpp), since ICU's
  functions cannot run there and its `U8_NEXT` macro would need ICU's
  headers in the public ones; a test checks it answers as ICU does.
- Optional: the GSS-API library (MIT krb5) for SASL GSSAPI, with
  `JHETZ_LDAP_WITH_GSSAPI` (pkg-config `krb5-gssapi`), privately linked
  by `jhetz_ldap`.
- Coverage: Clang source-based coverage (`JHETZ_LDAP_COVERAGE`, llvm-cov),
  scoped to our own targets like the warnings; `tests/coverage/run_coverage.sh`
  runs it (docs/DEVELOPMENT.md, "Coverage"). Local only, not in CI.
- C++26 (reflection, `std::execution` interop) on a separate branch.

## 10. Message model (implemented, step 3)

`jhetz/ldap/message.hpp` is a faithful wire model of RFC 4511: an
`ldap::message {id, op, controls}` where `op` is a `std::variant` of every
protocol operation, requests and responses. The client libraries encode
every operation but decode only what a server sends; the server side of
the codec is the testing target (below), so the same model serves the
client and the mock servers.

- Wire fields (LDAPDN, LDAPString, attribute values) are `std::string` holding
  raw octets, so a server sending an odd DN never breaks decoding; the
  vocabulary types of section 1 are for the API layer.
- Types have value constructors (not aggregates); wire strings are
  `std::pmr::string`, lists `std::pmr::vector` (`string_list`). The
  decoded ones (responses, `message`, `control`) are allocator-aware, the
  requests are plain values (section 8).
- `encode(const message&, mr)` returns `result<std::pmr::vector<std::byte>>`.
  It fails with `invalid_filter` (empty or over-limit filter) or
  `encode_error` (values the wire
  format cannot carry: negative ids or limits, out-of-range enums, an add
  with no values, a request with message id 0, which RFC 4511 section 4.1.1
  reserves for unsolicited notifications), and all checks run before any
  byte is written. The testing target's `testing::decode` rejects the
  same empty adds and id-0 requests, so it and `encode` accept the same
  messages. `testing::decode(encode(m)) == m` exactly (filters are trees),
  `decode(encode(m)) == m` for a response, and
  `encode(decode(encode(m)))` is byte-identical to `encode(m)`.
- `decode(bytes, decode_options)` takes exactly one framed message from a
  server. It rejects request operations before decoding them, so a hostile
  server cannot make the client parse client-only structures such as
  search filters; the client libraries have no request decoder at all.
  Depth and element limits are options.
- The server side of the codec is a separate, never installed library:
  `testing/` builds `jhetz::ldap_testing` (over `jhetz::ldap_core`) and
  `jhetz::ldap_testing_net` (adds `testing::read_message`, over
  `jhetz::ldap`), only with the tests or fuzzers, which
  link them, as do the mock servers. Namespace `ldap::testing`, headers in
  `testing/include/jhetz/ldap/testing/`: `testing::decode(bytes,
  testing::decode_options)` with `from = origin::any / server / client`
  (default `any`, for round trips) and the filter limits;
  `decode_filter`; the response controls a server writes (sort result, VLV
  response, pre/post-read entry, Sync State / Done / Info, txnEndRes,
  DirSync response); the request controls it reads (matched values, VLV,
  Transaction Specification, Sync Request, txnEndReq, DirSync request);
  and NTLM's CHALLENGE_MESSAGE encoder and AUTHENTICATE_MESSAGE parser. It
  reuses the client's internals through `src/` (the message decoder in
  `message_codec.hpp` takes a `request_reader` for the request
  operations, the filter tree's access in `filter_ast.hpp`, the BER
  helpers in `control_util.hpp`, the NTLM wire layout in `ntlm_wire.hpp`),
  so nothing is duplicated and the client libraries ship none of it.
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

`client.cpp` keeps the state in three parts, all used on the pool's
strand: `server_health` (the servers in priority order and their
backoff), `connection_pool` (the pooled connections, the slots they and
the attempts take, `closed`, and the event acquire() waits on), and
`client_state`, which owns both with the options and the stop sources
close() stops. The acquire loop, the forwarders and the referral wiring
are free coroutines over a `shared_ptr<client_state>`; leases are built
and read through `detail::lease_access`.

- One type, `ldap::client` (the name `naming-connection` reserved), built
  from `client_options{servers, connection, setup, max_connections = 1,
  idle_check = 60 s, probe_timeout = 5 s, max_lifetime, acquire_timeout =
  30 s, backoff, failback_after = 5 min, observer, referrals}` on one io_context;
  the pool state runs on a strand of its own and each connection on its
  own (section 7, "Threading"). Connections are
  opened lazily by `acquire()`, up to `max_connections`; nothing runs in
  the background (no timer keeps `io_context::run()` alive).
- `max_connections` stays 1 by default (c67, user decision): one
  multiplexed connection, which every shared lease uses at once. More
  connections mostly matter for exclusive leases, which wait for an idle
  connection, and for isolating slow operations; the header and API.md say
  so where the option is.
- **Leases share connections by default** (the open choice of the
  decision: "exclusive or shared"; the 3pf.6 review kept shared as the
  default and added exclusive). `acquire() -> task<result<lease>>`; a
  lease gives the pooled `connection`, and several leases may hold the same
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
  it for all. A connection whose `unbind()` has begun takes no more
  requests although `is_open()` stays true until the UnbindRequest is
  written: the pool tests `detail::accepts_requests()`, so it is retired
  (`closed`) and never handed out again. A failed bind silently drops
  them all to anonymous. Hence `acquire_exclusive() ->
  task<result<exclusive_lease>>`: an idle connection, else a new one
  while a slot is free, else it waits; no other acquire (shared or
  exclusive) gets that connection while the exclusive lease holds it.
  While an exclusive acquire waits (`connection_pool::exclusive_waiting`),
  shared acquires never take an idle connection: they share one already
  shared, else open a new one (a slot free, a server to try) or wait, so
  shared load cannot starve it (3pf.7; 3pf.9 for the case with no other
  shared connection, e.g. `max_connections = 1`). With every server
  excluded such a shared acquire waits too rather than fail while the
  idle connection exists (`waits_for_exclusive`), and an exclusive
  acquire that waited and ends without a lease (stopped, timed out,
  destroyed) calls `notify()`, so the shared ones it held back look
  again at once (3pf.11).
  Bind, `start_tls()` and `unbind()` belong on exclusive leases. A
  shared `lease` gives the `connection` itself, as an `exclusive_lease`
  does (both derive from `detail::lease_base`: `server()`, `release()`,
  `operator bool`); its `simple_bind`, `sasl_bind`, `start_tls`, `unbind`
  and `close` change the session for every lease sharing the connection
  (a bind retires it, see below). coro-ldap-9uu had a
  `shared_connection` type without those five, so that misuse would not
  compile; coro-ldap-tfn removed it by user decision (it was not
  useful), and what took one (the free `chase_search`, `chase_compare`,
  `make_same_policy_connector`, `ad::change_password` /
  `reset_password`) takes `connection &` again. Copying the leased
  `connection` (coro-ldap-vk8) makes a handle the pool does not track: the
  pool's bookkeeping counts leases, not handles, and it ends a connection
  leaving the pool with an explicit `close()` or `unbind()`, never by
  dropping its own handle, so the session ends for such copies too; an
  exclusive lease's exclusivity covers leases only. The `acquire_options{.exclusive}`
  run-time flag stays two calls. The blocking facade matches:
  `sync::lease` (`acquire()`) and `sync::exclusive_lease`
  (`acquire_exclusive()`) both have every `sync::connection` operation,
  both `sync::basic_lease<Exclusive>`. The header says to use one client
  per identity and keep binds to the setup; per-identity sub-pools are a
  later bead. (`acquire()` is not a
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
  the last error (or the last error of the server whose backoff ends
  first, its context marked "backing off"; with none backing off,
  `capy::error::timeout` "no connection ready"). With no
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
  unbound (3pf.13): a task posted then would never run. Corosio before
  232c79f leaked such a task, its connection and socket when the
  io_context was destroyed (LeakSanitizer, `examples/pool.cpp` with the
  client in `main()`); Corosio now destroys it with the io_context
  (tested: a client destroyed after `restart()`, the io_context never
  run again), but the rule stays: the connection is freed at once, its
  memory resource need not outlive the io_context, and no task is left
  that can only be destroyed. Closed is what a `connection` or a
  `sync::connection` does when its last handle is destroyed: no UnbindRequest, nothing left
  on the io_context. Unbinding cleanly at `close()` still works while
  the executor runs (from a task, as `examples/pool.cpp` does).
- `client_observer`: virtual hooks, no-ops by default, called
  synchronously on the client's strand: `on_connect(server, outcome)` after each
  attempt, `on_retry(server, error, delay)` when a server enters backoff,
  `on_disconnect(server, reason)` when a connection leaves the pool,
  `on_probe(server, outcome)`, `on_acquire_wait(waited)` once per acquire
  that had to wait. None after `close()`. No logging dependency.
- Setup helpers: `simple_bind_setup(dn, password)` and
  `sasl_bind_setup(factory, dn)`, the factory making a fresh mechanism per
  connection (a null one fails with `invalid_argument`, so the server is
  not retried in that acquire).
- Read forwarders (3pf.4): `client::search`, `search_stream` and
  `compare`, the `connection` names and shapes. Each acquires a
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
  search with nothing to send returns at its first change. Extended
  operations are a write forwarder (below). The observer has no hook for an
  operation's retry (the retirement shows as `on_disconnect`, a new
  connection as `on_connect`). Each call may land
  on any pooled connection, so connection-bound request controls (a
  paged-results cookie from an earlier page, anything tied to the
  session) need a lease (3pf.15).
- Write forwarders: `client::add`, `modify`, `del`, `modify_dn` and
  `extended`, the `connection` names and shapes (`extended` is one: an
  extended operation may change the directory, so it is retried only
  after `not_sent`; the free `ldap::who_am_i` and password calls run on
  it, and Who am I? lost its read retry, coro-ldap-aw4.4). Typed CRUD is a layer over the client and
  the connection (`ldap::repository`, section 4). Each acquires a shared
  lease, runs the operation and returns the lease, like the read
  forwarders, but retries only after `client_errc::not_sent`: the request
  never reached the connection's writer (refused by a closed connection,
  still queued behind another PDU, or held behind a bind when the
  connection closed), so the server never saw it and running it on another
  connection cannot apply it twice. Every other failure may follow a
  request the server received, and possibly applied: a connection lost
  after the writer took the request (`not_connected`, a transport error),
  a timeout (the server may still apply it), busy or unavailable (an
  unsolicited Notice of Disconnection fails the outstanding operations
  with its code even when the server already applied them), so it is
  returned and the caller decides (reading the entry back, an idempotent
  change, a transaction). The retry's `acquire()` goes by priority order
  (no `avoid`): `not_sent` says nothing about the server.
  `forward_write<T, Op>` is the loop, a template like `forward_read<T, Op>`,
  the operation called once per attempt on the lease, copying the request
  into each; a forwarder builds its error context only for a moved-from
  client. A referral result is never chased for a write, whatever
  `client_options::referrals` says: it fails with `errc::referral` and the
  URIs in `error::referrals`, as on a connection (a referral means the
  update was not performed, RFC 4511 section 4.1.10). Chasing an update
  would send it, with the client's credentials, to a server the update's
  author did not name. UnboundID (`followReferrals`), libldap
  (`LDAP_OPT_REFERRALS`) and JNDI (`java.naming.referral=follow`) chase
  writes when asked to; this client keeps never, with no switch, until a
  use case asks for one. Connection-bound request controls
  (`transaction_specification`) need a lease, as for the read forwarders.
  Tests: a write queued on a shared connection behind another lease's 1
  MiB AddRequest while that lease closes the connection: the queued write
  fails `not_sent` and succeeds on a new connection; a connection lost
  after the server read the request, a timeout, busy, a result code and a
  referral are each returned with exactly one request seen. The queued
  write must still be queued when the connection closes, so the AddRequest
  must not fit in the kernel's buffers while the server reads nothing: the
  server's end has a small SO_RCVBUF, and the pooled connections are
  opened by a test connector (`detail::test_access::set_connector`, src/test_access.hpp, like
  `set_jitter`) on a socket with a small SO_SNDBUF set before it
  connects. Setting SO_SNDBUF turns autotuning off, so `tcp_wmem` (whose
  default or maximum may reach several MiB) no longer applies, and the
  test requires the two buffers as the kernel reports them to hold less
  than the AddRequest.
- Tests (`tests/net/client_tests.cpp`): loopback servers each running one
  script per accepted connection; backoff on real delays of 30 to 60 ms
  with the jitter fixed by `detail::test_access::set_jitter`. One slapd
  test drops a connection through a relay and acquires again.
- Blocking facade (3pf.5, `jhetz/ldap/sync.hpp`): `sync::client(options,
  mr)` owns a `detail::client_core`, the `io_thread` (section 7) and the
  `ldap::client` made, used and destroyed on it, shared through a
  `shared_ptr` by the facade and its `sync::lease`s (each holding an
  aliasing pointer to the core's `io_thread`, its `ldap::lease`, touched
  only on that thread, and a copy of its server URL). `acquire()`, the
  read forwarders `search`, `compare` and the write
  forwarders `add`, `modify`, `del`, `modify_dn`, `extended` post
  to the I/O thread and wait, as `sync::connection` does; the retry is
  `ldap::client`'s.
  `sync::lease` exposes `sync::connection`'s operations
  (`detail::connection_api`) on the leased connection. `search_stream`
  returns a `sync::search_stream` holding one shared lease until
  destroyed, retried as `client::search_stream` is. Its destructor
  destroys the stream on the connection's strand and returns once the
  lease's return is queued on the client's strand, so a `sync::client`
  destroyed next unbinds that connection instead of closing it as still
  leased (coro-ldap-44h).
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
  shared lease (a request's `follow_referrals` overrides the first
  switch), and return the chase's `search_result` / `compare_result`:
  the entries, the URIs of the continuation references not followed (as
  `connection::search()` returns the ones it does not follow), the done
  fields, where a followed reference's limit code stands in for the
  origin's success so that partial entries are never `is_success()`, and
  the report (`referrals`, `unlisted`). A reference not followed because
  `follow_references` is off is counted in `unlisted` and kept in
  `references` (so `is_complete()` is false), without an attempt entry
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
  no `follow_writes` in v1. The client's write forwarders (`add`,
  `modify`, `del`, `modify_dn`, also `sync::client`'s) run each write on a
  lease, whose `connection` returns a referral result as is: a referral
  result means the update was not performed (RFC 4511 4.1.10), and
  resending it elsewhere is the caller's decision, with
  `referral_target(url, add_params ...)` building the request. `search_stream()` and `extended()` never chase: a stream hands its
  references out as they come, and merging chased entries into it would
  change what `next()` means. `client_observer::on_referral(server,
  attempt)` is called for each attempt as it is decided (also beyond
  `max_attempts`), never for references left unexamined or switched off.
  `sync::client`'s `search()` and `compare()` chase through
  `ldap::client`'s.
- Later (beads): a background prober, DNS SRV, weighted or round-robin
  selection, per-identity sub-pools, pooled referred connections.

## 12. Active Directory layer (`ldap::ad`)

Active Directory behaviour that no RFC describes lives in
`namespace jhetz::ldap::ad`, a layer built only on the public API, as
ldap3's `conn.extend.microsoft` sits on its connection and .NET's
AccountManagement on System.DirectoryServices.Protocols. The split rule:

- The core keeps the standard extension points, whoever uses them: SASL
  mechanisms (NTLM through GSS-SPNEGO included: a mechanism is a SASL
  plug-in), generic controls and extended operations (any OID, typed or
  raw), and the raw result (result code, diagnosticMessage, matched DN) of
  every error.
- `ldap::ad` holds AD semantics: what AD's attributes, values and
  diagnostics mean, and operations only AD defines
  (unicodePwd password changes, DirSync, change notification, ranged
  retrieval, domain controller discovery).
- Free functions taking what they work on (`connection &`, `client &`,
  `const error &`, the sync facade's types), no wrapper class until one
  carries state of its own.

Layout:

- Codec-level AD code (no network) is in `jhetz::ldap_core`: headers under
  `include/jhetz/ldap/ad/`, sources under `src/ad/`. `ad/filetime.hpp`
  (the FILETIME clock and its `value_traits`, section 4),
  `ad/syntax.hpp` (AD's syntax OIDs), `ad/sid.hpp`, `ad/guid.hpp` and
  `ad/user_account_control.hpp` (the value types below),
  `ad/filters.hpp` (filters on AD's bitwise matching rules, below),
  `ad/controls.hpp` (AD's request controls, change notification's search
  and DirSync's codec),
  `ad/range.hpp` (the range
  option of ranged retrieval),
  `ad/password_value.hpp` (the `unicodePwd` value) and
  `ad/diagnostic.hpp` (`explain`). These headers are installed with the
  codec-only package too.
- AD operations that need the network go in the target `jhetz::ldap_ad`
  (export name `ldap_ad`, package component `ad`), sources under `src/ad/`
  next to the codec's, their headers under `include/jhetz/ldap/ad/` too,
  listed with the net headers in the codec-only install's EXCLUDE patterns
  and `tests/CMakeLists.txt`'s header check.
  It links `jhetz::ldap` and includes only public headers, never
  `src/connection/` or `src/net/`; it is built and installed whenever
  `jhetz::ldap` is. `ad/password.hpp`, `ad/ranged_values.hpp` and
  `ad/dirsync.hpp` (async, `connection &` and `client &`),
  `ad/discover.hpp` (DNS discovery, blocking) and `ad/sync.hpp` (the
  blocking forms, over the sync facades through `sync::run`).
  A target of its own rather than `src/ad/` inside `jhetz::ldap`: the
  dependency is one-way and visible in CMake (`jhetz::ldap` cannot
  reach `ldap::ad`, `jhetz::ldap_ad` sees no private header), a consumer
  who never talks to AD does not link it, and the package says by
  component whether it is there.
- The core does not depend on `jhetz::ldap_ad`.

Value types, each with `value_traits` for the typed mapping (section 4):
`ad::sid` (MS-DTYP 2.4.2: the binary form objectSid holds, revision 1,
the 48-bit authority big-endian and up to 15 sub-authorities
little-endian, and the "S-1-..." string form, the authority in decimal
below 2^32 and in "0x" and 12 hex digits above; a class, since the count
and the authority's width are invariants), `ad::guid` (MS-DTYP 2.3.4:
an aggregate of Data1, Data2, Data3 and Data4; the binary form has the
first three little-endian, so objectGUID's octets are not the text's
order; the text is written in lower case without braces, as RFC 4122 and
.NET's default, and read with or without braces) and
`ad::user_account_control` (MS-ADTS 2.2.16's UF_ bits as an
`enum class` over `std::uint32_t` with bitmask operators and `has`; the
value is AD's signed 32-bit INTEGER, so bit 31 is written negative and
both spellings are read). `sid` and `guid` accept Octet String in
`validate<T>`, `user_account_control` INTEGER. `sid::parse` also takes a
SID without sub-authorities ("S-1-0"), which MS-DTYP's ABNF does not
list but the binary form can hold, so every value round-trips. Tested
with MS-DTYP and .NET vectors (`tests/ad_types_tests.cpp`) and on Samba
(`integration.samba_ad`: Administrator's RID 500 under the domain SID,
lookups by typed objectSid and objectGUID filters, a new user's
userAccountControl written back).

Filters: `ad::all_bits` and `ad::any_bits` (`ad/filters.hpp`) build the
extensible matches on LDAP_MATCHING_RULE_BIT_AND and BIT_OR (MS-ADTS
3.1.1.3.4.4.1), from an attribute or a described member, for a
`user_account_control` or an integer. The value is written by the type's
`value_traits`, so bit 31 of a `user_account_control` is AD's signed
decimal, and the rule OIDs are named constants. Tested byte for byte
(`tests/ad_types_tests.cpp`) and on Samba (`integration.samba_ad`: a
disabled user found by BIT_AND and BIT_OR, not found negated).

Controls: AD's request controls are types in `ldap::ad` that convert
implicitly to a raw `ldap::control`, the core's escape hatch allowed on
every operation, so `.controls = { ldap::ad::show_deleted{} }` reads like
a core typed control without the core's closed variant lists knowing about
AD. `ad::show_deleted` (1.2.840.113556.1.4.417, MS-ADTS 3.1.1.3.4.1.14)
has no value and is critical by default, as System.DirectoryServices.
Protocols' ShowDeletedControl: on a server that does not know it the
search fails (unavailable_critical_extension) rather than silently
leaving deleted objects out. Tested by its encoding
(`tests/ad_controls_tests.cpp`) and on Samba (a user added, deleted, then
found by its objectGUID with the control, under CN=Deleted Objects with
isDeleted TRUE, and not without it).

Passwords: `ad::change_password(c, user, old, new)` sends one
ModifyRequest of `unicodePwd` deleting the old value and adding the new
one (a user's own change, which AD checks against the old password),
`ad::reset_password(c, user, new)` one replacing it (an administrator's),
with `ad::password_value()`'s quoted UTF-16LE (MS-ADTS 3.1.1.3.1.5). AD
DS, AD LDS and Samba AD alike: no detection, the caller knows its
directory. Validation (empty passwords, an empty DN, ill-formed UTF-8)
fails before anything is sent, and so does an open connection protected
by neither TLS nor a SASL confidentiality layer
(`client_errc::tls_required`): AD takes unicodePwd over any connection
encrypted with keys of 128 bits or more (MS-ADTS 3.1.1.3.1.5.1), TLS or a
sealing SASL layer (Kerberos, NTLM; Windows' own tools seal on port 389).
NTLM's integrity seals too over LDAP, so `security_layer()` reports
confidentiality for both NTLM levels; GSSAPI integrity alone is refused.
AD's Win32 code at the start of a refusal's diagnostic is explained in
the context (0000052D, 00000056, 00000005, 00000775) by
`ad::explain(const error &)`, a codec function returning a static text
(empty when the code is not one it knows); the diagnostic is kept as
sent, and the core never interprets it. Overloads: `connection &`
(a connection or a shared lease's) and
`client &` (a shared lease, retried once after `not_sent` as the write
forwarders are: the protection check needs the connection the modify goes
to, so it cannot go through `client::modify`; the connection that failed
with `not_sent` is closed or being unbound, so the retry's `acquire()`
never gets it again; both `acquire()` tasks are created before the call
returns, so, as with the client's own forwarders, the task does not refer
to the client), and blocking ones in `ad/sync.hpp`, which run the async
ones with `sync::run`. There is no
"detect and dispatch" helper: the caller calls the core's RFC 3062
functions or these. Tested against the scripted mock
(`tests/net/ad_password_tests.cpp`, with the `client &` overloads'
`not_sent` retry, `sync_tests.cpp`, `sync_client_tests.cpp` for
`sync::lease &` and `sync::client &`, `sasl_layer_tests.cpp` with a
made-up layer at each level) and a Samba AD DC (`integration.samba_ad`:
reset, change, a non-BMP password, 0000052D and 00000056, plain ldap://
refused, a change and a reset over the NTLM layer (integrity and
confidentiality) on plain ldap://, an NTLM bind without a layer refused,
`ldap::client`, `sync::connection`, and the core's RFC 3062 calls refused
by Samba).

Ranged retrieval: AD returns a multi-valued attribute with more values
than MaxValRange (lDAPAdminLimits, 1500 by default) in windows, named by
a range option (MS-ADTS 3.1.1.3.1.3.3): `member;range=0-1499`, and the
client asks for `member;range=1500-*` until a window ends with `*`.
`ad::read_all_values(c, object, attribute)` does that with base-object
searches and returns the values as one `string_list`. By default it asks
for the plain attribute first, as AD's own clients do: a server that
needs no window answers with all the values at once. With
`range_options::step` it asks for windows of that size from the start
(`member;range=0-999`), which bounds each answer on a server that does
not enforce MaxValRange; a window the server cuts shorter is followed
from where it ended. The answer ends the read when it holds the plain
attribute (the first answer only), a window ending with `*`, or no such
attribute: Samba drops the attribute when a window starts past the last
value, which happens when the count is a multiple of the step. A
server answers under its own name for the type, not the requested form
(Samba and AD answer `2.5.4.31` as `member`, slapd an alias with the
primary name), and matching that needs the server schema; since the
search asks for one attribute of one entry, the returned attributes are
grouped by description without the range option (case-insensitive, other
options kept), and the group named as asked is the answer, else the only
group present whatever its name; the following windows ask for the
server's name. A server may ignore the range option (Samba answers
`2.5.4.31;range=0-2` with a bare entry, slapd ignores it on every
attribute), which looks exactly like an attribute without values, so
with a step a first window (`low == 0`) that completes with no value is
asked for once more with the plain description, at most once, and that
answer is taken as without a step: no attribute is no values, the plain
attribute all of them, and a ranged answer continues under the server's
name in windows of the step. An attribute without values then costs two
searches; the values do not depend on the step, except that such a
server sends them in one answer, and naming the lDAPDisplayName keeps
the bound on a server that honours ranges. A bare later window keeps
meaning "past the end", which Samba relies on. Refusing a numeric OID
with a step, or probing with typesOnly, was rejected: the retry costs
one search only in the empty case and needs no new error. Several groups none named as
asked are refused. Within the group, AD may send a value-less plain
attribute next to the window (MS-ADTS 3.1.1.3.1.3.3: `member` and
`member;range=0-1499`), so one ranged attribute with at most one
value-less plain one is the window and a lone plain one is every value;
any other combination (two ranged, a plain one with values next to a
ranged one) is `unexpected_response` rather than a first match. Every
other shape is refused rather than guessed at (a window not starting
where the previous one ended, the plain attribute after a window:
`unexpected_response`; a malformed range: `decode_error`), so the values
are never silently incomplete or duplicated. The range option's syntax is
a codec function (`ad/range.hpp`: `parse_range`, `with_range`, bounds of
32 bits, the option name case-insensitive, other options kept), fuzzed
through `message_fuzz` on every search entry's attribute names. The
`client &` overload runs every window on one shared lease, the windows of
one entry on one server, and starts over once on a new lease after
`connection_lost`, as `load_schema(client &)` does; the blocking form is
in `ad/sync.hpp`. Samba (4.22) honours range options but does not enforce
MaxValRange (a plain request gets every value), so its test
(`integration.samba_ad`, a group of 1600 contacts made at image build
time) reads the group without a step and with steps that end inside,
at, and past the last window; the mock tests
(`tests/net/ad_ranged_values_tests.cpp`) play AD's windows and the
refused shapes.

DirSync (MS-ADTS 3.1.1.3.4.1.3) is AD's poll-based change tracking, the
counterpart of RFC 4533's refreshOnly: a search carrying the DirSync
control returns the objects changed in a naming context since the
cookie, each with the requested attributes that changed, and the
response control carries the next cookie and MoreResults. Codec in
`ad/controls.hpp` (`jhetz::ldap_core`, so `message_fuzz` covers it):
`dirsync_request` converts implicitly to a raw `control` like
`show_deleted`, since every value is encodable; names and field order are
the spec's (Flags, MaxBytes, Cookie; MoreResults, unused, CookieServer).
Flags is written as the signed 32-bit INTEGER Windows and .NET send
(`incremental_values` is bit 31, so negative) and read signed or
unsigned; MaxBytes defaults to .NET's 1048576; MoreResults is an INTEGER
read as non-zero and written 1 or 0. One OID names both the request and
the response control, so the fuzzer decodes every such control both ways.
`ad::dirsync(c, request, options, max_rounds)` (`ad/dirsync.hpp`,
`jhetz::ldap_ad`) runs the search again with each new cookie while
MoreResults is set, at most `max_rounds` searches, and returns every
entry and the last cookie; the caller stores the cookie for the next
poll. `ad::dirsync_request` stays the pure wire value; the bound is a
parameter of the call. Collecting the batches is the common case, and a
caller who wants batch by batch passes `max_rounds = 1` or sends the
control itself with `ad::find_dirsync_response`. MS-ADTS 3.1.1.3.4.1.3
makes each response a valid batch and its CookieServer the resume point,
and MaxBytes and MaxPageSize mean a large naming context needs many
rounds, so reaching the bound is not an error: the result carries the
entries so far, the last cookie and `more_results = true`, and a
complete snapshot loops `while (r->more_results)`. A periodic poller that
only saves the cookie stays correct and gets the rest on its next poll.
The default, `ad::dirsync_default_max_rounds` = 1000, is about a million
objects at AD's default MaxPageSize; it counts searches (1 = one search,
the per-round call of ldap3, go-ldap and .NET). `max_rounds == 0` fails
with `std::errc::invalid_argument` before anything is sent, as
search_paged refuses a non-positive page size: 0 is LDAP's "no limit" for
size and time limits, so neither clamping it nor reading it as one search
would be clear. There is no entry cap; memory per round is bounded only
as far as the server honours MaxBytes and MaxPageSize. A server that
cycles cookies would otherwise keep the loop going: the call keeps the
cookies it has seen (the caller's and every CookieServer), and a response
with MoreResults whose CookieServer is one of them fails
(`unexpected_response`, "more results with a cookie already seen"); a
repeat without MoreResults is a success. A response without the control
fails the same way. `request.timeout` bounds each search, not the call;
an async caller can stop the whole call with its stop token. The
`client &` overload keeps one shared lease (the cookie is a DC's) and
starts again from the caller's cookie after `connection_lost`,
discarding what it collected and resetting the count of rounds; the
blocking form is in `ad/sync.hpp`. Samba never sets MoreResults
(source4 dirsync.c), so the multi-round paths are tested on the mock
only. Tested by its encoding (`tests/ad_controls_tests.cpp`, including
unsigned Flags and malformed values), against the mock
(`tests/net/ad_dirsync_tests.cpp`: cookies chained through MoreResults,
cycles of cookies, `max_rounds` reached and resumed, 0 refused, refused
answers) and on Samba
(`integration.samba_ad`: a changed description found with the cookie and
gone from the next poll, `incremental_values` returning an added member
as `member;range=1-1`, a user without the right refused and served with
`object_security`, `ldap::client` and `sync::connection`).

Change notification (MS-ADTS 3.1.1.3.4.1.9) is AD's push counterpart, close
to refreshAndPersist without the refresh: a search carrying
LDAP_SERVER_NOTIFICATION_OID never ends, and the server sends an entry
each time an object in scope changes, with no initial content and no
cookie (a reconnecting client re-reads what it needs). It needs no
plumbing of its own: `ad::notification` is a value-less control like
`show_deleted`, and `ad::notification_search(base, scope, attributes)`
a params builder (AD's filter `(objectClass=*)`, the control,
`no_timeout` so the operation timeout does not end it) for the core's
`search_stream`, which already serves RFC 4533's persist phase: entries
are queued until read, a stop token or the stream's destruction abandons
the search. There is no blocking form, since the sync facade has no
streams, and no `client &` overload: `client::search_stream` returns at
the first message, here the first change, so a caller holds a lease and
streams on it. AD's limits (base or one-level scope,
MaxNotificationPerConn, 5) are the server's to enforce. Tested by the
control and builder (`tests/ad_controls_tests.cpp`), against the mock
(`tests/net/ad_notification_tests.cpp`: changes after the operation
timeout, the AbandonRequest when the stream is destroyed) and on Samba,
which supports it (`integration.samba_ad`: two description changes on
one stream, base and one-level).

Domain controller discovery (`ad/discover.hpp`): the DC locator's DNS
records (MS-ADTS 6.3.2.3), `_ldap._tcp.dc._msdcs.<domain>` for a domain's
DCs, `_ldap._tcp.<site>._sites.dc._msdcs.<domain>` for a site's, and the
`gc` forms for Global Catalogs, turned into `url`s for
`client_options::servers`, whose order is the client's priority order.
Each record set is ordered as RFC 2782 says (priority, then a weighted
random pick, weight 0 first in the list so only a draw of 0 takes it);
with a site, its DCs come first and the domain's others follow, so the
client falls back past the site without a second discovery. Duplicates
and the "." target (service not offered) are dropped, and nothing left
is `host_unreachable` (`busy_or_unavailable`), the same condition as a
server that cannot be reached. SRV records give the LDAP ports only
(389, 3268); with `tls` the URLs use the fixed LDAPS ports (636, 3269).
`getaddrinfo` cannot ask for SRV records, so the system resolver is
called directly: `res_nquery` with its own `res_state` (thread-safe) and
libresolv's `ns_parserr` / `dn_expand` to read the answer, so the library
has no DNS message parser of its own to fuzz; on Windows
`DnsQuery_UTF8`. The resolver is a seam (`discover_options::resolver`,
`std::function`), which the tests script; `order_srv` is a template over
any `uniform_random_bit_generator`, tested with a scripted one, and
discovery itself uses a per-thread `mt19937_64`. Names are converted to
A-labels with ICU's UTS #46 (nontransitional, as IDNA2008 resolvers do),
so an internationalized domain or site is looked up as DNS holds it; the
targets DNS returns go through the same conversion (A-labels already,
lower-cased, one trailing dot removed; one it refuses is skipped). The
conversion runs without the STD3 rules, which refuse `_`, found in legacy
AD host names (NetBIOS-derived, accepted by Microsoft DNS); a converted
target must instead hold only letters, digits, `-`, `_` and `.`, so a
space, a control character, `/` or `:` still skips it. URLs are built from host and
port (`url::server`), never by concatenating text and parsing it, so a
target cannot smuggle in percent-escapes, a DN or extensions. With TLS
the target must be the queried domain or under it (RFC 6125 section
6.2.1: label-wise, case-insensitive, on A-labels): SRV answers are
unauthenticated, and the certificate check only proves the server is the
target, so a spoofed answer naming `dc.attacker.example` (with a valid
certificate for it) is skipped unless `require_target_in_domain` is
false. Unusable records are skipped, and only when none is left does
discovery fail, listing up to four of them with the reason. The calls block on DNS, as
`getaddrinfo` would: discovery runs once before a client is built, so
there is no async form. The link dependencies are private to
`jhetz::ldap_ad` (ICU, `resolv` or `dnsapi` by name, carried in the
exported link interface as plain names, so the package config only
documents them); the install check's consumer calls discovery with a
scripted resolver. No live DNS test: the Samba DC is provisioned without
DNS, and the unit tests cover the resolver only on a `.invalid` name
(RFC 6761), which must give no records.

What stays in the core (the audit of AD mentions outside `ad/`):
interop notes on how AD and Samba behave as servers (quoted schema OIDs,
MUSTs AD fills in, `member;range=` names, account lockout and the
client's bind backoff, channel binding and SASL layer policy), the NTLM
mechanism's own rules (no layer over TLS, sealing when only signing is
negotiated, its FILETIME timestamp), the RFC 2696 and RFC 2891 control
OIDs that sit in Microsoft's arc, and `validate<T>`'s acceptance of Large
Integer for signed integers of 64 bits or more: that is the core's
mapping of its own types, and a type has one `value_syntaxes`, so the AD
layer could not add it. The OID itself is public only as
`ad::large_integer_syntax`.

No detection: the library does not tell AD from other servers (no
reading of supportedCapabilities, no AD DS / AD LDS edition). The caller
knows its directory and picks the core's RFC calls or `ldap::ad`'s by the
function it calls; nothing in the library needed the answer once the
password method enum was gone.

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
