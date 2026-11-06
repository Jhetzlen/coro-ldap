# API reference

What each public header provides, in more detail than the README. The design
rationale is in [`DESIGN.md`](DESIGN.md).

## `jhetz::ldap`: the codec

- `jhetz/ldap/error.hpp`: `ldap::error`, `ldap::result<T>` (`std::expected`),
  `ldap::errc` (RFC 4511 result codes, RFC 4528's `assertion_failed`, RFC
  4533's `e_sync_refresh_required` and the VLV draft's
  `virtual_list_view_error`,
  category `ldap.result`) and
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
- `jhetz/ldap/content_sync.hpp`: RFC 4533 content synchronization
  ("syncrepl") codecs. `sync_request{.mode = sync_mode::refresh_only /
  refresh_and_persist, .cookie, .reload_hint, .critical = true}` is a
  search request control (`search_controls`, controls.hpp); `find_sync_state()`
  reads an entry's Sync State control (`sync_state{state = present / add /
  modify / del, entry_uuid, cookie}`, the UUID as 16 octets in
  `sync_uuid`, `to_string()` giving the entryUUID text),
  `find_sync_done()` the SearchResultDone's Sync Done control
  (`sync_done{cookie, refresh_deletes}`), and `decode_sync_info()` a Sync
  Info Message, an IntermediateResponse (`sync_info{type = new_cookie /
  refresh_delete / refresh_present / sync_id_set, cookie, refresh_done,
  refresh_deletes, sync_uuids}`). Each fails with a decode error on a
  malformed value; the `encode_` functions (and `decode_sync_request()`)
  are for mock servers. Defaults are left out when encoding and accepted
  when sent. A server that cannot continue a sync search (a cookie too old
  to resume from, say) ends it with `errc::e_sync_refresh_required` (RFC
  4533 section 3.8): resend it with the cookie of that result's Sync Done
  control (`find_sync_done(s.controls())`, kept on an error result too), or,
  if it has none, with no cookie for a full reload, discarding the local
  copy.
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
  nothing but encoding recurses. For filter text built elsewhere (another
  tool, a config file), `escape_filter_value(v)` gives the RFC 4515 text of
  one value, exactly as `to_string()` writes it (`*` `(` `)` `\` NUL and
  non-UTF-8 octets as `\xx`; UTF-8 is kept), and
  `unescape_filter_value(text)` returns `result<std::pmr::string>`, failing
  with `invalid_filter` on what `filter::raw` would reject in a value.
- `jhetz/ldap/dn.hpp`: `ldap::dn` (RFC 4514 parse / `to_string`, multi-valued
  RDNs, `parent()`, `child()`, compile-time checked literals). Its `==` is
  syntactic (values exact after unescaping, `cn=A` != `cn=a`); compare as a
  server does with `distinguished_name_match` (`matching.hpp`). `ldap::rdn`
  has its own literal and `rdn::parse()` / `to_string()` for exactly one RDN
  (`cn=a+sn=b` is one RDN, `cn=a,dc=b` is rejected). DNs are built from parts with `child()`:
  `base.child(ldap::rdn{"uid=jdoe"})` is `uid=jdoe,<base>`, and
  `base.child(ldap::dn{"uid=jdoe,ou=people"})` prepends a relative DN
  (`uid=jdoe,ou=people,<base>`); the result uses `base`'s resource.
  `escape_dn_value(v)` gives the RFC 4514 text of one attribute value,
  exactly as `to_string()` writes it, for DN text built elsewhere.
- `jhetz/ldap/matching.hpp`: RFC 4517 matching rules on values prepared by
  LDAPprep (RFC 4518). Each rule is a function named after it, taking the
  attribute value and the assertion value and returning `match_result`
  (`true_value`, `false_value`, `undefined`): `case_ignore_match`,
  `case_exact_match`, `case_ignore_ia5_match`, `case_exact_ia5_match`,
  `numeric_string_match`, `telephone_number_match`, the ordering rules
  (`case_ignore_ordering_match`, `case_exact_ordering_match`,
  `numeric_string_ordering_match`, `octet_string_ordering_match`,
  `integer_ordering_match`: TRUE if the value is less than the assertion),
  the substrings rules (`case_ignore_substrings_match(value,
  substring_assertion{.initial, .any, .final})` and the case exact, IA5,
  numericString and telephoneNumber ones), `octet_string_match`,
  `integer_match`, `boolean_match` and `bit_string_match`;
  `object_identifier_match(a, b[, schema])` (descriptors resolved through
  the schema, then the attribute type and object class names of RFC 4512
  and RFC 4519, a type first; an unresolved descriptor is Undefined, even
  against itself), `unique_member_match(a, b[, schema])`
  (a DN with an optional `#'0101'B` UID), `generalized_time_match` and
  `generalized_time_ordering_match` (exact instants in UTC, fractions of
  any length, a leap second its own instant), `uuid_match` and
  `uuid_ordering_match` (RFC 4530, RFC 4122 text in either case),
  `case_ignore_list_match` and `case_ignore_list_substrings_match` (Postal
  Address lines; no substring spans two lines). `match(rule, value, assertion)` takes
  the rule by NAME or OID (substrings rules then take RFC 4517's Substring
  Assertion text, `ja*doe`); an unknown rule is Undefined, and
  `is_known_matching_rule()` says which are implemented. A value that is not
  valid UTF-8, holds a prohibited code point or one unassigned in Unicode
  3.2 (RFC 4518's repertoire), or is not of the rule's syntax makes the match
  Undefined. `prepare_string(value, prep_options{.case_fold, .handling,
  .input})` gives the prepared string itself (`result<std::pmr::string>`,
  `client_errc::string_prep_failed` naming the failed step).
  `distinguished_name_match(a, b)` compares DNs (RFC 4517 section 4.2.15)
  with caseIgnoreMatch for every attribute; `distinguished_name_match(a, b,
  schema)` uses each type's EQUALITY from a `server_schema` (inherited
  through SUP, caseIgnoreMatch when none); `distinguished_name_match(a, b,
  lookup)` takes a callable on `const ldap::attribute &` returning a rule
  NAME or OID, or an empty string for caseIgnoreMatch, as a
  `std::string_view`, a `const char *` or a reference to a string (a
  `std::string` by value does not compile). Every overload treats a type's
  names and OID as one (the schema's, then RFC 4512's and RFC 4519's:
  `cn`, `commonName`, `2.5.4.3`); RDNs that differ only in a type name
  nothing resolves compare Undefined.
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
- `jhetz/ldap/referral.hpp`: `referral_target(url, request)`, the request
  that progresses an operation at a referral's target (RFC 4511 section
  4.1.10), for a search, a compare and each update; build only, nothing is
  sent. An absent (or empty) DN, an absent scope or filter keep the
  original's; the URL's attribute list is ignored. With
  `reference_kind::continuation_reference` (section 4.5.3) the URL must
  name a DN; an absent scope is the original's there too. A
  URL with a critical extension (RFC 4516 section 2: none is implemented)
  fails with `invalid_url`.

## `jhetz::ldap_net`: transports and connecting

A second library (target `jhetz::ldap_net`, option `JHETZ_LDAP_BUILD_NET`,
on by default) with the network parts. It depends on Corosio and Capy
(fetched with FetchContent at pinned commits), OpenSSL and ICU; `jhetz::ldap`
itself needs only ICU.

- `jhetz/ldap/net/transport.hpp`: `net::transport`, the one byte stream a
  connection uses: plain TCP (`ldap://`), TLS over TCP (`ldaps://`), a Unix
  domain socket (`ldapi://`), or any `capy::Stream` (`transport::wrap`, used by
  the tests with Capy's mock streams). Reads and writes go through a
  `capy::any_stream`. The TCP socket is owned separately from the TLS layer,
  which wraps it in reference mode, so StartTLS (step 7) can later add TLS to
  a plain connection in place; the header describes how.
- `jhetz/ldap/net/connect.hpp`: `co_await net::connect(ioc, url, options, mr)`
  returns `result<net::transport>`: resolves the host, races the addresses
  with Happy Eyeballs (RFC 8305: families alternate, a new attempt every
  `attempt_delay` = 250 ms or as soon as the previous one fails, first
  connection wins),
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
    (the io_context stays busy until it returns). Happy Eyeballs attempts
    all run within that one budget.
  - `transport::close()` closes at once; `transport::shutdown(timeout)` ends
    a TLS session with close_notify first (`connection::unbind()` does, within
    `connection_options::tls_shutdown_timeout`). `transport::wrap()` forwards
    `close()` / `cancel()` to the wrapped stream when it has them.
  - Host name checks are strict by default (RFC 6125): subjectAltName DNS
    entries only (never the subject CN), wildcards only as a whole leftmost
    label (`*.example.org`, not `ld*.example.org`); IP literals against
    iPAddress entries, without an IPv6 zone. `tls_options::host_matching =
    host_name_matching::legacy` accepts what OpenSSL does by default (CN
    when there is no subjectAltName, partial wildcards).
  - Errors keep the system / TLS `error_code` and name the stage:
    `connect ldaps://h:636: tls handshake: server certificate: hostname mismatch ...`.
  - Linux is the supported platform (macOS is not; configure rejects Apple
    Clang). `ldapi://` and IPv6 are tested there, IPv6 over `[::1]` and a
    link-local address with a zone. CI builds with GCC 16 and Clang 23
    (libstdc++ 16).
  - `mr` holds the transport's own block and name.
- `jhetz/ldap/net/message_io.hpp`: `read_message(transport, read_buffer,
  options)` returns the next complete `ldap::message`, decoded with
  `origin::server` by default; bytes of the following PDUs stay in the
  `read_buffer`. A PDU that is not a SEQUENCE or declares more than
  `max_message_size` (16 MiB default) is rejected from its header, before its
  body is read; the buffer grows to one PDU (or 16 KiB) at most. A PDU that
  decodes to more than `decode_options::max_elements` strings (1,000,000
  by default) fails with `message_too_large`, which bounds the memory of a
  PDU made of tiny values (38 MiB instead of 320 MiB for 16 MiB of empty
  values). A TLS peer
  closing without close_notify between PDUs reads as a close. After any
  error the connection must be dropped. `read_options::decode.memory` is the
  resource the message is decoded into (e.g. a per-response arena).
  `write_message(t, m, mr)` encodes into a buffer on `mr`;
  `write_message(t, m, writer)` reuses the caller's `ber::writer`;
  `write_bytes` sends raw bytes.

- `jhetz/ldap/connection.hpp` (steps 5a, 5b): `ldap::connection`, the
  client API, with `ldap::connect()`. It includes
  the headers below, so it is the one to include; each also compiles on
  its own:
  - `jhetz/ldap/connection_options.hpp`: `connection_options`,
    `schema_check`.
  - `jhetz/ldap/operations.hpp` (part of the codec, `jhetz::ldap`): the
    request aggregates (`search_params`, `add_params`, `modify_params`,
    `del_params`, `modify_dn_params`, `compare_params`, `extended_params`,
    `password_modify_params`; `search_base`, the type of the required
    `search_params::base`), `root_dse()`, the `ldap::mod` builders, `response`
    (`{message_id, controls}`; breaking: `message_id` is new and comes
    first, as in the LDAPMessage), `intermediate`, `extended_result`,
    `end_transaction_result`, `search_result` and `typed_search_result<T>`
    (`basic_search_result`), and the OIDs `who_am_i_oid` and
    `password_modify_oid`.
  - `jhetz/ldap/search_stream.hpp` and `jhetz/ldap/paged_search.hpp`: the
    entry streams `search_stream()` and `search_paged()` return, and
    `search_entry` and `search_reference`, the items of
    `search_stream::next_item()`.
  - `jhetz/ldap/cancel.hpp`: `raceable()` and `with_stop()`.
  - `jhetz/ldap/transaction.hpp`: `ldap::transaction` and
    `commit_result` (RFC 5805, below).

   `co_await ldap::connect(ioc, url, connection_options, mr)`
  wraps `net::connect` (`connection_options`: connect `timeout`, `tls`,
  `tcp_no_delay`, `max_message_size` (16 MiB by default), `max_elements`
  (1,000,000 decoded strings per response by default),
  `operation_timeout`). The URL can also be given as text,
  `ldap::connect(ioc, "ldaps://ldap.example.org")`: it is parsed before
  connecting and a bad one fails with `url::parse`'s `invalid_url`. A
  connection can also be built on any `net::transport` with
  `connection(ioc, transport, options, mr)`.
  Operations: `simple_bind(dn, password)` (an empty name and password is
  anonymous; a name with an empty password is refused with
  `client_errc::unauthenticated_bind`, RFC 4513 section 5.1.2),
  `search(search_params, mr)` returning `result<search_result>` (`entries`,
  `references`, and the SearchResultDone's `result_code`, `matched_dn`,
  `diagnostic_message` and `controls`; a value for success and for
  sizeLimitExceeded, timeLimitExceeded and adminLimitExceeded, with the
  entries received before it and `is_success()` false; any other code is
  an error; `search_as<T>` returns the same as `typed_search_result<T>`),
  `search_stream(search_params, mr)` whose `co_await s.next()` yields one
  entry at a time (and keeps the search references and the done controls),
  and `unbind()`. `search_params` is a plain aggregate for designated
  initializers (`.base`, `.scope`, `.filter`, `.attributes`, `.deref`,
  `.size_limit`, `.time_limit`, `.types_only`, `.controls`, `.timeout`,
  `.intermediate_responses`); `.base` is required (a `search_base`, an
  `ldap::dn` with no default constructor: leaving it out does not compile,
  and `.base = ldap::dn{}` searches from the empty DN), and
  `ldap::root_dse(attributes = {"*", "+"})` is the root DSE read (base_object
  on the empty DN). `.timeout = ldap::no_timeout` (in any
  request) lifts the client-side limit for that operation, whatever
  `operation_timeout` says.
  Multiplexed: any number of operations may be outstanding (concurrent
  tasks on the connection's executor); one writer sends the PDUs in order
  and one reader, running only while something is outstanding, routes
  each response by message id and decodes it straight into that
  operation's memory resource. Each operation honours its task's stop
  token and its timeout: it then fails with `capy::error::canceled` /
  `timeout` and is abandoned (AbandonRequest; late responses dropped), and
  the connection stays usable; so does a stream destroyed before its end.
  To give up on an operation when another event comes first,
  `capy::when_any(ldap::raceable(c.search(p)), corosio::delay(5s))` races
  it (`raceable` makes its `result<T>` the payload of a `capy::results`,
  as `when_any` requires; the first to complete wins, the other is
  stopped, so a losing operation is abandoned; one stopped before it
  starts is not sent). `ldap::with_stop(token, op)` cancels it on a
  `std::stop_token` of your own (stoppable from any thread only with the
  io_context's default `corosio::locking_mode::safe`; under `unsafe_io`
  and `unsafe`, only from the thread running the io_context) as well as on
  the awaiting task's.
  Abandon is best effort (RFC 4511 section 4.11): the server may have
  finished first, so an update (add, modify, delete, modify DN) that timed
  out, was stopped or lost a race may still have been applied; re-read the
  entry if the outcome matters.
  An operation stopped before it starts is not sent (an update is then
  certainly not applied); it fails with `capy::error::canceled`.
  Bind and StartTLS cannot be abandoned (RFC 4511 section 4.11): giving up
  on one closes the connection (one stopped before it starts is not sent
  either, and the connection stays open). Nothing is sent while a bind is
  outstanding (RFC 4511 section 4.2.1): requests started during a bind
  exchange are held and sent after it, and binds are serialized.
  Every response is decoded with `origin::server` and must answer an
  outstanding request (else `client_errc::unexpected_response`);
  IntermediateResponses (RFC 4511 section 4.13) are skipped unless the
  request sets `.intermediate_responses` (`search_params`,
  `extended_params`); `extended()` then collects them in
  `extended_result::intermediates` as `ldap::intermediate`
  (`response_name`, `response_value`, `controls`). A search stream's
  `next_item()` reads every message of the search in the order the server
  sent it, each with its message's controls (RFC 4533's Sync State control,
  ...): a `std::variant` of `search_entry` (an `entry` plus `controls`),
  `search_reference` (`uris` plus `controls`, also appended to
  `references()`) and `intermediate` (only when asked for). `next()` and
  `next_item()` may be mixed on a stream; `next()`, `search()` and
  `search_paged()` drop the entries' controls and the intermediates.
  Content synchronization (RFC 4533, `content_sync.hpp`) runs on
  `next_item()`: a search with a `sync_request` control,
  `.intermediate_responses = true` and, for refreshAndPersist,
  `.timeout = ldap::no_timeout`; `find_sync_state(entry.controls)`,
  `decode_sync_info(intermediate)` and `find_sync_done(s.controls())` read
  it (`examples/syncrepl.cpp`). The entries queue on the stream's resource
  until read, without backpressure: a long-lived persist search wants the
  default resource (not a monotonic arena, which never frees) and a
  reader that keeps up. A
  Notice of Disconnection fails every
  outstanding operation. A server result error fails one operation; a
  transport or protocol error fails all of them once and closes the
  connection, and later operations fail with `client_errc::not_sent`
  naming the first error. The header documents the memory, threading and
  lifetime rules.
  Step 6 adds the other operations: `add`, `modify` (changes from
  `ldap::mod::add / remove / replace / increment`), `del`, `modify_dn`
  (rename and / or move; `move(entry, new_parent)` keeps the RDN and sets
  newSuperior, `rename(entry, new_rdn, delete_old_rdn = true)` keeps the
  parent; both build the ModifyDNRequest for `modify_dn`, on
  `sync::connection` too), `compare` (`result<bool>`), `extended`,
  `who_am_i` (RFC 4532; an authzId that is not UTF-8 is
  conversion_failed) and `password_modify` (RFC 3062: returns the
  server-generated password, if any), each taking a params aggregate
  with `.controls` (that operation's control list, see controls.hpp
  below) and `.timeout` (`extended` refuses the StartTLS name with
  encode_error before sending: use `start_tls`);
  transactions (RFC 5805): `start_transaction(extended_controls)` ->
  `result<std::pmr::string>` (the identifier; proxied authorization goes
  here, section 4.4), updates carrying
  `ldap::transaction_specification{.identifier}`, and
  `end_transaction(identifier, commit = true)` ->
  `result<end_transaction_result>` (`updates_controls`, the decoded
  updatesControls `{message_id, controls}`, with
  `find_update_controls(response::message_id)`, and `controls`); a refused
  End Transaction has the context "end transaction: update message N" when
  the server names the update. `begin_transaction(extended_controls)`
  returns the helper `ldap::transaction` (move-only):
  `add` / `modify` / `del` / `modify_dn` attach the control (a request that
  already carries one, typed or raw, or carries proxied authorization,
  fails with encode_error before sending), `commit()` ->
  `result<commit_result>` (an error names the failing operation: "commit
  transaction: update message 3 (add uid=...)"), `abort()`, `identifier()`, `is_open()`; commit and
  abort settle it whatever the outcome (later calls fail with
  `std::errc::invalid_argument`); `commit()` while an update is still in
  flight fails with `client_errc::operation_in_progress`, sends nothing and
  leaves it open (await every update first). One destroyed while the server
  may still hold it (open, or a commit / abort whose End Transaction got no
  answer: stopped before sending, or given up on) queues an End
  Transaction (abort) without waiting. `sync::connection` forwards
  `start_transaction` and `end_transaction`, and its `begin_transaction()`
  returns a `sync::transaction`, which aborts synchronously when destroyed
  open, waiting five seconds at most for the answer. The Aborted
  Transaction Notice is not routed: the next use fails.
  An update cancelled or timed out inside a transaction may be part of it:
  abort. The codecs (`end_transaction_request`, `update_controls`,
  `end_transaction_response`, `encode_` / `decode_end_transaction_request`
  / `_response`, the OIDs) are in `message.hpp`;
  `search_paged(params, page_size)` follows the Simple Paged Results cookie across pages (destroyed early, it abandons the
  current page and releases the server's paging state with a page size 0
  request, RFC 2696 section 3, unless the search already ended; the
  release's answer is read and dropped, and counted by `outstanding()`
  until it arrives or the page timeout passes). Several paged searches
  may run at once on a connection (RFC 2696 section 3), but OpenLDAP keeps
  one per connection: it refuses the next page of any but the one whose
  page it answered last, with unwillingToPerform (53) or protocolError (2)
  depending on the cookies' entry order, and with `server_side_sort` its
  sssvlv overlay
  answers that page with the latest sorted paged search's entries
  instead, which the client cannot detect; there, give each concurrent
  paged search its own connection. Referrals are returned (in
  `error::referrals` and `search_stream::references()`), never chased by
  the connection; `url::parse_list` parses them, and
  `jhetz/ldap/referral_chase.hpp` (below) follows them on request.
- `jhetz/ldap/referral_chase.hpp`: opt-in referral chasing.
  `co_await ldap::chase_search(conn, params, connector, policy, mr)` runs
  the search, then follows a referral result and the continuation
  references (RFC 4511 sections 4.1.10, 4.5.3) through `connector`, a
  `referral_connector` (`std::function` returning
  `task<result<connection *>>` for a URL and its depth; null skips it), which
  decides which servers may be contacted and how their connections are
  bound. It returns `chased_search{entries, result_code, matched_dn,
  diagnostic_message, controls, referrals, unlisted, complete}` (the done
  fields are the origin's search's, or the referral target's: success or a
  limit code, as `search()`): the
  entries of every server reached, one `referral_attempt` per URI tried
  (`followed`, `skipped_policy`, `skipped_loop`, `limit_reached`,
  `unparseable`, `failed` with its error), and `complete == false` when a
  continuation reference could not be followed (partial results are never
  a plain success; such a reference never fails the search). A referral
  result that cannot be followed fails the call (the last error, else the
  referral; its context counts the attempts' outcomes). `chase_compare(conn, params, connector, policy)` does the
  same for a compare (`chased_compare{value, referrals, unlisted}`). The URIs of one
  reference are alternatives, tried in order; `referral_policy` bounds the
  depth (`max_hops`, 10 by default as RFC 4511 asks), the connector calls
  (`max_targets`, 64; once reached the chase stops, and the references still
  waiting are only counted in `unlisted`) and the attempt list
  (`max_attempts`, 256; the rest counted in `unlisted`); the request's
  `timeout` bounds the whole chase, the connector's work included
  (cancelled when the budget is spent). Loops
  (the same server, DN, scope and filter, the origin's own request
  included) are skipped. Writes are never chased.
  `make_same_policy_connector(ioc, origin, options, allowed_hosts, setup)`
  builds a connector keeping the origin's policy: ldapi:// and hosts
  outside `allowed_hosts` (a name and its subdomains, IDNs in ASCII form;
  IP addresses exactly; empty by default, so nothing is followed), hosts
  with bytes no host name has, and ports other than the scheme's default
  and the origin's (unless an entry names it: `host:port`, `[::1]:port`;
  `example.org:1389` allows that port on the subdomains too)
  are skipped, a TLS origin makes ldap:// targets use StartTLS (failure fails
  the URI), the certificate is checked against the referred host, and
  each new connection is bound only by `setup` (a `session_setup`, e.g.
  `simple_bind_setup`; none: anonymous, and the TLS client certificate of
  `options` is presented only with a setup: to keep it, pass
  `sasl_bind_setup` with an EXTERNAL mechanism, or `no_bind_setup()`, which
  presents it without binding). Its connections are reused per server and
  closed with the connector.
- Password changes with RFC 3062 Password Modify: `password_modify(params)`
  (the request as the RFC has it, a generated password returned), and two
  conveniences over it, `change_password(user, old, new)` (a user's own)
  and `reset_password(user, new)` (an administrator's; an empty `user` is
  the bound user), on `connection` and `sync::connection`. Active Directory
  has no RFC 3062: its password changes are `ad::change_password` and
  `ad::reset_password` (section `ldap::ad`). Which one runs is the call's
  choice: nothing reads the root DSE to pick. Passwords never appear in
  errors. Password memory is not wiped (simple binds, `password_modify`,
  these calls, `ad::password_value`): the password goes through
  `std::string` copies the library cannot all reach. Only
  `sasl_scram_sha256` and `sasl_ntlm` wipe what they hold.
- StartTLS (step 7): `connection::start_tls(tls_options)` upgrades a plain
  ldap:// connection in place (refused while operations are outstanding;
  it first waits for the answers due to paged search releases; bytes
  received before the handshake are rejected; a server refusal keeps the
  connection usable in clear), `connection_options::start_tls` does it in
  `ldap::connect`, and `net::start_tls` is the transport-level piece.
- SASL (#11, `jhetz/ldap/sasl.hpp`): `connection::sasl_bind(mechanism)`
  drives the saslBindInProgress exchange; `sasl_external` (identity from a
  TLS client certificate or ldapi://, optional authorization identity) and
  `sasl_scram_sha256` (`jhetz/ldap/sasl_scram.hpp`, RFC 5802 / 7677:
  username and password, the bind fails unless the server proves it knows
  the password; UTF-8 usernames and passwords prepared with SASLprep, RFC
  4013, through ICU; `sasl_scram_options` sets channel binding, the
  authorization identity, the largest iteration count accepted from the
  server, `max_iterations`, 1'000'000 by default, and the count above which
  PBKDF2 runs on a thread of its own, `offload_above_iterations`, 16'384 by
  default, inline under `locking_mode::unsafe`; the SaltedPassword is
  cached per salt and count across binds with the same object) are built in,
  `sasl_ntlm` (`jhetz/ldap/sasl_ntlm.hpp`, NTLMv2 for Active Directory,
  see below), `sasl_gssapi` (`jhetz/ldap/sasl_gssapi.hpp`, Kerberos V5,
  RFC 4752; optional, see below) too when built with
  `JHETZ_LDAP_WITH_GSSAPI`,
  and `sasl_mechanism` is the interface for others (`prepare()` gives a
  mechanism the URL's host before each bind, whether a step can be
  offloaded, `sasl_bind_context::can_offload`, and the TLS channel
  bindings; a step that may block, such
  as a network call, is handed to `sasl_bind` with `offload_start()` /
  `offload_step()` and runs on a thread of its own). When the server
  reports success but the mechanism's `complete()` refuses it (e.g. a
  wrong SCRAM server signature), `sasl_bind` returns the error and closes
  the connection, since the server considers it bound.
- TLS channel bindings (`jhetz/ldap/channel_binding.hpp`, RFC 5056):
  `connection::peer_certificate()` is the server's certificate (DER) and
  `connection::channel_bindings()` the connection's tls-server-end-point
  (RFC 5929 section 4.1: the certificate's hash with its signature's hash
  function, SHA-256 for MD5 and SHA-1; absent for Ed25519) and
  tls-exporter (RFC 9266; TLS 1.3, or TLS 1.2 with the extended master
  secret) bytes, with `default_type` tls-exporter on TLS 1.3; on TLS 1.2
  tls-server-end-point, or tls-exporter when the certificate has none
  (Ed25519, Ed448) and the extended master secret was negotiated; all
  empty unless `is_tls()` (the sync facade has `peer_certificate()` too,
  copied). tls-unique is not provided. `sasl_bind` hands them to the
  mechanism (`sasl_bind_context::tls` and `bindings`). RFC 9266 section
  4.1: tls-exporter MUST NOT be used for more than one authentication on
  a TLS connection, so once a bind used it (the mechanism's
  `channel_binding_used()` says tls_exporter after `start()`; failed
  binds count; the default implementation says tls_exporter, so a
  mechanism that does not override it consumes tls-exporter whenever it
  is given the data and its `start()` succeeds, while EXTERNAL, GSSAPI
  (tls-server-end-point when it binds, never tls-exporter) and SCRAM
  report exactly what they used), later binds get no
  tls-exporter data: SCRAM-SHA-256-PLUS then defaults to
  tls-server-end-point, and fails with
  `client_errc::tls_required` before sending anything when that is
  absent or tls_exporter was asked for. `connection::channel_bindings()`
  keeps reporting tls-exporter (it describes the connection).
  SCRAM-SHA-256-PLUS:
  `sasl_scram_options{ .channel_binding = scram_channel_binding::plus }`
  (mechanism "SCRAM-SHA-256-PLUS", GS2 header "p=<type>,,", c= carrying
  the binding data; `binding_type` overrides the connection's default;
  `client_errc::tls_required` before anything is sent without TLS or
  without data of that type). `scram_channel_binding::not_offered`, for a
  server whose supportedSASLMechanisms lacks -PLUS
  (`scram_channel_binding_for(mechanisms)` picks plus or not_offered),
  sends "y,," over TLS so that a server that does support -PLUS detects
  the downgrade (RFC 5802 section 6); `none`, the default, keeps "n,,".
  OpenLDAP's slapd (`sasl-cbinding tls-endpoint`) uses its own form,
  "p=ldap" with "tls-server-end-point:<hash>" as data:
  `binding_form = scram_channel_binding_form::openldap` speaks it
  (tls-server-end-point implied, hashed as OpenLDAP does: SHA-256 for
  RSASSA-PSS, Ed25519 and Ed448 too; `binding_type = tls_exporter` with
  it and `channel_binding = plus` fails `start()` with
  `client_errc::encode_error`). The client turns off TLS 1.2
  renegotiation after a handshake in which the server sent a certificate
  (RFC 9266 section 4.2), so the recorded certificate and bindings stay
  the connection's; without a server certificate nothing is recorded and
  renegotiation is left at OpenSSL's default. Compatibility: a server
  that starts a TLS 1.2 renegotiation (a HelloRequest, e.g. to ask for a
  client certificate later) is refused on every ldaps:// and StartTLS
  connection, whether channel binding is used or not, and the connection
  fails (an error comparing equal to `cond::tls_failure`).
- SASL GSSAPI (`sasl_gssapi`, option `JHETZ_LDAP_WITH_GSSAPI`, off by
  default; needs the GSS-API library, MIT krb5's `libgssapi_krb5`, found
  with pkg-config: Debian `libkrb5-dev`, Arch `krb5`): Kerberos binds with
  the default credentials (the ticket cache of `kinit`, `KRB5CCNAME`) or
  `sasl_gssapi_options::principal` (UTF-8, e.g. `jdoe@EXAMPLE.ORG`); the
  target is `ldap@<the URL's host>` unless `options.target` names
  another (connect with the server's DNS name, not an address; ldapi://
  needs an explicit target); mutual authentication is required; an
  optional `authz_id`. By default the client chooses "no security layer"
  (maximum buffer size 0), so SASL neither signs nor seals the session:
  use it over ldaps:// or StartTLS unless the network is trusted. A
  server that requires integrity or confidentiality then fails the bind
  with `client_errc::security_layer_required`. `options.security_layer`
  (`integrity`, `confidentiality`, `best_offered`: the strongest offered,
  none over TLS when offered) selects a layer instead, with
  `options.max_receive_size` (default 64 KiB) as the largest protected
  buffer accepted: from the successful BindResponse on, every PDU is
  `gss_wrap`ped both ways (`connection::security_layer()` says which).
  The security context must provide the layer's protection and sequence
  detection (`GSS_C_SEQUENCE_FLAG` in its ret_flags, RFC 4752 section
  3.1), `gssapi_failure` otherwise, and a replayed or out-of-sequence
  buffer closes the connection; a layer not offered fails with
  `security_layer_unavailable`; with a layer in effect `start_tls()` fails
  with `security_layer_in_effect`. Active Directory: with the "LDAP server
  signing requirements" policy set to require signing, AD refuses unsigned
  SASL binds over plain ldap:// (`stronger_auth_required`, `00002028`):
  use TLS there, or ask for integrity. Channel binding: over TLS the
  Kerberos exchange is bound to the server's certificate (RFC 5929
  tls-server-end-point, given to `gss_init_sec_context` as
  `application_data` "tls-server-end-point:<hash>" with no addresses, the
  form Windows SSPI uses and OpenLDAP's libldap builds), which an AD
  whose "LDAP channel binding" policy is "Always" requires; a man in the
  middle with a certificate of its own cannot relay the bind. With
  bindings the client also passes `GSS_C_CHANNEL_BOUND_FLAG` (MIT krb5
  1.19+ then sends KERB_AP_OPTIONS_CBT, as krb5.conf's
  `client_aware_channel_bindings` would), a signal on which AD and MIT
  report the context as channel bound: an acceptor refuses a wrong
  binding with or without it. slapd does not check GSSAPI bindings:
  cyrus-sasl 2.1.28, its latest release, passes none to Kerberos; its
  unreleased master passes them only with `sasl-secprops ...,nonstdcbind`
  (beside `sasl-cbinding tls-endpoint`), a flag that, from the sources,
  also disables every SASL mechanism in that master's mechanism
  selection. No bindings without TLS. Over TLS without a hash (a
  certificate without one, e.g. Ed25519, Ed448 or ML-DSA in the RFC
  form, one the openldap form cannot parse or whose signature algorithm
  OpenSSL does not know, or no server certificate) `start()` fails with
  `client_errc::tls_required` before anything is sent, as SCRAM-PLUS
  does: the certificate is the TLS peer's choice, so falling back to no
  bindings would be a downgrade a man in the middle could pick.
  `sasl_gssapi_options::channel_binding = gssapi_channel_binding::none`
  turns it off (a server behind a TLS-terminating proxy refuses the
  client's bindings), and `binding_form =
  gssapi_channel_binding_form::openldap` takes OpenLDAP's hash (for a
  slapd that checks them; it differs for an RSASSA-PSS or EdDSA
  certificate). `prefixed_channel_binding(type, data)`
  (`channel_binding.hpp`) gives RFC 5056's prefixed form.
  GSS-API failures (no ticket, unknown service principal, unreachable
  KDC) are `client_errc::gssapi_failure` (`cond::auth_failed`), the
  context quoting GSS-API's major and minor status messages; never
  tokens or credentials. Every GSS-API handle is released (RAII).
  The GSS-API calls that may block (`gss_acquire_cred`,
  `gss_init_sec_context`: MIT krb5 does DNS lookups and asks the KDC for
  the service ticket, retrying over the KDCs with backoff; the total is
  bounded by krb5.conf's `request_timeout`, MIT 1.22 and later, default
  none, and DNS by `resolv.conf`'s `timeout` and `attempts`)
  run on a thread of their own, one per call, so the io_context (or the
  `sync::connection`'s I/O thread) is not stalled. `operation_timeout`
  and cancellation stop the bind's wait (`capy::error::timeout` /
  `canceled`; before the first BindRequest nothing was sent and the
  connection stays usable), not the Kerberos call, which runs to its end
  on its thread; `io_context::run()` returns only after it, and
  destroying the io_context (or a `sync::connection`) waits for its
  thread to end, as long as krb5's own timeouts. That needs an io_context
  that accepts posts from other threads (the default `locking_mode::safe`;
  under `unsafe` the bind fails with `std::errc::operation_not_supported`
  before anything is sent; `unsafe_io` is unsupported).
  `examples/gssapi.cpp` binds with StartTLS and the default ticket.
- SASL NTLM (`sasl_ntlm`, `jhetz/ldap/sasl_ntlm.hpp`, MS-NLMP NTLMv2):
  `sasl_ntlm(username, password, sasl_ntlm_options)` binds to Active
  Directory with a user's own password where Kerberos is not available.
  The mechanism is "GSS-SPNEGO" with raw NTLMSSP messages (two
  BindRequests: NEGOTIATE, then AUTHENTICATE answering the server's
  CHALLENGE), as AD accepts it. The username is "DOMAIN\user",
  "user@dns.domain" (a UPN, no domain) or "user" with
  `options.domain`; `options.workstation` and `options.target` (the SPN in
  MsvAvTargetName, default "ldap/<the URL's host>") are optional. UTF-8
  throughout, sent as UTF-16LE; the user name is uppercased for NTOWFv2
  as Windows does (ICU simple case mapping), the password is hashed as
  typed (no normalization). NTLMv2 only: a server that does not offer it
  (no NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY, no TargetInfo, no
  Unicode) fails the bind with `client_errc::unexpected_response`. The
  AUTHENTICATE_MESSAGE carries a MIC (keyed with the ExportedSessionKey)
  and MsvAvFlags with the MIC bit; the timestamp is the server's. By
  default no signing or sealing is negotiated: SASL does not protect the
  session, TLS does. `options.security_layer` (a `sasl_protection`:
  `integrity` negotiates signing, `confidentiality` signing and sealing,
  and both sign and seal every later PDU, as an LDAP DC expects (Samba
  and Windows seal once signing is negotiated), so
  `connection::security_layer()` reports `confidentiality` for both;
  MS-NLMP section 3.4, RC4 and HMAC-MD5 with key exchange and 128-bit
  keys) negotiates an NTLM security layer for plain ldap://, where AD's
  "LDAP server signing requirements" policy demands one:
  `connection::sasl_bind` installs it after the successful BindResponse
  (`connection::security_layer()` reports it), and a buffer that fails its
  checksum or sequence number closes the connection. Only without TLS (AD
  refuses a SASL layer over TLS): over ldaps:// or StartTLS `start()`
  fails with `client_errc::security_layer_unavailable`, as does a
  CHALLENGE_MESSAGE that does not grant SIGN, KEY_EXCH and 128 (and SEAL
  for confidentiality). With a layer, `require_tls` is not consulted (the
  layer stands in for it). `options.max_receive_size` (16 MiB) bounds
  the server's buffers.
  `options.require_tls` (default true, without a layer) fails the bind with
  `client_errc::tls_required` on a plain ldap:// connection before
  anything is sent. NTLM does not authenticate the server, so only TLS's
  certificate check says whom the client talks to; with `require_tls =
  false` on plain ldap:// the bind works where the server allows it, but
  every PDU after it is in clear and unsigned (an active attacker can take
  over the connection, and a recorded exchange can be attacked offline),
  and AD with "LDAP server signing requirements" set to require signing
  refuses it (`errc::stronger_auth_required`, diagnostic `00002028`).
  Channel binding over TLS: MsvAvChannelBindings is the MD5 of the
  gss_channel_bindings_struct with "tls-server-end-point:<hash>" as
  application data, as Windows sends it and as AD's "LDAP server channel
  binding token requirements" policy checks it; without a hash (an
  Ed25519 or Ed448 certificate) `start()` fails with
  `client_errc::tls_required`; `options.channel_binding =
  ntlm_channel_binding::none` leaves MsvAvChannelBindings out instead (a
  TLS-terminating proxy; Samba refuses an explicit Z(16) over TLS even
  when it does not require channel binding). The password and the keys derived from it are wiped
  (`OPENSSL_cleanse`). A wrong password is `errc::invalid_credentials`.
  `examples/ntlm.cpp` binds over ldaps://.
- `jhetz/ldap/controls.hpp`: typed request controls (`ldap::paged`
  (RFC 2696), `manage_dsa_it` (RFC 3296), `relax_rules`
  (draft-zeilenga-ldap-relax, critical by default), `proxied_authorization`
  (RFC 4370), `server_side_sort` (RFC 2891), `assertion` (RFC 4528, critical
  by default; a false one fails with `errc::assertion_failed`), `pre_read` /
  `post_read` (RFC 4527), `sync_request` (RFC 4533), `matched_values` (RFC
  3876: `.values_return_filter`, one `ldap::filter` per item; and, or, not
  and dnAttributes, which RFC 3876 excludes, fail with invalid_filter when
  encoded; `parse_values_return_filter("((mail=*)(cn=x))")` reads the RFC
  3876 string form, `decode_matched_values` reads the control back for mock
  servers), `virtual_list_view` (draft-ietf-ldapext-ldapv3-vlv-09:
  `.before_count`, `.after_count`, `.target` = `vlv_by_offset{.offset,
  .content_count}` or `vlv_greater_than_or_equal{.value}`, `.context_id`;
  needs a `server_side_sort` on the same search, else encode_error before
  sending; `decode_virtual_list_view` for mock servers),
  `transaction_specification` (RFC 5805: `.identifier`, always critical,
  on add, modify, modify DN and delete; with a proxied authorization
  control, typed or raw, encode_error before sending;
  `decode_transaction_specification` for mock servers)) or a raw
  `ldap::control`.
  Each operation's params take its own list: `search_controls`,
  `add_controls`, `modify_controls`, `modify_dn_controls`, `del_controls`,
  `compare_controls` and `extended_controls` (also `password_modify_params`,
  `who_am_i`), each a `std::vector` of a `std::variant` of the raw control
  and the typed controls the table `control_rule_of<T>` allows there
  (`applies_to<T>(operation_kind)`, each row citing its RFC section), so a
  misplaced typed control does not compile (`assertion` and
  `manage_dsa_it` are not on `extended_controls`: RFC 4528 and RFC 3296
  section 3 allow them only on extended operations whose document defines
  them); the raw control is allowed everywhere and not checked, even with
  the OID of a typed control. A list shared by several operations is a `request_controls`
  (every alternative), converted with `controls_for<add_controls>(list)`:
  encode_error "pre_read is not valid on add (RFC 4527 section 3.1)" for a
  control the operation does not take. `to_control` (one overload per
  control) and `append_controls` (any of these lists) encode them, and
  readers for the typed response controls of a `std::pmr::vector<control>`
  (`response::controls`,
  `search_stream::controls()`, ...): `find_paged`, `find_sort_result`
  (`sort_result{result_code, attribute_type}`), `find_vlv_response`
  (`vlv_response{target_position, content_count, result_code,
  context_id}`), `find_pre_read` /
  `find_post_read` (the entry as an `ldap::entry`). Each returns nullopt when
  the control is absent and an error when it is malformed. The response
  control codecs (`encode_` / `decode_sort_result`, `encode_` /
  `decode_vlv_response`, `encode_` / `decode_read_entry`) are in
  `message.hpp`, for mock servers. The sort result and the VLV response
  come with the SearchResultDone: `search_result::controls`, or
  `search_stream::controls()`, which keeps them when
  the search fails, e.g. with `errc::virtual_list_view_error` (76), whose
  reason is the VLV response's `result_code` (OpenLDAP 2.7: 77 for an
  offset beyond the list). OpenLDAP's sssvlv keeps each VLV list's state
  until the connection closes and answers a new list past
  `sssvlv-maxperconn` (default 5) per connection with busy (51): send the
  contextID back. RFC 2891 section 2 says a server
  that cannot sort SHOULD fail a critical sort and should return the
  entries unsorted for a non-critical one, with a SortResult, though
  scenario 6 lets it omit the SortResult when the search fails or returns
  no entries; a server may also accept only one key. Servers deviate:
  OpenLDAP 2.7's sssvlv fails an unsortable search with
  inappropriateMatching (18) and no SortResult even when not critical, and
  answers every multi-key sort with protocolError (2) "decoding error" and
  no SortResult, even when not critical, libldap's own included. So check
  the search's result, and handle `find_sort_result` returning nullopt
  ("not known to be sorted"). Sorted paged searches sharing one OpenLDAP
  connection get each other's entries: see `search_paged` above.
- `jhetz/ldap/mapping.hpp` (#9): typed struct mapping. A descriptor
  (`ldap::schema<T> = ldap::describe(ldap::object_class(...),
  ldap::field<&T::m>("attr", ldap::read_only)...)`) maps members to
  attributes; the member type decides cardinality (`T`,
  `std::optional<T>`, `std::vector<T>`); `value_traits<T>` converts values
  (strings, which must be well-formed UTF-8 or the decode is
  `conversion_failed`, and one bad value fails the whole `decode<T>` and
  so the whole `search_as<T>`; integers, bool, `dn`, `binary` for binary
  attributes such as userPassword (Octet String), jpegPhoto and
  userCertificate, `sys_seconds` as GeneralizedTime, enums with an
  `enum_names` table). `decode<T>(entry)`,
  `to_attributes(value)`, typed changes `replace / add / remove<&T::m>(v)`,
  typed filters `filters::field<&T::m>() == v`, and on the connection
  `search_as<T>`, `modify<T>(dn, changes)` and `add(dn, value)`. Mistakes
  (unmapped or read_only member, wrong value type, invalid names) fail to
  compile; `tests/compile/` checks each. Encoding can fail (breaking
  change, coro-ldap-vcp): `value_traits<T>::encode` returns `std::string`
  or `result<std::string>` (`detail::encode_value` takes both); the
  string traits reject ill-formed UTF-8, enums a value without a name and
  `sys_seconds` a year outside 0000-9999, all as `encode_error`.
  `to_attributes` returns `result<...>` and `change<T>::wire` is a
  `result<modify_change>`; `modify<T>` and `add(dn, value)` return the
  error before sending anything, and a typed filter on such a value is the
  empty filter (fails with `invalid_filter` when sent).

- `jhetz/ldap/schema.hpp` (#13): runtime schema validation. A lenient
  RFC 4512 parser for the subschema's attributeTypes / objectClasses
  (a definition that does not parse, or is not UTF-8, is skipped and
  counted), `server_schema` (`syntax_of()` and `equality_of()` follow SUP to the
  inherited SYNTAX and EQUALITY), `validate<T>(schema)` listing every issue (unknown
  attribute or object class, syntax the member's type cannot read, a
  writable member on a NO-USER-MODIFICATION attribute; single member on a
  multi-valued attribute as a warning; MUST attributes of the declared
  object classes and their superclasses that no required, writable member
  maps as warnings: `must_attribute_not_mapped`,
  `must_attribute_not_required`, `unknown_superclass`),
  `object_class_type` with `sup`, `kind` (`object_class_kind`), `must`
  and `may`, `connection::load_schema()` and
  `connection_options::schema_check = schema_check::on_first_use`.
  Breaking: a `std::string` or `std::pmr::string` member on a binary
  syntax (Octet String, JPEG, Fax, Certificate, Certificate List,
  Certificate Pair, Audio, Binary; see `value_rejected_syntaxes`) is a
  `syntax_mismatch`: map userPassword and the like to `ldap::binary`.
- `jhetz/ldap/directory.hpp` (coro-ldap-2cx.1): the `ldap::directory`
  concept, the protocol operations a layer runs on (`search`, `add`,
  `modify`, `del`, `modify_dn` with `connection`'s signatures and
  results), satisfied by `connection`, `client` and a shared lease's
  `shared_connection`; `ldap::load_schema(directory &)`, the subschema
  read of `connection::load_schema()` written once over the public
  `search` (so it works on a `client`).
- `jhetz/ldap/store.hpp` (coro-ldap-2cx.1, DESIGN.md section 4):
  `ldap::store`, typed CRUD of one mapped struct under a base DN, each
  entry named by one member: `ldap::store people(source, base,
  ldap::named_by<&person::uid>, store_options{.schema_check})`, the
  struct and the source type deduced (`store<&person::uid,
  ldap::client>`). The naming member must be in `schema<T>`, required,
  single-valued and writable (static_assert). `dn_of(key)`
  (`uid=<escaped key>,<base>`); `get(key)` / `get_at(dn)` -> `task<result<
  std::optional<T>>>` (a base-object search for T's attributes and object
  classes; noSuchObject or no entry of T's classes is nullopt);
  `add(T)`, `modify(key, changes)` / `modify_at(dn, changes)`,
  `remove(key)` / `remove_at(dn)` -> `task<result<response>>`, each with
  its operation's controls; `search(filter = (objectClass=*), scope =
  single_level)` -> `task<result<typed_search_result<record<T>>>>`,
  `record<T>{dn, value}` with the DN the server sent (entries named
  otherwise included), the limit codes a value as for `search()`. Values
  that do not encode fail before anything is sent, with the contexts of
  `modify<T>` / `add(dn, T)`. `schema_check::on_first_use` loads the
  schema with `load_schema` on the first operation and keeps the outcome
  (a mismatch fails every operation; a schema that does not load is tried
  again). The store keeps a pointer to the source, which must outlive it
  and its tasks. `jhetz/ldap/sync_store.hpp`: `ldap::sync::directory`,
  `sync::load_schema` and `sync::store`, the same over
  `sync::connection`, `sync::client`, `sync::lease` and
  `sync::exclusive_lease`, blocking.
- `net::read_frame` and `peek_message_header` (message.hpp) are the pieces
  the reader uses: wait for one complete PDU without decoding it, then read
  only its message id and operation tag.
- `jhetz/ldap/sync.hpp` (#12): `ldap::sync::connection`, the blocking facade.
  It owns an io_context and an I/O thread; every method runs the
  corresponding connection operation there and waits, with the same
  types (`connect` takes a `url` or its text, as `ldap::connect` does);
  `search_paged(params, page_size)` collects every page into one
  `search_result` (the last page's done; a limit code keeps the entries).
  Callable from any number of threads; a call from its own I/O
  thread fails with `client_errc::would_deadlock`.
- `jhetz/ldap/client.hpp` (3pf, DESIGN.md section 11): `ldap::client`, a
  pool of multiplexed connections opened lazily. `client(ioc,
  client_options{.servers, .connection, .setup, .max_connections = 1,
  .idle_check, .probe_timeout, .max_lifetime, .acquire_timeout,
  .backoff, .failback_after, .observer, .referrals})`; `acquire() ->
  task<result<lease>>`, the lease giving a `shared_connection`
  (connection.hpp: every `connection` operation but `simple_bind`,
  `sasl_bind`, `start_tls`, `unbind` and `close`, which do not compile on
  it; `(*lease)->search(...)`), shared with other leases on the same
  connection; `acquire_exclusive() -> task<result<exclusive_lease>>`, the
  full `connection` on an idle or new connection nobody else uses while it
  is held (for binds, `start_tls()`, `unbind()`). Breaking:
  `acquire_options` is gone. A lease returns the connection when destroyed
  or `release()`d. `shared_connection` is a non-owning handle made
  implicitly from a `connection &`; `chase_search`, `chase_compare`,
  `make_same_policy_connector` and `ad::change_password` /
  `reset_password` take one. `servers` fail over in priority order with a per-server
  jittered exponential backoff (`backoff_options{initial, max,
  multiplier, auth_failure_min}`), and an idle connection to a
  lower-priority server goes back to the primary after `failback_after`.
  `session_setup` (`simple_bind_setup(dn, password)`,
  `sasl_bind_setup(factory, dn)`, `no_bind_setup()` (does nothing: the
  connection keeps its TLS identity), or any `task<result<void>>(connection
  &)`) runs on every new connection after connect and StartTLS; an auth
  failure backs that server off for at least `auth_failure_min`, during
  which acquires fail at once with the stored error instead of binding
  again. An idle connection is probed (root DSE, `1.1`) after
  `idle_check`, within `probe_timeout`; a connection older than
  `max_lifetime`, or whose `connection::bind_count()` changed (a bind
  done or in progress), is no longer handed out and closes once its last
  lease returns, and does not count against `max_connections` meanwhile.
  `client_observer` hooks (`on_connect`, `on_disconnect` with a
  `disconnect_reason`, `on_retry`, `on_probe`, `on_acquire_wait`) do
  nothing by default, and none runs after `close()`. `close()`,
  `connections()`. Read forwarders `search(params, mr)`,
  `search_stream(params, mr)`, `compare(params)` and
  `who_am_i(controls)` run the operation on a shared lease and retry it
  once on another connection after `cond::connection_lost` or
  `cond::busy_or_unavailable` (a stream only before its first message;
  it holds the lease until destroyed). Write forwarders `add(params)`,
  `modify(params)`, `del(params)`, `modify_dn(params)`, `move(entry,
  new_parent, controls, timeout)`, `rename(entry, new_rdn,
  delete_old_rdn, controls, timeout)`, each `->
  task<result<response>>`, run the operation on a shared lease and retry
  it once on another connection only after `client_errc::not_sent` (the
  server never saw the request); any other failure (a connection lost
  after sending, a timeout, busy, a result code) is returned, the update
  perhaps applied. A referral result of a write is the error
  (`errc::referral`, `error::referrals`), never chased. Connection-bound
  controls (`transaction_specification`) need a lease.
  Referrals (3pf.1): `client_options::referrals` (`referral_options{
  .follow_referrals, .follow_references, .authorize, .limits}`) chases
  nothing by default. `follow_referrals` chases referral results of
  `search()` and `compare()`, `follow_references` the continuation
  references of `search()`, as `chase_search` / `chase_compare` do, from
  the pooled connection, within `limits` (a `referral_policy`).
  `authorize`, a `std::function<referral_binding(const referral_hop &)>`
  (`referral_hop{target, depth, origin}`), returns `refuse`, `anonymous`
  or `same_setup` (bind with the client's `session_setup`) per URI;
  empty: nothing is contacted. `same_setup_for_domains(domains)` builds
  one from `make_same_policy_connector`'s allow-list rules. ldapi:// and
  implausible hosts are refused before `authorize` is asked; a TLS pooled
  connection makes ldap:// targets use StartTLS (no downgrade). Referred
  connections belong to one call (closed when it ends, not pooled). Only
  the pooled connection's own failure is retried, never a referred
  server's. `chase_search(params, mr) -> task<result<chased_search>>`
  and `chase_compare(params) -> task<result<chased_compare>>` return what
  the chase did (`search()` returns only the entries, even when some
  references were not followed); `client_observer::on_referral(server,
  attempt)` hears of each URI. Writes (forwarders and leases),
  `search_stream()` and `who_am_i()` never chase.
- `jhetz/ldap/sync.hpp` (3pf.5): `ldap::sync::client`, the blocking facade
  over `ldap::client`. `sync::client(client_options, mr)` owns an
  io_context and an I/O thread, where the `ldap::client` lives (session
  setup and observer hooks run there). `acquire() -> result<sync::lease>`
  and `acquire_exclusive() -> result<sync::exclusive_lease>`; a
  `sync::exclusive_lease` has `sync::connection`'s operations (bind,
  search, `search_paged`, `search_as`, add, modify, ...,
  `begin_transaction`, `unbind`, `close`), run on the leased connection, a
  `sync::lease` the same but `simple_bind`, `sasl_bind`, `start_tls`,
  `unbind` and `close` (as `ldap::shared_connection`), both with
  `server()`, `release()` and `operator bool` (`sync::basic_lease`). The forwarders
  `search`, `compare` and `who_am_i`, and the write forwarders `add`,
  `modify`, `del`, `modify_dn`, `move`, `rename`, block and retry as the
  async ones, and `chase_search` / `chase_compare` mirror the async
  client's (referrals as `client_options::referrals` says; the authorizer
  and `on_referral` run on the I/O thread); no `search_stream` (no
  blocking stream, as for `sync::connection`). `close()` (from any thread,
  the I/O thread included) fails waiting and later `acquire()` calls with
  `not_connected`; `connections()`, `executor()`. A call from the I/O
  thread fails with `would_deadlock` (context `"sync::client"`). The
  destructor closes the pool (idle connections unbound) and joins the I/O
  thread; a lease may outlive the client (its connection is closed, its
  operations fail with `cond::connection_lost`) and keeps the I/O thread
  until it is destroyed or released. `detail::io_thread` and
  `detail::connection_api` are the machinery `sync::connection` and the
  sync leases share.
- `client_errc::not_sent` (connection.hpp, "Sent or not"): the operation
  failed before its request reached the writer (connection closed before
  it was submitted, still queued, or held behind a bind), so the server
  never saw it. It matches `cond::connection_lost`, like `not_connected`.
  A behaviour change: a request held behind a bind when a Notice of
  Disconnection (or any failure) closes the connection now fails with
  `not_sent` (`cond::connection_lost`), no longer with the notice's own
  code (`unavailable` or `busy`: `cond::busy_or_unavailable`).
- `examples/ldapsearch.cpp` (target `jhetz_ldapsearch`, binary
  `jhetz-ldapsearch`, option `JHETZ_LDAP_BUILD_EXAMPLES`): connect,
  StartTLS (`-Z`), simple bind (`-D dn -w pw`) or SASL EXTERNAL
  (`-Y EXTERNAL [-X authzid]`, client certificate `--cert` / `--key`),
  search (paged with `--page N`), LDIF output, unbind;
  `jhetz-ldapsearch [options] URL [filter [attrs]]`.

## `ldap::ad`: Active Directory

Active Directory behaviour no RFC describes, as free functions and types in
`jhetz::ldap::ad` over the public API (DESIGN.md section 12). The
codec-level headers are part of `jhetz::ldap`; the operations that need
the network are in the target `jhetz::ldap_ad` (links `jhetz::ldap_net`;
package component `ad`:
`find_package(jhetz_ldap 0.1 REQUIRED COMPONENTS net ad)`).

- `jhetz/ldap/ad/password.hpp` (`jhetz::ldap_ad`): `ad::change_password(c,
  user, old, new)` (a user's own) and `ad::reset_password(c, user, new)`
  (an administrator's), with `c` a `connection &` or a `client &` and the
  passwords `std::string_view`s, read before the call returns. One
  ModifyRequest of `user`'s `unicodePwd`, deleting the old value and
  adding the new one for a change, replacing it for a reset: what AD DS,
  AD LDS and Samba AD take instead of RFC 3062. Refused before anything is
  sent on an open connection with neither TLS nor a SASL confidentiality
  layer (`security_layer()` reports confidentiality: `sasl_ntlm` with
  either layer, `sasl_gssapi` with
  `gssapi_security_layer::confidentiality`, not integrity;
  `client_errc::tls_required`), for an empty `user`
  (`client_errc::invalid_dn`), an empty password
  (`std::errc::invalid_argument`) or ill-formed UTF-8
  (`client_errc::encode_error`). AD's diagnostics for common refusals
  (`0000052D` password policy, `00000056` wrong old password, `00000005`,
  `00000775`) are explained in the error's context (`ad::explain`);
  `error::diagnostic` keeps the server's text. The `client &` overloads
  run on a shared lease and retry once after `client_errc::not_sent`, as
  the client's write forwarders do (the connection that failed is closed,
  so the retry gets another). The connection must outlive the task; the
  `client &` tasks, like `client::acquire()`'s, do not refer to the
  client.
- `jhetz/ldap/ad/sync.hpp` (`jhetz::ldap_ad`): the same calls, blocking,
  over `sync::connection &`, `sync::lease &` and `sync::client &`.
- `jhetz/ldap/ad/diagnostic.hpp` (`jhetz::ldap`): `ad::explain(error)`,
  the explanation of the Win32 code (eight hex digits and a colon) that
  starts an AD diagnosticMessage, for the codes a password change commonly
  fails with: `00000005` (not allowed), `00000056` (wrong old password),
  `0000052D` (password policy), `00000775` (locked out); empty for any
  other code or text. The core leaves the diagnostic raw.
- `jhetz/ldap/ad/password_value.hpp` (`jhetz::ldap`):
  `ad::password_value(password)`, the `unicodePwd` value (quoted, UTF-16LE,
  full Unicode; `client_errc::encode_error` for ill-formed UTF-8), for a
  ModifyRequest built by hand.

- `jhetz/ldap/ad/filetime.hpp` (`jhetz::ldap`): Active Directory's Large
  Integer syntax (1.2.840.113556.1.4.906) as std::chrono types.
  `ad::filetime_clock` is a C++20 Clock for FILETIME (100 ns ticks since 1601-01-01 UTC;
  `clock_cast` to `system_clock` and `utc_clock`, and a `zoned_time` from
  the resulting `sys_time`);
  `ad::filetime_clock::time_point` members map dates (accountExpires,
  pwdLastSet, lastLogonTimestamp) as the plain tick count:
  9223372036854775807 is `ad::never`, 0 is tick 0 (1601-01-01, before every
  date: "never happened" for lastLogon, `ad::pwd_must_change` for
  pwdLastSet), and `ad::is_never(t)` is true for both of accountExpires'
  "never expires" spellings; `ad::pwd_must_change` / `ad::pwd_set_now`
  write pwdLastSet 0 / -1; and `ad::filetime_clock::duration` members map
  the negative intervals (maxPwdAge, lockoutDuration; `ad::forever` for
  -9223372036854775808). `std::int64_t` members read any 906 attribute raw.
- `jhetz/ldap/ad/sid.hpp` (`jhetz::ldap`): `ad::sid`, a security
  identifier (MS-DTYP 2.4.2): `sid::parse(text)` ("S-1-5-21-...", the
  authority in decimal or "0x" and 12 hex digits), `sid::from_binary(raw)`
  (objectSid's value: revision 1, count, 48-bit authority big-endian,
  sub-authorities little-endian), `sid::make(authority, sub_authorities)`,
  `identifier_authority()`, `sub_authorities()`, `to_string()`,
  `to_binary()`, `==` and `<=>`; up to 15 sub-authorities. Malformed input
  is `client_errc::conversion_failed` (`std::errc::invalid_argument` for
  `make`). Its `value_traits` map objectSid, sIDHistory, tokenGroups
  (Octet String) as the binary form, so typed filters match on it.
- `jhetz/ldap/ad/guid.hpp` (`jhetz::ldap`): `ad::guid`, a GUID by its
  MS-DTYP 2.3.4 fields (`data1`, `data2`, `data3`, `data4`):
  `guid::from_binary(raw)` (16 octets, the first three fields
  little-endian, as objectGUID holds it), `guid::parse(text)` (with or
  without braces, either case), `to_string()` (lower case, no braces),
  `to_binary()`, `==` and `<=>`. `value_traits` on Octet String.
- `jhetz/ldap/ad/user_account_control.hpp` (`jhetz::ldap`):
  `enum class ad::user_account_control : std::uint32_t`, the
  userAccountControl bits (MS-ADTS 2.2.16, `normal_account`,
  `account_disable`, `dont_expire_passwd`, ...), with `|`, `&`, `^`, `~`,
  their assignments and `has(flags, bits)`. `value_traits` on INTEGER: the
  signed 32-bit decimal AD writes (bits not named are kept).
- `jhetz/ldap/ad/controls.hpp` (`jhetz::ldap`): AD's request controls,
  converting to a raw `ldap::control`, so they go in any operation's
  `.controls` (and `request_controls`). `ad::show_deleted{}`
  (`ad::show_deleted_oid`, 1.2.840.113556.1.4.417, MS-ADTS
  3.1.1.3.4.1.14): searches include deleted objects (isDeleted TRUE, under
  CN=Deleted Objects); no value, critical by default
  (`.critical = false` to send it non-critical).
- `jhetz/ldap/ad/syntax.hpp` (`jhetz::ldap`): `ad::large_integer_syntax`,
  the Large Integer syntax OID (1.2.840.113556.1.4.906), which
  `validate<T>` accepts for signed integers of 64 bits or more and the
  FILETIME types.

## Memory

Memory (DESIGN.md section 8): the public types use `std::pmr` containers
and are allocator-aware: the message model (every operation, `ldap_result`,
`control`, `partial_attribute`, `message`, `paged_results`), `filter`,
`dn` / `rdn` / `ava`, `attribute`, `entry` / `attribute_values`, `url` /
`url_extension` and `ber::writer` have `allocator_type`, `get_allocator()`,
an allocator constructor, allocator-extended copy and move constructors, and
assignment that keeps the target's resource (also for their `std::optional`
and `std::variant` members). Parsing and decoding take the resource:
`decode_options::memory`, `filter::raw(text, mr)`, `decode_filter(r, limits,
mr)`, `dn::parse(text, mr)`, `rdn::parse(text, mr)`, `attribute::parse(text, mr)`,
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

Not yet: Kerberos through GSS-SPNEGO, tls-unique.
