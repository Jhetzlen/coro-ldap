# API reference

What each public header provides, in more detail than the README. The design
rationale is in [`DESIGN.md`](DESIGN.md).

## Which call do I use

Several calls overlap: the RFC-named operation, and conveniences on top.

| To | Call | Notes |
|---|---|---|
| Search, all entries at once | `connection::search(params)` | `result<search_result>`: entries, references (not followed), the done's result code; a limit code (sizeLimitExceeded, timeLimitExceeded, adminLimitExceeded) is a value that keeps the entries received, so check `is_complete()` before treating `entries` as the whole answer (Active Directory ends an unpaged search past its MaxPageSize, 1000 by default, with sizeLimitExceeded: page it with `search_paged`) |
| Search, entry by entry | `connection::search_stream(params)` | `next()` / `next_item()`; memory bounded by the caller's pace; abandons the search when destroyed early |
| Search a large result in pages | `ldap::search_paged_stream(conn_or_client, params, page_size)` | RFC 2696 paged results, one page requested at a time; `ldap::search_paged` and `sync::search_paged` collect every page |
| Search into structs | `repository<T>::search` / `search_stream` / `search_paged` / `search_paged_stream` (repository.hpp) | the same shapes, entries decoded to `record<T>` |
| Search and follow referrals | `client::search(params)` with `client_options::referrals` | the pool chases referral results and continuation references; the report is in `search_result::referrals` / `unlisted`, `is_complete()`; a request's `follow_referrals` / `follow_references` override the pool's switches for one call; `client::search_stream`, `search_paged` and the `connection` / `sync::connection` calls ignore it (they never chase) |
| Follow referrals from a bare connection | `ldap::chase_search(conn, params, connector)`, `chase_compare` (referral_chase.hpp) | the caller's `referral_connector` decides which servers and how to bind (`make_same_policy_connector`) |
| Watch changes | `search_stream` with `ldap::sync_request` (content_sync.hpp) | RFC 4533 refreshOnly / refreshAndPersist |
| Change a password, RFC 3062 | `ldap::password_modify(d, params)` | the Password Modify request as the RFC has it; returns the generated password, if any |
| Change one's own password | `ldap::change_password(d, user, old, new)` | RFC 3062 with the old password |
| Set a password as an administrator | `ldap::reset_password(d, user, new)` | RFC 3062 without the old password |
| Active Directory passwords | `ldap::ad::change_password` / `ad::reset_password` (ad/password.hpp) | `unicodePwd` modify (AD does not implement RFC 3062); needs TLS or a SASL confidentiality layer |
| A transaction, the easy way | `transaction::begin(conn)` | an `ldap::transaction`: its updates (`t->add`, `t->modify`, ...) carry the specification control; `commit()` / `abort()`; aborted when destroyed unsettled |
| A transaction, by hand | `ldap::start_transaction(conn)`, `ldap::end_transaction(conn, id, commit)` (transaction.hpp) | RFC 5805's two extended operations; put `transaction_specification{id}` on each update yourself |

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
  table is in DESIGN.md section 5. `ldap::error` is `{code, matched_dn,
  diagnostic_message, referrals, context}`, the server's LDAPResult fields
  under their RFC 4511 names, empty when none. Every type with a raw
  `result_code` (`ldap_result`, `basic_search_result`, `sort_result`,
  `vlv_response`) also has `code()`, the `std::error_code` in
  `ldap.result`: `if (found->code() == ldap::errc::size_limit_exceeded)`.
  Breaking (coro-ldap-bhe.9): `error::diagnostic` is now
  `error::diagnostic_message`, and `error::matched_dn` is a plain string
  (was `std::optional`; empty means none).
- `jhetz/ldap/ber.hpp`: the restricted BER codec LDAP uses (RFC 4511 section 5.1):
  `ber::writer` (its buffer on a `memory_resource`, reusable), `ber::reader`
  (non-owning, depth-bounded, safe on untrusted input) and the framer
  `ber::complete_message_size`. Only definite lengths, tag numbers 0..30
  and the universal types LDAP uses. The reader rejects indefinite lengths
  and lengths of more than 4 octets but accepts non-minimal ones; a
  BOOLEAN is one octet, any non-zero value true; an INTEGER or ENUMERATED
  is not empty and at most 8 octets (else `integer_overflow`); NULL is
  empty. Every read either succeeds and advances or fails and leaves the
  reader unchanged, errors naming the absolute offset. A reader and what
  it returns borrow the buffer and must not outlive it; nested BER (a
  control value) is read with `enter_encapsulated`, keeping depth and
  offsets. The writer sets the constructed bit by method, not from the
  tag; `constructed(tag, body)` removes a partial element if `body` throws,
  and `body` must only append (`clear()` or `take()` inside it throws
  `std::logic_error`).
- `jhetz/ldap/message.hpp`: RFC 4511 `LDAPMessage` as a wire model
  (`ldap::message`, `protocol_op` = every request and response, `control`,
  `ldap_result` with `to_error()`), `encode()` / `decode()`, and the paged
  results control (RFC 2696). Wire strings are `std::pmr::string` holding the
  octets as sent (values may be binary), so an odd DN or attribute name
  never breaks decoding; the search filter is an `ldap::filter` tree.
  Decoding follows RFC 4511 section 4: unknown elements at the end of a
  SEQUENCE are skipped (they must be well-formed BER) and optional
  components are recognized only in their defined order; an unknown
  protocolOp fails with `client_errc::unsupported_operation`; enumerations
  (scope, derefAliases, modify operation) and INTEGER ranges (message id,
  version, limits) are checked (decode_error) while unknown resultCode
  values are kept; a SEQUENCE OF with SIZE (1..MAX) (referral, search
  references) is accepted empty, as absent; AddRequest and modify `add`
  values must not be empty (encode_error, decode_error); nesting is bounded
  by the reader's depth and filters by `filter_limits`, and nothing is
  allocated from an unchecked length. `search_scope` also has
  subordinateSubtree (3, draft-sermersheim-ldap-subordinate-scope), and
  `modify_operation` increment (3, RFC 4525). `encode()` fails before
  writing anything with invalid_filter (an empty or over-limit filter) or
  encode_error (a value the wire format cannot carry). `peek_message_header`
  reads the message id and protocolOp tag of a PDU without decoding the
  rest. `encode_paged_results` / `decode_paged_results`,
  `decode_sort_result`, `decode_vlv_response`, `decode_read_entry`,
  `encode_end_transaction_request` and `decode_end_transaction_response`
  are the control and value codecs; `vlv_response::context_id`
  is to be sent back unchanged, and `content_count` in the next
  `vlv_by_offset`. Assigning directly to an optional or variant member
  follows the standard types' rules (a newly engaged value uses its own
  resource), and nested initializer lists are built on the default
  resource first: to avoid it entirely, use the allocator constructor and
  assign the members.
  `decode()` reads what a server sends: a request operation fails with
  `unsupported_operation` before anything of it is decoded (the request
  decoder is the testing target's, not installed: DESIGN.md section 10).
  `decode(encode(m)) == m` exactly for a response (for any operation with
  the testing target's `testing::decode`), and re-encoding is
  byte-identical. Breaking (coro-ldap-3jj.1): `decode_options::from` and
  `::filter`, `ldap::origin`, `decode_filter` and the server-side control
  and value codecs (`encode_sort_result`, `encode_vlv_response`,
  `encode_read_entry`, `decode_sync_request`, `encode_sync_*`,
  `ad::decode_dirsync_request`, ...) left the public headers for
  `ldap::testing` (testing/include/, not installed).
  `decode_options` limits the reader depth and the decoded strings;
  `memory` is the resource everything decoded is allocated from. The
  types have constructors taking the fields in order
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
  malformed value. Defaults are left out when encoding and accepted
  when sent. A server that cannot continue a sync search (a cookie too old
  to resume from, say) ends it with `errc::e_sync_refresh_required` (RFC
  4533 section 3.8): resend it with the cookie of that result's Sync Done
  control (`find_sync_done(s.controls())`, kept on an error result too), or,
  if it has none, with no cookie for a full reload, discarding the local
  copy. `sync_request` is critical by default (a server without content
  synchronization refuses the search); `reload_hint` asks for the full
  content instead of that error when the cookie is too old. After a
  present-mode refresh (a Sync Done, or a refreshPresent, with
  `refresh_deletes` false) the entries not reported present are gone; a
  `refresh_done` false means another refresh phase follows, true in
  refreshAndPersist that the persist stage begins (RFC 4533 sections
  3.3.2, 3.4.1). Cookies are opaque octets, absent and empty kept apart.
- `jhetz/ldap/filter.hpp`: `ldap::filter`, a typed tree (and / or / not,
  equality, substrings, >=, <=, present, approx, extensible match) holding
  unescaped values. Built by the builders in `ldap::filters`
  (`attr("uid") == v && !attr("x").present()`), which make nodes directly
  (never text), or parsed once from RFC 4515 text by `filter::raw(text)`,
  which returns `result<filter>` (malformed text fails there, with
  `invalid_filter`). `encode_filter` writes BER straight from the tree;
  `to_string()` prints canonical RFC 4515 text for logs; `root()` gives a
  read-only view of the nodes. Equality compares trees. `&&`, `||` and `!`
  only add nodes (AND / OR chains are flattened), so combining parsed
  filters cannot change their meaning. Filters nest at most
  `max_filter_depth` (24) levels and have at most `max_filter_elements`
  (10,000) elements (`filter_limits`): `raw` checks while
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
  `filter::raw` reads text not starting with `(` as if wrapped in
  parentheses (`uid=jdoe`, as ldapsearch does); otherwise no whitespace
  between elements, and `(`, `)`, `*` outside substrings, `\` and NUL must
  be escaped. A default-constructed filter is empty: combining it gives an
  empty filter, and encoding one fails with `invalid_filter`.
  `filter::failed(error)` is an empty filter holding the error it was not
  built for (`build_error()` returns it, nullopt for any other filter):
  `&&`, `||` and `!` keep the first such operand's error, and encoding
  fails with that error instead of `invalid_filter`. A filter
  combined from others uses the left operand's memory resource. An
  attribute given to `filters::attr` that is not a valid description (only
  possible with `attribute::unchecked`) makes every filter built from it a
  `failed()` one (`invalid_attribute`), and so does a bad extensible-match
  rule (`invalid_filter`). Breaking (coro-ldap-bhe.10): these threw
  `std::invalid_argument`.
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
  Parsing follows RFC 4514 with RFC 2253 section 4's leniency (spaces
  around `,`, `+` and `=` ignored, unescaped trailing spaces dropped);
  `\` escapes any octet, so values need not be UTF-8, and `to_string()`
  escapes octets that are not valid UTF-8. `child(rdn)` returns
  `result<dn>`, `client_errc::invalid_dn` for an RDN without an AVA, a bad
  type or an empty `#` value; `child(dn)` cannot fail and returns `dn`.
  `base.child({"uid=jdoe"})` is ambiguous: name the type. Breaking
  (coro-ldap-bhe.10): `child(rdn)` returned `dn` and threw
  `std::invalid_argument`.
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
  case-insensitive equality, ordering and `std::hash`; also
  `attribute::parse(text)` (runtime text, `invalid_attribute`) and
  `attribute::unchecked(text)` for names a server sent as they are (AD's
  `member;range=0-1499`). The hash is seeded per process: its values must
  not be stored or sent.
- `jhetz/ldap/entry.hpp`: `ldap::entry`, the untyped search result entry
  (DN text + attributes, case-insensitive `find`); `entry::from` takes the
  strings of a decoded `search_result_entry` and keeps its resource,
  merging attributes of the same description (first spelling and order
  kept). `find(type)` compares options as a set (`a;x;y` is `a;y;x`, but
  `cn;lang-en` is not `cn`) and returns null when absent, an empty vector
  for an attribute without values (typesOnly). `parsed_dn(mr)` parses the
  DN text into the `ldap::dn` the requests take (`invalid_dn` when the text
  is not RFC 4514).
- `jhetz/ldap/url.hpp`: `ldap::url`, RFC 4516 LDAP URLs (`ldap://`,
  `ldaps://`, `ldapi://` with a percent-encoded socket path): host (name,
  IPv4, bracketed IPv6 with optional zone), port (explicit or scheme
  default), DN, attributes, scope, filter and extensions (with the critical
  `!` marker), all percent-decoded; `parse()` / `to_string()` round-trip.
  Absent and empty DN / scope / filter stay distinct, as referrals need.
  Server URLs: `check_server()` (non-empty host without control
  characters, UTF-8 except for an ldapi path, no critical extension, no DN, attributes, scope or filter;
  an empty DN is allowed), `parse_server(text, mr)`, `parse_servers(texts,
  mr) -> result<std::vector<url>>` (any range of strings or a braced list;
  the context names the failing index, `servers[1]`), `url::server(scheme,
  host, port = nullopt, mr)` (a server URL from its parts, no text parsed:
  `host` is taken decoded, as `host()` returns it, so a `%` or `/` in it
  stays part of the host; an IPv6 address without brackets, an optional
  `%zone`; a port with ldapi or port 0 is invalid_url, then the
  `check_server()` host rules), and the explicit
  compile-time checked literal `ldap::url{"ldaps://ldap.example.org"}`
  (`scheme://host[:port]`, optional trailing `/`).
  Allocator-aware (`std::pmr`, see below). `parse()` validates the DN (RFC
  4514), filter (RFC 4515), scope (base / one / sub, any case), extension
  types and port (1..65535), and rejects IPvFuture, userinfo and a `#`
  fragment; unencoded spaces and bytes >= 0x80 are accepted in the DN,
  attribute, scope, filter and extension parts, which must be UTF-8 once
  decoded; errors are `invalid_url` with the reason and offset. Comparison
  is syntactic on the decoded parts (hosts exactly, the DN with dn's
  equality, the filter as a tree), and `to_string()` is canonical.
  `parse_list(uris)` keeps only the valid LDAP URLs (servers may send any
  scheme).
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
  a plain connection in place (`net::start_tls`, below).
- `jhetz/ldap/net/connect.hpp`: `co_await net::connect(ioc, url, options, mr)`
  returns `result<net::transport>`: resolves the host, races the addresses
  with Happy Eyeballs (RFC 8305: families alternate, a new attempt every
  `attempt_delay` = 250 ms or as soon as the previous one fails, first
  connection wins),
  sets TCP_NODELAY, and for `ldaps://` runs the TLS handshake with
  certificate and host name verification, SNI and TLS 1.2+ by default
  (`net::connect_options`: `timeout`, `tls`, `attempt_delay`,
  `tcp_no_delay`; `tls_options`: `verification` (`certificate_verification::full`,
  `insecure_accept_any` as the explicit opt-out), CA file / directory
  (`std::filesystem::path`) / PEM, client certificate, `server_name`,
  `host_matching`, and `min_version` (TLS 1.2 by default)). TLS configuration (files, certificates, `ca_dir`,
  `server_name`) is checked before any network traffic.
  - Timeout: `milliseconds timeout` (default 30 s) bounds the
    whole connect; `ldap::no_timeout` means no limit, zero or negative fails
    at once with `capy::error::timeout`. The name lookup runs detached because
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
    host_name_matching::legacy` accepts what OpenSSL does by default (the
    subject CN when the leaf has no subjectAltName DNS name, partial
    wildcards).
  - Errors keep the system / TLS `error_code` and name the stage:
    `connect ldaps://h:636: tls handshake: server certificate: hostname mismatch ...`.
  - Linux is the supported platform (macOS is not; configure rejects Apple
    Clang). `ldapi://` and IPv6 are tested there, IPv6 over `[::1]` and a
    link-local address with a zone. CI builds with GCC 16 and Clang 23
    (libstdc++ 16).
  - `mr` holds the transport's own block and name.
  - `ldapi://` connects to the Unix socket named by the host part, which
    must fit in `sockaddr_un`; on Windows (AF_UNIX, code-only) a path
    outside the ANSI code page may not reach the right file. `connect()`
    refuses with `invalid_url` an empty host, a host with control
    characters once decoded (a leading NUL, a Linux abstract socket, is
    allowed on Linux), and a critical extension; the DN and later parts
    are ignored.
  - `tls_options`: `ca_file`, `ca_dir` (hashed with `openssl rehash`; keep
    its path ASCII on Windows) and `ca_pem` replace the system store
    (OpenSSL's `SSL_CERT_FILE` / `SSL_CERT_DIR`; on Windows CryptoAPI,
    which blocks the io_context's thread during the handshake, its
    revocation fetches bounded by the timeout, at most 20 s);
    `cert_file` and `key_file` go together; `server_name` (default the
    URL's host) rejects control characters, and a trailing dot is dropped
    before SNI and matching. Not allocator-aware.
  - The connect task must run on `ioc`'s executor, its continuations not
    concurrently (a single-threaded io_context, or a strand).
    `net::start_tls(t, pending, options, timeout)` upgrades a plain TCP
    transport in place: `invalid_argument` unless plain TCP, `decode_error`
    if `pending` holds unread bytes (CVE-2011-0411), both without touching
    the transport; a failed handshake leaves it unusable (close it), and an
    exception during the handshake closes it before propagating.
  - A transport allows one read and one write in flight, on the executor of
    its io_context; destroying or moving it with an operation in flight is
    undefined (`close()` or `cancel()` and let it finish). `cancel()`
    keeps it open. `shutdown(timeout)` returns the TLS shutdown's result
    (`capy::cond::timeout` when the peer did not answer in time,
    `stream_truncated` when it closed without close_notify,
    `cond::canceled` on a stop) and closes in every case; a read may be in
    flight, not a write. `peer_certificate()` and `channel_bindings()` are
    views valid until the transport is destroyed or a StartTLS handshake
    is redone.
- `jhetz/ldap/net/message_io.hpp`: `read_message(transport, read_buffer,
  options)` returns the next complete `ldap::message` a server sent (a
  request operation fails with `unsupported_operation`); bytes of the following PDUs stay in the
  `read_buffer`. A PDU that is not a SEQUENCE or declares more than
  `max_message_size` (16 MiB default) is rejected from its header, before its
  body is read; the buffer grows to one PDU (or 16 KiB) at most. A PDU that
  decodes to more than `decode_options::max_elements` strings (1,000,000
  by default) fails with `message_too_large`, which bounds the memory of a
  PDU made of tiny values (38 MiB instead of 320 MiB for 16 MiB of empty
  values). A TLS peer
  closing without close_notify between PDUs reads as a close. After any
  error the connection must be dropped: a framing error consumes nothing,
  so every later call fails the same way, and only a decode error
  consumes the bad PDU. `read_frame` keeps the bytes received before a
  cancellation, so a reader stopped between PDUs can resume.
  `read_options::decode.memory` is the resource the message is decoded
  into (e.g. a per-response arena).
  `write_message(t, m, mr)` encodes into a buffer on `mr`;
  `write_message(t, m, writer)` reuses the caller's `ber::writer`;
  `write_bytes` sends raw bytes.

- `jhetz/ldap/connection.hpp` (steps 5a, 5b): `ldap::connection`, the
  client API, with `ldap::connect()`. Breaking (coro-ldap-vk8):
  `ldap::connection` is copyable, like Rust ldap3's `Ldap`: a copy is
  another handle on the same session (operations multiplexed on its
  strand; bind identity, TLS and security layer shared). Destroying or
  assigning over a handle releases it and the last handle closes the
  connection; `close()` or `unbind()` through any copy ends the session
  for all (the others see a closed connection: requests fail with
  `not_sent`, outstanding ones with `not_connected`). Streams,
  paged searches and transactions keep working until it closes, whatever
  the handles. `ldap::client` stays move-only; a copy of a leased
  connection is not a lease (the pool does not count it and closes the
  connection for every copy when it leaves the pool). It includes
  the headers below, so it is the one to include; each also compiles on
  its own:
  - `jhetz/ldap/connection_options.hpp`: `connection_options`.
  - `jhetz/ldap/operations.hpp` (part of the codec, `jhetz::ldap`): the
    request aggregates (`search_params`, `add_params`, `modify_params`,
    `del_params`, `modify_dn_params`, `compare_params`, `extended_params`,
    `password_modify_params`; `search_base`, the type of the required
    `search_params::base`), `root_dse()`, the `ldap::mod` builders, `response`
    (`{message_id, matched_dn, diagnostic_message, controls}`: the
    LDAPResult's matchedDN and diagnosticMessage kept on success, where a
    server may warn, RFC 4511 section 4.1.9), `intermediate`, `extended_result`,
    `end_transaction_result`, `search_result` and `typed_search_result<T>`
    (`basic_search_result`), and the OIDs `who_am_i_oid` and
    `password_modify_oid`.
  - `jhetz/ldap/search_stream.hpp` and `jhetz/ldap/paged_search.hpp`: the
    entry streams `search_stream()` and the free `ldap::search_paged_stream()`
    (on a connection, or on a client's pool through one shared lease the
    `paged_search` holds) return, and
    `search_entry` and `search_reference`, the items of
    `search_stream::next_item()`.
  - `jhetz/ldap/cancel.hpp`: `raceable()` and `with_stop()`.
  - `jhetz/ldap/run.hpp`: `ldap::run(f, args...) -> T` runs a task from
    `main()`: it makes an io_context, calls `f(ioc, args...)` (a function
    or lambda taking the `io_context &` first and returning a
    `capy::task<T>`; an overloaded name does not deduce), runs the task as
    below, and destroys the io_context before returning. A `T` bound to
    that io_context (a connection, client, stream, lease or transaction,
    also inside `result`, `std::optional`, `std::unique_ptr` or
    `std::shared_ptr`) fails a static_assert: use `run(ioc, task)` or
    return plain values. `ldap::run(ioc, task) -> T` starts the task on
    `ioc`, runs `ioc` on the calling thread until no work is left
    (restarting it first if stopped; other threads may run `ioc` too, and
    what the task leaves behind, such as a closing connection or a detached
    name lookup, is waited for), and returns the task's value or
    rethrows its exception (also one `f` throws); `std::system_error` with
    `capy::error::canceled` if `ioc` was stopped (or the task abandoned)
    before the task ended; use it when the io_context outlives the task.
    Breaking: the owning `ldap::run(task)` is gone (`run(f, args...)`
    replaces it). Not to be called from a thread already running `ioc`. `ldap::run` is a function
    object, so argument-dependent lookup does not find it: a caller's own
    unqualified `run(ioc, task)` helper stays unambiguous.

    ```cpp
    return ldap::run(search, "ldap://localhost");   // search(io_context &, std::string) -> capy::task<int>
    ```
  - `jhetz/ldap/transaction.hpp`: `ldap::transaction` and
    `commit_result` (RFC 5805, below).

   `co_await ldap::connect(ioc, url, connection_options, mr)`
  wraps `net::connect` (`connection_options`: connect `timeout`, `tls`,
  `tcp_no_delay`, `max_message_size` (16 MiB by default), `max_elements`
  (1,000,000 decoded strings per response by default),
  `attempt_delay`, `tls_shutdown_timeout` (1 s), `operation_timeout`
  (30 s, the limit of each operation without a `.timeout` of its own),
  `allow_cleartext_passwords`, `start_tls`). Timeouts are plain
  `milliseconds` and `ldap::no_timeout` (timeout.hpp) is the one spelling
  of "no limit", in the options and in a request's `.timeout`; `nullopt`
  exists only in a request's `.timeout` and means the connection's
  `operation_timeout`. A search that must outlive it (a large unpaged
  result, refreshAndPersist, a notification search) sets `.timeout`. The
  URL can also be given as text,
  `ldap::connect(ioc, "ldaps://ldap.example.org")`: it is parsed before
  connecting and a bad one fails with `url::parse`'s `invalid_url`. A
  connection can also be built on any `net::transport` with
  `connection(ioc, transport, options, mr)`.
  Operations: `simple_bind(dn, password)` (an empty name and password is
  anonymous; a name with an empty password is refused with
  `client_errc::unauthenticated_bind`, RFC 4513 section 5.1.2; a password
  is refused with `client_errc::tls_required` before anything is sent on a
  TCP connection with neither TLS nor a SASL confidentiality layer, unless
  `connection_options::allow_cleartext_passwords` is set, and so is a
  Password Modify (RFC 3062) extended operation; ldapi:// and a wrapped
  stream are not checked),
  `search(search_params, mr)` returning `result<search_result>` (`entries`,
  `references`, and the SearchResultDone's `result_code`, `matched_dn`,
  `diagnostic_message` and `controls`; a value for success and for
  sizeLimitExceeded, timeLimitExceeded and adminLimitExceeded, with the
  entries received before it and `is_success()` false, so `is_complete()`
  is the check before using `entries` as the whole answer (AD's default
  MaxPageSize of 1000 is the common case); any other code is
  an error; a repository's `search` returns the same as
  `typed_search_result<record<T>>`),
  `search_stream(search_params, mr)` whose `co_await s.next()` yields one
  entry at a time (and keeps the search references and the done controls),
  and `unbind()`. `search_params` is a plain aggregate for designated
  initializers (`.base`, `.scope`, `.filter`, `.attributes`, `.deref`,
  `.size_limit`, `.time_limit`, `.types_only`, `.controls`, `.timeout`,
  `.intermediate_responses`, and `.follow_referrals` / `.follow_references`,
  read only by `ldap::client` and `sync::client`, below); `.base` is required (a `search_base`, an
  `ldap::dn` with no default constructor: leaving it out does not compile,
  and `.base = ldap::dn{}` searches from the empty DN), and
  `ldap::root_dse(attributes = {"*", "+"})` is the root DSE read (base_object
  on the empty DN). `.timeout = ldap::no_timeout` (in any
  request) lifts the client-side limit for that operation, whatever
  `operation_timeout` says; so does any timeout whose deadline would
  overflow the clock. A negative `size_limit` or `time_limit`, or a
  `time_limit` above maxInt seconds, fails with encode_error before
  anything is sent.
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
  exchange are held and sent after it if the bind succeeds, and binds are
  serialized. If the bind fails, is stopped while none of its
  BindRequests is outstanding (during an offloaded GSSAPI start, say) or
  does not complete, the held requests fail with
  `client_errc::bind_failed` (`cond::auth_failed`) and none is sent
  (anonymously, or without the security layer the bind was to install);
  the context names the bind's error. A bind stopped while a BindRequest
  is outstanding closes the connection (above), and the held requests
  fail with `client_errc::not_sent`. Held requests that only discard server state are still sent:
  AbandonRequests, a destroyed transaction's abort and a paged search's
  release.
  Every response is decoded with `ldap::decode` and must answer an
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
  `search_paged_stream()` drop the entries' controls and the intermediates.
  A stream is move-only; do not destroy or move it while `next()` or
  `next_item()` is suspended. After the end or an error, `next()` returns
  the same again without I/O. `references()` keeps every reference for
  the stream's life. `search_stream::item` is a `std::variant`, which is
  not allocator-aware: a `std::pmr::vector<item>` does not propagate its
  resource.
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
  outstanding operation. A server result error fails one operation, also
  when it comes in an ExtendedResponse without a responseName to a request
  other than a Bind (Samba's answer to an unsupported critical control,
  e.g. `errc::unavailable_critical_extension`); a
  transport or protocol error fails all of them once and closes the
  connection, and later operations fail with `client_errc::not_sent`
  naming the first error. A Notice of Disconnection's success code reads
  as `errc::unavailable`; other unsolicited responses are ignored.
  `not_sent` has exceptions: an allocation failure stays
  `std::errc::not_enough_memory`, operations abandoned by `unbind()` and
  calls on a default-constructed or moved-from connection fail with
  `not_connected`.
  Memory: `search()` and `search_stream()` entries are decoded into the
  call's memory resource and must not outlive it; they are allocated on
  the strand and may be freed on another thread, so the resource must
  allow that (the default resource, `std::pmr::synchronized_pool_resource`,
  or an arena that frees nothing until the search ends). The connection's
  own state lives on the resource given to `connect()` or the
  constructor, of whose `connection_options` only `max_message_size` and
  `operation_timeout` apply.
  Lifetime: the last handle's destruction closes the transport without an
  UnbindRequest (`co_await unbind()` first for a clean shutdown); a moved-from
  connection is default-constructed (not connected), `close()` is
  idempotent, and `executor()` requires a connection built with a
  transport, not moved from. `add`, `modify`, `del`, `modify_dn` and
  `extended` return any result code but success as an error, referrals
  included (`connection` never chases them).
  Streams, paged searches, transactions and outstanding operations may
  outlive every handle (they then fail with `not_connected`); destroying a
  task suspended in an operation abandons it. Work posted by a close or
  destructor off the strand leaks if the io_context is destroyed without
  running it: after `run_one()` or a stop, `restart()` and `poll()` first.
  Accessors: `is_tls()` is false while `start_tls()` runs and whenever
  `is_open()` is; `security_layer()` holds from the first octet after the
  successful BindResponse until the connection closes, a later bind
  leaving it in place (RFC 4513 section 5.2.1.4), and a bind negotiating
  another fails with `security_layer_in_effect`; `peer_certificate()` is
  a view valid until the connection is destroyed or assigned to, or
  `start_tls()` runs again; `bind_count()` counts the bind exchanges
  begun, whatever their outcome; `outstanding()` counts the operations and
  the paged search releases still due, not abandoned requests; `name()`
  is where it is connected, for logs.
  `sasl_bind(mechanism, name)` (the mechanism must outlive the task) sends
  at most 32 BindRequests, then fails with `unexpected_response`. A
  mechanism error after a saslBindInProgress aborts the exchange with an
  anonymous simple bind before any held request is sent (RFC 4511
  section 4.2.1); any answer but saslBindInProgress leaves the
  connection usable, anonymous and without a security layer, else it is
  closed with `unexpected_response`. Offloaded steps run within
  `operation_timeout` and the stop token; giving up leaves the step
  running (the io_context counts it as work) and closes the connection
  only once a BindRequest was sent; under `locking_mode::unsafe` an
  offloaded step fails with `std::errc::operation_not_supported`.
  `start_tls(options, timeout)` checks `options.server_name`, else the
  URL's host; it fails with `invalid_argument` unless the connection is
  plain TCP; once its request is sent other operations fail with
  `operation_in_progress`, and an `unbind()` closes the connection (the
  StartTLS fails with `not_connected`). `timeout` bounds the wait for
  release answers, the exchange and the handshake each; `nullopt`:
  `operation_timeout`.
  `unbind()` during a bind or a StartTLS only closes; on TLS it then sends
  close_notify and waits for the server's within `tls_shutdown_timeout`
  (best effort). An operation started while the UnbindRequest is being
  written fails with `not_sent`, a second `unbind()` with `not_connected`;
  the connection is closed even if the write fails or the task is
  cancelled.
  Threading (coro-ldap-nj9): a connection may be used from any number of
  threads, on an io_context run by one thread or a pool.
  `connection::executor_type` is a `capy::strand` of the io_context's
  executor; every operation of the connection, its streams, paged searches
  and transactions runs on it and resumes the awaiting task on that
  task's own executor. `is_open()`, `outstanding()`, `is_tls()`,
  `security_layer()` and `bind_count()` are snapshots, safe on any thread;
  a second concurrent `next()` on a stream fails with
  `operation_in_progress`. Breaking: `close()` and the destructors of
  `connection`, `search_stream`, `paged_search` and `transaction`, called
  off the strand (from another thread, or a task of the plain io_context
  executor), post their work: `close()` takes effect when the io_context
  next runs (`is_open()` reports it at once), and the memory resource of
  a destroyed stream's entries must outlive that run. On the strand, or
  with the io_context stopped and called outside its `run()`, they run at
  once.
  Precondition (temporary, until Capy's strand can be entered
  synchronously): `close()` and the destructors of a `connection`,
  `search_stream`, `paged_search`, `transaction`, `client` or lease (and
  a lease's `release()`), called from a thread outside `run()` of a
  stopped io_context, require that no thread is still inside `run()` (or
  `run_one()`, `run_for()`, `poll()`) of that io_context: join those
  threads first. A violation is a data race, which TSan reports. With
  `std::jthread`s, declaration order decides: members and locals are
  destroyed in reverse order, so declare the threads after the
  connections, clients, streams and transactions they serve, and they are
  joined before those are destroyed:

  ```cpp
  corosio::io_context ioc;
  auto c = /* ldap::connection, ldap::client, ... */;
  std::vector<std::jthread> pool;   // declared last: joined first
  for (int i = 0; i < 4; ++i) {
      pool.emplace_back([&] { ioc.run(); });
  }
  // ...
  ioc.stop();
  // leaving the scope: pool joins, then c is destroyed, then ioc
  ```

  Declared the other way round (`pool` before `c`), `c` is destroyed
  while the pool threads may still finish a handler on its strand, a race
  TSan reports. `locking_mode::unsafe_io` and `unsafe` opt out of
  cross-thread use.
  Step 6 adds the other operations: `add`, `modify` (changes from
  `ldap::mod::add / remove / replace / increment`; `add`, `remove` and
  `replace` take a braced list or any `ldap::string_range`, such as a
  `std::vector<std::string>`, like `partial_attribute(type, values)`),
  `del`, `modify_dn`
  (rename and / or move: `{.entry, .new_rdn, .delete_old_rdn,
  .new_superior}`; breaking (coro-ldap-aw4.3): `move()` and `rename()`
  are gone from `connection`, `client` and the sync facades), `compare`
  (`result<compare_result>`: `value` true / false for compareTrue /
  compareFalse, the response's `matched_dn`, `diagnostic_message` and
  `controls`, and an empty chase report (`referrals`, `unlisted`) where
  nothing chases; breaking: it returned `result<bool>` on `connection`,
  the leases and `sync::connection`) and `extended`, each taking a params aggregate
  with `.controls` (that operation's control list, see controls.hpp
  below) and `.timeout` (`extended` refuses the StartTLS name with
  encode_error before sending: use `start_tls`);
  transactions (RFC 5805), as non-members in transaction.hpp next to
  `ldap::transaction`: `ldap::start_transaction(connection &,
  extended_controls = {})` -> `result<std::string>` (the identifier;
  proxied authorization goes here, section 4.4), updates carrying
  `ldap::transaction_specification{.identifier}`, and
  `ldap::end_transaction(connection &, identifier, commit = true)` ->
  `result<end_transaction_result>` (`updates_controls`, the decoded
  updatesControls `{message_id, controls}`, with
  `find_update_controls(response::message_id)`, and `controls`); a refused
  End Transaction has the context "end transaction: update message N" when
  the server names the update. Before sending, `start_transaction` waits
  for the answers still due (a destroyed transaction's abort, a destroyed
  paged search's release) within the default timeout, then sends anyway
  (a stop meanwhile fails with `cond::canceled`, nothing sent), so slapd's
  one transaction per connection does not refuse the next one as busy.
  The static `ldap::transaction::begin(connection &, extended_controls = {})`
  -> `task<result<transaction>>` sends Start Transaction and returns the
  started helper `ldap::transaction` (move-only; it replaced
  `connection::begin_transaction()`, removed):
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
  Transaction (abort) without waiting. Breaking (coro-ldap-bhe.13):
  `connection::start_transaction` / `end_transaction` and their
  `sync::connection` / sync lease forwarders are gone: call the
  non-members (`ldap::sync::run(c, [](ldap::connection &a) { return
  ldap::start_transaction(a); })` from a sync facade). The static
  `sync::transaction::begin(sync::connection &, extended_controls = {})`
  (and `begin(sync::basic_lease<E> &, ...)` for a lease) returns a
  `result<sync::transaction>`, which aborts synchronously when destroyed
  open, waiting five seconds at most for the answer. The Aborted
  Transaction Notice is not routed: the next use fails.
  An update cancelled or timed out inside a transaction may be part of it:
  abort. A commit whose answer is lost has an unknown outcome. A bind or
  unbind aborts every transaction of the connection (RFC 5805 section
  3.5); transactions do not nest. The codecs (`end_transaction_request`,
  `update_controls`, `end_transaction_response`,
  `encode_end_transaction_request`, `decode_end_transaction_response`,
  the OIDs) are in `message.hpp`;
  `ldap::search_paged_stream(conn, params, page_size, max_pages =
  ldap::search_paged_default_max_pages, mr)` (a free function over
  `search_stream()`; `ldap::search_paged_stream(client, ...)` runs it on one shared
  lease, the first page retried as `client::search_stream()` is) follows
  the Simple Paged Results cookie across pages, at most `max_pages` pages
  (default 10000, about a million entries at a page size of 100; a page
  ending with a cookie after that fails `next()` with
  `std::errc::value_too_large`, the paging state then released on
  destruction; 0 fails with `std::errc::invalid_argument` before anything
  is sent, on a client before any acquire; `request.timeout` bounds each
  page, not the search; a repeated cookie is not an error, the cookie
  being the server's opaque state) (destroyed early, it
  abandons the current page and releases the server's paging state with a page size 0
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
  `ldap::search_paged(conn_or_client, params, page_size, max_pages, mr)`
  -> `task<result<search_result>>` reads every page of a
  `search_paged_stream` into one `search_result` (the last page's done; a
  limit code keeps the entries; more than `max_pages` pages fails with
  `std::errc::value_too_large`). The names are the same in every layer:
  `search_paged` collects every page (`ldap::`, `sync::`, both
  repositories), `search_paged_stream` streams them (async only); the
  arguments are the search, then the page size, then the rest. Breaking
  (coro-ldap-bhe.5): `ldap::search_paged` was the stream, now
  `ldap::search_paged_stream`; `repository::search_paged(page_size,
  filter, scope)` was the stream, now `search_paged_stream(filter,
  page_size, scope)`, and `search_paged(filter, page_size, scope)` collects
  (also the order of `sync::repository::search_paged`).
- `jhetz/ldap/referral_chase.hpp`: opt-in referral chasing.
  `co_await ldap::chase_search(conn, params, connector, policy, mr)` runs
  the search, then follows a referral result and the continuation
  references (RFC 4511 sections 4.1.10, 4.5.3) through `connector`, a
  `referral_connector` (`std::function` returning
  `task<result<connection *>>` for a URL and its depth; null skips it), which
  decides which servers may be contacted and how their connections are
  bound. It returns a `search_result` (`entries, references, result_code,
  matched_dn, diagnostic_message, controls, referrals, unlisted`, and
  `is_complete()`; the done fields are the origin's search's, or the referral
  target's: success or a limit code, as `search()`; on success, the first
  limit code a followed continuation reference's search ended with;
  `references` holds the URIs of the continuation references not
  followed): the entries of every server reached, one `referral_attempt`
  per URI tried (`followed`, `skipped_policy`, `skipped_loop`,
  `limit_reached`, `unparseable`, `failed` with its error), and
  `is_complete() == false` (`is_success() && references.empty()`) when a
  continuation reference could not be followed or a search ended with a
  limit code (partial results are
  never a plain success; such a reference never fails the search). A referral
  result that cannot be followed fails the call (the last error, else the
  referral; its context counts the attempts' outcomes); with the
  request's `follow_referrals` false, a referral result is not chased (the
  call fails with `errc::referral`). `chase_compare(conn, params, connector, policy)` does the
  same for a compare (`compare_result{value, matched_dn, diagnostic_message,
  controls, referrals, unlisted}`, the LDAPResult tail and controls of the
  response that answered). The URIs of one
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
  are skipped, a protected origin (TLS, ldapi://, or a SASL
  confidentiality layer) makes ldap:// targets use StartTLS (failure fails
  the URI), the certificate is checked against the referred host, and
  each new connection is bound only by `setup` (a `session_setup`, e.g.
  `simple_bind_setup`; none: anonymous, and the TLS client certificate of
  `options` is presented only with a setup: to keep it, pass
  `sasl_bind_setup` with an EXTERNAL mechanism, or `no_bind_setup()`, which
  presents it without binding). Its connections are reused per server and
  closed (without an UnbindRequest) with the last copy of the connector;
  `ioc` must outlive it.
  Continuation references are followed breadth first after the search
  ended, their entries appended in that order. Loops compare hosts in
  ASCII form, case-insensitively, DNs by distinguishedNameMatch and
  filters as trees. Without a request `timeout`, each request has its
  connection's `operation_timeout`; a connector ignoring the stop token is
  bounded only by itself, and its connection is then not used. The
  connector's connections must belong to the origin's executor, and the
  origin and those connections must outlive the task.
- `jhetz/ldap/extended_operations.hpp` (coro-ldap-aw4.4): the standard
  extended operations as free functions over `ldap::extended_directory`
  (anything with `connection`'s `extended()`: `connection`, `client`),
  written once: `who_am_i(d,
  controls)` (RFC 4532; an authzId that is not UTF-8 is
  conversion_failed) and RFC 3062 Password Modify, `password_modify(d,
  params)` (the request as the RFC has it, a generated password
  returned), and two conveniences over it, `change_password(d, user, old,
  new)` (a user's own) and `reset_password(d, user, new)` (an
  administrator's; an empty `user` is the bound user). The tasks refer
  to `d`, which must outlive them (an `ldap::client` too: unlike
  `client::extended()`'s own task, these hold the client).
  `sync_extended_operations.hpp`: the same
  four, blocking, over `sync::connection`, `sync::client` and the sync
  leases (`sync::directory`), each running the async one with
  `sync::run` (coro-ldap-aw4.5; breaking: `sync::extended_directory` is
  gone). Breaking: the members `who_am_i`, `password_modify`,
  `change_password` and `reset_password` are gone from `connection`
  and the sync facades, and `client::who_am_i` /
  `sync::client::who_am_i` with them (`client::extended` replaces them,
  retried only after `not_sent`, so a Who am I? on a client is no longer
  retried after a lost connection). The raw transaction operations
  (`ldap::start_transaction`, `ldap::end_transaction`) stay dedicated
  functions: a refused End Transaction's txnEndRes does not reach the
  public `extended()`. Active Directory
  has no RFC 3062: its password changes are `ad::change_password` and
  `ad::reset_password` (section `ldap::ad`). Which one runs is the call's
  choice: nothing reads the root DSE to pick. Passwords never appear in
  errors. The library wipes the password copies it makes before freeing
  them: a simple bind's, `password_modify`'s and these calls', those of
  `ad::change_password` / `ad::reset_password` and `ad::password_value`'s
  UTF-16 buffer, the values of `unicodePwd` and `userPassword` in any
  `modify`, and the encoded PDUs that carry them; `sasl_scram_sha256` and
  `sasl_ntlm` wipe what they hold. Not wiped: the caller's strings, the
  value `ad::password_value` returns, a generated password, and buffers
  inside OpenSSL or a SASL security layer.
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
  Writing a mechanism: one object serves one bind at a time; `start()`,
  `step()` and `complete()` run on the connection's I/O thread and must
  not block; `start()` also resets the mechanism; error contexts should
  not name the mechanism (`sasl_bind` prefixes "sasl bind <name>").
  `sasl_bind_context`'s views (host, bindings, `peer_certificate`) are
  valid only during `prepare()`. A `sasl_work` (from `offload_start()` /
  `offload_step()`, empty: run inline) runs once on a thread of its own;
  once `sasl_bind` gave up waiting it runs on while the mechanism may be
  destroyed or start another bind, so it must own or share what it uses.
  `channel_binding_used()` defaults to tls_exporter (fail-closed: a
  mechanism given tls-exporter data counts as having used it); override
  it to report what the exchange actually bound to.
  `take_security_layer()`, called once per step, returns the layer the
  exchange negotiated if that step's BindRequest is the last; it is
  installed when the server answers it with success, before `complete()`.
  A `sasl_security_layer` only wraps and unwraps buffers (on the I/O
  thread, one connection per layer): the connection frames each buffer
  with a four-octet network-order length, cuts outgoing PDUs to
  `max_wrap_input()` (at least 1) octets, and closes the connection on an
  incoming length above `max_received()` or an `unwrap()` error.
  SCRAM details: the server's iteration count must be at least 4096 (RFC
  7677 section 4) and at most `max_iterations`; the server nonce must
  extend the client's; `=` and `,` in the username and `authz_id` are
  escaped as `=3D` and `=2C`; `authz_id` must be UTF-8 without control
  characters (not SASLprep'ed). cyrus-sasl (slapd) does not SASLprep
  stored passwords, so a password SASLprep changes does not match there.
  `scram_channel_binding_for(supportedSASLMechanisms)` gives `plus` or
  `not_offered` (`"y,,"` over TLS, so a -PLUS server notices a stripped
  -PLUS, RFC 5802 section 6).
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
  the default, sends "y,," over TLS so that a server that does support
  -PLUS detects the downgrade (RFC 5802 section 6), and "n,," without TLS
  or binding data; a server that advertises -PLUS (slapd with
  `sasl-cbinding`) then refuses plain SCRAM-SHA-256 over TLS, so bind
  with `plus` there, or with `none` ("n,,", no downgrade signal).
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
  (maximum buffer size 0), so SASL neither signs nor seals the session,
  and `options.require_tls` (default true) then fails the bind with
  `client_errc::tls_required` on a connection without TLS (plain ldap://,
  ldapi://) before anything is sent: Kerberos authenticates the bind, but
  without TLS or a layer every later PDU is in clear and unsigned, so an
  active attacker can take over the connection. A layer stands in for
  TLS, as with NTLM: `integrity` or `confidentiality` bind over plain
  ldap://, and `best_offered` there fails with `tls_required` when the
  server offers no layer (the exchange is aborted). `require_tls = false`
  allows a bind without either where the network is trusted. A
  server that requires integrity or confidentiality fails a bind without
  a layer with `client_errc::security_layer_required`. `options.security_layer`
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
  tokens or credentials. Every GSS-API handle is released (RAII). The
  target, principal and `authz_id` must be well-formed UTF-8 without
  control characters (`encode_error`).
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
  that accepts posts from other threads (the default `locking_mode::safe`,
  or `unsafe_io`; under `unsafe` the bind fails with
  `std::errc::operation_not_supported` before anything is sent).
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
  layer stands in for it). `options.max_receive_size` (16 MiB, at least
  16) bounds the server's buffers; outgoing buffers are at most 128 KiB.
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
  3876 string form), `virtual_list_view` (draft-ietf-ldapext-ldapv3-vlv-09:
  `.before_count`, `.after_count`, `.target` = `vlv_by_offset{.offset,
  .content_count}` or `vlv_greater_than_or_equal{.value}`, `.context_id`;
  needs a `server_side_sort` on the same search, else encode_error before
  sending),
  `transaction_specification` (RFC 5805: `.identifier`, always critical,
  on add, modify, modify DN and delete; with a proxied authorization
  control, typed or raw, encode_error before sending)) or a raw
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
  the control is absent and an error when it is malformed. Their decoders
  (`decode_sort_result`, `decode_vlv_response`, `decode_read_entry`) are
  in `message.hpp`. The sort result and the VLV response
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
  Details: `relax_rules` lets an update bend the schema rules (e.g. set a
  NO-USER-MODIFICATION attribute such as `createTimestamp` when
  migrating); the server still decides who may (OpenLDAP: manage access).
  `proxied_authorization{.authz_id}` takes `"dn:<dn>"`, `"u:<user>"` or
  `""` (anonymous). `pre_read` goes on modify, delete and modify DN,
  `post_read` on add, modify and modify DN; empty attributes mean all
  user attributes. `matched_values` is non-critical by default; per RFC
  3876 section 2 an attribute without a matching value comes back with no
  values (OpenLDAP 2.7 leaves it out), and typesOnly or `"1.1"` make it a
  no-op. `vlv_by_offset`: offset 1 is the first entry, `content_count` 0
  means the server's count; `vlv_greater_than_or_equal`: the first entry
  whose primary sort key is >= the value. A `transaction_specification`
  update is answered at once and applied at End Transaction, where its
  response controls come back (`end_transaction_result::updates_controls`);
  Password Modify takes it only as a raw control, and only a typed one is
  checked against proxied authorization.
- `jhetz/ldap/mapping.hpp` (#9): typed struct mapping. A descriptor
  (`ldap::schema<T> = ldap::describe(ldap::object_class(...),
  ldap::auxiliary_class(...), ldap::field<&T::m>("attr",
  ldap::read_only)...)`, both class lists optional, auxiliary only after
  object_class) maps members to attributes; auxiliary classes are added
  and validated with the object classes, but not ANDed into a repository's
  search filter (`auxiliary_classes_of<T>()`); the member type decides cardinality (`T`,
  `std::optional<T>`, `std::vector<T>`); `value_traits<T>` converts values
  (strings, which must be well-formed UTF-8 or the decode is
  `conversion_failed`, and one bad value fails the whole `decode<T>` and
  so the whole repository search; the error names the attribute, the
  reason and the value's length, never the value, which may be a
  secret; integers, bool, `dn`, `binary` for binary
  attributes such as userPassword (Octet String), jpegPhoto and
  userCertificate, `sys_seconds` as GeneralizedTime, enums with an
  `enum_names` table). `decode<T>(entry)` (an entry holding a mapped
  attribute with a range option, AD's `member;range=0-1499`, fails with
  `client_errc::incomplete_values`: read it with
  `ldap::ad::read_all_values`),
  `to_attributes(value)`, typed changes `replace / add / remove<&T::m>(v)`,
  typed filters `filters::field<&T::m>() == v`; the I/O is `ldap::repository`
  (repository.hpp, below). Breaking (coro-ldap-2cx.2): `connection::search_as<T>`,
  `modify<T>(dn, changes)` and `add(dn, value)`, their sync copies and
  `connection_options::schema_check` are gone. Breaking
  (coro-ldap-2cx.2.1): connection.hpp (and so sync.hpp and client.hpp)
  no longer includes directory.hpp, mapping.hpp and schema.hpp: include
  jhetz/ldap/directory.hpp for `load_schema`, mapping.hpp and schema.hpp
  for the typed mapping (`decode<T>`, `ldap::schema<T>`, `describe`,
  `validate<T>`), repository.hpp for `ldap::repository`. Mistakes
  (unmapped or read_only member, wrong value type, invalid names) fail to
  compile; `tests/compile/` checks each. Encoding can fail (breaking
  change, coro-ldap-vcp): `value_traits<T>::encode` returns `std::string`
  or `result<std::string>` (`detail::encode_value` takes both); the
  string traits reject ill-formed UTF-8, enums a value without a name and
  `sys_seconds` a year outside 0000-9999, all as `encode_error`.
  `to_attributes` returns `result<...>` and `change<T>::wire` is a
  `result<modify_change>`; a repository's `modify` and `add` return the
  error before sending anything, and a typed filter on such a value is
  `filter::failed()` with that error (context `filter uid: not valid
  UTF-8 (ill-formed sequence at offset 1)`), which a repository's search
  and the encoder return before sending.

- `jhetz/ldap/schema.hpp` (#13): runtime schema validation. A lenient
  RFC 4512 parser for the subschema's attributeTypes / objectClasses /
  dITContentRules (a definition that does not parse, or is not UTF-8, is skipped and
  counted), `server_schema` (`syntax_of()` and `equality_of()` follow SUP to the
  inherited SYNTAX and EQUALITY), `validate<T>(schema)` listing every issue (unknown
  attribute or object class, syntax the member's type cannot read, a
  writable member on a NO-USER-MODIFICATION attribute; single member on a
  multi-valued attribute as a warning; MUST attributes of the declared
  object classes and their superclasses that no required, writable member
  maps as warnings: `must_attribute_not_mapped`,
  `must_attribute_not_required`, `unknown_superclass`; an auxiliary class
  of another kind on the server: `not_auxiliary`; a writable member whose
  attribute no MUST or MAY of those classes, the auxiliary ones or the
  structural class's DIT content rule lists, or that the rule precludes:
  `attribute_not_allowed`; a declared auxiliary class that rule's `AUX`
  does not list: `auxiliary_class_not_allowed`; an OBSOLETE rule counts
  for nothing; a member named by an alias or numeric OID rather than the
  attribute's first NAME: `not_primary_name`; a writable member whose
  attribute has no EQUALITY on its SUP chain, on a schema that declares
  EQUALITY somewhere: `no_equality_rule`; two members mapping one
  attribute type with the same options under different names or its OID
  (`sn` and `surname`): `duplicate_attribute`, an error, as an update
  would write it twice and a read decode only one; `cn` and `cn;lang-en`
  are not; never reported: objectClass, operational attributes,
  attributes the server does not define, and every member when a class
  is extensibleObject or a class or superclass is not defined),
  `server_schema::skipped_for_syntax(name)` (an attribute type defined
  but skipped because its SYNTAX is not a numeric OID),
  `attribute_type` with `usage` (`attribute_usage`),
  `object_class_type` with `sup`, `kind` (`object_class_kind`), `must`
  and `may`, `dit_content_rule` (`obsolete`, `aux`, `must`, `may`, `precluded`: RFC
  4512 4.1.6; `parse_dit_content_rule`,
  `server_schema::find_dit_content_rule(class_oid)`); the free
  `ldap::load_schema` (which reads dITContentRules too) (directory.hpp) and
  `repository_options::schema_check = schema_check::on_first_use`. Breaking
  (coro-ldap-aw4.1): `connection::load_schema()` is gone, and with it the
  connection's schema cache.
  Breaking: a `std::string` or `std::pmr::string` member on a binary
  syntax (Octet String, JPEG, Fax, Certificate, Certificate List,
  Certificate Pair, Audio, Binary; see `value_rejected_syntaxes`) is a
  `syntax_mismatch`: map userPassword and the like to `ldap::binary`.
- `jhetz/ldap/directory.hpp` (coro-ldap-2cx.1): the `ldap::directory`
  concept, the protocol operations a layer runs on (`search`, `add`,
  `modify`, `del`, `modify_dn`, `compare` with `connection`'s signatures
  and results), satisfied by `connection` and `client`; `ldap::load_schema(directory &)`, the subschema
  read over the public `search`; a limit code with no entry on either
  read is an error. `ldap::load_schema(client &)` (coro-ldap-2cx.2.2,
  defined in jhetz::ldap_net) runs both searches on one shared lease, so
  the root DSE and the subschema come from the same server, and runs
  them once more on a new lease after `cond::connection_lost` (not after
  busy or unavailable); `sync::load_schema(d)` runs it on a sync facade
  (the facade's own `not_connected` and `would_deadlock` with the context
  "load schema" too).
- `jhetz/ldap/repository.hpp` (coro-ldap-2cx.1, DESIGN.md section 4):
  `ldap::repository`, typed CRUD of one mapped struct under a base DN, each
  entry named by one member: `ldap::repository people(source, base,
  ldap::named_by<&person::uid>, repository_options{.schema_check})`, the
  struct and the source type deduced (`repository<&person::uid,
  ldap::client>`); one repository may be used from several threads (its
  schema-check outcome is behind a lock). Breaking: `ldap::store`,
  `sync::store`, `store_options`, store.hpp and sync_store.hpp are now
  `ldap::repository`, `sync::repository`, `repository_options`,
  repository.hpp and sync_repository.hpp, with no alias (a repository
  keeps no entries: each call is one request). The naming member must be in
  `schema<T>`, required, single-valued and writable (static_assert).
  `dn_of(key)`
  (`uid=<escaped key>,<base>`); `get(key)` / `get_at(dn)` -> `task<result<
  std::optional<T>>>` (a base-object search for T's attributes and object
  classes; noSuchObject or no entry of T's classes is nullopt, a limit
  code with no entry is an error; a read, `get` or `search`, fails with
  `client_errc::schema_mismatch` when the answer holds an attribute whose
  description is none of the names T maps (RFC 4512 2.5: the same type
  and option set, options in any order) nor a subtype of a name without
  options (`cn;lang-en` for `cn`; `cn;lang-en;x-foo` for `cn;lang-en`
  fails, decode would not read it), an alias, OID
  or supertype mapping answered under another name, RFC 4511 4.5.2: map
  members by the name the server returns);
  `add(T)`, `modify(key, changes)` / `modify_at(dn, changes)`,
  `update(original, changed)` (`original` a `record<T>`, sent to its
  DN, or a `T`, sent to `dn_of` its naming member) -> `task<result<
  std::optional<response>>>`: one modify of the members that differ
  (`ldap::diff(original, changed)` in mapping.hpp: replace or delete for
  single-valued members, delete then add of the values for multi-valued
  ones, a cleared one included, so values `original` does not hold stay;
  one replace with the new set for `std::vector<ldap::binary>`, whose
  attributes often have no equality rule; a member empty in `original` is
  written with replace too, since empty in the struct is not absent on
  the server: an attribute the reader may not see, RFC 4511 4.5.1.8, such
  as a userPassword under `by self =xw` or AD's unicodePwd;
  read_only members skipped), nullopt with nothing sent when none
  differs, `client_errc::naming_value_changed` when the naming member
  differs (use `rename`);
  `update_if(original, changed)` and `update_if(original, changed,
  ldap::versioned_by<&T::m>)`, the same modify with a critical Assertion
  control (RFC 4528) on `original`: `ldap::unchanged_filter(original)`
  (mapping.hpp: `(a=v)` for each value of each member, read_only members
  skipped; true while every value of `original` is still held by its
  attribute, subtypes and tagged values included, RFC 4511 4.5.1.7, RFC
  4512 2.5; it does not see added values nor a plain value replaced while
  a tagged or subtype sibling holds the same text, so a value written
  meanwhile to a member empty in `original` is overwritten) or
  `(m=<original's value>)` on a single-valued member, read_only or not
  (entryCSN, uSNChanged, modifyTimestamp), the exact check; a value of
  `original` gone fails with `errc::assertion_failed` (122). A 122 from
  the default filter can also mean Undefined (RFC 4528 section 3), then
  permanent: an attribute without an equality rule (jpegPhoto, audio), an
  equality rule whose assertion syntax is not the attribute's
  (userCertificate), or one the bound identity may not read, so retry
  loops on 122 must be bounded; with `schema_check::on_first_use`, the
  default guard on a struct with a writable member without an equality
  rule fails with `client_errc::no_equality_rule` (cond `invalid_input`)
  before sending, `schema_mismatch` first; `versioned_by` is the fix. An
  `original` with no values gives the empty filter
  (`invalid_filter` before sending). The default
  filter past `max_filter_elements` (10,000) elements, one per value, fails
  with `invalid_filter` before anything is sent: use `versioned_by`. An empty
  version member fails with `client_errc::missing_attribute`, and an
  Assertion control in the `controls` argument with `encode_error`, before
  anything is sent. AD and Samba do not support the Assertion control (no
  1.3.6.1.1.12 in supportedControl): Samba answers the critical control
  with `errc::unavailable_critical_extension` (12) and applies nothing, the
  connection staying open, so `update_if` never succeeds there; use
  `update`;
  `remove(key)` / `remove_at(dn)`, `rename(from, to)` (modify DN to
  `<naming attribute>=<to>`, deleteoldrdn TRUE) and `move(key, new_base)` /
  `move(key, other_repository)` (newSuperior, RDN kept) -> `task<result<response>>`, each with
  its operation's controls; `search(filter = (objectClass=*), scope =
  whole_subtree)` -> `task<result<typed_search_result<record<T>>>>`,
  `record<T>{dn, value}` with the DN the server sent (entries named
  otherwise included), the limit codes a value as for `search()`;
  `search_paged(filter, page_size, scope = whole_subtree)`, as `search()`
  with every page collected;
  `search_stream(filter, scope)` and `search_paged_stream(filter, page_size,
  scope)` -> `task<result<record_stream<T, search_stream | paged_search>>>`,
  whose `next()` yields `record<T>` one at a time (the first entry that does
  not decode ends the stream with its error, as it fails `search()`;
  `stream()` is the underlying stream; on a client, one shared lease held
  by the stream). Values
  that do not encode fail before anything is sent (`add uid=...:
  attribute mail: ...`, `modify uid=...: replace mail: ...`).
  `schema_check::on_first_use` (the enum is in repository.hpp) loads the
  schema with `load_schema` on the first operation and keeps the outcome
  (a mismatch fails every operation; a schema that does not load is tried
  again), and checks again once the source's `is_tls()` or
  `security_layer()` changed (RFC 4513 sections 3.1.5 and 5.2.1.6), on a
  source that has them. Over a `client` that is one check for the whole
  pool (a client has no `is_tls()`), whichever server later operations
  run on: every server of a pool must serve the same schema; use a
  lease's connection (`*lease`) as the source for a check per
  connection. The repository keeps a pointer to the source, which must
  outlive it and its tasks. `jhetz/ldap/sync_repository.hpp`:
  `sync::load_schema` and `sync::repository`, the same over
  `sync::connection`, `sync::client`, `sync::lease` and
  `sync::exclusive_lease` (`sync::directory`), blocking (no streams:
  `search_paged` collects every page into a
  `typed_search_result<record<T>>`); each `sync::repository` call runs the
  async repository's operation (`detail::repository_core`, shared with
  `ldap::repository`) as one task on the I/O thread.
- `net::read_frame` and `peek_message_header` (message.hpp) are the pieces
  the reader uses: wait for one complete PDU without decoding it, then read
  only its message id and operation tag.
- `jhetz/ldap/sync.hpp` (#12): `ldap::sync::connection`, the blocking facade.
  `ldap::sync::connect(url | string_view, connection_options = {}, mr)`
  -> `result<sync::connection>` is the only way to open one (as
  `ldap::connect`, without an io_context); reconnecting is
  `c = sync::connect(...)`. A connected one owns an io_context and an I/O
  thread in one shared heap core: it is copyable, a copy being another
  handle on that thread and connection (coro-ldap-vk8; `close()` or
  `unbind()` through any copy ends it for all), and moves and copies keep
  its transactions valid (destroying the last handle, or assigning a new
  connection over it to reconnect, closes the connection, joins the thread
  and ends them: they must not be used after that); a default-constructed (noexcept) or moved-from one
  has no thread and its operations fail with `not_connected`. Every
  method runs the corresponding connection operation on the I/O thread
  and waits, with the same types;
  `sync::search_paged(c, params, page_size, max_pages, mr)` (also on a
  sync lease and a `sync::client`) is `ldap::search_paged`, blocking.
  `sync::run(d, make_task, args...)` (coro-ldap-aw4.5) runs any async
  free function on a facade: `make_task(a, args...)` is called on the
  I/O thread with the facade's `ldap::connection` (a `sync::connection`'s
  or a lease's) or `ldap::client` and the task it returns is waited for,
  `ldap::sync::run(c, [](auto &a) { return ldap::who_am_i(a); })`; its
  `result<T>` is returned, after the facade's own `not_connected` and
  `would_deadlock`. A task whose result has to be destroyed on the I/O
  thread (a `search_stream`, `paged_search`, `record_stream`, `lease`,
  `exclusive_lease` or `transaction`, also inside `result`,
  `std::optional`, `std::unique_ptr` or `std::shared_ptr`) is rejected by
  a `static_assert`. `sync::directory` is the concept of the four facades
  (`sync::connection`, `sync::lease`, `sync::exclusive_lease`,
  `sync::client`); the blocking conveniences (`sync::who_am_i`,
  `sync::search_paged`, `sync::load_schema`, `sync::repository`,
  `ad::change_password`, ...) are written over it. Breaking:
  `sync::directory` was a structural concept (blocking `search`, `add`,
  ...), and `sync::search_paged(client &)` and `sync::load_schema(client
  &)` are no longer separate overloads.
  Callable from any number of threads; a call from its own I/O
  thread fails with `client_errc::would_deadlock`. Exceptions thrown by
  an operation are rethrown in the calling thread. The last handle's
  destructor also waits for a host name lookup or a SASL step still
  running (e.g. GSSAPI waiting for a KDC), so it may take as long as
  their timeouts. Do not destroy or assign to a `sync::connection`, a
  sync lease or a `sync::client` while another thread is inside one of
  its methods, nor destroy the last owner of an I/O thread on that
  thread (`std::terminate()` with a message on stderr). In `sync::run`,
  `make_task`, its task and `args` are used on the I/O thread, whatever
  the task creates there (a stream) must end there too, and copies of
  `a` must not leave the task. A `sync::transaction` made by a
  `sync::connection` must not outlive its last handle; one made by a
  sync lease shares the client's I/O thread and may outlive the lease
  and client, but keep the lease while using it. A sync lease keeps the
  client's I/O thread alive; on that thread its release and destructor
  return the connection without waiting. The memory resource of a
  `sync::connection` or `sync::client` must outlive its I/O thread.
- `jhetz/ldap/client.hpp` (3pf, DESIGN.md section 11): `ldap::client`, a
  pool of multiplexed connections opened lazily, usable from any number of
  threads (its pool state on a strand of its own, `executor()`, each
  connection on its own; `close()`, the destructor and a lease's release
  off that strand post their work, as `connection::close()` does).
  `client(ioc, client_options{.servers, .connection, .setup,
  .max_connections = 1, .idle_check, .probe_timeout, .max_lifetime,
  .acquire_timeout, .backoff, .failback_after, .observer, .referrals})`. The default
  `max_connections = 1` is one multiplexed connection that every shared
  lease uses at once, not a pool of one connection per caller; raise it
  for exclusive leases (binds, StartTLS) or to isolate slow operations.
  `acquire() ->
  task<result<lease>>`, the lease giving the pooled `connection`
  (`(*lease)->search(...)`), shared with other leases on the same
  connection (coro-ldap-tfn: `shared_connection` is gone; `simple_bind`,
  `sasl_bind`, `start_tls`, `unbind` and `close` through a shared lease
  change the session for every lease sharing it); `acquire_exclusive() -> task<result<exclusive_lease>>`, the
  full `connection` on an idle or new connection nobody else uses while it
  is held (for binds, `start_tls()`, `unbind()`). Breaking:
  `acquire_options` is gone. A lease returns the connection when destroyed
  or `release()`d. `max_connections` must be at least 1: 0 makes every
  `acquire()` and `acquire_exclusive()` fail with
  `std::errc::invalid_argument`. `acquire()` waits at most
  `acquire_timeout` and fails with the last server's error (its context
  names the server: `acquire ldap://ldap1.example.org: ...`), the stored
  error of a server backing off after an authentication failure,
  `capy::error::timeout` when no connection was ready in time and no
  server failed, `capy::error::canceled` when the task's stop token is
  set, and `client_errc::not_connected` once `close()` was called or on a
  moved-from client; `acquire_exclusive()` fails the same way. The task
  does not refer to the client, which may be moved or destroyed while it
  runs (destroying it fails the task with `not_connected`). The free `chase_search`, `chase_compare`,
  `make_same_policy_connector` and `ad::change_password` /
  `reset_password` take a `connection &` (a lease's too). `servers` (checked with `url::check_server()` when the
  client is built: an empty list or a refused entry fails every
  `acquire()` with `invalid_url`), then the text URLs of `server_urls`
  (`{.server_urls = {"ldaps://ldap1.example.org", ...}}`, parsed with
  `url::parse_server()` when the client is built, an unparsable one
  failing every `acquire()` the same way, its context naming
  `server_urls[i]` and the text) fail over in priority order with a per-server
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
  `idle_check` (`nullopt`: never), within `probe_timeout`
  (`ldap::no_timeout`: only `acquire_timeout` bounds it); with
  `acquire_timeout = ldap::no_timeout` an `acquire()` retries until it
  succeeds, is cancelled or the client is closed; a connection older than
  `max_lifetime`, or whose `connection::bind_count()` changed (a bind
  done or in progress), is no longer handed out and closes once its last
  lease returns, and does not count against `max_connections` meanwhile.
  `client_observer` hooks (`on_connect`, `on_disconnect` with a
  `disconnect_reason`, `on_retry`, `on_probe`, `on_acquire_wait`) do
  nothing by default, and none runs after `close()`. `close()`,
  `connections()`. Read forwarders `search(params, mr)`,
  `search_stream(params, mr)` and `compare(params)` (`->
  task<result<compare_result>>`: `value`, and the chase's report) run the operation on a
  shared lease and retry it
  once on another connection after `cond::connection_lost` or
  `cond::busy_or_unavailable` (a stream only before its first message;
  it holds the lease until destroyed; `ldap::search_paged_stream(client, ...)`
  retries its first page the same way). Write forwarders `add(params)`,
  `modify(params)`, `del(params)`, `modify_dn(params)`, each `->
  task<result<response>>`, and `extended(params)` (`->
  task<result<extended_result>>`, where `ldap::who_am_i(pool)` and the
  password calls run), run the operation on a shared lease and retry
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
  the pooled connection, within `limits` (a `referral_policy`). A
  request's `follow_referrals` (`search_params`, `compare_params`:
  `std::optional<bool>`) overrides `follow_referrals` for that call
  (`search()`, `compare()`, and the same on `sync::client`), and
  `search_params::follow_references` overrides `follow_references` for
  that search (false: the references stay in `references`, counted in
  `unlisted`); each governs only its own mechanism (referral results,
  continuation references), and `chase_search` / `chase_compare` take
  them too (false turns chasing off). The calls that never chase ignore
  both: `client::search_stream`, `ldap::search_paged_stream` and `search_paged` on a client, every
  `connection` and `sync::connection` call, and a call on a lease
  (`(*lease)->search(...)`).
  `authorize`, a `std::function<referral_binding(const referral_hop &)>`
  (`referral_hop{target, depth, origin}`), returns `refuse`, `anonymous`
  or `same_setup` (bind with the client's `session_setup`) per URI;
  empty: nothing is contacted. `same_setup_for_domains(domains)` builds
  one from `make_same_policy_connector`'s allow-list rules. ldapi:// and
  implausible hosts are refused before `authorize` is asked; a protected
  pooled connection (TLS, ldapi://, or a SASL confidentiality layer)
  makes ldap:// targets use StartTLS (no downgrade). Referred
  connections belong to one call (closed when it ends, not pooled). Only
  the pooled connection's own failure is retried, never a referred
  server's. `search()` returns the chase's `search_result` (the URIs of
  the continuation references not followed in `references`, when the
  origin's search succeeded the first limit code of a followed
  reference's search as `result_code`, and what the chase did in
  `referrals` and `unlisted`; with `follow_references` off, the
  references received are counted in `unlisted`), `compare()` its
  `compare_result`; `client_observer::on_referral(server,
  attempt)` hears of each URI. Writes (forwarders and leases),
  `search_stream()` and `extended()` never chase.
  `referral_hop::target` is the URL as the server sent it: the host
  percent-decoded but not lowercased, not in its ASCII (IDNA) form, a
  trailing dot kept, while the chase connects to the ASCII form; a
  hand-written authorizer must not compare the host as a raw string and
  must check the scheme and port itself (`same_setup_for_domains` does
  both). An exception the authorizer throws propagates out of `search()`
  / `compare()` (`sync::client` rethrows it), the chase's referred
  connections closed and the lease returned.
  Lifetime: the io_context must outlive the client and its leases, the
  memory resource the work left on the io_context (until `run()`
  returns), the observer the client or its `close()`. The observer, the
  authorizer and `session_setup` run on the client's strand;
  `session_setup` is copied into each attempt and may run concurrently
  for several connections. A connection leaving the pool after
  `io_context::stopped()` is closed, not unbound; a posted unbind runs
  only if the io_context runs again, so call `restart()` just before
  running it again, or call `close()` from a task on the executor to
  unbind cleanly. Called from a thread outside `run()` of a stopped
  io_context, `close()`, the destructor and a lease's release have the
  temporary precondition of the connection.hpp entry's "Threading" above
  (no thread still inside `run()`).
  Breaking (coro-ldap-bhe.7): the test hooks `detail::set_jitter`,
  `detail::set_connector` (client.hpp) and `detail::set_next_message_id`
  (connection.hpp) left the public headers for `detail::test_access` in
  src/test_access.hpp (not installed).
- `jhetz/ldap/sync.hpp` (3pf.5): `ldap::sync::client`, the blocking facade
  over `ldap::client`. `sync::client(client_options, mr)` owns an
  io_context and an I/O thread, where the `ldap::client` lives (session
  setup and observer hooks run there). `acquire() -> result<sync::lease>`
  and `acquire_exclusive() -> result<sync::exclusive_lease>`; a
  `sync::exclusive_lease` has `sync::connection`'s operations (bind,
  search, add, modify, ...,
  `unbind`, `close`; `sync::transaction::begin(lease)`), run on the leased connection, and so
  does a `sync::lease` (the five session operations then change the
  session for every lease sharing it), both with
  `server()`, `release()` and `operator bool` (`sync::basic_lease`). The forwarders
  `search` and `compare`, and the write forwarders `add`,
  `modify`, `del`, `modify_dn` and `extended`, block and retry as the
  async ones (`compare` returns a `compare_result`; both chase
  referrals as `client_options::referrals` says, the authorizer and
  `on_referral` running on the I/O thread); no `search_stream` (no
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
- `client_errc::bind_failed`: the request was held behind a bind that
  failed, was stopped with no BindRequest outstanding or did not complete
  (RFC 4511 section 4.2.1), so it was never sent; the context quotes the
  bind's error. It matches
  `cond::auth_failed`. A behaviour change: such requests used to be sent
  after the failed bind, anonymously and without the bind's security
  layer. If the failure closed the connection (also a bind stopped while
  its BindRequest is outstanding) they fail with `not_sent`.
- `client_errc::not_sent`: the operation failed before the connection's
  writer took its request (the connection closed while the request was
  refused, still queued, or held behind a bind), so the server never saw
  it and even an update may be retried elsewhere; the context names the
  failure. Once the writer took it, the failure's own code is reported
  (the server may have seen it). The exceptions (allocation failure,
  `unbind()`, a default-constructed or moved-from connection) are in the
  connection.hpp entry above. It matches `cond::connection_lost`, like
  `not_connected`.
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
  `error::diagnostic_message` keeps the server's text. The `client &` overloads
  run on a shared lease and retry once after `client_errc::not_sent`, as
  the client's write forwarders do (the connection that failed is closed,
  so the retry gets another). The connection must outlive the task; the
  `client &` tasks, like `client::acquire()`'s, do not refer to the
  client.
- `jhetz/ldap/ad/ranged_values.hpp` (`jhetz::ldap_ad`):
  `ad::read_all_values(c, object, attribute, options = {}, mr)`, every
  value of a multi-valued attribute that AD returns in windows of at most
  MaxValRange values (ranged retrieval, MS-ADTS 3.1.1.3.1.3.3), as a
  `string_list` on `mr`. Base-object searches for `attribute`, then
  `attribute;range=<next>-*`, until the answer holds the attribute without
  a range, a window ending with `*`, or no such attribute;
  `ad::range_options{.step = N}` asks for windows of N values instead
  (`member;range=0-999`, ...; a smaller window from the server is
  followed). More than `range_options::max_values` values (1,000,000 by
  default) or `max_rounds` searches (10,000) is
  `client_errc::message_too_large`; a window holding more values than its
  range names is `unexpected_response`. `c` is a `connection &` or a `client &` (one shared lease for
  every window, run once more after `cond::connection_lost`). An empty
  attribute or one with a range option is `std::errc::invalid_argument`
  before sending; a window that does not continue the previous one, the
  plain attribute after a window or no entry is
  `client_errc::unexpected_response`, as is an entry whose attributes
  name several types none of which is `attribute`, or several answers for
  one; a malformed range is `client_errc::decode_error`. The returned
  attributes are grouped by description without the range option
  (ignoring case, other options kept): the group named `attribute` is the
  answer, otherwise the only group present is taken as the server's name
  for an OID or alias (`2.5.4.31` answered as `member`), and the following
  windows ask for that name. In the group, one ranged attribute with at
  most one value-less plain one (AD's `member` next to
  `member;range=0-1499`, MS-ADTS 3.1.1.3.1.3.3) is a window, a lone plain
  one is every value; two ranged ones, or a plain one with values next to
  a ranged one, are `unexpected_response`. With a step, when the first window
  comes back without values, it is asked for once more without a range
  and that answer is taken as without a step (a ranged answer continues
  in windows of the step under the server's name): a server may ignore
  the range option (Samba on a numeric OID, slapd on every attribute). An
  attribute without values then costs two searches; the values do not
  depend on the step, except that such a server sends them in one
  answer; naming the lDAPDisplayName keeps the bound on a server that
  honours ranges. A bare later window still means past the end.
- `jhetz/ldap/ad/dirsync.hpp` (`jhetz::ldap_ad`): `ad::dirsync(c, request,
  options = {}, max_rounds = ad::dirsync_default_max_rounds, mr)`, DirSync
  polling (MS-ADTS 3.1.1.3.4.1.3): runs the search `request` (its base the
  root of a naming context) with a DirSync control from `options` (an
  `ad::dirsync_request`: its cookie, then each response's) while the
  response says MoreResults, at most `max_rounds` searches (default 1000),
  and returns an `ad::dirsync_result`: the entries changed since the
  cookie (with the asked-for attributes that changed; all with an empty
  cookie), the last cookie, for the next poll, and `more_results`. Each
  response is a complete batch and its CookieServer the point to resume
  from; MaxBytes and the server's MaxPageSize bound each round, so a large
  naming context needs many (1000 rounds is about a million objects at
  AD's default MaxPageSize). When MoreResults is still set after
  `max_rounds` searches, the call succeeds with the entries so far, the
  last cookie and `more_results == true`: call again now with that cookie
  for the rest. A complete snapshot needs `more_results == false`, and
  the entries of every call: each result holds only its own call's
  entries, so the loop accumulates them and keeps the caller's flags,
  `max_bytes` and other options, replacing only the cookie:

  ```cpp
  std::vector<ldap::entry> snapshot;
  auto r = co_await ldap::ad::dirsync(c, request, options);
  while (r) {
      std::ranges::move(r->entries, std::back_inserter(snapshot));
      if (!r->more_results) {
          break;
      }
      options.cookie = r->cookie;
      r = co_await ldap::ad::dirsync(c, request, options);
  }
  // r: the error, or the last call's result (r->cookie for the next poll)
  ```

  `max_rounds = 1` returns one batch per call, and a periodic poller that
  only saves `cookie` stays correct and gets the rest on its next poll.
  `max_rounds == 0` fails with `std::errc::invalid_argument` before
  anything is sent. `request.timeout` bounds each search, not the call; an
  async caller can stop the whole call with its stop token. Memory per
  round is bounded only as far as the server honours MaxBytes and
  MaxPageSize. `c` is a `connection &` or a `client &` (one shared lease,
  run once more from the first cookie after `cond::connection_lost`, the
  count of rounds reset). Without the Replicating Directory Changes right
  the server refuses it (`insufficient_access_rights`) unless
  `dirsync_flags::object_security` is set. A SearchResultDone without the
  control, or MoreResults with a cookie already seen in this call (the
  caller's included), is `client_errc::unexpected_response`; a repeated
  cookie without MoreResults is a success.
- `jhetz/ldap/ad/discover.hpp` (`jhetz::ldap_ad`): domain controller
  discovery from DNS SRV records, for `client_options::servers`.
  `ad::discover_domain_controllers(domain, options = {})` returns the
  `ldap://host:port` URLs of `_ldap._tcp.dc._msdcs.<domain>`;
  `ad::discover_global_catalogs(forest, options = {})` those of
  `_ldap._tcp.gc._msdcs.<forest>` (port 3268). `ad::discover_options`:
  `.site` (that site's `_ldap._tcp.<site>._sites....` records first, then
  the domain's others), `.tls` (`ldaps://` on 636, or 3269 for a Global
  Catalog), `.require_target_in_domain` (default true: with `.tls`, a
  record whose target is not the domain or a name under it is skipped,
  since DNS is unauthenticated and the TLS certificate is checked against
  the target; compared per label on the A-labels, ignoring ASCII case, as
  RFC 6125 section 6.2.1 does, so `dc.evilexample.org` is not under
  `example.org`; false keeps DCs outside the domain), `.resolver` (an
  `ad::srv_resolver`, a function from an ASCII DNS name to
  `result<std::vector<ad::srv_record>>`; empty: the system's
  `ad::resolve_srv`, res_nquery on Linux (links libresolv), DnsQuery_UTF8
  on Windows (dnsapi)). Each list is in RFC 2782 order
  (`ad::order_srv(records, g)`: by priority, then weighted random), without
  duplicates or the `.` target. Internationalized names are converted to
  A-labels (UTS #46, ICU), the SRV targets too (one trailing dot removed
  first, so `dc1.example.org.` and `dc1.example.org` are one server; the
  URLs hold them in lower case); a converted target holds only letters,
  digits, `-`, `_` (legacy AD host names such as `dc_01`) and `.`. Each
  URL is built with `url::server`, not from text. Unusable records are
  skipped: a target UTS #46 refuses or with another character, port 0
  (without `.tls` only, since `.tls` replaces the SRV port), a target
  outside the domain (above). Errors: `std::errc::invalid_argument`
  (empty domain), `client_errc::string_prep_failed` (a domain or site UTS
  #46 refuses), `std::errc::host_unreachable` (no SRV record names a
  server, or none is usable: the context lists the skipped targets and
  why, `no usable SRV record (dc.attacker.example: outside the domain)`;
  `cond::busy_or_unavailable`), the resolver's error
  (`std::errc::resource_unavailable_try_again` for a temporary DNS
  failure, `client_errc::decode_error` for an unparsable answer, or one
  whose SRV records are all malformed; `ad::resolve_srv` skips a
  malformed record among good ones).
  Blocking: call it before building the client or off the I/O thread.
- `jhetz/ldap/ad/range.hpp` (`jhetz::ldap`): the range option itself:
  `ad::parse_range(description)` splits `member;range=0-1499` into
  `ad::ranged_description{.type = "member", .range = {0, 1499}}` (nullopt
  without a range option, `decode_error` for a malformed one), and
  `ad::with_range(type, range)` writes `member;range=1500-*`
  (`ad::value_range{.low, .high}`, `high` nullopt for `*`).
- `jhetz/ldap/ad/sync.hpp` (`jhetz::ldap_ad`): the same calls, blocking,
  over a sync facade (`sync::directory`: a `sync::connection`, a sync
  lease or a `sync::client`), each running the async one with
  `sync::run`.
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
  Test `ad::is_never` before converting or doing arithmetic: arithmetic
  near the top of the range overflows, `ad::never` converts to year 30828,
  and a converted value keeps 100 ns ticks, which may not fit a
  `system_clock::time_point` (libstdc++'s nanoseconds end in 2262): keep
  the ticks or floor to seconds. Negating `ad::forever` overflows. Dates
  below -1 are rejected (`conversion_failed`). An equality filter on
  `ad::never` misses accounts stored as 0: "never expires" is
  `(|(accountExpires=9223372036854775807)(accountExpires=0))`, and
  `>= 1` leaves those out of an "expired" filter.
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
- `jhetz/ldap/ad/filters.hpp` (`jhetz::ldap`): AD's bitwise matching
  rules as extensible-match filters: `ad::matching_rule_bit_and`
  (LDAP_MATCHING_RULE_BIT_AND, 1.2.840.113556.1.4.803) and
  `ad::matching_rule_bit_or` (1.2.840.113556.1.4.804);
  `ad::all_bits(attr, bits)` / `ad::any_bits(attr, bits)` and the typed
  `ad::all_bits<&T::m>(bits)` / `ad::any_bits<&T::m>(bits)` on a
  described member, for a `user_account_control` (written as its
  `value_traits` write it, AD's signed 32-bit decimal) or an integer
  (groupType, systemFlags, searchFlags; its own decimal value):
  `ad::all_bits<&user::uac>(account_disable)` is
  `(userAccountControl:1.2.840.113556.1.4.803:=2)`.
- `jhetz/ldap/ad/controls.hpp` (`jhetz::ldap`): AD's request controls,
  converting to a raw `ldap::control`, so they go in any operation's
  `.controls` (and `request_controls`). `ad::show_deleted{}`
  (`ad::show_deleted_oid`, 1.2.840.113556.1.4.417, MS-ADTS
  3.1.1.3.4.1.14): searches include deleted objects (isDeleted TRUE, under
  CN=Deleted Objects); no value, critical by default
  (`.critical = false` to send it non-critical).
  `ad::notification{}` (`ad::notification_oid`, 1.2.840.113556.1.4.528,
  MS-ADTS 3.1.1.3.4.1.9): change notification, critical by default; and
  `ad::notification_search(base, scope = base_object, attributes = {})`,
  the `search_params` it needs ((objectClass=*), the control,
  `ldap::no_timeout`), for `search_stream()`: the stream yields an entry
  each time an object in scope changes (no initial content) until it is
  destroyed or stopped. On an `ldap::client`, open it on a lease
  (`client::search_stream()` returns only at the first message, here the
  first change); the sync facade has no streams.
  DirSync's codec (`ad::dirsync_oid`, 1.2.840.113556.1.4.841, MS-ADTS
  3.1.1.3.4.1.3): `ad::dirsync_request{.flags, .max_bytes, .cookie,
  .critical = true}` converts to the request control (Flags as AD's signed
  32-bit INTEGER, MaxBytes 1048576 by default as .NET sends it);
  `ad::dirsync_flags` (`object_security`, `ancestors_first_order`,
  `public_data_only`, `incremental_values`, with `|`, `&`, `has`); the
  response `ad::dirsync_response{.more_results, .unused, .cookie_server}`
  from `ad::decode_dirsync_response(c)` or
  `ad::find_dirsync_response(controls)`; and
  `ad::encode_dirsync_request`. Malformed values are
  `decode_error`.
- `jhetz/ldap/ad/syntax.hpp` (`jhetz::ldap`): `ad::large_integer_syntax`,
  the Large Integer syntax OID (1.2.840.113556.1.4.906), which
  `validate<T>` accepts for signed integers of 64 bits or more and the
  FILETIME types.

## What throws

Errors are values (`result<T>`); the exceptions left are these:

- `std::bad_alloc` wherever memory is allocated.
- `ber::make_tag` (and `universal`, `application`, `context`,
  `private_tag`) and `ber::identifier_octet`: `std::invalid_argument` for a
  tag number above 30 (a compile error in a constant expression);
  `ber::writer::constructed`: `std::logic_error` when `body` calls
  `clear()` or `take()`, and whatever `body` throws, after removing the
  partial element.
- `ldap::run`: the task's exception, rethrown, and `std::system_error`
  (`capy::error::canceled`) when the task did not finish.
- The sync facades: an exception an operation throws on the I/O thread,
  rethrown in the calling thread.
- An exception a user callback throws (a referral authorizer, for one)
  propagates out of the call that ran it.
- `result<T>::value()` on an error: `std::bad_expected_access`.

The literal constructors (`dn`, `rdn`, `attribute`, `url`, the mapping
descriptors) are consteval: an invalid literal does not compile.

## Memory

Memory (DESIGN.md section 8): the public types use `std::pmr` containers
and are allocator-aware: the message model (every operation, `ldap_result`,
`control`, `partial_attribute`, `message`, `paged_results`), `filter`,
`dn` / `rdn` / `ava`, `attribute`, `entry` / `attribute_values`, `url` /
`url_extension` and `ber::writer` have `allocator_type`, `get_allocator()`,
an allocator constructor, allocator-extended copy and move constructors, and
assignment that keeps the target's resource (also for their `std::optional`
and `std::variant` members). Parsing and decoding take the resource:
`decode_options::memory`, `filter::raw(text, mr)`, `dn::parse(text, mr)`, `rdn::parse(text, mr)`, `attribute::parse(text, mr)`,
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
- String types: a call taking a `memory_resource *` returns `std::pmr`
  strings on it; members of allocator-aware types (entry values,
  `extended_result`, the message model) are `std::pmr`; every other
  returned string is `std::string` (`who_am_i()`, `password_modify()`,
  `start_transaction()`, `sync::transaction::identifier()`). `ldap::error`
  is the exception (above). Coroutine string parameters are by value
  (`end_transaction(std::string identifier, commit)`).

LDAP resultCode 0 (success) has no `errc` value: success is the absence of
an error; `ldap_result::is_success()` checks for it.

Not yet: Kerberos through GSS-SPNEGO, tls-unique.
