# API reference

What each public header provides, in more detail than the README. The design
rationale is in [`DESIGN.md`](DESIGN.md).

## `jhetz::ldap`: the codec

- `jhetz/ldap/error.hpp`: `ldap::error`, `ldap::result<T>` (`std::expected`),
  `ldap::errc` (RFC 4511 result codes and RFC 4528's `assertion_failed`,
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
  RDNs, `parent()`, `child()`, compile-time checked literals). Syntax only: no
  matching-rule normalization of values. `ldap::rdn` has its own literal and
  `rdn::parse()` / `to_string()` for exactly one RDN (`cn=a+sn=b` is one RDN,
  `cn=a,dc=b` is rejected). DNs are built from parts with `child()`:
  `base.child(ldap::rdn{"uid=jdoe"})` is `uid=jdoe,<base>`, and
  `base.child(ldap::dn{"uid=jdoe,ou=people"})` prepends a relative DN
  (`uid=jdoe,ou=people,<base>`); the result uses `base`'s resource.
  `escape_dn_value(v)` gives the RFC 4514 text of one attribute value,
  exactly as `to_string()` writes it, for DN text built elsewhere.
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

## `jhetz::ldap_net`: transports and connecting

A second library (target `jhetz::ldap_net`, option `JHETZ_LDAP_BUILD_NET`,
on by default) with the network parts. It depends on Corosio and Capy
(fetched with FetchContent at pinned commits), OpenSSL and ICU; `jhetz::ldap`
itself stays dependency-free.

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
  client API, with `ldap::connect()` and `ad_password_value()`. It includes
  the headers below, so it is the one to include; each also compiles on
  its own:
  - `jhetz/ldap/connection_options.hpp`: `connection_options`,
    `schema_check`, `password_method`.
  - `jhetz/ldap/operations.hpp` (part of the codec, `jhetz::ldap`): the
    request aggregates (`search_params`, `add_params`, `modify_params`,
    `del_params`, `modify_dn_params`, `compare_params`, `extended_params`,
    `password_modify_params`), the `ldap::mod` builders, `response`,
    `extended_result`, and the OIDs `who_am_i_oid`, `password_modify_oid`
    and `active_directory_capability_oid`.
  - `jhetz/ldap/search_stream.hpp` and `jhetz/ldap/paged_search.hpp`: the
    entry streams `search_stream()` and `search_paged()` return.
  - `jhetz/ldap/cancel.hpp`: `raceable()` and `with_stop()`.

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
  To give up on an operation when another event comes first,
  `capy::when_any(ldap::raceable(c.search(p)), corosio::delay(5s))` races
  it (`raceable` makes its `result<T>` the payload of a `capy::io_result`,
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
  IntermediateResponses are skipped; a Notice of Disconnection fails every
  outstanding operation. A server result error fails one operation; a
  transport or protocol error fails all of them once and closes the
  connection, and later operations fail with `client_errc::not_connected`
  naming the first error. The header documents the memory, threading and
  lifetime rules.
  Step 6 adds the other operations: `add`, `modify` (changes from
  `ldap::mod::add / remove / replace / increment`), `del`, `modify_dn`
  (rename and / or move), `compare` (`result<bool>`), `extended`,
  `who_am_i` (RFC 4532) and `password_modify` (RFC 3062: returns the
  server-generated password, if any), each taking a params aggregate with `.controls`
  and `.timeout`; `search_paged(params, page_size)` follows the Simple
  Paged Results cookie across pages (destroyed early, it abandons the
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
  `error::referrals` and `search_stream::references()`), never chased;
  `url::parse_list` parses them.
- Password changes that work on OpenLDAP and Active Directory alike:
  `change_password(user, old, new)` (a user's own) and
  `reset_password(user, new)` (an administrator's), on `connection` and
  `sync::connection`. The method comes from the server's root DSE, read
  once per connection (again after StartTLS): RFC 3062 Password Modify if
  `supportedExtension` lists it, else Active Directory (and Samba AD) if
  `supportedCapabilities` lists `1.2.840.113556.1.4.800`, else
  `client_errc::no_password_method`; a server offering both gets RFC 3062.
  On AD the password goes into one ModifyRequest of `unicodePwd`
  (`ldap::ad_password_value`: quoted, UTF-16LE, full Unicode), deleting the
  old value and adding the new one for a change, replacing it for a reset,
  and only over TLS (`client_errc::tls_required` before anything is sent);
  AD's diagnostics for common refusals (`0000052D` password policy,
  `00000056` wrong old password) are explained in the error's context.
  When the root DSE is hidden by access controls, choose the method with
  `connection_options::password_method` or per call
  (`ldap::password_method::rfc3062` / `active_directory`): an explicit
  method never reads the root DSE. Passwords never appear in errors.
  Password memory is not wiped (simple binds, `password_modify`, these
  two, `ad_password_value`): the password goes through `std::string`
  copies the library cannot all reach. Only `sasl_scram_sha256` wipes
  what it holds.
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
  4013, through ICU; no channel binding; `sasl_scram_options` sets the
  authorization identity, the largest iteration count accepted from the
  server, `max_iterations`, 1'000'000 by default, and the count above which
  PBKDF2 runs on a thread of its own, `offload_above_iterations`, 16'384 by
  default, inline under `locking_mode::unsafe`; the SaltedPassword is
  cached per salt and count across binds with the same object) are built in,
  `sasl_gssapi` (`jhetz/ldap/sasl_gssapi.hpp`, Kerberos V5, RFC 4752;
  optional, see below) too when built with `JHETZ_LDAP_WITH_GSSAPI`,
  and `sasl_mechanism` is the interface for others (`prepare()` gives a
  mechanism the URL's host before each bind, and whether a step can be
  offloaded, `sasl_bind_context::can_offload`; a step that may block, such
  as a network call, is handed to `sasl_bind` with `offload_start()` /
  `offload_step()` and runs on a thread of its own). When the server
  reports success but the mechanism's `complete()` refuses it (e.g. a
  wrong SCRAM server signature), `sasl_bind` returns the error and closes
  the connection, since the server considers it bound.
- SASL GSSAPI (`sasl_gssapi`, option `JHETZ_LDAP_WITH_GSSAPI`, off by
  default; needs the GSS-API library, MIT krb5's `libgssapi_krb5`, found
  with pkg-config: Debian `libkrb5-dev`, Arch `krb5`): Kerberos binds with
  the default credentials (the ticket cache of `kinit`, `KRB5CCNAME`) or
  `sasl_gssapi_options::principal` (UTF-8, e.g. `jdoe@EXAMPLE.ORG`); the
  target is `ldap@<the URL's host>` unless `options.target` names
  another (connect with the server's DNS name, not an address; ldapi://
  needs an explicit target); mutual authentication is required; an
  optional `authz_id`. The client always chooses "no security layer"
  (maximum buffer size 0), so SASL neither signs nor seals the session:
  use it over ldaps:// or StartTLS unless the network is trusted. A
  server that requires integrity or confidentiality fails the bind with
  `client_errc::security_layer_required`. Active Directory: with the
  "LDAP server signing requirements" policy set to require signing, AD
  refuses unsigned SASL binds over plain ldap:// (`stronger_auth_required`,
  `00002028`), so use TLS there; there is no channel binding, so an AD
  whose "LDAP channel binding" policy is "Always" refuses it over TLS.
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
- `jhetz/ldap/controls.hpp`: typed request controls in a `std::variant`
  (`ldap::paged`, `manage_dsa_it`, `relax_rules`
  (draft-zeilenga-ldap-relax, critical by default), `proxied_authorization`,
  `server_side_sort` (RFC 2891), `assertion` (RFC 4528, critical by default;
  a false one fails with `errc::assertion_failed`), `pre_read` /
  `post_read` (RFC 4527), or a raw `ldap::control`), `to_control` /
  `append_controls` to encode them, and readers for the typed response
  controls of a `std::pmr::vector<control>` (`response::controls`,
  `search_stream::controls()`, ...): `find_paged`, `find_sort_result`
  (`sort_result{result_code, attribute_type}`), `find_pre_read` /
  `find_post_read` (the entry as an `ldap::entry`). Each returns nullopt when
  the control is absent and an error when it is malformed. The response
  control codecs (`encode_` / `decode_sort_result`, `encode_` /
  `decode_read_entry`) are in `message.hpp`, for mock servers. The sort
  result comes with the SearchResultDone, so it needs `search_stream`
  (`search()` returns only the entries). RFC 2891 section 2 says a server
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
  (strings, integers, bool, `dn`, `binary`, `sys_seconds` as
  GeneralizedTime, enums with an `enum_names` table). `decode<T>(entry)`,
  `to_attributes(value)`, typed changes `replace / add / remove<&T::m>(v)`,
  typed filters `filters::field<&T::m>() == v`, and on the connection
  `search_as<T>`, `modify<T>(dn, changes)` and `add(dn, value)`. Mistakes
  (unmapped or read_only member, wrong value type, invalid names) fail to
  compile; `tests/compile/` checks each.
- `jhetz/ldap/ad.hpp`: Active Directory's Large Integer syntax
  (1.2.840.113556.1.4.906) as std::chrono types. `ad::filetime_clock` is a
  C++20 Clock for FILETIME (100 ns ticks since 1601-01-01 UTC;
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
- `jhetz/ldap/schema.hpp` (#13): runtime schema validation. A lenient
  RFC 4512 parser for the subschema's attributeTypes / objectClasses,
  `server_schema`, `validate<T>(schema)` listing every issue (unknown
  attribute or object class, syntax the member's type cannot read, a
  writable member on a NO-USER-MODIFICATION attribute; single member on a
  multi-valued attribute as a warning), `connection::load_schema()` and
  `connection_options::schema_check = schema_check::on_first_use`.
- `net::read_frame` and `peek_message_header` (message.hpp) are the pieces
  the reader uses: wait for one complete PDU without decoding it, then read
  only its message id and operation tag.
- `jhetz/ldap/sync.hpp` (#12): `ldap::sync::connection`, the blocking facade.
  It owns an io_context and an I/O thread; every method runs the
  corresponding connection operation there and waits, with the same
  types (`connect` takes a `url` or its text, as `ldap::connect` does).
  Callable from any number of threads; a call from its own I/O
  thread fails with `client_errc::would_deadlock`.
- `examples/ldapsearch.cpp` (target `jhetz_ldapsearch`, binary
  `jhetz-ldapsearch`, option `JHETZ_LDAP_BUILD_EXAMPLES`): connect,
  StartTLS (`-Z`), simple bind (`-D dn -w pw`) or SASL EXTERNAL
  (`-Y EXTERNAL [-X authzid]`, client certificate `--cert` / `--key`),
  search (paged with `--page N`), LDIF output, unbind;
  `jhetz-ldapsearch [options] URL [filter [attrs]]`.

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

Not yet: other SASL mechanisms (SCRAM-SHA-256-PLUS, GSS-SPNEGO, GSSAPI
security layers and channel binding), a connection pool.
