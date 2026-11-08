// An LDAP connection: bind, search and unbind over a net::transport, with
// any number of operations outstanding at once (DESIGN.md sections 3, 5 and
// 7). Part of jhetz::ldap_net.
//
//   corosio::io_context ioc;
//   ldap::result<ldap::connection> c = co_await ldap::connect(ioc, "ldaps://ldap.example.org", {.timeout = 5s});
//   if (!c) ...                           // a bad URL fails here too (invalid_url)
//   if (auto b = co_await c->simple_bind(ldap::dn{"cn=admin,dc=example,dc=org"}, password); !b) ...
//   auto people = co_await c->search({
//       .base       = ldap::dn{"ou=people,dc=example,dc=org"},
//       .filter     = ldap::filters::attr("uid") == user,
//       .attributes = {"cn", "mail"},
//   });                                   // result<search_result>: people->entries
//   co_await c->unbind();
//
// Multiplexing (step 5b): operations started concurrently (several tasks,
// on any threads, e.g. with capy::when_all) are all sent at once,
// each with its own message id, and their responses are matched by id. One
// writer coroutine sends the PDUs in order, never interleaved; one reader
// coroutine routes each response to the operation waiting for it, and runs
// only while some operation waits or the answer to a paged search release
// is due (see paged_search; an idle connection has no pending read, so
// io_context::run() can return). Search entries are queued per search
// until its stream takes them; the queue is not bounded, because a bound
// would let one slow stream stall every other operation on the connection.
//
// Cancellation and timeouts: every operation honours the stop token of the
// task awaiting it, and a timeout (search_params::timeout, else
// connection_options::operation_timeout). When either fires before the
// final response, the operation fails with capy::error::canceled or
// capy::error::timeout (ldap::cond::canceled / cond::timeout), an
// AbandonRequest (RFC 4511 section 4.11) is sent for it, and responses that
// still arrive for it are dropped; the connection stays usable. A
// search_stream destroyed before its end abandons its search the same way.
// Abandon is best effort: the server may have answered already, so an update
// (add, modify, delete, modify DN) that timed out or was cancelled may still
// have been applied; re-read the entry if the outcome matters. Bind and
// StartTLS cannot be abandoned (section 4.11): giving up on one closes the
// connection instead (its outcome is unknown). An operation whose stop token
// is set before it starts is not sent (nothing is abandoned, an update is
// not applied): it fails with capy::error::canceled and the connection stays
// open. unbind() is sent regardless.
//
// To race an operation against another event (a timer, Ctrl-C) or cancel
// it from a std::stop_source of your own, see cancel.hpp: raceable() and
// with_stop().
//
// Binds (RFC 4511 section 4.2.1): nothing is sent while a BindRequest is
// outstanding. Requests started during a bind exchange (all the steps of a
// SASL bind) are held and sent, in order, once it ends; one cancelled while
// held is never sent. Binds are serialized: a second waits for the first.
// A connection reached through a shared ldap::lease (client.hpp) is used by
// the other leases too, so a bind, start_tls(), unbind() or close() on it
// changes the session for all of them: do those on acquire_exclusive().
//
// What the server sends is decoded with origin::server, always. Each
// response must carry the id of an outstanding (or recently abandoned)
// request and an operation that answers it; anything else is
// client_errc::unexpected_response. IntermediateResponses (RFC 4511
// section 4.13) are skipped unread, unless the request asked for them
// (search_params / extended_params::intermediate_responses): then they are
// decoded and returned, by search_stream::next_item() in order with the
// entries and references, or in extended_result::intermediates.
// Unsolicited notifications (id 0, RFC 4511 section 4.4): a Notice of
// Disconnection fails every outstanding operation with the server's result
// code (errc::unavailable if it sent success) and closes the connection;
// other extended responses with id 0 are ignored.
//
// Errors: a server result other than success is `ldap_result::to_error`
// with the operation as context, e.g. "search ou=people,dc=example,dc=org";
// it fails that operation only. So does a request that fails to encode
// (nothing is sent) and a cancellation or timeout. A transport error, a
// malformed or oversized PDU, an unexpected response or a Notice of
// Disconnection fails every outstanding operation, exactly once, and closes
// the connection: every later operation fails with client_errc::not_sent,
// naming the original error.
//
// Sent or not: an operation whose request the writer never took (refused
// because the connection is closed, still queued behind other PDUs, or held
// behind a bind) when the connection closes fails with client_errc::not_sent
// instead of the failure's own code; its context still names that failure.
// The server never saw such a request, so even an update may be retried on
// another connection. So a request held behind a bind when a Notice of
// Disconnection arrives fails with not_sent, not with the notice's code
// (unavailable or busy). Once the writer has taken the request, the failure's
// own code is reported (not_connected after close(), a transport error, ...):
// the server may have seen it. not_sent matches cond::connection_lost, like
// not_connected, so code testing the condition needs no change. Exceptions:
// an allocation failure stays std::errc::not_enough_memory, unbind()'s
// abandoned operations fail with not_connected (their requests were queued
// before the UnbindRequest), and a default-constructed or moved-from
// connection keeps not_connected.
//
// Memory: entries returned by search() and search_stream are decoded
// straight into the memory resource given to that call (default: the
// default resource), with no copy: the reader looks at a PDU's message id
// before decoding it. With a caller's arena the entries must not outlive it
// (DESIGN.md section 8). The connection's own state, buffers and queues live
// on the resource given to connect() or the constructor.
//
// Threading: a connection may be used from any number of threads at once,
// with an io_context run by one thread or by a pool. It runs on a
// capy::strand of its io_context's executor (executor()): the writer, the
// reader, the timers and every operation of the connection, of its
// search_streams, paged_searches and transactions hop onto it when they
// start (at once when the awaiting task already runs there) and resume the
// awaiting task on its own executor when they end. The accessors (is_open(),
// outstanding(), is_tls(), security_layer(), bind_count(), ...) read
// snapshots, safe on any thread. A search_stream or paged_search has one
// next() at a time: another, from any thread, fails with
// client_errc::operation_in_progress. The objects themselves (connection,
// stream, transaction) follow the standard library's rule: one thread at a
// time calls their non-const members (move, assign, destroy). Values
// returned (entry, dn, search_result) are plain values. A search's entries
// are allocated on the strand while the caller may free those it got on
// another thread: the resource given for them must allow that (the default
// resource, std::pmr::synchronized_pool_resource, or an arena that frees
// nothing until the search has ended). Corosio's locking_mode::unsafe_io and unsafe opt
// out of cross-thread use: the io_context must then run on one thread and
// the connection be used from it only.
// Destructors and close() called off the strand (from a thread not running
// it, or from a task of another executor, as a task started with
// capy::run_async(ioc.get_executor()) is) do not wait for it: they post
// their work there, and it runs when the io_context next runs. So close()
// takes effect then (is_open(), outstanding(), is_tls() and
// security_layer() report it at once), and after destroying a stream,
// paged_search or transaction off the strand, the memory resource given
// for its entries must outlive that run of the io_context. An io_context destroyed before it runs that work again drops
// it, and what it would have freed is leaked: after run_one() or a stop,
// let it run (poll()) first. They run at once when called on the strand,
// or once the io_context is stopped from a thread outside its run():
// stopped() is true from stop() on, while the threads running it may still
// finish a handler on the strand, so join them before destroying a
// connection or stream on another thread. Called from inside run() after
// stop(), they post their work as above. The shared state is
// reference counted, so a stream, an outstanding operation or the internal
// reader may outlive the connection object (destroying the connection
// closes it; they then fail with not_connected). Operations never wait on
// I/O themselves (the writer and reader do), only for their responses, so
// destroying a task suspended in one of them is safe: the operation is
// abandoned. Stop tokens are the normal way to cancel.
#pragma once

#include "jhetz/ldap/ber.hpp"
#include "jhetz/ldap/cancel.hpp"
#include "jhetz/ldap/channel_binding.hpp"
#include "jhetz/ldap/connection_options.hpp"
#include "jhetz/ldap/controls.hpp"
#include "jhetz/ldap/dn.hpp"
#include "jhetz/ldap/entry.hpp"
#include "jhetz/ldap/error.hpp"
#include "jhetz/ldap/filter.hpp"
#include "jhetz/ldap/message.hpp"
#include "jhetz/ldap/net/connect.hpp"
#include "jhetz/ldap/net/transport.hpp"
#include "jhetz/ldap/operations.hpp"
#include "jhetz/ldap/paged_search.hpp"
#include "jhetz/ldap/sasl.hpp"
#include "jhetz/ldap/search_stream.hpp"
#include "jhetz/ldap/transaction.hpp"
#include "jhetz/ldap/url.hpp"

#include <boost/capy/ex/strand.hpp>
#include <boost/capy/task.hpp>
#include <boost/corosio/io_context.hpp>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory_resource>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace jhetz::ldap {

class connection;

namespace detail {
	// For tests only: the message id the next request tries first.
	void set_next_message_id(connection &c, std::int32_t id) noexcept;
	// For ldap::client: `hook` runs once, on the connection's executor, when
	// the connection closes (an error, close(), unbind(), its destruction).
	// Replaces an earlier hook. Ignored on a default-constructed or
	// moved-from connection.
	void set_close_hook(connection &c, std::move_only_function<void() noexcept> hook) noexcept;
	// For ldap::client: the connection takes requests (open, no unbind()
	// under way). False on a default-constructed or moved-from connection.
	[[nodiscard]] auto accepts_requests(const connection &c) noexcept -> bool;
}// namespace detail

class connection
{
  public:
	// The connection's strand over its io_context's executor: everything
	// the connection does runs on it (see "Threading" above).
	using executor_type = boost::capy::strand<boost::corosio::io_context::executor_type>;

	// Not connected: every operation fails with client_errc::not_connected.
	connection() noexcept = default;
	// Runs LDAP over an open transport (for example one from net::connect(),
	// or transport::wrap() of a test stream) whose I/O runs on `ioc`. Of
	// `options` only max_message_size and operation_timeout apply here. The
	// connection's state is allocated from `mr`.
	connection(boost::corosio::io_context &ioc,
	  net::transport t,
	  const connection_options &options = {},
	  std::pmr::memory_resource *mr = std::pmr::get_default_resource());
	connection(connection &&other) noexcept;
	auto operator=(connection &&other) noexcept -> connection &;
	connection(const connection &) = delete;
	auto operator=(const connection &) -> connection & = delete;
	// Closes the transport without sending an UnbindRequest (a destructor
	// cannot wait for I/O); co_await unbind() first for a clean shutdown.
	// Outstanding operations and open streams fail with not_connected.
	~connection();

	// False before connecting, after unbind() or close(), and once a
	// failure closed the connection.
	[[nodiscard]] auto is_open() const noexcept -> bool;
	// Where it is connected ("ldap://127.0.0.1:389"), for logs; empty if never
	// connected.
	[[nodiscard]] auto name() const noexcept -> std::string_view;
	// The connection's strand (see "Threading" above).
	// Precondition: constructed with a transport (not default, not moved from).
	[[nodiscard]] auto executor() const noexcept -> executor_type;
	// Requests waiting for a response: operations (searches until their
	// SearchResultDone, or until abandoned) and paged search releases until
	// their answer arrives or their deadline passes (see paged_search; an
	// abandoned request is not counted: it may never be answered). For
	// tests and diagnostics.
	[[nodiscard]] auto outstanding() const noexcept -> std::size_t;
	// True while TLS protects the open connection (ldaps://, or once
	// start_tls() has succeeded; false while it runs, its handshake
	// included). False whenever is_open() is: before connecting, after
	// unbind() or close(), and once a failure closed the connection.
	[[nodiscard]] auto is_tls() const noexcept -> bool;
	// The SASL security layer (RFC 4422 section 3.7) protecting the open
	// connection: set by a sasl_bind whose mechanism negotiated integrity
	// or confidentiality (sasl_mechanism::take_security_layer, e.g.
	// sasl_gssapi_options::security_layer or
	// sasl_ntlm_options::security_layer), from the first octet after its
	// successful BindResponse, for every later PDU both ways, until the
	// connection closes (a later bind, failed or not, leaves it in place,
	// RFC 4513 section 5.2.1.4). none otherwise, and once closed. While one
	// is in effect start_tls() fails with
	// client_errc::security_layer_in_effect, and so does a bind that
	// negotiates another.
	[[nodiscard]] auto security_layer() const noexcept -> sasl_protection;
	// The server's certificate (DER) as received in the TLS handshake (not
	// verified unless tls_options asked for it); empty unless is_tls(). A
	// view into the connection's state, valid until the connection is
	// destroyed or assigned to, or start_tls() runs again.
	[[nodiscard]] auto peer_certificate() const noexcept -> std::span<const std::byte>;
	// The TLS channel bindings (RFC 5056, channel_binding.hpp:
	// tls-server-end-point, tls-exporter) of the connection; empty unless
	// is_tls(). Views valid as long as peer_certificate()'s. sasl_bind
	// passes them to the mechanism (sasl_bind_context), but without
	// tls-exporter once a bind used it (RFC 9266 section 4.1: one
	// authentication per TLS connection; channel_binding.hpp). This
	// accessor keeps reporting it: it describes the connection.
	[[nodiscard]] auto channel_bindings() const noexcept -> ldap::channel_bindings;
	// The bind exchanges begun on this connection (simple or SASL, each
	// counted once when its first BindRequest is about to be sent, whatever
	// its outcome: a failed bind leaves the connection anonymous, which
	// changes its identity too). 0 for a connection never bound, or
	// default-constructed. ldap::client compares it to tell whether a lease
	// re-bound its connection.
	[[nodiscard]] auto bind_count() const noexcept -> std::uint64_t;

	// Simple bind (RFC 4511 section 4.2, RFC 4513 section 5.1). An empty name
	// and password is an anonymous bind. A name with an empty password would
	// be an "unauthenticated bind", which servers answer with success without
	// checking anything, so it is refused before anything is sent
	// (client_errc::unauthenticated_bind). A server error (e.g.
	// errc::invalid_credentials) comes back as an error; the connection stays
	// usable (anonymous) and may bind again. Other operations started while
	// the bind is outstanding are held until it ends (RFC 4511 section
	// 4.2.1), and a second bind waits for this one. Cancelled or timed out,
	// the bind closes the connection (a bind cannot be abandoned).
	auto simple_bind(dn name, std::string password) -> boost::capy::task<result<void>>;

	// SASL bind (RFC 4513 section 5.2): sends one BindRequest per step of
	// `mechanism` while the server answers saslBindInProgress (at most 32
	// steps, then the bind fails with unexpected_response), after
	// mechanism.prepare() with the URL's host, whether TLS protects the
	// connection and its channel bindings (sasl_bind_context). `name` is
	// usually empty (the mechanism carries the identity). A server error
	// (e.g. errc::inappropriate_authentication) or a mechanism error fails
	// the bind; the connection stays usable (anonymous). A mechanism error
	// (or the step limit) once the server answered saslBindInProgress first
	// aborts the exchange with an anonymous simple bind (RFC 4511 section
	// 4.2.1), before any held request is sent. A BindResponse to it ends
	// the exchange, even a refusal (a server that disallows anonymous
	// binds), and the connection stays usable (anonymous, and with no SASL
	// security layer, even one the mechanism negotiated). The exception is
	// saslBindInProgress, which cannot answer a simple bind (RFC 4511
	// section 4.2.2): then the connection is closed with
	// unexpected_response, as it is for an answer that is not a
	// BindResponse. Without an answer (timeout, cancellation) the
	// connection is closed, as for any bind. Except: when the
	// server reports success and the mechanism's complete() refuses it
	// (e.g. SCRAM-SHA-256 with a wrong server signature), the server
	// considers the connection bound, so it is closed. The same rules as
	// simple_bind apply otherwise. `mechanism` must outlive the task.
	// A step the mechanism offloads (sasl_mechanism::offload_start,
	// offload_step: GSSAPI's calls to the KDC, SCRAM's costly PBKDF2) runs
	// on a thread of its own
	// while the task waits, within operation_timeout and the stop token.
	// Giving up on it fails the bind with capy::error::timeout or canceled
	// and leaves the step running on its thread (it is not interrupted);
	// before the first BindRequest nothing was sent, so the connection
	// stays usable; later the exchange is aborted as for a mechanism error
	// (a cancellation cancels that abort too, which closes the connection).
	// The io_context counts the running step as work: run() returns only
	// once it is over, and destroying the io_context waits for its thread
	// to end (as long as the step takes: krb5's own timeouts). The thread
	// posts to the io_context, which must keep its scheduler lock
	// (locking_mode::safe, Corosio's default, or unsafe_io): under unsafe
	// an offloaded step fails with std::errc::operation_not_supported
	// before it runs (at the first step, nothing sent).
	auto sasl_bind(sasl_mechanism &mechanism, dn name = {}) -> boost::capy::task<result<void>>;

	// Runs a search to its end and returns a search_result (operations.hpp):
	// the entries in the order received, allocated from `mr` (see "Memory"
	// above), the URIs of the search result references (continuation
	// references, not followed: chase_search in referral_chase.hpp follows
	// them), and the SearchResultDone's result code, matched DN, diagnostic
	// message and controls. A SearchResultDone with sizeLimitExceeded,
	// timeLimitExceeded or adminLimitExceeded returns a search_result too,
	// with the entries received before it (is_success() false); any other
	// result code than success fails the call.
	auto search(search_params request, std::pmr::memory_resource *mr = std::pmr::get_default_resource())
	  -> boost::capy::task<result<search_result>>;

	// Sends the search and returns a stream that yields its entries one at a
	// time, each decoded into `mr`. Other operations may run while the
	// stream is open. Destroyed before its end, the stream abandons the
	// search.
	auto search_stream(search_params request, std::pmr::memory_resource *mr = std::pmr::get_default_resource())
	  -> boost::capy::task<result<ldap::search_stream>>;

	// A search in pages of `page_size` entries (Simple Paged Results, RFC
	// 2696): when a page ends, the next page is requested with the server's
	// cookie, until the cookie is empty. A paged control already in
	// `request.controls` (typed, or raw with paged_results_oid) is
	// replaced. A server that ignores the (non-critical) control returns
	// everything as one page, which works the same. Each page is one search on the wire, with its own message id
	// and its own `request.timeout`. Destroyed early, the paged_search
	// abandons the current page and releases the server's paging state
	// (see paged_search). Several may run at once on one connection (RFC
	// 2696 section 3), but servers may limit that: OpenLDAP keeps one paged
	// search per connection and refuses the next page of any but the one
	// whose page it answered last (unwilling_to_perform or protocol_error,
	// depending on the cookies' entry order), and with server_side_sort (its
	// sssvlv overlay) it answers any next page with the latest sorted paged
	// search's entries instead, which the client cannot detect. Give each
	// concurrent paged search its own connection there.
	auto search_paged(search_params request,
	  std::int32_t page_size,
	  std::pmr::memory_resource *mr = std::pmr::get_default_resource())
	  -> boost::capy::task<result<ldap::paged_search>>;

	// The other operations. Result codes: success returns the value; any
	// other code is an error (`ldap_result::to_error`, with the operation as
	// context), referral included (errc::referral, the URIs in
	// error::referrals; referrals are not chased, see url::parse_list and
	// chase_compare in referral_chase.hpp).
	// compare() maps compareTrue / compareFalse to true / false.
	auto add(add_params request) -> boost::capy::task<result<response>>;
	auto modify(modify_params request) -> boost::capy::task<result<response>>;
	auto del(del_params request) -> boost::capy::task<result<response>>;
	auto modify_dn(modify_dn_params request) -> boost::capy::task<result<response>>;
	auto compare(compare_params request) -> boost::capy::task<result<bool>>;
	// Any extended operation but StartTLS: its name (start_tls_oid) fails
	// with encode_error before anything is sent; use start_tls(). Who am I?
	// and Password Modify are free functions (extended_operations.hpp).
	auto extended(extended_params request) -> boost::capy::task<result<extended_result>>;

	// LDAP transactions (RFC 5805; transaction.hpp has the helper and the
	// rules). start_transaction() sends a Start Transaction request (section
	// 2.1) and returns the transaction identifier; `controls` may carry
	// proxied_authorization, to run the whole transaction as another
	// identity (section 4.4). Updates carrying a transaction_specification
	// control with that identifier are then part of the transaction, and
	// end_transaction() settles it (section 2.3): `commit` true applies
	// every update or none, false aborts. A refusal is the server's result
	// code with the context "start transaction" / "end transaction", the
	// latter followed by ": update message N" when the server names the
	// update at fault (txnEndRes.messageID; response::message_id is the id
	// of each update). On success end_transaction() returns the updates'
	// response controls (end_transaction_result). An answer that does not
	// follow section 2 (a responseName, no identifier, a malformed
	// txnEndRes) fails with decode_error. begin_transaction() is
	// start_transaction() wrapped in an ldap::transaction.
	auto start_transaction(extended_controls controls = {}) -> boost::capy::task<result<std::string>>;
	auto end_transaction(std::string identifier, bool commit = true)
	  -> boost::capy::task<result<end_transaction_result>>;
	auto begin_transaction(extended_controls controls = {}) -> boost::capy::task<result<transaction>>;

	// StartTLS (RFC 4511 section 4.14): upgrades a plain ldap:// connection to
	// TLS in place, with the same verification rules as ldaps:// (`options`;
	// the name checked is options.server_name, else the URL's host). Fails at
	// once with invalid_argument on a connection that is not plain TCP
	// (ldaps://, ldapi://, a custom stream), and with operation_in_progress
	// while any operation (or a bind exchange) is outstanding. The answers
	// still due to destroyed paged_searches' releases are then waited for
	// (RFC 4513 section 3.1.1: no response outstanding), until they arrive or
	// their deadline passes (see paged_search); the checks are made again
	// after the wait, so an operation started meanwhile and still outstanding
	// refuses it. A timeout or cancellation during that wait sends nothing and
	// leaves the connection usable. Once the request is sent, starting another
	// operation, or another start_tls, fails with operation_in_progress. If
	// the server refuses (a result code other than success), that error is
	// returned and the connection stays usable, unprotected. Bytes received
	// after the StartTLS response and before the handshake are refused
	// (decode_error: a plaintext injection attempt), and a failed handshake
	// closes the connection, as does a std::bad_alloc from the handshake or
	// its setup (then rethrown), or a cancellation or timeout (StartTLS
	// cannot be abandoned, RFC 4511 section 4.11). So a release's answer that
	// comes after its deadline is dropped if it comes before the StartTLS
	// response; after it, it closes the connection (refused as such bytes, or
	// failing the handshake). `timeout` bounds the wait for due answers, then
	// the exchange, then the handshake, each on its own, so start_tls may take
	// up to three times `timeout`. nullopt:
	// connection_options::operation_timeout for the wait and the exchange, no
	// limit for the handshake. An unbind() once the StartTLS request is sent
	// closes the connection (nothing may be sent until the handshake), and
	// start_tls then fails with not_connected, during the handshake too.
	auto start_tls(net::tls_options options = {}, std::optional<std::chrono::milliseconds> timeout = std::nullopt)
	  -> boost::capy::task<result<void>>;

	// Sends an UnbindRequest, waits until it is written, and closes the
	// connection (RFC 4511 section 4.3: there is no response). During a bind
	// or a start_tls() it only closes: nothing may be sent while a BindRequest
	// or StartTLS is in progress (the start_tls() fails). On TLS it
	// then ends the TLS session gracefully: close_notify, then the server's,
	// within connection_options::tls_shutdown_timeout (best effort: the
	// result does not depend on it). Outstanding
	// operations and open streams fail with not_connected (an unbind
	// abandons them on the server too). Nothing is sent after the
	// UnbindRequest: an operation or start_tls() started while it is being
	// written fails with not_sent, an unbind() with not_connected. The
	// connection is closed even if the write fails or the task is cancelled.
	auto unbind() -> boost::capy::task<result<void>>;

	// Closes the transport at once, without an UnbindRequest. Outstanding
	// operations complete with not_connected (not_sent for those whose
	// request was not written yet, see "Sent or not" above). Idempotent.
	void close() noexcept;

	class core;// defined in src/connection/core.hpp

  private:
	friend class ldap::search_stream;
	friend class ldap::paged_search;
	friend void detail::set_next_message_id(connection &, std::int32_t) noexcept;
	friend void detail::set_close_hook(connection &, std::move_only_function<void() noexcept>) noexcept;
	friend auto detail::accepts_requests(const connection &) noexcept -> bool;

	core *core_ = nullptr;// reference counted; allocated from the resource it records
};

// Opens a connection to `u` (net::connect: resolve, TCP, TLS for ldaps://,
// Unix socket for ldapi://) with the timeout and TLS settings of `options`.
// Nothing is sent: bind next, or search anonymously. The same rules as
// net::connect apply: `ioc` must outlive the connection and the task must
// run on its executor. Arguments are taken by value.
auto connect(boost::corosio::io_context &ioc,
  url u,
  connection_options options = {},
  std::pmr::memory_resource *mr = std::pmr::get_default_resource()) -> boost::capy::task<result<connection>>;

// As above, to the URL `text` (RFC 4516, url::parse). A bad URL fails with
// url::parse's error (client_errc::invalid_url) and nothing is connected.
// `text` is parsed here, before the task starts, so it need not outlive the
// call.
auto connect(boost::corosio::io_context &ioc,
  std::string_view text,
  connection_options options = {},
  std::pmr::memory_resource *mr = std::pmr::get_default_resource()) -> boost::capy::task<result<connection>>;

}// namespace jhetz::ldap
