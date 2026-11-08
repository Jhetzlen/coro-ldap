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
// Multiplexing: concurrent operations (from any threads) are sent at once,
// each with its own message id, and responses are matched by id. One writer
// sends PDUs in order; one reader routes responses and runs only while an
// operation waits (an idle connection lets io_context::run() return). Search
// entries are queued per search, unbounded, until its stream takes them.
//
// Cancellation and timeouts: every operation honours its task's stop token
// and a timeout (search_params::timeout, else
// connection_options::operation_timeout). Either fails it with
// capy::error::canceled or capy::error::timeout and sends an AbandonRequest
// (RFC 4511 section 4.11); late responses are dropped and the connection
// stays usable. A search_stream destroyed early abandons its search too.
// Abandon is best effort: a cancelled update may still have been applied.
// Giving up on a bind or StartTLS closes the connection instead. An operation
// whose stop token is set before it starts is not sent and fails with
// canceled. unbind() is sent regardless. cancel.hpp has raceable() and
// with_stop() for racing an operation or cancelling it from a stop_source.
//
// Binds (RFC 4511 section 4.2.1): requests started during a bind exchange
// (every step of a SASL bind) are held and sent in order once it ends; one
// cancelled while held is never sent. Binds are serialized. Through a shared
// ldap::lease (client.hpp), a bind, start_tls(), unbind() or close() affects
// every lease on the connection: use acquire_exclusive() for those.
//
// Server messages are decoded with origin::server. A response must carry the
// id of an outstanding (or recently abandoned) request and an operation that
// answers it, else client_errc::unexpected_response. IntermediateResponses
// (section 4.13) are skipped unless requested
// (search_params / extended_params::intermediate_responses), then returned
// by search_stream::next_item() or in extended_result::intermediates. A
// Notice of Disconnection (section 4.4) fails every outstanding operation
// with its result code (errc::unavailable for success) and closes the
// connection; other unsolicited responses are ignored.
//
// Errors: a non-success result is `ldap_result::to_error` with the operation
// as context (e.g. "search ou=people,dc=example,dc=org") and fails that
// operation only, as do an encoding failure (nothing sent), a cancellation
// and a timeout. A transport error, a malformed or oversized PDU, an
// unexpected response or a Notice of Disconnection fails every outstanding
// operation once and closes the connection; later operations fail with
// client_errc::not_sent, naming the original error.
//
// Sent or not: an operation whose request the writer had not taken when the
// connection closed (refused, queued, or held behind a bind) fails with
// client_errc::not_sent, its context naming the failure: the server never
// saw it, so even an update may be retried elsewhere. Once taken, the
// failure's own code is reported (the server may have seen it). not_sent
// matches cond::connection_lost. Exceptions: allocation failure stays
// std::errc::not_enough_memory, operations abandoned by unbind() fail with
// not_connected, and a default-constructed or moved-from connection fails
// with not_connected.
//
// Memory: search() and search_stream entries are decoded straight into the
// memory resource given to that call (default: the default resource) and
// must not outlive it. The connection's own state lives on the resource
// given to connect() or the constructor.
//
// Threading: a connection may be used from any number of threads, with an
// io_context run by one thread or several. Everything runs on a capy::strand
// of the io_context (executor()); operations hop onto it and resume the
// awaiting task on its own executor. The accessors (is_open(),
// outstanding(), is_tls(), security_layer(), bind_count(), ...) are safe on
// any thread. A search_stream or paged_search allows one next() at a time
// (another fails with client_errc::operation_in_progress). The objects
// themselves (connection, stream, transaction) allow one thread at a time in
// their non-const members. Entries are allocated on the strand and may be
// freed on another thread, so their resource must allow that (the default
// resource, std::pmr::synchronized_pool_resource, or an arena that frees
// nothing until the search ends). Corosio's locking_mode::unsafe_io and
// unsafe require a single thread.
// Destructors and close() called off the strand post their work, which runs
// when the io_context next runs (is_open(), outstanding(), is_tls() and
// security_layer() reflect close() at once); the entries' memory resource
// must outlive that run. An io_context destroyed before running it leaks
// that work: after run_one() or a stop, restart() and poll() first. They run
// at once on the strand, or once the io_context is stopped from outside its
// run() (join its threads first before destroying a connection or stream on
// another thread). Streams, outstanding operations and the reader may
// outlive the connection object (destroying it closes the connection; they
// fail with not_connected). Destroying a task suspended in an operation is
// safe: the operation is abandoned.
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
	// and password is an anonymous bind; a name with an empty password is
	// refused before sending (client_errc::unauthenticated_bind). A server
	// error (e.g. errc::invalid_credentials) leaves the connection usable
	// (anonymous). Operations started meanwhile are held until it ends, and a
	// second bind waits. A cancellation or timeout closes the connection.
	auto simple_bind(dn name, std::string password) -> boost::capy::task<result<void>>;

	// SASL bind (RFC 4513 section 5.2): calls mechanism.prepare() with
	// sasl_bind_context (the URL's host, TLS, channel bindings), then sends one
	// BindRequest per step while the server answers saslBindInProgress (at
	// most 32 steps, then unexpected_response). `name` is usually empty. A
	// server or mechanism error fails the bind and leaves the connection usable
	// (anonymous). A mechanism error (or the step limit) after the server
	// answered saslBindInProgress aborts the exchange with an anonymous simple
	// bind (RFC 4511 section 4.2.1) before any held request is sent; any
	// BindResponse to it but saslBindInProgress leaves the connection usable,
	// anonymous and without a security layer, otherwise it is closed with
	// unexpected_response. A timeout or cancellation closes the connection, and
	// so does a server success that the mechanism's complete() refuses.
	// Otherwise as simple_bind. `mechanism` must outlive the task.
	// Offloaded steps (sasl_mechanism::offload_start, offload_step) run on a
	// thread of their own within operation_timeout and the stop token. Giving
	// up fails the bind with timeout or canceled and leaves the step running:
	// before the first BindRequest the connection stays usable, later the
	// exchange is aborted as above. The io_context counts a running step as
	// work (run() and its destructor wait for it). The io_context must keep its
	// scheduler lock (locking_mode::safe or unsafe_io): under unsafe an
	// offloaded step fails with std::errc::operation_not_supported before it
	// runs.
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
	// TLS in place, verified as ldaps:// would be (`options`; the name checked
	// is options.server_name, else the URL's host). Fails at once with
	// invalid_argument unless the connection is plain TCP, and with
	// operation_in_progress while an operation or bind is outstanding. It
	// first waits for the answers due to destroyed paged_searches' releases
	// (until they arrive or their deadline passes), then checks again; a
	// timeout or cancellation during that wait sends nothing. Once the request
	// is sent, other operations fail with operation_in_progress. A server
	// refusal is returned and the connection stays usable, unprotected. Bytes
	// received between the response and the handshake fail with decode_error
	// and close the connection, as do a failed handshake, std::bad_alloc
	// (rethrown), a cancellation and a timeout. `timeout` bounds the wait,
	// the exchange and the handshake each (up to three times `timeout` in
	// all); nullopt: connection_options::operation_timeout for the first two,
	// none for the handshake. An unbind() after the request is sent closes the
	// connection and start_tls fails with not_connected.
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
