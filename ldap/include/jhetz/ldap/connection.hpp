// An LDAP connection: bind, search and unbind over a net::transport, one
// operation at a time (DESIGN.md sections 3, 5 and 7). Part of
// jhetz::ldap_net.
//
//   corosio::io_context ioc;
//   auto u = ldap::url::parse("ldaps://ldap.example.org");
//   ldap::result<ldap::connection> c = co_await ldap::connect(ioc, *u, {.timeout = 5s});
//   if (auto b = co_await c->simple_bind(ldap::dn{"cn=admin,dc=example,dc=org"}, password); !b) ...
//   auto people = co_await c->search({
//       .base       = ldap::dn{"ou=people,dc=example,dc=org"},
//       .filter     = ldap::filters::attr("uid") == user,
//       .attributes = {"cn", "mail"},
//   });                                   // result<std::pmr::vector<entry>>
//   co_await c->unbind();
//
// Sequential: one request is in flight at a time, and a search_stream counts
// as in flight until it has read the SearchResultDone or is destroyed.
// Starting another operation meanwhile fails with
// client_errc::operation_in_progress (nothing is queued). Multiplexing,
// cancellation and abandon are step 5b.
//
// What the server sends is decoded with origin::server, always: a server
// cannot make the client decode request operations such as filters. Each
// response must carry the id of the request in flight and an operation that
// answers it; anything else (another id, a bind response to a search, a
// request operation) is client_errc::unexpected_response. IntermediateResponse
// messages with the right id are skipped. Unsolicited notifications (id 0,
// RFC 4511 section 4.4): a Notice of Disconnection fails the operation with
// the server's result code (errc::unavailable if it sent success) and closes
// the connection; other extended responses with id 0 are ignored, and any
// other operation with id 0 is unexpected_response.
//
// Errors: a server result other than success is `ldap_result::to_error` (code
// in the ldap.result category, diagnostic, matched DN and referrals, as text)
// with the operation as context, e.g. "search ou=people,dc=example,dc=org".
// Such an error leaves the connection usable. So does a request that fails to
// encode (nothing is sent). A transport error, a malformed or oversized PDU,
// an unexpected response or a Notice of Disconnection closes the connection:
// every later operation fails with client_errc::not_connected, naming the
// original error. The same happens when an operation's task is destroyed
// before it finished (or its read is cancelled): the response it was waiting
// for would otherwise be read by the next operation.
//
// Memory: entries returned by search() and search_stream are decoded into
// the memory resource given to that call (default: the default resource) and
// moved into the result, with no copy; with a caller's arena the entries
// must not outlive it (DESIGN.md section 8). Responses the connection
// discards (those of a search_stream destroyed early) are decoded into a
// per-connection monotonic arena that is released after each message. The
// connection's own state, read buffer and encode buffer live on the resource
// given to connect() or the constructor.
//
// Threading (Capy / Corosio rules): all operations of a connection, and of
// its search_streams, must run on the executor of the io_context it was
// created on, never concurrently. A connection may be moved; a search_stream
// keeps working across the move because the state stays where it is.
// Destroying a connection while one of its tasks is suspended is undefined:
// let the task finish (close() makes a pending read finish at once).
#pragma once

#include "jhetz/ldap/ber.hpp"
#include "jhetz/ldap/dn.hpp"
#include "jhetz/ldap/entry.hpp"
#include "jhetz/ldap/error.hpp"
#include "jhetz/ldap/filter.hpp"
#include "jhetz/ldap/message.hpp"
#include "jhetz/ldap/net/connect.hpp"
#include "jhetz/ldap/net/transport.hpp"
#include "jhetz/ldap/url.hpp"

#include <boost/capy/task.hpp>
#include <boost/corosio/io_context.hpp>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory_resource>
#include <optional>
#include <string>
#include <vector>

namespace jhetz::ldap {

struct connection_options
{
	// Budget for the whole connect (resolve, TCP, TLS handshake); see
	// net::connect_options. nullopt: no limit.
	std::optional<std::chrono::milliseconds> timeout{ std::chrono::seconds(30) };
	net::tls_options tls{};
	bool tcp_no_delay = true;
	// Largest PDU accepted from the server, checked from its header before
	// the body is read (client_errc::message_too_large, which closes the
	// connection). 16 MiB by default: one entry of a large group or with
	// photos and certificates can legitimately take several MiB. Decoding
	// can take about 12-18x the PDU size in memory for pathological entries
	// (many empty values); lower this if the server is not trusted.
	std::size_t max_message_size = ber::default_max_message_size;
};

// A search, as a plain aggregate for designated initializers (DESIGN.md
// section 3). Values are validated when the request is encoded: a negative
// size_limit or time_limit, or a time_limit above max_int seconds, fails with
// encode_error, an empty filter with invalid_filter, before anything is sent.
struct search_params
{
	dn base{};// the empty DN is the root DSE
	search_scope scope = search_scope::whole_subtree;
	ldap::filter filter = filters::attr("objectClass").present();
	// Attribute selectors as sent: descriptions, "*" (all user attributes),
	// "+" (operational, RFC 3673), "1.1" (none). Empty: all user attributes.
	string_list attributes{};
	deref_aliases deref = deref_aliases::never;
	std::int32_t size_limit = 0;// entries; 0 = no client-requested limit
	std::chrono::seconds time_limit{ 0 };// 0 = no client-requested limit
	bool types_only = false;
	// Request controls, sent as given (typed controls: step 6).
	std::pmr::vector<control> controls{};
};

class search_stream;

class connection
{
  public:
	// Not connected: every operation fails with client_errc::not_connected.
	connection() noexcept = default;
	// Runs LDAP over an open transport (for example one from net::connect(),
	// or transport::wrap() of a test stream). Of `options` only
	// max_message_size applies here. The connection's state is allocated
	// from `mr`.
	explicit connection(net::transport t,
	  const connection_options &options = {},
	  std::pmr::memory_resource *mr = std::pmr::get_default_resource());
	connection(connection &&other) noexcept;
	connection &operator=(connection &&other) noexcept;
	connection(const connection &) = delete;
	connection &operator=(const connection &) = delete;
	// Closes the transport without sending an UnbindRequest (a destructor
	// cannot wait for I/O); co_await unbind() first for a clean shutdown.
	~connection();

	// False before connecting, after unbind() or close(), and once a
	// failure closed the connection.
	bool is_open() const noexcept;
	// Where it is connected ("ldap://127.0.0.1:389"), for logs; empty if never
	// connected.
	std::string_view name() const noexcept;

	// Simple bind (RFC 4511 section 4.2, RFC 4513 section 5.1). An empty name
	// and password is an anonymous bind. A name with an empty password would
	// be an "unauthenticated bind", which servers answer with success without
	// checking anything, so it is refused before anything is sent
	// (client_errc::unauthenticated_bind). A server error (e.g.
	// errc::invalid_credentials) comes back as an error; the connection stays
	// usable (anonymous) and may bind again.
	boost::capy::task<result<void>> simple_bind(dn name, std::string password);

	// Runs a search to its end and returns the entries in the order received,
	// allocated from `mr` (see "Memory" above). Search result references
	// (continuation references) are not returned here: use search_stream()
	// to see them (referral handling is step 6). A result code other than
	// success fails the whole call, size_limit_exceeded included; the
	// entries received before it are lost (search_stream() keeps them).
	boost::capy::task<result<std::pmr::vector<entry>>> search(search_params request,
	  std::pmr::memory_resource *mr = std::pmr::get_default_resource());

	// Sends the search and returns a stream that yields its entries one at a
	// time, each decoded into `mr`. The connection is busy until the stream
	// has returned the end (or an error), or is destroyed; destroyed early,
	// the next operation first reads and discards the rest of the search
	// (no Abandon yet: step 5b).
	boost::capy::task<result<ldap::search_stream>> search_stream(search_params request,
	  std::pmr::memory_resource *mr = std::pmr::get_default_resource());

	// Sends an UnbindRequest and closes the connection (RFC 4511 section
	// 4.3: there is no response). Allowed while a search_stream is open (the
	// stream then fails with not_connected), not while another operation is
	// suspended. The connection is closed even if the write fails.
	boost::capy::task<result<void>> unbind();

	// Closes the transport at once, without an UnbindRequest. A suspended
	// operation completes with an error. Idempotent.
	void close() noexcept;

	struct impl;// defined in connection.cpp

  private:
	friend class ldap::search_stream;

	impl *impl_ = nullptr;// allocated from the resource it records
};

// The entries of one search, read one at a time:
//
//   auto s = co_await conn.search_stream({.base = base, .filter = f});
//   if (!s) return s.error();
//   while (true) {
//       ldap::result<std::optional<ldap::entry>> e = co_await s->next();
//       if (!e) return e.error();   // transport, protocol or server error
//       if (!*e) break;             // SearchResultDone with success
//       use(**e);
//   }
//
// Move-only. A default-constructed stream, or one whose connection was
// closed or destroyed, fails with client_errc::not_connected. The stream
// must not be destroyed or moved while its next() is suspended.
class search_stream
{
  public:
	search_stream() noexcept = default;
	search_stream(search_stream &&other) noexcept;
	search_stream &operator=(search_stream &&other) noexcept;
	search_stream(const search_stream &) = delete;
	search_stream &operator=(const search_stream &) = delete;
	// Unfinished: the connection discards the rest of the search before its
	// next operation.
	~search_stream();

	// The next entry, nullopt at the end (SearchResultDone with success), or
	// an error: the server's result code (the connection stays usable) or a
	// connection failure. After the end or an error, next() returns the same
	// again without I/O.
	boost::capy::task<result<std::optional<entry>>> next();

	// True once the SearchResultDone (or an error) was read.
	bool done() const noexcept { return finished_; }
	// URIs of the SearchResultReference messages received so far, in order,
	// as sent (one string per URI; parse with url::parse).
	const string_list &references() const noexcept { return references_; }
	// Controls of the SearchResultDone (e.g. paged results), once done().
	const std::pmr::vector<control> &controls() const noexcept { return controls_; }

  private:
	friend class connection;
	friend struct connection::impl;

	search_stream(connection::impl *conn, std::int32_t id, std::pmr::string context, std::pmr::memory_resource *mr);
	void detach() noexcept;

	connection::impl *conn_ = nullptr;
	std::int32_t id_ = 0;
	std::pmr::memory_resource *mr_ = std::pmr::get_default_resource();
	bool finished_ = false;
	std::optional<error> error_{};
	std::pmr::string context_{};// "search <base>"
	string_list references_{};
	std::pmr::vector<control> controls_{};
};

// Opens a connection to `u` (net::connect: resolve, TCP, TLS for ldaps://,
// Unix socket for ldapi://) with the timeout and TLS settings of `options`.
// Nothing is sent: bind next, or search anonymously. The same rules as
// net::connect apply: `ioc` must outlive the connection and the task must
// run on its executor. Arguments are taken by value.
boost::capy::task<result<connection>> connect(boost::corosio::io_context &ioc,
  url u,
  connection_options options = {},
  std::pmr::memory_resource *mr = std::pmr::get_default_resource());

}// namespace jhetz::ldap
