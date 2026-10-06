// An LDAP connection: bind, search and unbind over a net::transport, with
// any number of operations outstanding at once (DESIGN.md sections 3, 5 and
// 7). Part of jhetz::ldap_net.
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
// Multiplexing (step 5b): operations started concurrently (several tasks on
// the connection's executor, e.g. with capy::when_all) are all sent at once,
// each with its own message id, and their responses are matched by id. One
// writer coroutine sends the PDUs in order, never interleaved; one reader
// coroutine routes each response to the operation waiting for it, and runs
// only while some operation waits (an idle connection has no pending read,
// so io_context::run() can return). Search entries are queued per search
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
// Abandon is best effort: the server may have answered already.
//
// What the server sends is decoded with origin::server, always. Each
// response must carry the id of an outstanding (or recently abandoned)
// request and an operation that answers it; anything else is
// client_errc::unexpected_response. IntermediateResponses are skipped.
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
// the connection: every later operation fails with
// client_errc::not_connected, naming the original error.
//
// Memory: entries returned by search() and search_stream are decoded
// straight into the memory resource given to that call (default: the
// default resource), with no copy: the reader looks at a PDU's message id
// before decoding it. With a caller's arena the entries must not outlive it
// (DESIGN.md section 8). The connection's own state, buffers and queues live
// on the resource given to connect() or the constructor.
//
// Threading (Capy / Corosio rules): a connection belongs to the executor of
// the io_context it was created with. All its operations, and those of its
// search_streams, must run on that executor (one thread); from another
// thread, start them there, e.g. capy::run_async(conn.executor())(task).
// Operations may be outstanding concurrently, but each search_stream has at
// most one next() at a time. Connections and streams are cheap to move;
// the shared state is reference counted, so a stream, an outstanding
// operation or the internal reader may outlive the connection object
// (destroying the connection closes it; they then fail with not_connected).
// Operations never wait on I/O themselves (the writer and reader do), only
// for their responses, so destroying a task suspended in one of them is
// safe: the operation is abandoned. Stop tokens are the normal way to cancel.
#pragma once

#include "jhetz/ldap/ber.hpp"
#include "jhetz/ldap/controls.hpp"
#include "jhetz/ldap/dn.hpp"
#include "jhetz/ldap/entry.hpp"
#include "jhetz/ldap/error.hpp"
#include "jhetz/ldap/filter.hpp"
#include "jhetz/ldap/mapping.hpp"
#include "jhetz/ldap/message.hpp"
#include "jhetz/ldap/net/connect.hpp"
#include "jhetz/ldap/net/transport.hpp"
#include "jhetz/ldap/sasl.hpp"
#include "jhetz/ldap/schema.hpp"
#include "jhetz/ldap/url.hpp"

#include <boost/capy/task.hpp>
#include <boost/corosio/io_context.hpp>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <memory_resource>
#include <optional>
#include <string>
#include <string_view>
#include <typeindex>
#include <vector>

namespace jhetz::ldap {

// When typed operations check their struct against the server's schema
// (DESIGN.md section 6).
enum class schema_check {
	off,
	// The first search_as / modify<T> / add(dn, T) for each T loads the
	// subschema (once per connection) and runs validate<T>; errors in the
	// report fail the operation with client_errc::schema_mismatch (the
	// report in the context). The result is cached per connection and T.
	on_first_use,
};

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
	// Default limit for each operation, from sending its request to its
	// final response (for a search: to the SearchResultDone, across every
	// next()). On expiry the operation fails with capy::error::timeout and
	// is abandoned. nullopt: no limit (cancel with a stop token instead).
	std::optional<std::chrono::milliseconds> operation_timeout{};
	// ldap::connect() only: upgrade an ldap:// connection with StartTLS
	// right after connecting (using `tls` and `timeout`), and fail if that
	// does not work. Not allowed with ldaps:// or ldapi:// (invalid_url).
	bool start_tls = false;
	ldap::schema_check schema_check = ldap::schema_check::off;
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
	std::chrono::seconds time_limit{ 0 };// 0 = no client-requested limit (sent to the server)
	bool types_only = false;
	// Request controls: typed (ldap::paged, ldap::manage_dsa_it, ...) or a
	// raw ldap::control (controls.hpp).
	request_controls controls{};
	// Client-side limit for the whole search (see
	// connection_options::operation_timeout, which applies if this is
	// nullopt). Unlike time_limit it is enforced by the client.
	std::optional<std::chrono::milliseconds> timeout{};
};

// The other operations (step 6), as plain aggregates like search_params.
// `controls` and `timeout` mean the same everywhere: request controls, and
// a client-side limit overriding connection_options::operation_timeout.

// AddRequest (RFC 4511 section 4.7). Every attribute needs at least one
// value (encode_error otherwise, before anything is sent).
struct add_params
{
	dn entry{};
	std::pmr::vector<partial_attribute> attributes{};// {"cn", {"Jane Doe"}}, ...
	request_controls controls{};
	std::optional<std::chrono::milliseconds> timeout{};
};

// ModifyRequest (RFC 4511 section 4.6): changes applied in order, atomically.
// Build them with ldap::mod::add / remove / replace / increment.
struct modify_params
{
	dn object{};
	std::pmr::vector<modify_change> changes{};
	request_controls controls{};
	std::optional<std::chrono::milliseconds> timeout{};
};

namespace mod {
	// Adds values (at least one).
	modify_change add(std::string_view type, std::initializer_list<std::string_view> values);
	// Deletes the given values, or the whole attribute if none are given.
	modify_change remove(std::string_view type, std::initializer_list<std::string_view> values = {});
	// Replaces all values (none: deletes the attribute if present).
	modify_change replace(std::string_view type, std::initializer_list<std::string_view> values);
	// Adds `delta` to an integer attribute (RFC 4525 Modify-Increment).
	modify_change increment(std::string_view type, std::string_view delta = "1");
}// namespace mod

// DelRequest (RFC 4511 section 4.8): deletes a leaf entry.
struct del_params
{
	dn entry{};
	request_controls controls{};
	std::optional<std::chrono::milliseconds> timeout{};
};

// ModifyDNRequest (RFC 4511 section 4.9): renames an entry (new_rdn) and/or
// moves it under new_superior. To move without renaming, pass its current
// RDN (entry.rdns().front()).
struct modify_dn_params
{
	dn entry{};
	rdn new_rdn{};
	bool delete_old_rdn = true;// drop the old RDN's values from the entry
	std::optional<dn> new_superior{};
	request_controls controls{};
	std::optional<std::chrono::milliseconds> timeout{};
};

// CompareRequest (RFC 4511 section 4.10).
struct compare_params
{
	dn entry{};
	std::string attribute{};
	std::string value{};
	request_controls controls{};
	std::optional<std::chrono::milliseconds> timeout{};
};

// ExtendedRequest (RFC 4511 section 4.12).
struct extended_params
{
	std::string name{};// requestName, an OID
	std::optional<std::string> value{};// requestValue, as encoded for that operation
	request_controls controls{};
	std::optional<std::chrono::milliseconds> timeout{};
};

// What a successful operation returns besides success: the controls of the
// server's response (e.g. a post-read entry, RFC 4527).
struct response
{
	std::pmr::vector<control> controls{};
};

struct extended_result
{
	std::optional<std::pmr::string> name{};// responseName
	std::optional<std::pmr::string> value{};// responseValue
	std::pmr::vector<control> controls{};
};

// RFC 4532 "Who am I?" extended operation.
inline constexpr std::string_view who_am_i_oid = "1.3.6.1.4.1.4203.1.11.3";

class search_stream;
class paged_search;

class connection
{
  public:
	using executor_type = boost::corosio::io_context::executor_type;

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
	connection &operator=(connection &&other) noexcept;
	connection(const connection &) = delete;
	connection &operator=(const connection &) = delete;
	// Closes the transport without sending an UnbindRequest (a destructor
	// cannot wait for I/O); co_await unbind() first for a clean shutdown.
	// Outstanding operations and open streams fail with not_connected.
	~connection();

	// False before connecting, after unbind() or close(), and once a
	// failure closed the connection.
	bool is_open() const noexcept;
	// Where it is connected ("ldap://127.0.0.1:389"), for logs; empty if never
	// connected.
	std::string_view name() const noexcept;
	// The executor every operation of this connection must run on.
	// Precondition: constructed with a transport (not default, not moved from).
	executor_type executor() const noexcept;
	// Operations waiting for a response (searches until their
	// SearchResultDone, or until abandoned). For tests and diagnostics.
	std::size_t outstanding() const noexcept;
	// True once TLS protects the connection (ldaps://, or after start_tls()).
	bool is_tls() const noexcept;

	// Simple bind (RFC 4511 section 4.2, RFC 4513 section 5.1). An empty name
	// and password is an anonymous bind. A name with an empty password would
	// be an "unauthenticated bind", which servers answer with success without
	// checking anything, so it is refused before anything is sent
	// (client_errc::unauthenticated_bind). A server error (e.g.
	// errc::invalid_credentials) comes back as an error; the connection stays
	// usable (anonymous) and may bind again. RFC 4511 section 4.2.1: do not
	// start other operations while a bind is outstanding (the server may
	// reject or delay them); this is not enforced.
	boost::capy::task<result<void>> simple_bind(dn name, std::string password);

	// SASL bind (RFC 4513 section 5.2): sends one BindRequest per step of
	// `mechanism` while the server answers saslBindInProgress (at most 32
	// steps, then the bind fails with unexpected_response). `name` is
	// usually empty (the mechanism carries the identity). A server error
	// (e.g. errc::inappropriate_authentication) or a mechanism error fails
	// the bind; the connection stays usable (anonymous). The same rules as
	// simple_bind apply otherwise. `mechanism` must outlive the task.
	boost::capy::task<result<void>> sasl_bind(sasl_mechanism &mechanism, dn name = {});

	// Runs a search to its end and returns the entries in the order received,
	// allocated from `mr` (see "Memory" above). Search result references
	// (continuation references) are not returned here: use search_stream()
	// to see them (referral handling is step 6). A result code other than
	// success fails the whole call, size_limit_exceeded included; the
	// entries received before it are lost (search_stream() keeps them).
	boost::capy::task<result<std::pmr::vector<entry>>> search(search_params request,
	  std::pmr::memory_resource *mr = std::pmr::get_default_resource());

	// Sends the search and returns a stream that yields its entries one at a
	// time, each decoded into `mr`. Other operations may run while the
	// stream is open. Destroyed before its end, the stream abandons the
	// search.
	boost::capy::task<result<ldap::search_stream>> search_stream(search_params request,
	  std::pmr::memory_resource *mr = std::pmr::get_default_resource());

	// A search in pages of `page_size` entries (Simple Paged Results, RFC
	// 2696): when a page ends, the next page is requested with the server's
	// cookie, until the cookie is empty. A paged control already in
	// `request.controls` is replaced. A server that ignores the
	// (non-critical) control returns everything as one page, which works the
	// same. Each page is one search on the wire, with its own message id
	// and its own `request.timeout`.
	boost::capy::task<result<ldap::paged_search>> search_paged(search_params request,
	  std::int32_t page_size,
	  std::pmr::memory_resource *mr = std::pmr::get_default_resource());

	// The other operations. Result codes: success returns the value; any
	// other code is an error (`ldap_result::to_error`, with the operation as
	// context), referral included (errc::referral, the URIs in
	// error::referrals; referrals are not chased, see url::parse_list).
	// compare() maps compareTrue / compareFalse to true / false.
	boost::capy::task<result<response>> add(add_params request);
	boost::capy::task<result<response>> modify(modify_params request);
	boost::capy::task<result<response>> del(del_params request);
	boost::capy::task<result<response>> modify_dn(modify_dn_params request);
	boost::capy::task<result<bool>> compare(compare_params request);
	boost::capy::task<result<extended_result>> extended(extended_params request);
	// The authorization identity of this connection (RFC 4532): "dn:<dn>",
	// "u:<user>", or "" when anonymous.
	boost::capy::task<result<std::string>> who_am_i(request_controls controls = {});

	// Reads the server's subschema (RFC 4512): the root DSE's
	// subschemaSubentry (cn=Subschema if it names none), then that entry's
	// attributeTypes and objectClasses. See schema.hpp.
	boost::capy::task<result<server_schema>> load_schema();

	// Typed operations (mapping.hpp, DESIGN.md section 4).
	//
	// search_as<T>: a search whose attribute list is T's descriptor's (any
	// `request.attributes` are replaced) and whose filter is narrowed to T's
	// object classes, if it declares some. Each entry is decoded to T; the
	// first entry that does not decode fails the whole call (its error names
	// the search, the entry and the attribute).
	template<described T> boost::capy::task<result<std::vector<T>>> search_as(search_params request)
	{
		if (auto c = co_await check_schema(typeid(T), &validate<T>); !c)
			co_return std::unexpected(std::move(c.error()));
		request.attributes = attribute_names<T>();
		request.filter = narrow_filter<T>(std::move(request.filter));
		const std::string base = request.base.empty() ? std::string("\"\"") : std::string(request.base.to_string());
		auto entries = co_await search(std::move(request));
		if (!entries) co_return std::unexpected(std::move(entries.error()));
		std::vector<T> out;
		out.reserve(entries->size());
		for (const auto &e : *entries) {
			auto v = ldap::decode<T>(e);
			if (!v) co_return std::unexpected(detail::with_context(std::move(v.error()), "search " + base));
			out.push_back(std::move(*v));
		}
		co_return out;
	}

	// modify<T>: changes built with ldap::replace / add / remove<&T::member>.
	template<described T>
	boost::capy::task<result<response>>
	  modify(dn object, std::vector<change<T>> changes, request_controls controls = {})
	{
		if (auto c = co_await check_schema(typeid(T), &validate<T>); !c)
			co_return std::unexpected(std::move(c.error()));
		modify_params p{ .object = std::move(object), .controls = std::move(controls) };
		p.changes.reserve(changes.size());
		for (auto &c : changes) p.changes.push_back(std::move(c.wire));
		co_return co_await modify(std::move(p));
	}

	// add(dn, value): the attributes of ldap::to_attributes(value) (no
	// read_only members, objectClass from the descriptor).
	template<described T> boost::capy::task<result<response>> add(dn entry, T value, request_controls controls = {})
	{
		if (auto c = co_await check_schema(typeid(T), &validate<T>); !c)
			co_return std::unexpected(std::move(c.error()));
		co_return co_await add(
		  add_params{ .entry = std::move(entry), .attributes = to_attributes(value), .controls = std::move(controls) });
	}

	// StartTLS (RFC 4511 section 4.14): upgrades a plain ldap:// connection
	// to TLS in place, with the same verification rules as ldaps://
	// (`options`; the name checked is options.server_name, else the URL's
	// host). Refused with operation_in_progress while any operation is
	// outstanding; while it runs, starting another operation fails the same
	// way. If the server refuses (a result code other than success), that
	// error is returned and the connection stays usable, unprotected. Bytes
	// received after the StartTLS response and before the handshake are
	// refused (decode_error: a plaintext injection attempt), and a failed
	// handshake closes the connection. `timeout` bounds the exchange and the
	// handshake (nullopt: connection_options::operation_timeout for the
	// exchange, no limit for the handshake).
	boost::capy::task<result<void>> start_tls(net::tls_options options = {},
	  std::optional<std::chrono::milliseconds> timeout = std::nullopt);

	// Sends an UnbindRequest, waits until it is written, and closes the
	// connection (RFC 4511 section 4.3: there is no response). Outstanding
	// operations and open streams fail with not_connected (an unbind
	// abandons them on the server too). The connection is closed even if
	// the write fails or the task is cancelled.
	boost::capy::task<result<void>> unbind();

	// Closes the transport at once, without an UnbindRequest. Outstanding
	// operations complete with not_connected. Idempotent.
	void close() noexcept;

	struct impl;// defined in connection.cpp

  private:
	friend class ldap::search_stream;
	friend class ldap::paged_search;

	// schema_check::on_first_use for one type (see above).
	boost::capy::task<result<void>> check_schema(std::type_index type,
	  schema_report (*validate_type)(const server_schema &));

	impl *impl_ = nullptr;// reference counted; allocated from the resource it records
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
// Move-only. A default-constructed stream fails with
// client_errc::not_connected. The stream must not be destroyed or moved
// while its next() is suspended; a second next() while one is suspended
// fails with client_errc::operation_in_progress.
class search_stream
{
  public:
	search_stream() noexcept = default;
	search_stream(search_stream &&other) noexcept;
	search_stream &operator=(search_stream &&other) noexcept;
	search_stream(const search_stream &) = delete;
	search_stream &operator=(const search_stream &) = delete;
	// Unfinished: the search is abandoned.
	~search_stream();

	// The next entry, nullopt at the end (SearchResultDone with success), or
	// an error: the server's result code (the connection stays usable), a
	// cancellation or timeout (the search is abandoned, the connection stays
	// usable) or a connection failure. After the end or an error, next()
	// returns the same again without I/O.
	boost::capy::task<result<std::optional<entry>>> next();

	// True once the SearchResultDone (or an error) was read.
	bool done() const noexcept;
	// URIs of the SearchResultReference messages received so far, in order,
	// as sent (one string per URI). They are not chased; reference_urls()
	// parses them.
	const string_list &references() const noexcept;
	// references() parsed as LDAP URLs; URIs that do not parse are left out.
	std::pmr::vector<url> reference_urls(std::pmr::memory_resource *mr = std::pmr::get_default_resource()) const;
	// Controls of the SearchResultDone (e.g. paged results), once done().
	const std::pmr::vector<control> &controls() const noexcept;

	struct state;// defined in connection.cpp

  private:
	friend class connection;
	friend struct connection::impl;
	friend class paged_search;

	explicit search_stream(state *s) noexcept : state_(s) {}

	state *state_ = nullptr;
};

// The entries of a paged search, across pages (connection::search_paged):
// used like search_stream. Move-only; the same rules as search_stream
// apply. Destroyed early, the current page's search is abandoned (the
// server may keep its paging state until the connection closes; RFC 2696
// would need one more request with page size 0 to release it early).
class paged_search
{
  public:
	paged_search() noexcept = default;
	paged_search(paged_search &&other) noexcept;
	paged_search &operator=(paged_search &&other) noexcept;
	paged_search(const paged_search &) = delete;
	paged_search &operator=(const paged_search &) = delete;
	~paged_search();

	// The next entry, nullopt after the last page, or an error (the
	// search's, or a malformed paged results control: decode_error).
	boost::capy::task<result<std::optional<entry>>> next();

	bool done() const noexcept;
	// Pages requested so far (1 after search_paged()).
	std::size_t pages() const noexcept;
	// References of every page so far, in order.
	const string_list &references() const noexcept;
	std::pmr::vector<url> reference_urls(std::pmr::memory_resource *mr = std::pmr::get_default_resource()) const;
	// Controls of the last SearchResultDone, once done().
	const std::pmr::vector<control> &controls() const noexcept;

	struct state;// defined in connection.cpp

  private:
	friend class connection;
	friend struct connection::impl;

	explicit paged_search(state *s) noexcept : state_(s) {}

	state *state_ = nullptr;
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
