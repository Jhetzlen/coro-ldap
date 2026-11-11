// ldap::client: a bounded pool of multiplexed connections to a list of
// servers, opened lazily, with failover, jittered backoff, a session setup
// run on every new connection, and a health check on acquire (DESIGN.md
// section 11). Part of jhetz::ldap_net.
//
//   corosio::io_context ioc;
//   ldap::client pool(ioc, {
//       .servers    = {ldap::url{"ldap://ldap1.example.org"}, ldap::url{"ldap://ldap2.example.org"}},
//       .connection = {.timeout = 5s, .operation_timeout = 30s, .start_tls = true},
//       .setup      = ldap::simple_bind_setup(ldap::dn{"cn=app,dc=example,dc=org"}, password),
//   });
//   auto lease = co_await pool.acquire();   // result<ldap::lease>: a shared ldap::connection
//   if (!lease) ...                         // every server failed, or acquire_timeout
//   auto people = co_await (*lease)->search({.base = ldap::dn{"ou=people,dc=example,dc=org"}});   // people->entries
//   auto again = co_await pool.search({.base = ...});   // a shared lease for one search, retried once
//   auto added = co_await pool.add({.entry = ..., .attributes = ...});   // retried only if never sent
//
// Leases: a lease (acquire()) shares its connection with other leases, their
// operations multiplexed on it. acquire() takes an idle connection, else
// opens a new one while fewer than max_connections exist, else shares the one
// with the fewest leases; it also shares rather than wait or fail when no
// server may be tried now. An exclusive_lease (acquire_exclusive()) gets an
// idle or new connection no other lease shares while it is held; while one
// waits, shared acquires do not take idle connections (they share, open a new
// one, or wait, without failing while that idle connection exists). On a
// shared lease, a bind, start_tls() (operation_in_progress while another
// lease has an operation outstanding), unbind() and close() act on every
// lease sharing the connection: do them on an exclusive lease. A connection
// whose bind_count() changed since session_setup (a bind done, failed or in
// progress) is never handed out again and leaves the pool once its last lease
// returns, as does one whose unbind() has begun. Use one client per identity
// and keep binds in session_setup.
//
// Servers and failover: `servers` is in priority order; a new connection
// tries each server whose backoff has ended, in order. A failed connect,
// StartTLS or session_setup puts the server in backoff: uniform in [0, d],
// d = min(backoff.max, backoff.initial * backoff.multiplier^(failures - 1)),
// reset by a success; concurrent failures count once. An attempt cut short by
// acquire_timeout counts as a failure unless it began with less than half of
// acquire_timeout left. acquire() waits for the earliest backoff, up to
// acquire_timeout, then fails with the last server's error.
// cond::invalid_input excludes the server for that acquire().
// cond::auth_failed backs off for at least backoff.auth_failure_min and half
// of d; acquire() calls already running stop trying that server, and during
// the backoff every acquire() fails at once with the stored error (unless
// another server or a pooled connection serves it). Afterwards one acquire()
// binds again while the others fail; if that bind ends without the server's
// verdict (cut short, stopped, its task destroyed, another error), the
// authentication backoff starts again. So a wrong password costs at most one
// bind per server per backoff period, plus attempts in flight (a rate limit,
// not a lockout guard), and a password fixed on the server is noticed only
// once the backoff ends. An idle connection to a lower-priority server at
// least failback_after old is closed by acquire() when a higher-priority
// server may be tried. All servers must serve the same directory and schema
// (a store's schema check holds for any of them).
//
// Health: there is no background timer. acquire() drops connections found
// closed and probes an idle connection unused for longer than idle_check (a
// root DSE base search for "1.1", within probe_timeout): no answer (a server
// error is an answer) closes and replaces it, unless acquire_timeout cut a
// probe short that began with less than half of it left. A connection older
// than max_lifetime is not handed out again. Retired connections do not count
// against max_connections while their leases drain. An acquire() waiting for
// a slot looks again when a leased connection closes or passes max_lifetime.
//
// Closing: a connection leaving the pool is unbound (a detached unbind() on
// the executor) if no lease holds it, else closed; once the io_context is
// stopped (io_context::stopped()) it is closed. stopped() is false after
// restart() and after run_one(), run_for() or poll() returned with work left:
// the posted unbind then runs only if the io_context runs again, else it is
// destroyed with the io_context without an UnbindRequest; so restart() just
// before running it again. To unbind cleanly, call close() (or destroy the
// client) from a task on the executor. close() (and the destructor) closes
// every pooled connection, leased ones included (outstanding operations fail
// with not_connected, or not_sent if not written yet), stops connection
// attempts and referral chases in progress (they fail with not_connected),
// and fails waiting and later acquire() calls with not_connected. No observer
// hook runs once close() has returned.
//
// Referrals (client_options::referrals): off by default; search() and
// compare() then return a referral result as errc::referral (URIs in
// error::referrals) and search() returns continuation references unfollowed.
// follow_referrals and follow_references chase them as ldap::chase_search /
// chase_compare (referral_chase.hpp) do, within `limits`, from the pooled
// connection. `authorize` decides per URI (empty: every URI skipped_policy);
// ldapi:// and implausible hosts are never contacted. Only same_setup sends
// the client's session_setup and TLS client certificate to a referred server
// (same_setup_for_domains() builds such an authorizer). No TLS downgrade:
// from a TLS connection, ldaps:// stays TLS and ldap:// uses StartTLS. The
// certificate is checked against the referred host (tls_options::server_name
// cleared) as the client's TLS settings say: only
// certificate_verification::full (and strict host_matching) authenticates a
// referred server before same_setup sends it credentials. Referred
// connections are per chase, not pooled, with no backoff or auth guard. Only
// a failure of the pooled connection's own operation is retried. search()
// returns the chase's search_result (operations.hpp): references not
// followed stay in search_result::references, a followed search's limit code
// replaces the origin's success, and `referrals` and `unlisted` report each
// URI; compare() returns a compare_result with the same report. A request's
// follow_referrals overrides referral_options::follow_referrals for it, and a search's follow_references
// referral_options::follow_references. Writes, search_stream(), extended() and
// ldap::search_paged(client&) never chase, and ignore both: a write's referral is
// errc::referral (referral_target() builds the request for another server).
//
// sync::client (sync.hpp) wraps a client in blocking calls.
//
// Threading and lifetime: a client may be used from any number of threads.
// Its pool state is on its own strand (executor()); each pooled connection
// has its own strand. The observer, the referral authorizer and session_setup
// are called on the client's strand. close(), the destructor and a lease's
// release or destruction called off that strand post their work there (it
// takes effect when the io_context next runs, so the no-hook guarantee of
// close() holds for a close() called on the strand). connections() reads a
// snapshot. The io_context must outlive the client and its leases; the memory
// resource must outlive the work left on the io_context (keep it until
// io_context::run() returns). A lease may outlive its client: its connection
// is then closed, its operations fail, and destroying it is safe.
#pragma once

#include "jhetz/ldap/connection.hpp"
#include "jhetz/ldap/connection_options.hpp"
#include "jhetz/ldap/dn.hpp"
#include "jhetz/ldap/error.hpp"
#include "jhetz/ldap/referral.hpp"
#include "jhetz/ldap/sasl.hpp"
#include "jhetz/ldap/url.hpp"

#include <boost/capy/task.hpp>
#include <boost/corosio/io_context.hpp>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <memory_resource>
#include <optional>
#include <string>
#include <vector>

namespace jhetz::ldap {

// Prepares each new connection before it is pooled: usually a bind. Runs
// after connect and StartTLS; a failure fails that connection attempt (and
// counts against the server, see "Servers and failover" in the header
// comment). The connection outlives the task. Copied into each attempt's
// call, so it must be copyable; it may be called concurrently for several
// connections.
using session_setup = std::function<boost::capy::task<result<void>>(connection &)>;

// A session_setup doing simple_bind(name, password) (an empty name and
// password: an anonymous bind). The password is kept in the setup, unwiped
// (see extended_operations.hpp on password memory).
[[nodiscard]] auto simple_bind_setup(dn name, std::string password) -> session_setup;

// Makes a fresh SASL mechanism for each connection (a mechanism holds the
// state of one exchange).
using sasl_mechanism_factory = std::function<std::unique_ptr<sasl_mechanism>()>;

// A session_setup doing sasl_bind(*factory(), name) with a new mechanism
// per connection. A factory returning null fails the setup with
// std::errc::invalid_argument.
[[nodiscard]] auto sasl_bind_setup(sasl_mechanism_factory factory, dn name = {}) -> session_setup;

// A session_setup that does nothing: the connection keeps the identity its
// transport gives it (none, or the TLS client certificate a server may map
// to an identity, as with SASL EXTERNAL implied by TLS). Unlike an empty
// session_setup, it counts as a setup where one decides whether the client
// certificate is presented (make_same_policy_connector).
[[nodiscard]] auto no_bind_setup() -> session_setup;

// The delay before a failed server is tried again (see the header comment).
struct backoff_options
{
	static constexpr std::chrono::milliseconds default_initial{ 100 };
	static constexpr std::chrono::milliseconds default_max{ 30'000 };
	static constexpr double default_multiplier = 2.0;

	static constexpr std::chrono::milliseconds default_auth_failure_min{ 5'000 };

	std::chrono::milliseconds initial{ default_initial };// cap after the first failure
	std::chrono::milliseconds max{ default_max };// cap for any number of failures
	double multiplier = default_multiplier;// cap growth per failure; below 1 counts as 1
	// The shortest backoff after an authentication failure (whose delay is
	// also at least half the cap: no jitter down to 0).
	std::chrono::milliseconds auth_failure_min{ default_auth_failure_min };
};

// Why a connection left the pool (client_observer::on_disconnect).
enum class disconnect_reason {
	closed,// found closed or being unbound (the server or an error closed it, or a lease's unbind() or close())
	probe_failed,// the idle check got no answer
	max_lifetime,// older than client_options::max_lifetime
	rebound,// a lease bound it again
	failback,// to a lower-priority server, closed to return to a higher-priority one
	client_closed,// client::close() or the client's destructor
	// A read forwarder's operation got busy or unavailable on it, and was
	// retried on another connection (see client::search).
	busy_or_unavailable,
};

// Hooks for metrics and logs; every one does nothing by default. Called on
// the client's executor, synchronously: they must not throw, and should
// not block. None is called once client::close() has returned. A hook may
// call client::close().
class client_observer
{
  public:
	client_observer() = default;
	client_observer(const client_observer &) = default;
	client_observer(client_observer &&) = default;
	auto operator=(const client_observer &) -> client_observer & = default;
	auto operator=(client_observer &&) -> client_observer & = default;
	virtual ~client_observer() = default;

	// A connection attempt to `server` ended: connected and set up, or the
	// error (of connect, StartTLS or session_setup). Not called for an
	// attempt stopped (close(), the acquire's stop token) or excused when
	// acquire_timeout cut it short (it began with less than half of it left).
	virtual void on_connect(const url &server, const result<void> &outcome)
	{
		(void)server;
		(void)outcome;
	}
	// A pooled connection to `server` left the pool.
	virtual void on_disconnect(const url &server, disconnect_reason reason)
	{
		(void)server;
		(void)reason;
	}
	// `server` failed with `failure` and will not be tried again for `delay`
	// (its backoff). When the one bind let through after an authentication
	// backoff ends without a verdict (cut short, stopped, another error) and
	// that backoff starts again, `failure` is the stored authentication
	// error, the reason the server backs off, not what ended the bind. Not
	// called when that bind's acquire() task is destroyed (the backoff still
	// starts again).
	virtual void on_retry(const url &server, const error &failure, std::chrono::milliseconds delay)
	{
		(void)server;
		(void)failure;
		(void)delay;
	}
	// The idle check of a connection to `server` ended: answered, or not.
	// Not called for one excused when acquire_timeout cut it short (it
	// began with less than half of it left).
	virtual void on_probe(const url &server, const result<void> &outcome)
	{
		(void)server;
		(void)outcome;
	}
	// An acquire() had to wait (for a server's backoff, or for a connection
	// another acquire() was opening or probing) for `waited` in all; called
	// once it ends, successfully or not.
	virtual void on_acquire_wait(std::chrono::milliseconds waited) { (void)waited; }
	// A chase from a connection to `server` decided what became of one URI
	// of a referral or continuation reference (client_options::referrals),
	// as it went: each URI search_result::referrals (compare_result::
	// referrals) lists, and those beyond referral_policy::max_attempts. Not
	// called for the references left unexamined, or not followed
	// (follow_references off): those are only counted (`unlisted`).
	virtual void on_referral(const url &server, const referral_attempt &attempt)
	{
		(void)server;
		(void)attempt;
	}
};

// A referred server a chase would contact (referral_options::authorize).
// `target` is the URL as the server sent it: its host is percent-decoded,
// but not lowercased, nor converted to its ASCII form (IDNA), and a
// trailing dot is kept, while the chase connects to the ASCII form. So a
// hand-written authorizer must not compare the host as a raw string
// (same_setup_for_domains compares the ASCII forms, case-insensitively),
// and must check the scheme and the port itself: the connection goes to
// whatever port the URL names (same_setup_for_domains allows only the
// usual ones unless told otherwise).
struct referral_hop
{
	url target{};// its scheme, host and port name the server
	std::size_t depth = 1;// 1: returned by the pooled connection's server
	url origin{};// the pooled connection's server (lease::server())
};

// How a referred server is contacted.
enum class referral_binding : std::uint8_t {
	refuse,// not at all: the URI is skipped (referral_outcome::skipped_policy)
	// Connected, not bound, and without the client's TLS certificate
	// (connection_options::tls cert_file and key_file are left out).
	anonymous,
	// Connected and set up with client_options::setup: the client's
	// credentials, its TLS certificate included.
	same_setup,
};

// Decides for each referred server. Called on the client's executor. An
// exception it throws propagates out of the operation (search(),
// compare(); sync::client rethrows it)
// as an exception, not as an error result; the chase's referred
// connections are closed and the lease is returned.
using referral_authorizer = std::function<referral_binding(const referral_hop &hop)>;

// An authorizer giving same_setup to the hosts of `domains` and refusing
// the others, by make_same_policy_connector's allow-list rules
// (referral_chase.hpp): a name matches an entry equal to it or of which it
// is a subdomain, compared in ASCII form (IDNA); an IP address only the
// same address; the port must be the scheme's default or the pooled
// connection's server's, unless the entry names it (`example.org:1389`,
// which allows it on the subdomains too; `[::1]:1389`). Empty: refuses
// everything.
[[nodiscard]] auto same_setup_for_domains(std::vector<std::string> domains) -> referral_authorizer;

// Referral chasing by the read forwarders (see "Referrals" in the header
// comment). The default chases nothing.
struct referral_options
{
	// Chase referral results (RFC 4511 section 4.1.10) of search() and
	// compare(); a request's follow_referrals overrides it.
	bool follow_referrals = false;
	// Follow the continuation references (section 4.5.3) of search(); a
	// request's follow_references overrides it.
	bool follow_references = false;
	// Which servers to contact, and how to bind; empty: none.
	referral_authorizer authorize{};
	// Depth, connector calls and attempts listed, per chase.
	referral_policy limits{};
};

struct client_options
{
	static constexpr std::chrono::milliseconds default_idle_check{ 60'000 };
	static constexpr std::chrono::milliseconds default_acquire_timeout{ 30'000 };
	static constexpr std::chrono::milliseconds default_failback_after{ 300'000 };
	static constexpr std::chrono::milliseconds default_probe_timeout{ 5'000 };

	// In priority order; url::parse_servers, url::parse_server or the url
	// literal build them. Empty, or an entry url::check_server() refuses
	// (checked when the client is built): every acquire() fails with
	// invalid_url.
	std::vector<url> servers{};
	// For every connection (connect timeout, TLS, operation_timeout,
	// start_tls, ...).
	connection_options connection{};
	// Run on every new connection; empty: none (anonymous connections).
	session_setup setup{};
	// Connections open at once, at least 1 (0 makes acquire() fail with
	// std::errc::invalid_argument). The default, 1, is a single multiplexed
	// connection that every shared lease uses at once; more connections
	// matter mostly for exclusive leases (acquire_exclusive(): binds,
	// StartTLS) and for isolating slow operations, and an exclusive lease
	// with max_connections = 1 waits until no shared lease holds the one
	// connection.
	std::size_t max_connections = 1;
	// Probe an idle connection unused for longer than this before handing it
	// out; nullopt: never (a dead connection is then found by the lease's
	// first operation).
	std::optional<std::chrono::milliseconds> idle_check{ default_idle_check };
	// Bounds the idle check, within what is left of acquire_timeout; no
	// answer by then: the connection is replaced. ldap::no_timeout: only
	// acquire_timeout bounds it.
	std::chrono::milliseconds probe_timeout{ default_probe_timeout };
	// A connection this old is no longer handed out, and leaves the pool
	// once its last lease returns; nullopt: no limit.
	std::optional<std::chrono::milliseconds> max_lifetime{};
	// Bounds each acquire(): waiting for backoffs and for other acquires,
	// connecting, setting up and probing. On expiry acquire() fails with the
	// last server's error if it has one, else capy::error::timeout. nullopt
	// (or ldap::no_timeout): none, so acquire() keeps retrying failed servers
	// until it succeeds, is cancelled, or close() is called.
	std::optional<std::chrono::milliseconds> acquire_timeout{ default_acquire_timeout };
	backoff_options backoff{};
	// How old an idle connection to a lower-priority server must be before
	// acquire() closes it to go back to a higher-priority one.
	std::chrono::milliseconds failback_after{ default_failback_after };
	// Not owned; must outlive the client, or its close(). Null: none.
	client_observer *observer = nullptr;
	// Off by default: see "Referrals" in the header comment.
	referral_options referrals{};
};

class client;

namespace detail {
	struct client_state;
	struct pooled_connection;

	// The backoff cap after `failures` (>= 1) failures, scaled by `unit` in
	// [0, 1] (the jitter): unit * min(max, initial * multiplier^(failures - 1)).
	[[nodiscard]] auto backoff_delay(const backoff_options &options, std::size_t failures, double unit) noexcept
	  -> std::chrono::milliseconds;

	// For tests only: the jitter source (values in [0, 1]) instead of a
	// random generator.
	void set_jitter(const client &c, std::function<double()> unit);

	// For tests only: what opens the pooled connections instead of
	// ldap::connect, called with the server's URL and
	// client_options::connection (the setup then runs on the connection).
	using pool_connector = std::function<boost::capy::task<result<
	  connection>>(boost::corosio::io_context &ioc, url u, connection_options options, std::pmr::memory_resource *mr)>;
	void set_connector(const client &c, pool_connector open);

	// ldap::search_paged(client &): the first page on a shared lease,
	// retried as client::search_stream() is.
	auto search_paged_of(const client &c, search_params request, std::int32_t page_size, std::pmr::memory_resource *mr)
	  -> boost::capy::task<result<paged_search>>;
}// namespace detail

namespace detail {
	// What lease and exclusive_lease share: the hold on one pooled
	// connection, until destroyed, reassigned or released.
	class lease_base
	{
	  public:
		lease_base(const lease_base &) = delete;
		auto operator=(const lease_base &) -> lease_base & = delete;

		// False for a default-constructed, moved-from or released lease.
		explicit operator bool() const noexcept { return conn_ != nullptr; }
		// The server the connection goes to. Precondition: *this is true.
		[[nodiscard]] auto server() const noexcept -> const url &;
		// Returns the connection to the pool now (the destructor's job).
		void release() noexcept;

	  protected:
		lease_base() noexcept = default;
		lease_base(std::shared_ptr<client_state> state, std::shared_ptr<pooled_connection> conn) noexcept;
		lease_base(lease_base &&other) noexcept = default;
		auto operator=(lease_base &&other) noexcept -> lease_base &;
		~lease_base();

		[[nodiscard]] auto pooled() const noexcept -> connection &;

	  private:
		friend struct client_state;

		std::shared_ptr<client_state> state_{};
		std::shared_ptr<pooled_connection> conn_{};
	};
}// namespace detail

// A shared use of one pooled connection (client::acquire()): other leases
// may use the connection at once (see the header comment). It gives the
// full ldap::connection, but simple_bind, sasl_bind, start_tls, unbind and
// close change the session for every lease sharing the connection (a bind
// also retires it from the pool, see "Bind identity"): use an
// exclusive_lease for those.
class lease : public detail::lease_base
{
  public:
	lease() noexcept = default;
	lease(lease &&other) noexcept = default;
	auto operator=(lease &&other) noexcept -> lease & = default;
	lease(const lease &) = delete;
	auto operator=(const lease &) -> lease & = delete;
	~lease() = default;

	// The connection. Precondition: *this is true.
	[[nodiscard]] auto get() const noexcept -> connection & { return pooled(); }
	auto operator*() const noexcept -> connection & { return pooled(); }
	auto operator->() const noexcept -> connection * { return &pooled(); }

  private:
	friend struct detail::client_state;
	lease(std::shared_ptr<detail::client_state> state, std::shared_ptr<detail::pooled_connection> conn) noexcept;
};

// The exclusive use of one pooled connection (client::acquire_exclusive()):
// an idle or new connection that no other lease shares while it is held,
// with the full connection API, binds, start_tls() and unbind() included
// (see the header comment for what a bind does to the connection's place in
// the pool).
class exclusive_lease : public detail::lease_base
{
  public:
	exclusive_lease() noexcept = default;
	exclusive_lease(exclusive_lease &&other) noexcept = default;
	auto operator=(exclusive_lease &&other) noexcept -> exclusive_lease & = default;
	exclusive_lease(const exclusive_lease &) = delete;
	auto operator=(const exclusive_lease &) -> exclusive_lease & = delete;
	~exclusive_lease() = default;

	// The connection. Precondition: *this is true.
	[[nodiscard]] auto get() const noexcept -> connection & { return pooled(); }
	auto operator*() const noexcept -> connection & { return pooled(); }
	auto operator->() const noexcept -> connection * { return &pooled(); }

  private:
	friend struct detail::client_state;
	exclusive_lease(std::shared_ptr<detail::client_state> state,
	  std::shared_ptr<detail::pooled_connection> conn) noexcept;
};

class client
{
  public:
	// The client's strand over its io_context's executor (as
	// connection::executor_type).
	using executor_type = connection::executor_type;

	// Opens nothing yet: connections are opened by acquire(). Connections'
	// state is allocated from `mr`.
	client(boost::corosio::io_context &ioc,
	  client_options options,
	  std::pmr::memory_resource *mr = std::pmr::get_default_resource());
	client(client &&other) noexcept = default;
	auto operator=(client &&other) noexcept -> client &;
	client(const client &) = delete;
	auto operator=(const client &) -> client & = delete;
	// close().
	~client();

	// The client's strand (see "Threading and lifetime" in the header
	// comment). Precondition: not moved from.
	[[nodiscard]] auto executor() const noexcept -> executor_type;

	// A shared lease on a pooled connection: an idle one (probed first if
	// unused for longer than idle_check), else a new one while fewer than
	// max_connections exist and a server may be tried now, else the open one
	// with the fewest leases (see the header comment). Waits at most
	// acquire_timeout. Fails with the last server's error (its context names
	// the server: "acquire ldap://ldap1.example.org: ..."), the stored error
	// of a server backing off after an authentication failure,
	// capy::error::timeout when it waited for other acquires that long,
	// capy::error::canceled if the task's stop token is set, and
	// client_errc::not_connected once close() was called (or on a moved-from
	// client). The task does not refer to *this: the client may be moved or
	// destroyed while it runs (destroying it fails it with not_connected).
	auto acquire() -> boost::capy::task<result<lease>>;
	// As acquire(), an exclusive lease: an idle connection or a new one,
	// which no other lease shares while this one holds it, for binds,
	// start_tls() and unbind(). It waits (within acquire_timeout) when every
	// connection is leased and max_connections are open.
	auto acquire_exclusive() -> boost::capy::task<result<exclusive_lease>>;

	// Read forwarders: each acquires a shared lease, runs the connection's
	// operation of the same name and returns the lease. A failure with
	// cond::connection_lost (not_sent included) or cond::busy_or_unavailable
	// is retried once on another connection: the failed one is retired
	// (disconnect_reason::busy_or_unavailable if still open), and after busy
	// or unavailable the retry prefers the other servers (the server's
	// backoff is untouched). Any other error (a result code, a timeout, a
	// cancellation) and the retry's outcome are returned as is. Each acquire()
	// is bounded by acquire_timeout and fails as acquire() does; the
	// operations by their own timeouts, else
	// connection_options::operation_timeout. The stop token stops both. A
	// request control bound to one connection (a paged-results cookie,
	// anything tied to the session) needs a lease, since each call may land
	// on any pooled connection. The tasks do not refer to *this.
	//
	// search(): connection::search()'s search_result (a limit code is a
	// value, never retried); entries are collected before any is handed
	// over, so it is retried whatever it had received. When chasing, the
	// chase's: its references are those the chase did not follow, with
	// what it did in `referrals` and `unlisted`.
	auto search(search_params request, std::pmr::memory_resource *mr = std::pmr::get_default_resource())
	  -> boost::capy::task<result<search_result>>;
	// search_stream(): returns once the search has a first message or has
	// ended, retried only if it fails before any message. The stream holds
	// the lease until destroyed; next() and next_item() errors are never
	// retried. A non-retried end code or a passed deadline is reported by
	// next(). A refreshAndPersist search with nothing to send returns only at
	// its first change.
	auto search_stream(search_params request, std::pmr::memory_resource *mr = std::pmr::get_default_resource())
	  -> boost::capy::task<result<ldap::search_stream>>;
	// compare(): compareTrue / compareFalse as compare_result::value, with
	// the answering response's LDAPResult tail and controls; when chasing,
	// with what the chase did.
	auto compare(compare_params request) -> boost::capy::task<result<compare_result>>;
	// search() and compare() chase referrals as client_options::referrals
	// (and the request's follow_referrals and follow_references) say, as ldap::chase_search and
	// ldap::chase_compare (referral_chase.hpp) do, on a shared lease with
	// the read forwarders' retry. With follow_references off, the
	// references received are counted in `unlisted`; with follow_referrals
	// off, a referral result fails the call (errc::referral).
	// search_stream() never chases.

	// Write forwarders: as the read forwarders, but retried once only after
	// client_errc::not_sent (the server never saw the request). Any other
	// failure (a lost connection, a timeout, busy or unavailable, any result
	// code, errc::referral: never chased) is returned as is, and the update
	// may or may not have been applied. A connection-bound request control
	// (transaction_specification) needs a lease. The tasks do not refer to
	// *this.
	auto add(add_params request) -> boost::capy::task<result<response>>;
	auto modify(modify_params request) -> boost::capy::task<result<response>>;
	auto del(del_params request) -> boost::capy::task<result<response>>;
	auto modify_dn(modify_dn_params request) -> boost::capy::task<result<response>>;
	// Any extended operation but StartTLS, as a write forwarder: retried
	// only after not_sent, since an extended operation may change the
	// directory (who_am_i() and the password calls of
	// extended_operations.hpp run on it, and their tasks refer to the
	// client). A referral result is an error, never chased.
	auto extended(extended_params request) -> boost::capy::task<result<extended_result>>;

	// Connections in the pool, open or retired and waiting for their last
	// lease to return (not those still being opened). For tests and
	// diagnostics.
	[[nodiscard]] auto connections() const noexcept -> std::size_t;

	// Closes every pooled connection, stops the connection attempts in
	// progress, and fails later and waiting acquire() calls with
	// not_connected. Idempotent.
	void close() noexcept;

  private:
	friend void detail::set_jitter(const client &, std::function<double()>);
	friend void detail::set_connector(const client &, detail::pool_connector);
	friend auto detail::search_paged_of(const client &, search_params, std::int32_t, std::pmr::memory_resource *)
	  -> boost::capy::task<result<paged_search>>;

	std::shared_ptr<detail::client_state> state_{};
};

}// namespace jhetz::ldap
