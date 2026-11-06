// ldap::client: a bounded pool of multiplexed connections to a list of
// servers, opened lazily, with failover, jittered backoff, a session setup
// replayed on every new connection, and a health check on acquire
// (DESIGN.md section 11). Part of jhetz::ldap_net.
//
//   corosio::io_context ioc;
//   ldap::client pool(ioc, {
//       .servers    = {*ldap::url::parse("ldap://ldap1.example.org"), *ldap::url::parse("ldap://ldap2.example.org")},
//       .connection = {.timeout = 5s, .operation_timeout = 30s, .start_tls = true},
//       .setup      = ldap::simple_bind_setup(ldap::dn{"cn=app,dc=example,dc=org"}, password),
//   });
//   auto lease = co_await pool.acquire();   // result<ldap::lease>: a shared_connection
//   if (!lease) ...                         // every server failed, or acquire_timeout
//   auto people = co_await (*lease)->search({.base = ldap::dn{"ou=people,dc=example,dc=org"}});   // people->entries
//   auto again = co_await pool.search({.base = ...});   // a shared lease for one search, retried once
//   auto added = co_await pool.add({.entry = ..., .attributes = ...});   // retried only if never sent
//
// Leases share connections by default. A lease (acquire()) gives a
// shared_connection on one pooled connection: every operation of
// ldap::connection but simple_bind, sasl_bind, start_tls, unbind and close,
// which do not compile on it. Several leases may use the same connection at
// once: their operations are multiplexed on it (connection.hpp), which is
// why max_connections defaults to 1. An exclusive_lease
// (acquire_exclusive()) gives the full ldap::connection.
// acquire() hands out an idle connection (no lease) first, then opens a new
// one while fewer than max_connections exist, and only then shares the
// connection with the fewest leases: N connections give N-way isolation (a
// slow paged search, a long SASL exchange) before any sharing. It also
// shares one, rather than wait or fail, when no new connection may be opened
// now (every server backing off, or excluded for this acquire(), e.g. after
// an authentication failure). While an acquire_exclusive() waits, shared
// ones never take an idle connection: they share one already shared, else
// open a new one (a slot free, a server to try) or wait (even with every
// server excluded: then they do not fail while that idle connection
// exists), so shared load cannot starve it. Because shared leases share,
// what one changes on its connection the others would see: a bind would
// change the identity of all of them, start_tls() would fail with
// operation_in_progress while another lease has an operation outstanding,
// and unbind() or close() would end the connection for everyone. So a
// shared lease has none of them; they are on an exclusive lease
// (acquire_exclusive()): an idle or new connection that no other lease
// shares while it is held (from the moment its unbind() begins, the
// connection is not handed out again). A connection whose bind_count()
// changed (a bind done, failed, or still in progress) is never handed out
// again, to anyone: it leaves the pool once its last lease returns (see
// "Bind identity"). Use a client per identity, and keep binds to
// session_setup.
//
// Servers and failover: `servers` is in priority order. A new connection
// tries each server whose backoff has ended, in that order. A server that
// fails (connect, StartTLS, or session_setup) is not tried again until a
// backoff delay has passed: full jitter, uniform in [0, d] with d =
// min(backoff.max, backoff.initial * backoff.multiplier^(failures - 1)),
// reset by a success. Concurrent attempts failing together count as one
// failure. An attempt cut short by acquire_timeout is a failure too (a
// hung server must not block failover) unless it began with less than half
// of acquire_timeout left (the acquire waited, or tried other servers,
// first): only then is it excused (no backoff, no on_connect). The one
// bind let through after an authentication backoff (below) that ends
// without the server's verdict on the password (cut short, late or not,
// stopped, its acquire() task destroyed, or any other error) starts that
// authentication backoff again, with the stored error. acquire() waits
// for the earliest backoff to end, up to acquire_timeout, and then fails
// with the last server's error (or shares an open connection, see above).
// A failure that retrying cannot fix (cond::invalid_input: a bad URL, a
// setup that cannot work) stops this acquire() from trying that server
// again. An authentication failure
// (cond::auth_failed, e.g. a wrong password) does more: its backoff is at
// least backoff.auth_failure_min and at least half of d (no jitter down to
// 0), every acquire() already running stops trying that server, and every
// acquire() started during that backoff fails at once with the stored error
// (unless another server or a pooled connection serves it) instead of
// binding again. Once the backoff ends, one acquire() binds again; the
// others fail with the stored error while it runs. So a wrong password costs
// at most one bind per server per backoff period (plus, the first time, the
// attempts already in flight, up to max_connections), not a retry storm;
// this limits the rate of failed binds, it cannot keep a password that stays
// wrong from locking an account (Active Directory) in the end. Mind that it
// works both ways: once the service password is fixed on the server, this
// client's acquire() still fails at once until the backoff ends, at least
// auth_failure_min after the last failed bind, unless a pooled connection
// serves it. A connection to a lower-priority server that is idle, at least
// failback_after old, while a higher-priority server this acquire() may try
// has ended its backoff, is closed when acquire() finds it, so the next
// connection goes back to the primary (failing over again if the primary
// still fails).
//
// Health: there is no background timer (it would keep io_context::run()
// from returning). acquire() drops pooled connections found closed, and
// probes an idle connection unused for longer than idle_check with a root
// DSE base search for the attribute "1.1" (no attributes) before handing it
// out, within probe_timeout: one that does not answer (a server error is an
// answer) is closed and replaced, also when acquire_timeout cuts the probe
// short, unless the probe began with less than half of acquire_timeout left:
// that proves nothing, the connection stays, and acquire() fails with the
// timeout. A connection
// older than max_lifetime is no longer handed out (acquire() opens a
// replacement instead), and leaves the pool once its last lease returns.
// An acquire() waiting for a slot looks again when a leased connection
// closes or passes max_lifetime.
//
// Bind identity: session_setup runs on every new connection, after connect
// and StartTLS (connection_options::start_tls). The client records the
// connection's bind_count() after it; once the count differs (a lease bound
// again, or is binding), no acquire() hands the connection out, and it is
// closed once no lease uses it.
//
// Retired connections (closed, re-bound, too old, failed back) do not count
// against max_connections while their last leases drain: acquire() opens a
// replacement at once, so the pool may briefly hold more connections.
//
// Closing: a connection leaving the pool while open is unbound (a detached
// unbind() on the executor) if no lease holds it, else closed. Once the
// io_context is stopped (io_context::stopped(): its run() returned, as for
// a client destroyed at the end of main()), it is closed, as a connection's
// destructor does: a task posted then would never run. So call close() (or
// destroy the client) from a task on the executor to unbind cleanly. But
// stopped() is false, and the unbind is still posted, while the io_context
// was restart()ed and not run since, or once run_one(), run_for() or poll()
// returned with work outstanding: that task runs only if the io_context is
// run again, else it and its connection are destroyed with the io_context,
// the socket closed without an UnbindRequest. So restart() it just before
// running it again, not right after run() returns.
//
// close() closes every pooled connection, leased ones included (their
// outstanding operations fail with not_connected, or not_sent for requests
// not written yet, see connection.hpp "Sent or not"), stops the connection
// attempts in progress (connect, StartTLS, session_setup) and the referral
// chases running (no referred server is authorized, connected to or set up
// after it: the chase fails with not_connected), and fails waiting and
// later acquire() calls with not_connected at once; the destructor calls
// it. No observer hook runs once close() has returned.
//
// Referrals (client_options::referrals): off by default, as for a
// connection, nothing is chased: search() and compare() return a referral
// result as an error (errc::referral, the URIs in error::referrals) and
// search() returns continuation references unfollowed
// (search_result::references). Opting in, follow_referrals
// chases referral results (RFC 4511 section 4.1.10) of search() and
// compare(), follow_references the continuation references (section 4.5.3)
// of search(), as ldap::chase_search and ldap::chase_compare
// (referral_chase.hpp) do, from the pooled connection the operation ran
// on, within `limits`. The URIs of a reference are alternatives, loops are
// skipped, the request's timeout bounds the whole chase: see
// referral_chase.hpp. Which servers may be contacted, and how their
// connections are bound, is `authorize`'s call (empty: none, every URI
// skipped_policy), asked once per URI that passes the fixed rules: never
// ldapi:// (a server's URL must not reach a local socket), nor a host
// with bytes no host name has. Only an authorizer returning same_setup
// sends the client's session_setup (its credentials) to a referred
// server, and presents its TLS client certificate (tls_options::cert_file)
// there; the library never does by itself; same_setup_for_domains()
// builds one that does so for the hosts of the domains named.
// No TLS downgrade: when the pooled connection is TLS-protected, an ldaps://
// target is opened as such and an ldap:// one with StartTLS (a failed
// StartTLS fails that URI); otherwise client_options::connection applies
// as given. The certificate is checked against the referred host
// (connection_options::tls::server_name cleared), as the client's TLS
// settings say: only with certificate_verification::full (and strict
// host_matching for the strict name rules) is a referred server
// authenticated before same_setup sends it the client's credentials; a
// client configured with insecure_accept_any sends them to whatever
// answers. These are make_same_policy_connector's rules, with `authorize`
// for its allow-list.
// Referred connections are not pooled: each chase opens its own (one per
// server and binding, reused within the chase), runs the setup chosen on
// them, and closes them (without an UnbindRequest) when it ends. So they
// get neither the pool's backoff nor its authentication-failure guard: a
// referred server refusing the client's credentials is bound again by the
// next chase that reaches it. A failure of the pooled connection's own
// operation is retried once as usual (the whole chase starts again on
// another connection); a referred server's failure or the chase's is
// returned as is, never retried. search() returns the search_result only
// (chased_search's entries, references and done fields): one whose
// continuation references were not all followed (refused, over a limit,
// failed, or follow_references off) still succeeds with what it got, the
// URIs not followed in search_result::references, as connection::search()
// does; one whose followed reference's search ended with a limit code
// has that code (is_success() false) when the origin's search succeeded.
// chase_search() tells more (complete, referrals, unlisted). client_observer::on_referral hears of each URI.
// Writes are never chased, whatever client_options::referrals says: the
// write forwarders (add(), modify(), ...) and leases return a referral
// result as an error (errc::referral, the URIs in error::referrals; the
// update was not performed, section 4.1.10; referral_target builds the
// request for another server). UnboundID's followReferrals, libldap's
// LDAP_OPT_REFERRALS and JNDI's java.naming.referral=follow chase writes
// too; this client does not.
// search_stream() and extended() never chase either: the stream hands out
// its references (search_stream::references(), next_item()).
//
// For code without coroutines, sync::client (sync.hpp) owns an io_context
// and its thread, and wraps a client in blocking calls.
//
// Threading and lifetime: like connection, a client belongs to the executor
// of its io_context; acquire() and the leases (their connections, their
// destruction) must be used on it. The io_context must outlive the client
// and its leases. The memory resource must outlive the work the client
// leaves on the io_context (a detached unbind() may still run after the
// client and its leases are gone): keep it until io_context::run() returns.
// A lease may outlive its client, but the client's destruction closes its
// connection (close()): its operations then fail, and destroying the lease
// later is safe.
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
	// as it went: each URI chased_search::referrals lists, and those beyond
	// referral_policy::max_attempts. Not called for the references left
	// unexamined, or not followed (follow_references off): those are only
	// counted (chased_search::unlisted).
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
// compare(), chase_search(), chase_compare(); sync::client rethrows it)
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
	// compare().
	bool follow_referrals = false;
	// Follow the continuation references (section 4.5.3) of search().
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

	// In priority order. Empty: acquire() fails with invalid_url.
	std::vector<url> servers{};
	// For every connection (connect timeout, TLS, operation_timeout,
	// start_tls, ...).
	connection_options connection{};
	// Run on every new connection; empty: none (anonymous connections).
	session_setup setup{};
	// Connections open at once, at least 1 (0 makes acquire() fail with
	// std::errc::invalid_argument).
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
// may use the connection at once (see the header comment), so it gives a
// shared_connection (connection.hpp), without the operations that change
// the session for every lease (simple_bind, sasl_bind, start_tls, unbind,
// close): those need an exclusive_lease. Destroy it on the client's
// executor.
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
	[[nodiscard]] auto get() const noexcept -> const shared_connection & { return view_; }
	auto operator*() const noexcept -> const shared_connection & { return view_; }
	auto operator->() const noexcept -> const shared_connection * { return &view_; }

  private:
	friend struct detail::client_state;
	lease(std::shared_ptr<detail::client_state> state, std::shared_ptr<detail::pooled_connection> conn) noexcept;

	shared_connection view_{};
};

// The exclusive use of one pooled connection (client::acquire_exclusive()):
// an idle or new connection that no other lease shares while it is held,
// with the full connection API, binds, start_tls() and unbind() included
// (see the header comment for what a bind does to the connection's place in
// the pool). Destroy it on the client's executor.
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
	using executor_type = boost::corosio::io_context::executor_type;

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

	// The executor everything must run on. Precondition: not moved from.
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

	// Read forwarders: each acquires a shared lease (acquire()), runs the
	// connection's operation of the same name on it, and returns the lease.
	// An operation failing with cond::connection_lost (client_errc::not_sent
	// included) or cond::busy_or_unavailable (the result codes busy and
	// unavailable, a Notice of Disconnection) is retried once, on another
	// connection: the one it failed on is no longer handed out (if still
	// open, it is retired with disconnect_reason::busy_or_unavailable and
	// leaves the pool once its last lease returns), so the retry's acquire()
	// takes another pooled connection or opens a new one. After busy or
	// unavailable it prefers the other servers: a pooled connection to one
	// of them, else a new connection to the first of them, in priority
	// order, that may be tried now, and only then that server again (a
	// pooled connection to it first, before a new one; so a single server
	// is retried as before); its backoff is not touched (it answered).
	// After a lost connection it goes by priority order, as acquire() does.
	// Any other error, a server result code included (no_such_object, ...),
	// a timeout or a cancellation, is returned as is, and so is the retry's
	// outcome. Each acquire() is bounded by acquire_timeout and fails as
	// acquire() does (that error is returned, also for the retry's); the
	// operations are bounded by their own timeouts
	// (search_params::timeout, ..., else
	// connection_options::operation_timeout). The task's stop token stops
	// the acquire() and the operation. The write forwarders (below) retry
	// only after client_errc::not_sent.
	// Each call may land on any pooled connection, so a request control
	// bound to one connection (the paged-results cookie of an earlier page,
	// anything tied to the session) needs a lease, not the forwarders. Like
	// acquire(), the tasks do not refer to *this.
	//
	// search(): connection::search()'s search_result (a limit code is a
	// value, never retried); the entries reach the caller only once the
	// search ends, so it is retried whatever it had received. When it
	// chases (client_options::referrals) its references are those the
	// chase did not follow (chase_search() tells more).
	auto search(search_params request, std::pmr::memory_resource *mr = std::pmr::get_default_resource())
	  -> boost::capy::task<result<search_result>>;
	// search_stream(): returns once the search has a first message (an
	// entry, a reference, an intermediate response) or has ended, and is
	// retried only if it fails (as above) before any message. The stream
	// holds the lease until it is destroyed; its next() and next_item()
	// errors are never retried, so a stream is never retried once its first
	// entry may have been delivered. A search ended with a code that is not
	// retried (no_such_object, ...) or a passed deadline is reported by
	// next(), as for connection::search_stream(). Mind that it waits for
	// that first message: a refreshAndPersist search with nothing to send
	// returns at its first change.
	auto search_stream(search_params request, std::pmr::memory_resource *mr = std::pmr::get_default_resource())
	  -> boost::capy::task<result<ldap::search_stream>>;
	auto compare(compare_params request) -> boost::capy::task<result<bool>>;
	//
	// search() and compare() chase referrals as client_options::referrals
	// says (see "Referrals" in the header comment); search_stream() never
	// does.

	// search() and compare() with what the chase did: as ldap::chase_search
	// and ldap::chase_compare (referral_chase.hpp) on a shared lease, with
	// client_options::referrals' switches, authorize and limits, and the
	// read forwarders' retry. With follow_references off, the references
	// received are counted in `unlisted` and clear `complete`; with
	// follow_referrals off, a referral result fails the call
	// (errc::referral) as it does search().
	auto chase_search(search_params request, std::pmr::memory_resource *mr = std::pmr::get_default_resource())
	  -> boost::capy::task<result<chased_search>>;
	auto chase_compare(compare_params request) -> boost::capy::task<result<chased_compare>>;

	// Write forwarders: each acquires a shared lease (acquire()), runs the
	// connection's operation of the same name on it, and returns the lease,
	// with the connection's results (connection.hpp). An operation failing
	// with client_errc::not_sent (connection.hpp "Sent or not") is retried
	// once, on another connection: the one it failed on is no longer handed
	// out, and the retry's acquire() goes by priority order. Any other
	// failure is returned as is, and so is the retry's outcome: a lost
	// connection (not_connected, a transport error), a timeout, a server
	// result code (busy and unavailable included, and errc::referral:
	// referrals are never chased, see "Referrals" in the header comment), a
	// cancellation; the update may then have been applied or not. Each
	// acquire() fails as acquire() does; the operations are bounded by their
	// own timeouts, else connection_options::operation_timeout. Each call
	// may land on any pooled connection, so a request control bound to one
	// connection (transaction_specification, anything tied to the session)
	// needs a lease, not the forwarders. Like acquire(), the tasks do not
	// refer to *this.
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

	std::shared_ptr<detail::client_state> state_{};
};

}// namespace jhetz::ldap
