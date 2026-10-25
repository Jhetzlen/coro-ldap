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
//   auto lease = co_await pool.acquire();   // result<ldap::lease>
//   if (!lease) ...                         // every server failed, or acquire_timeout
//   auto people = co_await (*lease)->search({.base = ldap::dn{"ou=people,dc=example,dc=org"}});
//
// Leases share connections. A lease gives the full ldap::connection API on
// one pooled connection, and several leases may use the same connection at
// once: their operations are multiplexed on it (connection.hpp), which is
// why max_connections defaults to 1. acquire() hands out an idle
// connection (no lease) first, then opens a new one while fewer than
// max_connections exist, and only then shares the connection with the
// fewest leases: N connections give N-way isolation (a slow paged search,
// a StartTLS, a long SASL exchange) before any sharing. Because leases
// share, whatever a lease changes on its connection is seen by the others
// sharing it: a bind changes the identity of all of them (the connection is
// then closed once its last lease returns, see "Bind identity" below),
// start_tls() fails with operation_in_progress while another lease has an
// operation outstanding, and unbind() or close() ends the connection for
// everyone. Use a client per identity, and keep binds to session_setup.
//
// Servers and failover: `servers` is in priority order. A new connection
// tries each server whose backoff has ended, in that order. A server that
// fails (connect, StartTLS, or session_setup) is not tried again until a
// backoff delay has passed: full jitter, uniform in [0, d] with d =
// min(backoff.max, backoff.initial * backoff.multiplier^(failures - 1)),
// reset by a success. acquire() waits for the earliest backoff to end, up to
// acquire_timeout, and then fails with the last server's error. A failure
// that retrying cannot fix (cond::auth_failed, cond::invalid_input, e.g.
// wrong credentials or a bad URL) also stops this acquire() from trying that
// server again, so a wrong password costs one bind per server per backoff
// period, not a retry storm (or an Active Directory account lockout). A
// connection to a lower-priority server that is idle, at least
// failback_after old, while a higher-priority server's backoff has ended,
// is closed when acquire() finds it, so the next connection goes back to
// the primary (failing over again if the primary still fails).
//
// Health: there is no background timer (it would keep io_context::run()
// from returning). acquire() drops pooled connections found closed, and
// probes an idle connection unused for longer than idle_check with a root
// DSE base search for the attribute "1.1" (no attributes) before handing it
// out: one that does not answer (a server error is an answer) is closed and
// replaced. A connection older than max_lifetime is closed instead of being
// pooled again when its last lease returns (or when acquire() finds it
// idle).
//
// Bind identity: session_setup runs on every new connection, after connect
// and StartTLS (connection_options::start_tls). The client records the
// connection's bind_count() after it; a lease returned with a different
// count (the caller bound again) gets its connection closed once no lease
// uses it, and no later acquire() hands it out.
//
// Closing: a connection leaving the pool while open is unbound (a detached
// unbind() on the executor) if no lease holds it, else closed. close()
// closes every pooled connection (leased ones included: their operations
// fail with not_connected) and fails later acquire() calls; the destructor
// calls it.
//
// Threading: like connection, a client belongs to the executor of its
// io_context; acquire() and the leases (their connections, their
// destruction) must be used on it. The io_context must outlive the client
// and its leases. A lease may outlive its client: its connection stays
// usable until close() or the lease returns.
#pragma once

#include "jhetz/ldap/connection.hpp"
#include "jhetz/ldap/connection_options.hpp"
#include "jhetz/ldap/dn.hpp"
#include "jhetz/ldap/error.hpp"
#include "jhetz/ldap/sasl.hpp"
#include "jhetz/ldap/url.hpp"

#include <boost/capy/task.hpp>
#include <boost/corosio/io_context.hpp>

#include <chrono>
#include <cstddef>
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
// (see connection::change_password on password memory).
[[nodiscard]] auto simple_bind_setup(dn name, std::string password) -> session_setup;

// Makes a fresh SASL mechanism for each connection (a mechanism holds the
// state of one exchange).
using sasl_mechanism_factory = std::function<std::unique_ptr<sasl_mechanism>()>;

// A session_setup doing sasl_bind(*factory(), name) with a new mechanism
// per connection. A factory returning null fails the setup with
// std::errc::invalid_argument.
[[nodiscard]] auto sasl_bind_setup(sasl_mechanism_factory factory, dn name = {}) -> session_setup;

// The delay before a failed server is tried again (see the header comment).
struct backoff_options
{
	static constexpr std::chrono::milliseconds default_initial{ 100 };
	static constexpr std::chrono::milliseconds default_max{ 30'000 };
	static constexpr double default_multiplier = 2.0;

	std::chrono::milliseconds initial{ default_initial };// cap after the first failure
	std::chrono::milliseconds max{ default_max };// cap for any number of failures
	double multiplier = default_multiplier;// cap growth per failure; below 1 counts as 1
};

// Why a connection left the pool (client_observer::on_disconnect).
enum class disconnect_reason {
	closed,// found closed (the server or an error closed it, or a lease's unbind() or close())
	probe_failed,// the idle check got no answer
	max_lifetime,// older than client_options::max_lifetime
	rebound,// a lease bound it again
	failback,// to a lower-priority server, closed to return to a higher-priority one
	client_closed,// client::close() or the client's destructor
};

// Hooks for metrics and logs; every one does nothing by default. Called on
// the client's executor, synchronously: they must not throw, and should
// not block.
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
	// error (of connect, StartTLS or session_setup).
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
	// (its backoff).
	virtual void on_retry(const url &server, const error &failure, std::chrono::milliseconds delay)
	{
		(void)server;
		(void)failure;
		(void)delay;
	}
	// The idle check of a connection to `server` ended: answered, or not.
	virtual void on_probe(const url &server, const result<void> &outcome)
	{
		(void)server;
		(void)outcome;
	}
	// An acquire() had to wait (for a server's backoff, or for a connection
	// another acquire() was opening or probing) for `waited` in all; called
	// once it ends, successfully or not.
	virtual void on_acquire_wait(std::chrono::milliseconds waited) { (void)waited; }
};

struct client_options
{
	static constexpr std::chrono::milliseconds default_idle_check{ 60'000 };
	static constexpr std::chrono::milliseconds default_acquire_timeout{ 30'000 };
	static constexpr std::chrono::milliseconds default_failback_after{ 300'000 };

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
	// Close a connection this old when its last lease returns; nullopt: no
	// limit.
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
	// Not owned; must outlive the client. Null: none.
	client_observer *observer = nullptr;
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
}// namespace detail

// The use of one pooled connection, until the lease is destroyed,
// reassigned or released. Not exclusive: other leases may share the
// connection (see the header comment). Destroy it on the client's executor.
class lease
{
  public:
	lease() noexcept = default;
	lease(lease &&other) noexcept = default;
	auto operator=(lease &&other) noexcept -> lease &;
	lease(const lease &) = delete;
	auto operator=(const lease &) -> lease & = delete;
	~lease();

	// False for a default-constructed, moved-from or released lease.
	explicit operator bool() const noexcept { return conn_ != nullptr; }
	// The connection. Precondition: *this is true.
	[[nodiscard]] auto get() const noexcept -> connection &;
	auto operator*() const noexcept -> connection & { return get(); }
	auto operator->() const noexcept -> connection * { return &get(); }
	// The server the connection goes to. Precondition: *this is true.
	[[nodiscard]] auto server() const noexcept -> const url &;
	// Returns the connection to the pool now (the destructor's job).
	void release() noexcept;

  private:
	friend class client;
	friend struct detail::client_state;
	lease(std::shared_ptr<detail::client_state> state, std::shared_ptr<detail::pooled_connection> conn) noexcept;

	std::shared_ptr<detail::client_state> state_{};
	std::shared_ptr<detail::pooled_connection> conn_{};
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

	// A lease on a pooled connection: an idle one (probed first if unused for
	// longer than idle_check), else a new one while fewer than
	// max_connections exist, else the open one with the fewest leases (see
	// the header comment). Waits at most acquire_timeout. Fails with the
	// last server's error (its context names the server: "acquire
	// ldap://ldap1.example.org: ..."), capy::error::timeout when it waited
	// for other acquires that long, capy::error::canceled if the task's stop
	// token is set, and client_errc::not_connected once close() was called
	// (or on a moved-from client).
	auto acquire() -> boost::capy::task<result<lease>>;

	// Connections in the pool, open or being closed once their last lease
	// returns (not those still being opened). For tests and diagnostics.
	[[nodiscard]] auto connections() const noexcept -> std::size_t;

	// Closes every pooled connection and fails later and waiting acquire()
	// calls with not_connected. Idempotent.
	void close() noexcept;

  private:
	friend void detail::set_jitter(const client &, std::function<double()>);

	std::shared_ptr<detail::client_state> state_{};
};

}// namespace jhetz::ldap
