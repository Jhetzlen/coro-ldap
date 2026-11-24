// ldap::client: a pool of multiplexed connections with failover, backoff,
// session setup and health checks (docs/API.md, DESIGN.md section 11).
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

// Prepares each new connection before it is pooled, after connect and
// StartTLS; a failure fails that connection attempt.
using session_setup = std::function<boost::capy::task<result<void>>(connection &)>;

// Simple bind with `name` and `password`; both empty: anonymous.
[[nodiscard]] auto simple_bind_setup(dn name, std::string password) -> session_setup;

// Makes a fresh SASL mechanism for each connection.
using sasl_mechanism_factory = std::function<std::unique_ptr<sasl_mechanism>()>;

// SASL bind with a new mechanism per connection; a null one fails with
// std::errc::invalid_argument.
[[nodiscard]] auto sasl_bind_setup(sasl_mechanism_factory factory, dn name = {}) -> session_setup;

// Does nothing: the connection keeps its transport's identity (the TLS
// client certificate, if any).
[[nodiscard]] auto no_bind_setup() -> session_setup;

// The delay before a failed server is tried again.
struct backoff_options
{
	static constexpr std::chrono::milliseconds default_initial{ 100 };
	static constexpr std::chrono::milliseconds default_max{ 30'000 };
	static constexpr double default_multiplier = 2.0;

	static constexpr std::chrono::milliseconds default_auth_failure_min{ 5'000 };

	std::chrono::milliseconds initial{ default_initial };
	std::chrono::milliseconds max{ default_max };
	double multiplier = default_multiplier;// below 1 counts as 1
	// Minimum backoff after an authentication failure.
	std::chrono::milliseconds auth_failure_min{ default_auth_failure_min };
};

enum class disconnect_reason {
	closed,// found closed or being unbound
	probe_failed,
	max_lifetime,
	rebound,// a lease bound it again
	failback,// an idle connection to a lower-priority server
	client_closed,
	// retired after busy or unavailable, the operation retried elsewhere
	busy_or_unavailable,
};

// Metrics and logging hooks, no-ops by default, called synchronously on the
// client's executor; they must not throw. None runs after close() returned.
class client_observer
{
  public:
	client_observer() = default;
	client_observer(const client_observer &) = default;
	client_observer(client_observer &&) = default;
	auto operator=(const client_observer &) -> client_observer & = default;
	auto operator=(client_observer &&) -> client_observer & = default;
	virtual ~client_observer() = default;

	// A connection attempt to `server` ended (connect, StartTLS, setup).
	virtual void on_connect(const url &server, const result<void> &outcome)
	{
		(void)server;
		(void)outcome;
	}
	virtual void on_disconnect(const url &server, disconnect_reason reason)
	{
		(void)server;
		(void)reason;
	}
	// `server` failed and backs off for `delay`.
	virtual void on_retry(const url &server, const error &failure, std::chrono::milliseconds delay)
	{
		(void)server;
		(void)failure;
		(void)delay;
	}
	// The idle check of a connection to `server` ended.
	virtual void on_probe(const url &server, const result<void> &outcome)
	{
		(void)server;
		(void)outcome;
	}
	// An acquire() waited `waited` in all.
	virtual void on_acquire_wait(std::chrono::milliseconds waited) { (void)waited; }
	// A chase decided the fate of one referral or reference URI.
	virtual void on_referral(const url &server, const referral_attempt &attempt)
	{
		(void)server;
		(void)attempt;
	}
};

// A referred server a chase would contact. `target` is as the server sent
// it (host not lowercased nor in ASCII form, see docs/API.md).
struct referral_hop
{
	url target{};
	std::size_t depth = 1;// 1: returned by the pooled connection's server
	url origin{};// lease::server()
};

enum class referral_binding : std::uint8_t {
	refuse,// the URI is skipped (referral_outcome::skipped_policy)
	// Connected, not bound, without the client's TLS certificate.
	anonymous,
	// Connected and set up with client_options::setup and its TLS certificate.
	same_setup,
};

// Decides for each referred server, on the client's executor.
using referral_authorizer = std::function<referral_binding(const referral_hop &hop)>;

// same_setup for the hosts of `domains` (and their subdomains), refusal for
// the others, by make_same_policy_connector's allow-list rules. Empty:
// refuses everything.
[[nodiscard]] auto same_setup_for_domains(std::vector<std::string> domains) -> referral_authorizer;

// Referral chasing by search() and compare(); off by default.
struct referral_options
{
	// Referral results of search() and compare() (RFC 4511 section 4.1.10).
	bool follow_referrals = false;
	// Continuation references of search() (RFC 4511 section 4.5.3).
	bool follow_references = false;
	// Empty: no server is contacted.
	referral_authorizer authorize{};
	referral_policy limits{};
};

struct client_options
{
	static constexpr std::chrono::milliseconds default_idle_check{ 60'000 };
	static constexpr std::chrono::milliseconds default_acquire_timeout{ 30'000 };
	static constexpr std::chrono::milliseconds default_failback_after{ 300'000 };
	static constexpr std::chrono::milliseconds default_probe_timeout{ 5'000 };

	// In priority order.
	std::vector<url> servers{};
	// Server URL text, parsed with url::parse_server() when the client is
	// built; tried after `servers`, in priority order.
	std::vector<std::string> server_urls{};
	connection_options connection{};
	// Empty: anonymous connections.
	session_setup setup{};
	// At least 1.
	std::size_t max_connections = 1;
	// Probe an idle connection unused for longer than this; nullopt: never.
	std::optional<std::chrono::milliseconds> idle_check{ default_idle_check };
	// Bounds the idle check.
	std::chrono::milliseconds probe_timeout{ default_probe_timeout };
	// Age after which a connection is no longer handed out; nullopt: no limit.
	std::optional<std::chrono::milliseconds> max_lifetime{};
	// Bounds each acquire().
	std::chrono::milliseconds acquire_timeout{ default_acquire_timeout };
	backoff_options backoff{};
	// Age of an idle connection to a lower-priority server before acquire()
	// closes it to return to a higher-priority one.
	std::chrono::milliseconds failback_after{ default_failback_after };
	// Not owned; null: none.
	client_observer *observer = nullptr;
	referral_options referrals{};
};

class client;

namespace detail {
	struct client_state;
	struct pooled_connection;

	// unit * min(max, initial * multiplier^(failures - 1)), unit in [0, 1].
	[[nodiscard]] auto backoff_delay(const backoff_options &options, std::size_t failures, double unit) noexcept
	  -> std::chrono::milliseconds;

	struct test_access;

	// ldap::search_paged(client &): the first page on a shared lease, retried
	// as client::search_stream() is.
	auto search_paged_of(const client &c,
	  search_params request,
	  std::int32_t page_size,
	  std::size_t max_pages,
	  std::pmr::memory_resource *mr) -> boost::capy::task<result<paged_search>>;
}// namespace detail

namespace detail {
	// The hold on one pooled connection that lease and exclusive_lease share.
	class lease_base
	{
	  public:
		lease_base(const lease_base &) = delete;
		auto operator=(const lease_base &) -> lease_base & = delete;

		// False for a default-constructed, moved-from or released lease.
		explicit operator bool() const noexcept { return conn_ != nullptr; }
		// Precondition: *this is true.
		[[nodiscard]] auto server() const noexcept -> const url &;
		// Returns the connection to the pool now.
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

// A shared use of one pooled connection (client::acquire()). Binds,
// start_tls, unbind and close affect every lease sharing it.
class lease : public detail::lease_base
{
  public:
	lease() noexcept = default;
	lease(lease &&other) noexcept = default;
	auto operator=(lease &&other) noexcept -> lease & = default;
	lease(const lease &) = delete;
	auto operator=(const lease &) -> lease & = delete;
	~lease() = default;

	// Precondition: *this is true.
	[[nodiscard]] auto get() const noexcept -> connection & { return pooled(); }
	auto operator*() const noexcept -> connection & { return pooled(); }
	auto operator->() const noexcept -> connection * { return &pooled(); }

  private:
	friend struct detail::client_state;
	lease(std::shared_ptr<detail::client_state> state, std::shared_ptr<detail::pooled_connection> conn) noexcept;
};

// The exclusive use of one pooled connection (client::acquire_exclusive()).
class exclusive_lease : public detail::lease_base
{
  public:
	exclusive_lease() noexcept = default;
	exclusive_lease(exclusive_lease &&other) noexcept = default;
	auto operator=(exclusive_lease &&other) noexcept -> exclusive_lease & = default;
	exclusive_lease(const exclusive_lease &) = delete;
	auto operator=(const exclusive_lease &) -> exclusive_lease & = delete;
	~exclusive_lease() = default;

	// Precondition: *this is true.
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
	using executor_type = connection::executor_type;

	// Opens nothing yet; connections' state is allocated from `mr`.
	client(boost::corosio::io_context &ioc,
	  client_options options,
	  std::pmr::memory_resource *mr = std::pmr::get_default_resource());
	client(client &&other) noexcept = default;
	auto operator=(client &&other) noexcept -> client &;
	client(const client &) = delete;
	auto operator=(const client &) -> client & = delete;
	~client();

	// Precondition: not moved from.
	[[nodiscard]] auto executor() const noexcept -> executor_type;

	// A shared lease: an idle connection, else a new one, else the open one
	// with the fewest leases. The task does not refer to *this.
	auto acquire() -> boost::capy::task<result<lease>>;
	// A lease on a connection no other lease shares while it is held.
	auto acquire_exclusive() -> boost::capy::task<result<exclusive_lease>>;

	// Read forwarders: run the operation on a shared lease, retried once on
	// another connection after cond::connection_lost or
	// cond::busy_or_unavailable. The tasks do not refer to *this.
	auto search(search_params request, std::pmr::memory_resource *mr = std::pmr::get_default_resource())
	  -> boost::capy::task<result<search_result>>;
	// Retried only if it fails before its first message; the stream holds the
	// lease until destroyed.
	auto search_stream(search_params request, std::pmr::memory_resource *mr = std::pmr::get_default_resource())
	  -> boost::capy::task<result<ldap::search_stream>>;
	auto compare(compare_params request) -> boost::capy::task<result<compare_result>>;

	// Write forwarders: retried once only after client_errc::not_sent. The
	// tasks do not refer to *this.
	auto add(add_params request) -> boost::capy::task<result<response>>;
	auto modify(modify_params request) -> boost::capy::task<result<response>>;
	auto del(del_params request) -> boost::capy::task<result<response>>;
	auto modify_dn(modify_dn_params request) -> boost::capy::task<result<response>>;
	// Any extended operation but StartTLS, as a write forwarder; a referral
	// result is an error, never chased.
	auto extended(extended_params request) -> boost::capy::task<result<extended_result>>;

	// Pooled connections, open or retired (not those being opened).
	[[nodiscard]] auto connections() const noexcept -> std::size_t;

	// Closes every pooled connection, stops attempts in progress and fails
	// acquire() calls with not_connected. Idempotent.
	void close() noexcept;

  private:
	friend struct detail::test_access;
	friend auto
	  detail::search_paged_of(const client &, search_params, std::int32_t, std::size_t, std::pmr::memory_resource *)
		-> boost::capy::task<result<paged_search>>;

	std::shared_ptr<detail::client_state> state_{};
};

}// namespace jhetz::ldap
