#include "jhetz/ldap/client.hpp"

#include "jhetz/ldap/cancel.hpp"

#include "../connection/referral_chase_impl.hpp"
#include "../connection/search.hpp"
#include "../format_util.hpp"
#include "../net/deadline.hpp"
#include "../scope_util.hpp"
#include "../strand_util.hpp"
#include "lease_retry.hpp"

#include <boost/capy/cond.hpp>
#include <boost/capy/error.hpp>
#include <boost/capy/ex/async_event.hpp>
#include <boost/capy/ex/run_async.hpp>
#include <boost/capy/ex/this_coro.hpp>
#include <boost/corosio/timeout.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <initializer_list>
#include <memory>
#include <memory_resource>
#include <optional>
#include <random>
#include <stop_token>
#include <string>
#include <string_view>
#include <system_error>
#include <type_traits>
#include <utility>
#include <vector>

namespace capy = boost::capy;
namespace corosio = boost::corosio;

namespace jhetz::ldap {

// ---------------------------------------------------------------- setup helpers

namespace {

	auto sasl_setup_run(connection &c, std::unique_ptr<sasl_mechanism> mechanism, dn name) -> capy::task<result<void>>
	{
		if (mechanism == nullptr) {
			co_return fail(std::make_error_code(std::errc::invalid_argument),
			  "session setup: the SASL mechanism factory returned null");
		}
		co_return co_await c.sasl_bind(*mechanism, std::move(name));
	}

}// namespace

auto simple_bind_setup(dn name, std::string password) -> session_setup
{
	return [name = std::move(name), password = std::move(password)](
			 connection &c) -> capy::task<result<void>> { return c.simple_bind(name, password); };
}

auto sasl_bind_setup(sasl_mechanism_factory factory, dn name) -> session_setup
{
	return [factory = std::move(factory), name = std::move(name)](connection &c) -> capy::task<result<void>> {
		return sasl_setup_run(c, factory ? factory() : nullptr, name);
	};
}

auto no_bind_setup() -> session_setup
{
	return [](connection &) -> capy::task<result<void>> { co_return result<void>{}; };
}

auto same_setup_for_domains(std::vector<std::string> domains) -> referral_authorizer
{
	return [domains = std::move(domains)](const referral_hop &hop) {
		std::optional<std::uint16_t> origin_port;
		if (hop.origin.scheme() != url_scheme::ldapi) {
			origin_port = hop.origin.port_or_default();
		}
		return detail::referral_server_allowed(hop.target, domains, origin_port) ? referral_binding::same_setup
																				 : referral_binding::refuse;
	};
}

// ---------------------------------------------------------------- state

namespace detail {

	using clock = std::chrono::steady_clock;
	using std::chrono::milliseconds;

	auto backoff_delay(const backoff_options &options, std::size_t failures, double unit) noexcept -> milliseconds
	{
		const auto max = static_cast<double>(std::max<milliseconds::rep>(0, options.max.count()));
		double cap = std::min(static_cast<double>(std::max<milliseconds::rep>(0, options.initial.count())), max);
		const double multiplier = std::max(1.0, options.multiplier);// NaN gives 1
		for (std::size_t i = 1; i < failures && cap < max && cap > 0.0 && multiplier > 1.0; ++i) {
			cap = std::min(cap * multiplier, max);
		}
		if (!(unit >= 0.0)) {// NaN too
			unit = 0.0;
		}
		unit = std::min(unit, 1.0);
		return milliseconds(static_cast<milliseconds::rep>(cap * unit));
	}

	auto client_referral_identity(referral_binding binding, const session_setup &client_setup)
	  -> std::optional<referral_identity>
	{
		switch (binding) {
		case referral_binding::anonymous:
			return referral_identity{ .identity = 0 };
		case referral_binding::same_setup:
			return referral_identity{ .identity = 1, .setup = client_setup, .client_certificate = true };
		case referral_binding::refuse:
			break;
		}
		return std::nullopt;
	}

	// One connection of the pool.
	struct pooled_connection
	{
		connection conn{};
		std::size_t server = 0;// index in client_state::servers
		// Leases holding it, plus an acquire() probing it.
		std::size_t leases = 0;
		clock::time_point created{};
		clock::time_point last_used{};// set up, or its last lease returned
		std::uint64_t binds = 0;// conn.bind_count() after the session setup
		// Set: never handed out again, not counted against max_connections, and
		// dropped once no lease holds it.
		std::optional<disconnect_reason> retired{};
		bool probing = false;
		bool exclusive = false;// held by an exclusive lease
	};

	struct server_state
	{
		url address;
		std::string name;// address as text, for error contexts
		std::size_t failures = 0;// failure episodes since the last success
		clock::time_point retry_at{};// not tried before (its backoff)
		std::optional<error> last_error{};
		// Failure episodes recorded; concurrent attempts failing together count
		// once.
		std::uint64_t episode = 0;
		// Authentication failures recorded; an acquire() seeing it change
		// stops trying the server.
		std::uint64_t auth_failures = 0;
		// The backoff follows an authentication failure (last_error): new
		// acquires fail with it at once until retry_at.
		bool auth_backoff = false;
		// The one attempt let through once that backoff ended is running:
		// other acquires fail with last_error meanwhile.
		bool auth_retrying = false;
	};

	struct client_state
	{
		client_state(corosio::io_context &io, client_options o, std::pmr::memory_resource *memory)
		  : ioc(&io), strand(io.get_executor()), options(std::move(o)), mr(memory), rng(std::random_device{}())
		{
			servers.reserve(options.servers.size());
			for (const auto &u : options.servers) {
				servers.push_back({ .address = u, .name = std::string(std::string_view(u.to_string())) });
				if (auto r = u.check_server(); !r && !bad_server) {
					bad_server = detail::with_context(std::move(r.error()),
					  detail::format(
						"acquire: client_options::servers[{}] {}", servers.size() - 1, servers.back().name));
				}
			}
		}

		corosio::io_context *ioc;
		// Everything below is used on it.
		client::executor_type strand;
		client_options options;
		std::pmr::memory_resource *mr;
		std::vector<server_state> servers{};
		// The first entry of options.servers check_server() refuses.
		std::optional<error> bad_server{};
		std::vector<std::shared_ptr<pooled_connection>> pool{};
		std::atomic<std::size_t> pool_size = 0;// pool.size(), for client::connections() on any thread
		std::size_t opening = 0;// connection attempts in progress (they count against max_connections)
		// Their stop sources (copies share the stop state): close() stops them.
		std::vector<std::stop_source> attempts{};
		// Those of the referral chases running: close() stops them too.
		std::vector<std::stop_source> chases_running{};
		// Exclusive acquires waiting: shared ones leave idle connections to them.
		std::size_t exclusive_waiting = 0;
		// Set on every change an acquire() may wait for; `version` counts them.
		capy::async_event changed{};
		std::uint64_t version = 0;
		bool closed = false;
		std::minstd_rand rng;
		std::function<double()> jitter{};// tests: replaces rng
		pool_connector connector{};// tests: replaces ldap::connect

		// ---------------------------------------------------------------- events

		void notify() noexcept
		{
			pool_size.store(pool.size(), std::memory_order_relaxed);
			++version;
			changed.set();
		}

		// Null once close() has run.
		[[nodiscard]] auto observer() const noexcept -> client_observer * { return options.observer; }

		// ---------------------------------------------------------------- servers

		auto jitter_unit() -> double
		{
			if (jitter) {
				return jitter();
			}
			return std::uniform_real_distribution<double>(0.0, 1.0)(rng);
		}

		// try_servers()' attempt on server `i` ended; `settled`: server_failed() or
		// server_succeeded() handled it.
		void attempt_ended(std::size_t i, bool auth_retry, bool settled) noexcept
		{
			--opening;
			if (auth_retry) {
				servers[i].auth_retrying = false;
				if (!settled) {
					restart_auth_backoff(i);
				}
			}
			notify();
		}

		// Server `i` failed with `e` in an attempt begun at `episode`.
		void server_failed(std::size_t i, const error &e, std::uint64_t episode, bool auth_retry)
		{
			auto &s = servers[i];
			const bool auth_failed = e.code == cond::auth_failed;
			// An auth retry ended without a verdict: the authentication backoff starts
			// again, its stored error and auth_failures unchanged.
			const bool unproven = auth_retry && !auth_failed && s.auth_backoff;
			const bool auth = auth_failed || unproven;
			// After a success (failures reset) any failure counts.
			if (s.failures != 0 && s.episode != episode && (!auth || s.auth_backoff)) {
				return;// a concurrent attempt recorded this failure already
			}
			// What may throw goes first, leaving the counts unchanged on a throw.
			const double unit = jitter_unit();
			if (!unproven) {
				s.last_error = e;
			}
			++s.episode;
			++s.failures;
			const milliseconds delay =
			  auth ? auth_delay(s.failures, unit) : backoff_delay(options.backoff, s.failures, unit);
			if (auth_failed) {
				++s.auth_failures;
			}
			s.retry_at = clock::now() + delay;
			s.auth_backoff = auth;
			if (auto *o = observer()) {
				// Unproven: report the stored authentication error.
				o->on_retry(s.address, unproven && s.last_error ? *s.last_error : e, delay);
			}
		}

		// Backoff after an authentication failure: at least half the cap and
		// auth_failure_min.
		[[nodiscard]] auto auth_delay(std::size_t failures, double unit) const noexcept -> milliseconds
		{
			constexpr double half = 0.5;
			return std::max(
			  options.backoff.auth_failure_min, backoff_delay(options.backoff, failures, half + (half * unit)));
		}

		// An auth retry left unsettled by a destroyed task: restarts the backoff,
		// noexcept, without an observer hook.
		void restart_auth_backoff(std::size_t i) noexcept
		{
			auto &s = servers[i];
			if (!s.auth_backoff) {
				return;
			}
			double unit = 1.0;
			try {
				unit = jitter_unit();
			} catch (...) {
				unit = 1.0;// the jitter source failed: the longest delay
			}
			++s.episode;
			++s.failures;
			s.retry_at = clock::now() + auth_delay(s.failures, unit);
		}

		void server_succeeded(std::size_t i) noexcept
		{
			auto &s = servers[i];
			++s.episode;// attempts begun before it do not join a later failure's episode
			s.failures = 0;
			s.retry_at = {};
			s.last_error.reset();
			s.auth_backoff = false;
		}

		[[nodiscard]] auto auth_failure_counts() const -> std::vector<std::uint64_t>
		{
			std::vector<std::uint64_t> counts;
			counts.reserve(servers.size());
			for (const auto &s : servers) {
				counts.push_back(s.auth_failures);
			}
			return counts;
		}

		// Excludes the servers that failed to authenticate since `seen`, are
		// backing off after that, or are running their one retry; `last` becomes
		// the stored error.
		void exclude_auth_failures(std::vector<bool> &excluded,
		  const std::vector<std::uint64_t> &seen,
		  std::optional<error> &last,
		  clock::time_point now) const
		{
			for (std::size_t i = 0; i < servers.size(); ++i) {
				const auto &s = servers[i];
				if (excluded[i] || !s.auth_backoff || !s.last_error
					|| (s.auth_failures == seen[i] && s.retry_at <= now && !s.auth_retrying)) {
					continue;
				}
				excluded[i] = true;
				last = *s.last_error;
				last->context += " (backing off after an authentication failure)";
			}
		}

		// The earliest end of a backoff among the servers not excluded.
		[[nodiscard]] auto next_retry(const std::vector<bool> &excluded) const -> std::optional<clock::time_point>
		{
			std::optional<clock::time_point> next;
			for (std::size_t i = 0; i < servers.size(); ++i) {
				if (!excluded[i] && (!next || servers[i].retry_at < *next)) {
					next = servers[i].retry_at;
				}
			}
			return next;
		}

		// A slot is free and a server not excluded (nor `skip`) may be tried now.
		[[nodiscard]] auto can_open(const std::vector<bool> &excluded,
		  clock::time_point now,
		  std::optional<std::size_t> skip = std::nullopt) const noexcept -> bool
		{
			if (!has_free_slot()) {
				return false;
			}
			for (std::size_t i = 0; i < servers.size(); ++i) {
				if (!excluded[i] && i != skip && servers[i].retry_at <= now && !servers[i].auth_retrying) {
					return true;
				}
			}
			return false;
		}

		// The error of the server not excluded whose backoff ends first,
		// among those backing off after a failure; nullopt if none is.
		[[nodiscard]] auto backoff_error(const std::vector<bool> &excluded, clock::time_point now) const
		  -> std::optional<error>
		{
			const server_state *first = nullptr;
			for (std::size_t i = 0; i < servers.size(); ++i) {
				const auto &s = servers[i];
				if (excluded[i] || !s.last_error || s.retry_at <= now) {
					continue;
				}
				if (first == nullptr || s.retry_at < first->retry_at) {
					first = &s;
				}
			}
			if (first == nullptr || !first->last_error) {
				return std::nullopt;
			}
			error e = *first->last_error;
			e.context += " (backing off: acquire_timeout ends first)";
			return e;
		}

		// Whether an attempt cut short by `deadline` is excused: it began with less
		// than half of acquire_timeout left.
		[[nodiscard]] auto begun_late(net::detail::deadline_t deadline, clock::time_point begun) const noexcept -> bool
		{
			return deadline && (*deadline - begun) * 2 < options.acquire_timeout;
		}

		// ---------------------------------------------------------------- pool

		[[nodiscard]] auto expired(const pooled_connection &c, clock::time_point now) const noexcept -> bool
		{
			return options.max_lifetime && now - c.created >= *options.max_lifetime;
		}

		[[nodiscard]] auto retire_reason(const pooled_connection &c, clock::time_point now) const noexcept
		  -> std::optional<disconnect_reason>
		{
			if (!detail::accepts_requests(c.conn)) {// closed, or being unbound
				return disconnect_reason::closed;
			}
			if (c.conn.bind_count() != c.binds) {// bound again, or binding
				return disconnect_reason::rebound;
			}
			if (expired(c, now)) {
				return disconnect_reason::max_lifetime;
			}
			return std::nullopt;
		}

		// Connections counting against max_connections: those not retired,
		// and those being opened.
		[[nodiscard]] auto live() const noexcept -> std::size_t
		{
			return opening
				   + static_cast<std::size_t>(std::ranges::count_if(pool, [](const auto &c) { return !c->retired; }));
		}

		[[nodiscard]] auto has_free_slot() const noexcept -> bool { return live() < options.max_connections; }

		// When the first connection that may be handed out passes
		// max_lifetime: acquire() waiting for a slot looks again then.
		[[nodiscard]] auto next_expiry() const noexcept -> std::optional<clock::time_point>
		{
			std::optional<clock::time_point> next;
			if (!options.max_lifetime) {
				return next;
			}
			for (const auto &c : pool) {
				if (!c->retired && (!next || c->created + *options.max_lifetime < *next)) {
					next = c->created + *options.max_lifetime;
				}
			}
			return next;
		}

		// Ends a connection that left the pool: unbound if open and unleased (a
		// detached task), else closed; closed once the io_context is stopped.
		void shut_down(pooled_connection &c) const noexcept
		{
			if (!c.conn.is_open()) {
				return;
			}
			if (c.leases != 0 || ioc->stopped()) {
				c.conn.close();
				return;
			}
			try {
				capy::run_async(ioc->get_executor())(unbind_detached(std::move(c.conn)));
			} catch (...) {// out of memory for the task: just close
				c.conn.close();
			}
		}

		static auto unbind_detached(connection c) -> capy::task<void>
		{
			try {
				(void)co_await c.unbind();
			} catch (...) {// bad_alloc: unbind() closed the connection already
				c.close();
			}
		}

		// Takes `c` out of the pool and ends it.
		void remove(const std::shared_ptr<pooled_connection> &c, disconnect_reason reason) noexcept
		{
			const auto it = std::ranges::find(pool, c);
			if (it == pool.end()) {
				return;
			}
			pool.erase(it);
			if (auto *o = observer()) {
				o->on_disconnect(servers[c->server].address, reason);
			}
			shut_down(*c);
			notify();
		}

		// No acquire() hands `c` out any more; it leaves the pool once no
		// lease holds it.
		void retire(const std::shared_ptr<pooled_connection> &c, disconnect_reason reason) noexcept
		{
			if (!c->retired) {
				c->retired = reason;
				notify();// its slot is free
			}
			if (c->leases == 0) {
				remove(c, *c->retired);
			}
		}

		// Retires what must not be handed out again and drops retired, unleased
		// connections.
		void prune(clock::time_point now) noexcept
		{
			const auto all = pool;// remove() changes `pool`
			for (const auto &c : all) {
				if (!c->retired) {
					if (const auto why = retire_reason(*c, now); why) {
						retire(c, *why);
						continue;
					}
				}
				if (c->retired && c->leases == 0) {
					remove(c, *c->retired);
				}
			}
		}

		// The connection to hand out, or null to open one (or wait). Call prune()
		// first. `avoid`: that server's connections are left out.
		[[nodiscard]] auto pick(bool exclusive,
		  bool openable,
		  clock::time_point now,
		  std::optional<std::size_t> avoid = std::nullopt) const -> std::shared_ptr<pooled_connection>
		{
			std::shared_ptr<pooled_connection> idle;
			std::shared_ptr<pooled_connection> shared;
			for (const auto &c : pool) {
				if (c->retired || c->probing || c->exclusive || c->server == avoid || retire_reason(*c, now)) {
					continue;
				}
				if (c->leases == 0) {
					if (!idle || c->server < idle->server
						|| (c->server == idle->server && c->last_used > idle->last_used)) {
						idle = c;
					}
				} else if (!shared || c->leases < shared->leases) {
					shared = c;
				}
			}
			if (!exclusive && exclusive_waiting != 0) {
				return shared;// the idle one is left to the waiter
			}
			if (idle) {
				return idle;
			}
			if (exclusive || openable) {
				return nullptr;
			}
			return shared;
		}

		// pick() preferring other servers to `avoid`.
		[[nodiscard]] auto pick_avoiding(bool exclusive,
		  const std::vector<bool> &excluded,
		  clock::time_point now,
		  std::optional<std::size_t> avoid) const -> std::shared_ptr<pooled_connection>
		{
			if (avoid) {
				const bool elsewhere = can_open(excluded, now, avoid);
				if (auto c = pick(exclusive, elsewhere, now, avoid); c || elsewhere) {
					return c;
				}
			}
			return pick(exclusive, can_open(excluded, now), now);
		}

		// `c` (idle) is to a lower-priority server, failback_after old, and a
		// higher-priority server may be tried.
		[[nodiscard]] auto should_fail_back(const pooled_connection &c,
		  const std::vector<bool> &excluded,
		  clock::time_point now,
		  std::optional<std::size_t> avoid) const noexcept -> bool
		{
			if (c.leases != 0 || c.server == 0 || now - c.created < options.failback_after) {
				return false;
			}
			for (std::size_t i = 0; i < c.server; ++i) {
				if (!excluded[i] && i != avoid && servers[i].retry_at <= now) {
					return true;
				}
			}
			return false;
		}

		[[nodiscard]] auto needs_probe(const pooled_connection &c, clock::time_point now) const noexcept -> bool
		{
			return c.leases == 0 && options.idle_check && now - c.last_used >= *options.idle_check;
		}

		// A lease returned.
		void release(const std::shared_ptr<pooled_connection> &c) noexcept
		{
			--c->leases;
			if (c->leases == 0) {
				c->exclusive = false;
			}
			const auto now = clock::now();
			c->last_used = now;
			if (closed || std::ranges::find(pool, c) == pool.end()) {
				return;
			}
			if (!c->retired) {
				c->retired = retire_reason(*c, now);
			}
			if (c->retired && c->leases == 0) {
				remove(c, *c->retired);
			}
			notify();
		}

		void close() noexcept
		{
			if (closed) {
				return;
			}
			closed = true;
			const auto all = std::move(pool);
			pool.clear();
			for (const auto &c : all) {
				c->retired = disconnect_reason::client_closed;
				if (auto *o = observer()) {
					o->on_disconnect(servers[c->server].address, disconnect_reason::client_closed);
				}
				shut_down(*c);
			}
			// Stop the connection attempts in progress: waiting acquires fail
			// at once.
			// NOLINTNEXTLINE(misc-const-correctness): request_stop() is non-const in the standard (MSVC)
			for (auto &attempt : std::exchange(attempts, {})) {
				attempt.request_stop();
			}
			// And the referral chases: no referred server is asked about,
			// connected to or set up once the client is closed.
			// NOLINTNEXTLINE(misc-const-correctness): request_stop() is non-const in the standard (MSVC)
			for (auto &chase : std::exchange(chases_running, {})) {
				chase.request_stop();
			}
			// The observer need only outlive close(): no hook runs after it.
			options.observer = nullptr;
			notify();
		}

		// ---------------------------------------------------------------- tasks

		// Connect, StartTLS (by connect, per the options) and the setup.
		static auto connect_and_set_up(std::shared_ptr<client_state> self, std::size_t i)
		  -> capy::task<result<connection>>
		{
			auto c =
			  self->connector
				? co_await self->connector(*self->ioc, self->servers[i].address, self->options.connection, self->mr)
				: co_await ldap::connect(*self->ioc, self->servers[i].address, self->options.connection, self->mr);
			if (!c) {
				co_return std::unexpected(std::move(c.error()));
			}
			if (self->options.setup) {
				auto s = co_await self->options.setup(*c);
				if (!s) {
					c->close();
					co_return std::unexpected(detail::with_context(std::move(s.error()), "session setup"));
				}
			}
			co_return std::move(*c);
		}

		// connect_and_set_up within `deadline`, stopped by close().
		// `cut_short`: set if the deadline ended it.
		static auto
		  open_one(std::shared_ptr<client_state> self, std::size_t i, net::detail::deadline_t deadline, bool &cut_short)
			-> capy::task<result<connection>>
		{
			const std::stop_source stop;
			self->attempts.push_back(stop);
			const scope_exit unregister{ [&self, &stop] noexcept { std::erase(self->attempts, stop); } };
			auto attempt = with_stop(stop.get_token(), connect_and_set_up(self, i));
			if (!deadline) {
				co_return co_await std::move(attempt);
			}
			auto [ec, r] = co_await corosio::timeout(raceable(std::move(attempt)), *deadline);
			if (ec) {// the deadline, or the acquire's own stop token
				cut_short = ec == capy::cond::timeout;
				co_return fail(ec, cut_short ? "acquire_timeout expired" : "acquire");
			}
			co_return std::move(r);
		}

		// Tells waiting acquires when `c` closes, whatever closes it.
		static void watch_close(const std::shared_ptr<client_state> &self, connection &c) noexcept
		{
			detail::set_close_hook(c, [state = std::weak_ptr<client_state>(self)] noexcept {
				if (auto s = state.lock()) {
					const client::executor_type strand = s->strand;
					detail::run_on_strand(strand, [s = std::move(s)] noexcept { s->notify(); });
				}
			});
		}

		// The k-th server try_servers() tries: priority order, `avoid` last.
		[[nodiscard]] static auto
		  nth_server(std::size_t k, std::size_t count, std::optional<std::size_t> avoid) noexcept -> std::size_t
		{
			if (!avoid) {
				return k;
			}
			if (k + 1 == count) {
				return *avoid;
			}
			return k < *avoid ? k : k + 1;
		}

		// try_servers()' new connection to server `i`, pooled with one lease
		// (exclusive or not). Fails if on_connect closed the client.
		static auto adopt(const std::shared_ptr<client_state> &self,
		  std::size_t i,
		  connection conn,
		  bool exclusive,
		  const std::string &context) -> result<std::shared_ptr<pooled_connection>>
		{
			auto p = std::make_shared<pooled_connection>();
			p->conn = std::move(conn);
			p->server = i;
			p->leases = 1;
			p->created = clock::now();
			p->last_used = p->created;
			p->binds = p->conn.bind_count();
			p->exclusive = exclusive;
			watch_close(self, p->conn);
			self->pool.push_back(p);
			self->pool_size.store(self->pool.size(), std::memory_order_relaxed);
			if (auto *o = self->observer()) {
				o->on_connect(self->servers[i].address, result<void>{});
			}
			if (self->closed) {// closed by the hook: close() closed `p` too
				return fail(client_errc::not_connected, context + ": client closed");
			}
			return p;
		}

		// try_servers()' attempt on server `i` failed with `e`, the
		// server's failure: on_connect, then server_failed().
		void connect_failed(std::size_t i, const error &e, std::uint64_t episode, bool auth_retry)
		{
			if (auto *o = observer()) {
				o->on_connect(servers[i].address, std::unexpected(e));
			}
			server_failed(i, e, episode, auth_retry);
		}

		// One pass over the servers whose backoff has ended, `avoid` last: the
		// connection pooled with one lease, or null (`last` is then the last
		// failure). Fails only when the client closed or the task stopped.
		static auto try_servers(std::shared_ptr<client_state> self,
		  net::detail::deadline_t deadline,
		  bool exclusive,
		  std::vector<bool> &excluded,
		  std::optional<error> &last,
		  std::optional<std::size_t> avoid) -> capy::task<result<std::shared_ptr<pooled_connection>>>
		{
			const std::size_t count = self->servers.size();
			for (std::size_t k = 0; k < count; ++k) {
				const std::size_t i = nth_server(k, count, avoid);
				if (self->closed) {// an observer hook may close the client
					co_return fail(client_errc::not_connected, "acquire: client closed");
				}
				const auto now = clock::now();
				if (deadline && now >= *deadline) {
					co_return nullptr;
				}
				auto &server = self->servers[i];
				if (excluded[i] || server.retry_at > now || server.auth_retrying) {
					continue;
				}
				// The avoided server comes last; a pooled connection pick_avoiding() would
				// now hand out serves instead.
				if (i == avoid && self->pick_avoiding(exclusive, excluded, now, avoid)) {
					co_return nullptr;
				}
				const std::uint64_t episode = server.episode;
				// After an authentication backoff, one attempt only.
				const bool auth_retry = server.auth_backoff;
				server.auth_retrying = auth_retry;
				++self->opening;
				// Set once server_failed() or server_succeeded() handled the attempt; an
				// auth retry left unsettled restarts its backoff.
				bool settled = false;
				const scope_exit done{ [&self, i, auth_retry, &settled] noexcept {
					self->attempt_ended(i, auth_retry, settled);
				} };
				const bool late = self->begun_late(deadline, now);
				bool cut_short = false;
				auto r = co_await open_one(self, i, deadline, cut_short);
				const std::string context = "acquire " + server.name;
				if (self->closed) {
					settled = true;
					if (r) {
						r->close();
					}
					co_return fail(client_errc::not_connected, context + ": client closed");
				}
				if (!r && cut_short && late) {// excused; the deadline passed: nothing more is tried
					last = detail::with_context(std::move(r.error()), context);
					if (auth_retry) {// no on_connect, but the auth backoff starts again
						self->server_failed(i, *last, episode, true);
					}
					settled = true;
					co_return nullptr;
				}
				if (r) {
					self->server_succeeded(i);
					settled = true;
					co_return adopt(self, i, std::move(*r), exclusive, context);
				}
				error e = detail::with_context(std::move(r.error()), context);
				if (e.code == cond::canceled && (co_await capy::this_coro::stop_token).stop_requested()) {
					if (auth_retry) {// no on_connect, but the auth backoff starts again
						self->server_failed(i, e, episode, true);
					}
					settled = true;
					co_return std::unexpected(std::move(e));// not the server's fault
				}
				self->connect_failed(i, e, episode, auth_retry);
				settled = true;
				if (e.code == cond::auth_failed || e.code == cond::invalid_input) {
					excluded[i] = true;// retrying cannot help: not again in this acquire()
				}
				last = std::move(e);
			}
			co_return nullptr;
		}

		// The idle check: a root DSE base search for no attributes, within
		// probe_timeout and `deadline`. `cut_short`: the deadline ended it and it is
		// excused.
		static auto probe(std::shared_ptr<client_state> self,
		  std::shared_ptr<pooled_connection> c,
		  net::detail::deadline_t deadline,
		  bool &cut_short) -> capy::task<result<void>>
		{
			c->probing = true;
			++c->leases;// so that nothing removes it meanwhile
			const scope_exit done{ [&self, &c] noexcept {
				c->probing = false;
				--c->leases;
				self->notify();
			} };
			milliseconds timeout = self->options.probe_timeout;
			bool capped = false;
			const auto begun = clock::now();
			if (deadline) {
				const auto left = std::max(milliseconds(0), std::chrono::ceil<milliseconds>(*deadline - begun));
				capped = left < timeout;
				timeout = std::min(timeout, left);
			}
			auto r = co_await c->conn.search(
			  { .base = dn{}, .scope = search_scope::base_object, .attributes = { "1.1" }, .timeout = timeout });
			if (capped && !r && r.error().code == cond::timeout && self->begun_late(deadline, begun)) {
				cut_short = true;
				co_return std::unexpected(std::move(r.error()));
			}
			result<void> outcome;
			if (!r && r.error().code.category() != result_category()) {
				outcome = std::unexpected(std::move(r.error()));
			}
			if (auto *o = self->observer()) {
				o->on_probe(self->servers[c->server].address, outcome);
			}
			co_return outcome;
		}

		// acquire()'s look at the pool: an error, nullopt (nothing to hand out), a
		// connection with its lease counted, or null to look again.
		static auto from_pool(std::shared_ptr<client_state> self,
		  net::detail::deadline_t deadline,
		  bool exclusive,
		  const std::vector<bool> &excluded,
		  std::optional<std::size_t> avoid) -> capy::task<result<std::optional<std::shared_ptr<pooled_connection>>>>
		{
			using found = std::optional<std::shared_ptr<pooled_connection>>;
			const auto now = clock::now();
			self->prune(now);
			auto c = self->pick_avoiding(exclusive, excluded, now, avoid);
			if (!c) {
				co_return found{};
			}
			if (self->should_fail_back(*c, excluded, now, avoid)) {
				self->retire(c, disconnect_reason::failback);
				co_return found{ nullptr };
			}
			if (self->needs_probe(*c, now)) {
				if (deadline && now >= *deadline) {
					co_return found{};// no time left to probe it: acquire() gives up
				}
				bool cut_short = false;
				auto p = co_await probe(self, c, deadline, cut_short);
				if (cut_short) {
					co_return found{};// no time left: acquire() gives up, the connection stays
				}
				if (!p && p.error().code == cond::canceled && (co_await capy::this_coro::stop_token).stop_requested()) {
					co_return fail(capy::error::canceled, "acquire");// the connection stays
				}
				if (!p) {
					self->retire(c, disconnect_reason::probe_failed);
					co_return found{ nullptr };
				}
				if (self->closed || c->retired || self->retire_reason(*c, clock::now())) {
					co_return found{ nullptr };
				}
			}
			++c->leases;
			c->exclusive = exclusive;
			c->last_used = now;
			co_return found{ std::move(c) };
		}

		// acquire() gives up at its deadline: the last failure, else (if
		// `backing_off`) the error of the server backing off, else a timeout.
		[[nodiscard]] auto give_up(const std::vector<bool> &excluded, std::optional<error> last, bool backing_off) const
		  -> error
		{
			if (last) {
				return std::move(*last);
			}
			if (backing_off) {
				if (auto e = backoff_error(excluded, clock::now()); e) {
					return std::move(*e);
				}
			}
			return make_error(capy::error::timeout, "acquire: no connection ready within acquire_timeout");
		}

		// Waits for notify(), until `until` at most. An error only if stopped.
		auto wait_for_change(std::optional<clock::time_point> until) -> capy::task<std::error_code>
		{
			changed.clear();
			std::error_code ec;
			if (until) {
				auto [e] = co_await corosio::timeout(changed.wait(), *until);
				ec = e;
			} else {
				auto [e] = co_await changed.wait();
				ec = e;
			}
			co_return ec == capy::cond::timeout ? std::error_code{} : ec;
		}

		// The earliest of `times` (nullopt: none).
		[[nodiscard]] static auto earliest(std::initializer_list<std::optional<clock::time_point>> times) noexcept
		  -> std::optional<clock::time_point>
		{
			std::optional<clock::time_point> first;
			for (const auto &t : times) {
				if (t && (!first || *t < *first)) {
					first = t;
				}
			}
			return first;
		}

		// wait_for_change(), counted in exclusive_waiting for an exclusive
		// acquire (until it resumes, or its task is destroyed).
		static auto wait(std::shared_ptr<client_state> self, std::optional<clock::time_point> until, bool exclusive)
		  -> capy::task<std::error_code>
		{
			const std::size_t counted = exclusive ? 1 : 0;
			self->exclusive_waiting += counted;
			const scope_exit done{ [&self, counted] noexcept { self->exclusive_waiting -= counted; } };
			co_return co_await self->wait_for_change(until);
		}

		// Options acquire() cannot work with.
		[[nodiscard]] auto unusable_options() const -> std::optional<error>
		{
			if (servers.empty()) {
				return make_error(client_errc::invalid_url, "acquire: client_options::servers is empty");
			}
			if (bad_server) {
				return bad_server;
			}
			if (options.max_connections == 0) {
				return make_error(
				  std::make_error_code(std::errc::invalid_argument), "acquire: client_options::max_connections is 0");
			}
			return std::nullopt;
		}

		// What open_new() leaves acquire() to do.
		struct opened
		{
			std::shared_ptr<pooled_connection> conn{};// to hand out
			// Every server excluded, but an open connection may be shared
			// (or the idle one left to an exclusive waiter is): look again.
			bool look_again = false;
			// When the earliest backoff ends; nullopt: no slot free, or every server
			// excluded.
			std::optional<clock::time_point> wake{};
		};

		// acquire() found nothing in the pool: try_servers() if a slot is free,
		// else `wake` is when the earliest backoff ends.
		static auto open_new(std::shared_ptr<client_state> self,
		  net::detail::deadline_t deadline,
		  bool exclusive,
		  std::vector<bool> &excluded,
		  std::optional<error> &last,
		  std::optional<std::size_t> avoid) -> capy::task<result<opened>>
		{
			if (!self->has_free_slot()) {
				co_return opened{};
			}
			auto r = co_await try_servers(self, deadline, exclusive, excluded, last, avoid);
			if (!r) {
				co_return std::unexpected(std::move(r.error()));
			}
			if (*r) {
				co_return opened{ .conn = std::move(*r) };
			}
			const auto wake = self->next_retry(excluded);
			if (!wake && (exclusive || (!self->pick(false, false, clock::now()) && !self->waits_for_exclusive()))) {
				co_return std::unexpected(self->give_up(excluded, std::move(last), false));
			}
			co_return opened{ .look_again = !wake && !self->waits_for_exclusive(), .wake = wake };
		}

		// A shared acquire with nothing to share while an idle connection is left
		// to a waiting exclusive acquire: it waits.
		[[nodiscard]] auto waits_for_exclusive() const -> bool
		{
			const auto now = clock::now();
			return exclusive_waiting != 0 && !pick(false, false, now) && pick(true, false, now);
		}

		// `avoid`: a server used only when no other serves; its backoff is
		// untouched.
		template<class Lease>
		static auto acquire(std::shared_ptr<client_state> self, std::optional<std::size_t> avoid = std::nullopt)
		  -> capy::task<result<Lease>>
		{
			constexpr bool exclusive = std::is_same_v<Lease, exclusive_lease>;
			constexpr std::string_view context = "acquire";
			if (auto bad = self->unusable_options(); bad) {
				co_return std::unexpected(std::move(*bad));
			}
			const auto start = clock::now();
			const auto deadline = net::detail::deadline_after(self->options.acquire_timeout, start);
			std::vector<bool> excluded(self->servers.size(), false);
			const auto auth_seen = self->auth_failure_counts();
			std::optional<error> last;
			bool waited = false;
			bool leased = false;
			const scope_exit report{ [&self, &waited, start] noexcept {
				if (auto *o = self->observer(); o != nullptr && waited) {
					o->on_acquire_wait(std::chrono::duration_cast<milliseconds>(clock::now() - start));
				}
			} };
			// An exclusive acquire ending without a lease: the shared ones look again.
			const scope_exit leave{ [&] noexcept {
				if constexpr (exclusive) {
					if (waited && !leased) {
						self->notify();
					}
				}
			} };
			const auto hand_out = [&self, &leased](std::shared_ptr<pooled_connection> c) {
				leased = true;
				return Lease(self, std::move(c));
			};
			while (true) {
				if (self->closed) {
					co_return fail(client_errc::not_connected, "acquire: client closed");
				}
				if ((co_await capy::this_coro::stop_token).stop_requested()) {
					co_return fail(capy::error::canceled, context);
				}
				self->exclude_auth_failures(excluded, auth_seen, last, clock::now());
				const std::uint64_t seen = self->version;
				auto pooled = co_await from_pool(self, deadline, exclusive, excluded, avoid);
				if (!pooled) {
					co_return std::unexpected(std::move(pooled.error()));
				}
				if (*pooled) {
					if (**pooled) {
						co_return hand_out(std::move(**pooled));
					}
					continue;
				}
				if (deadline && clock::now() >= *deadline) {// nothing is tried after the deadline
					co_return std::unexpected(self->give_up(excluded, std::move(last), false));
				}
				auto r = co_await open_new(self, deadline, exclusive, excluded, last, avoid);
				if (!r) {
					co_return std::unexpected(std::move(r.error()));
				}
				if (r->conn) {
					co_return hand_out(std::move(r->conn));
				}
				if (r->look_again || self->version != seen) {
					continue;// an open connection to share, or something changed meanwhile
				}
				const auto wake = r->wake;
				if (deadline && (clock::now() >= *deadline || (wake && *wake > *deadline))) {
					co_return std::unexpected(self->give_up(excluded, std::move(last), wake.has_value()));
				}
				waited = true;
				// Looks again when the earliest backoff ends, a held connection expires, or
				// at the deadline.
				const auto until = earliest({ wake, self->next_expiry(), deadline });
				if (const auto ec = co_await wait(self, until, exclusive); ec) {
					co_return fail(ec, context);
				}
			}
		}

		// ---------------------------------------------------------------- read forwarders

		// A read forwarder's failure it retries once, on another connection.
		[[nodiscard]] static auto retryable(const error &e) noexcept -> bool
		{
			return e.code == cond::connection_lost || e.code == cond::busy_or_unavailable;
		}

		// Retires `held`'s connection after the retryable failure `code`; returns
		// the server to avoid (one that answered busy or unavailable).
		auto set_aside(const lease &held, std::error_code code) noexcept -> std::optional<std::size_t>
		{
			const auto &c = held.conn_;
			const bool refused = code == cond::busy_or_unavailable;
			if (!closed && !c->retired && detail::accepts_requests(c->conn)
				&& std::ranges::find(pool, c) != pool.end()) {
				retire(c, refused ? disconnect_reason::busy_or_unavailable : disconnect_reason::closed);
			}
			return refused ? std::optional<std::size_t>{ c->server } : std::nullopt;
		}

		// Whether a failed outcome is the pooled connection's own (a chase's may
		// be a referred server's).
		template<class T> static auto origin_failed(const result<T> & /*r*/) -> bool { return true; }
		template<class T> static auto origin_failed(const chase_result<T> &r) -> bool { return r.origin_failed; }

		// `op` on a shared lease, retried once after a retryable failure of the
		// pooled connection's own operation.
		template<class T, class Op> static auto read(std::shared_ptr<client_state> self, Op op) -> capy::task<result<T>>
		{
			return retry_once_on_lease<T>(
			  acquire<lease>(std::move(self)),
			  [](auto &r) { return origin_failed(r) && retryable(lease_outcome(r).error()); },
			  std::move(op));
		}

		// ---------------------------------------------------------------- write forwarders

		// `op` on a shared lease, retried once on another connection only if its
		// request never reached the writer.
		template<class T = response, class Op>
		static auto write(std::shared_ptr<client_state> self, Op op) -> capy::task<result<T>>
		{
			return retry_once_on_lease<T>(
			  acquire<lease>(std::move(self)),
			  [](const result<T> &r) { return r.error().code == client_errc::not_sent; },
			  std::move(op));
		}

		// reacquire(): on the strand.
		static auto reacquire(lease failed, std::error_code code) -> capy::task<result<lease>>
		{
			auto self = failed.state_;
			const client::executor_type strand = self->strand;
			return on_strand(strand, set_aside_and_acquire(std::move(self), std::move(failed), code));
		}

		static auto set_aside_and_acquire(std::shared_ptr<client_state> self, lease failed, std::error_code code)
		  -> capy::task<result<lease>>
		{
			const auto avoid = self->set_aside(failed, code);
			failed.release();
			co_return co_await acquire<lease>(std::move(self), avoid);
		}

		// ---------------------------------------------------------------- referrals

		// Whether `request`, with its overrides, chases.
		[[nodiscard]] auto chases(const search_params &request) const noexcept -> bool
		{
			return request.follow_referrals.value_or(options.referrals.follow_referrals)
				   || request.follow_references.value_or(options.referrals.follow_references);
		}
		[[nodiscard]] auto chases(const compare_params &request) const noexcept -> bool
		{
			return request.follow_referrals.value_or(options.referrals.follow_referrals);
		}

		// The connector of a chase from `held`'s connection, with
		// referral_options::authorize deciding.
		static auto connector_for(const std::shared_ptr<client_state> &self, const lease &held) -> referral_connector
		{
			auto choose = [self, origin = held.server()](
							const url &target, std::size_t depth) -> std::optional<referral_identity> {
				const auto &authorize = self->options.referrals.authorize;
				if (!authorize || self->closed) {
					return std::nullopt;
				}
				return client_referral_identity(
				  authorize(referral_hop{ .target = target, .depth = depth, .origin = origin }), self->options.setup);
			};
			return make_policy_connector(
			  *self->ioc, detail::origin_protected(*held), self->options.connection, std::move(choose), self->mr);
		}

		// The switches of client_options::referrals, and the observer's hook.
		static auto settings_for(const std::shared_ptr<client_state> &self, const lease &held) -> chase_settings
		{
			return { .referrals = self->options.referrals.follow_referrals,
				.references = self->options.referrals.follow_references,
				.on_attempt = [self, server = held.server()](const referral_attempt &a) {
					if (auto *o = self->observer()) {
						o->on_referral(server, a);
					}
				} };
		}

		// `chase`, stopped by close() (then not_connected, not retried).
		template<class T>
		static auto stopped_by_close(std::shared_ptr<client_state> self, capy::task<chase_result<T>> chase)
		  -> capy::task<chase_result<T>>
		{
			std::stop_source stop;
			if (self->closed) {
				stop.request_stop();
			} else {
				self->chases_running.push_back(stop);
			}
			const scope_exit unregister{ [&self, &stop] noexcept { std::erase(self->chases_running, stop); } };
			auto r = co_await with_stop(stop.get_token(), std::move(chase));
			if (!r.value && self->closed) {
				r.value = fail(client_errc::not_connected, "referral chase: client closed");
				r.origin_failed = false;
			}
			co_return r;
		}

		static auto chase_search(const std::shared_ptr<client_state> &self,
		  search_params request,
		  std::pmr::memory_resource *mr) -> capy::task<result<search_result>>
		{
			return read<search_result>(self, [self, request = std::move(request), mr](const lease &held) {
				return stopped_by_close(self,
				  detail::chase_search(*held,
					request,
					connector_for(self, held),
					self->options.referrals.limits,
					mr,
					settings_for(self, held)));
			});
		}

		static auto chase_compare(const std::shared_ptr<client_state> &self, compare_params request)
		  -> capy::task<result<compare_result>>
		{
			return read<compare_result>(self, [self, request = std::move(request)](const lease &held) {
				return stopped_by_close(self,
				  detail::chase_compare(*held,
					request,
					connector_for(self, held),
					self->options.referrals.limits,
					settings_for(self, held)));
			});
		}

		// Destroys `s` on `c`'s strand.
		static auto end_stream(connection &c, ldap::search_stream &s) -> capy::task<void>
		{
			return detail::on_strand(c.executor(), [](ldap::search_stream &stream) -> capy::task<void> {
				stream = ldap::search_stream{};
				co_return;
			}(s));
		}

		static auto end_stream(connection & /*c*/, ldap::paged_search &s) -> capy::task<void> { return end_paged(s); }

		// `start` on a shared lease, retried once if it fails before its first
		// message.
		template<class Stream, class Start>
		static auto read_stream(std::shared_ptr<client_state> self, Start start) -> capy::task<result<Stream>>
		{
			std::optional<std::size_t> avoid;
			for (bool retried = false;; retried = true) {
				auto held = co_await acquire<lease>(self, avoid);
				if (!held) {
					co_return std::unexpected(std::move(held.error()));
				}
				result<Stream> s = co_await start(**held);
				std::optional<error> outcome;
				const error *failed = s ? nullptr : &s.error();
				if (s) {
					auto first = co_await first_outcome(*s);
					if (!first) {// stopped
						co_await end_stream(**held, *s);
						co_return std::unexpected(std::move(first.error()));
					}
					outcome = std::move(*first);
					failed = outcome ? &*outcome : nullptr;
				}
				if (failed != nullptr && !retried && retryable(*failed)) {
					if (s) {
						co_await end_stream(**held, *s);
					}
					avoid = self->set_aside(*held, failed->code);
					continue;
				}
				if (!s) {
					co_return std::unexpected(std::move(s.error()));
				}
				keep_alive(*s, std::make_shared<lease>(std::move(*held)));
				co_return std::move(*s);
			}
		}
	};

	auto reacquire(lease failed, std::error_code code) -> capy::task<result<lease>>
	{
		return client_state::reacquire(std::move(failed), code);
	}

	void set_jitter(const client &c, std::function<double()> unit) { c.state_->jitter = std::move(unit); }

	void set_connector(const client &c, pool_connector open) { c.state_->connector = std::move(open); }

}// namespace detail

// ---------------------------------------------------------------- leases

namespace detail {

	lease_base::lease_base(std::shared_ptr<client_state> state, std::shared_ptr<pooled_connection> conn) noexcept
	  : state_(std::move(state)), conn_(std::move(conn))
	{}

	auto lease_base::operator=(lease_base &&other) noexcept -> lease_base &
	{
		if (this != &other) {
			release();
			state_ = std::move(other.state_);
			conn_ = std::move(other.conn_);
		}
		return *this;
	}

	lease_base::~lease_base() { release(); }

	auto lease_base::pooled() const noexcept -> connection & { return conn_->conn; }

	auto lease_base::server() const noexcept -> const url & { return state_->servers[conn_->server].address; }

	void lease_base::release() noexcept
	{
		if (conn_ == nullptr) {
			return;
		}
		const client::executor_type strand = state_->strand;
		detail::run_on_strand(
		  strand, [state = std::move(state_), conn = std::move(conn_)] noexcept { state->release(conn); });
		conn_.reset();
		state_.reset();
	}

}// namespace detail

lease::lease(std::shared_ptr<detail::client_state> state, std::shared_ptr<detail::pooled_connection> conn) noexcept
  : lease_base(std::move(state), std::move(conn))
{}

exclusive_lease::exclusive_lease(std::shared_ptr<detail::client_state> state,
  std::shared_ptr<detail::pooled_connection> conn) noexcept
  : lease_base(std::move(state), std::move(conn))
{}

// ---------------------------------------------------------------- client

client::client(corosio::io_context &ioc, client_options options, std::pmr::memory_resource *mr)
  : state_(std::make_shared<detail::client_state>(ioc, std::move(options), mr))
{}

auto client::operator=(client &&other) noexcept -> client &
{
	if (this != &other) {
		close();
		state_ = std::move(other.state_);
	}
	return *this;
}

client::~client() { close(); }

auto client::executor() const noexcept -> executor_type { return state_->strand; }

namespace {

	template<class Lease> auto acquire_refused() -> capy::task<result<Lease>>
	{
		co_return fail(client_errc::not_connected, "acquire: client moved from");
	}

}// namespace

// Not coroutines: the tasks hold their own copy of the state, never `this`.
auto client::acquire() -> capy::task<result<lease>>
{
	if (state_ == nullptr) {
		return acquire_refused<lease>();
	}
	return detail::on_strand(state_->strand, detail::client_state::acquire<lease>(state_));
}

auto client::acquire_exclusive() -> capy::task<result<exclusive_lease>>
{
	if (state_ == nullptr) {
		return acquire_refused<exclusive_lease>();
	}
	return detail::on_strand(state_->strand, detail::client_state::acquire<exclusive_lease>(state_));
}

namespace {

	template<class T> auto read_refused(std::string context) -> capy::task<result<T>>
	{
		co_return fail(client_errc::not_connected, context + ": client moved from");
	}

	// Not a coroutine: the task holds its own copy of the state.
	template<class Params>
	auto update(const std::shared_ptr<detail::client_state> &state, Params request) -> capy::task<result<response>>
	{
		if (state == nullptr) {
			return read_refused<response>(detail::update_context(request));
		}
		return detail::on_strand(
		  state->strand, detail::client_state::write(state, [request = std::move(request)](const lease &held) {
			  return std::invoke(detail::update_op<Params>::member, *held, request);
		  }));
	}

}// namespace

// Not coroutines either: the tasks hold their own copy of the state.
auto client::search(search_params request, std::pmr::memory_resource *mr) -> capy::task<result<search_result>>
{
	if (state_ == nullptr) {
		return read_refused<search_result>(detail::op_context("search", request.base));
	}
	if (state_->chases(request)) {
		return detail::on_strand(state_->strand, detail::client_state::chase_search(state_, std::move(request), mr));
	}
	return detail::on_strand(state_->strand,
	  detail::client_state::read<search_result>(
		state_, [request = std::move(request), mr](const lease &held) { return held->search(request, mr); }));
}

auto client::search_stream(search_params request, std::pmr::memory_resource *mr)
  -> capy::task<result<ldap::search_stream>>
{
	if (state_ == nullptr) {
		return read_refused<ldap::search_stream>(detail::op_context("search", request.base));
	}
	return detail::on_strand(state_->strand,
	  detail::client_state::read_stream<ldap::search_stream>(
		state_, [request = std::move(request), mr](connection &c) { return c.search_stream(request, mr); }));
}

namespace detail {

	auto search_paged_of(const client &c,
	  search_params request,
	  std::int32_t page_size,
	  std::size_t max_pages,
	  std::pmr::memory_resource *mr) -> capy::task<result<ldap::paged_search>>
	{
		if (c.state_ == nullptr) {
			return read_refused<ldap::paged_search>(op_context("search", request.base));
		}
		return on_strand(c.state_->strand,
		  client_state::read_stream<ldap::paged_search>(
			c.state_, [request = std::move(request), page_size, max_pages, mr](connection &conn) {
				return ldap::search_paged(conn, request, page_size, max_pages, mr);
			}));
	}

}// namespace detail

auto client::compare(compare_params request) -> capy::task<result<compare_result>>
{
	if (state_ == nullptr) {
		return read_refused<compare_result>(detail::op_context("compare", request.entry));
	}
	if (state_->chases(request)) {
		return detail::on_strand(state_->strand, detail::client_state::chase_compare(state_, std::move(request)));
	}
	return detail::on_strand(state_->strand,
	  detail::client_state::read<compare_result>(
		state_, [request = std::move(request)](const lease &held) { return held->compare(request); }));
}

auto client::add(add_params request) -> capy::task<result<response>> { return update(state_, std::move(request)); }

auto client::modify(modify_params request) -> capy::task<result<response>>
{
	return update(state_, std::move(request));
}

auto client::del(del_params request) -> capy::task<result<response>> { return update(state_, std::move(request)); }

auto client::modify_dn(modify_dn_params request) -> capy::task<result<response>>
{
	return update(state_, std::move(request));
}

auto client::extended(extended_params request) -> capy::task<result<extended_result>>
{
	if (state_ == nullptr) {
		return read_refused<extended_result>("extended operation " + request.name);
	}
	return detail::on_strand(state_->strand,
	  detail::client_state::write<extended_result>(
		state_, [request = std::move(request)](const lease &held) { return held->extended(request); }));
}

auto client::connections() const noexcept -> std::size_t
{
	return state_ == nullptr ? 0 : state_->pool_size.load(std::memory_order_relaxed);
}

void client::close() noexcept
{
	if (state_ != nullptr) {
		const executor_type strand = state_->strand;
		detail::run_on_strand(strand, [state = state_] noexcept { state->close(); });
	}
}

}// namespace jhetz::ldap
