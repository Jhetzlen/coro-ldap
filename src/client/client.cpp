#include "jhetz/ldap/client.hpp"

#include "jhetz/ldap/cancel.hpp"

#include "../net/deadline.hpp"
#include "../scope_util.hpp"

#include <boost/capy/cond.hpp>
#include <boost/capy/error.hpp>
#include <boost/capy/ex/async_event.hpp>
#include <boost/capy/ex/run_async.hpp>
#include <boost/capy/ex/this_coro.hpp>
#include <boost/corosio/timeout.hpp>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <memory_resource>
#include <optional>
#include <random>
#include <string>
#include <string_view>
#include <system_error>
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
		// Set: no acquire() hands it out any more, it no longer counts
		// against max_connections, and it leaves the pool (unbound or
		// closed) once no lease holds it.
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
		// Failure episodes recorded: an attempt that fails after another one
		// recorded a failure since it began joins that episode (concurrent
		// attempts failing together count once).
		std::uint64_t episode = 0;
		// Authentication failures recorded; an acquire() seeing it change
		// stops trying the server.
		std::uint64_t auth_failures = 0;
		// The backoff follows an authentication failure (last_error): new
		// acquires fail with it at once until retry_at.
		bool auth_backoff = false;
	};

	struct client_state
	{
		client_state(corosio::io_context &io, client_options o, std::pmr::memory_resource *memory)
		  : ioc(&io), options(std::move(o)), mr(memory), rng(std::random_device{}())
		{
			servers.reserve(options.servers.size());
			for (const auto &u : options.servers) {
				servers.push_back({ .address = u, .name = std::string(std::string_view(u.to_string())) });
			}
		}

		corosio::io_context *ioc;
		client_options options;
		std::pmr::memory_resource *mr;
		std::vector<server_state> servers{};
		std::vector<std::shared_ptr<pooled_connection>> pool{};
		std::size_t opening = 0;// connection attempts in progress (they count against max_connections)
		// Set on every change an acquire() may wait for (a connection pooled,
		// returned, removed, probed; an attempt ended; close()); `version`
		// counts them, so a waiter sees the changes made while it was busy.
		capy::async_event changed{};
		std::uint64_t version = 0;
		bool closed = false;
		std::minstd_rand rng;
		std::function<double()> jitter{};// tests: replaces rng

		// ---------------------------------------------------------------- events

		void notify() noexcept
		{
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

		// Server `i` failed with `e` in an attempt begun at failure episode
		// `episode`.
		void server_failed(std::size_t i, const error &e, std::uint64_t episode)
		{
			auto &s = servers[i];
			const bool auth = e.code == cond::auth_failed;
			if (s.episode != episode && (!auth || s.auth_backoff)) {
				return;// a concurrent attempt recorded this failure already
			}
			++s.episode;
			++s.failures;
			milliseconds delay{};
			if (auth) {
				// Half the cap at least, and auth_failure_min: a wrong password
				// must not be retried soon (account lockouts).
				constexpr double half = 0.5;
				delay = std::max(options.backoff.auth_failure_min,
				  backoff_delay(options.backoff, s.failures, half + (half * jitter_unit())));
				++s.auth_failures;
			} else {
				delay = backoff_delay(options.backoff, s.failures, jitter_unit());
			}
			s.retry_at = clock::now() + delay;
			s.last_error = e;
			s.auth_backoff = auth;
			if (auto *o = observer()) {
				o->on_retry(s.address, e, delay);
			}
		}

		void server_succeeded(std::size_t i) noexcept
		{
			auto &s = servers[i];
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

		// Excludes, for one acquire(), the servers whose last attempt failed
		// to authenticate since it began (`seen`: their counts then), or
		// which are still backing off after such a failure; `last` becomes
		// the stored error, which acquire() fails with if nothing else
		// serves it.
		void exclude_auth_failures(std::vector<bool> &excluded,
		  const std::vector<std::uint64_t> &seen,
		  std::optional<error> &last,
		  clock::time_point now) const
		{
			for (std::size_t i = 0; i < servers.size(); ++i) {
				const auto &s = servers[i];
				if (excluded[i] || !s.auth_backoff || !s.last_error
					|| (s.auth_failures == seen[i] && s.retry_at <= now)) {
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

		// acquire() gives up while every server backs off: the error of the
		// one whose backoff ends first.
		[[nodiscard]] auto backoff_error(const std::vector<bool> &excluded) const -> error
		{
			const server_state *first = nullptr;
			for (std::size_t i = 0; i < servers.size(); ++i) {
				if (!excluded[i] && (first == nullptr || servers[i].retry_at < first->retry_at)) {
					first = &servers[i];
				}
			}
			if (first == nullptr || !first->last_error) {
				return make_error(capy::error::timeout, "acquire: no server available within acquire_timeout");
			}
			error e = *first->last_error;
			e.context += " (backing off: acquire_timeout ends first)";
			return e;
		}

		// ---------------------------------------------------------------- pool

		[[nodiscard]] auto expired(const pooled_connection &c, clock::time_point now) const noexcept -> bool
		{
			return options.max_lifetime && now - c.created >= *options.max_lifetime;
		}

		// Why `c` must not be handed out again, if it must not.
		[[nodiscard]] auto retire_reason(const pooled_connection &c, clock::time_point now) const noexcept
		  -> std::optional<disconnect_reason>
		{
			if (!c.conn.is_open()) {
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

		// Ends a connection that left the pool: unbound if open and no lease
		// holds it (a detached task on the executor), else closed.
		void shut_down(pooled_connection &c) const noexcept
		{
			if (!c.conn.is_open()) {
				return;
			}
			if (c.leases != 0) {
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

		// Retires what must not be handed out again (closed, bound again or
		// binding, too old), leased or not, and drops what is retired and
		// holds no lease.
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

		// The connection to hand out (see client::acquire), or null to open
		// a new one (or wait, if no slot is free). Call prune() first: it
		// retires the connections that must not be handed out.
		[[nodiscard]] auto pick(bool exclusive, clock::time_point now) const -> std::shared_ptr<pooled_connection>
		{
			std::shared_ptr<pooled_connection> idle;
			std::shared_ptr<pooled_connection> shared;
			for (const auto &c : pool) {
				if (c->retired || c->probing || c->exclusive || retire_reason(*c, now)) {
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
			if (idle) {
				return idle;
			}
			if (exclusive || has_free_slot()) {
				return nullptr;
			}
			return shared;
		}

		// `c` (idle) goes to a lower-priority server, is failback_after old,
		// and a higher-priority server this acquire() may try has ended its
		// backoff.
		[[nodiscard]] auto should_fail_back(const pooled_connection &c,
		  const std::vector<bool> &excluded,
		  clock::time_point now) const noexcept -> bool
		{
			if (c.leases != 0 || c.server == 0 || now - c.created < options.failback_after) {
				return false;
			}
			for (std::size_t i = 0; i < c.server; ++i) {
				if (!excluded[i] && servers[i].retry_at <= now) {
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
			// The observer need only outlive close(): no hook runs after it.
			options.observer = nullptr;
			notify();
		}

		// ---------------------------------------------------------------- tasks

		// Connect, StartTLS (by connect, per the options) and the setup.
		static auto connect_and_set_up(std::shared_ptr<client_state> self, std::size_t i)
		  -> capy::task<result<connection>>
		{
			auto c = co_await ldap::connect(*self->ioc, self->servers[i].address, self->options.connection, self->mr);
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

		// connect_and_set_up within `deadline`.
		static auto open_one(std::shared_ptr<client_state> self, std::size_t i, net::detail::deadline_t deadline)
		  -> capy::task<result<connection>>
		{
			if (!deadline) {
				co_return co_await connect_and_set_up(std::move(self), i);
			}
			auto [ec, r] = co_await corosio::timeout(raceable(connect_and_set_up(std::move(self), i)), *deadline);
			if (ec) {
				co_return fail(ec, "acquire_timeout expired");
			}
			co_return std::move(r);
		}

		// One pass over the servers whose backoff has ended, in priority
		// order, until one connects: that connection, pooled with one lease
		// (exclusive or not), or null if none did (`last` is then the last
		// failure) or `deadline` passed (no attempt starts after it). Fails
		// only when it must not go on: the client closed, or the task
		// stopped.
		static auto try_servers(std::shared_ptr<client_state> self,
		  net::detail::deadline_t deadline,
		  bool exclusive,
		  std::vector<bool> &excluded,
		  std::optional<error> &last) -> capy::task<result<std::shared_ptr<pooled_connection>>>
		{
			for (std::size_t i = 0; i < self->servers.size(); ++i) {
				if (self->closed) {// an observer hook may close the client
					co_return fail(client_errc::not_connected, "acquire: client closed");
				}
				const auto now = clock::now();
				if (deadline && now >= *deadline) {
					co_return nullptr;
				}
				if (excluded[i] || self->servers[i].retry_at > now) {
					continue;
				}
				const std::uint64_t episode = self->servers[i].episode;
				++self->opening;
				const scope_exit done{ [&self] noexcept {
					--self->opening;
					self->notify();
				} };
				auto r = co_await open_one(self, i, deadline);
				const std::string context = "acquire " + self->servers[i].name;
				if (self->closed) {
					if (r) {
						r->close();
					}
					co_return fail(client_errc::not_connected, context + ": client closed");
				}
				if (r) {
					self->server_succeeded(i);
					auto p = std::make_shared<pooled_connection>();
					p->conn = std::move(*r);
					p->server = i;
					p->leases = 1;
					p->created = clock::now();
					p->last_used = p->created;
					p->binds = p->conn.bind_count();
					p->exclusive = exclusive;
					self->pool.push_back(p);
					if (auto *o = self->observer()) {
						o->on_connect(self->servers[i].address, result<void>{});
					}
					if (self->closed) {// closed by the hook: close() closed `p` too
						co_return fail(client_errc::not_connected, context + ": client closed");
					}
					co_return p;
				}
				error e = detail::with_context(std::move(r.error()), context);
				if (e.code == cond::canceled && (co_await capy::this_coro::stop_token).stop_requested()) {
					co_return std::unexpected(std::move(e));// not the server's fault
				}
				if (auto *o = self->observer()) {
					o->on_connect(self->servers[i].address, std::unexpected(e));
				}
				self->server_failed(i, e, episode);
				if (e.code == cond::auth_failed || e.code == cond::invalid_input) {
					excluded[i] = true;// retrying cannot help: not again in this acquire()
				}
				last = std::move(e);
			}
			co_return nullptr;
		}

		// The idle check: a root DSE base search for no attributes, within
		// probe_timeout and what is left before `deadline`. A server error
		// is an answer too.
		static auto probe(std::shared_ptr<client_state> self,
		  std::shared_ptr<pooled_connection> c,
		  net::detail::deadline_t deadline) -> capy::task<result<void>>
		{
			c->probing = true;
			++c->leases;// so that nothing removes it meanwhile
			const scope_exit done{ [&self, &c] noexcept {
				c->probing = false;
				--c->leases;
				self->notify();
			} };
			milliseconds timeout = self->options.probe_timeout;
			if (deadline) {
				timeout = std::min(
				  timeout, std::max(milliseconds(0), std::chrono::ceil<milliseconds>(*deadline - clock::now())));
			}
			auto r = co_await c->conn.search(
			  { .base = dn{}, .scope = search_scope::base_object, .attributes = { "1.1" }, .timeout = timeout });
			result<void> outcome;
			if (!r && r.error().code.category() != result_category()) {
				outcome = std::unexpected(std::move(r.error()));
			}
			if (auto *o = self->observer()) {
				o->on_probe(self->servers[c->server].address, outcome);
			}
			co_return outcome;
		}

		// acquire()'s look at the pool: an error (the task stopped), nullopt
		// when there is nothing to hand out (open a connection, or wait), a
		// connection to hand out (its lease counted), or null to look again
		// (one was retired, or the pool changed while probing).
		static auto from_pool(std::shared_ptr<client_state> self,
		  net::detail::deadline_t deadline,
		  bool exclusive,
		  const std::vector<bool> &excluded) -> capy::task<result<std::optional<std::shared_ptr<pooled_connection>>>>
		{
			using found = std::optional<std::shared_ptr<pooled_connection>>;
			const auto now = clock::now();
			self->prune(now);
			auto c = self->pick(exclusive, now);
			if (!c) {
				co_return found{};
			}
			if (self->should_fail_back(*c, excluded, now)) {
				self->retire(c, disconnect_reason::failback);
				co_return found{ nullptr };
			}
			if (self->needs_probe(*c, now)) {
				if (deadline && now >= *deadline) {
					co_return found{};// no time left to probe it: acquire() gives up
				}
				auto p = co_await probe(self, c, deadline);
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

		// acquire() gives up at its deadline: the last failure, else the
		// error of the server backing off (`backing_off`), else a timeout.
		[[nodiscard]] auto give_up(const std::vector<bool> &excluded, std::optional<error> last, bool backing_off) const
		  -> error
		{
			if (last) {
				return std::move(*last);
			}
			if (backing_off) {
				return backoff_error(excluded);
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

		// Options acquire() cannot work with.
		[[nodiscard]] auto unusable_options() const -> std::optional<error>
		{
			if (servers.empty()) {
				return make_error(client_errc::invalid_url, "acquire: client_options::servers is empty");
			}
			if (options.max_connections == 0) {
				return make_error(
				  std::make_error_code(std::errc::invalid_argument), "acquire: client_options::max_connections is 0");
			}
			return std::nullopt;
		}

		// acquire() with a slot free: try_servers(), then, if no server
		// connected, `wake` is when the earliest backoff ends. Fails as
		// try_servers() does, and with the last error once every server is
		// excluded (each failed in a way retrying cannot fix).
		static auto open_new(std::shared_ptr<client_state> self,
		  net::detail::deadline_t deadline,
		  bool exclusive,
		  std::vector<bool> &excluded,
		  std::optional<error> &last,
		  std::optional<clock::time_point> &wake) -> capy::task<result<std::shared_ptr<pooled_connection>>>
		{
			auto r = co_await try_servers(self, deadline, exclusive, excluded, last);
			if (!r || *r) {
				co_return r;
			}
			wake = self->next_retry(excluded);
			if (!wake) {
				co_return std::unexpected(self->give_up(excluded, std::move(last), false));
			}
			co_return nullptr;
		}

		static auto acquire(std::shared_ptr<client_state> self, acquire_options how) -> capy::task<result<lease>>
		{
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
			const scope_exit report{ [&self, &waited, start] noexcept {
				if (auto *o = self->observer(); o != nullptr && waited) {
					o->on_acquire_wait(std::chrono::duration_cast<milliseconds>(clock::now() - start));
				}
			} };
			while (true) {
				if (self->closed) {
					co_return fail(client_errc::not_connected, "acquire: client closed");
				}
				if ((co_await capy::this_coro::stop_token).stop_requested()) {
					co_return fail(capy::error::canceled, context);
				}
				self->exclude_auth_failures(excluded, auth_seen, last, clock::now());
				const std::uint64_t seen = self->version;
				auto pooled = co_await from_pool(self, deadline, how.exclusive, excluded);
				if (!pooled) {
					co_return std::unexpected(std::move(pooled.error()));
				}
				if (*pooled) {
					if (**pooled) {
						co_return lease(self, std::move(**pooled));
					}
					continue;
				}
				if (deadline && clock::now() >= *deadline) {// nothing is tried after the deadline
					co_return std::unexpected(self->give_up(excluded, std::move(last), false));
				}
				std::optional<clock::time_point> wake;
				if (self->has_free_slot()) {
					auto r = co_await open_new(self, deadline, how.exclusive, excluded, last, wake);
					if (!r) {
						co_return std::unexpected(std::move(r.error()));
					}
					if (*r) {
						co_return lease(self, std::move(*r));
					}
				}
				if (self->version != seen) {
					continue;// something changed meanwhile: look again
				}
				if (deadline && (clock::now() >= *deadline || (wake && *wake > *deadline))) {
					co_return std::unexpected(self->give_up(excluded, std::move(last), wake.has_value()));
				}
				waited = true;
				if (deadline && (!wake || *deadline < *wake)) {
					wake = deadline;
				}
				if (const auto ec = co_await self->wait_for_change(wake); ec) {
					co_return fail(ec, context);
				}
			}
		}
	};

	void set_jitter(const client &c, std::function<double()> unit) { c.state_->jitter = std::move(unit); }

}// namespace detail

// ---------------------------------------------------------------- lease

lease::lease(std::shared_ptr<detail::client_state> state, std::shared_ptr<detail::pooled_connection> conn) noexcept
  : state_(std::move(state)), conn_(std::move(conn))
{}

auto lease::operator=(lease &&other) noexcept -> lease &
{
	if (this != &other) {
		release();
		state_ = std::move(other.state_);
		conn_ = std::move(other.conn_);
	}
	return *this;
}

lease::~lease() { release(); }

auto lease::get() const noexcept -> connection & { return conn_->conn; }

auto lease::server() const noexcept -> const url & { return state_->servers[conn_->server].address; }

void lease::release() noexcept
{
	if (conn_ == nullptr) {
		return;
	}
	state_->release(conn_);
	conn_.reset();
	state_.reset();
}

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

auto client::executor() const noexcept -> executor_type { return state_->ioc->get_executor(); }

namespace {

	auto acquire_refused() -> capy::task<result<lease>>
	{
		co_return fail(client_errc::not_connected, "acquire: client moved from");
	}

}// namespace

// Not a coroutine: the task holds its own copy of the state, never `this`.
auto client::acquire(acquire_options options) -> capy::task<result<lease>>
{
	if (state_ == nullptr) {
		return acquire_refused();
	}
	return detail::client_state::acquire(state_, options);
}

auto client::connections() const noexcept -> std::size_t { return state_ == nullptr ? 0 : state_->pool.size(); }

void client::close() noexcept
{
	if (state_ != nullptr) {
		state_->close();
	}
}

}// namespace jhetz::ldap
