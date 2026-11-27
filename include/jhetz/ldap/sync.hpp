// Blocking facades over ldap::connection and ldap::client, each owning an
// io_context and one I/O thread (docs/API.md, "jhetz/ldap/sync.hpp").
#pragma once

#include "jhetz/ldap/channel_binding.hpp"
#include "jhetz/ldap/client.hpp"
#include "jhetz/ldap/connection.hpp"
#include "jhetz/ldap/directory.hpp"
#include "jhetz/ldap/run.hpp"

#include <boost/capy/ex/run_async.hpp>
#include <boost/capy/ex/work_guard.hpp>
#include <boost/capy/task.hpp>
#include <boost/corosio/io_context.hpp>

#include <chrono>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <expected>
#include <functional>
#include <future>
#include <memory>
#include <memory_resource>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <thread>
#include <type_traits>
#include <utility>
#include <vector>

namespace jhetz::ldap {
class server_schema;
template<class T, class Stream> class record_stream;
}// namespace jhetz::ldap

namespace jhetz::ldap::sync {

class transaction;
class connection;
template<bool Exclusive> class basic_lease;
// Declared before lease so MSVC binds its friend declaration here.
class client;

// The facades sync::run runs tasks on.
template<class D>
concept directory = std::same_as<D, connection> || std::same_as<D, basic_lease<false>>
					|| std::same_as<D, basic_lease<true>> || std::same_as<D, client>;

namespace detail {
	template<class> struct task_value;
	template<class R> struct task_value<boost::capy::task<R>>
	{
		using type = R;
	};

	// Writes "jhetz::ldap::<facade>: <what>" to stderr and calls std::terminate().
	[[noreturn]] void fatal(const char *facade, const char *what) noexcept;

	[[nodiscard]] auto done() -> boost::capy::task<result<void>>;
	// Success or the error of `bind`, a bind or StartTLS.
	[[nodiscard]] auto bound(boost::capy::task<result<ldap::connection>> bind) -> boost::capy::task<result<void>>;

	// What a facade's binds and StartTLS return on success.
	template<class D> struct chain_handle
	{
		using type = D;
	};
	template<bool Exclusive> struct chain_handle<basic_lease<Exclusive>>
	{
		using type = std::reference_wrapper<basic_lease<Exclusive>>;
	};

	// An io_context and the one thread running it.
	class io_thread
	{
	  public:
		// `facade` names the owner in would_deadlock errors' context.
		explicit io_thread(const char *facade);
		io_thread(const io_thread &) = delete;
		auto operator=(const io_thread &) -> io_thread & = delete;
		~io_thread();

		[[nodiscard]] auto context() noexcept -> boost::corosio::io_context & { return ioc_; }
		[[nodiscard]] auto executor() const noexcept -> boost::corosio::io_context::executor_type
		{
			return ioc_.get_executor();
		}
		[[nodiscard]] auto on_this_thread() const noexcept -> bool { return std::this_thread::get_id() == id_; }

		// Creates and runs make_task()'s task on the I/O thread and waits for its
		// result; would_deadlock from the I/O thread itself.
		template<class F> auto run(const F &make_task) const -> task_value<std::invoke_result_t<const F &>>::type
		{
			using R = task_value<std::invoke_result_t<const F &>>::type;
			if (on_this_thread()) {
				return std::unexpected(make_error(client_errc::would_deadlock, facade_));
			}
			std::promise<R> done;
			auto f = done.get_future();
			boost::capy::run_async(
			  ioc_.get_executor(),
			  [&done](R r) { done.set_value(std::move(r)); },
			  [&done](std::exception_ptr e) { done.set_exception(std::move(e)); })(
			  [](const F &make) -> boost::capy::task<R> { co_return co_await make(); }(make_task));
			return f.get();
		}

		// run() for a noexcept path handing I/O-thread objects over to make_task.
		// A failure before make_task ran calls fatal(); a later one is ignored.
		template<class F> void hand_over(const F &make_task, const char *what) const noexcept
		{
			bool taken = false;
			try {
				(void)run([&] {
					taken = true;
					return make_task();
				});
			} catch (...) {
				// `taken` is set on the I/O thread before the exception is stored.
				if (!taken) {
					fatal(facade_, what);
				}
			}
		}

		// Drops the work guard and joins the thread. Idempotent; fatal() on the
		// I/O thread itself.
		void join() noexcept;

	  private:
		const char *facade_;
		boost::corosio::io_context ioc_{};
		std::optional<boost::capy::work_guard<boost::corosio::io_context::executor_type>> guard_;
		std::thread thread_;
		std::thread::id id_;
	};

	// The value of `t` on the heap.
	template<class T> auto boxed(boost::capy::task<result<T>> t) -> boost::capy::task<result<std::unique_ptr<T>>>
	{
		auto r = co_await std::move(t);
		if (!r) {
			co_return std::unexpected(std::move(r.error()));
		}
		co_return std::make_unique<T>(std::move(*r));
	}

	// A task returning f()'s value, or success after f() for a void f.
	template<class F> auto invoked(F f) -> boost::capy::task<result<std::invoke_result_t<F &>>>
	{
		if constexpr (std::is_void_v<std::invoke_result_t<F &>>) {
			f();
			co_return result<void>{};
		} else {
			co_return f();
		}
	}

	template<class Derived> class connection_api;
	struct facade_access;
}// namespace detail

// ldap::transaction for a sync::connection or a sync lease, run on the I/O
// thread. Destroyed open, it aborts and waits at most five seconds.
class transaction
{
  public:
	transaction(transaction &&other) noexcept;
	auto operator=(transaction &&other) noexcept -> transaction &;
	transaction(const transaction &) = delete;
	auto operator=(const transaction &) -> transaction & = delete;
	~transaction();

	[[nodiscard]] static auto begin(connection &c, extended_controls controls = {}) -> result<transaction>;
	template<bool Exclusive>
	[[nodiscard]] static auto begin(basic_lease<Exclusive> &l, extended_controls controls = {}) -> result<transaction>;

	// Empty once moved from.
	[[nodiscard]] auto identifier() const -> std::string;
	[[nodiscard]] auto is_open() const -> bool;

	[[nodiscard]] auto add(add_params request) -> result<update_result>;
	[[nodiscard]] auto modify(modify_params request) -> result<update_result>;
	[[nodiscard]] auto del(del_params request) -> result<update_result>;
	[[nodiscard]] auto modify_dn(modify_dn_params request) -> result<update_result>;
	[[nodiscard]] auto commit() -> result<commit_result>;
	[[nodiscard]] auto abort() -> result<void>;

  private:
	transaction(std::shared_ptr<const detail::io_thread> io, std::unique_ptr<ldap::transaction> t) noexcept;

	template<class D> static auto begin_on(D &d, extended_controls controls) -> result<transaction>;

	// Ends the ldap::transaction, aborting it first if still open.
	void settle() noexcept;

	// Owning when made by a sync lease, not owning when made by a connection.
	std::shared_ptr<const detail::io_thread> io_{};
	// Touched only on the I/O thread; null once moved from.
	std::unique_ptr<ldap::transaction> txn_;
};

// ldap::search_stream for a sync::connection, a sync lease or a
// sync::client, read on the I/O thread; next() blocks until the next
// message. Destroyed unfinished, it abandons the search. Made by a
// sync::connection, it must not outlive its last handle.
class search_stream
{
  public:
	search_stream() noexcept = default;
	search_stream(search_stream &&other) noexcept;
	auto operator=(search_stream &&other) noexcept -> search_stream &;
	search_stream(const search_stream &) = delete;
	auto operator=(const search_stream &) -> search_stream & = delete;
	~search_stream();

	// The next entry, nullopt at the end, or an error.
	[[nodiscard]] auto next() -> result<std::optional<entry>>;
	// As next(), every message before the SearchResultDone, in order.
	[[nodiscard]] auto next_item() -> result<std::optional<ldap::search_stream::item>>;

	// True once moved from.
	[[nodiscard]] auto done() const -> bool;
	// Copied; empty once moved from.
	[[nodiscard]] auto references() const -> string_list;
	[[nodiscard]] auto reference_urls(std::pmr::memory_resource *mr = std::pmr::get_default_resource()) const
	  -> std::pmr::vector<url>;
	[[nodiscard]] auto controls() const -> std::pmr::vector<control>;

  private:
	template<class> friend class detail::connection_api;
	friend class client;
	search_stream(std::shared_ptr<const detail::io_thread> io, std::unique_ptr<ldap::search_stream> s) noexcept;

	// Destroys the ldap::search_stream on the I/O thread.
	void settle() noexcept;

	// As sync::transaction's.
	std::shared_ptr<const detail::io_thread> io_{};
	// Touched only on the I/O thread; null once moved from.
	std::unique_ptr<ldap::search_stream> stream_;
};

// The TLS channel bindings (RFC 5056) of a blocking facade's connection,
// copied.
struct channel_bindings
{
	std::vector<std::byte> tls_server_end_point{};
	std::vector<std::byte> tls_exporter{};
	std::optional<channel_binding_type> default_type{};

	// Empty when not available.
	[[nodiscard]] auto get(channel_binding_type t) const noexcept -> std::span<const std::byte>
	{
		return ldap::channel_bindings{ .tls_server_end_point = tls_server_end_point, .tls_exporter = tls_exporter }.get(
		  t);
	}
};

namespace detail {

	// The blocking ldap::connection operations shared by sync::connection and
	// the sync leases. `Derived` provides call(make_task) and runner().
	template<class Derived> class connection_api
	{
	  public:
		[[nodiscard]] auto is_open() const -> bool
		{
			return self()
			  .call([](const ldap::connection &c) { return invoked([&c] { return c.is_open(); }); })
			  .value_or(false);
		}
		// Copied; empty if never connected.
		[[nodiscard]] auto endpoint() const -> std::string
		{
			return self()
			  .call([](const ldap::connection &c) { return invoked([&c] { return std::string(c.endpoint()); }); })
			  .value_or(std::string{});
		}
		[[nodiscard]] auto outstanding_count() const -> std::size_t
		{
			return self()
			  .call([](const ldap::connection &c) { return invoked([&c] { return c.outstanding_count(); }); })
			  .value_or(0);
		}
		[[nodiscard]] auto bind_count() const -> std::uint64_t
		{
			return self()
			  .call([](const ldap::connection &c) { return invoked([&c] { return c.bind_count(); }); })
			  .value_or(0);
		}
		[[nodiscard]] auto is_tls() const -> bool
		{
			return self()
			  .call([](const ldap::connection &c) { return invoked([&c] { return c.is_tls(); }); })
			  .value_or(false);
		}
		[[nodiscard]] auto security_layer() const -> sasl_protection
		{
			return self()
			  .call([](const ldap::connection &c) { return invoked([&c] { return c.security_layer(); }); })
			  .value_or(sasl_protection::none);
		}
		// Copied; empty unless is_tls().
		[[nodiscard]] auto peer_certificate() const -> std::vector<std::byte>
		{
			return self()
			  .call([](const ldap::connection &c) {
				  return invoked([&c] {
					  const auto der = c.peer_certificate();
					  return std::vector<std::byte>(der.begin(), der.end());
				  });
			  })
			  .value_or(std::vector<std::byte>{});
		}
		// Copied; empty unless is_tls().
		[[nodiscard]] auto channel_bindings() const -> sync::channel_bindings
		{
			return self()
			  .call([](const ldap::connection &c) {
				  return invoked([&c] {
					  const auto b = c.channel_bindings();
					  return sync::channel_bindings{
						  .tls_server_end_point =
							std::vector<std::byte>(b.tls_server_end_point.begin(), b.tls_server_end_point.end()),
						  .tls_exporter = std::vector<std::byte>(b.tls_exporter.begin(), b.tls_exporter.end()),
						  .default_type = b.default_type,
					  };
				  });
			  })
			  .value_or(sync::channel_bindings{});
		}

		// The binds and StartTLS return a copy of a sync::connection, a
		// reference to a lease.
		[[nodiscard]] auto simple_bind(dn name, std::string password) -> result<typename chain_handle<Derived>::type>
		{
			return handle_after(self().call(
			  [&](ldap::connection &c) { return bound(c.simple_bind(std::move(name), std::move(password))); }));
		}
		// `mechanism` is used on the I/O thread while the call runs.
		[[nodiscard]] auto sasl_bind(sasl_mechanism &mechanism, dn name = {})
		  -> result<typename chain_handle<Derived>::type>
		{
			return handle_after(
			  self().call([&](ldap::connection &c) { return bound(c.sasl_bind(mechanism, std::move(name))); }));
		}
		[[nodiscard]] auto start_tls(net::tls_options options = {},
		  std::optional<std::chrono::milliseconds> timeout = std::nullopt)
		  -> result<typename chain_handle<Derived>::type>
		{
			return handle_after(
			  self().call([&](ldap::connection &c) { return bound(c.start_tls(std::move(options), timeout)); }));
		}

		[[nodiscard]] auto search(search_params request,
		  std::pmr::memory_resource *mr = std::pmr::get_default_resource()) -> result<search_result>
		{
			return self().call([&](ldap::connection &c) { return c.search(std::move(request), mr); });
		}
		[[nodiscard]] auto search_stream(search_params request,
		  std::pmr::memory_resource *mr = std::pmr::get_default_resource()) -> result<sync::search_stream>
		{
			auto s = self().call([&](ldap::connection &c) { return boxed(c.search_stream(std::move(request), mr)); });
			if (!s) {
				return std::unexpected(std::move(s.error()));
			}
			return sync::search_stream(self().runner(), std::move(*s));
		}
		[[nodiscard]] auto add(add_params request) -> result<update_result>
		{
			return self().call([&](ldap::connection &c) { return c.add(std::move(request)); });
		}
		[[nodiscard]] auto modify(modify_params request) -> result<update_result>
		{
			return self().call([&](ldap::connection &c) { return c.modify(std::move(request)); });
		}
		[[nodiscard]] auto del(del_params request) -> result<update_result>
		{
			return self().call([&](ldap::connection &c) { return c.del(std::move(request)); });
		}
		[[nodiscard]] auto modify_dn(modify_dn_params request) -> result<update_result>
		{
			return self().call([&](ldap::connection &c) { return c.modify_dn(std::move(request)); });
		}
		[[nodiscard]] auto compare(compare_params request) -> result<compare_result>
		{
			return self().call([&](ldap::connection &c) { return c.compare(std::move(request)); });
		}
		[[nodiscard]] auto extended(extended_params request) -> result<extended_result>
		{
			return self().call([&](ldap::connection &c) { return c.extended(std::move(request)); });
		}

		[[nodiscard]] auto unbind() -> result<void>
		{
			return self().call([](ldap::connection &c) { return c.unbind(); });
		}
		// Closes at once, without an UnbindRequest.
		void close()
		{
			(void)self().call([](ldap::connection &c) { return invoked([&c] { c.close(); }); });
		}

	  private:
		friend Derived;
		connection_api() = default;

		[[nodiscard]] auto self() noexcept -> Derived & { return static_cast<Derived &>(*this); }
		[[nodiscard]] auto handle_after(result<void> r) -> result<typename chain_handle<Derived>::type>
		{
			if (!r) {
				return std::unexpected(std::move(r.error()));
			}
			return typename chain_handle<Derived>::type(self());
		}
		[[nodiscard]] auto self() const noexcept -> const Derived & { return static_cast<const Derived &>(*this); }
	};

}// namespace detail

namespace detail {

	// What the handles of a sync::connection share.
	struct connection_core
	{
		io_thread io{ "sync::connection" };
		ldap::connection conn{};// touched only on the I/O thread

		connection_core() = default;
		connection_core(const connection_core &) = delete;
		auto operator=(const connection_core &) -> connection_core & = delete;
		connection_core(connection_core &&) = delete;
		auto operator=(connection_core &&) -> connection_core & = delete;
		// Closes the connection on the I/O thread and joins it.
		~connection_core();
	};

}// namespace detail

// The blocking ldap::connect: starts the I/O thread and connects there.
// `mr` must outlive the sync::connection.
[[nodiscard]] auto connect(url u,
  connection_options options = {},
  std::pmr::memory_resource *mr = std::pmr::get_default_resource()) -> result<connection>;
// From the URL text; a bad URL fails with invalid_url before any thread
// starts.
[[nodiscard]] auto connect(std::string_view text,
  connection_options options = {},
  std::pmr::memory_resource *mr = std::pmr::get_default_resource()) -> result<connection>;

// The blocking ldap::connection. Copyable: a copy is another handle on the
// same I/O thread and connection.
class connection : public detail::connection_api<connection>
{
  public:
	connection() noexcept = default;
	connection(const connection &) noexcept = default;
	connection(connection &&) noexcept = default;
	auto operator=(const connection &) noexcept -> connection & = default;
	auto operator=(connection &&) noexcept -> connection & = default;
	// The last handle closes the connection and joins the I/O thread; never on
	// that thread.
	~connection() = default;

	// The I/O thread's executor; no context without an I/O thread.
	[[nodiscard]] auto executor() const noexcept -> boost::corosio::io_context::executor_type
	{
		return core_ ? core_->io.executor() : boost::corosio::io_context::executor_type{};
	}

  private:
	friend class detail::connection_api<connection>;
	friend struct detail::facade_access;
	friend auto connect(url u, connection_options options, std::pmr::memory_resource *mr) -> result<connection>;
	explicit connection(std::shared_ptr<detail::connection_core> core) noexcept : core_(std::move(core)) {}

	// Runs make_task(c) on the I/O thread and waits; not_connected without one.
	template<class Self, class F>
	auto call(this Self &self, const F &make_task)
	  -> detail::task_value<decltype(make_task(std::forward_like<Self &>(std::declval<ldap::connection &>())))>::type
	{
		if (!self.core_) {
			return std::unexpected(make_error(client_errc::not_connected, "sync::connection: not connected"));
		}
		auto &c = std::forward_like<Self &>(self.core_->conn);
		return self.core_->io.run([&] { return make_task(c); });
	}
	// Not owning.
	[[nodiscard]] auto runner() const noexcept -> std::shared_ptr<const detail::io_thread>
	{
		return { std::shared_ptr<const detail::io_thread>{}, &core_->io };
	}

	std::shared_ptr<detail::connection_core> core_;
};

namespace detail {
	struct client_core;
}

// A blocking ldap::lease (Exclusive false) or ldap::exclusive_lease of a
// sync::client, run on the client's I/O thread.
template<bool Exclusive> class basic_lease : public detail::connection_api<basic_lease<Exclusive>>
{
  public:
	basic_lease() noexcept = default;
	basic_lease(basic_lease &&other) noexcept;
	auto operator=(basic_lease &&other) noexcept -> basic_lease &;
	basic_lease(const basic_lease &) = delete;
	auto operator=(const basic_lease &) -> basic_lease & = delete;
	~basic_lease();

	// False for a default-constructed, moved-from or released lease.
	explicit operator bool() const noexcept { return io_ != nullptr; }
	// Empty for a false lease.
	[[nodiscard]] auto server() const noexcept -> const url & { return server_; }
	// Returns the connection to the pool now and waits for that.
	void release() noexcept;

  private:
	using held_lease = std::conditional_t<Exclusive, ldap::exclusive_lease, ldap::lease>;

	friend class client;
	friend class detail::connection_api<basic_lease>;
	friend struct detail::facade_access;
	basic_lease(std::shared_ptr<const detail::io_thread> io, held_lease held, url server) noexcept;

	// Runs make_task(c) on the I/O thread with the leased connection.
	template<class Self, class F>
	auto call(this Self &self, const F &make_task)
	  -> detail::task_value<decltype(make_task(std::forward_like<Self &>(std::declval<ldap::connection &>())))>::type
	{
		if (self.io_ == nullptr) {
			return std::unexpected(make_error(client_errc::not_connected, "sync::lease: no connection (released)"));
		}
		return self.io_->run([&] { return make_task(std::forward_like<Self &>(self.leased())); });
	}
	[[nodiscard]] auto runner() const noexcept -> std::shared_ptr<const detail::io_thread> { return io_; }
	// Touched only on the I/O thread.
	[[nodiscard]] auto leased() const noexcept -> ldap::connection & { return held_.get(); }

	// An aliasing pointer to the client's core; null iff the lease holds nothing.
	std::shared_ptr<const detail::io_thread> io_{};
	held_lease held_{};// touched only on the I/O thread
	url server_{};
};

using lease = basic_lease<false>;
using exclusive_lease = basic_lease<true>;

extern template class basic_lease<false>;
extern template class basic_lease<true>;

// The blocking ldap::client: the ldap::client, its setup and observer run
// on an I/O thread the facade owns.
class client
{
  public:
	// Starts the I/O thread and makes the ldap::client there.
	explicit client(client_options options, std::pmr::memory_resource *mr = std::pmr::get_default_resource());
	client(const client &) = delete;
	auto operator=(const client &) -> client & = delete;
	// close(), then joins the I/O thread unless leases are still alive.
	~client();

	// The I/O thread's executor.
	[[nodiscard]] auto executor() const noexcept -> boost::corosio::io_context::executor_type;

	[[nodiscard]] auto acquire() -> result<lease>;
	[[nodiscard]] auto acquire_exclusive() -> result<exclusive_lease>;

	// Read forwarders, as ldap::client's.
	[[nodiscard]] auto search(search_params request, std::pmr::memory_resource *mr = std::pmr::get_default_resource())
	  -> result<search_result>;
	// The stream holds its shared lease until destroyed.
	[[nodiscard]] auto search_stream(search_params request,
	  std::pmr::memory_resource *mr = std::pmr::get_default_resource()) -> result<sync::search_stream>;
	[[nodiscard]] auto compare(compare_params request) -> result<compare_result>;

	// Write forwarders, as ldap::client's.
	[[nodiscard]] auto add(add_params request) -> result<update_result>;
	[[nodiscard]] auto modify(modify_params request) -> result<update_result>;
	[[nodiscard]] auto del(del_params request) -> result<update_result>;
	[[nodiscard]] auto modify_dn(modify_dn_params request) -> result<update_result>;
	[[nodiscard]] auto extended(extended_params request) -> result<extended_result>;

	[[nodiscard]] auto connection_count() const -> std::size_t;

	// As ldap::client::close(), and waits for it. Idempotent.
	void close() noexcept;

  private:
	friend struct detail::facade_access;

	// Runs make_task(pool) on the I/O thread and waits for its result.
	template<class F>
	auto call(const F &make_task) -> detail::task_value<std::invoke_result_t<const F &, ldap::client &>>::type
	{
		return io().run([&] { return make_task(pool()); });
	}
	[[nodiscard]] auto io() const noexcept -> const detail::io_thread &;
	// Touched only on the I/O thread.
	[[nodiscard]] auto pool() const noexcept -> ldap::client &;
	// A Lease over a Pooled lease taken from pool().
	template<class Lease, class Pooled> auto acquire_as() -> result<Lease>;

	std::shared_ptr<detail::client_core> core_;
};

namespace detail {
	struct facade_access
	{
		template<class D, class F> static auto call(D &d, const F &make_task) { return d.call(make_task); }
		template<class D> static auto runner(const D &d) { return d.runner(); }
	};

	using ldap::detail::io_context_bound;
	using ldap::detail::io_thread_bound;
}// namespace detail

template<class D> auto transaction::begin_on(D &d, extended_controls controls) -> result<transaction>
{
	auto t = detail::facade_access::call(
	  d, [&](ldap::connection &c) { return detail::boxed(ldap::transaction::begin(c, std::move(controls))); });
	if (!t) {
		return std::unexpected(std::move(t.error()));
	}
	return transaction(detail::facade_access::runner(d), std::move(*t));
}

inline auto transaction::begin(connection &c, extended_controls controls) -> result<transaction>
{
	return begin_on(c, std::move(controls));
}

template<bool Exclusive>
auto transaction::begin(basic_lease<Exclusive> &l, extended_controls controls) -> result<transaction>
{
	return begin_on(l, std::move(controls));
}

// Runs make_task(a, args...) on the I/O thread of `d`, `a` being its
// ldap::connection or ldap::client, and returns the task's result:
//   ldap::sync::run(pool, [](auto &a) { return ldap::who_am_i(a); });
template<directory D, class F, class... Args> [[nodiscard]] auto run(D &d, F &&make_task, Args &&...args)
{
	const auto task_of = [&](
						   auto &a) { return std::invoke(std::forward<F>(make_task), a, std::forward<Args>(args)...); };
	static_assert(!detail::io_context_bound<decltype(detail::facade_access::call(d, task_of))>,
	  "sync::run: the task's result holds a stream, lease, transaction, connection or client, which is bound to "
	  "the I/O thread's io_context; consume it inside the task and return plain values");
	return detail::facade_access::call(d, task_of);
}

}// namespace jhetz::ldap::sync

namespace jhetz::ldap::detail {

// The facades as repository sources (repository.hpp).
template<sync::directory D> struct blocking_facade<D> : std::true_type
{
	template<class F> static auto run(D &d, F &&make_task) { return sync::run(d, std::forward<F>(make_task)); }
};

}// namespace jhetz::ldap::detail

namespace jhetz::ldap::sync {

// ldap::search_paged, blocking.
template<directory D>
[[nodiscard]] auto search_paged(D &d,
  search_params request,
  std::int32_t page_size,
  std::size_t max_pages = search_paged_default_max_pages,
  std::pmr::memory_resource *mr = std::pmr::get_default_resource()) -> result<search_result>
{
	return sync::run(d, [&](auto &a) { return ldap::search_paged(a, std::move(request), page_size, max_pages, mr); });
}

}// namespace jhetz::ldap::sync
