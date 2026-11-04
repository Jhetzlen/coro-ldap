// Blocking facades over ldap::connection and ldap::client (DESIGN.md
// sections 7 and 11): for code that does not use coroutines. Part of
// jhetz::ldap_net.
//
//   ldap::sync::connection c;
//   if (auto r = c.connect("ldaps://ldap.example.org"); !r) ...
//   c.simple_bind(ldap::dn{"cn=admin,dc=example,dc=org"}, password);
//   ldap::result<std::vector<person>> people = c.search_as<person>({.base = base});
//
//   ldap::sync::client pool({.servers = {...}, .setup = ldap::simple_bind_setup(...)});
//   auto found = pool.search({.base = base});      // a shared lease for one search, retried once
//   if (auto lease = pool.acquire({.exclusive = true})) lease->modify(...);
//
// A sync::connection (a sync::client) owns an io_context and one I/O
// thread running it. Each method starts the matching coroutine of
// ldap::connection (ldap::client) on that thread and waits for it, with
// exactly the same request, result, error and mapping types, so the APIs
// cannot drift apart. Methods may be called from any number of threads at
// once: their operations are multiplexed on the one connection (on the
// pool's connections).
//
// Calling a method from the facade's own I/O thread (from code running on
// its executor) would wait for itself; it fails at once with
// client_errc::would_deadlock instead.
//
// Exceptions thrown by an operation (allocation failure, programming
// errors) are rethrown in the calling thread; everything else is an
// ldap::error, as in the async API.
//
// sync::connection's shutdown: the destructor closes the connection (no
// UnbindRequest; call unbind() first for a clean end), lets the operations
// still running finish with not_connected, and joins the I/O thread. A
// host name lookup in progress (net::connect runs getaddrinfo detached,
// which cannot be interrupted) is waited for, so destruction can take as
// long as the system resolver's own timeout; so is a SASL step sasl_bind
// gave up on but which still runs on its thread (GSSAPI waiting for a KDC:
// with MIT krb5, bounded by krb5.conf's request_timeout, from 1.22, else
// by its retry schedule, and DNS by resolv.conf). Do not destroy a
// sync::connection while another thread is inside one of its methods, nor
// from its I/O thread.
//
// sync::client (below) has its own rules: see its comment.
#pragma once

#include "jhetz/ldap/client.hpp"
#include "jhetz/ldap/connection.hpp"

#include <boost/capy/ex/run_async.hpp>
#include <boost/capy/ex/work_guard.hpp>
#include <boost/capy/task.hpp>
#include <boost/corosio/io_context.hpp>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <future>
#include <memory>
#include <memory_resource>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <type_traits>
#include <utility>
#include <vector>

namespace jhetz::ldap::sync {

class transaction;

namespace detail {
	template<class> struct task_value;
	template<class R> struct task_value<boost::capy::task<R>>
	{
		using type = R;
	};

	// Writes "jhetz::ldap::<facade>: <what>" to stderr and calls
	// std::terminate(): what a noexcept path of the facades does when it
	// can neither finish its job on the I/O thread nor give it up safely.
	[[noreturn]] void fatal(const char *facade, const char *what) noexcept;

	// A task doing nothing, for a make_task that did its work at once.
	[[nodiscard]] auto done() -> boost::capy::task<result<void>>;

	// An io_context and the one thread running it (kept alive by a work
	// guard until join()): what the blocking facades share.
	class io_thread
	{
	  public:
		// `facade` names the owner in would_deadlock errors' context.
		explicit io_thread(const char *facade);
		io_thread(const io_thread &) = delete;
		auto operator=(const io_thread &) -> io_thread & = delete;
		// join().
		~io_thread();

		[[nodiscard]] auto context() noexcept -> boost::corosio::io_context & { return ioc_; }
		[[nodiscard]] auto executor() const noexcept -> boost::corosio::io_context::executor_type
		{
			return ioc_.get_executor();
		}
		// True on the I/O thread itself.
		[[nodiscard]] auto on_this_thread() const noexcept -> bool { return std::this_thread::get_id() == id_; }

		// Runs make_task(), a function returning a capy::task<result<T>>,
		// on the I/O thread (the task is created there too: whatever
		// make_task touches is only touched on that thread) and waits for
		// its result; an exception it throws is rethrown here. From the I/O
		// thread itself it fails at once with would_deadlock.
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

		// run(make_task) for a noexcept path (a destructor, release()) that
		// hands objects of the I/O thread over to it: make_task, called on
		// the I/O thread, takes them (closes, destroys or moves them). If
		// that fails before make_task was called (out of memory for the
		// post), nothing else may touch those objects from this thread (the
		// I/O thread may be using them: a data race), and waiting for what
		// make_task would have ended may never return: fatal() with `what`.
		// A failure once make_task was called (an exception in it, or in
		// its task) leaves the objects to the I/O thread, and is ignored.
		// From the I/O thread it does nothing (would_deadlock).
		template<class F> void hand_over(const F &make_task, const char *what) const noexcept
		{
			bool taken = false;
			try {
				(void)run([&] {
					taken = true;
					return make_task();
				});
			} catch (...) {
				// `taken` was set on the I/O thread before the exception was
				// stored in the promise, or never: no race reading it here.
				if (!taken) {
					fatal(facade_, what);
				}
			}
		}

		// Drops the work guard and waits for the thread: run() returns once
		// the work left on the io_context (operations ending, a detached
		// unbind, a name lookup) is done. Idempotent. From the I/O thread
		// itself (the facade's last owner destroyed there: it would join
		// itself), fatal().
		void join() noexcept;

	  private:
		const char *facade_;
		boost::corosio::io_context ioc_{};
		std::optional<boost::capy::work_guard<boost::corosio::io_context::executor_type>> guard_;
		std::thread thread_;
		std::thread::id id_;
	};

	// The tasks behind sync::connection_api's non-inline operations
	// (sync.cpp).
	[[nodiscard]] auto
	  collect_paged(ldap::connection &c, search_params request, std::int32_t page_size, std::pmr::memory_resource *mr)
		-> boost::capy::task<result<std::pmr::vector<entry>>>;
	[[nodiscard]] auto make_transaction(ldap::connection &c, extended_controls controls)
	  -> boost::capy::task<result<std::unique_ptr<ldap::transaction>>>;
	[[nodiscard]] auto is_open_of(const ldap::connection &c) -> boost::capy::task<result<bool>>;
	[[nodiscard]] auto is_tls_of(const ldap::connection &c) -> boost::capy::task<result<bool>>;
	[[nodiscard]] auto peer_certificate_of(const ldap::connection &c)
	  -> boost::capy::task<result<std::vector<std::byte>>>;
	[[nodiscard]] auto close_of(ldap::connection &c) -> boost::capy::task<result<void>>;

	template<class Derived> class connection_api;
}// namespace detail

// ldap::transaction (transaction.hpp) for a sync::connection or a
// sync::lease: each method runs the async one on its I/O thread and waits
// for it, with the same results. Destroyed while still open, it aborts the
// transaction and waits for the server's answer (ignored), five seconds at
// most even without a default timeout (the abort is then abandoned and
// queued again without waiting); from the I/O thread itself it queues the
// abort without waiting, as ldap::transaction does. Made by a
// sync::connection, it must not outlive it. Made by a sync::lease, it
// shares the ownership of the client's I/O thread as the lease does, so
// it may outlive the lease and the client without dangling; but keep the
// lease while using it: `pool.acquire()->begin_transaction()` releases
// the lease at the end of the statement, and the transaction then runs on
// a connection back in the pool, which other leases may share, and which
// the pool may unbind or close under it (max_lifetime, a failed idle
// check, failback, the client's destruction). As the last owner of the
// I/O thread (the client, the leases and the other transactions gone), it
// must not be destroyed or move-assigned on that thread: it would join
// itself, and std::terminate() is called with a message on stderr.
// Move-only. Not [[nodiscard]] as a class: it comes inside a result,
// which is [[nodiscard]] on its own.
class transaction
{
  public:
	transaction(transaction &&other) noexcept;
	auto operator=(transaction &&other) noexcept -> transaction &;
	transaction(const transaction &) = delete;
	auto operator=(const transaction &) -> transaction & = delete;
	~transaction();

	// A copy of ldap::transaction::identifier(); empty once moved from.
	[[nodiscard]] auto identifier() const -> std::string;
	[[nodiscard]] auto is_open() const -> bool;

	[[nodiscard]] auto add(add_params request) -> result<response>;
	[[nodiscard]] auto modify(modify_params request) -> result<response>;
	[[nodiscard]] auto del(del_params request) -> result<response>;
	[[nodiscard]] auto modify_dn(modify_dn_params request) -> result<response>;
	[[nodiscard]] auto commit() -> result<commit_result>;
	[[nodiscard]] auto abort() -> result<void>;

  private:
	template<class> friend class detail::connection_api;
	transaction(std::shared_ptr<const detail::io_thread> io, std::unique_ptr<ldap::transaction> t) noexcept;

	// Ends the ldap::transaction on the I/O thread, aborting it first if
	// still open.
	void settle() noexcept;

	// The I/O thread it runs on: owning (the client's core) when made by a
	// sync::lease, not owning when made by a sync::connection.
	std::shared_ptr<const detail::io_thread> io_{};
	// Touched only on the I/O thread (null once moved from).
	std::unique_ptr<ldap::transaction> txn_;
};

namespace detail {

	// The blocking ldap::connection operations, shared by sync::connection
	// and sync::lease. `Derived` provides
	//   call(make_task): runs make_task(c) on the I/O thread with its
	//     ldap::connection c (const from a const member) and waits for it;
	//   runner(): its io_thread, as the shared_ptr a sync::transaction
	//     keeps.
	template<class Derived> class connection_api
	{
	  public:
		// As ldap::connection::is_open() / is_tls(): is_tls() is true only
		// while TLS protects the open connection (false after unbind() or
		// close()).
		[[nodiscard]] auto is_open() const -> bool
		{
			return self().call([](const ldap::connection &c) { return is_open_of(c); }).value_or(false);
		}
		[[nodiscard]] auto is_tls() const -> bool
		{
			return self().call([](const ldap::connection &c) { return is_tls_of(c); }).value_or(false);
		}
		// As ldap::connection::peer_certificate(), copied: the server's
		// certificate (DER), empty unless is_tls().
		[[nodiscard]] auto peer_certificate() const -> std::vector<std::byte>
		{
			return self()
			  .call([](const ldap::connection &c) { return peer_certificate_of(c); })
			  .value_or(std::vector<std::byte>{});
		}

		[[nodiscard]] auto simple_bind(dn name, std::string password) -> result<void>
		{
			return self().call(
			  [&](ldap::connection &c) { return c.simple_bind(std::move(name), std::move(password)); });
		}
		// `mechanism` is used on the I/O thread while the call runs.
		[[nodiscard]] auto sasl_bind(sasl_mechanism &mechanism, dn name = {}) -> result<void>
		{
			return self().call([&](ldap::connection &c) { return c.sasl_bind(mechanism, std::move(name)); });
		}
		[[nodiscard]] auto start_tls(net::tls_options options = {},
		  std::optional<std::chrono::milliseconds> timeout = std::nullopt) -> result<void>
		{
			return self().call([&](ldap::connection &c) { return c.start_tls(std::move(options), timeout); });
		}

		[[nodiscard]] auto search(search_params request,
		  std::pmr::memory_resource *mr = std::pmr::get_default_resource()) -> result<std::pmr::vector<entry>>
		{
			return self().call([&](ldap::connection &c) { return c.search(std::move(request), mr); });
		}
		// Every page of a paged search (ldap::connection::search_paged), collected.
		[[nodiscard]] auto search_paged(search_params request,
		  std::int32_t page_size,
		  std::pmr::memory_resource *mr = std::pmr::get_default_resource()) -> result<std::pmr::vector<entry>>
		{
			return self().call(
			  [&](ldap::connection &c) { return detail::collect_paged(c, std::move(request), page_size, mr); });
		}

		template<described T> [[nodiscard]] auto search_as(search_params request) -> result<std::vector<T>>
		{
			return self().call([&](ldap::connection &c) { return c.search_as<T>(std::move(request)); });
		}

		[[nodiscard]] auto add(add_params request) -> result<response>
		{
			return self().call([&](ldap::connection &c) { return c.add(std::move(request)); });
		}
		template<described T> [[nodiscard]] auto add(dn entry, T value, add_controls controls = {}) -> result<response>
		{
			return self().call(
			  [&](ldap::connection &c) { return c.add(std::move(entry), std::move(value), std::move(controls)); });
		}
		[[nodiscard]] auto modify(modify_params request) -> result<response>
		{
			return self().call([&](ldap::connection &c) { return c.modify(std::move(request)); });
		}
		template<described T>
		[[nodiscard]] auto modify(dn object, std::vector<change<T>> changes, modify_controls controls = {})
		  -> result<response>
		{
			return self().call([&](ldap::connection &c) {
				return c.modify<T>(std::move(object), std::move(changes), std::move(controls));
			});
		}
		[[nodiscard]] auto del(del_params request) -> result<response>
		{
			return self().call([&](ldap::connection &c) { return c.del(std::move(request)); });
		}
		[[nodiscard]] auto modify_dn(modify_dn_params request) -> result<response>
		{
			return self().call([&](ldap::connection &c) { return c.modify_dn(std::move(request)); });
		}
		[[nodiscard]] auto move(dn entry,
		  dn new_parent,
		  modify_dn_controls controls = {},
		  std::optional<std::chrono::milliseconds> timeout = std::nullopt) -> result<response>
		{
			return self().call([&](ldap::connection &c) {
				return c.move(std::move(entry), std::move(new_parent), std::move(controls), timeout);
			});
		}
		[[nodiscard]] auto rename(dn entry,
		  rdn new_rdn,
		  bool delete_old_rdn = true,
		  modify_dn_controls controls = {},
		  std::optional<std::chrono::milliseconds> timeout = std::nullopt) -> result<response>
		{
			return self().call([&](ldap::connection &c) {
				return c.rename(std::move(entry), std::move(new_rdn), delete_old_rdn, std::move(controls), timeout);
			});
		}
		[[nodiscard]] auto compare(compare_params request) -> result<bool>
		{
			return self().call([&](ldap::connection &c) { return c.compare(std::move(request)); });
		}
		[[nodiscard]] auto extended(extended_params request) -> result<extended_result>
		{
			return self().call([&](ldap::connection &c) { return c.extended(std::move(request)); });
		}
		[[nodiscard]] auto who_am_i(extended_controls controls = {}) -> result<std::string>
		{
			return self().call([&](ldap::connection &c) { return c.who_am_i(std::move(controls)); });
		}
		[[nodiscard]] auto password_modify(password_modify_params request) -> result<std::optional<std::string>>
		{
			return self().call([&](ldap::connection &c) { return c.password_modify(std::move(request)); });
		}
		[[nodiscard]] auto change_password(dn user,
		  std::string old_password,
		  std::string new_password,
		  std::optional<ldap::password_method> method = std::nullopt) -> result<void>
		{
			return self().call([&](ldap::connection &c) {
				return c.change_password(std::move(user), std::move(old_password), std::move(new_password), method);
			});
		}
		[[nodiscard]] auto reset_password(dn user,
		  std::string new_password,
		  std::optional<ldap::password_method> method = std::nullopt) -> result<void>
		{
			return self().call(
			  [&](ldap::connection &c) { return c.reset_password(std::move(user), std::move(new_password), method); });
		}

		// LDAP transactions (RFC 5805), as ldap::connection's.
		[[nodiscard]] auto start_transaction(extended_controls controls = {}) -> result<std::pmr::string>
		{
			return self().call([&](ldap::connection &c) { return c.start_transaction(std::move(controls)); });
		}
		[[nodiscard]] auto end_transaction(std::pmr::string identifier, bool commit = true)
		  -> result<end_transaction_result>
		{
			return self().call([&](ldap::connection &c) { return c.end_transaction(std::move(identifier), commit); });
		}
		// start_transaction() wrapped in a sync::transaction (below).
		[[nodiscard]] auto begin_transaction(extended_controls controls = {}) -> result<transaction>
		{
			auto t = self().call([&](ldap::connection &c) { return detail::make_transaction(c, std::move(controls)); });
			if (!t) {
				return std::unexpected(std::move(t.error()));
			}
			return transaction(self().runner(), std::move(*t));
		}

		[[nodiscard]] auto unbind() -> result<void>
		{
			return self().call([](ldap::connection &c) { return c.unbind(); });
		}
		// Closes the connection at once (no UnbindRequest).
		void close()
		{
			(void)self().call([](ldap::connection &c) { return close_of(c); });
		}

	  private:
		friend Derived;
		connection_api() = default;

		[[nodiscard]] auto self() noexcept -> Derived & { return static_cast<Derived &>(*this); }
		[[nodiscard]] auto self() const noexcept -> const Derived & { return static_cast<const Derived &>(*this); }
	};

}// namespace detail

// The blocking ldap::connection: connect(), then the operations of
// detail::connection_api (bind, search, add, ..., unbind, close).
class connection : public detail::connection_api<connection>
{
  public:
	// Starts the I/O thread; not connected yet. `options` apply to
	// connect().
	explicit connection(connection_options options = {});
	connection(const connection &) = delete;
	auto operator=(const connection &) -> connection & = delete;
	// Closes the connection on the I/O thread and joins it. Not on the I/O
	// thread itself: it would join itself, and std::terminate() is called
	// with a message on stderr.
	~connection();

	// Connects (and with options.start_tls, upgrades). Replaces (closes) a
	// previous connection.
	[[nodiscard]] auto connect(url u) -> result<void>;
	// As connect(url), to the URL `text` (url::parse); a bad URL fails with
	// url::parse's error (client_errc::invalid_url) before connecting.
	[[nodiscard]] auto connect(std::string_view text) -> result<void>;

	// The executor of the I/O thread, e.g. to run coroutines next to the
	// facade. Blocking methods called from there fail with would_deadlock.
	[[nodiscard]] auto executor() const noexcept -> ldap::connection::executor_type { return io_.executor(); }

  private:
	friend class detail::connection_api<connection>;

	// Runs make_task(conn_) on the I/O thread and waits for its result;
	// conn_ is const when called from a const member.
	template<class Self, class F>
	auto call(this Self &self, const F &make_task) -> detail::task_value<decltype(make_task(self.conn_))>::type
	{
		return self.io_.run([&] { return make_task(self.conn_); });
	}
	// Not owning: a transaction must not outlive its sync::connection.
	[[nodiscard]] auto runner() const noexcept -> std::shared_ptr<const detail::io_thread>
	{
		return { std::shared_ptr<const detail::io_thread>{}, &io_ };
	}

	connection_options options_;
	detail::io_thread io_{ "sync::connection" };
	ldap::connection conn_{};// touched only on the I/O thread
};

namespace detail {
	struct client_core;
}

// A pooled connection of a sync::client (ldap::lease, blocking): the
// operations of detail::connection_api run on the leased connection, on
// the client's I/O thread. Shared unless acquired with
// acquire_options::exclusive: bind, start_tls() and unbind() belong on an
// exclusive lease (client.hpp, "Leases share connections by default").
// Its methods may be called from any number of threads at once, except
// that moving, reassigning, release() and the destructor must not run
// while another thread is inside one of its methods. A lease may outlive
// its sync::client: the client's destruction closes the leased connection
// (operations then fail with cond::connection_lost), and the I/O thread
// keeps running until the last lease is released or destroyed and the
// last transaction made by one is destroyed. On the I/O thread, release()
// and the destructor return the connection without waiting; but there
// they must not end the last owner of the I/O thread (the client, every
// other lease and their transactions gone): it would join itself, and
// std::terminate() is called with a message on stderr. Move-only. Not
// [[nodiscard]] as a class: it comes inside a result, which is
// [[nodiscard]] on its own.
class lease : public detail::connection_api<lease>
{
  public:
	lease() noexcept = default;
	lease(lease &&other) noexcept;
	auto operator=(lease &&other) noexcept -> lease &;
	lease(const lease &) = delete;
	auto operator=(const lease &) -> lease & = delete;
	// release().
	~lease();

	// False for a default-constructed, moved-from or released lease, whose
	// operations fail with client_errc::not_connected.
	explicit operator bool() const noexcept { return io_ != nullptr; }
	// The server the connection goes to; empty for a false lease.
	[[nodiscard]] auto server() const noexcept -> const url & { return server_; }
	// Returns the connection to the pool now (the destructor's job), on the
	// I/O thread, and waits for that.
	void release() noexcept;

  private:
	friend class client;
	friend class detail::connection_api<lease>;
	lease(std::shared_ptr<const detail::io_thread> io, ldap::lease held, url server) noexcept;

	// Runs make_task(c) on the I/O thread with the leased connection c and
	// waits for its result; not_connected for a false lease.
	template<class Self, class F>
	auto call(this Self &self, const F &make_task)
	  -> detail::task_value<decltype(make_task(std::forward_like<Self &>(std::declval<ldap::connection &>())))>::type
	{
		if (self.io_ == nullptr) {
			return std::unexpected(make_error(client_errc::not_connected, "sync::lease: no connection (released)"));
		}
		return self.io_->run([&] { return make_task(std::forward_like<Self &>(self.held_.get())); });
	}
	[[nodiscard]] auto runner() const noexcept -> std::shared_ptr<const detail::io_thread> { return io_; }

	// Shares the ownership of the client's I/O thread (an aliasing pointer
	// to its client_core); null iff the lease holds nothing.
	std::shared_ptr<const detail::io_thread> io_{};
	ldap::lease held_{};// touched only on the I/O thread
	url server_{};
};

// The blocking ldap::client (client.hpp): a bounded pool of multiplexed
// connections to a list of servers, with failover, backoff, a session
// setup and the forwarders' retries, all as ldap::client's.
//
// It owns an io_context and one I/O thread, where the ldap::client lives:
// the session setup, the observer's hooks and the connections all run
// there. acquire() and the forwarders block the calling thread; any
// number of threads may call them at once (the pool then shares or opens
// connections as ldap::client::acquire() does). close() may be called from
// any thread, the I/O thread included, e.g. while other threads wait in
// acquire(): they then fail with not_connected.
//
// Lifetime: the destructor closes the ldap::client on the I/O thread
// (client::close(): idle connections are unbound, leased ones closed, the
// attempts in progress stopped), then lets the I/O thread run out of
// work, which the unbinds are, and joins it, unless leases or
// transactions made by leases are still alive: those keep the I/O thread
// (and the closed ldap::client) until the last of them is released or
// destroyed, which joins it (see sync::lease). So destroying a
// sync::client with leases outstanding is safe, and their operations fail
// from then on. The memory resource must outlive the I/O thread (the
// client, its last lease and their transactions); the observer
// (client_options::observer) need only outlive close(), the destructor's
// at the latest. Do not destroy a sync::client while another thread is
// inside one of its methods, nor on its I/O thread unless a lease (or a
// transaction made by one) outlives it there: the last owner of the I/O
// thread destroyed on it would join itself, and std::terminate() is
// called with a message on stderr.
//
// No search_stream(): as sync::connection, the facade has no blocking
// stream; use search(), or a lease's search_paged().
class client
{
  public:
	// Starts the I/O thread and makes the ldap::client there; opens
	// nothing yet. Connections' state is allocated from `mr`.
	explicit client(client_options options, std::pmr::memory_resource *mr = std::pmr::get_default_resource());
	client(const client &) = delete;
	auto operator=(const client &) -> client & = delete;
	// close(), then joins the I/O thread unless leases (or transactions
	// made by leases) are still alive.
	~client();

	// The executor of the I/O thread (the ldap::client's), e.g. to run
	// coroutines next to the facade. Blocking methods called from there
	// fail with would_deadlock.
	[[nodiscard]] auto executor() const noexcept -> ldap::client::executor_type;

	// As ldap::client::acquire(), blocking: a lease on a pooled connection,
	// or the same errors (not_connected once close() was called).
	[[nodiscard]] auto acquire(acquire_options options = {}) -> result<lease>;

	// The read forwarders, as ldap::client's: each acquires a shared lease,
	// runs the operation, returns the lease, and retries once on another
	// connection after cond::connection_lost or cond::busy_or_unavailable.
	[[nodiscard]] auto search(search_params request, std::pmr::memory_resource *mr = std::pmr::get_default_resource())
	  -> result<std::pmr::vector<entry>>;
	[[nodiscard]] auto compare(compare_params request) -> result<bool>;
	[[nodiscard]] auto who_am_i(extended_controls controls = {}) -> result<std::string>;
	// As ldap::client's, chasing referrals as client_options::referrals
	// says, with what the chase did (search() and compare() chase too, see
	// "Referrals" in client.hpp). The authorizer and the observer's
	// on_referral run on the I/O thread.
	[[nodiscard]] auto chase_search(search_params request,
	  std::pmr::memory_resource *mr = std::pmr::get_default_resource()) -> result<chased_search>;
	[[nodiscard]] auto chase_compare(compare_params request) -> result<chased_compare>;

	// The write forwarders, as ldap::client's: each acquires a shared
	// lease, runs the operation, returns the lease, and retries once on
	// another connection only after client_errc::not_sent; referral
	// results are errors (errc::referral), never chased.
	[[nodiscard]] auto add(add_params request) -> result<response>;
	[[nodiscard]] auto modify(modify_params request) -> result<response>;
	[[nodiscard]] auto del(del_params request) -> result<response>;
	[[nodiscard]] auto modify_dn(modify_dn_params request) -> result<response>;
	[[nodiscard]] auto move(dn entry,
	  dn new_parent,
	  modify_dn_controls controls = {},
	  std::optional<std::chrono::milliseconds> timeout = std::nullopt) -> result<response>;
	[[nodiscard]] auto rename(dn entry,
	  rdn new_rdn,
	  bool delete_old_rdn = true,
	  modify_dn_controls controls = {},
	  std::optional<std::chrono::milliseconds> timeout = std::nullopt) -> result<response>;

	// As ldap::client::connections(), from any thread (read at once on
	// the I/O thread).
	[[nodiscard]] auto connections() const -> std::size_t;

	// As ldap::client::close(), and waits for it: closes every pooled
	// connection, stops the attempts in progress, and fails waiting and
	// later acquire() calls with not_connected. From the I/O thread it
	// closes at once. Idempotent.
	void close() noexcept;

  private:
	std::shared_ptr<detail::client_core> core_;
};

}// namespace jhetz::ldap::sync
