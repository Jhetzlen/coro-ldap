// Blocking facade over ldap::connection (DESIGN.md section 7): for code
// that does not use coroutines. Part of jhetz::ldap_net.
//
//   ldap::sync::connection c;
//   if (auto r = c.connect("ldaps://ldap.example.org"); !r) ...
//   c.simple_bind(ldap::dn{"cn=admin,dc=example,dc=org"}, password);
//   ldap::result<std::vector<person>> people = c.search_as<person>({.base = base});
//
// A sync::connection owns an io_context and one I/O thread running it.
// Each method starts the matching coroutine of ldap::connection on that thread and
// waits for it, with exactly the same request, result, error and mapping
// types, so the two APIs cannot drift apart. Methods may be called from
// any number of threads at once: their operations are multiplexed on the
// one connection.
//
// Calling a method from the facade's own I/O thread (from code running on
// its executor) would wait for itself; it fails at once with
// client_errc::would_deadlock instead.
//
// Exceptions thrown by an operation (allocation failure, programming
// errors) are rethrown in the calling thread; everything else is an
// ldap::error, as in the async API.
//
// Shutdown: the destructor closes the connection (no UnbindRequest; call
// unbind() first for a clean end), lets the operations still running
// finish with not_connected, and joins the I/O thread. A host name lookup
// in progress (net::connect runs getaddrinfo detached, which cannot be
// interrupted) is waited for, so destruction can take as long as the
// system resolver's own timeout; so is a SASL step sasl_bind gave up on
// but which still runs on its thread (GSSAPI waiting for a KDC: with MIT
// krb5, bounded by krb5.conf's request_timeout, from 1.22, else by its
// retry schedule, and DNS by resolv.conf). Do not destroy a
// sync::connection while another thread is inside one of its methods.
#pragma once

#include "jhetz/ldap/connection.hpp"

#include <boost/capy/ex/run_async.hpp>
#include <boost/capy/ex/work_guard.hpp>
#include <boost/capy/task.hpp>
#include <boost/corosio/io_context.hpp>

#include <cstddef>
#include <exception>
#include <future>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

namespace jhetz::ldap::sync {

class transaction;

namespace detail {
	template<class> struct task_value;
	template<class R> struct task_value<boost::capy::task<R>>
	{
		using type = R;
	};
}// namespace detail

class connection
{
  public:
	// Starts the I/O thread; not connected yet. `options` apply to
	// connect().
	explicit connection(connection_options options = {});
	connection(const connection &) = delete;
	auto operator=(const connection &) -> connection & = delete;
	~connection();

	// Connects (and with options.start_tls, upgrades). Replaces (closes) a
	// previous connection.
	[[nodiscard]] auto connect(url u) -> result<void>;
	// As connect(url), to the URL `text` (url::parse); a bad URL fails with
	// url::parse's error (client_errc::invalid_url) before connecting.
	[[nodiscard]] auto connect(std::string_view text) -> result<void>;

	// As ldap::connection::is_open() / is_tls(): is_tls() is true only while TLS
	// protects the open connection (false after unbind() or close()).
	auto is_open() const -> bool;
	auto is_tls() const -> bool;
	// As ldap::connection::peer_certificate(), copied: the server's
	// certificate (DER), empty unless is_tls().
	auto peer_certificate() const -> std::vector<std::byte>;
	// The executor of the I/O thread, e.g. to run coroutines next to the
	// facade. Blocking methods called from there fail with would_deadlock.
	auto executor() const noexcept -> ldap::connection::executor_type { return ioc_.get_executor(); }

	[[nodiscard]] auto simple_bind(dn name, std::string password) -> result<void>
	{
		return call([&](ldap::connection &c) { return c.simple_bind(std::move(name), std::move(password)); });
	}
	// `mechanism` is used on the I/O thread while the call runs.
	[[nodiscard]] auto sasl_bind(sasl_mechanism &mechanism, dn name = {}) -> result<void>
	{
		return call([&](ldap::connection &c) { return c.sasl_bind(mechanism, std::move(name)); });
	}
	[[nodiscard]] auto start_tls(net::tls_options options = {},
	  std::optional<std::chrono::milliseconds> timeout = std::nullopt) -> result<void>
	{
		return call([&](ldap::connection &c) { return c.start_tls(std::move(options), timeout); });
	}

	[[nodiscard]] auto search(search_params request, std::pmr::memory_resource *mr = std::pmr::get_default_resource())
	  -> result<std::pmr::vector<entry>>
	{
		return call([&](ldap::connection &c) { return c.search(std::move(request), mr); });
	}
	// Every page of a paged search (ldap::connection::search_paged), collected.
	[[nodiscard]] auto search_paged(search_params request,
	  std::int32_t page_size,
	  std::pmr::memory_resource *mr = std::pmr::get_default_resource()) -> result<std::pmr::vector<entry>>;

	template<described T> [[nodiscard]] auto search_as(search_params request) -> result<std::vector<T>>
	{
		return call([&](ldap::connection &c) { return c.search_as<T>(std::move(request)); });
	}

	[[nodiscard]] auto add(add_params request) -> result<response>
	{
		return call([&](ldap::connection &c) { return c.add(std::move(request)); });
	}
	template<described T> [[nodiscard]] auto add(dn entry, T value, add_controls controls = {}) -> result<response>
	{
		return call(
		  [&](ldap::connection &c) { return c.add(std::move(entry), std::move(value), std::move(controls)); });
	}
	[[nodiscard]] auto modify(modify_params request) -> result<response>
	{
		return call([&](ldap::connection &c) { return c.modify(std::move(request)); });
	}
	template<described T>
	[[nodiscard]] auto modify(dn object, std::vector<change<T>> changes, modify_controls controls = {})
	  -> result<response>
	{
		return call(
		  [&](ldap::connection &c) { return c.modify<T>(std::move(object), std::move(changes), std::move(controls)); });
	}
	[[nodiscard]] auto del(del_params request) -> result<response>
	{
		return call([&](ldap::connection &c) { return c.del(std::move(request)); });
	}
	[[nodiscard]] auto modify_dn(modify_dn_params request) -> result<response>
	{
		return call([&](ldap::connection &c) { return c.modify_dn(std::move(request)); });
	}
	[[nodiscard]] auto move(dn entry,
	  dn new_parent,
	  modify_dn_controls controls = {},
	  std::optional<std::chrono::milliseconds> timeout = std::nullopt) -> result<response>
	{
		return call([&](ldap::connection &c) {
			return c.move(std::move(entry), std::move(new_parent), std::move(controls), timeout);
		});
	}
	[[nodiscard]] auto rename(dn entry,
	  rdn new_rdn,
	  bool delete_old_rdn = true,
	  modify_dn_controls controls = {},
	  std::optional<std::chrono::milliseconds> timeout = std::nullopt) -> result<response>
	{
		return call([&](ldap::connection &c) {
			return c.rename(std::move(entry), std::move(new_rdn), delete_old_rdn, std::move(controls), timeout);
		});
	}
	[[nodiscard]] auto compare(compare_params request) -> result<bool>
	{
		return call([&](ldap::connection &c) { return c.compare(std::move(request)); });
	}
	[[nodiscard]] auto extended(extended_params request) -> result<extended_result>
	{
		return call([&](ldap::connection &c) { return c.extended(std::move(request)); });
	}
	[[nodiscard]] auto who_am_i(extended_controls controls = {}) -> result<std::string>
	{
		return call([&](ldap::connection &c) { return c.who_am_i(std::move(controls)); });
	}
	[[nodiscard]] auto password_modify(password_modify_params request) -> result<std::optional<std::string>>
	{
		return call([&](ldap::connection &c) { return c.password_modify(std::move(request)); });
	}
	[[nodiscard]] auto change_password(dn user,
	  std::string old_password,
	  std::string new_password,
	  std::optional<ldap::password_method> method = std::nullopt) -> result<void>
	{
		return call([&](ldap::connection &c) {
			return c.change_password(std::move(user), std::move(old_password), std::move(new_password), method);
		});
	}
	[[nodiscard]] auto reset_password(dn user,
	  std::string new_password,
	  std::optional<ldap::password_method> method = std::nullopt) -> result<void>
	{
		return call(
		  [&](ldap::connection &c) { return c.reset_password(std::move(user), std::move(new_password), method); });
	}

	// LDAP transactions (RFC 5805), as ldap::connection's.
	[[nodiscard]] auto start_transaction(extended_controls controls = {}) -> result<std::pmr::string>
	{
		return call([&](ldap::connection &c) { return c.start_transaction(std::move(controls)); });
	}
	[[nodiscard]] auto end_transaction(std::pmr::string identifier, bool commit = true)
	  -> result<end_transaction_result>
	{
		return call([&](ldap::connection &c) { return c.end_transaction(std::move(identifier), commit); });
	}
	// start_transaction() wrapped in a sync::transaction (below).
	[[nodiscard]] auto begin_transaction(extended_controls controls = {}) -> result<transaction>;

	[[nodiscard]] auto unbind() -> result<void>;
	// Closes the connection at once (no UnbindRequest).
	void close();

  private:
	friend class transaction;

	// Runs make_task(conn_) on the I/O thread and waits for its result;
	// conn_ is const when called from a const member.
	template<class Self, class F>
	auto call(this Self &self, const F &make_task) -> detail::task_value<decltype(make_task(self.conn_))>::type
	{
		using R = detail::task_value<decltype(make_task(self.conn_))>::type;
		if (std::this_thread::get_id() == self.io_thread_id_) {
			return std::unexpected(make_error(client_errc::would_deadlock, "sync::connection"));
		}
		std::promise<R> done;
		auto f = done.get_future();
		// The task is created on the I/O thread too (the connection is only
		// touched there): a wrapper coroutine builds and awaits it.
		boost::capy::run_async(
		  self.ioc_.get_executor(),
		  [&done](R r) { done.set_value(std::move(r)); },
		  [&done](std::exception_ptr e) { done.set_exception(std::move(e)); })(
		  [](auto &c, const F &make) -> boost::capy::task<R> { co_return co_await make(c); }(self.conn_, make_task));
		return f.get();
	}

	connection_options options_;
	boost::corosio::io_context ioc_{};
	ldap::connection conn_{};// touched only on the I/O thread
	std::optional<boost::capy::work_guard<boost::corosio::io_context::executor_type>> guard_;
	std::thread io_thread_;
	std::thread::id io_thread_id_;
};

// ldap::transaction (transaction.hpp) for a sync::connection: each method
// runs the async one on the connection's I/O thread and waits for it, with
// the same results. Destroyed while still open, it aborts the transaction
// and waits for the server's answer (ignored); from the I/O thread itself it
// queues the abort without waiting, as ldap::transaction does. Must not
// outlive its sync::connection. Move-only.
class [[nodiscard]] transaction
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
	friend class connection;
	transaction(connection &c, std::unique_ptr<ldap::transaction> t) noexcept;

	// Ends the ldap::transaction on the I/O thread, aborting it first if
	// still open.
	void settle() noexcept;

	connection *conn_ = nullptr;
	// Touched only on the I/O thread (null once moved from).
	std::unique_ptr<ldap::transaction> txn_;
};

}// namespace jhetz::ldap::sync
