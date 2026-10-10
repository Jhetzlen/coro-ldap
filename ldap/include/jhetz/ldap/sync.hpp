// Blocking facade over ldap::connection (DESIGN.md section 7): for code
// that does not use coroutines. Part of jhetz::ldap_net.
//
//   ldap::sync::client c;
//   if (auto r = c.connect(*ldap::url::parse("ldaps://ldap.example.org")); !r) ...
//   c.simple_bind(ldap::dn{"cn=admin,dc=example,dc=org"}, password);
//   ldap::result<std::vector<person>> people = c.search_as<person>({.base = base});
//
// A client owns an io_context and one I/O thread running it. Each method
// starts the matching coroutine of ldap::connection on that thread and
// waits for it, with exactly the same request, result, error and mapping
// types, so the two APIs cannot drift apart. Methods may be called from
// any number of threads at once: their operations are multiplexed on the
// one connection.
//
// Calling a method from the client's own I/O thread (from code running on
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
// system resolver's own timeout. Do not destroy a client while another
// thread is inside one of its methods.
#pragma once

#include "jhetz/ldap/connection.hpp"

#include <boost/capy/ex/run_async.hpp>
#include <boost/capy/ex/work_guard.hpp>
#include <boost/capy/task.hpp>
#include <boost/corosio/io_context.hpp>

#include <exception>
#include <future>
#include <memory>
#include <optional>
#include <string>
#include <thread>
#include <vector>

namespace jhetz::ldap::sync {

namespace detail {
	template<class> struct task_value;
	template<class R> struct task_value<boost::capy::task<R>>
	{
		using type = R;
	};
}// namespace detail

class client
{
  public:
	// Starts the I/O thread; not connected yet. `options` apply to
	// connect().
	explicit client(connection_options options = {});
	client(const client &) = delete;
	client &operator=(const client &) = delete;
	~client();

	// Connects (and with options.start_tls, upgrades). Replaces (closes) a
	// previous connection.
	result<void> connect(url u);

	bool is_open() const;
	bool is_tls() const;
	// The executor of the I/O thread, e.g. to run coroutines next to the
	// facade. Blocking methods called from there fail with would_deadlock.
	connection::executor_type executor() const noexcept { return ioc_.get_executor(); }

	result<void> simple_bind(dn name, std::string password)
	{
		return call([&](connection &c) { return c.simple_bind(std::move(name), std::move(password)); });
	}
	// `mechanism` is used on the I/O thread while the call runs.
	result<void> sasl_bind(sasl_mechanism &mechanism, dn name = {})
	{
		return call([&](connection &c) { return c.sasl_bind(mechanism, std::move(name)); });
	}
	result<void> start_tls(net::tls_options options = {},
	  std::optional<std::chrono::milliseconds> timeout = std::nullopt)
	{
		return call([&](connection &c) { return c.start_tls(std::move(options), timeout); });
	}

	result<std::pmr::vector<entry>> search(search_params request,
	  std::pmr::memory_resource *mr = std::pmr::get_default_resource())
	{
		return call([&](connection &c) { return c.search(std::move(request), mr); });
	}
	// Every page of a paged search (connection::search_paged), collected.
	result<std::pmr::vector<entry>> search_paged(search_params request,
	  std::int32_t page_size,
	  std::pmr::memory_resource *mr = std::pmr::get_default_resource());

	template<described T> result<std::vector<T>> search_as(search_params request)
	{
		return call([&](connection &c) { return c.search_as<T>(std::move(request)); });
	}

	result<response> add(add_params request)
	{
		return call([&](connection &c) { return c.add(std::move(request)); });
	}
	template<described T> result<response> add(dn entry, T value, request_controls controls = {})
	{
		return call([&](connection &c) { return c.add(std::move(entry), std::move(value), std::move(controls)); });
	}
	result<response> modify(modify_params request)
	{
		return call([&](connection &c) { return c.modify(std::move(request)); });
	}
	template<described T>
	result<response> modify(dn object, std::vector<change<T>> changes, request_controls controls = {})
	{
		return call(
		  [&](connection &c) { return c.modify<T>(std::move(object), std::move(changes), std::move(controls)); });
	}
	result<response> del(del_params request)
	{
		return call([&](connection &c) { return c.del(std::move(request)); });
	}
	result<response> modify_dn(modify_dn_params request)
	{
		return call([&](connection &c) { return c.modify_dn(std::move(request)); });
	}
	result<bool> compare(compare_params request)
	{
		return call([&](connection &c) { return c.compare(std::move(request)); });
	}
	result<extended_result> extended(extended_params request)
	{
		return call([&](connection &c) { return c.extended(std::move(request)); });
	}
	result<std::string> who_am_i(request_controls controls = {})
	{
		return call([&](connection &c) { return c.who_am_i(std::move(controls)); });
	}
	result<std::optional<std::string>> password_modify(password_modify_params request)
	{
		return call([&](connection &c) { return c.password_modify(std::move(request)); });
	}

	result<void> unbind();
	// Closes the connection at once (no UnbindRequest).
	void close();

  private:
	// Runs make_task(conn_) on the I/O thread and waits for its result.
	template<class F>
	auto call(F &&make_task) -> typename detail::task_value<decltype(make_task(std::declval<connection &>()))>::type
	{
		using R = typename detail::task_value<decltype(make_task(std::declval<connection &>()))>::type;
		if (std::this_thread::get_id() == io_thread_id_)
			return std::unexpected(make_error(client_errc::would_deadlock, "sync::client"));
		std::promise<R> done;
		auto f = done.get_future();
		// The task is created on the I/O thread too (the connection is only
		// touched there): a wrapper coroutine builds and awaits it.
		boost::capy::run_async(
		  ioc_.get_executor(),
		  [&done](R r) { done.set_value(std::move(r)); },
		  [&done](std::exception_ptr e) { done.set_exception(e); })(
		  [](connection &c, F &make) -> boost::capy::task<R> { co_return co_await make(c); }(conn_, make_task));
		return f.get();
	}

	connection_options options_;
	boost::corosio::io_context ioc_{};
	connection conn_{};// touched only on the I/O thread
	std::optional<boost::capy::work_guard<boost::corosio::io_context::executor_type>> guard_;
	std::thread io_thread_;
	std::thread::id io_thread_id_;
};

}// namespace jhetz::ldap::sync
