#include "jhetz/ldap/sync.hpp"
#include "jhetz/ldap/cancel.hpp"

#include "connection/search.hpp"
#include "strand_util.hpp"

#include <boost/capy/when_any.hpp>
#include <boost/corosio/delay.hpp>

#include <chrono>
#include <cstddef>
#include <cstdio>
#include <exception>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

namespace capy = boost::capy;

namespace jhetz::ldap::sync {

// ---------------------------------------------------------------- io_thread

namespace detail {

	void fatal(const char *facade, const char *what) noexcept
	{
		(void)std::fputs("jhetz::ldap::", stderr);
		(void)std::fputs(facade, stderr);
		(void)std::fputs(": ", stderr);
		(void)std::fputs(what, stderr);
		(void)std::fputs("\n", stderr);
		std::terminate();
	}

	auto done() -> capy::task<result<void>> { co_return result<void>{}; }

	io_thread::io_thread(const char *facade) : facade_(facade)
	{
		guard_.emplace(ioc_.get_executor());
		thread_ = std::thread([this] { ioc_.run(); });
		id_ = thread_.get_id();
	}

	io_thread::~io_thread() { join(); }

	void io_thread::join() noexcept
	{
		guard_.reset();
		if (!thread_.joinable()) {
			return;
		}
		if (on_this_thread()) {
			fatal(facade_, "destroyed on its own I/O thread (it would join itself)");
		}
		thread_.join();
	}

	namespace {

		// On the paged_search's strand: it ends there, before the result is
		// delivered.
		auto collect_pages(ldap::paged_search pages, std::pmr::memory_resource *mr) -> capy::task<result<search_result>>
		{
			ldap::paged_search s = std::move(pages);
			co_return co_await ldap::detail::collect_search(s, [](ldap::paged_search &p) { return p.next(); }, mr);
		}

		template<class D>
		auto collect(D &d,
		  search_params request,
		  std::int32_t page_size,
		  std::size_t max_pages,
		  std::pmr::memory_resource *mr) -> capy::task<result<search_result>>
		{
			auto s = co_await ldap::search_paged(d, std::move(request), page_size, max_pages, mr);
			if (!s) {
				co_return std::unexpected(std::move(s.error()));
			}
			const auto strand = ldap::detail::paged_executor(*s);
			if (!strand) {
				co_return co_await collect_pages(std::move(*s), mr);
			}
			co_return co_await ldap::detail::on_strand(*strand, collect_pages(std::move(*s), mr));
		}

	}// namespace

	auto collect_paged(ldap::connection &c,
	  search_params request,
	  std::int32_t page_size,
	  std::size_t max_pages,
	  std::pmr::memory_resource *mr) -> capy::task<result<search_result>>
	{
		return collect(c, std::move(request), page_size, max_pages, mr);
	}

	auto collect_paged(ldap::client &c,
	  search_params request,
	  std::int32_t page_size,
	  std::size_t max_pages,
	  std::pmr::memory_resource *mr) -> capy::task<result<search_result>>
	{
		return collect(c, std::move(request), page_size, max_pages, mr);
	}

	// The ldap::transaction is made, and later destroyed, on the I/O thread.
	auto make_transaction(ldap::connection &c, extended_controls controls)
	  -> capy::task<result<std::unique_ptr<ldap::transaction>>>
	{
		auto r = co_await ldap::transaction::begin(c, std::move(controls));
		if (!r) {
			co_return std::unexpected(std::move(r.error()));
		}
		co_return std::make_unique<ldap::transaction>(std::move(*r));
	}

	auto is_open_of(const ldap::connection &c) -> capy::task<result<bool>> { co_return c.is_open(); }

	auto is_tls_of(const ldap::connection &c) -> capy::task<result<bool>> { co_return c.is_tls(); }

	auto security_layer_of(const ldap::connection &c) -> capy::task<result<sasl_protection>>
	{
		co_return c.security_layer();
	}

	auto peer_certificate_of(const ldap::connection &c) -> capy::task<result<std::vector<std::byte>>>
	{
		const auto der = c.peer_certificate();
		co_return std::vector<std::byte>(der.begin(), der.end());
	}

	auto close_of(ldap::connection &c) -> capy::task<result<void>>
	{
		c.close();
		co_return result<void>{};
	}

}// namespace detail

// ---------------------------------------------------------------- connection

namespace detail {

	connection_core::~connection_core()
	{
		// Close on the I/O thread, then let the io_context run out of work.
		// Terminates if the post cannot be allocated.
		io.hand_over(
		  [this] {
			  conn.close();
			  conn = ldap::connection{};
			  return done();
		  },
		  "out of memory closing the connection on the I/O thread");
		io.join();
	}

	namespace {

		auto open_on(connection_core &core, url where, connection_options o, std::pmr::memory_resource *mr)
		  -> capy::task<result<void>>
		{
			auto r = co_await ldap::connect(core.io.context(), std::move(where), std::move(o), mr);
			if (!r) {
				co_return std::unexpected(std::move(r.error()));
			}
			core.conn = std::move(*r);
			co_return result<void>{};
		}

	}// namespace

}// namespace detail

auto connect(url u, connection_options options, std::pmr::memory_resource *mr) -> result<connection>
{
	auto core = std::make_shared<detail::connection_core>();
	auto r = core->io.run([&] { return detail::open_on(*core, std::move(u), std::move(options), mr); });
	if (!r) {
		return std::unexpected(std::move(r.error()));
	}
	return connection(std::move(core));
}

auto connect(std::string_view text, connection_options options, std::pmr::memory_resource *mr) -> result<connection>
{
	auto u = url::parse(text);
	if (!u) {
		return std::unexpected(std::move(u.error()));
	}
	return connect(std::move(*u), std::move(options), mr);
}

// ---------------------------------------------------------------- transaction

namespace {

	auto moved_from(std::string_view what) -> error
	{
		return make_error(client_errc::not_connected, std::string(what) + ": no transaction (moved from)");
	}

	// How long finish() waits at most for the answer to its abort.
	constexpr std::chrono::seconds abort_wait_limit{ 5 };

	// Aborts `t` if still open, then destroys it, on the I/O thread.
	auto finish(std::unique_ptr<ldap::transaction> t) -> capy::task<result<void>>
	{
		if (t->is_open()) {
			// The outcome does not matter here.
			(void)co_await capy::when_any(ldap::raceable(t->abort()), boost::corosio::delay(abort_wait_limit));
		}
		co_return result<void>{};
	}

	// ldap::transaction's accessors, read on the I/O thread.
	auto identifier_of(const ldap::transaction *t) -> capy::task<result<std::string>>
	{
		co_return std::string(t->identifier());
	}
	auto is_open_of(const ldap::transaction *t) -> capy::task<result<bool>> { co_return t->is_open(); }

}// namespace

transaction::transaction(std::shared_ptr<const detail::io_thread> io, std::unique_ptr<ldap::transaction> t) noexcept
  : io_(std::move(io)), txn_(std::move(t))
{}

transaction::transaction(transaction &&other) noexcept : io_(std::move(other.io_)), txn_(std::move(other.txn_)) {}

auto transaction::operator=(transaction &&other) noexcept -> transaction &
{
	if (this != &other) {
		settle();
		io_ = std::move(other.io_);
		txn_ = std::move(other.txn_);
	}
	return *this;
}

// io_, destroyed after settle(), may be the last owner of a client's core:
// its destructor then joins the I/O thread.
transaction::~transaction() { settle(); }

void transaction::settle() noexcept
{
	if (!txn_) {
		return;
	}
	if (io_->on_this_thread()) {
		// The ldap::transaction queues its abort without waiting.
		txn_.reset();
		return;
	}
	// finish() takes txn_ on the I/O thread; terminates if the post cannot be
	// allocated.
	io_->hand_over([this] { return finish(std::move(txn_)); }, "out of memory ending a transaction on the I/O thread");
}

auto transaction::identifier() const -> std::string
{
	if (!txn_) {
		return {};
	}
	const ldap::transaction *t = txn_.get();
	return io_->run([t] { return identifier_of(t); }).value_or(std::string{});
}

auto transaction::is_open() const -> bool
{
	if (!txn_) {
		return false;
	}
	const ldap::transaction *t = txn_.get();
	return io_->run([t] { return is_open_of(t); }).value_or(false);
}

auto transaction::add(add_params request) -> result<response>
{
	if (!txn_) {
		return std::unexpected(moved_from("add"));
	}
	return io_->run([&] { return txn_->add(std::move(request)); });
}

auto transaction::modify(modify_params request) -> result<response>
{
	if (!txn_) {
		return std::unexpected(moved_from("modify"));
	}
	return io_->run([&] { return txn_->modify(std::move(request)); });
}

auto transaction::del(del_params request) -> result<response>
{
	if (!txn_) {
		return std::unexpected(moved_from("delete"));
	}
	return io_->run([&] { return txn_->del(std::move(request)); });
}

auto transaction::modify_dn(modify_dn_params request) -> result<response>
{
	if (!txn_) {
		return std::unexpected(moved_from("modify DN"));
	}
	return io_->run([&] { return txn_->modify_dn(std::move(request)); });
}

auto transaction::commit() -> result<commit_result>
{
	if (!txn_) {
		return std::unexpected(moved_from("commit transaction"));
	}
	return io_->run([this] { return txn_->commit(); });
}

auto transaction::abort() -> result<void>
{
	if (!txn_) {
		return std::unexpected(moved_from("abort transaction"));
	}
	return io_->run([this] { return txn_->abort(); });
}

// ---------------------------------------------------------------- client

namespace detail {

	// What a sync::client and its leases share; the last owner destroys the
	// ldap::client on the I/O thread and joins.
	struct client_core
	{
		io_thread io{ "sync::client" };
		std::optional<ldap::client> pool{};// touched only on the I/O thread

		client_core(client_options options, std::pmr::memory_resource *mr)
		{
			// Made on the I/O thread; an exception (out of memory) is
			// rethrown here, and io's destructor joins.
			(void)io.run([&] -> capy::task<result<void>> {
				return
				  [](client_core &core, client_options &o, std::pmr::memory_resource *m) -> capy::task<result<void>> {
					  core.pool.emplace(core.io.context(), std::move(o), m);
					  co_return result<void>{};
				  }(*this, options, mr);
			});
		}
		client_core(const client_core &) = delete;
		auto operator=(const client_core &) -> client_core & = delete;
		client_core(client_core &&) = delete;
		auto operator=(client_core &&) -> client_core & = delete;

		// Closes and destroys the ldap::client, then lets its tasks finish and
		// joins. Terminates if the post cannot be allocated.
		~client_core()
		{
			io.hand_over(
			  [this] {
				  pool.reset();
				  return done();
			  },
			  "out of memory destroying the ldap::client on the I/O thread");
			io.join();
		}

		static auto close_now(ldap::client &pool) -> capy::task<result<void>>
		{
			pool.close();
			co_return result<void>{};
		}

		// Closes the ldap::client on its strand.
		static auto close(client_core &core) -> capy::task<result<void>>
		{
			if (!core.pool) {
				co_return result<void>{};
			}
			co_return co_await ldap::detail::on_strand(core.pool->executor(), close_now(*core.pool));
		}
	};

	namespace {

		template<class Lease> auto take_lease(ldap::client &pool) -> capy::task<result<std::pair<Lease, url>>>
		{
			auto l = co_await [&pool] {
				if constexpr (std::is_same_v<Lease, ldap::exclusive_lease>) {
					return pool.acquire_exclusive();
				} else {
					return pool.acquire();
				}
			}();
			if (!l) {
				co_return std::unexpected(std::move(l.error()));
			}
			url server = l->server();
			co_return std::pair{ std::move(*l), std::move(server) };
		}

		auto connections_of(const ldap::client &pool) -> capy::task<result<std::size_t>>
		{
			co_return pool.connections();
		}

	}// namespace

}// namespace detail

template<bool Exclusive>
basic_lease<Exclusive>::basic_lease(std::shared_ptr<const detail::io_thread> io, held_lease held, url server) noexcept
  : io_(std::move(io)), held_(std::move(held)), server_(std::move(server))
{}

template<bool Exclusive>
basic_lease<Exclusive>::basic_lease(basic_lease &&other) noexcept
  : io_(std::move(other.io_)), held_(std::move(other.held_)), server_(std::move(other.server_))
{
	other.server_ = url{};
}

template<bool Exclusive> auto basic_lease<Exclusive>::operator=(basic_lease &&other) noexcept -> basic_lease &
{
	if (this != &other) {
		release();
		io_ = std::move(other.io_);
		held_ = std::move(other.held_);
		server_ = std::exchange(other.server_, url{});
	}
	return *this;
}

template<bool Exclusive> basic_lease<Exclusive>::~basic_lease() { release(); }

template<bool Exclusive> void basic_lease<Exclusive>::release() noexcept
{
	if (io_ == nullptr) {
		return;
	}
	if (io_->on_this_thread()) {
		held_.release();
	} else {
		// Terminates if the post cannot be allocated.
		io_->hand_over(
		  [this] {
			  held_.release();
			  return detail::done();
		  },
		  "out of memory returning a lease's connection on the I/O thread");
	}
	server_ = url{};
	// May be the I/O thread's last owner: its client_core then joins it.
	io_.reset();
}

template class basic_lease<false>;
template class basic_lease<true>;

client::client(client_options options, std::pmr::memory_resource *mr)
  : core_(std::make_shared<detail::client_core>(std::move(options), mr))
{}

// The leases keep core_ (and so the I/O thread) alive; the last owner's
// client_core destructor joins it.
client::~client() { close(); }

auto client::executor() const noexcept -> boost::corosio::io_context::executor_type { return core_->io.executor(); }

auto client::io() const noexcept -> const detail::io_thread & { return core_->io; }

auto client::pool() const noexcept -> ldap::client &
{
	return *core_->pool;// NOLINT(bugprone-unchecked-optional-access): engaged until the core is destroyed
}

auto client::acquire() -> result<lease>
{
	auto r = core_->io.run([&] { return detail::take_lease<ldap::lease>(*core_->pool); });
	if (!r) {
		return std::unexpected(std::move(r.error()));
	}
	// The lease shares the ownership of the core, pointing at its I/O thread.
	return lease(
	  std::shared_ptr<const detail::io_thread>(core_, &core_->io), std::move(r->first), std::move(r->second));
}

auto client::acquire_exclusive() -> result<exclusive_lease>
{
	auto r = core_->io.run([&] { return detail::take_lease<ldap::exclusive_lease>(*core_->pool); });
	if (!r) {
		return std::unexpected(std::move(r.error()));
	}
	return exclusive_lease(
	  std::shared_ptr<const detail::io_thread>(core_, &core_->io), std::move(r->first), std::move(r->second));
}
auto client::search(search_params request, std::pmr::memory_resource *mr) -> result<search_result>
{
	return core_->io.run([&] { return core_->pool->search(std::move(request), mr); });
}

auto client::compare(compare_params request) -> result<compare_result>
{
	return core_->io.run([&] { return core_->pool->compare(std::move(request)); });
}

auto client::add(add_params request) -> result<response>
{
	return core_->io.run([&] { return core_->pool->add(std::move(request)); });
}

auto client::modify(modify_params request) -> result<response>
{
	return core_->io.run([&] { return core_->pool->modify(std::move(request)); });
}

auto client::del(del_params request) -> result<response>
{
	return core_->io.run([&] { return core_->pool->del(std::move(request)); });
}

auto client::modify_dn(modify_dn_params request) -> result<response>
{
	return core_->io.run([&] { return core_->pool->modify_dn(std::move(request)); });
}

auto client::extended(extended_params request) -> result<extended_result>
{
	return core_->io.run([&] { return core_->pool->extended(std::move(request)); });
}

auto client::connections() const -> std::size_t
{
	if (core_->io.on_this_thread()) {
		return core_->pool ? core_->pool->connections() : 0;
	}
	return core_->io.run([this] { return detail::connections_of(*core_->pool); }).value_or(0);
}

void client::close() noexcept
{
	if (core_->io.on_this_thread()) {
		if (core_->pool) {
			core_->pool->close();
		}
		return;
	}
	try {
		(void)core_->io.run([this] { return detail::client_core::close(*core_); });
	} catch (...) {// NOLINT(bugprone-empty-catch): out of memory; the last owner's destructor still closes
	}
}

}// namespace jhetz::ldap::sync
