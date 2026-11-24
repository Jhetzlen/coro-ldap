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
#include <functional>
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

	auto make_stream(ldap::connection &c, search_params request, std::pmr::memory_resource *mr)
	  -> capy::task<result<std::unique_ptr<ldap::search_stream>>>
	{
		auto r = co_await c.search_stream(std::move(request), mr);
		if (!r) {
			co_return std::unexpected(std::move(r.error()));
		}
		co_return std::make_unique<ldap::search_stream>(std::move(*r));
	}

	auto make_stream(ldap::client &c, search_params request, std::pmr::memory_resource *mr)
	  -> capy::task<result<std::unique_ptr<ldap::search_stream>>>
	{
		auto r = co_await c.search_stream(std::move(request), mr);
		if (!r) {
			co_return std::unexpected(std::move(r.error()));
		}
		co_return std::make_unique<ldap::search_stream>(std::move(*r));
	}

}// namespace detail

// ---------------------------------------------------------------- search_stream

search_stream::search_stream(std::shared_ptr<const detail::io_thread> io,
  std::unique_ptr<ldap::search_stream> s) noexcept
  : io_(std::move(io)), stream_(std::move(s))
{}

search_stream::search_stream(search_stream &&other) noexcept
  : io_(std::move(other.io_)), stream_(std::move(other.stream_))
{}

auto search_stream::operator=(search_stream &&other) noexcept -> search_stream &
{
	if (this != &other) {
		settle();
		io_ = std::move(other.io_);
		stream_ = std::move(other.stream_);
	}
	return *this;
}

namespace {

	auto end_search_stream(ldap::search_stream &s) -> capy::task<result<void>>
	{
		co_await ldap::detail::end_search_stream(s);
		co_return result<void>{};
	}

}// namespace

// io_, destroyed after settle(), may be the last owner of a client's core.
search_stream::~search_stream() { settle(); }

void search_stream::settle() noexcept
{
	if (!stream_) {
		return;
	}
	if (io_->on_this_thread()) {
		stream_.reset();
		return;
	}
	// On the connection's strand, so a pool stream's lease return is queued
	// on the client's strand before settle() returns: a client closed next
	// unbinds the connection rather than closing it as still leased.
	// Terminates if the post cannot be allocated.
	io_->hand_over(
	  [this] { return end_search_stream(*stream_); }, "out of memory ending a search stream on the I/O thread");
	stream_.reset();// moved from on the strand: nothing left to post
}

namespace {

	auto no_stream() -> error
	{
		return make_error(client_errc::not_connected, "search: no search stream (moved from)");
	}

}// namespace

auto search_stream::next() -> result<std::optional<entry>>
{
	if (!stream_) {
		return std::unexpected(no_stream());
	}
	return io_->run([this] { return stream_->next(); });
}

auto search_stream::next_item() -> result<std::optional<ldap::search_stream::item>>
{
	if (!stream_) {
		return std::unexpected(no_stream());
	}
	return io_->run([this] { return stream_->next_item(); });
}

auto search_stream::done() const -> bool
{
	if (!stream_) {
		return true;
	}
	const ldap::search_stream *s = stream_.get();
	return io_->run([s] { return detail::invoked([s] { return s->done(); }); }).value_or(true);
}

auto search_stream::references() const -> string_list
{
	if (!stream_) {
		return {};
	}
	const ldap::search_stream *s = stream_.get();
	return io_->run([s] { return detail::invoked([s] { return string_list(s->references()); }); })
	  .value_or(string_list{});
}

auto search_stream::reference_urls(std::pmr::memory_resource *mr) const -> std::pmr::vector<url>
{
	if (!stream_) {
		return std::pmr::vector<url>(mr);
	}
	const ldap::search_stream *s = stream_.get();
	return io_->run([s, mr] { return detail::invoked([s, mr] { return s->reference_urls(mr); }); })
	  .value_or(std::pmr::vector<url>(mr));
}

auto search_stream::controls() const -> std::pmr::vector<control>
{
	if (!stream_) {
		return {};
	}
	const ldap::search_stream *s = stream_.get();
	return io_->run([s] { return detail::invoked([s] { return std::pmr::vector<control>(s->controls()); }); })
	  .value_or(std::pmr::vector<control>{});
}

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

	// The update `Op` of `t`, on the I/O thread `io`.
	template<auto Op, class Params>
	auto update(const detail::io_thread *io, ldap::transaction *t, Params request) -> result<response>
	{
		if (t == nullptr) {
			return std::unexpected(moved_from(ldap::detail::update_op<Params>::name));
		}
		return io->run([&] { return std::invoke(Op, *t, std::move(request)); });
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
	return io_->run([t] { return detail::invoked([t] { return std::string(t->identifier()); }); })
	  .value_or(std::string{});
}

auto transaction::is_open() const -> bool
{
	if (!txn_) {
		return false;
	}
	const ldap::transaction *t = txn_.get();
	return io_->run([t] { return detail::invoked([t] { return t->is_open(); }); }).value_or(false);
}

auto transaction::add(add_params request) -> result<response>
{
	return update<&ldap::transaction::add>(io_.get(), txn_.get(), std::move(request));
}

auto transaction::modify(modify_params request) -> result<response>
{
	return update<&ldap::transaction::modify>(io_.get(), txn_.get(), std::move(request));
}

auto transaction::del(del_params request) -> result<response>
{
	return update<&ldap::transaction::del>(io_.get(), txn_.get(), std::move(request));
}

auto transaction::modify_dn(modify_dn_params request) -> result<response>
{
	return update<&ldap::transaction::modify_dn>(io_.get(), txn_.get(), std::move(request));
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

		// Closes the ldap::client on its strand.
		static auto close(client_core &core) -> capy::task<result<void>>
		{
			if (!core.pool) {
				co_return result<void>{};
			}
			co_return co_await ldap::detail::on_strand(
			  core.pool->executor(), invoked([&pool = *core.pool] { pool.close(); }));
		}
	};

	namespace {

		// The ldap::client operation `Op` with `args`, run on the I/O thread.
		template<auto Op, class... Args> auto on_pool(client_core &core, Args &&...args)
		{
			return core.io.run([&] { return std::invoke(Op, *core.pool, std::forward<Args>(args)...); });
		}

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
	return detail::on_pool<&ldap::client::search>(*core_, std::move(request), mr);
}

auto client::search_stream(search_params request, std::pmr::memory_resource *mr) -> result<sync::search_stream>
{
	auto s = core_->io.run([&] { return detail::make_stream(*core_->pool, std::move(request), mr); });
	if (!s) {
		return std::unexpected(std::move(s.error()));
	}
	// The stream shares the ownership of the core, as a lease does.
	return sync::search_stream(std::shared_ptr<const detail::io_thread>(core_, &core_->io), std::move(*s));
}

auto client::compare(compare_params request) -> result<compare_result>
{
	return detail::on_pool<&ldap::client::compare>(*core_, std::move(request));
}

auto client::add(add_params request) -> result<response>
{
	return detail::on_pool<&ldap::client::add>(*core_, std::move(request));
}

auto client::modify(modify_params request) -> result<response>
{
	return detail::on_pool<&ldap::client::modify>(*core_, std::move(request));
}

auto client::del(del_params request) -> result<response>
{
	return detail::on_pool<&ldap::client::del>(*core_, std::move(request));
}

auto client::modify_dn(modify_dn_params request) -> result<response>
{
	return detail::on_pool<&ldap::client::modify_dn>(*core_, std::move(request));
}

auto client::extended(extended_params request) -> result<extended_result>
{
	return detail::on_pool<&ldap::client::extended>(*core_, std::move(request));
}

auto client::connections() const -> std::size_t
{
	if (core_->io.on_this_thread()) {
		return core_->pool ? core_->pool->connections() : 0;
	}
	return core_->io.run([this] { return detail::invoked([this] { return core_->pool->connections(); }); }).value_or(0);
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
