#include "jhetz/ldap/sync.hpp"
#include "jhetz/ldap/cancel.hpp"

#include <boost/capy/when_any.hpp>
#include <boost/corosio/delay.hpp>

#include <chrono>
#include <cstddef>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace capy = boost::capy;

namespace jhetz::ldap::sync {

// ---------------------------------------------------------------- io_thread

namespace detail {

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
		if (thread_.joinable()) {
			thread_.join();
		}
	}

	auto
	  collect_paged(ldap::connection &c, search_params request, std::int32_t page_size, std::pmr::memory_resource *mr)
		-> capy::task<result<std::pmr::vector<entry>>>
	{
		auto s = co_await c.search_paged(std::move(request), page_size, mr);
		if (!s) {
			co_return std::unexpected(std::move(s.error()));
		}
		std::pmr::vector<entry> out(mr);
		while (true) {
			auto e = co_await s->next();
			if (!e) {
				co_return std::unexpected(std::move(e.error()));
			}
			if (!*e) {
				co_return out;
			}
			out.push_back(std::move(**e));
		}
	}

	// The ldap::transaction is made, and later destroyed, on the I/O thread.
	auto make_transaction(ldap::connection &c, extended_controls controls)
	  -> capy::task<result<std::unique_ptr<ldap::transaction>>>
	{
		auto r = co_await c.begin_transaction(std::move(controls));
		if (!r) {
			co_return std::unexpected(std::move(r.error()));
		}
		co_return std::make_unique<ldap::transaction>(std::move(*r));
	}

	auto is_open_of(const ldap::connection &c) -> capy::task<result<bool>> { co_return c.is_open(); }

	auto is_tls_of(const ldap::connection &c) -> capy::task<result<bool>> { co_return c.is_tls(); }

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

connection::connection(connection_options options) : options_(std::move(options)) {}

connection::~connection()
{
	// Close on the I/O thread, then let the io_context run out of work:
	// operations still running finish with not_connected, a detached name
	// lookup or offloaded SASL step finishes, and run() returns. The
	// io_context's destructor then joins that step's thread.
	try {
		(void)io_.run([this] -> capy::task<result<void>> {
			return [](ldap::connection &c) -> capy::task<result<void>> {
				c = ldap::connection{};
				co_return result<void>{};
			}(conn_);
		});
	} catch (...) {// NOLINT(bugprone-empty-catch): out of memory; joining still closes nothing
	}
	io_.join();
}

auto connection::connect(url u) -> result<void>
{
	return call([&](ldap::connection &c) -> capy::task<result<void>> {
		return [](ldap::connection &target,
				 boost::corosio::io_context &ioc,
				 url where,
				 connection_options o) -> capy::task<result<void>> {
			auto r = co_await ldap::connect(ioc, std::move(where), std::move(o));
			if (!r) {
				co_return std::unexpected(std::move(r.error()));
			}
			target = std::move(*r);
			co_return result<void>{};
		}(c, io_.context(), std::move(u), options_);
	});
}

auto connection::connect(std::string_view text) -> result<void>
{
	auto u = url::parse(text);
	if (!u) {
		return std::unexpected(std::move(u.error()));
	}
	return connect(std::move(*u));
}

// ---------------------------------------------------------------- transaction

namespace {

	auto moved_from(std::string_view what) -> error
	{
		return make_error(client_errc::not_connected, std::string(what) + ": no transaction (moved from)");
	}

	// How long finish() waits at most for the server's answer to its abort,
	// so that a sync::transaction's destructor returns even without a
	// default timeout and with a server that never answers.
	constexpr std::chrono::seconds abort_wait_limit{ 5 };

	// Aborts `t` if it is still open, then destroys it, on the I/O thread.
	// If the abort is not answered within abort_wait_limit it is abandoned,
	// and the ldap::transaction's destructor queues another without waiting.
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

transaction::transaction(const detail::io_thread &io, std::unique_ptr<ldap::transaction> t) noexcept
  : io_(&io), txn_(std::move(t))
{}

transaction::transaction(transaction &&other) noexcept
  : io_(std::exchange(other.io_, nullptr)), txn_(std::move(other.txn_))
{}

auto transaction::operator=(transaction &&other) noexcept -> transaction &
{
	if (this != &other) {
		settle();
		io_ = std::exchange(other.io_, nullptr);
		txn_ = std::move(other.txn_);
	}
	return *this;
}

transaction::~transaction() { settle(); }

void transaction::settle() noexcept
{
	if (!txn_) {
		return;
	}
	try {
		if (io_->run([this] { return finish(std::move(txn_)); })) {
			return;
		}
	} catch (...) {// NOLINT(bugprone-empty-catch): the abort is best effort
	}
	// On the I/O thread (would_deadlock): the ldap::transaction queues its
	// abort without waiting.
	txn_.reset();
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

	// What a sync::client and its leases share: the I/O thread and the
	// ldap::client living on it. The last owner destroys the ldap::client
	// on the I/O thread and joins it.
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

		// Closes the ldap::client (idle connections unbound by detached
		// tasks) and destroys it, then lets those tasks finish and joins.
		~client_core()
		{
			try {
				(void)io.run([this] -> capy::task<result<void>> { return reset(*this); });
			} catch (...) {// NOLINT(bugprone-empty-catch): out of memory; joining still ends the thread
			}
			io.join();
		}

		static auto reset(client_core &core) -> capy::task<result<void>>
		{
			core.pool.reset();
			co_return result<void>{};
		}

		static auto close(client_core &core) -> capy::task<result<void>>
		{
			if (core.pool) {
				core.pool->close();
			}
			co_return result<void>{};
		}
	};

	namespace {

		auto take_lease(ldap::client &pool, acquire_options options) -> capy::task<result<std::pair<ldap::lease, url>>>
		{
			auto l = co_await pool.acquire(options);
			if (!l) {
				co_return std::unexpected(std::move(l.error()));
			}
			url server = l->server();
			co_return std::pair{ std::move(*l), std::move(server) };
		}

		auto release_lease(ldap::lease &held) -> capy::task<result<void>>
		{
			held.release();
			co_return result<void>{};
		}

		auto connections_of(const ldap::client &pool) -> capy::task<result<std::size_t>>
		{
			co_return pool.connections();
		}

	}// namespace

}// namespace detail

lease::lease(std::shared_ptr<const detail::io_thread> io, ldap::lease held, url server) noexcept
  : io_(std::move(io)), held_(std::move(held)), server_(std::move(server))
{}

lease::lease(lease &&other) noexcept
  : io_(std::move(other.io_)), held_(std::move(other.held_)), server_(std::move(other.server_))
{
	other.server_ = url{};
}

auto lease::operator=(lease &&other) noexcept -> lease &
{
	if (this != &other) {
		release();
		io_ = std::move(other.io_);
		held_ = std::move(other.held_);
		server_ = std::exchange(other.server_, url{});
	}
	return *this;
}

lease::~lease() { release(); }

void lease::release() noexcept
{
	if (io_ == nullptr) {
		return;
	}
	if (io_->on_this_thread()) {
		held_.release();
	} else {
		try {
			(void)io_->run([this] { return detail::release_lease(held_); });
		} catch (...) {// out of memory for the task: return it here, best effort (as transaction::settle)
			held_.release();
		}
	}
	server_ = url{};
	// May be the I/O thread's last owner: its client_core then joins it.
	io_.reset();
}

client::client(client_options options, std::pmr::memory_resource *mr)
  : core_(std::make_shared<detail::client_core>(std::move(options), mr))
{}

// The leases keep core_ (and so the I/O thread) alive; the last owner's
// client_core destructor joins it.
client::~client() { close(); }

auto client::executor() const noexcept -> ldap::client::executor_type { return core_->io.executor(); }

auto client::acquire(acquire_options options) -> result<lease>
{
	auto r = core_->io.run([&] { return detail::take_lease(*core_->pool, options); });
	if (!r) {
		return std::unexpected(std::move(r.error()));
	}
	// The lease shares the ownership of the core, pointing at its I/O thread.
	return lease(
	  std::shared_ptr<const detail::io_thread>(core_, &core_->io), std::move(r->first), std::move(r->second));
}

auto client::search(search_params request, std::pmr::memory_resource *mr) -> result<std::pmr::vector<entry>>
{
	return core_->io.run([&] { return core_->pool->search(std::move(request), mr); });
}

auto client::compare(compare_params request) -> result<bool>
{
	return core_->io.run([&] { return core_->pool->compare(std::move(request)); });
}

auto client::who_am_i(extended_controls controls) -> result<std::string>
{
	return core_->io.run([&] { return core_->pool->who_am_i(std::move(controls)); });
}

auto client::connections() const -> std::size_t
{
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
