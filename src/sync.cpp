#include "jhetz/ldap/sync.hpp"

#include <cstddef>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace capy = boost::capy;

namespace jhetz::ldap::sync {

connection::connection(connection_options options) : options_(std::move(options))
{
	guard_.emplace(ioc_.get_executor());
	io_thread_ = std::thread([this] { ioc_.run(); });
	io_thread_id_ = io_thread_.get_id();
}

connection::~connection()
{
	// Close on the I/O thread, then let the io_context run out of work:
	// operations still running finish with not_connected, a detached name
	// lookup or offloaded SASL step finishes, and run() returns. ioc_'s
	// destructor then joins that step's thread.
	std::promise<void> closed;
	capy::run_async(ioc_.get_executor())([](ldap::connection &c, std::promise<void> &p) -> capy::task<void> {
		c = ldap::connection{};
		p.set_value();
		co_return;
	}(conn_, closed));
	closed.get_future().wait();
	guard_.reset();
	io_thread_.join();
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
		}(c, ioc_, std::move(u), options_);
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

auto connection::is_open() const -> bool
{
	return call([](const ldap::connection &c) -> capy::task<result<bool>> { co_return c.is_open(); }).value_or(false);
}

auto connection::is_tls() const -> bool
{
	return call([](const ldap::connection &c) -> capy::task<result<bool>> { co_return c.is_tls(); }).value_or(false);
}

auto connection::peer_certificate() const -> std::vector<std::byte>
{
	return call([](const ldap::connection &c) -> capy::task<result<std::vector<std::byte>>> {
		const auto der = c.peer_certificate();
		co_return std::vector<std::byte>(der.begin(), der.end());
	}).value_or(std::vector<std::byte>{});
}

auto connection::search_paged(search_params request, std::int32_t page_size, std::pmr::memory_resource *mr)
  -> result<std::pmr::vector<entry>>
{
	return call([&](ldap::connection &c) {
		return [](ldap::connection &conn,
				 search_params p,
				 std::int32_t n,
				 std::pmr::memory_resource *m) -> capy::task<result<std::pmr::vector<entry>>> {
			auto s = co_await conn.search_paged(std::move(p), n, m);
			if (!s) {
				co_return std::unexpected(std::move(s.error()));
			}
			std::pmr::vector<entry> out(m);
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
		}(c, std::move(request), page_size, mr);
	});
}

auto connection::begin_transaction(extended_controls controls) -> result<transaction>
{
	// The ldap::transaction is made, and later destroyed, on the I/O thread.
	auto t = call([&](ldap::connection &c) {
		return
		  [](ldap::connection &conn, extended_controls cs) -> capy::task<result<std::unique_ptr<ldap::transaction>>> {
			  auto r = co_await conn.begin_transaction(std::move(cs));
			  if (!r) {
				  co_return std::unexpected(std::move(r.error()));
			  }
			  co_return std::make_unique<ldap::transaction>(std::move(*r));
		  }(c, std::move(controls));
	});
	if (!t) {
		return std::unexpected(std::move(t.error()));
	}
	return transaction(*this, std::move(*t));
}

// ---------------------------------------------------------------- transaction

namespace {

	auto moved_from(std::string_view what) -> error
	{
		return make_error(client_errc::not_connected, std::string(what) + ": no transaction (moved from)");
	}

	// Aborts `t` if it is still open, then destroys it, on the I/O thread.
	auto finish(std::unique_ptr<ldap::transaction> t) -> capy::task<result<void>>
	{
		if (t->is_open()) {
			(void)co_await t->abort();// the outcome does not matter here
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

transaction::transaction(connection &c, std::unique_ptr<ldap::transaction> t) noexcept : conn_(&c), txn_(std::move(t))
{}

transaction::transaction(transaction &&other) noexcept
  : conn_(std::exchange(other.conn_, nullptr)), txn_(std::move(other.txn_))
{}

auto transaction::operator=(transaction &&other) noexcept -> transaction &
{
	if (this != &other) {
		settle();
		conn_ = std::exchange(other.conn_, nullptr);
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
		if (conn_->call([this](ldap::connection &) { return finish(std::move(txn_)); })) {
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
	return conn_->call([t](const ldap::connection &) { return identifier_of(t); }).value_or(std::string{});
}

auto transaction::is_open() const -> bool
{
	if (!txn_) {
		return false;
	}
	const ldap::transaction *t = txn_.get();
	return conn_->call([t](const ldap::connection &) { return is_open_of(t); }).value_or(false);
}

auto transaction::add(add_params request) -> result<response>
{
	if (!txn_) {
		return std::unexpected(moved_from("add"));
	}
	return conn_->call([&](ldap::connection &) { return txn_->add(std::move(request)); });
}

auto transaction::modify(modify_params request) -> result<response>
{
	if (!txn_) {
		return std::unexpected(moved_from("modify"));
	}
	return conn_->call([&](ldap::connection &) { return txn_->modify(std::move(request)); });
}

auto transaction::del(del_params request) -> result<response>
{
	if (!txn_) {
		return std::unexpected(moved_from("delete"));
	}
	return conn_->call([&](ldap::connection &) { return txn_->del(std::move(request)); });
}

auto transaction::modify_dn(modify_dn_params request) -> result<response>
{
	if (!txn_) {
		return std::unexpected(moved_from("modify DN"));
	}
	return conn_->call([&](ldap::connection &) { return txn_->modify_dn(std::move(request)); });
}

auto transaction::commit() -> result<commit_result>
{
	if (!txn_) {
		return std::unexpected(moved_from("commit transaction"));
	}
	return conn_->call([this](ldap::connection &) { return txn_->commit(); });
}

auto transaction::abort() -> result<void>
{
	if (!txn_) {
		return std::unexpected(moved_from("abort transaction"));
	}
	return conn_->call([this](ldap::connection &) { return txn_->abort(); });
}

auto connection::unbind() -> result<void>
{
	return call([](ldap::connection &c) { return c.unbind(); });
}

void connection::close()
{
	(void)call([](ldap::connection &c) -> capy::task<result<void>> {
		c.close();
		co_return result<void>{};
	});
}

}// namespace jhetz::ldap::sync
