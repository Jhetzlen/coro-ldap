#include "jhetz/ldap/sync.hpp"

#include <utility>

namespace capy = boost::capy;

namespace jhetz::ldap::sync {

client::client(connection_options options) : options_(std::move(options))
{
	guard_.emplace(ioc_.get_executor());
	io_thread_ = std::thread([this] { ioc_.run(); });
	io_thread_id_ = io_thread_.get_id();
}

client::~client()
{
	// Close on the I/O thread, then let the io_context run out of work:
	// operations still running finish with not_connected, a detached name
	// lookup finishes, and run() returns.
	std::promise<void> closed;
	capy::run_async(ioc_.get_executor())([](connection &c, std::promise<void> &p) -> capy::task<void> {
		c = connection{};
		p.set_value();
		co_return;
	}(conn_, closed));
	closed.get_future().wait();
	guard_.reset();
	io_thread_.join();
}

result<void> client::connect(url u)
{
	return call([&](connection &c) -> capy::task<result<void>> {
		return [](connection &target,
				 boost::corosio::io_context &ioc,
				 url where,
				 connection_options o) -> capy::task<result<void>> {
			auto r = co_await ldap::connect(ioc, std::move(where), std::move(o));
			if (!r) co_return std::unexpected(std::move(r.error()));
			target = std::move(*r);
			co_return result<void>{};
		}(c, ioc_, std::move(u), options_);
	});
}

bool client::is_open() const
{
	return const_cast<client *>(this)
	  ->call([](connection &c) -> capy::task<result<bool>> { co_return c.is_open(); })
	  .value_or(false);
}

bool client::is_tls() const
{
	return const_cast<client *>(this)
	  ->call([](connection &c) -> capy::task<result<bool>> { co_return c.is_tls(); })
	  .value_or(false);
}

result<std::pmr::vector<entry>>
  client::search_paged(search_params request, std::int32_t page_size, std::pmr::memory_resource *mr)
{
	return call([&](connection &c) {
		return [](connection &conn,
				 search_params p,
				 std::int32_t n,
				 std::pmr::memory_resource *m) -> capy::task<result<std::pmr::vector<entry>>> {
			auto s = co_await conn.search_paged(std::move(p), n, m);
			if (!s) co_return std::unexpected(std::move(s.error()));
			std::pmr::vector<entry> out(m);
			while (true) {
				auto e = co_await s->next();
				if (!e) co_return std::unexpected(std::move(e.error()));
				if (!*e) co_return out;
				out.push_back(std::move(**e));
			}
		}(c, std::move(request), page_size, mr);
	});
}

result<void> client::unbind()
{
	return call([](connection &c) { return c.unbind(); });
}

void client::close()
{
	(void)call([](connection &c) -> capy::task<result<void>> {
		c.close();
		co_return result<void>{};
	});
}

}// namespace jhetz::ldap::sync
