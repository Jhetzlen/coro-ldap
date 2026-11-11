#include "jhetz/ldap/ad/dirsync.hpp"

#include "jhetz/ldap/ad/controls.hpp"
#include "jhetz/ldap/directory.hpp"
#include "jhetz/ldap/operations.hpp"

#include <boost/capy/task.hpp>

#include <iterator>
#include <string>
#include <utility>

namespace capy = boost::capy;

namespace jhetz::ldap::ad {

namespace {

	auto
	  poll(connection &c, const search_params &request, const dirsync_request &options, std::pmr::memory_resource *mr)
		-> capy::task<result<dirsync_result>>
	{
		const std::string context = detail::op_context("DirSync", request.base);
		dirsync_result out{ .entries = std::pmr::vector<entry>(mr), .cookie = options.cookie };
		while (true) {
			search_params query = request;
			dirsync_request control = options;
			control.cookie = out.cookie;
			query.controls.push_back(encode_dirsync_request(control));
			auto found = co_await c.search(std::move(query), mr);
			if (!found) {
				co_return std::unexpected(detail::with_context(std::move(found.error()), context));
			}
			if (!found->is_success()) {
				co_return std::unexpected(detail::search_error(*found, context));
			}
			auto response = find_dirsync_response(found->controls);
			if (!response) {
				co_return std::unexpected(detail::with_context(std::move(response.error()), context));
			}
			if (!*response) {
				co_return fail(
				  client_errc::unexpected_response, context + ": no DirSync control in the SearchResultDone");
			}
			out.entries.insert(out.entries.end(),
			  std::make_move_iterator(found->entries.begin()),
			  std::make_move_iterator(found->entries.end()));
			const bool same = (*response)->cookie_server == out.cookie;
			out.cookie = std::move((*response)->cookie_server);
			if (!(*response)->more_results) {
				co_return out;
			}
			if (same) {
				co_return fail(client_errc::unexpected_response, context + ": more results without a new cookie");
			}
		}
	}

	// `first` and `retry` are acquire() tasks of the same client: `retry`
	// runs only after cond::connection_lost on the first lease.
	auto poll(capy::task<result<lease>> first,
	  capy::task<result<lease>> retry,
	  search_params request,
	  dirsync_request options,
	  std::pmr::memory_resource *mr) -> capy::task<result<dirsync_result>>
	{
		{
			auto l = co_await std::move(first);
			if (!l) {
				co_return std::unexpected(std::move(l.error()));
			}
			auto r = co_await poll(l->get(), request, options, mr);
			if (r || r.error().code != cond::connection_lost) {
				co_return r;
			}
		}
		auto l = co_await std::move(retry);
		if (!l) {
			co_return std::unexpected(std::move(l.error()));
		}
		co_return co_await poll(l->get(), request, options, mr);
	}

	auto start(connection &c, search_params request, dirsync_request options, std::pmr::memory_resource *mr)
	  -> capy::task<result<dirsync_result>>
	{
		co_return co_await poll(c, request, options, mr);
	}

}// namespace

auto dirsync(connection &c, search_params request, dirsync_request options, std::pmr::memory_resource *mr)
  -> capy::task<result<dirsync_result>>
{
	return start(c, std::move(request), std::move(options), mr);
}

auto dirsync(client &pool, search_params request, dirsync_request options, std::pmr::memory_resource *mr)
  -> capy::task<result<dirsync_result>>
{
	return poll(pool.acquire(), pool.acquire(), std::move(request), std::move(options), mr);
}

}// namespace jhetz::ldap::ad
