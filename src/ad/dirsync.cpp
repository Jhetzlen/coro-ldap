#include "jhetz/ldap/ad/dirsync.hpp"

#include "jhetz/ldap/ad/controls.hpp"
#include "jhetz/ldap/directory.hpp"
#include "jhetz/ldap/operations.hpp"

#include <boost/capy/task.hpp>

#include <algorithm>
#include <cstddef>
#include <iterator>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

namespace capy = boost::capy;

namespace jhetz::ldap::ad {

namespace {

	auto no_rounds(const search_params &request) -> result<dirsync_result>
	{
		return fail(std::make_error_code(std::errc::invalid_argument),
		  detail::op_context("DirSync", request.base) + ": max_rounds is 0");
	}

	auto poll(connection &c,
	  const search_params &request,
	  const dirsync_request &options,
	  std::size_t max_rounds,
	  std::pmr::memory_resource *mr) -> capy::task<result<dirsync_result>>
	{
		const std::string context = detail::op_context("DirSync", request.base);
		dirsync_result out{ .entries = std::pmr::vector<entry>(mr), .cookie = options.cookie };
		std::vector<std::string> seen{ options.cookie };
		for (std::size_t round = 1;; ++round) {
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
			out.cookie = std::move((*response)->cookie_server);
			if (!(*response)->more_results) {
				co_return out;
			}
			if (std::ranges::find(seen, out.cookie) != seen.end()) {
				co_return fail(client_errc::unexpected_response, context + ": more results with a cookie already seen");
			}
			if (round == max_rounds) {
				out.more_results = true;
				co_return out;
			}
			seen.push_back(out.cookie);
		}
	}

	// `first` and `retry` are acquire() tasks of the same client: `retry`
	// runs only after cond::connection_lost on the first lease.
	auto poll(capy::task<result<lease>> first,
	  capy::task<result<lease>> retry,
	  search_params request,
	  dirsync_request options,
	  std::size_t max_rounds,
	  std::pmr::memory_resource *mr) -> capy::task<result<dirsync_result>>
	{
		if (max_rounds == 0) {
			co_return no_rounds(request);
		}
		{
			auto l = co_await std::move(first);
			if (!l) {
				co_return std::unexpected(std::move(l.error()));
			}
			auto r = co_await poll(l->get(), request, options, max_rounds, mr);
			if (r || r.error().code != cond::connection_lost) {
				co_return r;
			}
		}
		auto l = co_await std::move(retry);
		if (!l) {
			co_return std::unexpected(std::move(l.error()));
		}
		co_return co_await poll(l->get(), request, options, max_rounds, mr);
	}

	auto start(connection &c,
	  search_params request,
	  dirsync_request options,
	  std::size_t max_rounds,
	  std::pmr::memory_resource *mr) -> capy::task<result<dirsync_result>>
	{
		if (max_rounds == 0) {
			co_return no_rounds(request);
		}
		co_return co_await poll(c, request, options, max_rounds, mr);
	}

}// namespace

auto dirsync(connection &c,
  search_params request,
  dirsync_request options,
  std::size_t max_rounds,
  std::pmr::memory_resource *mr) -> capy::task<result<dirsync_result>>
{
	return start(c, std::move(request), std::move(options), max_rounds, mr);
}

auto dirsync(client &pool,
  search_params request,
  dirsync_request options,
  std::size_t max_rounds,
  std::pmr::memory_resource *mr) -> capy::task<result<dirsync_result>>
{
	return poll(pool.acquire(), pool.acquire(), std::move(request), std::move(options), max_rounds, mr);
}

}// namespace jhetz::ldap::ad
