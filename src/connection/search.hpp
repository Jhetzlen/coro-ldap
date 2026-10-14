// Internal: search_stream's state and the search helpers shared by
// paged search, schema loading and the AD password code.
#pragma once

#include "jhetz/ldap/connection.hpp"

#include "impl.hpp"

#include <boost/capy/task.hpp>

#include <memory_resource>
#include <optional>
#include <stop_token>
#include <string>
#include <utility>
#include <variant>
#include <vector>

namespace jhetz::ldap {

// ---------------------------------------------------------------- search_stream state

struct search_stream::state
{
	state(connection::impl *c, std::pmr::memory_resource *entries, std::string context_)
	  : conn(c), op(entries, true, detail::op_index<search_result_done>), context(std::move(context_))
	{}

	detail::impl_ref conn;
	detail::pending_op op;
	std::string context;// "search <base>"
	std::optional<detail::clock::time_point> deadline{};
	bool in_next = false;
	bool finished = false;
	std::optional<error> error_{};
	string_list references{};
	std::pmr::vector<control> controls{};

	// The SearchResultDone already queued (received, not yet read by
	// next()), or null.
	const message *queued_done() const noexcept
	{
		if (op.queue.empty() || !std::holds_alternative<search_result_done>(op.queue.back().op)) {
			return nullptr;
		}
		return &op.queue.back();
	}
};

namespace detail {

	// The SearchRequest for `p`, validated (errors carry `context`).
	result<message> search_message(connection::impl &c, const search_params &p, const std::string &context);

	// Validates and sends a search; returns its stream. Never suspends.
	// `stop` is the awaiting task's stop token: if it is set already, the
	// search is not sent and fails with capy::error::canceled.
	result<ldap::search_stream>
	  start_search(connection::impl &c, search_params &p, std::pmr::memory_resource *mr, const std::stop_token &stop);

	// The one entry of a base-scope search (nullopt if none came back).
	boost::capy::task<result<std::optional<entry>>> read_one(impl_ref self, search_params p);

}// namespace detail

}// namespace jhetz::ldap
