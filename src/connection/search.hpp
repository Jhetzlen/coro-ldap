// Internal: search_stream's state and the search helpers shared by
// paged search, schema loading and the AD password code.
#pragma once

#include "jhetz/ldap/connection.hpp"

#include "impl.hpp"

#include <boost/capy/task.hpp>

#include <memory>
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
	// Released once the stream is destroyed, after the search is abandoned:
	// ldap::client's lease on the connection (detail::keep_alive).
	std::shared_ptr<void> owner{};

	// The SearchResultDone already queued (received, not yet read by
	// next()), or null.
	[[nodiscard]] auto queued_done() const noexcept -> const message *
	{
		if (op.queue.empty() || !std::holds_alternative<search_result_done>(op.queue.back().op)) {
			return nullptr;
		}
		return &op.queue.back();
	}
};

namespace detail {

	// The SearchRequest for `p`, validated (errors carry `context`).
	auto search_message(const connection::impl &c, const search_params &p, const std::string &context)
	  -> result<message>;

	// Validates and sends a search; returns its stream. Never suspends.
	// `stop` is the awaiting task's stop token: if it is set already, the
	// search is not sent and fails with capy::error::canceled.
	auto start_search(connection::impl &c,
	  const search_params &p,
	  std::pmr::memory_resource *mr,
	  const std::stop_token &stop) -> result<ldap::search_stream>;

	// The one entry of a base-scope search (nullopt if none came back).
	auto read_one(impl_ref self, search_params p) -> boost::capy::task<result<std::optional<entry>>>;

	// For ldap::client: `owner` lives until `s` is destroyed (after its
	// search is abandoned). Ignored on a default-constructed or moved-from
	// stream.
	void keep_alive(ldap::search_stream &s, std::shared_ptr<void> owner) noexcept;

	// For ldap::client: waits until the search has a message for next() or
	// has ended, without taking anything. Returns the error next() would
	// return before any message (a connection failure, a SearchResultDone
	// with another code than success), else nullopt: a message is ready,
	// the search ended with success, or its deadline passed (next() then
	// reports the timeout). Fails only when the awaiting task is stopped.
	auto first_outcome(ldap::search_stream &s) -> boost::capy::task<result<std::optional<error>>>;

}// namespace detail

}// namespace jhetz::ldap
