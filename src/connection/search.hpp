// Internal: search_stream's state and the search helpers shared by
// paged search and schema loading.
#pragma once

#include "jhetz/ldap/connection.hpp"

#include "impl.hpp"

#include <boost/capy/task.hpp>

#include <cstdint>

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
	// The SearchResultDone's LDAPResult, once read.
	std::optional<ldap_result> done{};
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

	// The result codes other than success of a SearchResultDone that
	// search() returns as a search_result with the entries received:
	// sizeLimitExceeded, timeLimitExceeded, adminLimitExceeded.
	[[nodiscard]] constexpr auto limit_exceeded(std::int32_t result_code) noexcept -> bool
	{
		return result_code == static_cast<std::int32_t>(errc::size_limit_exceeded)
			   || result_code == static_cast<std::int32_t>(errc::time_limit_exceeded)
			   || result_code == static_cast<std::int32_t>(errc::admin_limit_exceeded);
	}

	// The SearchResultDone's LDAPResult `s` ended with, null before it (or
	// when it ended otherwise: a connection failure, a timeout).
	[[nodiscard]] auto search_done(ldap::search_stream &s) noexcept -> const ldap_result *;
	// As search_done(), for the current page of `p`.
	[[nodiscard]] auto paged_done(ldap::paged_search &p) noexcept -> const ldap_result *;

	// `out` with the outcome of `s`, which ended with `done`: its
	// references, the LDAPResult's fields and the done's controls.
	template<class Entries>
	void set_outcome(basic_search_result<Entries> &out,
	  const ldap_result &done,
	  const string_list &references,
	  const std::pmr::vector<control> &controls)
	{
		out.references.assign(references.begin(), references.end());
		out.result_code = done.result_code;
		out.matched_dn.assign(done.matched_dn);
		out.diagnostic_message.assign(done.diagnostic_message);
		out.controls.assign(controls.begin(), controls.end());
	}

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
