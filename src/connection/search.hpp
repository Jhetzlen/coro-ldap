// Internal: search_stream's state and the search helpers shared by
// paged search, the client and the sync facade.
#pragma once

#include "jhetz/ldap/connection.hpp"

#include "core.hpp"

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
	state(connection::core *c, std::pmr::memory_resource *entries, std::string context_)
	  : conn(c), op(entries, true, detail::op_index<search_result_done>), context(std::move(context_))
	{}

	detail::core_ref conn;
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
	auto search_message(const connection::core &c, const search_params &p, const std::string &context)
	  -> result<message>;

	// connection::search_stream() on the connection whose state is `self`.
	auto search_stream_of(const core_ref &self, search_params request, std::pmr::memory_resource *mr)
	  -> boost::capy::task<result<ldap::search_stream>>;

	// Validates and sends a search; returns its stream. Never suspends.
	// `stop` is the awaiting task's stop token: if it is set already, the
	// search is not sent and fails with capy::error::canceled.
	auto start_search(connection::core &c,
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
	[[nodiscard]] auto search_done(const ldap::search_stream &s) noexcept -> const ldap_result *;
	// As search_done(), for the current page of `p`.
	[[nodiscard]] auto paged_done(const ldap::paged_search &p) noexcept -> const ldap_result *;
	// The SearchResultDone `s` received and next() has not read yet, or
	// null. On the connection's strand.
	[[nodiscard]] auto queued_done(const ldap::search_stream &s) noexcept -> const message *;
	// The strand of `p`'s connection; nullopt for a default-constructed or
	// moved-from paged_search.
	[[nodiscard]] auto paged_executor(const ldap::paged_search &p) noexcept -> std::optional<connection::executor_type>;

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

	// As keep_alive and first_outcome, for the current page of `p`.
	void keep_alive(ldap::paged_search &p, std::shared_ptr<void> owner) noexcept;
	auto first_outcome(ldap::paged_search &p) -> boost::capy::task<result<std::optional<error>>>;
	// Destroys `p` on its connection's strand.
	auto end_paged(ldap::paged_search &p) -> boost::capy::task<void>;

}// namespace detail

}// namespace jhetz::ldap
