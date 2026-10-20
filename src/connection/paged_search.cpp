#include "jhetz/ldap/connection.hpp"

#include "../format_util.hpp"
#include "impl.hpp"
#include "search.hpp"

#include <boost/capy/cond.hpp>
#include <boost/capy/ex/this_coro.hpp>

#include <cstddef>
#include <cstdint>
#include <memory_resource>
#include <optional>
#include <stop_token>
#include <string>
#include <utility>
#include <variant>
#include <vector>

namespace capy = boost::capy;

namespace jhetz::ldap {

using detail::deadline_after;
using detail::impl_ref;
using detail::no_connection;
using detail::op_context;
using detail::search_message;
using detail::start_search;

// ---------------------------------------------------------------- paged_search

struct paged_search::state
{
	impl_ref conn;
	search_params params;
	std::int32_t page_size;
	std::pmr::memory_resource *mr;
	ldap::search_stream current{};
	std::size_t pages = 0;
	bool finished = false;
	std::optional<error> error_{};
	string_list references{};
	std::pmr::vector<control> controls{};
	// The last cookie the server returned: its paging state, to release if
	// the search stops early. Empty before the first page ends, after the
	// last one, and after an error that ended the search on the server.
	std::string cookie{};

	void set_page_control(std::int32_t size, std::string page_cookie)
	{
		auto &cs = params.controls;
		std::erase_if(cs, [](const request_control &c) {
			return std::holds_alternative<paged>(c)
				   || (std::holds_alternative<control>(c) && std::get<control>(c).type == paged_results_oid);
		});
		cs.emplace_back(paged{ .page_size = size, .cookie = std::move(page_cookie) });
	}

	// Sends the search for the next page (cookie empty for the first);
	// not sent if `stop` (the awaiting task's) is set already.
	auto request_page(std::string page_cookie, const std::stop_token &stop) -> result<void>
	{
		set_page_control(page_size, std::move(page_cookie));
		auto s = start_search(*conn, params, mr, stop);
		if (!s) {
			return std::unexpected(std::move(s.error()));
		}
		current = std::move(*s);
		++pages;
		return {};
	}

	// The paging state the server holds now: `cookie`, or the current
	// page's own if its SearchResultDone was already received (the page
	// ended, next() has not read it yet).
	[[nodiscard]] auto server_cookie() const -> std::string
	{
		if (current.state_ == nullptr) {
			return cookie;
		}
		const message *done = current.state_->queued_done();
		if (done == nullptr) {
			return cookie;
		}
		if (!std::get<search_result_done>(done->op).result.is_success()) {
			return {};
		}
		auto pr = find_paged(done->controls);
		if (!pr || !*pr) {
			return {};
		}
		return std::string((*pr)->cookie);
	}

	// Stopped before its end (destroyed): abandons the current page, then
	// releases the server's paging state (RFC 2696 section 3: page size 0
	// and the last cookie). Best effort and never suspends: the release is
	// sent without waiting for its answer, which is dropped. Nothing is sent
	// if the connection is closed or in StartTLS (a bind holds it until the
	// bind ends, like any request).
	void stop() noexcept
	{
		std::string last;
		try {
			last = finished ? cookie : server_cookie();
		} catch (...) {// NOLINT(bugprone-empty-catch): out of memory, the release is best effort
		}
		current = ldap::search_stream{};// abandons the page if it is still running
		finished = true;
		cookie.clear();
		try {
			if (last.empty() || !conn->is_open()) {
				return;
			}
			set_page_control(0, std::move(last));
			const std::string context = op_context("search", params.base) + " (paged results release)";
			auto request = search_message(*conn, params, context);
			// Its answer is waited for as long as a page would be.
			const auto timeout = params.timeout ? params.timeout : conn->default_timeout();
			if (request) {
				conn->send_unanswered(*request, true, deadline_after(timeout), context);
			}
		} catch (...) {// NOLINT(bugprone-empty-catch): out of memory, the release is best effort
		}
	}
};

auto connection::search_paged(search_params request, std::int32_t page_size, std::pmr::memory_resource *mr)
  -> capy::task<result<ldap::paged_search>>
{
	if (impl_ == nullptr) {
		co_return std::unexpected(no_connection(op_context("search", request.base)));
	}
	if (page_size <= 0) {
		co_return fail(client_errc::encode_error,
		  detail::format("{}: page size {} is not positive", op_context("search", request.base), page_size));
	}
	std::pmr::polymorphic_allocator<> alloc(impl_->mr());
	auto *st = alloc.new_object<paged_search::state>(
	  paged_search::state{ .conn = impl_ref(impl_), .params = std::move(request), .page_size = page_size, .mr = mr });
	ldap::paged_search out = connection::impl::make_paged(st);
	if (auto r = st->request_page({}, co_await capy::this_coro::stop_token); !r) {
		co_return std::unexpected(std::move(r.error()));
	}
	co_return std::move(out);
}

namespace {

	void delete_paged(paged_search::state *s) noexcept
	{
		if (s == nullptr) {
			return;
		}
		s->stop();
		impl_ref keep = s->conn;
		std::pmr::polymorphic_allocator<> alloc(keep->mr());
		alloc.delete_object(s);
	}

}// namespace

paged_search::paged_search(paged_search &&other) noexcept : state_(std::exchange(other.state_, nullptr)) {}

auto paged_search::operator=(paged_search &&other) noexcept -> paged_search &
{
	if (this != &other) {
		delete_paged(state_);
		state_ = std::exchange(other.state_, nullptr);
	}
	return *this;
}

paged_search::~paged_search() { delete_paged(state_); }

auto paged_search::done() const noexcept -> bool { return state_ == nullptr || state_->finished; }

auto paged_search::pages() const noexcept -> std::size_t { return state_ == nullptr ? 0 : state_->pages; }

auto paged_search::references() const noexcept -> const string_list &
{
	static const string_list none;
	return state_ == nullptr ? none : state_->references;
}

auto paged_search::reference_urls(std::pmr::memory_resource *mr) const -> std::pmr::vector<url>
{
	return url::parse_list(references(), mr);
}

auto paged_search::controls() const noexcept -> const std::pmr::vector<control> &
{
	static const std::pmr::vector<control> none;
	return state_ == nullptr ? none : state_->controls;
}

auto paged_search::next() -> capy::task<result<std::optional<entry>>>
{
	if (state_ == nullptr) {
		co_return std::unexpected(no_connection("search"));
	}
	state &s = *state_;
	if (s.finished) {
		if (s.error_) {
			co_return std::unexpected(*s.error_);
		}
		co_return std::optional<entry>{};
	}
	// `ended`: the error ended the search on the server (an error result,
	// a malformed answer, a closed connection), so there is nothing to
	// release. A cancelled or timed-out page was only abandoned, and a page
	// request that could not be sent was never seen: the server may still
	// hold the paging state of `cookie`, which the destructor releases.
	// Decided by capy::cond, not ldap::cond::timeout: that also matches the
	// server's timeLimitExceeded, which ended the search on the server.
	const auto finish = [&s](error e, bool ended = true) -> result<std::optional<entry>> {
		if (ended && e.code != capy::cond::canceled && e.code != capy::cond::timeout) {
			s.cookie.clear();
		}
		s.finished = true;
		s.error_ = e;
		return std::unexpected(std::move(e));
	};
	while (true) {
		const std::size_t seen = s.current.references().size();
		auto e = co_await s.current.next();
		const auto &refs = s.current.references();
		s.references.insert(s.references.end(), refs.begin() + static_cast<std::ptrdiff_t>(seen), refs.end());
		if (!e) {
			co_return finish(std::move(e.error()));
		}
		if (*e) {
			co_return std::move(*e);
		}
		// The page ended: the next one, if the server gave a cookie.
		s.controls = s.current.controls();
		auto pr = find_paged(s.controls);
		if (!pr) {
			co_return finish(detail::with_context(std::move(pr.error()), op_context("search", s.params.base)));
		}
		s.cookie = *pr ? std::string((*pr)->cookie) : std::string();
		if (s.cookie.empty()) {
			s.finished = true;
			co_return std::optional<entry>{};
		}
		if (auto r = s.request_page(s.cookie, co_await capy::this_coro::stop_token); !r) {
			co_return finish(std::move(r.error()), false);
		}
	}
}

}// namespace jhetz::ldap
