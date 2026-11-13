#include "jhetz/ldap/paged_search.hpp"

#include "jhetz/ldap/client.hpp"
#include "jhetz/ldap/connection.hpp"

#include "../format_util.hpp"
#include "core.hpp"
#include "search.hpp"

#include <boost/capy/cond.hpp>

#include <cstddef>
#include <cstdint>
#include <memory>
#include <memory_resource>
#include <optional>
#include <string>
#include <system_error>
#include <utility>
#include <variant>
#include <vector>

namespace capy = boost::capy;

namespace jhetz::ldap {

using detail::deadline_after;
using detail::core_ref;
using detail::no_connection;
using detail::op_context;
using detail::search_message;

// ---------------------------------------------------------------- paged_search

struct paged_search::state
{
	// The connection's shared state, where the pages are requested.
	core_ref conn;
	search_params params;
	std::int32_t page_size;
	std::size_t max_pages;
	std::pmr::memory_resource *mr;
	ldap::search_stream current{};
	std::size_t pages = 0;
	bool in_next = false;
	bool finished = false;
	std::optional<error> error_{};
	string_list references{};
	std::pmr::vector<control> controls{};
	// The last cookie the server returned; empty before the first page ends,
	// after the last one, and after an error that ended the search.
	std::string cookie{};
	// ldap::client's lease on the connection, released after the paged
	// results release is sent.
	std::shared_ptr<void> owner{};

	void set_page_control(std::int32_t size, std::string page_cookie)
	{
		auto &cs = params.controls;
		std::erase_if(cs, [](const search_controls::value_type &c) {
			return std::holds_alternative<paged>(c)
				   || (std::holds_alternative<control>(c) && std::get<control>(c).type == paged_results_oid);
		});
		cs.emplace_back(paged{ .page_size = size, .cookie = std::move(page_cookie) });
	}

	// The search for the next page (cookie empty for the first).
	auto request_page(std::string page_cookie) -> capy::task<result<ldap::search_stream>>
	{
		set_page_control(page_size, std::move(page_cookie));
		return detail::search_stream_of(conn, params, mr);
	}

	// `s`, the stream of the page requested, becomes the current page.
	auto take_page(result<ldap::search_stream> s) -> result<void>
	{
		if (!s) {
			return std::unexpected(std::move(s.error()));
		}
		current = std::move(*s);
		++pages;
		return {};
	}

	// The paging state the server holds now: `cookie`, or the current page's
	// if its SearchResultDone was received.
	[[nodiscard]] auto server_cookie() const -> std::string
	{
		const message *done = detail::queued_done(current);
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

	// Abandons the current page and releases the server's paging state (RFC
	// 2696 section 3), without waiting; nothing is sent on a closed connection
	// or during StartTLS.
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

namespace detail {

	struct paged_access
	{
		static auto make(paged_search::state *s) noexcept -> paged_search { return paged_search(s); }
		static auto state_of(const paged_search &p) noexcept -> paged_search::state * { return p.state_; }
	};

}// namespace detail

namespace {

	// The encode_error of a page size that is not positive, else nullopt.
	auto invalid_page_size(const search_params &request, std::int32_t page_size) -> std::optional<error>
	{
		if (page_size > 0) {
			return std::nullopt;
		}
		return make_error(client_errc::encode_error,
		  detail::format("{}: page size {} is not positive", op_context("search", request.base), page_size));
	}

	// The error of arguments refused before anything is sent, else nullopt.
	auto invalid_arguments(const search_params &request, std::int32_t page_size, std::size_t max_pages)
	  -> std::optional<error>
	{
		if (auto bad = invalid_page_size(request, page_size)) {
			return bad;
		}
		if (max_pages == 0) {
			return make_error(std::make_error_code(std::errc::invalid_argument),
			  op_context("search", request.base) + ": max_pages is 0");
		}
		return std::nullopt;
	}

	auto search_paged_impl(core_ref self,
	  search_params request,
	  std::int32_t page_size,
	  std::size_t max_pages,
	  std::pmr::memory_resource *mr) -> capy::task<result<ldap::paged_search>>
	{
		if (!self) {
			co_return std::unexpected(no_connection(op_context("search", request.base)));
		}
		if (auto bad = invalid_arguments(request, page_size, max_pages)) {
			co_return std::unexpected(std::move(*bad));
		}
		std::pmr::polymorphic_allocator<> alloc(self->mr());
		auto *st = alloc.new_object<paged_search::state>(paged_search::state{
		  .conn = self, .params = std::move(request), .page_size = page_size, .max_pages = max_pages, .mr = mr });
		ldap::paged_search out = detail::paged_access::make(st);
		if (auto r = st->take_page(co_await st->request_page({})); !r) {
			co_return std::unexpected(std::move(r.error()));
		}
		co_return std::move(out);
	}

}// namespace

// NOLINTNEXTLINE(misc-const-correctness): the search runs on `c`
auto search_paged(connection &c,
  search_params request,
  std::int32_t page_size,
  std::size_t max_pages,
  std::pmr::memory_resource *mr) -> capy::task<result<ldap::paged_search>>
{
	core_ref self(connection::core::of(c));
	auto body = search_paged_impl(self, std::move(request), page_size, max_pages, mr);
	return detail::on_strand(self, std::move(body));
}

namespace {

	auto paged_refused(error e) -> capy::task<result<ldap::paged_search>> { co_return std::unexpected(std::move(e)); }

}// namespace

// NOLINTNEXTLINE(misc-const-correctness): the search runs on `c`'s pool
auto search_paged(client &c,
  search_params request,
  std::int32_t page_size,
  std::size_t max_pages,
  std::pmr::memory_resource *mr) -> capy::task<result<ldap::paged_search>>
{
	if (auto bad = invalid_arguments(request, page_size, max_pages)) {
		return paged_refused(std::move(*bad));
	}
	return detail::search_paged_of(c, std::move(request), page_size, max_pages, mr);
}

namespace detail {

	auto paged_done(const ldap::paged_search &p) noexcept -> const ldap_result *
	{
		const auto *state = paged_access::state_of(p);
		return state == nullptr ? nullptr : search_done(state->current);
	}

	auto paged_executor(const ldap::paged_search &p) noexcept -> std::optional<connection::executor_type>
	{
		const auto *state = paged_access::state_of(p);
		if (state == nullptr) {
			return std::nullopt;
		}
		return state->conn->executor();
	}

	// NOLINTNEXTLINE(misc-const-correctness): `p`'s state changes
	void keep_alive(ldap::paged_search &p, std::shared_ptr<void> owner) noexcept
	{
		if (auto *state = paged_access::state_of(p)) {
			state->owner = std::move(owner);
		}
	}

	// NOLINTNEXTLINE(misc-const-correctness): `p`'s current page is read
	auto first_outcome(ldap::paged_search &p) -> capy::task<result<std::optional<error>>>
	{
		auto *state = paged_access::state_of(p);
		if (state == nullptr) {
			return [] -> capy::task<result<std::optional<error>>> {
				co_return std::optional<error>{ no_connection("search") };
			}();
		}
		return first_outcome(state->current);
	}

	auto end_paged(ldap::paged_search &p) -> capy::task<void>
	{
		const auto *state = paged_access::state_of(p);
		if (state == nullptr) {
			return [] -> capy::task<void> { co_return; }();
		}
		return on_strand(state->conn, [](ldap::paged_search &pages) -> capy::task<void> {
			pages = ldap::paged_search{};
			co_return;
		}(p));
	}

}// namespace detail

namespace {

	void delete_paged(paged_search::state *s) noexcept
	{
		if (s == nullptr) {
			return;
		}
		detail::run_on_strand(*s->conn, [s] noexcept {
			s->stop();
			core_ref keep = s->conn;
			std::pmr::polymorphic_allocator<> alloc(keep->mr());
			alloc.delete_object(s);
		});
	}

	auto next_page_entry(paged_search::state *sp) -> capy::task<result<std::optional<entry>>>;

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
	return detail::on_strand(state_ == nullptr ? core_ref() : state_->conn, next_page_entry(state_));
}

namespace {

	auto next_page_entry(paged_search::state *sp) -> capy::task<result<std::optional<entry>>>
	{
		if (sp == nullptr) {
			co_return std::unexpected(no_connection("search"));
		}
		paged_search::state &s = *sp;
		if (s.finished) {
			if (s.error_) {
				co_return std::unexpected(*s.error_);
			}
			co_return std::optional<entry>{};
		}
		if (s.in_next) {
			co_return fail(client_errc::operation_in_progress,
			  op_context("search", s.params.base) + " during an earlier next() on this paged_search");
		}
		s.in_next = true;
		const detail::scope_exit reset{ [&s] { s.in_next = false; } };
		// `ended`: the search ended on the server, nothing to release.
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
				if (detail::search_done(s.current) != nullptr) {
					s.controls = s.current.controls();
				}
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
			if (s.pages == s.max_pages) {
				co_return finish(
				  make_error(std::make_error_code(std::errc::value_too_large),
					detail::format(
					  "{}: more than max_pages ({}) pages", op_context("search", s.params.base), s.max_pages)),
				  false);
			}
			if (auto r = s.take_page(co_await s.request_page(s.cookie)); !r) {
				co_return finish(std::move(r.error()), false);
			}
		}
	}

}// namespace

}// namespace jhetz::ldap
