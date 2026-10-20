#include "jhetz/ldap/connection.hpp"

#include "../format_util.hpp"
#include "impl.hpp"
#include "search.hpp"

#include <boost/capy/error.hpp>
#include <boost/capy/ex/this_coro.hpp>

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

namespace {

	auto new_state(connection::impl &c, std::pmr::memory_resource *entries, const std::string &context)
	  -> search_stream::state *
	{
		std::pmr::polymorphic_allocator<> alloc(c.mr());
		return alloc.new_object<search_stream::state>(&c, entries, context);
	}

	void delete_state(search_stream::state *s) noexcept
	{
		if (s == nullptr) {
			return;
		}
		s->conn->abandon(s->op);
		impl_ref keep = s->conn;// the state lives on the connection's resource
		std::pmr::polymorphic_allocator<> alloc(keep->mr());
		alloc.delete_object(s);
	}

}// namespace

namespace detail {

	auto search_message(connection::impl &c, const search_params &p, const std::string &context) -> result<message>
	{
		const auto seconds = p.time_limit.count();
		if (seconds < 0 || seconds > max_int) {
			return fail(client_errc::encode_error,
			  detail::format("{}: time_limit of {} s is outside 0 .. 2^31-1", context, seconds));
		}

		const std::pmr::polymorphic_allocator<> alloc(c.mr());
		search_request wire(alloc);
		wire.base_object = p.base.to_string(c.mr());
		wire.scope = p.scope;
		wire.deref = p.deref;
		wire.size_limit = p.size_limit;
		wire.time_limit = static_cast<std::int32_t>(seconds);
		wire.types_only = p.types_only;
		wire.filter = p.filter;
		wire.attributes.assign(p.attributes.begin(), p.attributes.end());
		return with_controls(std::move(wire), p.controls, c.mr(), context);
	}

	auto start_search(connection::impl &c, search_params &p, std::pmr::memory_resource *mr, const std::stop_token &stop)
	  -> result<ldap::search_stream>
	{
		std::string context = op_context("search", p.base);
		auto request = search_message(c, p, context);
		if (!request) {
			return std::unexpected(std::move(request.error()));
		}
		if (stop.stop_requested()) {
			return fail(capy::error::canceled, context);
		}

		auto *state = new_state(c, mr, context);
		ldap::search_stream s = connection::impl::make_stream(state);
		state->deadline = deadline_after(p.timeout ? p.timeout : c.default_timeout());
		if (auto r = c.submit(*request, &state->op, context); !r) {
			return std::unexpected(std::move(r.error()));
		}
		return s;
	}

}// namespace detail

auto connection::search_stream(search_params p, std::pmr::memory_resource *mr)
  -> capy::task<result<ldap::search_stream>>
{
	if (impl_ == nullptr) {
		co_return std::unexpected(no_connection(op_context("search", p.base)));
	}
	// The analyzer does not model the promise's construction: Capy's env_ is
	// nullptr-initialised and set by the awaiting caller before the first resume.
	// NOLINTNEXTLINE(clang-analyzer-core.uninitialized.Branch): false positive
	co_return start_search(*impl_, p, mr, co_await capy::this_coro::stop_token);
}

auto connection::search(search_params request, std::pmr::memory_resource *mr)
  -> capy::task<result<std::pmr::vector<entry>>>
{
	auto s = co_await search_stream(std::move(request), mr);
	if (!s) {
		co_return std::unexpected(std::move(s.error()));
	}
	std::pmr::vector<entry> out(mr);
	while (true) {
		auto e = co_await s->next();
		if (!e) {
			co_return std::unexpected(std::move(e.error()));
		}
		if (!*e) {
			break;
		}
		out.push_back(std::move(**e));
	}
	co_return out;
}

namespace detail {

	auto read_one(impl_ref self, search_params p) -> capy::task<result<std::optional<entry>>>
	{
		// The analyzer does not model the promise's construction: Capy's env_ is
		// nullptr-initialised and set by the awaiting caller before the first resume.
		// NOLINTNEXTLINE(clang-analyzer-core.uninitialized.Branch): false positive
		auto s = start_search(*self, p, std::pmr::get_default_resource(), co_await capy::this_coro::stop_token);
		if (!s) {
			co_return std::unexpected(std::move(s.error()));
		}
		std::optional<entry> found;
		while (true) {
			auto e = co_await s->next();
			if (!e) {
				co_return std::unexpected(std::move(e.error()));
			}
			if (!*e) {
				co_return found;
			}
			if (!found) {
				found = std::move(**e);
			}
		}
	}

}// namespace detail

// ---------------------------------------------------------------- search_stream

search_stream::search_stream(search_stream &&other) noexcept : state_(std::exchange(other.state_, nullptr)) {}

auto search_stream::operator=(search_stream &&other) noexcept -> search_stream &
{
	if (this != &other) {
		delete_state(state_);
		state_ = std::exchange(other.state_, nullptr);
	}
	return *this;
}

search_stream::~search_stream() { delete_state(state_); }

auto search_stream::done() const noexcept -> bool { return state_ == nullptr || state_->finished; }

auto search_stream::references() const noexcept -> const string_list &
{
	static const string_list none;
	return state_ == nullptr ? none : state_->references;
}

auto search_stream::controls() const noexcept -> const std::pmr::vector<control> &
{
	static const std::pmr::vector<control> none;
	return state_ == nullptr ? none : state_->controls;
}

auto search_stream::next() -> capy::task<result<std::optional<entry>>>
{
	if (state_ == nullptr) {
		co_return std::unexpected(no_connection("search"));
	}
	state &s = *state_;// stable: the stream must not be moved while next() runs
	if (s.finished) {
		if (s.error_) {
			co_return std::unexpected(*s.error_);
		}
		co_return std::optional<entry>{};
	}
	if (s.in_next) {
		co_return fail(
		  client_errc::operation_in_progress, s.context + " during an earlier next() on this search_stream");
	}
	s.in_next = true;
	struct reset
	{
		bool &flag;
		~reset() { flag = false; }
	} r{ s.in_next };

	const impl_ref conn = s.conn;
	while (true) {
		auto m = co_await conn->next_response(s.op, s.deadline, s.context);
		if (!m) {
			s.finished = true;
			s.error_ = m.error();
			co_return std::unexpected(std::move(m.error()));
		}
		if (auto *e = std::get_if<search_result_entry>(&m->op)) {
			co_return std::optional<entry>(entry::from(std::move(*e)));// on the stream's resource, no copy
		}
		if (auto *ref = std::get_if<search_result_reference>(&m->op)) {
			s.references.append_range(ref->uris);
			continue;
		}
		const auto &d = std::get<search_result_done>(m->op);// checked by the reader
		s.finished = true;
		s.controls.assign(m->controls.begin(), m->controls.end());
		if (!d.result.is_success()) {
			s.error_ = d.result.to_error(s.context);
			co_return std::unexpected(*s.error_);
		}
		co_return std::optional<entry>{};
	}
}

auto search_stream::reference_urls(std::pmr::memory_resource *mr) const -> std::pmr::vector<url>
{
	return url::parse_list(references(), mr);
}

}// namespace jhetz::ldap
