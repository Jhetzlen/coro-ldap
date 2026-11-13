#include "jhetz/ldap/connection.hpp"

#include "../format_util.hpp"
#include "../scope_util.hpp"
#include "core.hpp"
#include "search.hpp"

#include <boost/capy/cond.hpp>
#include <boost/capy/error.hpp>
#include <boost/capy/ex/this_coro.hpp>
#include <boost/corosio/timeout.hpp>

#include <concepts>
#include <memory>
#include <memory_resource>
#include <optional>
#include <stop_token>
#include <string>
#include <system_error>
#include <utility>
#include <variant>
#include <vector>

namespace capy = boost::capy;
namespace corosio = boost::corosio;

namespace jhetz::ldap {

using detail::core_ref;
using detail::no_connection;
using detail::op_context;
using detail::pending_op;
using detail::start_search;

namespace {

	auto new_state(connection::core &c, std::pmr::memory_resource *entries, const std::string &context)
	  -> search_stream::state *
	{
		std::pmr::polymorphic_allocator<> alloc(c.mr());
		return alloc.new_object<search_stream::state>(&c, entries, context);
	}

	void delete_state_now(search_stream::state *s) noexcept
	{
		s->conn->abandon(s->op);
		std::shared_ptr<void> owner = std::move(s->owner);// released last
		core_ref keep = s->conn;// the state lives on the connection's resource
		std::pmr::polymorphic_allocator<> alloc(keep->mr());
		alloc.delete_object(s);
		keep = {};
		owner.reset();
	}

	// On the connection's strand: the search's registration is the reader's.
	void delete_state(search_stream::state *s) noexcept
	{
		if (s == nullptr) {
			return;
		}
		detail::run_on_strand(*s->conn, [s] noexcept { delete_state_now(s); });
	}

	auto core_stream_state(ldap::search_stream &s) noexcept -> search_stream::state *
	{
		return connection::core::stream_state(s);
	}

	// next() (Item = entry) and next_item() (Item = search_stream::item).
	template<class Item> auto next_of(search_stream::state *sp) -> capy::task<result<std::optional<Item>>>
	{
		if (sp == nullptr) {
			co_return std::unexpected(no_connection("search"));
		}
		search_stream::state &s = *sp;// stable: the stream must not be moved while next() runs
		if (s.finished) {
			if (s.error_) {
				co_return std::unexpected(*s.error_);
			}
			co_return std::optional<Item>{};
		}
		if (s.in_next) {
			co_return fail(client_errc::operation_in_progress,
			  s.context + " during an earlier next() or next_item() on this search_stream");
		}
		s.in_next = true;
		const detail::scope_exit reset{ [&s] { s.in_next = false; } };

		const core_ref conn = s.conn;
		while (true) {
			auto m = co_await conn->next_response(s.op, s.deadline, s.context);
			if (!m) {
				s.finished = true;
				s.error_ = m.error();
				co_return std::unexpected(std::move(m.error()));
			}
			constexpr bool items = std::same_as<Item, search_stream::item>;
			if (auto *e = std::get_if<search_result_entry>(&m->op)) {
				if constexpr (items) {
					// On the stream's resource, no copy.
					co_return std::optional<Item>(std::in_place,
					  std::in_place_type<search_entry>,
					  entry::from(std::move(*e)),
					  std::move(m->controls),
					  s.op.mr);
				} else {
					co_return std::optional<Item>(entry::from(std::move(*e)));// on the stream's resource, no copy
				}
			}
			if (auto *ref = std::get_if<search_result_reference>(&m->op)) {
				s.references.append_range(ref->uris);
				if constexpr (items) {
					co_return std::optional<Item>(std::in_place,
					  std::in_place_type<search_reference>,
					  std::move(*ref),
					  std::move(m->controls),
					  s.op.mr);
				} else {
					continue;
				}
			}
			// Queued only if asked for.
			if constexpr (items) {
				if (auto *i = std::get_if<intermediate_response>(&m->op)) {
					co_return std::optional<Item>(
					  std::in_place, std::in_place_type<intermediate>, std::move(*i), std::move(m->controls), s.op.mr);
				}
			} else if (std::holds_alternative<intermediate_response>(m->op)) {
				continue;
			}
			const auto &d = std::get<search_result_done>(m->op);// checked by the reader
			s.finished = true;
			s.controls.assign(m->controls.begin(), m->controls.end());
			s.done = d.result;
			if (!d.result.is_success()) {
				s.error_ = d.result.to_error(s.context);
				co_return std::unexpected(*s.error_);
			}
			co_return std::optional<Item>{};
		}
	}

}// namespace

namespace detail {

	auto search_message(const connection::core &c, const search_params &p, const std::string &context)
	  -> result<message>
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
		return build_request(std::move(wire), p.controls, c.mr(), context);
	}

	auto start_search(connection::core &c,
	  const search_params &p,
	  std::pmr::memory_resource *mr,
	  const std::stop_token &stop) -> result<ldap::search_stream>
	{
		const std::string context = op_context("search", p.base);
		auto request = search_message(c, p, context);
		if (!request) {
			return std::unexpected(std::move(request.error()));
		}
		if (stop.stop_requested()) {
			return fail(capy::error::canceled, context);
		}

		auto *state = new_state(c, mr, context);
		ldap::search_stream s = connection::core::make_stream(state);
		state->deadline = deadline_after(p.timeout ? p.timeout : c.default_timeout());
		state->op.intermediates = p.intermediate_responses;
		if (auto r = c.submit(*request, &state->op, context); !r) {
			return std::unexpected(std::move(r.error()));
		}
		return s;
	}

}// namespace detail

namespace {

	auto search_stream_impl(core_ref self, search_params request, std::pmr::memory_resource *mr)
	  -> capy::task<result<ldap::search_stream>>
	{
		if (!self) {
			co_return std::unexpected(no_connection(op_context("search", request.base)));
		}
		// The analyzer does not model the promise's construction: Capy's env_ is
		// nullptr-initialised and set by the awaiting caller before the first resume.
		// NOLINTNEXTLINE(clang-analyzer-core.uninitialized.Branch): false positive
		co_return start_search(*self, request, mr, co_await capy::this_coro::stop_token);
	}

	auto search_impl(core_ref self, search_params request, std::pmr::memory_resource *mr)
	  -> capy::task<result<search_result>>
	{
		auto s = co_await search_stream_impl(std::move(self), std::move(request), mr);
		if (!s) {
			co_return std::unexpected(std::move(s.error()));
		}
		search_result out{ .entries = std::pmr::vector<entry>(mr), .references = string_list(mr) };
		while (true) {
			auto e = co_await next_of<entry>(core_stream_state(*s));
			if (!e) {
				const ldap_result *done = detail::search_done(*s);
				if (done == nullptr || !detail::limit_exceeded(done->result_code)) {
					co_return std::unexpected(std::move(e.error()));
				}
				break;
			}
			if (!*e) {
				break;
			}
			out.entries.push_back(std::move(**e));
		}
		detail::set_outcome(out, *detail::search_done(*s), s->references(), s->controls());
		co_return out;
	}

}// namespace

auto detail::search_stream_of(const core_ref &self, search_params request, std::pmr::memory_resource *mr)
  -> capy::task<result<ldap::search_stream>>
{
	auto body = search_stream_impl(self, std::move(request), mr);
	return detail::on_strand(self, std::move(body));
}

auto connection::search_stream(search_params request, std::pmr::memory_resource *mr)
  -> capy::task<result<ldap::search_stream>>
{
	return detail::search_stream_of(core_, std::move(request), mr);
}

auto connection::search(search_params request, std::pmr::memory_resource *mr) -> capy::task<result<search_result>>
{
	const core_ref self(core_);
	return detail::on_strand(self, search_impl(self, std::move(request), mr));
}

namespace detail {

	auto search_done(const ldap::search_stream &s) noexcept -> const ldap_result *
	{
		const auto *state = connection::core::stream_state(s);
		return state == nullptr || !state->done ? nullptr : &*state->done;
	}

	auto queued_done(const ldap::search_stream &s) noexcept -> const message *
	{
		const auto *state = connection::core::stream_state(s);
		return state == nullptr ? nullptr : state->queued_done();
	}

	void keep_alive(ldap::search_stream &s, std::shared_ptr<void> owner) noexcept
	{
		if (auto *state = connection::core::stream_state(s)) {
			state->owner = std::move(owner);
		}
	}

	namespace {

		auto first_outcome_on_strand(search_stream::state &s) -> capy::task<result<std::optional<error>>>
		{
			using outcome = std::optional<error>;
			pending_op &p = s.op;
			const core_ref conn = s.conn;
			// As connection::core::next_response, without taking the message.
			while (p.queue.empty() && !p.finished) {
				p.ready.clear();
				std::error_code ec;
				if (s.deadline) {
					auto [e] = co_await corosio::timeout(p.ready.wait(), *s.deadline);
					ec = e;
				} else {
					auto [e] = co_await p.ready.wait();
					ec = e;
				}
				if (!ec || !p.queue.empty() || p.finished) {
					continue;
				}
				if (ec == capy::cond::timeout) {
					co_return outcome{};// next() reports it (and abandons the search)
				}
				co_return fail(ec, s.context);// stopped: destroying the stream abandons the search
			}
			if (!p.queue.empty()) {
				const auto *done = std::get_if<search_result_done>(&p.queue.front().op);
				if (done != nullptr && !done->result.is_success()) {
					co_return outcome{ done->result.to_error(s.context) };
				}
				co_return outcome{};
			}
			if (p.failure) {
				co_return outcome{ detail::with_context(*p.failure, s.context) };
			}
			co_return outcome{ conn->not_connected(s.context) };
		}

	}// namespace

	auto first_outcome(ldap::search_stream &stream) -> capy::task<result<std::optional<error>>>
	{
		auto *s = connection::core::stream_state(stream);
		if (s == nullptr) {
			return [] -> capy::task<result<std::optional<error>>> {
				co_return std::optional<error>{ no_connection("search") };
			}();
		}
		// Not a coroutine: the state is stable, the caller holds the stream.
		return on_strand(s->conn, first_outcome_on_strand(*s));
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
	return detail::on_strand(state_ == nullptr ? core_ref() : state_->conn, next_of<entry>(state_));
}

auto search_stream::next_item() -> capy::task<result<std::optional<item>>>
{
	return detail::on_strand(state_ == nullptr ? core_ref() : state_->conn, next_of<item>(state_));
}

auto search_stream::reference_urls(std::pmr::memory_resource *mr) const -> std::pmr::vector<url>
{
	return url::parse_list(references(), mr);
}

}// namespace jhetz::ldap
