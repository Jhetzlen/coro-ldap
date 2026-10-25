// LDAP transactions (RFC 5805): connection::start_transaction(),
// end_transaction() and begin_transaction(), and the ldap::transaction
// helper built on them (transaction.hpp).
#include "jhetz/ldap/transaction.hpp"
#include "jhetz/ldap/connection.hpp"

#include "../format_util.hpp"
#include "impl.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <memory_resource>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <variant>

namespace capy = boost::capy;

namespace jhetz::ldap {

using detail::build_request;
using detail::impl_ref;
using detail::no_connection;
using detail::op_context;
using detail::op_index;
using detail::request_response;

namespace {

	constexpr std::string_view start_context = "start transaction";
	constexpr std::string_view end_context = "end transaction";

	// What an End Transaction exchange ended with, once the server answered
	// as section 2.3 allows: its result, its txnEndRes (empty when there is
	// no responseValue) and the response's controls.
	struct end_reply
	{
		ldap_result result{};
		end_transaction_response value{};
		std::pmr::vector<control> controls{};
	};

	// `answered`, if given, is set once the server has answered the request,
	// whether or not the answer is one section 2.3 allows: the transaction
	// is then over on the server. It stays false when the request was not
	// sent, or was given up on (timeout, cancellation, connection failure).
	auto end_exchange(impl_ref self, std::string identifier, bool commit, std::string context, bool *answered)
	  -> capy::task<result<end_reply>>
	{
		const std::pmr::polymorphic_allocator<> alloc(self->mr());
		const std::pmr::string value =
		  encode_end_transaction_request(end_transaction_request(commit, identifier, alloc), self->mr());
		// RFC 5805 sections 4.1 to 4.5: no control goes on End Transaction.
		auto msg = build_request(extended_request(end_transaction_oid, std::string_view(value), alloc),
		  extended_controls{},
		  self->mr(),
		  context);
		if (!msg) {
			co_return std::unexpected(std::move(msg.error()));
		}
		auto m = co_await request_response(self, std::move(*msg), op_index<extended_response>, context, std::nullopt);
		if (!m) {
			co_return std::unexpected(std::move(m.error()));
		}
		if (answered != nullptr) {
			*answered = true;
		}
		auto &x = std::get<extended_response>(m->op);
		end_reply out;
		out.result = x.result;
		out.controls.assign(m->controls.begin(), m->controls.end());
		const bool success = x.result.is_success();
		if (success && x.response_name) {
			co_return fail(
			  client_errc::decode_error, context + ": the response has a responseName (RFC 5805 section 2.3)");
		}
		if (x.response_value) {
			auto v = decode_end_transaction_response(*x.response_value);
			if (v) {
				out.value = std::move(*v);
			} else if (success) {
				co_return std::unexpected(detail::with_context(std::move(v.error()), context));
			}
			// A failure whose txnEndRes is malformed: the server's result
			// code says more than the decode error, so it is kept, without
			// a message id.
		}
		co_return out;
	}

	auto to_result(end_reply reply) -> end_transaction_result
	{
		end_transaction_result out;
		out.updates_controls.assign(std::make_move_iterator(reply.value.updates_controls.begin()),
		  std::make_move_iterator(reply.value.updates_controls.end()));
		out.controls.assign(reply.controls.begin(), reply.controls.end());
		return out;
	}

	auto start_exchange(impl_ref self, extended_controls controls) -> capy::task<result<std::pmr::string>>
	{
		const std::string context(start_context);
		const std::pmr::polymorphic_allocator<> alloc(self->mr());
		auto msg =
		  build_request(extended_request(start_transaction_oid, std::nullopt, alloc), controls, self->mr(), context);
		if (!msg) {
			co_return std::unexpected(std::move(msg.error()));
		}
		auto m = co_await request_response(self, std::move(*msg), op_index<extended_response>, context, std::nullopt);
		if (!m) {
			co_return std::unexpected(std::move(m.error()));
		}
		const auto &x = std::get<extended_response>(m->op);
		if (!x.result.is_success()) {
			co_return std::unexpected(x.result.to_error(context));
		}
		if (x.response_name) {
			co_return fail(
			  client_errc::decode_error, context + ": the response has a responseName (RFC 5805 section 2.1)");
		}
		if (!x.response_value) {
			co_return fail(client_errc::decode_error,
			  context + ": the response has no transaction identifier (RFC 5805 section 2.1)");
		}
		co_return std::pmr::string(*x.response_value);
	}

}// namespace

auto connection::start_transaction(extended_controls controls) -> capy::task<result<std::pmr::string>>
{
	if (impl_ == nullptr) {
		co_return std::unexpected(no_connection(start_context));
	}
	co_return co_await start_exchange(impl_ref(impl_), std::move(controls));
}

auto connection::end_transaction(std::pmr::string identifier, bool commit) -> capy::task<result<end_transaction_result>>
{
	std::string context(end_context);
	if (impl_ == nullptr) {
		co_return std::unexpected(no_connection(context));
	}
	auto reply = co_await end_exchange(impl_ref(impl_), std::string(identifier), commit, context, nullptr);
	if (!reply) {
		co_return std::unexpected(std::move(reply.error()));
	}
	if (!reply->result.is_success()) {
		if (reply->value.message_id) {
			context += detail::format(": update message {}", *reply->value.message_id);
		}
		co_return std::unexpected(reply->result.to_error(context));
	}
	co_return to_result(std::move(*reply));
}

// ---------------------------------------------------------------- transaction

struct transaction::state
{
	// An update the server took into the transaction: its request's message
	// id and its error context ("add uid=jdoe,...").
	struct update
	{
		std::int32_t message_id = 0;
		std::pmr::string context;
	};

	impl_ref conn;
	std::pmr::string identifier;
	std::pmr::vector<update> updates;
	// Updates sent and not yet answered: commit() refuses while there are.
	std::size_t in_flight = 0;
	// The API state: neither commit() nor abort() was called.
	bool open = true;
	// The server may still hold the transaction: no End Transaction it
	// answered yet. The destructor aborts it while this holds, even after
	// a commit() or abort() whose request was not sent (stopped before it
	// started, StartTLS in progress) or was given up on.
	bool needs_abort = true;
};

namespace {

	void delete_transaction(transaction::state *s) noexcept
	{
		if (s == nullptr) {
			return;
		}
		// Still open: abort it without waiting, its answer dropped like a
		// late response to an abandoned request (RFC 5805 section 3.4: an
		// End Transaction is always answered).
		try {
			if (s->needs_abort && s->conn->is_open()) {
				const std::string context = std::string(end_context) + " (abort, transaction destroyed)";
				const std::pmr::polymorphic_allocator<> alloc(s->conn->mr());
				const std::pmr::string value =
				  encode_end_transaction_request(end_transaction_request(false, s->identifier, alloc), s->conn->mr());
				message m = detail::with_controls(
				  extended_request(end_transaction_oid, std::string_view(value), alloc), {}, s->conn->mr());
				s->conn->send_unanswered(m, false, detail::deadline_after(s->conn->default_timeout()), context);
			}
		} catch (...) {// NOLINT(bugprone-empty-catch): out of memory, the abort is best effort
		}
		impl_ref keep = s->conn;
		std::pmr::polymorphic_allocator<> alloc(keep->mr());
		alloc.delete_object(s);
	}

	// The error of an operation that cannot go on `s`: not started (or moved
	// from), or settled already.
	auto unusable(const transaction::state *s, std::string_view context) -> std::optional<error>
	{
		if (s == nullptr) {
			return no_connection(context);
		}
		if (!s->open) {
			return make_error(std::make_error_code(std::errc::invalid_argument),
			  std::string(context) + ": the transaction is already committed or aborted");
		}
		return std::nullopt;
	}

	// Whether `c` is a transaction specification control, typed or raw.
	template<class Control> auto is_specification(const Control &c) -> bool
	{
		if (std::holds_alternative<transaction_specification>(c)) {
			return true;
		}
		const auto *raw = std::get_if<control>(&c);
		return raw != nullptr && raw->type == transaction_specification_oid;
	}

	// The update `request` with the transaction specification control, or
	// encode_error if it carries one already (typed or raw: two would be
	// sent).
	template<class Params>
	auto specified(Params &request, const transaction::state &s, std::string_view context) -> std::optional<error>
	{
		if (std::ranges::any_of(request.controls, [](const auto &c) { return is_specification(c); })) {
			return make_error(client_errc::encode_error,
			  std::string(context) + ": the request already carries a transaction_specification");
		}
		request.controls.emplace_back(transaction_specification{ .identifier = std::string(s.identifier) });
		return std::nullopt;
	}

	// Runs one update of the transaction: `run(conn, request, context)` is
	// the connection's detail::*_impl.
	template<class Params, class Run>
	auto run_update(transaction::state *s, Params request, std::string context, Run run) -> capy::task<result<response>>
	{
		if (auto e = unusable(s, context)) {
			co_return std::unexpected(std::move(*e));
		}
		if (auto e = specified(request, *s, context)) {
			co_return std::unexpected(std::move(*e));
		}
		++s->in_flight;
		const detail::scope_exit answered([s] noexcept { --s->in_flight; });
		auto r = co_await run(s->conn, std::move(request), context);
		if (r) {
			s->updates.push_back(
			  { .message_id = r->message_id, .context = std::pmr::string(context, s->updates.get_allocator()) });
		}
		co_return r;
	}

}// namespace

auto connection::begin_transaction(extended_controls controls) -> capy::task<result<transaction>>
{
	if (impl_ == nullptr) {
		co_return std::unexpected(no_connection(start_context));
	}
	impl_ref self(impl_);
	auto id = co_await start_exchange(self, std::move(controls));
	if (!id) {
		co_return std::unexpected(std::move(id.error()));
	}
	std::pmr::polymorphic_allocator<> alloc(self->mr());
	auto *s = alloc.new_object<transaction::state>(transaction::state{ .conn = self,
	  .identifier = std::pmr::string(*id, alloc),
	  .updates = std::pmr::vector<transaction::state::update>(alloc) });
	co_return transaction(s);
}

transaction::transaction(transaction &&other) noexcept : state_(std::exchange(other.state_, nullptr)) {}

auto transaction::operator=(transaction &&other) noexcept -> transaction &
{
	if (this != &other) {
		delete_transaction(std::exchange(state_, std::exchange(other.state_, nullptr)));
	}
	return *this;
}

transaction::~transaction() { delete_transaction(state_); }

auto transaction::identifier() const noexcept -> std::string_view
{
	return state_ == nullptr ? std::string_view{} : std::string_view(state_->identifier);
}

auto transaction::is_open() const noexcept -> bool { return state_ != nullptr && state_->open; }

auto transaction::add(add_params request) -> capy::task<result<response>>
{
	std::string context = op_context("add", request.entry);
	return run_update(state_, std::move(request), std::move(context), &detail::add_impl);
}

auto transaction::modify(modify_params request) -> capy::task<result<response>>
{
	std::string context = op_context("modify", request.object);
	return run_update(state_, std::move(request), std::move(context), &detail::modify_impl);
}

auto transaction::del(del_params request) -> capy::task<result<response>>
{
	std::string context = op_context("delete", request.entry);
	return run_update(state_, std::move(request), std::move(context), &detail::del_impl);
}

auto transaction::modify_dn(modify_dn_params request) -> capy::task<result<response>>
{
	std::string context = op_context("modify DN", request.entry);
	return run_update(state_, std::move(request), std::move(context), &detail::modify_dn_impl);
}

auto transaction::commit() -> capy::task<result<commit_result>>
{
	std::string context = "commit transaction";
	if (auto e = unusable(state_, context)) {
		co_return std::unexpected(std::move(*e));
	}
	state *s = state_;
	if (s->in_flight != 0) {
		// The server would commit without them, or refuse the commit,
		// depending on which it reads first.
		co_return fail(client_errc::operation_in_progress,
		  detail::format("{}: {} update(s) still in flight: await every update first", context, s->in_flight));
	}
	s->open = false;// settled, whatever the outcome
	bool answered = false;
	auto reply = co_await end_exchange(s->conn, std::string(s->identifier), true, context, &answered);
	if (answered) {
		s->needs_abort = false;
	}
	if (!reply) {
		co_return std::unexpected(std::move(reply.error()));
	}
	if (!reply->result.is_success()) {
		if (const auto id = reply->value.message_id) {
			detail::format_to(context, ": update message {}", *id);
			const auto it = std::ranges::find(s->updates, *id, &state::update::message_id);
			if (it != s->updates.end()) {
				detail::format_to(context, " ({})", std::string_view(it->context));
			}
		}
		co_return std::unexpected(reply->result.to_error(context));
	}
	co_return to_result(std::move(*reply));
}

auto transaction::abort() -> capy::task<result<void>>
{
	const std::string context = "abort transaction";
	if (auto e = unusable(state_, context)) {
		co_return std::unexpected(std::move(*e));
	}
	state *s = state_;
	s->open = false;
	bool answered = false;
	auto reply = co_await end_exchange(s->conn, std::string(s->identifier), false, context, &answered);
	if (answered) {
		s->needs_abort = false;
	}
	if (!reply) {
		co_return std::unexpected(std::move(reply.error()));
	}
	if (!reply->result.is_success()) {
		co_return std::unexpected(reply->result.to_error(context));
	}
	co_return result<void>{};
}

}// namespace jhetz::ldap
