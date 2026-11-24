// RFC 5805 transactions: start_transaction(), end_transaction() and
// ldap::transaction.
#include "jhetz/ldap/transaction.hpp"
#include "jhetz/ldap/connection.hpp"

#include "../format_util.hpp"
#include "core.hpp"

#include <algorithm>
#include <atomic>
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
using detail::core_ref;
using detail::no_connection;
using detail::op_index;
using detail::request_response;

namespace {

	constexpr std::string_view start_context = "start transaction";
	constexpr std::string_view end_context = "end transaction";

	// An End Transaction exchange's result, txnEndRes and controls.
	struct end_reply
	{
		ldap_result result{};
		end_transaction_response value{};
		std::pmr::vector<control> controls{};
	};

	// The End Transaction request; no control goes on it (RFC 5805 sections
	// 4.1 to 4.5).
	auto end_request(std::string_view identifier, bool commit, std::pmr::memory_resource *mr) -> extended_request
	{
		const std::pmr::string value = encode_end_transaction_request(end_transaction_request(commit, identifier), mr);
		return { end_transaction_oid, std::string_view(value) };
	}

	// `answered` is set once the server answered: the transaction is over.
	auto end_exchange(core_ref self, std::string identifier, bool commit, std::string context, bool *answered)
	  -> capy::task<result<end_reply>>
	{
		auto msg = build_request(end_request(identifier, commit, self->mr()), extended_controls{}, self->mr(), context);
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
			// A malformed txnEndRes: keep the server's result code, without a message
			// id.
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

	// Waits for the answers still due (a destroyed transaction's abort), at
	// most the default timeout, then sends Start Transaction.
	auto start_exchange(core_ref self, extended_controls controls) -> capy::task<result<std::string>>
	{
		const std::string context(start_context);
		if (self->answers_due() != 0) {
			const auto [ec, left] = co_await self->wait_due_answers(detail::deadline_after(self->default_timeout()));
			if (ec && ec != capy::cond::timeout) {
				co_return fail(
				  ec, detail::format("{} (waiting for {} answer{} due)", context, left, left == 1 ? "" : "s"));
			}
		}
		auto msg = build_request(extended_request(start_transaction_oid), controls, self->mr(), context);
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
		co_return std::string(*x.response_value);
	}

}// namespace

namespace {

	auto start_transaction_impl(core_ref self, extended_controls controls) -> capy::task<result<std::string>>
	{
		if (!self) {
			co_return std::unexpected(no_connection(start_context));
		}
		co_return co_await start_exchange(std::move(self), std::move(controls));
	}

	auto end_transaction_impl(core_ref self, std::string identifier, bool commit)
	  -> capy::task<result<end_transaction_result>>
	{
		std::string context(end_context);
		if (!self) {
			co_return std::unexpected(no_connection(context));
		}
		auto reply = co_await end_exchange(std::move(self), std::move(identifier), commit, context, nullptr);
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

}// namespace

// NOLINTNEXTLINE(misc-const-correctness): the exchange runs on `conn`
auto start_transaction(connection &conn, extended_controls controls) -> capy::task<result<std::string>>
{
	const core_ref self(connection::core::of(conn));
	return detail::on_strand(self, start_transaction_impl(self, std::move(controls)));
}

// NOLINTNEXTLINE(misc-const-correctness): the exchange runs on `conn`
auto end_transaction(connection &conn, std::string identifier, bool commit)
  -> capy::task<result<end_transaction_result>>
{
	const core_ref self(connection::core::of(conn));
	return detail::on_strand(self, end_transaction_impl(self, std::move(identifier), commit));
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

	core_ref conn;
	std::pmr::string identifier;
	std::pmr::vector<update> updates;
	// Updates sent and not yet answered: commit() refuses while there are.
	std::size_t in_flight = 0;
	// Neither commit() nor abort() was called.
	std::atomic<bool> open = true;
	// No End Transaction answered yet: the destructor aborts it.
	bool needs_abort = true;
};

namespace {

	void delete_transaction_now(transaction::state *s) noexcept
	{
		// Abort without waiting; the answer is dropped.
		try {
			if (s->needs_abort && s->conn->is_open()) {
				const std::string context = std::string(end_context) + " (abort, transaction destroyed)";
				message m = detail::with_controls(end_request(s->identifier, false, s->conn->mr()), {}, s->conn->mr());
				s->conn->send_unanswered(m, false, detail::deadline_after(s->conn->default_timeout()), context);
			}
		} catch (...) {// NOLINT(bugprone-empty-catch): out of memory, the abort is best effort
		}
		core_ref keep = s->conn;
		std::pmr::polymorphic_allocator<> alloc(keep->mr());
		alloc.delete_object(s);
	}

	void delete_transaction(transaction::state *s) noexcept
	{
		if (s == nullptr) {
			return;
		}
		detail::run_on_strand(*s->conn, [s] noexcept { delete_transaction_now(s); });
	}

	auto conn_of(const transaction::state *s) -> core_ref { return s == nullptr ? core_ref() : s->conn; }

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

	// `request` with the transaction specification control; encode_error if it
	// has one already.
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

	// Runs one update of the transaction with the connection's detail::*_impl.
	template<class Params>
	auto run_update(transaction::state *s, Params request, std::string context) -> capy::task<result<response>>
	{
		if (auto e = unusable(s, context)) {
			co_return std::unexpected(std::move(*e));
		}
		if (auto e = specified(request, *s, context)) {
			co_return std::unexpected(std::move(*e));
		}
		++s->in_flight;
		const detail::scope_exit answered([s] noexcept { --s->in_flight; });
		auto r = co_await detail::update_op<Params>::run(s->conn, std::move(request), context);
		if (r) {
			s->updates.push_back(
			  { .message_id = r->message_id, .context = std::pmr::string(context, s->updates.get_allocator()) });
		}
		co_return r;
	}

	template<class Params> auto update(transaction::state *s, Params request) -> capy::task<result<response>>
	{
		std::string context = detail::update_context(request);
		return detail::on_strand(conn_of(s), run_update(s, std::move(request), std::move(context)));
	}

}// namespace

namespace {

	auto begin_impl(core_ref self, extended_controls controls) -> capy::task<result<transaction>>
	{
		if (!self) {
			co_return std::unexpected(no_connection(start_context));
		}
		auto id = co_await start_exchange(self, std::move(controls));
		if (!id) {
			co_return std::unexpected(std::move(id.error()));
		}
		std::pmr::polymorphic_allocator<> alloc(self->mr());
		auto *s = alloc.new_object<transaction::state>();
		s->conn = std::move(self);
		s->identifier = std::pmr::string(*id, alloc);
		s->updates = std::pmr::vector<transaction::state::update>(alloc);
		co_return connection::core::make_transaction(s);
	}

}// namespace

auto transaction::begin(connection &conn, extended_controls controls) -> capy::task<result<transaction>>
{
	const core_ref self(connection::core::of(conn));
	return detail::on_strand(self, begin_impl(self, std::move(controls)));
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

auto transaction::add(add_params request) -> capy::task<result<response>> { return update(state_, std::move(request)); }

auto transaction::modify(modify_params request) -> capy::task<result<response>>
{
	return update(state_, std::move(request));
}

auto transaction::del(del_params request) -> capy::task<result<response>> { return update(state_, std::move(request)); }

auto transaction::modify_dn(modify_dn_params request) -> capy::task<result<response>>
{
	return update(state_, std::move(request));
}

namespace {

	// End Transaction on `s`, settled whatever the outcome.
	auto settle(transaction::state *s, bool commit, std::string context) -> capy::task<result<end_reply>>
	{
		s->open = false;
		bool answered = false;
		auto reply = co_await end_exchange(s->conn, std::string(s->identifier), commit, std::move(context), &answered);
		if (answered) {
			s->needs_abort = false;
		}
		co_return reply;
	}

	auto commit_impl(transaction::state *s) -> capy::task<result<commit_result>>
	{
		std::string context = "commit transaction";
		if (auto e = unusable(s, context)) {
			co_return std::unexpected(std::move(*e));
		}
		if (s->in_flight != 0) {
			co_return fail(client_errc::operation_in_progress,
			  detail::format("{}: {} update(s) still in flight: await every update first", context, s->in_flight));
		}
		auto reply = co_await settle(s, true, context);
		if (!reply) {
			co_return std::unexpected(std::move(reply.error()));
		}
		if (!reply->result.is_success()) {
			if (const auto id = reply->value.message_id) {
				detail::format_to(context, ": update message {}", *id);
				const auto it = std::ranges::find(s->updates, *id, &transaction::state::update::message_id);
				if (it != s->updates.end()) {
					detail::format_to(context, " ({})", std::string_view(it->context));
				}
			}
			co_return std::unexpected(reply->result.to_error(context));
		}
		co_return to_result(std::move(*reply));
	}

	auto abort_impl(transaction::state *s) -> capy::task<result<void>>
	{
		const std::string context = "abort transaction";
		if (auto e = unusable(s, context)) {
			co_return std::unexpected(std::move(*e));
		}
		auto reply = co_await settle(s, false, context);
		if (!reply) {
			co_return std::unexpected(std::move(reply.error()));
		}
		if (!reply->result.is_success()) {
			co_return std::unexpected(reply->result.to_error(context));
		}
		co_return result<void>{};
	}

}// namespace

auto transaction::commit() -> capy::task<result<commit_result>>
{
	return detail::on_strand(conn_of(state_), commit_impl(state_));
}

auto transaction::abort() -> capy::task<result<void>> { return detail::on_strand(conn_of(state_), abort_impl(state_)); }

}// namespace jhetz::ldap
