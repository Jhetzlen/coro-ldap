#include "jhetz/ldap/connection.hpp"
#include "jhetz/ldap/mapping.hpp"

#include "core.hpp"

#include <memory_resource>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <variant>

namespace capy = boost::capy;

namespace jhetz::ldap {

using detail::core_ref;
using detail::no_connection;
using detail::op_context;
using detail::op_index;
using detail::request_response;

namespace {

	// The ldap_result of a response, whatever the operation.
	auto result_of(const message &m) -> const ldap_result &
	{
		return std::visit(
		  [](const auto &op) -> const ldap_result & {
			  if constexpr (requires { op.result; }) {
				  return op.result;
			  } else {
				  throw std::logic_error("ldap: response without an LDAPResult");// the reader checked the operation
			  }
		  },
		  m.op);
	}

	// A response that only carries an LDAPResult: success gives its
	// matchedDN, diagnosticMessage and controls, anything else the error.
	auto to_response(result<message> m, std::string_view context) -> result<response>
	{
		if (!m) {
			return std::unexpected(std::move(m.error()));
		}
		const ldap_result &r = result_of(*m);
		if (!r.is_success()) {
			return std::unexpected(r.to_error(context));
		}
		response out;
		out.message_id = m->id;
		out.matched_dn.assign(r.matched_dn);
		out.diagnostic_message.assign(r.diagnostic_message);
		out.controls.assign(m->controls.begin(), m->controls.end());
		return out;
	}

	// A task that fails at once, for the forwarders that refuse a request
	// before modify_dn() would.
	auto refuse(std::error_code code, std::string context) -> capy::task<result<response>>
	{
		co_return fail(code, context);
	}

}// namespace

namespace detail {

	auto with_controls(protocol_op op, std::pmr::vector<control> controls, std::pmr::memory_resource *mr) -> message
	{
		message m{ std::pmr::polymorphic_allocator<>(mr) };
		m.op = std::move(op);
		m.controls = std::move(controls);
		return m;
	}

}// namespace detail

using detail::build_request;

// ---------------------------------------------------------------- other operations

namespace detail {

	auto add_impl(core_ref self, add_params request, std::string context) -> capy::task<result<response>>
	{
		const std::pmr::polymorphic_allocator<> alloc(self->mr());
		add_request op(alloc);
		op.entry = request.entry.to_string(self->mr());
		op.attributes.assign(request.attributes.begin(), request.attributes.end());
		auto msg = build_request(std::move(op), request.controls, self->mr(), context);
		if (!msg) {
			co_return std::unexpected(std::move(msg.error()));
		}
		co_return to_response(
		  co_await request_response(self, std::move(*msg), op_index<add_response>, context, request.timeout), context);
	}

}// namespace detail

// Not a coroutine: the task of detail::add_impl() runs on the strand.
auto connection::add(add_params request) -> capy::task<result<response>>
{
	std::string context = op_context("add", request.entry);
	if (core_ == nullptr) {
		return refuse(client_errc::not_connected, std::move(context));
	}
	const core_ref self(core_);
	return detail::on_strand(self, detail::add_impl(self, std::move(request), std::move(context)));
}

namespace detail {

	auto modify_impl(core_ref self, modify_params request, std::string context) -> capy::task<result<response>>
	{
		const std::pmr::polymorphic_allocator<> alloc(self->mr());
		modify_request op(alloc);
		op.object = request.object.to_string(self->mr());
		op.changes.assign(request.changes.begin(), request.changes.end());
		auto msg = build_request(std::move(op), request.controls, self->mr(), context);
		if (!msg) {
			co_return std::unexpected(std::move(msg.error()));
		}
		co_return to_response(
		  co_await request_response(self, std::move(*msg), op_index<modify_response>, context, request.timeout),
		  context);
	}

}// namespace detail

// Not a coroutine: the task of detail::modify_impl() runs on the strand.
auto connection::modify(modify_params request) -> capy::task<result<response>>
{
	std::string context = op_context("modify", request.object);
	if (core_ == nullptr) {
		return refuse(client_errc::not_connected, std::move(context));
	}
	const core_ref self(core_);
	return detail::on_strand(self, detail::modify_impl(self, std::move(request), std::move(context)));
}

namespace detail {

	auto del_impl(core_ref self, del_params request, std::string context) -> capy::task<result<response>>
	{
		auto msg =
		  build_request(del_request(request.entry.to_string(self->mr()), std::pmr::polymorphic_allocator<>(self->mr())),
			request.controls,
			self->mr(),
			context);
		if (!msg) {
			co_return std::unexpected(std::move(msg.error()));
		}
		co_return to_response(
		  co_await request_response(self, std::move(*msg), op_index<del_response>, context, request.timeout), context);
	}

	auto modify_dn_impl(core_ref self, modify_dn_params request, std::string context) -> capy::task<result<response>>
	{
		if (request.new_rdn.avas.empty()) {
			co_return fail(client_errc::invalid_dn, context + ": empty new RDN");
		}
		const std::pmr::polymorphic_allocator<> alloc(self->mr());
		modify_dn_request op(alloc);
		op.entry = request.entry.to_string(self->mr());
		op.new_rdn = dn{}.child(request.new_rdn).to_string(self->mr());// an RDN prints as a one-RDN DN
		op.delete_old_rdn = request.delete_old_rdn;
		if (request.new_superior) {
			op.new_superior = request.new_superior->to_string(self->mr());
		}
		auto msg = build_request(std::move(op), request.controls, self->mr(), context);
		if (!msg) {
			co_return std::unexpected(std::move(msg.error()));
		}
		co_return to_response(
		  co_await request_response(self, std::move(*msg), op_index<modify_dn_response>, context, request.timeout),
		  context);
	}

}// namespace detail

// Not a coroutine: the task of detail::del_impl() runs on the strand.
auto connection::del(del_params request) -> capy::task<result<response>>
{
	std::string context = op_context("delete", request.entry);
	if (core_ == nullptr) {
		return refuse(client_errc::not_connected, std::move(context));
	}
	const core_ref self(core_);
	return detail::on_strand(self, detail::del_impl(self, std::move(request), std::move(context)));
}

// Not a coroutine: the task of detail::modify_dn_impl() runs on the strand.
auto connection::modify_dn(modify_dn_params request) -> capy::task<result<response>>
{
	std::string context = op_context("modify DN", request.entry);
	if (core_ == nullptr) {
		return refuse(client_errc::not_connected, std::move(context));
	}
	const core_ref self(core_);
	return detail::on_strand(self, detail::modify_dn_impl(self, std::move(request), std::move(context)));
}

namespace {

	auto compare_impl(core_ref self, compare_params request) -> capy::task<result<bool>>
	{
		const std::string context = op_context("compare", request.entry);
		if (!self) {
			co_return std::unexpected(no_connection(context));
		}
		const std::pmr::polymorphic_allocator<> alloc(self->mr());
		auto msg = build_request(compare_request(request.entry.to_string(self->mr()),
								   attribute_value_assertion(request.attribute, request.value, alloc),
								   alloc),
		  request.controls,
		  self->mr(),
		  context);
		if (!msg) {
			co_return std::unexpected(std::move(msg.error()));
		}
		auto m = co_await request_response(self, std::move(*msg), op_index<compare_response>, context, request.timeout);
		if (!m) {
			co_return std::unexpected(std::move(m.error()));
		}
		const ldap_result &r = result_of(*m);
		if (r.result_code == std::to_underlying(errc::compare_true)) {
			co_return true;
		}
		if (r.result_code == std::to_underlying(errc::compare_false)) {
			co_return false;
		}
		co_return std::unexpected(r.to_error(context));// success (0) is not a valid answer either
	}

}// namespace

auto connection::compare(compare_params request) -> capy::task<result<bool>>
{
	const core_ref self(core_);
	return detail::on_strand(self, compare_impl(self, std::move(request)));
}

namespace detail {

	auto extended_impl(core_ref self, extended_params request) -> capy::task<result<extended_result>>
	{
		const std::string context = "extended operation " + request.name;
		if (request.name == start_tls_oid) {
			// RFC 4511 section 4.14: StartTLS changes the transport, which
			// start_tls() drives; RFC 4370 section 3 keeps proxied
			// authorization off it, and start_tls() sends no control.
			co_return std::unexpected(make_error(client_errc::encode_error, context + ": use start_tls()"));
		}
		const std::pmr::polymorphic_allocator<> alloc(self->mr());
		std::optional<std::string_view> value;
		if (request.value) {
			value = *request.value;
		}
		auto msg = build_request(extended_request(request.name, value, alloc), request.controls, self->mr(), context);
		if (!msg) {
			co_return std::unexpected(std::move(msg.error()));
		}
		extended_result out;
		auto m = co_await request_response(self,
		  std::move(*msg),
		  op_index<extended_response>,
		  context,
		  request.timeout,
		  request.intermediate_responses ? &out.intermediates : nullptr);
		if (!m) {
			co_return std::unexpected(std::move(m.error()));
		}
		auto &x = std::get<extended_response>(m->op);
		if (!x.result.is_success()) {
			co_return std::unexpected(x.result.to_error(context));
		}
		if (x.response_name) {
			out.name.emplace(*x.response_name);
		}
		if (x.response_value) {
			out.value.emplace(*x.response_value);
		}
		out.controls.assign(m->controls.begin(), m->controls.end());
		co_return out;
	}

}// namespace detail

using detail::extended_impl;

namespace {

	auto refuse_extended(error e) -> capy::task<result<extended_result>> { co_return std::unexpected(std::move(e)); }

}// namespace

auto connection::extended(extended_params request) -> capy::task<result<extended_result>>
{
	if (core_ == nullptr) {
		return refuse_extended(no_connection("extended operation " + request.name));
	}
	const core_ref self(core_);
	return detail::on_strand(self, extended_impl(self, std::move(request)));
}

}// namespace jhetz::ldap
