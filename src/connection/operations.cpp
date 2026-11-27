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
	auto to_response(result<message> m, std::string_view context) -> result<update_result>
	{
		if (!m) {
			return std::unexpected(std::move(m.error()));
		}
		const ldap_result &r = result_of(*m);
		if (!r.is_success()) {
			return std::unexpected(r.to_error(context));
		}
		update_result out;
		out.message_id = m->id;
		out.matched_dn.assign(r.matched_dn);
		out.diagnostic_message.assign(r.diagnostic_message);
		out.controls.assign(m->controls.begin(), m->controls.end());
		return out;
	}

	// A task that fails at once.
	auto refuse(std::error_code code, std::string context) -> capy::task<result<update_result>>
	{
		co_return fail(code, context);
	}

	// Not a coroutine: the update's task runs on the strand.
	template<class Params> auto update(const core_ref &self, Params request) -> capy::task<result<update_result>>
	{
		std::string context = detail::update_context(request);
		if (!self) {
			return refuse(client_errc::not_connected, std::move(context));
		}
		return detail::on_strand(self, detail::update_op<Params>::run(self, std::move(request), std::move(context)));
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

namespace {

	// Sends `op` with the controls of `p` and waits for its `Response`.
	template<class Response, class Params>
	auto exchange(core_ref self, protocol_op op, const Params &p, const std::string &context)
	  -> capy::task<result<update_result>>
	{
		auto msg = build_request(std::move(op), p.controls, self->mr(), context);
		if (!msg) {
			co_return std::unexpected(std::move(msg.error()));
		}
		co_return to_response(
		  co_await request_response(self, std::move(*msg), op_index<Response>, context, p.timeout), context);
	}

}// namespace

// ---------------------------------------------------------------- other operations

namespace detail {

	auto add_impl(core_ref self, add_params request, std::string context) -> capy::task<result<update_result>>
	{
		add_request op(request.entry.to_string());
		op.attributes.assign(request.attributes.begin(), request.attributes.end());
		co_return co_await exchange<add_response>(self, std::move(op), request, context);
	}

}// namespace detail

auto connection::add(add_params request) -> capy::task<result<update_result>>
{
	return update(core_, std::move(request));
}

namespace detail {

	auto modify_impl(core_ref self, modify_params request, std::string context) -> capy::task<result<update_result>>
	{
		const scope_exit wipe{ [&request] noexcept {
			for (auto &c : request.changes) {
				if (is_password_attribute(c.modification.type)) {
					for (auto &v : c.modification.values) {
						wipe_string(v);
					}
				}
			}
		} };
		modify_request op(request.object.to_string());
		op.changes.assign(request.changes.begin(), request.changes.end());
		co_return co_await exchange<modify_response>(self, std::move(op), request, context);
	}

}// namespace detail

auto connection::modify(modify_params request) -> capy::task<result<update_result>>
{
	return update(core_, std::move(request));
}

namespace detail {

	auto del_impl(core_ref self, del_params request, std::string context) -> capy::task<result<update_result>>
	{
		co_return co_await exchange<del_response>(self, del_request(request.entry.to_string()), request, context);
	}

	auto modify_dn_impl(core_ref self, modify_dn_params request, std::string context)
	  -> capy::task<result<update_result>>
	{
		if (request.new_rdn.avas.empty()) {
			co_return fail(client_errc::invalid_dn, context + ": empty new RDN");
		}
		modify_dn_request op;
		op.entry = request.entry.to_string();
		auto new_rdn = dn{}.child(request.new_rdn);// an RDN prints as a one-RDN DN
		if (!new_rdn) {
			co_return std::unexpected(with_context(std::move(new_rdn.error()), context));
		}
		op.new_rdn = new_rdn->to_string();
		op.delete_old_rdn = request.delete_old_rdn;
		if (request.new_superior) {
			op.new_superior = request.new_superior->to_string();
		}
		co_return co_await exchange<modify_dn_response>(self, std::move(op), request, context);
	}

}// namespace detail

auto connection::del(del_params request) -> capy::task<result<update_result>>
{
	return update(core_, std::move(request));
}

auto connection::modify_dn(modify_dn_params request) -> capy::task<result<update_result>>
{
	return update(core_, std::move(request));
}

namespace {

	auto compare_impl(core_ref self, compare_params request) -> capy::task<result<compare_result>>
	{
		const std::string context = op_context("compare", request.entry);
		if (!self) {
			co_return std::unexpected(no_connection(context));
		}
		auto msg = build_request(compare_request(request.entry.to_string(), { request.attribute, request.value }),
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
		const bool is_true = r.result_code == std::to_underlying(errc::compare_true);
		if (!is_true && r.result_code != std::to_underlying(errc::compare_false)) {
			co_return std::unexpected(r.to_error(context));// success (0) is not a valid answer either
		}
		compare_result out;
		out.matched = is_true;
		out.matched_dn.assign(r.matched_dn);
		out.diagnostic_message.assign(r.diagnostic_message);
		out.controls.assign(m->controls.begin(), m->controls.end());
		co_return out;
	}

}// namespace

auto connection::compare(compare_params request) -> capy::task<result<compare_result>>
{
	const core_ref self(core_);
	return detail::on_strand(self, compare_impl(self, std::move(request)));
}

namespace detail {

	auto extended_impl(core_ref self, extended_params request) -> capy::task<result<extended_result>>
	{
		const std::string context = "extended operation " + request.name;
		if (request.name == start_tls_oid) {
			// StartTLS goes through start_tls(), which sends no control.
			co_return std::unexpected(make_error(client_errc::encode_error, context + ": use start_tls()"));
		}
		const scope_exit wipe{ [&request] noexcept {
			if (request.name == password_modify_oid && request.value) {
				wipe_string(*request.value);
			}
		} };
		if (request.name == password_modify_oid && self->refuses_cleartext_password()) {
			co_return fail(client_errc::tls_required,
			  context + ": the passwords would be sent in clear (use ldaps://, start_tls() or "
						"connection_options::allow_cleartext_passwords)");
		}
		std::optional<std::string_view> value;
		if (request.value) {
			value = *request.value;
		}
		auto msg = build_request(extended_request(request.name, value), request.controls, self->mr(), context);
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

auto connection::extended(extended_params request) -> capy::task<result<extended_result>>
{
	if (!core_) {
		return detail::failed_task<extended_result>(no_connection("extended operation " + request.name));
	}
	const core_ref self(core_);
	return detail::on_strand(self, extended_impl(self, std::move(request)));
}

}// namespace jhetz::ldap
