#include "jhetz/ldap/connection.hpp"

#include "impl.hpp"

#include <initializer_list>
#include <memory_resource>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <variant>

namespace capy = boost::capy;

namespace jhetz::ldap {

using detail::impl_ref;
using detail::no_connection;
using detail::op_context;
using detail::op_index;
using detail::request_response;

namespace {

	// The ldap_result of a response, whatever the operation.
	const ldap_result &result_of(const message &m)
	{
		return std::visit(
		  [](const auto &op) -> const ldap_result & {
			  if constexpr (requires { op.result; })
				  return op.result;
			  else
				  throw std::logic_error("ldap: response without an LDAPResult");// the reader checked the operation
		  },
		  m.op);
	}

	// A response that only carries an LDAPResult: success gives its
	// controls, anything else the error.
	result<response> to_response(result<message> m, std::string_view context)
	{
		if (!m) return std::unexpected(std::move(m.error()));
		const ldap_result &r = result_of(*m);
		if (!r.is_success()) return std::unexpected(r.to_error(context));
		response out;
		out.controls.assign(m->controls.begin(), m->controls.end());
		return out;
	}

}// namespace

namespace detail {

	result<message> with_controls(protocol_op op,
	  const request_controls &controls,
	  std::pmr::memory_resource *mr,
	  std::string_view context)
	{
		message m{ std::pmr::polymorphic_allocator<>(mr) };
		m.op = std::move(op);
		if (auto c = append_controls(controls, m.controls); !c)
			return std::unexpected(detail::with_context(std::move(c.error()), context));
		return m;
	}

}// namespace detail

using detail::with_controls;

// ---------------------------------------------------------------- other operations

namespace mod {

	namespace {
		modify_change change(modify_operation op, std::string_view type, std::initializer_list<std::string_view> values)
		{
			return modify_change(op, partial_attribute(type, values));
		}
	}// namespace

	modify_change add(std::string_view type, std::initializer_list<std::string_view> values)
	{
		return change(modify_operation::add, type, values);
	}
	modify_change remove(std::string_view type, std::initializer_list<std::string_view> values)
	{
		return change(modify_operation::delete_, type, values);
	}
	modify_change replace(std::string_view type, std::initializer_list<std::string_view> values)
	{
		return change(modify_operation::replace, type, values);
	}
	modify_change increment(std::string_view type, std::string_view delta)
	{
		return change(modify_operation::increment, type, { delta });
	}

}// namespace mod

capy::task<result<response>> connection::add(add_params p)
{
	std::string context = op_context("add", p.entry);
	if (impl_ == nullptr) co_return std::unexpected(no_connection(context));
	impl_ref self(impl_);
	const std::pmr::polymorphic_allocator<> alloc(self->mr());
	add_request op(alloc);
	op.entry = p.entry.to_string(self->mr());
	op.attributes.assign(p.attributes.begin(), p.attributes.end());
	auto request = with_controls(std::move(op), p.controls, self->mr(), context);
	if (!request) co_return std::unexpected(std::move(request.error()));
	co_return to_response(
	  co_await request_response(self, std::move(*request), op_index<add_response>, context, p.timeout), context);
}

namespace detail {

	capy::task<result<response>> modify_impl(impl_ref self, modify_params p, std::string context)
	{
		const std::pmr::polymorphic_allocator<> alloc(self->mr());
		modify_request op(alloc);
		op.object = p.object.to_string(self->mr());
		op.changes.assign(p.changes.begin(), p.changes.end());
		auto request = with_controls(std::move(op), p.controls, self->mr(), context);
		if (!request) co_return std::unexpected(std::move(request.error()));
		co_return to_response(
		  co_await request_response(self, std::move(*request), op_index<modify_response>, context, p.timeout), context);
	}

}// namespace detail

using detail::modify_impl;

capy::task<result<response>> connection::modify(modify_params p)
{
	std::string context = op_context("modify", p.object);
	if (impl_ == nullptr) co_return std::unexpected(no_connection(context));
	co_return co_await modify_impl(impl_ref(impl_), std::move(p), std::move(context));
}

capy::task<result<response>> connection::del(del_params p)
{
	std::string context = op_context("delete", p.entry);
	if (impl_ == nullptr) co_return std::unexpected(no_connection(context));
	impl_ref self(impl_);
	auto request =
	  with_controls(del_request(p.entry.to_string(self->mr()), std::pmr::polymorphic_allocator<>(self->mr())),
		p.controls,
		self->mr(),
		context);
	if (!request) co_return std::unexpected(std::move(request.error()));
	co_return to_response(
	  co_await request_response(self, std::move(*request), op_index<del_response>, context, p.timeout), context);
}

capy::task<result<response>> connection::modify_dn(modify_dn_params p)
{
	std::string context = op_context("modify DN", p.entry);
	if (impl_ == nullptr) co_return std::unexpected(no_connection(context));
	if (p.new_rdn.avas.empty()) co_return fail(client_errc::invalid_dn, context + ": empty new RDN");
	impl_ref self(impl_);
	const std::pmr::polymorphic_allocator<> alloc(self->mr());
	modify_dn_request op(alloc);
	op.entry = p.entry.to_string(self->mr());
	op.new_rdn = dn{}.child(p.new_rdn).to_string(self->mr());// an RDN prints as a one-RDN DN
	op.delete_old_rdn = p.delete_old_rdn;
	if (p.new_superior) op.new_superior = p.new_superior->to_string(self->mr());
	auto request = with_controls(std::move(op), p.controls, self->mr(), context);
	if (!request) co_return std::unexpected(std::move(request.error()));
	co_return to_response(
	  co_await request_response(self, std::move(*request), op_index<modify_dn_response>, context, p.timeout), context);
}

capy::task<result<bool>> connection::compare(compare_params p)
{
	std::string context = op_context("compare", p.entry);
	if (impl_ == nullptr) co_return std::unexpected(no_connection(context));
	impl_ref self(impl_);
	const std::pmr::polymorphic_allocator<> alloc(self->mr());
	auto request = with_controls(
	  compare_request(p.entry.to_string(self->mr()), attribute_value_assertion(p.attribute, p.value, alloc), alloc),
	  p.controls,
	  self->mr(),
	  context);
	if (!request) co_return std::unexpected(std::move(request.error()));
	auto m = co_await request_response(self, std::move(*request), op_index<compare_response>, context, p.timeout);
	if (!m) co_return std::unexpected(std::move(m.error()));
	const ldap_result &r = result_of(*m);
	if (r.result_code == std::to_underlying(errc::compare_true)) co_return true;
	if (r.result_code == std::to_underlying(errc::compare_false)) co_return false;
	co_return std::unexpected(r.to_error(context));// success (0) is not a valid answer either
}

namespace detail {

	capy::task<result<extended_result>> extended_impl(impl_ref self, extended_params p)
	{
		std::string context = "extended operation " + p.name;
		const std::pmr::polymorphic_allocator<> alloc(self->mr());
		std::optional<std::string_view> value;
		if (p.value) value = *p.value;
		auto request = with_controls(extended_request(p.name, value, alloc), p.controls, self->mr(), context);
		if (!request) co_return std::unexpected(std::move(request.error()));
		auto m = co_await request_response(self, std::move(*request), op_index<extended_response>, context, p.timeout);
		if (!m) co_return std::unexpected(std::move(m.error()));
		auto &x = std::get<extended_response>(m->op);
		if (!x.result.is_success()) co_return std::unexpected(x.result.to_error(context));
		extended_result out;
		if (x.response_name) out.name.emplace(*x.response_name);
		if (x.response_value) out.value.emplace(*x.response_value);
		out.controls.assign(m->controls.begin(), m->controls.end());
		co_return out;
	}

}// namespace detail

using detail::extended_impl;

capy::task<result<extended_result>> connection::extended(extended_params p)
{
	if (impl_ == nullptr) co_return std::unexpected(no_connection("extended operation " + p.name));
	co_return co_await extended_impl(impl_ref(impl_), std::move(p));
}

capy::task<result<std::string>> connection::who_am_i(request_controls controls)
{
	auto r = co_await extended({ .name = std::string(who_am_i_oid), .controls = std::move(controls) });
	if (!r) co_return std::unexpected(std::move(r.error()));
	co_return r->value ? std::string(*r->value) : std::string();
}

}// namespace jhetz::ldap
