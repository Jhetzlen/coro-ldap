#include "jhetz/ldap/connection.hpp"

#include "impl.hpp"

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
	// controls, anything else the error.
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
		out.controls.assign(m->controls.begin(), m->controls.end());
		return out;
	}

}// namespace

namespace detail {

	auto with_controls(protocol_op op,
	  const request_controls &controls,
	  std::pmr::memory_resource *mr,
	  std::string_view context) -> result<message>
	{
		message m{ std::pmr::polymorphic_allocator<>(mr) };
		m.op = std::move(op);
		if (auto c = append_controls(controls, m.controls); !c) {
			return std::unexpected(detail::with_context(std::move(c.error()), context));
		}
		return m;
	}

}// namespace detail

using detail::with_controls;

// ---------------------------------------------------------------- other operations

auto connection::add(add_params p) -> capy::task<result<response>>
{
	std::string context = op_context("add", p.entry);
	if (impl_ == nullptr) {
		co_return std::unexpected(no_connection(context));
	}
	impl_ref self(impl_);
	const std::pmr::polymorphic_allocator<> alloc(self->mr());
	add_request op(alloc);
	op.entry = p.entry.to_string(self->mr());
	op.attributes.assign(p.attributes.begin(), p.attributes.end());
	auto request = with_controls(std::move(op), p.controls, self->mr(), context);
	if (!request) {
		co_return std::unexpected(std::move(request.error()));
	}
	co_return to_response(
	  co_await request_response(self, std::move(*request), op_index<add_response>, context, p.timeout), context);
}

namespace detail {

	auto modify_impl(impl_ref self, modify_params p, std::string context) -> capy::task<result<response>>
	{
		const std::pmr::polymorphic_allocator<> alloc(self->mr());
		modify_request op(alloc);
		op.object = p.object.to_string(self->mr());
		op.changes.assign(p.changes.begin(), p.changes.end());
		auto request = with_controls(std::move(op), p.controls, self->mr(), context);
		if (!request) {
			co_return std::unexpected(std::move(request.error()));
		}
		co_return to_response(
		  co_await request_response(self, std::move(*request), op_index<modify_response>, context, p.timeout), context);
	}

}// namespace detail

using detail::modify_impl;

auto connection::modify(modify_params p) -> capy::task<result<response>>
{
	std::string context = op_context("modify", p.object);
	if (impl_ == nullptr) {
		co_return std::unexpected(no_connection(context));
	}
	co_return co_await modify_impl(impl_ref(impl_), std::move(p), std::move(context));
}

auto connection::del(del_params p) -> capy::task<result<response>>
{
	std::string context = op_context("delete", p.entry);
	if (impl_ == nullptr) {
		co_return std::unexpected(no_connection(context));
	}
	impl_ref self(impl_);
	auto request =
	  with_controls(del_request(p.entry.to_string(self->mr()), std::pmr::polymorphic_allocator<>(self->mr())),
		p.controls,
		self->mr(),
		context);
	if (!request) {
		co_return std::unexpected(std::move(request.error()));
	}
	co_return to_response(
	  co_await request_response(self, std::move(*request), op_index<del_response>, context, p.timeout), context);
}

auto connection::modify_dn(modify_dn_params p) -> capy::task<result<response>>
{
	std::string context = op_context("modify DN", p.entry);
	if (impl_ == nullptr) {
		co_return std::unexpected(no_connection(context));
	}
	if (p.new_rdn.avas.empty()) {
		co_return fail(client_errc::invalid_dn, context + ": empty new RDN");
	}
	impl_ref self(impl_);
	const std::pmr::polymorphic_allocator<> alloc(self->mr());
	modify_dn_request op(alloc);
	op.entry = p.entry.to_string(self->mr());
	op.new_rdn = dn{}.child(p.new_rdn).to_string(self->mr());// an RDN prints as a one-RDN DN
	op.delete_old_rdn = p.delete_old_rdn;
	if (p.new_superior) {
		op.new_superior = p.new_superior->to_string(self->mr());
	}
	auto request = with_controls(std::move(op), p.controls, self->mr(), context);
	if (!request) {
		co_return std::unexpected(std::move(request.error()));
	}
	co_return to_response(
	  co_await request_response(self, std::move(*request), op_index<modify_dn_response>, context, p.timeout), context);
}

// Not coroutines: the task of modify_dn() is returned as is.
auto connection::move(dn entry,
  dn new_parent,
  request_controls controls,
  std::optional<std::chrono::milliseconds> timeout) -> capy::task<result<response>>
{
	rdn kept = entry.empty() ? rdn{} : entry.rdns().front();
	return modify_dn({ .entry = std::move(entry),
	  .new_rdn = std::move(kept),
	  .new_superior = std::move(new_parent),
	  .controls = std::move(controls),
	  .timeout = timeout });
}

auto connection::rename(dn entry,
  rdn new_rdn,
  bool delete_old_rdn,
  request_controls controls,
  std::optional<std::chrono::milliseconds> timeout) -> capy::task<result<response>>
{
	return modify_dn({ .entry = std::move(entry),
	  .new_rdn = std::move(new_rdn),
	  .delete_old_rdn = delete_old_rdn,
	  .controls = std::move(controls),
	  .timeout = timeout });
}

auto connection::compare(compare_params p) -> capy::task<result<bool>>
{
	std::string context = op_context("compare", p.entry);
	if (impl_ == nullptr) {
		co_return std::unexpected(no_connection(context));
	}
	impl_ref self(impl_);
	const std::pmr::polymorphic_allocator<> alloc(self->mr());
	auto request = with_controls(
	  compare_request(p.entry.to_string(self->mr()), attribute_value_assertion(p.attribute, p.value, alloc), alloc),
	  p.controls,
	  self->mr(),
	  context);
	if (!request) {
		co_return std::unexpected(std::move(request.error()));
	}
	auto m = co_await request_response(self, std::move(*request), op_index<compare_response>, context, p.timeout);
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

namespace detail {

	auto extended_impl(impl_ref self, extended_params p) -> capy::task<result<extended_result>>
	{
		std::string context = "extended operation " + p.name;
		const std::pmr::polymorphic_allocator<> alloc(self->mr());
		std::optional<std::string_view> value;
		if (p.value) {
			value = *p.value;
		}
		auto request = with_controls(extended_request(p.name, value, alloc), p.controls, self->mr(), context);
		if (!request) {
			co_return std::unexpected(std::move(request.error()));
		}
		auto m = co_await request_response(self, std::move(*request), op_index<extended_response>, context, p.timeout);
		if (!m) {
			co_return std::unexpected(std::move(m.error()));
		}
		auto &x = std::get<extended_response>(m->op);
		if (!x.result.is_success()) {
			co_return std::unexpected(x.result.to_error(context));
		}
		extended_result out;
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

auto connection::extended(extended_params p) -> capy::task<result<extended_result>>
{
	if (impl_ == nullptr) {
		co_return std::unexpected(no_connection("extended operation " + p.name));
	}
	co_return co_await extended_impl(impl_ref(impl_), std::move(p));
}

auto connection::who_am_i(request_controls controls) -> capy::task<result<std::string>>
{
	auto r = co_await extended({ .name = std::string(who_am_i_oid), .controls = std::move(controls) });
	if (!r) {
		co_return std::unexpected(std::move(r.error()));
	}
	co_return r->value ? std::string(*r->value) : std::string();
}

}// namespace jhetz::ldap
