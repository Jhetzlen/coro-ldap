#include "jhetz/ldap/connection.hpp"

#include "../format_util.hpp"
#include "impl.hpp"
#include "search.hpp"

#include <algorithm>
#include <memory>
#include <string>
#include <typeindex>
#include <utility>
#include <vector>

namespace capy = boost::capy;

namespace jhetz::ldap {

using detail::impl_ref;
using detail::no_connection;
using detail::read_one;

namespace {

	auto load_schema_impl(impl_ref self) -> capy::task<result<server_schema>>
	{
		const std::string context = "load schema";
		auto root = co_await read_one(self, root_dse({ "subschemaSubentry" }));
		if (!root) {
			co_return std::unexpected(detail::with_context(std::move(root.error()), context));
		}
		std::string where = "cn=Subschema";
		if (*root) {
			if (const auto *v = (*root)->find("subschemaSubentry"); v != nullptr && !v->empty()) {
				where = std::string(v->front());
			}
		}
		// `where` is the server's text: quoted sanitized (a DN, as entry_context).
		const auto quoted = [&where](std::string text) {
			detail::append_sanitized(text, where, 256);
			return text;
		};
		auto base = dn::parse(where);
		if (!base) {
			co_return fail(
			  client_errc::invalid_dn, quoted(context + ": the root DSE names an invalid subschemaSubentry: "));
		}
		auto sub = co_await read_one(self,
		  { .base = std::move(*base),
			.scope = search_scope::base_object,
			.filter = filters::attr("objectClass") == "subschema",
			.attributes = { "attributeTypes", "objectClasses" } });
		if (!sub) {
			co_return std::unexpected(detail::with_context(std::move(sub.error()), context));
		}
		if (!*sub) {
			co_return fail(errc::no_such_object, quoted(context + ": no subschema entry at "));
		}
		static const std::pmr::vector<std::pmr::string> none;
		const auto *types = (*sub)->find("attributeTypes");
		const auto *classes = (*sub)->find("objectClasses");
		co_return server_schema::parse(types ? *types : none, classes ? *classes : none);
	}

}// namespace

auto connection::load_schema() -> capy::task<result<server_schema>>
{
	if (impl_ == nullptr) {
		co_return std::unexpected(no_connection("load schema"));
	}
	co_return co_await load_schema_impl(impl_ref(impl_));
}

auto connection::check_schema(std::type_index type, schema_report (*validate_type)(const server_schema &))
  -> capy::task<result<void>>
{
	if (impl_ == nullptr || impl_->knowledge().schema_mode == ldap::schema_check::off) {
		co_return result<void>{};
	}
	impl_ref self(impl_);
	if (std::ranges::contains(self->knowledge().schema_checked, type)) {
		co_return result<void>{};
	}
	if (!self->knowledge().schema) {
		auto s = co_await load_schema_impl(self);
		if (!s) {
			co_return std::unexpected(std::move(s.error()));
		}
		self->knowledge().schema = std::make_shared<const server_schema>(std::move(*s));
	}
	const schema_report report = validate_type(*self->knowledge().schema);
	if (!report.ok()) {
		co_return fail(
		  client_errc::schema_mismatch, detail::format("schema check of {}:\n{}", type.name(), report.to_string()));
	}
	self->knowledge().schema_checked.push_back(type);
	co_return result<void>{};
}

}// namespace jhetz::ldap
