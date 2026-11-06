#include "jhetz/ldap/directory.hpp"

#include "format_util.hpp"

#include <string>
#include <utility>

namespace jhetz::ldap {

namespace {

	// `where` is the server's text: quoted sanitized, as a DN in entry_context.
	auto quoted(std::string text, std::string_view where) -> std::string
	{
		detail::append_sanitized(text, where, 256);
		return text;
	}

}// namespace

auto detail::subschema_request(const result<search_result> &root) -> result<subschema_search>
{
	const std::string context(load_schema_context);
	if (!root) {
		return std::unexpected(detail::with_context(root.error(), context));
	}
	std::string where = "cn=Subschema";
	if (!root->entries.empty()) {
		if (const auto *v = root->entries.front().find("subschemaSubentry"); v != nullptr && !v->empty()) {
			where = std::string(v->front());
		}
	}
	auto base = dn::parse(where);
	if (!base) {
		return fail(
		  client_errc::invalid_dn, quoted(context + ": the root DSE names an invalid subschemaSubentry: ", where));
	}
	return subschema_search{ .request = { .base = std::move(*base),
							   .scope = search_scope::base_object,
							   .filter = filters::attr("objectClass") == "subschema",
							   .attributes = { "attributeTypes", "objectClasses" } },
		.where = std::move(where) };
}

auto detail::subschema_of(result<search_result> sub, std::string_view where) -> result<server_schema>
{
	const std::string context(load_schema_context);
	if (!sub) {
		return std::unexpected(detail::with_context(std::move(sub.error()), context));
	}
	if (sub->entries.empty()) {
		return fail(errc::no_such_object, quoted(context + ": no subschema entry at ", where));
	}
	static const std::pmr::vector<std::pmr::string> none;
	const entry &e = sub->entries.front();
	const auto *types = e.find("attributeTypes");
	const auto *classes = e.find("objectClasses");
	return server_schema::parse(types != nullptr ? *types : none, classes != nullptr ? *classes : none);
}

auto detail::schema_mismatch(std::string_view type, const schema_report &report) -> error
{
	return make_error(
	  client_errc::schema_mismatch, detail::format("schema check of {}:\n{}", type, report.to_string()));
}

}// namespace jhetz::ldap
