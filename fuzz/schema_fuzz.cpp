// libFuzzer target for the RFC 4512 subschema parser: the attribute type,
// object class and content rule grammars agree, and server_schema lookups
// and validate<T>'s MUST check terminate.
#include "jhetz/ldap/schema.hpp"

#include "check.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <ranges>
#include <string>
#include <string_view>
#include <vector>

constexpr jhetz::ldap::fuzz::checker check{ "schema_fuzz" };

namespace ldap = jhetz::ldap;

namespace {

// The input split at its newlines, as several definitions.
void check_multi(std::string_view text)
{
	if (!text.contains('\n')) {
		return;
	}
	std::pmr::vector<std::pmr::string> lines;
	std::vector<ldap::object_class_type> parsed;
	for (const auto line : std::views::split(text, '\n')) {
		lines.emplace_back(std::string_view(line));
		if (auto lc = ldap::parse_object_class(lines.back())) {
			parsed.push_back(std::move(*lc));
		}
	}
	const auto multi = ldap::server_schema::parse(lines, lines, lines);
	std::vector<const char *> declared;
	std::vector<ldap::detail::field_use> fields;
	for (const auto &pc : parsed) {
		declared.push_back(pc.oid.c_str());
		for (const auto &n : pc.names) {
			fields.push_back({ .name = n, .kind = ldap::cardinality::multiple, .read_only = false });
		}
	}
	ldap::schema_report rep;
	ldap::detail::check_class_attributes(multi, declared, fields, rep);
	for (const auto &i : rep.issues) {
		check(!i.is_error(), "!i.is_error()");
		if (i.what == ldap::schema_issue::kind::attribute_not_allowed) {
			check(std::ranges::contains(fields, std::string_view(i.name), &ldap::detail::field_use::name),
			  "a not-allowed issue names a member");
			continue;
		}
		const bool superclass = i.what == ldap::schema_issue::kind::unknown_superclass;
		check(std::ranges::any_of(parsed,
				[&](const ldap::object_class_type &pc) {
					return std::ranges::contains(superclass ? pc.sup : pc.must, i.name);
				}),
		  "a MUST issue names a parsed class's MUST entry, a superclass issue a SUP entry");
	}
}

}// namespace

extern "C" auto LLVMFuzzerTestOneInput(const std::uint8_t *data, std::size_t size) -> int
{
	const std::string_view text(reinterpret_cast<const char *>(data), size);
	auto a = ldap::parse_attribute_type(text);
	if (!a) {
		check(a.error().code == ldap::client_errc::decode_error, "a.error().code == ldap::client_errc::decode_error");
	} else {
		check(ldap::detail::is_valid_utf8(text), "ldap::detail::is_valid_utf8(text)");
		check(!a->oid.empty(), "!a->oid.empty()");
		check(!a->syntax || ldap::detail::is_numericoid(*a->syntax),
		  "!a->syntax || ldap::detail::is_numericoid(*a->syntax)");
	}
	auto c = ldap::parse_object_class(text);
	// Only an attribute type's SYNTAX is checked, and only an object class
	// takes an unparenthesised list.
	const bool unparenthesised_list = !a && text.contains('$') && a.error().context == "schema: expected a keyword";
	check(!a ? !c || a.error().context == "schema: SYNTAX is not a numeric OID" || unparenthesised_list : c.has_value(),
	  "!a ? !c || a.error().context == \"schema: SYNTAX is not a numeric OID\" || unparenthesised_list : "
	  "c.has_value()");
	if (c) {
		for (const auto *list : { &c->sup, &c->must, &c->may }) {
			check(std::ranges::all_of(*list, [](const std::string &o) { return ldap::detail::is_oid(o); }),
			  "every SUP, MUST and MAY entry is an oid");
		}
	}

	if (auto r = ldap::parse_dit_content_rule(text)) {
		for (const auto *list : { &r->aux, &r->must, &r->may, &r->precluded }) {
			check(std::ranges::all_of(*list, [](const std::string &o) { return ldap::detail::is_oid(o); }),
			  "every AUX, MUST, MAY and NOT entry is an oid");
		}
	} else {
		check(r.error().code == ldap::client_errc::decode_error, "r.error().code == ldap::client_errc::decode_error");
		check(!c, "what parses as an object class parses as a DIT content rule");
	}

	const std::pmr::vector<std::pmr::string> values{ std::pmr::string(text) };
	const auto s = ldap::server_schema::parse(values, values);
	if (a) {
		const auto *found = s.find_attribute(a->oid);
		check(found != nullptr, "found != nullptr");
		for (const auto &n : a->names) {
			check(s.find_attribute(n) != nullptr, "s.find_attribute(n) != nullptr");
		}
		(void)s.syntax_of(*found);
		check(s.find_object_class(c->oid) != nullptr, "s.find_object_class(c->oid) != nullptr");
		check(s.skipped() == 0, "s.skipped() == 0");
	} else {
		check(s.skipped() == (c ? 1u : 2u), "s.skipped() == (c ? 1u : 2u)");
		check(s.attribute_count() == 0, "s.attribute_count() == 0");
		if (c) {
			check(s.find_object_class(c->oid) != nullptr, "s.find_object_class(c->oid) != nullptr");
		}
	}
	if (c) {
		// The class declared, a required member per NAME and an optional one for
		// the OID.
		const std::array<const char *, 1> classes{ c->oid.c_str() };
		std::vector<ldap::detail::field_use> fields;
		for (const auto &n : c->names) {
			fields.push_back({ .name = n, .kind = ldap::cardinality::required, .read_only = false });
		}
		fields.push_back({ .name = c->oid, .kind = ldap::cardinality::optional, .read_only = false });
		ldap::schema_report rep;
		ldap::detail::check_class_attributes(s, classes, fields, rep);
		for (const auto &i : rep.issues) {
			check(!i.is_error(), "!i.is_error()");
			if (i.what == ldap::schema_issue::kind::attribute_not_allowed) {
				check(std::ranges::contains(fields, std::string_view(i.name), &ldap::detail::field_use::name),
				  "a not-allowed issue names a member");
				continue;
			}
			const auto named = [&](
								 const std::vector<std::string> &list) { return std::ranges::contains(list, i.name); };
			check(i.what == ldap::schema_issue::kind::unknown_superclass ? named(c->sup) : named(c->must),
			  "a MUST issue names a MUST entry, a superclass issue a SUP entry");
		}
	}
	check_multi(text);
	return 0;
}
