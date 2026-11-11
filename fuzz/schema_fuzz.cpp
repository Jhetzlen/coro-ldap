// libFuzzer target for the RFC 4512 subschema parser (schema.hpp), which
// reads server text (also driven by schema_fuzz_replay).
//
// For any input it must not crash, and:
// - a rejected definition fails with decode_error;
// - an accepted one is well-formed UTF-8 (RFC 4512 qdstrings), has a
//   non-empty OID, and a SYNTAX that is a numeric OID (the input's noidlen
//   without its "{" 1*DIGIT "}", the only length accepted; a length apart
//   from the OID fails as a keyword);
// - the object class grammar is the same, but SYNTAX is not checked and
//   SUP, MUST and MAY also take an unparenthesised "a$b" list: what parses
//   as an attribute type parses as an object class, and what parses only
//   as an object class failed SYNTAX or has a "$"; an accepted object
//   class's SUP, MUST and MAY entries are oids;
// - server_schema::parse of the input (as both an attribute type and an
//   object class) finds what parsed by OID and every NAME, and counts
//   what did not as skipped; syntax_of terminates, and so does the MUST
//   check of validate<T> (a SUP naming the class itself is a cycle) with
//   the class declared and a member for each of its names, whose issues
//   are warnings named by the MUST or SUP entries;
// - split at its newlines, as several definitions (a schema with SUP
//   chains, cycles and shared MUSTs), the MUST check with every class
//   declared terminates, and its issues are warnings named by a MUST or
//   SUP entry of a class that parsed.
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
	const auto multi = ldap::server_schema::parse(lines, lines);
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
	// Same grammar; only an attribute type's SYNTAX is checked, and only an
	// object class's SUP, MUST and MAY take an unparenthesised list ("a$b"),
	// whose "$" the attribute type finds where a keyword should be.
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
		// The MUST check, the class declared, a required member per NAME
		// (an attribute of the same name, if one parsed) and an optional one
		// for the OID.
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
