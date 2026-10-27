// libFuzzer target for the RFC 4512 subschema parser (schema.hpp), which
// reads server text (also driven by schema_fuzz_replay).
//
// For any input it must not crash, and:
// - a rejected definition fails with decode_error;
// - an accepted one is well-formed UTF-8 (RFC 4512 qdstrings), has a
//   non-empty OID, and a SYNTAX that is a numeric OID (the input's noidlen
//   without its "{" 1*DIGIT "}", the only length accepted; a length apart
//   from the OID fails as a keyword);
// - the object class grammar is the same, but SYNTAX is not checked; an
//   accepted object class's SUP, MUST and MAY entries are oids;
// - server_schema::parse of the input (as both an attribute type and an
//   object class) finds what parsed by OID and every NAME, and counts
//   what did not as skipped; syntax_of terminates, and so does the MUST
//   check of validate<T> (a SUP naming the class itself is a cycle) with
//   the class declared and a member for each of its names, whose issues
//   are warnings named by the MUST or SUP entries.
#include "jhetz/ldap/schema.hpp"

#include "check.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

constexpr jhetz::ldap::fuzz::checker check{ "schema_fuzz" };

namespace ldap = jhetz::ldap;

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
	// Same grammar; only an attribute type's SYNTAX is checked.
	check(!a ? !c || a.error().context == "schema: SYNTAX is not a numeric OID" : c.has_value(),
	  "!a ? !c || a.error().context == \"schema: SYNTAX is not a numeric OID\" : c.has_value()");
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
		ldap::detail::check_must(s, classes, fields, rep);
		for (const auto &i : rep.issues) {
			check(!i.is_error(), "!i.is_error()");
			const auto named = [&](
								 const std::vector<std::string> &list) { return std::ranges::contains(list, i.name); };
			check(i.what == ldap::schema_issue::kind::unknown_superclass ? named(c->sup) : named(c->must),
			  "a MUST issue names a MUST entry, a superclass issue a SUP entry");
		}
	}
	return 0;
}
