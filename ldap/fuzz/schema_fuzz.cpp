// libFuzzer target for the RFC 4512 subschema parser (schema.hpp), which
// reads server text (also driven by schema_fuzz_replay).
//
// For any input it must not crash, and:
// - a rejected definition fails with decode_error;
// - an accepted one has a non-empty OID, and a SYNTAX that is a numeric
//   OID (no '{');
// - the object class grammar is the same, but SYNTAX is not checked;
// - server_schema::parse of the input (as both an attribute type and an
//   object class) finds what parsed by OID and every NAME, and counts
//   what did not as skipped; syntax_of terminates.
#include "jhetz/ldap/schema.hpp"

#define FUZZ_TARGET "schema_fuzz"
#include "check.hpp"

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace ldap = jhetz::ldap;

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *data, std::size_t size)
{
	const std::string_view text(reinterpret_cast<const char *>(data), size);
	auto a = ldap::parse_attribute_type(text);
	if (!a) {
		LDAP_FUZZ_CHECK(a.error().code == ldap::client_errc::decode_error);
	} else {
		LDAP_FUZZ_CHECK(!a->oid.empty());
		LDAP_FUZZ_CHECK(!a->syntax || ldap::detail::is_numericoid(*a->syntax));
	}
	auto c = ldap::parse_object_class(text);
	// Same grammar; only an attribute type's SYNTAX is checked.
	LDAP_FUZZ_CHECK(!a ? !c || a.error().context == "schema: SYNTAX is not a numeric OID" : c.has_value());

	const std::pmr::vector<std::pmr::string> values{ std::pmr::string(text) };
	const auto s = ldap::server_schema::parse(values, values);
	if (a) {
		const auto *found = s.find_attribute(a->oid);
		LDAP_FUZZ_CHECK(found != nullptr);
		for (const auto &n : a->names) LDAP_FUZZ_CHECK(s.find_attribute(n) != nullptr);
		(void)s.syntax_of(*found);
		LDAP_FUZZ_CHECK(s.find_object_class(c->oid) != nullptr);
		LDAP_FUZZ_CHECK(s.skipped() == 0);
	} else {
		LDAP_FUZZ_CHECK(s.skipped() == (c ? 1u : 2u));
		LDAP_FUZZ_CHECK(s.attribute_count() == 0);
		if (c) LDAP_FUZZ_CHECK(s.find_object_class(c->oid) != nullptr);
	}
	return 0;
}
