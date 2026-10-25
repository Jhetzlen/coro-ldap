// libFuzzer target for LDAP string preparation (RFC 4518) and the matching
// rules (matching.hpp), which read untrusted attribute values (also driven
// by matching_fuzz_replay). The input is split in two values at an offset
// given by its first byte.
//
// For any input it must not crash, and:
// - prepare_string fails only with string_prep_failed (never ICU's
//   internal_error), and a prepared value prepares to itself (idempotent;
//   one SPACE more at most, for a value starting with a combining mark);
// - a value matches itself under caseIgnoreMatch and caseExactMatch exactly
//   when it prepares and is not empty (Directory String is 1*UTF8), and is
//   Undefined otherwise;
// - the equality rules are symmetric, caseExactMatch TRUE implies
//   caseIgnoreMatch TRUE, and Undefined comes from either value failing;
// - an ordering rule is never TRUE both ways, nor TRUE for equal values;
// - substrings: a value contains its own prefix, suffix and the whole value;
// - a DN that parses never fails to match itself (TRUE or Undefined), also
//   with distinguishedNameMatch for every type (AVA values nested as DNs);
// - distinguishedNameMatch is symmetric, also with a lookup that gives the
//   names of one type different rules.
// - objectIdentifierMatch, uniqueMemberMatch, generalizedTimeMatch,
//   uuidMatch, bitStringMatch and caseIgnoreListMatch are symmetric; their
//   ordering rules are never TRUE both ways nor TRUE for a value against
//   itself or for equal instants; a value never fails to match itself
//   (TRUE or Undefined), and objectIdentifierMatch is TRUE on a value
//   against itself exactly when it is of the OID syntax.
#include "jhetz/ldap/matching.hpp"

#include "check.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

constexpr jhetz::ldap::fuzz::checker check{ "matching_fuzz" };

namespace ldap = jhetz::ldap;
using ldap::match_result;

namespace {

// distinguishedNameMatch for every type: each AVA value is compared as a DN.
auto dn_everywhere(const ldap::attribute &) -> std::string_view { return "distinguishedNameMatch"; }

// A rule per type NAME, different for names of one type (cn, commonName,
// 2.5.4.3; uid, userid): distinguishedNameMatch stays symmetric.
auto by_spelling(const ldap::attribute &t) -> std::string_view
{
	const std::string_view name = t.name();
	if (name == "cn" || name == "uid") {
		return "caseExactMatch";
	}
	if (name == "commonName" || name == "userid") {
		return "integerMatch";
	}
	if (name == "2.5.4.3") {
		return "distinguishedNameMatch";
	}
	return {};
}

auto prepares(std::string_view s, bool fold) -> bool
{
	const ldap::prep_options o{ .case_fold = fold };
	auto p = ldap::prepare_string(s, o);
	if (!p) {
		check(p.error().code == ldap::client_errc::string_prep_failed,
		  "p.error().code == ldap::client_errc::string_prep_failed");
		return false;
	}
	// Idempotent, except that a value starting with a combining mark gets
	// one more SPACE (the SPACE added before the mark is not a space the
	// second time, RFC 4518 section 2.6.1); then it is a fixed point.
	auto again = ldap::prepare_string(*p, o);
	check(again.has_value(), "again.has_value()");
	if (*again != *p) {
		check(std::string_view(*again) == " " + std::string(*p), "*again == \" \" + *p");
		auto third = ldap::prepare_string(*again, o);
		check(third.has_value() && *third == *again, "third.has_value() && *third == *again");
	}
	return true;
}

void self_checks(std::string_view s)
{
	const bool exact_ok = prepares(s, false);
	const bool fold_ok = prepares(s, true);
	check(exact_ok == fold_ok, "exact_ok == fold_ok");
	const auto expected = exact_ok && !s.empty() ? match_result::true_value : match_result::undefined;
	check(ldap::case_exact_match(s, s) == expected, "ldap::case_exact_match(s, s) == expected");
	check(ldap::case_ignore_match(s, s) == expected, "ldap::case_ignore_match(s, s) == expected");
	check(ldap::case_ignore_ordering_match(s, s) != match_result::true_value,
	  "ldap::case_ignore_ordering_match(s, s) != match_result::true_value");
	for (const auto *const rule : { "caseIgnoreSubstringsMatch", "caseExactSubstringsMatch" }) {
		// The value contains its own halves (as initial and final) and itself
		// (as an any part); "*" and "\" are escaped for the assertion syntax.
		std::string escaped;
		for (const char c : s) {
			if (c == '*') {
				escaped += "\\2A";
			} else if (c == '\\') {
				escaped += "\\5C";
			} else {
				escaped += c;
			}
		}
		if (!escaped.empty()) {
			check(ldap::match(rule, s, "*" + escaped + "*") == expected, "match(rule, s, *s*) == expected");
		}
		check(ldap::match(rule, s, "*") == expected, "match(rule, s, *) == expected");
	}
	// TRUE for a numericoid, TRUE or Undefined for a descriptor (Undefined
	// when it names nothing known), Undefined for anything else.
	const match_result oid_self = ldap::object_identifier_match(s, s);
	if (jhetz::ldap::detail::is_numericoid(s)) {
		check(oid_self == match_result::true_value, "object_identifier_match(s, s) TRUE for a numericoid");
	} else if (jhetz::ldap::detail::is_descr(s)) {
		check(oid_self != match_result::false_value, "object_identifier_match(s, s) not FALSE for a descriptor");
	} else {
		check(oid_self == match_result::undefined, "object_identifier_match(s, s) Undefined for a non-OID");
	}
	for (const auto *const rule : { "generalizedTimeMatch", "uuidMatch", "bitStringMatch", "caseIgnoreListMatch" }) {
		check(ldap::match(rule, s, s) != match_result::false_value, "match(rule, s, s) != FALSE");
	}
	for (const auto *const rule : { "generalizedTimeOrderingMatch", "uuidOrderingMatch" }) {
		check(ldap::match(rule, s, s) != match_result::true_value, "ordering(s, s) != TRUE");
	}
	check(ldap::unique_member_match(s, s) != match_result::false_value, "unique_member_match(s, s) != FALSE");
	(void)ldap::match("caseIgnoreListSubstringsMatch", s, "*" + std::string(s.substr(0, s.size() / 2)) + "*");
	if (const auto d = ldap::dn::parse(s)) {
		check(ldap::distinguished_name_match(*d, *d) != match_result::false_value,
		  "distinguished_name_match(*d, *d) != match_result::false_value");
		check(ldap::distinguished_name_match(*d, *d, dn_everywhere) != match_result::false_value,
		  "distinguished_name_match(*d, *d, dn_everywhere) != match_result::false_value");
	}
}

void pair_checks(std::string_view a, std::string_view b)
{
	const auto exact = ldap::case_exact_match(a, b);
	const auto ignore = ldap::case_ignore_match(a, b);
	check(exact == ldap::case_exact_match(b, a), "exact == ldap::case_exact_match(b, a)");
	check(ignore == ldap::case_ignore_match(b, a), "ignore == ldap::case_ignore_match(b, a)");
	check(exact != match_result::true_value || ignore == match_result::true_value,
	  "exact != match_result::true_value || ignore == match_result::true_value");
	const bool defined =
	  !a.empty() && !b.empty() && ldap::prepare_string(a).has_value() && ldap::prepare_string(b).has_value();
	check((exact != match_result::undefined) == defined, "(exact != match_result::undefined) == defined");
	check((ignore != match_result::undefined) == defined, "(ignore != match_result::undefined) == defined");
	const auto lt = ldap::case_ignore_ordering_match(a, b);
	const auto gt = ldap::case_ignore_ordering_match(b, a);
	check(lt != match_result::true_value || gt != match_result::true_value, "not a < b and b < a");
	check(ignore != match_result::true_value || lt == match_result::false_value,
	  "ignore != match_result::true_value || lt == match_result::false_value");
	check(ldap::integer_match(a, b) == ldap::integer_match(b, a), "integer_match symmetric");
	check(ldap::numeric_string_match(a, b) == ldap::numeric_string_match(b, a), "numeric_string_match symmetric");
	check(ldap::telephone_number_match(a, b) == ldap::telephone_number_match(b, a), "telephone_number_match symmetric");
	check(ldap::boolean_match(a, b) == ldap::boolean_match(b, a), "boolean_match symmetric");
	for (const auto *const rule : { "objectIdentifierMatch",
		   "uniqueMemberMatch",
		   "generalizedTimeMatch",
		   "uuidMatch",
		   "bitStringMatch",
		   "caseIgnoreListMatch" }) {
		check(ldap::match(rule, a, b) == ldap::match(rule, b, a), "equality rule symmetric");
	}
	for (const auto *const rule : { "generalizedTimeOrderingMatch", "uuidOrderingMatch" }) {
		const auto before = ldap::match(rule, a, b);
		const auto after = ldap::match(rule, b, a);
		check(before != match_result::true_value || after != match_result::true_value, "not a < b and b < a");
	}
	const auto same_time = ldap::generalized_time_match(a, b);
	check(
	  same_time != match_result::true_value || ldap::generalized_time_ordering_match(a, b) == match_result::false_value,
	  "equal instants are not ordered");
	const std::array<std::string_view, 1> any_list{ b };
	(void)ldap::case_ignore_list_substrings_match(a, { .initial = b, .any = any_list, .final = b });
	const std::array<std::string_view, 1> any{ b };
	(void)ldap::case_ignore_substrings_match(a, { .initial = b, .any = any, .final = b });
	const auto da = ldap::dn::parse(a);
	const auto db = ldap::dn::parse(b);
	if (da && db) {
		check(ldap::distinguished_name_match(*da, *db) == ldap::distinguished_name_match(*db, *da),
		  "distinguished_name_match symmetric");
		check(ldap::distinguished_name_match(*da, *db, dn_everywhere)
				== ldap::distinguished_name_match(*db, *da, dn_everywhere),
		  "distinguished_name_match(dn_everywhere) symmetric");
		check(ldap::distinguished_name_match(*da, *db, by_spelling)
				== ldap::distinguished_name_match(*db, *da, by_spelling),
		  "distinguished_name_match(by_spelling) symmetric");
	}
}

}// namespace

extern "C" auto LLVMFuzzerTestOneInput(const std::uint8_t *data, std::size_t size) -> int
{
	if (size == 0) {
		return 0;
	}
	const std::string_view text(reinterpret_cast<const char *>(data) + 1, size - 1);
	const std::size_t split = data[0] % (text.size() + 1);
	self_checks(text);
	pair_checks(text.substr(0, split), text.substr(split));
	return 0;
}
