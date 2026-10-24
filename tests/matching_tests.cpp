#include "jhetz/ldap/matching.hpp"
#include "jhetz/ldap/schema.hpp"

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <chrono>
#include <cstddef>
#include <memory_resource>
#include <string>
#include <string_view>
#include <vector>

namespace ldap = jhetz::ldap;
using ldap::match_result;

namespace {

constexpr auto yes = match_result::true_value;
constexpr auto no = match_result::false_value;
constexpr auto undefined = match_result::undefined;

auto prep(std::string_view s, ldap::prep_options o = {}) -> std::string
{
	auto r = ldap::prepare_string(s, o);
	REQUIRE(r.has_value());
	return std::string(*r);
}

auto prep_fails(std::string_view s, ldap::prep_options o = {}) -> bool
{
	auto r = ldap::prepare_string(s, o);
	return !r && r.error().code == ldap::client_errc::string_prep_failed;
}

auto parse(std::string_view text) -> ldap::dn
{
	auto d = ldap::dn::parse(text);
	REQUIRE(d.has_value());
	return *d;
}

constexpr ldap::prep_options fold{ .case_fold = true };

}// namespace

// ---------------------------------------------------------------- RFC 4518 steps

TEST_CASE("prep: RFC 4518 section 2.6.1 examples, with errata 1757 and 1758", "[matching][rfc]")
{
	using enum ldap::prep_input;
	// "foo<SPACE>bar<SPACE><SPACE>" as an attribute value or initial substring.
	CHECK(prep("foo bar  ") == " foo  bar ");
	CHECK(prep("foo bar  ", { .input = initial_substring }) == " foo  bar ");
	// As an any or final substring (erratum 1758: the inner space is doubled too).
	CHECK(prep("foo bar  ", { .input = any_substring }) == "foo  bar ");
	CHECK(prep("foo bar  ", { .input = final_substring }) == "foo  bar ");
	// No non-space character: two SPACEs for a value, one for a substring.
	CHECK(prep("") == "  ");
	CHECK(prep("    ") == "  ");
	CHECK(prep("   ", { .input = any_substring }) == " ");
	// Leading spaces of any/final become one; final always ends with one.
	CHECK(prep("  x", { .input = any_substring }) == " x");
	CHECK(prep("x", { .input = any_substring }) == "x");
	CHECK(prep("x", { .input = final_substring }) == "x ");
	CHECK(prep("x", { .input = initial_substring }) == " x");
	CHECK(prep("  a   b  c ") == " a  b  c ");
	// Initial and final substrings of spaces only are one SPACE.
	CHECK(prep("   ", { .input = initial_substring }) == " ");
	CHECK(prep("   ", { .input = final_substring }) == " ");
}

TEST_CASE("prep: a SPACE followed by a combining mark is not a space", "[matching][rfc]")
{
	// U+0020 U+0301 stays (NFKC does not compose it): an ordinary character.
	CHECK(prep("a \u0301") == " a \u0301 ");
	CHECK(prep("a  \u0301") == " a   \u0301 ");
	CHECK(ldap::case_exact_match("a \u0301", "a  \u0301") == no);
	CHECK(ldap::case_exact_match("a \u0301", "a\u0301") == no);
}

TEST_CASE("prep: map step (RFC 4518 section 2.2)", "[matching][rfc]")
{
	// Mapped to nothing: soft hyphen, CGJ, variation selectors, ZWSP, controls, BOM.
	CHECK(prep("Jo\u00ADhn") == " John ");
	CHECK(prep("a\u034Fb\uFE0Fc\u200Bd\u0001e\u200De\uFEFF") == " abcdee ");
	CHECK(prep(std::string_view("a\0b", 3)) == " ab ");
	// To SPACE: tab, line breaks, NEL, NBSP, ideographic space, line separator.
	CHECK(prep("a\tb\nc\rd\u0085e\u00A0f\u3000g\u2028h") == " a  b  c  d  e  f  g  h ");
	// Case folding (table B.2) only for the case-ignore rules.
	CHECK(prep("Hello WORLD") == " Hello  WORLD ");
	CHECK(prep("Hello WORLD", fold) == " hello  world ");
}

TEST_CASE("prep: case folding beyond ASCII follows table B.2, not a locale", "[matching][rfc]")
{
	// ß folds to "ss".
	CHECK(prep("Stra\u00DFe", fold) == " strasse ");
	CHECK(ldap::case_ignore_match("Stra\u00DFe", "STRASSE") == yes);
	CHECK(ldap::case_exact_match("Stra\u00DFe", "Strasse") == no);
	// Turkish: İ (U+0130) folds to i + U+0307, never to plain i; ı (U+0131)
	// is not folded at all; I folds to i (no Turkish locale rule).
	CHECK(prep("\u0130", fold) == " i\u0307 ");
	CHECK(ldap::case_ignore_match("\u0130", "i\u0307") == yes);
	CHECK(ldap::case_ignore_match("\u0130", "i") == no);
	CHECK(ldap::case_ignore_match("\u0131", "I") == no);
	CHECK(ldap::case_ignore_match("\u0131", "i") == no);
	CHECK(ldap::case_ignore_match("I", "i") == yes);
	// Greek sigma: capital, small and final all fold to σ.
	CHECK(ldap::case_ignore_match("\u03A3", "\u03C3") == yes);
	CHECK(ldap::case_ignore_match("\u03C2", "\u03C3") == yes);
	CHECK(ldap::case_exact_match("\u03C2", "\u03C3") == no);
	// Cyrillic and fullwidth Latin.
	CHECK(ldap::case_ignore_match("\u0416\u0423\u041A", "\u0436\u0443\u043A") == yes);
	CHECK(ldap::case_ignore_match("\uFF21\uFF22\uFF23", "abc") == yes);
}

TEST_CASE("prep: NFKC normalization (RFC 4518 section 2.3)", "[matching][rfc]")
{
	// Ligature ﬁ is "fi"; composed and decomposed é are the same.
	CHECK(prep("\uFB01") == " fi ");
	CHECK(ldap::case_exact_match("\uFB01le", "file") == yes);
	CHECK(ldap::case_exact_match("caf\u00E9", "cafe\u0301") == yes);
	CHECK(ldap::case_ignore_match("CAF\u00C9", "cafe\u0301") == yes);
	CHECK(ldap::case_exact_match("caf\u00E9", "cafe") == no);
	// Roman numeral four (U+2163) is "IV"; superscript two is "2".
	CHECK(ldap::case_exact_match("\u2163", "IV") == yes);
	CHECK(ldap::case_exact_match("x\u00B2", "x2") == yes);
}

TEST_CASE("prep: prohibited and unassigned code points give Undefined", "[matching][rfc]")
{
	// Private use, non-characters, U+FFFD (RFC 4518 section 2.4; ICU's
	// profile lets U+FFFD through, the library refuses it).
	CHECK(prep_fails("a\uE000"));
	CHECK(prep_fails("a\U000F0000"));
	CHECK(prep_fails("a\uFDD0"));
	CHECK(prep_fails("a\uFFFE"));
	CHECK(prep_fails("a\uFFFD"));
	// Unassigned in Unicode 3.2 (the repertoire of RFC 4518): U+0221, an
	// emoji, capital sharp s (Unicode 5.1).
	CHECK(prep_fails("\u0221"));
	CHECK(prep_fails("\U0001F600"));
	CHECK(prep_fails("\u1E9E"));
	CHECK(ldap::case_ignore_match("a\uE000", "a\uE000") == undefined);
	CHECK(ldap::case_exact_match("a", "a\uFFFD") == undefined);
	CHECK(ldap::case_ignore_match("\U0001F600", "x") == undefined);
	// Bidirectional text is not checked (section 2.5).
	CHECK(prep("\u05D0a1") == " \u05D0a1 ");
	// C.7 (U+2FF0) is not prohibited by RFC 4518.
	CHECK(prep("\u2FF0") == " \u2FF0 ");
}

TEST_CASE("prep: ill-formed UTF-8 gives Undefined", "[matching][rfc]")
{
	const auto bad = std::to_array<std::string_view>({
	  "\xC3",// truncated
	  "a\xC0\xAF",// overlong
	  "\xED\xA0\x80",// surrogate
	  "\xF4\x90\x80\x80",// above U+10FFFF
	  "\x80x",// stray continuation octet
	  "\xFF",
	});
	for (const auto s : bad) {
		CHECK(prep_fails(s));
		CHECK(ldap::case_ignore_match(s, s) == undefined);
		CHECK(ldap::case_exact_match("x", s) == undefined);
	}
	const auto e = ldap::prepare_string("\xC3");
	REQUIRE_FALSE(e.has_value());
	CHECK(e.error().code == ldap::cond::invalid_input);
	CHECK(e.error().context.contains("2.1"));
}

TEST_CASE("prep: a value too long for ICU fails as too long, not as an ICU failure", "[matching]")
{
	// NFKC expands U+FDFA 18 times; ICU counts in int32_t. The cap is about
	// 13 MB of input, so 16 MiB is refused up front.
	constexpr std::size_t sixteen_mib = std::size_t{ 16 } << 20U;
	const std::string big(sixteen_mib, 'a');
	const auto r = ldap::prepare_string(big);
	REQUIRE_FALSE(r.has_value());
	CHECK(r.error().code == ldap::client_errc::string_prep_failed);
	CHECK(r.error().context.contains("too long"));
	CHECK(ldap::case_exact_match(big, "a") == undefined);
}

TEST_CASE("prep: the result is allocated from the given resource", "[matching]")
{
	std::array<std::byte, 1024> buffer{};
	std::pmr::monotonic_buffer_resource arena(buffer.data(), buffer.size(), std::pmr::null_memory_resource());
	const auto r = ldap::prepare_string("a_long_enough_value_for_the_heap,_past_SSO", {}, &arena);
	REQUIRE(r.has_value());
	CHECK(r->get_allocator().resource() == &arena);
	CHECK(*r == " a_long_enough_value_for_the_heap,_past_SSO ");
}

// ---------------------------------------------------------------- rules

TEST_CASE("caseIgnoreMatch and caseExactMatch", "[matching]")
{
	CHECK(ldap::case_ignore_match("Jane Doe", "jane doe") == yes);
	CHECK(ldap::case_ignore_match("  Jane   Doe ", "JANE DOE") == yes);
	CHECK(ldap::case_ignore_match("JaneDoe", "jane doe") == no);
	CHECK(ldap::case_exact_match("Jane  Doe ", " Jane Doe") == yes);
	CHECK(ldap::case_exact_match("Jane Doe", "jane doe") == no);
	// Directory String is 1*UTF8 (RFC 4517 section 3.3.6): an empty value is
	// not one. A value of spaces only is, and prepares to two SPACEs (RFC
	// 4518 section 2.6.1), as does one that maps to nothing (a soft hyphen).
	CHECK(ldap::case_ignore_match("", "   ") == undefined);
	CHECK(ldap::case_exact_match("", "") == undefined);
	CHECK(ldap::case_ignore_match("", "a") == undefined);
	CHECK(ldap::case_ignore_match("  ", "   ") == yes);
	CHECK(ldap::case_exact_match("\u00AD", " ") == yes);
	CHECK(ldap::case_ignore_ordering_match("", "a") == undefined);
	CHECK(ldap::case_ignore_substrings_match("", {}) == undefined);
	// IA5 String is *IA5: empty is valid.
	CHECK(ldap::case_exact_ia5_match("", "  ") == yes);
}

TEST_CASE("caseIgnoreIA5Match and caseExactIA5Match take IA5 strings", "[matching]")
{
	CHECK(ldap::case_ignore_ia5_match("Example", "EXAMPLE") == yes);
	CHECK(ldap::case_exact_ia5_match("Example", "EXAMPLE") == no);
	CHECK(ldap::case_exact_ia5_match("a\tb", "a b") == yes);
	CHECK(ldap::case_ignore_ia5_match("caf\u00E9", "caf\u00E9") == undefined);
}

TEST_CASE("numericStringMatch, telephoneNumberMatch", "[matching]")
{
	CHECK(ldap::numeric_string_match("123 456", " 123456 ") == yes);
	CHECK(ldap::numeric_string_match("123", "124") == no);
	CHECK(ldap::numeric_string_match("12a", "12a") == undefined);
	CHECK(ldap::numeric_string_match("", "") == undefined);
	// Numeric String is checked as given (RFC 4517 section 3.3.23, ASCII):
	// fullwidth digits are not digits there, although NFKC would map them.
	CHECK(ldap::numeric_string_match("\uFF11\uFF12\uFF13", "123") == undefined);
	CHECK(ldap::numeric_string_match("1\u00A02", "12") == undefined);// NBSP is not SPACE
	CHECK(ldap::numeric_string_match("   ", " ") == yes);// both "" once prepared
	CHECK(ldap::numeric_string_ordering_match("\uFF11", "2") == undefined);
	const std::array<std::string_view, 1> fullwidth{ "\uFF12" };
	CHECK(ldap::numeric_string_substrings_match("123", { .any = fullwidth }) == undefined);
	CHECK(ldap::numeric_string_substrings_match("123", { .initial = "1 " }) == yes);
	CHECK(ldap::match("numericStringSubstringsMatch", "123", "*a*") == undefined);
	CHECK(ldap::telephone_number_match("", "") == undefined);
	CHECK(ldap::telephone_number_match("+1 555-123-4567", "+15551234567") == yes);
	CHECK(ldap::telephone_number_match("+1 555\u2212123\u20104567", "+1-555-123-4567") == yes);
	CHECK(ldap::telephone_number_match("+1 555 123 4567 ext", "+15551234567EXT") == yes);
	CHECK(ldap::telephone_number_match("+1 555 123 4567", "+1 555 123 4568") == no);
}

TEST_CASE("ordering rules compare prepared code points", "[matching]")
{
	CHECK(ldap::case_ignore_ordering_match("abc", "ABD") == yes);
	CHECK(ldap::case_ignore_ordering_match("ABD", "abc") == no);
	CHECK(ldap::case_ignore_ordering_match("abc", "ABC") == no);
	CHECK(ldap::case_exact_ordering_match("ABC", "abc") == yes);
	CHECK(ldap::case_exact_ordering_match("z", "\u00E9") == yes);// U+007A < U+00E9
	CHECK(ldap::case_exact_ordering_match("a\uE000", "b") == undefined);
	CHECK(ldap::numeric_string_ordering_match("1 2", "13") == yes);
	CHECK(ldap::octet_string_ordering_match("ab", "abc") == yes);
	CHECK(ldap::octet_string_ordering_match("\x80", "\x7F") == no);
}

TEST_CASE("substrings rules: RFC 4518 Appendix B", "[matching][rfc]")
{
	// (CN=foo\20*\20bar) matches "foo<SPACE><SPACE>bar", and so values that
	// differ from it only in insignificant spaces.
	const ldap::substring_assertion a{ .initial = "foo ", .any = {}, .final = " bar" };
	CHECK(ldap::case_ignore_substrings_match("foo  bar", a) == yes);
	CHECK(ldap::case_ignore_substrings_match("foo   bar", a) == yes);
	CHECK(ldap::case_ignore_substrings_match("foo bar", a) == yes);
	CHECK(ldap::case_ignore_substrings_match("foobar", a) == no);
	// (CN=*\20foobar\20*) and (CN=*\20*foobar*\20*) both match "foobar".
	const std::array<std::string_view, 1> one{ " foobar " };
	const std::array<std::string_view, 3> three{ " ", "foobar", " " };
	CHECK(ldap::case_ignore_substrings_match("foobar", { .any = one }) == yes);
	CHECK(ldap::case_ignore_substrings_match("foobar", { .any = three }) == yes);
}

TEST_CASE("substrings rules", "[matching]")
{
	const std::array<std::string_view, 2> parts{ "ne", "o" };
	const ldap::substring_assertion a{ .initial = "JA", .any = parts, .final = "E" };
	CHECK(ldap::case_ignore_substrings_match("Jane Doe", a) == yes);
	CHECK(ldap::case_exact_substrings_match("Jane Doe", a) == no);
	CHECK(ldap::case_exact_substrings_match("JAne DoE", a) == yes);
	CHECK(ldap::case_ignore_substrings_match("Jane", a) == no);// "ne" and "o" would overlap final
	CHECK(ldap::case_ignore_substrings_match("Stra\u00DFe", { .initial = "STRASS" }) == yes);
	CHECK(ldap::case_ignore_substrings_match("anything", {}) == yes);
	CHECK(ldap::case_ignore_substrings_match("a\uE000", {}) == undefined);
	CHECK(ldap::case_ignore_substrings_match("abc", { .initial = "\xC3" }) == undefined);
	CHECK(ldap::case_ignore_ia5_substrings_match("Example", { .final = "PLE" }) == yes);
	CHECK(ldap::numeric_string_substrings_match("555 123 4567", { .initial = "5551", .final = "4567" }) == yes);
	CHECK(ldap::telephone_number_substrings_match("+1 555-123-4567", { .initial = "+1555" }) == yes);
	// The final part cannot reuse characters of the initial one.
	CHECK(ldap::case_exact_substrings_match("aba", { .initial = "ab", .final = "ba" }) == no);
	// Initial and final of spaces only: one SPACE, at the value's start or end.
	CHECK(ldap::case_ignore_substrings_match("foo", { .initial = "   " }) == yes);
	CHECK(ldap::case_ignore_substrings_match("foo", { .initial = "  ", .final = " " }) == yes);
	// An any part's inner run of spaces is two SPACEs (erratum 1757), like
	// the value's.
	const std::array<std::string_view, 1> spaced{ "o   b" };
	const std::array<std::string_view, 1> single{ "o b" };
	const std::array<std::string_view, 1> joined{ "ob" };
	CHECK(ldap::case_ignore_substrings_match("foo bar", { .any = spaced }) == yes);
	CHECK(ldap::case_ignore_substrings_match("foo    bar", { .any = single }) == yes);
	CHECK(ldap::case_ignore_substrings_match("foo bar", { .any = joined }) == no);
}

TEST_CASE("substrings rules: a long any part is found in linear time", "[matching]")
{
	// "a...ab" in "a...a": quadratic for a naive search.
	const std::string value(200'000, 'a');
	std::string part(100'000, 'a');
	part += 'b';
	const std::array<std::string_view, 1> any{ part };
	CHECK(ldap::case_exact_substrings_match(value, { .any = any }) == no);
	const std::array<std::string_view, 1> present{ std::string_view(part).substr(0, part.size() - 1) };
	CHECK(ldap::case_exact_substrings_match(value, { .any = present }) == yes);
	const std::array<std::string_view, 2> two{ "abcabcabcabcabcabd", "xyz" };
	CHECK(ldap::case_exact_substrings_match("abcabcabcabcabcabcabdxyz", { .any = two }) == yes);
	CHECK(ldap::case_exact_substrings_match("abcabcabcabcabcabcabxyz", { .any = two }) == no);
}

TEST_CASE("substrings rules: two long any parts, each at its leftmost place", "[matching]")
{
	// "A b A b A c": "A b" is there twice, and "A b A c" fits only after the
	// first one, so the first part must take its leftmost occurrence.
	const std::string run(50'000, 'a');
	const std::string ab = run + "b";
	const std::string value = ab + ab + run + "c";
	const std::string abac = ab + run + "c";
	const auto start = std::chrono::steady_clock::now();
	const std::array<std::string_view, 2> fits{ ab, abac };
	CHECK(ldap::case_exact_substrings_match(value, { .any = fits }) == yes);
	const std::array<std::string_view, 2> twice{ abac, ab };
	CHECK(ldap::case_exact_substrings_match(value, { .any = twice }) == no);
	const std::array<std::string_view, 3> three{ ab, ab, abac };
	CHECK(ldap::case_exact_substrings_match(value, { .any = three }) == no);
	CHECK(std::chrono::steady_clock::now() - start < std::chrono::seconds(10));
}

TEST_CASE("integerMatch, integerOrderingMatch, booleanMatch, octetStringMatch", "[matching]")
{
	CHECK(ldap::integer_match("1000", "1000") == yes);
	CHECK(ldap::integer_match("-5", "5") == no);
	CHECK(ldap::integer_match("0", "0") == yes);
	CHECK(ldap::integer_match("-0", "0") == undefined);
	CHECK(ldap::integer_match("01000", "1000") == undefined);
	CHECK(ldap::integer_match("", "1") == undefined);
	CHECK(ldap::integer_match("+1", "1") == undefined);
	CHECK(ldap::integer_ordering_match("-10", "-9") == yes);
	CHECK(ldap::integer_ordering_match("-9", "-10") == no);
	CHECK(ldap::integer_ordering_match("-1", "0") == yes);
	CHECK(ldap::integer_ordering_match("99", "100") == yes);
	CHECK(ldap::integer_ordering_match("100", "100") == no);
	CHECK(ldap::integer_ordering_match("123456789012345678901234567890", "123456789012345678901234567891") == yes);
	CHECK(ldap::boolean_match("TRUE", "TRUE") == yes);
	CHECK(ldap::boolean_match("TRUE", "FALSE") == no);
	// ABNF quoted strings are case-insensitive (RFC 4234 section 2.3).
	CHECK(ldap::boolean_match("true", "TRUE") == yes);
	CHECK(ldap::boolean_match("True", "false") == no);
	CHECK(ldap::boolean_match("yes", "TRUE") == undefined);
	CHECK(ldap::octet_string_match("Abc", "Abc") == yes);
	CHECK(ldap::octet_string_match("Abc", "abc") == no);
}

TEST_CASE("match by rule NAME or OID", "[matching]")
{
	CHECK(ldap::match("caseIgnoreMatch", "Jane", "JANE") == yes);
	CHECK(ldap::match("caseignorematch", "Jane", "JANE") == yes);
	CHECK(ldap::match("2.5.13.2", "Jane", "JANE") == yes);
	CHECK(ldap::match("2.5.13.5", "Jane", "JANE") == no);
	CHECK(ldap::match("caseExactMatch", "Jane", "Jane") == yes);
	CHECK(ldap::match("integerMatch", "1", "1") == yes);
	CHECK(ldap::match("caseIgnoreOrderingMatch", "a", "B") == yes);
	CHECK(ldap::match("distinguishedNameMatch", "CN=Jane,DC=Example", "cn=jane,dc=example") == yes);
	CHECK(ldap::match("distinguishedNameMatch", "not a dn", "cn=jane") == undefined);
	CHECK(ldap::match("generalizedTimeMatch", "20240101000000Z", "20240101000000Z") == undefined);
	CHECK(ldap::match("noSuchMatch", "a", "a") == undefined);
	CHECK(ldap::is_known_matching_rule("caseIgnoreMatch"));
	CHECK(ldap::is_known_matching_rule("1.3.6.1.4.1.1466.109.114.2"));
	CHECK_FALSE(ldap::is_known_matching_rule("uniqueMemberMatch"));
	// Substrings rules take the Substring Assertion syntax (RFC 4517 3.3.30).
	CHECK(ldap::match("caseIgnoreSubstringsMatch", "Jane Doe", "ja*d*E") == yes);
	CHECK(ldap::match("caseIgnoreSubstringsMatch", "Jane Doe", "*doe") == yes);
	CHECK(ldap::match("caseIgnoreSubstringsMatch", "Jane Doe", "*") == yes);
	CHECK(ldap::match("2.5.13.7", "a*b\\c", "a\\2A*\\5cc") == yes);
	CHECK(ldap::match("2.5.13.7", "a*b", "a\\2a*") == yes);
	CHECK(ldap::match("caseIgnoreSubstringsMatch", "Jane", "Jane") == undefined);// no ASTERISK
	CHECK(ldap::match("caseIgnoreSubstringsMatch", "Jane", "J**e") == undefined);// zero-length substring
	CHECK(ldap::match("caseIgnoreSubstringsMatch", "Jane", "J\\41*") == undefined);// only \2A and \5C
}

// ---------------------------------------------------------------- DNs

TEST_CASE("distinguishedNameMatch: caseIgnoreMatch by default", "[matching][dn]")
{
	const auto a = parse("CN=Jane  Doe,OU=People,DC=Example,DC=COM");
	const auto b = parse("cn=jane doe,ou=people,dc=example,dc=com");
	CHECK(ldap::distinguished_name_match(a, b) == yes);
	// dn's own equality stays byte-exact.
	CHECK(a != b);
	CHECK(ldap::distinguished_name_match(parse("cn=Stra\u00DFe,dc=de"), parse("CN=STRASSE,DC=DE")) == yes);
	CHECK(ldap::distinguished_name_match(parse("cn=a,dc=x"), parse("cn=b,dc=x")) == no);
	CHECK(ldap::distinguished_name_match(parse("cn=a,dc=x"), parse("cn=a")) == no);
	CHECK(ldap::distinguished_name_match(parse("cn=a,dc=x"), parse("sn=a,dc=x")) == no);
	CHECK(ldap::distinguished_name_match(ldap::dn{}, ldap::dn{}) == yes);
	// Multi-valued RDNs: any order, same number of AVAs.
	CHECK(ldap::distinguished_name_match(parse("cn=A+sn=B,dc=x"), parse("SN=b+cn=a,dc=x")) == yes);
	CHECK(ldap::distinguished_name_match(parse("cn=A+sn=B,dc=x"), parse("cn=a,dc=x")) == no);
	CHECK(ldap::distinguished_name_match(parse("cn=a+cn=b"), parse("cn=a+cn=b")) == undefined);
	CHECK(ldap::distinguished_name_match(parse("cn=a+2.5.4.3=b"), parse("cn=a+sn=b")) == undefined);
}

TEST_CASE("distinguishedNameMatch: names and OIDs without a schema", "[matching][dn][rfc]")
{
	const auto m = [](std::string_view a, std::string_view b) {
		return ldap::distinguished_name_match(parse(a), parse(b));
	};
	// RFC 4519's names and OIDs are one type each.
	CHECK(m("cn=Jane", "2.5.4.3=jane") == yes);
	CHECK(m("cn=Jane", "commonName=jane") == yes);
	CHECK(m("CN=Jane", "COMMONNAME=jane") == yes);
	CHECK(m("sn=Doe", "surname=doe") == yes);
	CHECK(m("uid=jd", "userid=JD") == yes);
	CHECK(m("dc=example", "0.9.2342.19200300.100.1.25=EXAMPLE") == yes);
	CHECK(m("st=x+street=y", "stateOrProvinceName=x+streetAddress=y") == yes);
	// Different resolved types: FALSE.
	CHECK(m("cn=a", "sn=a") == no);
	CHECK(m("2.5.4.3=a", "2.5.4.4=a") == no);
	CHECK(m("cn=a", "1.2.3.4=a") == no);
	CHECK(m("cn=a+sn=b", "cn=a+title=b") == no);
	// A name nothing resolves might be another name of the other type.
	CHECK(m("foo=a", "2.5.4.3=a") == undefined);
	CHECK(m("foo=a", "bar=a") == undefined);
	CHECK(m("foo=a", "FOO=a") == yes);
	CHECK(m("cn=a+foo=b", "cn=a+sn=b") == undefined);
	// Unless something else is FALSE.
	CHECK(m("cn=a+foo=b", "cn=z+sn=b") == no);
	CHECK(m("foo=a,dc=x", "2.5.4.3=a,dc=y") == no);
	// A resolved type left over with no unresolved name on the other side.
	CHECK(m("cn=a+foo=b", "sn=a+foo=b") == no);
}

TEST_CASE("distinguishedNameMatch: a large multi-valued RDN in n log n", "[matching][dn]")
{
	// Pairwise type comparison took about 7 s for 4000 AVAs (ASan build);
	// sorted keys take milliseconds. The bound is loose against a loaded
	// machine but far below the quadratic time (minutes for 10000).
	constexpr int count = 10'000;
	std::string forward = "a0=x";
	std::string backward = "a" + std::to_string(count - 1) + "=X";
	for (int i = 1; i < count; ++i) {
		forward += "+a" + std::to_string(i) + "=x";
		backward += "+a" + std::to_string(count - 1 - i) + "=X";
	}
	const auto a = parse(forward);
	const auto b = parse(backward);
	const auto start = std::chrono::steady_clock::now();
	CHECK(ldap::distinguished_name_match(a, b) == yes);
	CHECK(ldap::distinguished_name_match(a, parse(forward + "+a0=y")) == no);// more AVAs
	CHECK(ldap::distinguished_name_match(parse(forward + "+a5=y"), parse(backward + "+b=y")) == undefined);
	CHECK(std::chrono::steady_clock::now() - start < std::chrono::seconds(10));
}

TEST_CASE("distinguishedNameMatch: Undefined unless some AVA is FALSE", "[matching][dn]")
{
	const auto bad = parse(R"(cn=a\EE\80\80,dc=x)");// U+E000, private use
	CHECK(ldap::distinguished_name_match(bad, parse("cn=a,dc=x")) == undefined);
	CHECK(ldap::distinguished_name_match(bad, parse("cn=a,dc=y")) == no);
	CHECK(ldap::distinguished_name_match(parse("cn=\\C3,dc=x"), parse("cn=\\C3,dc=x")) == undefined);
}

TEST_CASE("distinguishedNameMatch: #hex values are decoded and transcoded", "[matching][dn]")
{
	// UTF8String "Jane", BMPString "Jane", UniversalString "Jé".
	CHECK(ldap::distinguished_name_match(parse("cn=#0C044A616E65"), parse("cn=jane")) == yes);
	CHECK(ldap::distinguished_name_match(parse("cn=#1E08004A0061006E0065"), parse("cn=JANE")) == yes);
	CHECK(ldap::distinguished_name_match(parse("cn=#1C080000004A000000E9"), parse("cn=J\u00E9")) == yes);
	CHECK(ldap::distinguished_name_match(parse("cn=#0C044A616E65"), parse("cn=#13044A414E45")) == yes);
	// TeletexString (transcoding is a local matter), not BER, a surrogate in a BMPString.
	CHECK(ldap::distinguished_name_match(parse("cn=#14044A616E65"), parse("cn=jane")) == undefined);
	CHECK(ldap::distinguished_name_match(parse("cn=#41"), parse("cn=A")) == undefined);
	CHECK(ldap::distinguished_name_match(parse("cn=#1E02D800"), parse("cn=a")) == undefined);
	// An odd-length BMPString, a UniversalString above U+10FFFF.
	CHECK(ldap::distinguished_name_match(parse("cn=#1E03004A00"), parse("cn=J")) == undefined);
	CHECK(ldap::distinguished_name_match(parse("cn=#1C0400110000"), parse("cn=a")) == undefined);
	// Restricted strings are checked against their character sets:
	// NumericString "12 " and "12a", PrintableString "a@", IA5String "a@",
	// VisibleString "a\n".
	CHECK(ldap::distinguished_name_match(parse("cn=#1203313220"), parse("cn=12")) == yes);
	CHECK(ldap::distinguished_name_match(parse("cn=#1203313261"), parse("cn=12a")) == undefined);
	CHECK(ldap::distinguished_name_match(parse("cn=#13026140"), parse("cn=a@")) == undefined);
	CHECK(ldap::distinguished_name_match(parse("cn=#16026140"), parse("cn=a@")) == yes);
	CHECK(ldap::distinguished_name_match(parse("cn=#1A02610A"), parse("cn=a")) == undefined);
	// INTEGER for integerMatch.
	const auto rules = [](const ldap::attribute &) -> std::string_view { return "integerMatch"; };
	CHECK(ldap::distinguished_name_match(parse("uidNumber=#020203E8"), parse("uidNumber=1000"), rules) == yes);
	// Any magnitude: 2^64, -(2^64), 2^128, -1, -128, -129, 255, 0, 10^9.
	const auto integer = [&](std::string_view hex, std::string_view decimal) {
		return ldap::distinguished_name_match(
		  parse("x=" + std::string(hex)), parse("x=" + std::string(decimal)), rules);
	};
	CHECK(integer("#0209010000000000000000", "18446744073709551616") == yes);
	CHECK(integer("#0209FF0000000000000000", "-18446744073709551616") == yes);
	CHECK(integer("#02110100000000000000000000000000000000", "340282366920938463463374607431768211456") == yes);
	CHECK(integer("#0201FF", "-1") == yes);
	CHECK(integer("#020180", "-128") == yes);
	CHECK(integer("#0202FF7F", "-129") == yes);
	CHECK(integer("#020200FF", "255") == yes);
	CHECK(integer("#020100", "0") == yes);
	CHECK(integer("#02043B9ACA00", "1000000000") == yes);
	CHECK(integer("#02043B9ACA00", "999999999") == no);
	// X.690 section 8.3.2: not minimal, or empty.
	CHECK(integer("#02020001", "1") == undefined);
	CHECK(integer("#0202FFFF", "-1") == undefined);
	CHECK(integer("#0200", "0") == undefined);
}

TEST_CASE("distinguishedNameMatch: a #hex INTEGER is decoded up to 4096 octets", "[matching][dn]")
{
	// The decimal conversion is quadratic: 160 KB took 22 s before the cap.
	const auto rules = [](const ldap::attribute &) -> std::string_view { return "integerMatch"; };
	const auto integer = [](std::string_view length, std::size_t octets) {
		std::string hex = "x=#02";
		hex += length;
		hex += "7F";
		for (std::size_t i = 1; i < octets; ++i) {
			hex += "AB";
		}
		return parse(hex);
	};
	const auto start = std::chrono::steady_clock::now();
	const auto largest = integer("821000", 4096);
	CHECK(ldap::distinguished_name_match(largest, largest, rules) == yes);
	CHECK(ldap::distinguished_name_match(largest, parse("x=1"), rules) == no);
	const auto too_long = integer("821001", 4097);
	CHECK(ldap::distinguished_name_match(too_long, too_long, rules) == undefined);
	const auto huge = integer("83100000", std::size_t{ 1 } << 20U);
	CHECK(ldap::distinguished_name_match(huge, parse("x=1"), rules) == undefined);
	CHECK(std::chrono::steady_clock::now() - start < std::chrono::seconds(10));
}

TEST_CASE("distinguishedNameMatch with a per-attribute rule lookup", "[matching][dn]")
{
	const auto rules = [](const ldap::attribute &t) -> std::string_view {
		if (t == ldap::attribute{ "uid" }) {
			return "caseExactMatch";
		}
		if (t == ldap::attribute{ "uidNumber" }) {
			return "2.5.13.14";// integerMatch
		}
		if (t == ldap::attribute{ "createTimestamp" }) {
			return "generalizedTimeMatch";// not implemented
		}
		if (t == ldap::attribute{ "seeAlso" }) {
			return "caseIgnoreOrderingMatch";// not an equality rule
		}
		return {};// caseIgnoreMatch
	};
	CHECK(ldap::distinguished_name_match(parse("uid=JDoe,ou=People"), parse("uid=JDoe,ou=PEOPLE"), rules) == yes);
	CHECK(ldap::distinguished_name_match(parse("uid=JDoe,ou=People"), parse("uid=jdoe,ou=people"), rules) == no);
	CHECK(ldap::distinguished_name_match(parse("uidNumber=1000+cn=X"), parse("cn=x+uidNumber=1000"), rules) == yes);
	CHECK(ldap::distinguished_name_match(parse("uidNumber=01000"), parse("uidNumber=1000"), rules) == undefined);
	CHECK(ldap::distinguished_name_match(parse("createTimestamp=1"), parse("createTimestamp=1"), rules) == undefined);
	CHECK(ldap::distinguished_name_match(parse("seeAlso=a"), parse("seeAlso=a"), rules) == undefined);
}

TEST_CASE("distinguishedNameMatch: both type names are looked up", "[matching][dn]")
{
	// `uid` and `userid` are one type (RFC 4519): a lookup that knows only
	// `uid` gives two rules for the pair, whichever side it is on.
	const auto only_uid = [](const ldap::attribute &t) -> std::string_view {
		return t == ldap::attribute{ "uid" } ? "caseExactMatch" : "";
	};
	const auto m = [](std::string_view a, std::string_view b, const auto &rules) {
		return ldap::distinguished_name_match(parse(a), parse(b), rules);
	};
	CHECK(m("uid=JD", "userid=jd", only_uid) == undefined);
	CHECK(m("userid=JD", "uid=jd", only_uid) == undefined);
	CHECK(m("uid=JD", "0.9.2342.19200300.100.1.1=JD", only_uid) == undefined);
	CHECK(m("uid=JD", "uid=jd", only_uid) == no);
	CHECK(m("userid=JD", "userid=jd", only_uid) == yes);
	// The same rule for both names: compared by it, in either order.
	const auto both = [](const ldap::attribute &t) -> std::string_view {
		return t == ldap::attribute{ "uid" } || t == ldap::attribute{ "userid" } ? "caseExactMatch" : "2.5.13.2";
	};
	CHECK(m("uid=JD", "userid=jd", both) == no);
	CHECK(m("userid=JD", "uid=jd", both) == no);
	CHECK(m("userid=JD", "uid=JD", both) == yes);
	// A rule NAME and its OID are the same rule (caseIgnoreMatch, 2.5.13.2).
	const auto name_or_oid = [](const ldap::attribute &t) -> std::string_view {
		return t == ldap::attribute{ "cn" } ? "caseIgnoreMatch" : "2.5.13.2";
	};
	CHECK(m("cn=JD", "commonName=jd", name_or_oid) == yes);
	CHECK(m("commonName=JD", "cn=jd", name_or_oid) == yes);
}

namespace {

template<class F>
concept dn_lookup_accepted = requires(const ldap::dn &d, const F &f) { ldap::distinguished_name_match(d, d, f); };

const std::string exact_rule = "caseExactMatch";

constexpr auto returns_view = [](const ldap::attribute &) -> std::string_view { return "caseExactMatch"; };
constexpr auto returns_pointer = [](const ldap::attribute &) -> const char * { return nullptr; };
const auto returns_reference = [](const ldap::attribute &) -> const std::string & { return exact_rule; };
// Only checked by the concept, so these are types rather than unused variables.
using returns_string = decltype([](const ldap::attribute &) -> std::string { return "caseExactMatch"; });
using returns_pmr_string = decltype([](const ldap::attribute &) -> std::pmr::string { return "caseExactMatch"; });
using returns_rvalue_reference = decltype([](const ldap::attribute &) -> const std::string && {
	return static_cast<const std::string &&>(exact_rule);
});
const auto returns_mutable_pointer = [](const ldap::attribute &) -> char * { return nullptr; };
// The capture keeps the lambda from converting to a function pointer, which a const object could still call.
using mutable_lambda = decltype([n = 0](const ldap::attribute &) mutable -> std::string_view {
	++n;
	return n == 1 ? "caseExactMatch" : "caseIgnoreMatch";
});

struct non_const_lookup
{
	auto operator()(const ldap::attribute &) -> std::string_view { return {}; }
};

auto exact_everywhere(const ldap::attribute &) -> std::string_view { return "caseExactMatch"; }

}// namespace

TEST_CASE("distinguishedNameMatch: the rule lookup must not return owned text", "[matching][dn]")
{
	// A std::string returned by value is gone before the rule's name is read.
	static_assert(dn_lookup_accepted<decltype(returns_view)>);
	static_assert(dn_lookup_accepted<decltype(returns_pointer)>);
	static_assert(dn_lookup_accepted<decltype(returns_reference)>);
	static_assert(!dn_lookup_accepted<returns_string>);
	static_assert(!dn_lookup_accepted<returns_pmr_string>);
	static_assert(!dn_lookup_accepted<returns_rvalue_reference>);
	static_assert(dn_lookup_accepted<decltype(returns_mutable_pointer)>);
	// It is called through a const reference.
	static_assert(!dn_lookup_accepted<mutable_lambda>);
	static_assert(!dn_lookup_accepted<non_const_lookup>);
	CHECK(ldap::distinguished_name_match(parse("uid=Jane"), parse("uid=jane"), returns_view) == no);
	CHECK(ldap::distinguished_name_match(parse("uid=Jane"), parse("uid=jane"), returns_reference) == no);
	// A plain function, or a pointer to one.
	CHECK(ldap::distinguished_name_match(parse("uid=Jane"), parse("uid=jane"), exact_everywhere) == no);
	CHECK(ldap::distinguished_name_match(parse("uid=Jane"), parse("uid=Jane"), &exact_everywhere) == yes);
	// A null const char * is caseIgnoreMatch.
	CHECK(ldap::distinguished_name_match(parse("uid=Jane"), parse("uid=jane"), returns_pointer) == yes);
	CHECK(ldap::distinguished_name_match(parse("uid=Jane"), parse("uid=jane"), returns_mutable_pointer) == yes);
}

TEST_CASE("distinguishedNameMatch: DN-valued AVAs use the outer rules", "[matching][dn]")
{
	const auto rules = [](const ldap::attribute &t) -> std::string_view {
		if (t == ldap::attribute{ "member" }) {
			return "distinguishedNameMatch";
		}
		return t == ldap::attribute{ "uid" } ? "caseExactMatch" : "";
	};
	const auto a = parse(R"(member=uid\=Jane\,dc\=x)");
	CHECK(ldap::distinguished_name_match(a, parse(R"(member=UID\=Jane\,DC\=X)"), rules) == yes);
	CHECK(ldap::distinguished_name_match(a, parse(R"(member=uid\=jane\,dc\=x)"), rules) == no);
	CHECK(ldap::distinguished_name_match(a, parse(R"(member=uid\=jane\,dc\=x)")) == yes);// caseIgnoreMatch
	// Nesting is bounded: "member=member=...=uid=x" (an unescaped = in a
	// value).
	const auto nested = [](int depth) {
		std::string text;
		for (int i = 0; i < depth; ++i) {
			text += "member=";
		}
		return parse(text + "uid=x");
	};
	CHECK(ldap::distinguished_name_match(nested(5), nested(5), rules) == yes);
	CHECK(ldap::distinguished_name_match(nested(5), nested(6), rules) == no);
	CHECK(ldap::distinguished_name_match(nested(100), nested(100), rules) == undefined);
}

namespace {

const std::pmr::vector<std::pmr::string> schema_types{
	// NOLINTNEXTLINE(bugprone-suspicious-missing-comma): one definition, wrapped at the column limit
	"( 2.5.4.41 NAME 'name' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX "
	"1.3.6.1.4.1.1466.115.121.1.15{32768} )",
	"( 2.5.4.3 NAME ( 'cn' 'commonName' ) SUP name )",
	"( 0.9.2342.19200300.100.1.1 NAME ( 'uid' 'userid' ) EQUALITY caseIgnoreMatch SYNTAX "
	"1.3.6.1.4.1.1466.115.121.1.15{256} )",
	"( 0.9.2342.19200300.100.1.25 NAME ( 'dc' 'domainComponent' ) EQUALITY caseIgnoreIA5Match SYNTAX "
	"1.3.6.1.4.1.1466.115.121.1.26 SINGLE-VALUE )",
	"( 1.3.6.1.1.1.1.0 NAME 'uidNumber' EQUALITY integerMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 )",
	"( 1.3.6.1.4.1.99999.1 NAME 'exactCode' EQUALITY caseExactMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
	"( 1.3.6.1.4.1.99999.2 NAME 'subCode' SUP exactCode )",
	"( 1.3.6.1.4.1.99999.3 NAME 'noRule' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
};

}// namespace

TEST_CASE("distinguishedNameMatch driven by the server schema", "[matching][dn][schema]")
{
	const auto s = ldap::server_schema::parse(schema_types, {});
	REQUIRE(s.skipped() == 0);
	const auto m = [&s](std::string_view a, std::string_view b) {
		return ldap::distinguished_name_match(parse(a), parse(b), s);
	};
	// cn inherits caseIgnoreMatch from name; its names and OID are one type.
	CHECK(m("cn=Jane Doe,dc=Example", "commonName=jane doe,dc=EXAMPLE") == yes);
	CHECK(m("2.5.4.3=Jane", "CN=JANE") == yes);
	CHECK(m("cn=Jane", "name=Jane") == no);// a subtype is not the same type
	CHECK(m("exactCode=AB", "exactCode=ab") == no);
	CHECK(m("subCode=AB", "subCode=ab") == no);// inherited caseExactMatch
	CHECK(m("subCode=AB", "subCode=AB") == yes);
	CHECK(m("uidNumber=1000", "uidNumber=1000") == yes);
	CHECK(m("uidNumber=1000", "uidNumber=x") == undefined);
	CHECK(m("dc=caf\u00E9", "dc=caf\u00E9") == undefined);// IA5 String
	// No EQUALITY, or a type the schema does not define: caseIgnoreMatch.
	CHECK(m("noRule=A", "noRule=a") == yes);
	CHECK(m("unknownType=A", "unknownType=a") == yes);
	// Names and OIDs: the schema's definitions, then RFC 4519's names.
	CHECK(m("exactCode=AB", "1.3.6.1.4.1.99999.1=AB") == yes);
	CHECK(m("1.3.6.1.4.1.99999.1=AB", "exactCode=ab") == no);
	CHECK(m("surname=Doe", "2.5.4.4=doe") == yes);// sn is not in this schema
	CHECK(m("unknownType=a", "2.5.4.3=a") == undefined);
	CHECK(m("unknownType=a", "otherType=a") == undefined);
	CHECK(m("cn=a", "1.2.3.4=a") == no);
}

TEST_CASE("distinguishedNameMatch: a schema that lists uid but not userid", "[matching][dn][schema]")
{
	// userid is uid's RFC 4519 name: the same type, so uid's rule.
	const std::pmr::vector<std::pmr::string> types{
		"( 0.9.2342.19200300.100.1.1 NAME 'uid' EQUALITY caseExactMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
	};
	const auto s = ldap::server_schema::parse(types, {});
	REQUIRE(s.skipped() == 0);
	const auto m = [&s](std::string_view a, std::string_view b) {
		return ldap::distinguished_name_match(parse(a), parse(b), s);
	};
	CHECK(m("uid=JD", "userid=jd") == no);
	CHECK(m("userid=JD", "uid=jd") == no);
	CHECK(m("userid=JD", "uid=JD") == yes);
	CHECK(m("USERID=JD", "0.9.2342.19200300.100.1.1=jd") == no);
	CHECK(m("cn=JD", "commonName=jd") == yes);// not in the schema: caseIgnoreMatch
}

TEST_CASE("schema: EQUALITY is parsed and inherited", "[matching][schema]")
{
	const auto s = ldap::server_schema::parse(schema_types, {});
	const auto *cn = s.find_attribute("cn");
	REQUIRE(cn != nullptr);
	CHECK_FALSE(cn->equality.has_value());
	const auto *rule = s.equality_of(*cn);
	REQUIRE(rule != nullptr);
	CHECK(*rule == "caseIgnoreMatch");
	const auto *uid = s.find_attribute("userid");
	REQUIRE(uid != nullptr);
	CHECK(uid->equality == "caseIgnoreMatch");
	const auto *no_rule = s.find_attribute("noRule");
	REQUIRE(no_rule != nullptr);
	CHECK(s.equality_of(*no_rule) == nullptr);
}
