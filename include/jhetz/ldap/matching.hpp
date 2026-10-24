// Matching rules (RFC 4517 section 4.2) with LDAP string preparation
// (LDAPprep, RFC 4518), DESIGN.md section 1.
//
//   ldap::case_ignore_match("Strau\u00DF  Johann", "STRAUSS johann")   // true_value
//   ldap::match("caseExactMatch", "Jane", "jane")                      // false_value
//   ldap::distinguished_name_match(ldap::dn{"CN=Jane Doe,DC=Example"},
//     ldap::dn{"cn=jane  doe,dc=example"})                             // true_value
//
// dn's operator== stays byte-exact after unescaping; these functions are the
// explicit, server-like comparison. Every matching rule evaluates to
// TRUE, FALSE or Undefined (RFC 4511 section 4.5.1.7, RFC 4517 section 4.1):
// a value that fails preparation (ill-formed UTF-8, a prohibited or
// unassigned code point, RFC 4518 section 2) or that is not of the rule's
// assertion syntax makes the match Undefined, never FALSE.
//
// Values are UTF-8 (the LDAP-specific encoding of Directory String, RFC 4517
// section 3.3.6). The character repertoire is Unicode 3.2, as RFC 4518
// section 2 requires: code points assigned later are unassigned there, so a
// value holding one (an emoji, U+1E9E) makes the match Undefined, as it does
// on servers that follow RFC 4518.
#pragma once

#include "jhetz/ldap/attribute.hpp"
#include "jhetz/ldap/dn.hpp"
#include "jhetz/ldap/error.hpp"

#include <concepts>
#include <cstdint>
#include <functional>
#include <memory>
#include <memory_resource>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>

namespace jhetz::ldap {

class server_schema;

// The result of a matching rule: TRUE, FALSE or Undefined (RFC 4511 section
// 4.5.1.7). Not a bool on purpose: Undefined is neither, and a filter's NOT
// of Undefined is Undefined.
enum class match_result : std::uint8_t { false_value, true_value, undefined };

// ---------------------------------------------------------------- LDAPprep

// RFC 4518 section 2.6: the Insignificant Character Handling step, which the
// matching rule chooses.
enum class insignificant_handling : std::uint8_t {
	space,// section 2.6.1: case ignore and case exact rules
	numeric_string,// section 2.6.2: every space removed
	telephone_number,// section 2.6.3: every space and hyphen removed
};

// What is being prepared (RFC 4518 section 2.6.1 treats them differently): an
// attribute value or a non-substring assertion value, or one substring of a
// substring assertion.
enum class prep_input : std::uint8_t { value, initial_substring, any_substring, final_substring };

struct prep_options
{
	// Map step (section 2.2): case fold per RFC 3454 table B.2 (case ignore
	// rules, telephoneNumber), or not (case exact rules, numericString).
	bool case_fold = false;
	insignificant_handling handling = insignificant_handling::space;
	prep_input input = prep_input::value;
};

// RFC 4518 string preparation of a UTF-8 string, the result in UTF-8:
//   2.1 Transcode: the UTF-8 is decoded; ill-formed UTF-8 fails.
//   2.2 Map: soft hyphens, joiners, variation selectors, controls and other
//       format characters to nothing; tabs, line breaks and every other
//       separator to SPACE; with case_fold, table B.2 case folding (so U+00DF
//       becomes "ss" and U+0130 becomes "i" + U+0307, whatever the locale).
//   2.3 Normalize: NFKC (U+FB01 is "fi", "e" + U+0301 is U+00E9).
//   2.4 Prohibit: code points unassigned in Unicode 3.2, private use,
//       non-characters, surrogates, display-changing or deprecated
//       characters (table C.8) and U+FFFD fail.
//   2.5 Check bidi: nothing (bidirectional characters are ignored).
//   2.6 Insignificant Character Handling, per `options`: for space handling
//       (2.6.1), a value with no non-space character becomes exactly two
//       SPACEs, otherwise it starts and ends with exactly one SPACE and each
//       inner run of spaces is exactly two ("foo bar  " becomes
//       " foo  bar "); substrings follow 2.6.1 as amended by errata 1757 and
//       1758. A SPACE followed by a combining mark (RFC 4518 Appendix A) is
//       not a space (so preparing a prepared value that starts with a
//       combining mark adds a SPACE: " " + mark is no longer a space).
// Fails with client_errc::string_prep_failed (the context names the step)
// for input that cannot be prepared or is too long to (over about 13 MB:
// ICU counts in int32_t and NFKC can expand a code point 18 times), and with
// client_errc::internal_error if ICU itself fails. The context never quotes
// the value.
[[nodiscard]] auto prepare_string(std::string_view value,
  const prep_options &options = {},
  std::pmr::memory_resource *mr = std::pmr::get_default_resource()) -> result<std::pmr::string>;

// ---------------------------------------------------------------- rules

// A substring assertion (RFC 4511 SubstringFilter, RFC 4517 section 3.3.30):
// `initial*any[0]*...*final`. An empty initial or final is absent; empty
// `any` parts are skipped (an LDAP substring is never empty).
struct substring_assertion
{
	std::string_view initial{};
	std::span<const std::string_view> any{};
	std::string_view final{};
};

// Equality rules: TRUE if the prepared values are the same code points.
// caseIgnoreMatch (2.5.13.2) and caseExactMatch (2.5.13.5) take Directory
// String values. The IA5 rules take IA5 String values (RFC 4517 section
// 3.3.15: octets 0x00-0x7F); any other octet makes them Undefined.
[[nodiscard]] auto case_ignore_match(std::string_view attribute_value, std::string_view assertion_value)
  -> match_result;
[[nodiscard]] auto case_exact_match(std::string_view attribute_value, std::string_view assertion_value) -> match_result;
[[nodiscard]] auto case_ignore_ia5_match(std::string_view attribute_value, std::string_view assertion_value)
  -> match_result;
[[nodiscard]] auto case_exact_ia5_match(std::string_view attribute_value, std::string_view assertion_value)
  -> match_result;
// caseIgnoreMatch and caseExactMatch (and their ordering and substrings
// rules) take Directory String values, 1*UTF8: an empty value is Undefined,
// while a value of spaces only is valid (it prepares to two SPACEs).
// numericStringMatch (2.5.13.8): spaces ignored; Undefined unless each value
// is a Numeric String as given (ASCII digits and spaces, not empty: RFC 4517
// section 3.3.23, so a fullwidth digit is not one).
[[nodiscard]] auto numeric_string_match(std::string_view attribute_value, std::string_view assertion_value)
  -> match_result;
// telephoneNumberMatch (2.5.13.20): case ignored, spaces and hyphens ignored;
// an empty value is Undefined.
[[nodiscard]] auto telephone_number_match(std::string_view attribute_value, std::string_view assertion_value)
  -> match_result;

// Ordering rules: TRUE if the prepared attribute value comes before the
// prepared assertion value in code point order ("less than").
[[nodiscard]] auto case_ignore_ordering_match(std::string_view attribute_value, std::string_view assertion_value)
  -> match_result;
[[nodiscard]] auto case_exact_ordering_match(std::string_view attribute_value, std::string_view assertion_value)
  -> match_result;
[[nodiscard]] auto numeric_string_ordering_match(std::string_view attribute_value, std::string_view assertion_value)
  -> match_result;

// Substrings rules: TRUE if the prepared substrings match disjoint portions
// of the prepared value in order, initial at its start, final at its end.
// An assertion with no substring at all matches any value that prepares.
// Each substring is checked against the rule's syntax as given (a
// numericString substring is ASCII digits and spaces). Linear time.
[[nodiscard]] auto case_ignore_substrings_match(std::string_view attribute_value, const substring_assertion &assertion)
  -> match_result;
[[nodiscard]] auto case_exact_substrings_match(std::string_view attribute_value, const substring_assertion &assertion)
  -> match_result;
[[nodiscard]] auto case_ignore_ia5_substrings_match(std::string_view attribute_value,
  const substring_assertion &assertion) -> match_result;
[[nodiscard]] auto numeric_string_substrings_match(std::string_view attribute_value,
  const substring_assertion &assertion) -> match_result;
[[nodiscard]] auto telephone_number_substrings_match(std::string_view attribute_value,
  const substring_assertion &assertion) -> match_result;

// Rules without string preparation. octetStringMatch (2.5.13.17) and
// octetStringOrderingMatch (2.5.13.18) compare octets; integerMatch
// (2.5.13.14) and integerOrderingMatch (2.5.13.15) take the Integer syntax
// (RFC 4517 section 3.3.16: no leading zero, no "-0", any magnitude);
// booleanMatch (2.5.13.13) takes "TRUE" or "FALSE", in any case (RFC 4517
// section 3.3.3 is ABNF, whose quoted strings are case-insensitive). A
// value not of the syntax makes them Undefined.
[[nodiscard]] auto octet_string_match(std::string_view attribute_value, std::string_view assertion_value)
  -> match_result;
[[nodiscard]] auto octet_string_ordering_match(std::string_view attribute_value, std::string_view assertion_value)
  -> match_result;
[[nodiscard]] auto integer_match(std::string_view attribute_value, std::string_view assertion_value) -> match_result;
[[nodiscard]] auto integer_ordering_match(std::string_view attribute_value, std::string_view assertion_value)
  -> match_result;
[[nodiscard]] auto boolean_match(std::string_view attribute_value, std::string_view assertion_value) -> match_result;

// A rule by NAME (case-insensitive) or OID, as in an attribute type's
// EQUALITY or an extensible match (RFC 4517 section 4.2): every rule above,
// and distinguishedNameMatch (2.5.13.1, values in RFC 4514 form, compared as
// distinguished_name_match(a, b) below). For the substrings rules the
// assertion value is in the Substring Assertion syntax (RFC 4517 section
// 3.3.30: `initial*any*final`, "*" and "\" escaped as \2A and \5C). An
// unknown rule, or one this library does not implement, gives Undefined
// (RFC 4511 section 4.5.1.7: the server would not recognize it either).
[[nodiscard]] auto match(std::string_view rule, std::string_view attribute_value, std::string_view assertion_value)
  -> match_result;
// Whether match() implements `rule` (NAME or OID).
[[nodiscard]] auto is_known_matching_rule(std::string_view rule) noexcept -> bool;

// ---------------------------------------------------------------- DNs

namespace detail {
	using equality_rule_lookup = std::string_view (*)(const void *context, const attribute &type);

	// What a per-type rule lookup may return: text it does not own (a
	// std::string_view, a const char * or char *, or a reference to a string
	// that outlives the call). A std::string returned by value would be
	// destroyed before the rule's name is read.
	template<class R>
	inline constexpr bool is_borrowed_rule_name =
	  std::same_as<std::remove_cv_t<R>, std::string_view> || std::same_as<std::remove_cv_t<R>, const char *>
	  || std::same_as<std::remove_cv_t<R>, char *>
	  || (std::is_lvalue_reference_v<R> && std::convertible_to<R, std::string_view>);

	template<class F>
	concept equality_rule_lookup_function =
	  std::invocable<const F &, const attribute &>
	  && is_borrowed_rule_name<std::invoke_result_t<const F &, const attribute &>>;

	[[nodiscard]] auto distinguished_name_match(const dn &attribute_value,
	  const dn &assertion_value,
	  equality_rule_lookup lookup,
	  const void *context,
	  const server_schema *schema) -> match_result;
}// namespace detail

// distinguishedNameMatch (RFC 4517 section 4.2.15): the same number of RDNs,
// and RDNs by position with the same number of AVAs, each AVA equal to the
// other RDN's AVA of the same type (in any order) by that type's equality
// rule. FALSE if any comparison is FALSE; otherwise Undefined if any is
// Undefined (also for an RDN that has a type twice, or a `#hex` value that
// is not a BER string, OCTET STRING, INTEGER or BOOLEAN, or is a
// TeletexString: RFC 4518 section 2.1 leaves its transcoding a local
// matter); otherwise TRUE. `#hex` values are decoded and transcoded (BER
// BMPString and UniversalString to UTF-8, RFC 4518 section 2.1; INTEGER to
// decimal, up to 4096 content octets: a longer one is Undefined, as the
// conversion is quadratic) before the rule sees them. A value whose rule is
// distinguishedNameMatch is compared as a DN with the same rules, up to a
// small nesting depth (Undefined deeper).
//
// Types: a name (ASCII case-insensitive) or a numeric OID is resolved to its
// definition's OID through the schema (if any), then the names RFC 4519
// gives the user schema (`cn`, `commonName` and `2.5.4.3` are one type, as
// are `sn` and `surname`, `uid` and `userid`, ...). Two resolved types are
// the same type exactly when their OIDs are. A name that cannot be resolved
// might be another name of any type: if the RDNs differ only in such types
// (`foo=x` against `2.5.4.3=x`), the comparison is Undefined, not FALSE.
//
// This overload uses caseIgnoreMatch for every type.
[[nodiscard]] auto distinguished_name_match(const dn &attribute_value, const dn &assertion_value) -> match_result;

// Schema-driven: each type's EQUALITY (inherited from its supertypes, see
// server_schema::equality_of), caseIgnoreMatch for a type the schema does
// not know or that declares none. An RFC 4519 name the schema does not list
// (`userid` when it lists only `uid`) takes the rule of its OID's
// definition. A rule match() does not implement gives
// Undefined. Types are the same when they name the same definition in the
// schema.
[[nodiscard]] auto distinguished_name_match(const dn &attribute_value,
  const dn &assertion_value,
  const server_schema &schema) -> match_result;

// With a per-type rule lookup: `equality_rule(type)` returns the rule's NAME
// or OID for match(), or an empty string (or a null pointer) for
// caseIgnoreMatch. It is called through a const reference (a `mutable`
// lambda or an object with only a non-const operator() does not compile),
// and returns a std::string_view, a const char *, a char * or an lvalue
// reference to a string, never an owning std::string (that does not
// compile); the text must stay valid until the next call of
// `equality_rule`. Both AVAs' types are looked up when their names differ
// (`uid` and `userid`, a name and its OID): two different rules give
// Undefined.
//
//   ldap::distinguished_name_match(a, b, [](const ldap::attribute &t) -> std::string_view {
//       return t == ldap::attribute{"uid"} ? "caseExactMatch" : "";
//   });
template<detail::equality_rule_lookup_function F>
[[nodiscard]] auto
  distinguished_name_match(const dn &attribute_value, const dn &assertion_value, const F &equality_rule) -> match_result
{
	if constexpr (std::is_function_v<F>) {
		// A function: through a function pointer, an object `context` can
		// point to.
		F *const function = &equality_rule;
		return distinguished_name_match(attribute_value, assertion_value, function);
	} else {
		const detail::equality_rule_lookup lookup = [](const void *context, const attribute &type) -> std::string_view {
			const F &f = *static_cast<const F *>(context);
			if constexpr (std::is_pointer_v<std::remove_cvref_t<std::invoke_result_t<const F &, const attribute &>>>) {
				const char *const rule = std::invoke(f, type);
				return rule == nullptr ? std::string_view{} : std::string_view{ rule };
			} else {
				return std::invoke(f, type);
			}
		};
		return detail::distinguished_name_match(
		  attribute_value, assertion_value, lookup, static_cast<const void *>(std::addressof(equality_rule)), nullptr);
	}
}

}// namespace jhetz::ldap
