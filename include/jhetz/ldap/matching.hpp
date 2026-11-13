// Matching rules (RFC 4517 section 4.2) with LDAP string preparation
// (LDAPprep, RFC 4518). A value that fails preparation or is not of the
// rule's assertion syntax makes the match Undefined, never FALSE.
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

// TRUE, FALSE or Undefined (RFC 4511 section 4.5.1.7).
enum class match_result : std::uint8_t { false_value, true_value, undefined };

// ---------------------------------------------------------------- LDAPprep

// RFC 4518 section 2.6: the Insignificant Character Handling step.
enum class insignificant_handling : std::uint8_t {
	space,// section 2.6.1: case ignore and case exact rules
	numeric_string,// section 2.6.2: every space removed
	telephone_number,// section 2.6.3: every space and hyphen removed
};

// An attribute or assertion value, or one substring of a substring assertion
// (RFC 4518 section 2.6.1).
enum class prep_input : std::uint8_t { value, initial_substring, any_substring, final_substring };

struct prep_options
{
	// Map step (section 2.2): case fold per RFC 3454 table B.2.
	bool case_fold = false;
	insignificant_handling handling = insignificant_handling::space;
	prep_input input = prep_input::value;
};

// RFC 4518 string preparation (transcode, map, NFKC, prohibit, bidi,
// insignificant character handling) of a UTF-8 string, to UTF-8. Fails with
// string_prep_failed, the context naming the step, never the value.
[[nodiscard]] auto prepare_string(std::string_view value,
  const prep_options &options = {},
  std::pmr::memory_resource *mr = std::pmr::get_default_resource()) -> result<std::pmr::string>;

// ---------------------------------------------------------------- rules

// A substring assertion (RFC 4517 section 3.3.30): `initial*any[0]*...*final`.
struct substring_assertion
{
	std::string_view initial{};
	std::span<const std::string_view> any{};
	std::string_view final{};
};

// Equality rules: TRUE if the prepared values are the same code points.
[[nodiscard]] auto case_ignore_match(std::string_view attribute_value, std::string_view assertion_value)
  -> match_result;
[[nodiscard]] auto case_exact_match(std::string_view attribute_value, std::string_view assertion_value) -> match_result;
[[nodiscard]] auto case_ignore_ia5_match(std::string_view attribute_value, std::string_view assertion_value)
  -> match_result;
[[nodiscard]] auto case_exact_ia5_match(std::string_view attribute_value, std::string_view assertion_value)
  -> match_result;
[[nodiscard]] auto numeric_string_match(std::string_view attribute_value, std::string_view assertion_value)
  -> match_result;
[[nodiscard]] auto telephone_number_match(std::string_view attribute_value, std::string_view assertion_value)
  -> match_result;

// Ordering rules: TRUE if the prepared attribute value is less than the
// prepared assertion value, in code point order.
[[nodiscard]] auto case_ignore_ordering_match(std::string_view attribute_value, std::string_view assertion_value)
  -> match_result;
[[nodiscard]] auto case_exact_ordering_match(std::string_view attribute_value, std::string_view assertion_value)
  -> match_result;
[[nodiscard]] auto numeric_string_ordering_match(std::string_view attribute_value, std::string_view assertion_value)
  -> match_result;

// Substrings rules: the substrings match disjoint portions of the value, in
// order. Linear time.
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

// Rules without string preparation.
[[nodiscard]] auto octet_string_match(std::string_view attribute_value, std::string_view assertion_value)
  -> match_result;
[[nodiscard]] auto octet_string_ordering_match(std::string_view attribute_value, std::string_view assertion_value)
  -> match_result;
[[nodiscard]] auto integer_match(std::string_view attribute_value, std::string_view assertion_value) -> match_result;
[[nodiscard]] auto integer_ordering_match(std::string_view attribute_value, std::string_view assertion_value)
  -> match_result;
[[nodiscard]] auto boolean_match(std::string_view attribute_value, std::string_view assertion_value) -> match_result;

// objectIdentifierMatch (RFC 4517 section 4.2.26); a descriptor is resolved
// through the schema, then RFC 4512 and RFC 4519 names.
[[nodiscard]] auto object_identifier_match(std::string_view attribute_value, std::string_view assertion_value)
  -> match_result;
[[nodiscard]] auto object_identifier_match(std::string_view attribute_value,
  std::string_view assertion_value,
  const server_schema &schema) -> match_result;

// bitStringMatch (RFC 4517 section 4.2.1).
[[nodiscard]] auto bit_string_match(std::string_view attribute_value, std::string_view assertion_value) -> match_result;

// uniqueMemberMatch (RFC 4517 section 4.2.31): `cn=Jane,o=Test#'0101'B`.
[[nodiscard]] auto unique_member_match(std::string_view attribute_value, std::string_view assertion_value)
  -> match_result;
[[nodiscard]] auto unique_member_match(std::string_view attribute_value,
  std::string_view assertion_value,
  const server_schema &schema) -> match_result;

// generalizedTimeMatch and generalizedTimeOrderingMatch (RFC 4517 sections
// 4.2.16, 4.2.17): instants in UTC, compared exactly.
[[nodiscard]] auto generalized_time_match(std::string_view attribute_value, std::string_view assertion_value)
  -> match_result;
[[nodiscard]] auto generalized_time_ordering_match(std::string_view attribute_value, std::string_view assertion_value)
  -> match_result;

// uuidMatch and uuidOrderingMatch (RFC 4530 sections 2.2, 2.3).
[[nodiscard]] auto uuid_match(std::string_view attribute_value, std::string_view assertion_value) -> match_result;
[[nodiscard]] auto uuid_ordering_match(std::string_view attribute_value, std::string_view assertion_value)
  -> match_result;

// caseIgnoreListMatch and caseIgnoreListSubstringsMatch (RFC 4517 sections
// 4.2.9, 4.2.10) on Postal Address values.
[[nodiscard]] auto case_ignore_list_match(std::string_view attribute_value, std::string_view assertion_value)
  -> match_result;
[[nodiscard]] auto case_ignore_list_substrings_match(std::string_view attribute_value,
  const substring_assertion &assertion) -> match_result;

// A rule by NAME or OID; an unknown rule gives Undefined.
[[nodiscard]] auto match(std::string_view rule, std::string_view attribute_value, std::string_view assertion_value)
  -> match_result;
[[nodiscard]] auto is_known_matching_rule(std::string_view rule) noexcept -> bool;

// ---------------------------------------------------------------- DNs

namespace detail {
	using equality_rule_lookup = std::string_view (*)(const void *context, const attribute &type);

	// A per-type rule lookup returns text it does not own (string_view, char
	// pointer, or a reference to a string that outlives the call).
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

// distinguishedNameMatch (RFC 4517 section 4.2.15), caseIgnoreMatch for
// every type.
[[nodiscard]] auto distinguished_name_match(const dn &attribute_value, const dn &assertion_value) -> match_result;

// Each type's EQUALITY from the schema, caseIgnoreMatch when it has none.
[[nodiscard]] auto distinguished_name_match(const dn &attribute_value,
  const dn &assertion_value,
  const server_schema &schema) -> match_result;

// `equality_rule(type)` returns the rule's NAME or OID, or empty for
// caseIgnoreMatch; the text stays valid until its next call.
template<detail::equality_rule_lookup_function F>
[[nodiscard]] auto
  distinguished_name_match(const dn &attribute_value, const dn &assertion_value, const F &equality_rule) -> match_result
{
	if constexpr (std::is_function_v<F>) {
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
