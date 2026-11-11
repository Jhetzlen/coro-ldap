// Active Directory's bitwise matching rules (MS-ADTS 3.1.1.3.4.4.1):
// extensible-match filters (RFC 4511 section 4.5.1.7.7) testing the bits of
// an integer attribute such as userAccountControl, groupType, systemFlags
// or searchFlags.
//
//   using enum ldap::ad::user_account_control;
//   auto disabled = ldap::ad::all_bits<&ad_user::uac>(account_disable);
//       // (userAccountControl:1.2.840.113556.1.4.803:=2)
//   auto security = ldap::ad::all_bits(ldap::filters::attr("groupType"), std::uint32_t{ 0x8000'0000 });
//       // (groupType:1.2.840.113556.1.4.803:=2147483648)
#pragma once

#include "jhetz/ldap/ad/user_account_control.hpp"
#include "jhetz/ldap/filter.hpp"
#include "jhetz/ldap/mapping.hpp"

#include <concepts>
#include <string>
#include <type_traits>

namespace jhetz::ldap::ad {

// LDAP_MATCHING_RULE_BIT_AND: every bit of the assertion value is set.
inline constexpr const char *matching_rule_bit_and = "1.2.840.113556.1.4.803";
// LDAP_MATCHING_RULE_BIT_OR: at least one bit of the assertion value is set.
inline constexpr const char *matching_rule_bit_or = "1.2.840.113556.1.4.804";

// A value the bitwise rules take: user_account_control, or an integer.
template<class E>
concept bitmask_value =
  std::same_as<E, user_account_control> || (std::integral<E> && !std::same_as<E, bool> && !ldap::detail::char_like<E>);

namespace detail {
	template<auto Ptr> using element_of = std::remove_cvref_t<decltype(ldap::detail::field_of<Ptr>())>::element;

	// (a:rule:=bits), the value as its value_traits write it.
	template<bitmask_value E> auto bit_filter(const ldap::filters::attr &a, const char *rule, E bits) -> filter
	{
		return a.matches(rule, std::string(value_traits<E>::encode(bits)));
	}
}// namespace detail

// (a:1.2.840.113556.1.4.803:=bits): every bit of `bits` set. The value is
// written as the type's value_traits write it: AD's signed 32-bit decimal
// for user_account_control, an integer's own decimal value.
template<bitmask_value E> [[nodiscard]] auto all_bits(const ldap::filters::attr &a, E bits) -> filter
{
	return detail::bit_filter(a, matching_rule_bit_and, bits);
}
// (a:1.2.840.113556.1.4.804:=bits): at least one bit of `bits` set.
template<bitmask_value E> [[nodiscard]] auto any_bits(const ldap::filters::attr &a, E bits) -> filter
{
	return detail::bit_filter(a, matching_rule_bit_or, bits);
}

// As above, on a described member (mapping.hpp) of user_account_control or
// integer type: ad::all_bits<&ad_user::uac>(account_disable).
template<auto Ptr> [[nodiscard]] auto all_bits(const detail::element_of<Ptr> &bits) -> filter
{
	static_assert(bitmask_value<detail::element_of<Ptr>>,
	  "ldap::ad::all_bits: the member must be a user_account_control or an integer");
	return all_bits(ldap::filters::attr(ldap::detail::field_of<Ptr>().name), bits);
}
template<auto Ptr> [[nodiscard]] auto any_bits(const detail::element_of<Ptr> &bits) -> filter
{
	static_assert(bitmask_value<detail::element_of<Ptr>>,
	  "ldap::ad::any_bits: the member must be a user_account_control or an integer");
	return any_bits(ldap::filters::attr(ldap::detail::field_of<Ptr>().name), bits);
}

}// namespace jhetz::ldap::ad
