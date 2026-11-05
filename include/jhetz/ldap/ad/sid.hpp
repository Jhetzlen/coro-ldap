// Active Directory's security identifier (MS-DTYP 2.4.2): objectSid,
// sIDHistory, tokenGroups.
//
//   struct ad_user {
//       std::string sam_account_name;
//       ldap::ad::sid object_sid;
//   };
//   std::string text = u.object_sid.to_string();   // "S-1-5-21-...-1104"
//   auto admins = ldap::ad::sid::parse("S-1-5-32-544");
#pragma once

#include "jhetz/ldap/error.hpp"
#include "jhetz/ldap/mapping.hpp"
#include "jhetz/ldap/schema.hpp"

#include <array>
#include <compare>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <utility>

namespace jhetz::ldap::ad {

// A SID of revision 1: a 48-bit identifier authority and up to 15
// sub-authorities. The default is S-1-0 (null authority, no
// sub-authority).
//
// Binary form (MS-DTYP 2.4.2.2), the attribute value: Revision (1),
// SubAuthorityCount, IdentifierAuthority in 6 octets big-endian, then each
// SubAuthority in 4 octets little-endian.
// String form (MS-DTYP 2.4.2.1): "S-1-", the authority (decimal below 2^32,
// else "0x" and 12 hex digits), then "-" and each sub-authority in decimal.
class sid
{
  public:
	static constexpr std::size_t max_sub_authorities = 15;
	static constexpr std::uint64_t max_identifier_authority = 0xFFFF'FFFF'FFFF;

	sid() = default;

	// The string form; "s-" and hex digits in either case. Anything else
	// fails with client_errc::conversion_failed.
	[[nodiscard]] static auto parse(std::string_view text) -> result<sid>;
	// The binary form, exactly 8 + 4 * SubAuthorityCount octets; anything
	// else fails with client_errc::conversion_failed.
	[[nodiscard]] static auto from_binary(std::string_view raw) -> result<sid>;
	// std::errc::invalid_argument for an authority above
	// max_identifier_authority or more than max_sub_authorities.
	[[nodiscard]] static auto make(std::uint64_t identifier_authority, std::span<const std::uint32_t> sub_authorities)
	  -> result<sid>;

	[[nodiscard]] auto identifier_authority() const noexcept -> std::uint64_t { return authority_; }
	[[nodiscard]] auto sub_authorities() const noexcept -> std::span<const std::uint32_t>
	{
		return std::span<const std::uint32_t>(sub_).first(count_);
	}

	[[nodiscard]] auto to_string() const -> std::string;
	[[nodiscard]] auto to_binary() const -> std::string;

	friend auto operator==(const sid &, const sid &) -> bool = default;
	friend auto operator<=>(const sid &, const sid &) = default;

  private:
	std::uint64_t authority_ = 0;
	std::array<std::uint32_t, max_sub_authorities> sub_{};
	std::uint8_t count_ = 0;
};

}// namespace jhetz::ldap::ad

namespace jhetz::ldap {

// The binary form, on Octet String attributes (objectSid's syntax).
template<> struct value_traits<ad::sid>
{
	static constexpr std::array syntaxes{ syntax::octet_string };

	[[nodiscard]] static auto decode(std::string_view raw) -> result<ad::sid> { return ad::sid::from_binary(raw); }
	[[nodiscard]] static auto encode(const ad::sid &v) -> std::string { return v.to_binary(); }
};

}// namespace jhetz::ldap
