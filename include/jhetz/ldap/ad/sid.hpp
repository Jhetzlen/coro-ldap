// Active Directory's security identifier (MS-DTYP 2.4.2).
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

namespace jhetz::ldap::ad {

// A SID of revision 1: a 48-bit authority and up to 15 sub-authorities;
// S-1-0 by default. Binary form MS-DTYP 2.4.2.2, string form 2.4.2.1.
class sid
{
  public:
	static constexpr std::size_t max_sub_authorities = 15;
	static constexpr std::uint64_t max_identifier_authority = 0xFFFF'FFFF'FFFF;

	sid() = default;

	// conversion_failed unless a string form ("s-" and hex in either case).
	[[nodiscard]] static auto parse(std::string_view text) -> result<sid>;
	// conversion_failed unless exactly 8 + 4 * SubAuthorityCount octets.
	[[nodiscard]] static auto from_binary(std::string_view raw) -> result<sid>;
	// std::errc::invalid_argument for an authority or count out of range.
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

// The binary form, on Octet String attributes.
template<> struct value_traits<ad::sid>
{
	static constexpr std::array syntaxes{ syntax::octet_string };

	[[nodiscard]] static auto decode(std::string_view raw) -> result<ad::sid> { return ad::sid::from_binary(raw); }
	[[nodiscard]] static auto encode(const ad::sid &v) -> std::string { return v.to_binary(); }
};

}// namespace jhetz::ldap
