// Active Directory's GUID (MS-DTYP 2.3.4): objectGUID, schemaIDGUID.
#pragma once

#include "jhetz/ldap/error.hpp"
#include "jhetz/ldap/mapping.hpp"
#include "jhetz/ldap/schema.hpp"

#include <array>
#include <compare>
#include <cstdint>
#include <string>
#include <string_view>

namespace jhetz::ldap::ad {

// A GUID by its MS-DTYP 2.3.4 fields. Binary form (2.3.4.2): Data1, Data2,
// Data3 little-endian, then Data4; to_string() writes lower case.
struct guid
{
	std::uint32_t data1{};
	std::uint16_t data2{};
	std::uint16_t data3{};
	std::array<std::uint8_t, 8> data4{};

	// With or without braces, either case; else conversion_failed.
	[[nodiscard]] static auto parse(std::string_view text) -> result<guid>;
	// Exactly 16 octets; else conversion_failed.
	[[nodiscard]] static auto from_binary(std::string_view raw) -> result<guid>;

	[[nodiscard]] auto to_string() const -> std::string;
	[[nodiscard]] auto to_binary() const -> std::string;

	friend auto operator==(const guid &, const guid &) -> bool = default;
	friend auto operator<=>(const guid &, const guid &) = default;
};

}// namespace jhetz::ldap::ad

namespace jhetz::ldap {

// The binary form, on Octet String attributes.
template<> struct value_traits<ad::guid>
{
	static constexpr std::array syntaxes{ syntax::octet_string };

	[[nodiscard]] static auto decode(std::string_view raw) -> result<ad::guid> { return ad::guid::from_binary(raw); }
	[[nodiscard]] static auto encode(const ad::guid &v) -> std::string { return v.to_binary(); }
};

}// namespace jhetz::ldap
