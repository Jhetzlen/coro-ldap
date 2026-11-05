// Active Directory's GUID (MS-DTYP 2.3.4): objectGUID, schemaIDGUID.
//
//   struct ad_user {
//       ldap::ad::guid object_guid;
//   };
//   std::string text = u.object_guid.to_string();   // "1b9f2a5e-8f3c-4d1e-..."
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

// A GUID by its MS-DTYP 2.3.4 fields.
//
// Binary form (MS-DTYP 2.3.4.2), the attribute value: 16 octets, Data1,
// Data2 and Data3 little-endian, then Data4's 8 octets as they are. So
// the text's first three groups are the first 8 octets reversed group by
// group: octets 33 22 11 00 55 44 77 66 88 99 AA BB CC DD EE FF are
// 00112233-4455-6677-8899-aabbccddeeff.
// String form (MS-DTYP 2.3.4.3, without the braces): Data1 in 8 hex
// digits, Data2 and Data3 in 4, Data4 in 4 and 12, joined by "-";
// to_string() writes lower case.
struct guid
{
	std::uint32_t data1{};
	std::uint16_t data2{};
	std::uint16_t data3{};
	std::array<std::uint8_t, 8> data4{};

	// The string form, with or without braces ("{...}"), hex digits in
	// either case. Anything else fails with client_errc::conversion_failed.
	[[nodiscard]] static auto parse(std::string_view text) -> result<guid>;
	// Exactly 16 octets; anything else fails with
	// client_errc::conversion_failed.
	[[nodiscard]] static auto from_binary(std::string_view raw) -> result<guid>;

	[[nodiscard]] auto to_string() const -> std::string;
	[[nodiscard]] auto to_binary() const -> std::string;

	friend auto operator==(const guid &, const guid &) -> bool = default;
	friend auto operator<=>(const guid &, const guid &) = default;
};

}// namespace jhetz::ldap::ad

namespace jhetz::ldap {

// The binary form, on Octet String attributes (objectGUID's syntax).
template<> struct value_traits<ad::guid>
{
	static constexpr std::array syntaxes{ syntax::octet_string };

	[[nodiscard]] static auto decode(std::string_view raw) -> result<ad::guid> { return ad::guid::from_binary(raw); }
	[[nodiscard]] static auto encode(const ad::guid &v) -> std::string { return v.to_binary(); }
};

}// namespace jhetz::ldap
