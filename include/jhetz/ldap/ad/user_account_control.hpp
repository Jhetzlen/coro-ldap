// Active Directory's userAccountControl flags (MS-ADTS 2.2.16).
//
//   struct ad_user {
//       ldap::ad::user_account_control uac{};
//   };
//   using enum ldap::ad::user_account_control;
//   if (has(u.uac, account_disable)) ...
//   u.uac |= account_disable;
#pragma once

#include "jhetz/ldap/error.hpp"
#include "jhetz/ldap/mapping.hpp"
#include "jhetz/ldap/schema.hpp"

#include <array>
#include <cstdint>
#include <limits>
#include <string>
#include <string_view>
#include <utility>

namespace jhetz::ldap::ad {

// The bits of userAccountControl, named after MS-ADTS's UF_ constants. A
// value may hold bits not listed here; they are kept both ways. AD computes
// lockout and password_expired in msDS-User-Account-Control-Computed and
// does not store them in userAccountControl.
enum class user_account_control : std::uint32_t {
	none = 0,
	script = 0x0000'0001,
	account_disable = 0x0000'0002,
	homedir_required = 0x0000'0008,
	lockout = 0x0000'0010,
	passwd_notreqd = 0x0000'0020,
	passwd_cant_change = 0x0000'0040,
	encrypted_text_password_allowed = 0x0000'0080,
	temp_duplicate_account = 0x0000'0100,
	normal_account = 0x0000'0200,
	interdomain_trust_account = 0x0000'0800,
	workstation_trust_account = 0x0000'1000,
	server_trust_account = 0x0000'2000,
	dont_expire_passwd = 0x0001'0000,
	mns_logon_account = 0x0002'0000,
	smartcard_required = 0x0004'0000,
	trusted_for_delegation = 0x0008'0000,
	not_delegated = 0x0010'0000,
	use_des_key_only = 0x0020'0000,
	dont_require_preauth = 0x0040'0000,
	password_expired = 0x0080'0000,
	trusted_to_authenticate_for_delegation = 0x0100'0000,
	no_auth_data_required = 0x0200'0000,
	partial_secrets_account = 0x0400'0000,
	use_aes_keys = 0x0800'0000,
};

[[nodiscard]] constexpr auto operator|(user_account_control a, user_account_control b) noexcept -> user_account_control
{
	return user_account_control(std::to_underlying(a) | std::to_underlying(b));
}
[[nodiscard]] constexpr auto operator&(user_account_control a, user_account_control b) noexcept -> user_account_control
{
	return user_account_control(std::to_underlying(a) & std::to_underlying(b));
}
[[nodiscard]] constexpr auto operator^(user_account_control a, user_account_control b) noexcept -> user_account_control
{
	return user_account_control(std::to_underlying(a) ^ std::to_underlying(b));
}
[[nodiscard]] constexpr auto operator~(user_account_control a) noexcept -> user_account_control
{
	return user_account_control(~std::to_underlying(a));
}
constexpr auto operator|=(user_account_control &a, user_account_control b) noexcept -> user_account_control &
{
	return a = a | b;
}
constexpr auto operator&=(user_account_control &a, user_account_control b) noexcept -> user_account_control &
{
	return a = a & b;
}
constexpr auto operator^=(user_account_control &a, user_account_control b) noexcept -> user_account_control &
{
	return a = a ^ b;
}

// True when every bit of `bits` is set in `flags`.
[[nodiscard]] constexpr auto has(user_account_control flags, user_account_control bits) noexcept -> bool
{
	return (flags & bits) == bits;
}

}// namespace jhetz::ldap::ad

namespace jhetz::ldap {

// The INTEGER value, a signed 32-bit number in AD: decodes -2^31 to
// 2^32 - 1 (as the 32 bits), encodes the 32 bits as a signed number.
template<> struct value_traits<ad::user_account_control>
{
	static constexpr std::array syntaxes{ syntax::integer };

	[[nodiscard]] static auto decode(std::string_view raw) -> result<ad::user_account_control>
	{
		auto v = value_traits<std::int64_t>::decode(raw);
		if (!v) {
			return std::unexpected(std::move(v.error()));
		}
		if (std::cmp_less(*v, std::numeric_limits<std::int32_t>::min())
			|| std::cmp_greater(*v, std::numeric_limits<std::uint32_t>::max())) {
			return std::unexpected(detail::conversion_error("userAccountControl out of 32-bit range", raw));
		}
		return ad::user_account_control(static_cast<std::uint32_t>(*v));
	}
	[[nodiscard]] static auto encode(ad::user_account_control v) -> std::string
	{
		return std::to_string(static_cast<std::int32_t>(std::to_underlying(v)));
	}
};

}// namespace jhetz::ldap
