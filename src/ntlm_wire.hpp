// Internal: the MS-NLMP wire layout, shared with the server side of the
// testing target.
#pragma once

#include "format_util.hpp"
#include "ntlm_message.hpp"

#include "jhetz/ldap/error.hpp"

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

namespace jhetz::ldap::detail::ntlm_wire {

inline constexpr unsigned byte_bits = 8;
inline constexpr std::uint32_t byte_mask = 0xFF;
inline constexpr std::uint32_t max_field_length = 0xFFFF;// a USHORT Len

// The fixed parts (MS-NLMP sections 2.2.1.1 to 2.2.1.3).
inline constexpr std::size_t negotiate_size = 40;// with its Version
inline constexpr std::size_t challenge_fixed_size = 48;// up to TargetInfoFields
inline constexpr std::size_t challenge_version_size = 56;// with the Version
inline constexpr std::size_t version_size = 8;

// Field offsets in the CHALLENGE_MESSAGE.
inline constexpr std::size_t challenge_target_name_fields = 12;
inline constexpr std::size_t challenge_flags = 20;
inline constexpr std::size_t challenge_server_challenge = 24;
inline constexpr std::size_t challenge_target_info_fields = 40;
inline constexpr std::size_t challenge_version = 48;

// Field offsets in the AUTHENTICATE_MESSAGE.
inline constexpr std::size_t auth_lm_fields = 12;
inline constexpr std::size_t auth_nt_fields = 20;
inline constexpr std::size_t auth_domain_fields = 28;
inline constexpr std::size_t auth_user_fields = 36;
inline constexpr std::size_t auth_workstation_fields = 44;
inline constexpr std::size_t auth_session_key_fields = 52;
inline constexpr std::size_t auth_flags = 60;
inline constexpr std::size_t auth_version = 64;

inline constexpr std::size_t message_type_offset = 8;
inline constexpr std::size_t av_header_size = 4;// AvId, AvLen
inline constexpr std::size_t av_flags_size = 4;
inline constexpr std::size_t av_timestamp_size = 8;

// ---------------------------------------------------------------- little-endian integers

inline void put16(std::string &out, std::uint32_t v)
{
	out += static_cast<char>(v & byte_mask);
	out += static_cast<char>((v >> byte_bits) & byte_mask);
}

inline void put32(std::string &out, std::uint32_t v)
{
	put16(out, v & max_field_length);
	put16(out, v >> (2 * byte_bits));
}

// Little-endian integer of `n` octets at s[at] (the caller checked the bounds).
// NOLINTNEXTLINE(bugprone-easily-swappable-parameters): local, offset then size as substr()
inline auto get_le(std::string_view s, std::size_t at, std::size_t n) -> std::uint64_t
{
	std::uint64_t v = 0;
	for (std::size_t i = n; i > 0; --i) {
		v = v << byte_bits | static_cast<unsigned char>(s[at + i - 1]);
	}
	return v;
}
inline auto get16(std::string_view s, std::size_t at) -> std::uint16_t
{
	return static_cast<std::uint16_t>(get_le(s, at, 2));
}
inline auto get32(std::string_view s, std::size_t at) -> std::uint32_t
{
	return static_cast<std::uint32_t>(get_le(s, at, 4));
}

inline void put_version(std::string &out, const ntlm_version &v)
{
	out += static_cast<char>(v.product_major_version);
	out += static_cast<char>(v.product_minor_version);
	put16(out, v.product_build);
	out.append(3, '\0');// Reserved
	out += static_cast<char>(v.ntlm_revision_current);
}

inline auto get_version(std::string_view s, std::size_t at) -> ntlm_version
{
	constexpr std::size_t revision_offset = 7;
	return { .product_major_version = static_cast<std::uint8_t>(s[at]),
		.product_minor_version = static_cast<std::uint8_t>(s[at + 1]),
		.product_build = get16(s, at + 2),
		.ntlm_revision_current = static_cast<std::uint8_t>(s[at + revision_offset]) };
}

// Len, MaxLen, BufferOffset of a payload field (MS-NLMP's *Fields).
// NOLINTNEXTLINE(bugprone-easily-swappable-parameters): local, in the wire order
inline void put_fields(std::string &out, std::size_t length, std::size_t offset)
{
	put16(out, static_cast<std::uint32_t>(length));
	put16(out, static_cast<std::uint32_t>(length));
	put32(out, static_cast<std::uint32_t>(offset));
}

inline auto malformed(std::string_view message, std::string_view what) -> std::unexpected<error>
{
	return fail(client_errc::decode_error, detail::format("{}: {}", message, what));
}

// The payload field described at `fields`, within the message; empty when
// its length is 0.
inline auto payload_field(std::string_view message, std::string_view kind, std::size_t fields, std::string_view name)
  -> result<std::string_view>
{
	const std::uint64_t length = get16(message, fields);
	const std::uint64_t offset = get32(message, fields + 4);
	if (length == 0) {
		return std::string_view{};
	}
	if (offset + length > message.size()) {
		return malformed(kind,
		  detail::format("{} ({} octets at offset {}) runs past the end of the {}-octet message",
			name,
			length,
			offset,
			message.size()));
	}
	return message.substr(static_cast<std::size_t>(offset), static_cast<std::size_t>(length));
}

inline auto check_header(std::string_view message, std::string_view kind, std::size_t fixed, std::uint32_t type)
  -> result<void>
{
	if (message.size() < fixed) {
		return malformed(
		  kind, detail::format("{} octets, shorter than its {}-octet fixed part", message.size(), fixed));
	}
	if (!message.starts_with(ntlmssp_signature)) {
		return malformed(kind, "no \"NTLMSSP\" signature");
	}
	if (const auto t = get32(message, message_type_offset); t != type) {
		return malformed(kind, detail::format("MessageType {}, not {}", t, type));
	}
	return {};
}

}// namespace jhetz::ldap::detail::ntlm_wire
