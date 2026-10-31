// The messages of the NT LAN Manager authentication protocol (MS-NLMP,
// [MS-NLMP] section 2.2), which sasl_ntlm (sasl_ntlm.hpp) sends and reads:
// NEGOTIATE_MESSAGE, CHALLENGE_MESSAGE, AUTHENTICATE_MESSAGE and the AV_PAIR
// list of TargetInfo, with MD4 (RFC 1320) for NTOWFv2. Part of the codec
// (jhetz::ldap, no dependency but ICU), so the CHALLENGE_MESSAGE parser can
// be fuzzed with the other parsers; the keyed hashes (HMAC-MD5, MD5) need
// OpenSSL and are in sasl_ntlm.hpp. Everything here is internal (detail),
// exposed for the tests and the fuzz target.
//
// Names follow MS-NLMP: the structures' fields come in the order of the
// wire format, the flags are named after NegotiateFlags (section 2.2.2.5)
// and the AvIds after section 2.2.2.1. Integers are little-endian on the
// wire, as MS-NLMP says. Strings (TargetName, DomainName, UserName,
// Workstation, the AV_PAIR names) are kept as their wire bytes: UTF-16LE
// once NTLMSSP_NEGOTIATE_UNICODE is negotiated, the only form this client
// uses (ntlm_unicode() converts UTF-8 to it).
#pragma once

#include "jhetz/ldap/error.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace jhetz::ldap::detail {

// NegotiateFlags (MS-NLMP section 2.2.2.5), letters A to W there.
inline constexpr std::uint32_t ntlmssp_negotiate_unicode = 0x0000'0001;// A
inline constexpr std::uint32_t ntlm_negotiate_oem = 0x0000'0002;// B
inline constexpr std::uint32_t ntlmssp_request_target = 0x0000'0004;// C
inline constexpr std::uint32_t ntlmssp_negotiate_sign = 0x0000'0010;// D
inline constexpr std::uint32_t ntlmssp_negotiate_seal = 0x0000'0020;// E
inline constexpr std::uint32_t ntlmssp_negotiate_datagram = 0x0000'0040;// F
inline constexpr std::uint32_t ntlmssp_negotiate_lm_key = 0x0000'0080;// G
inline constexpr std::uint32_t ntlmssp_negotiate_ntlm = 0x0000'0200;// H
inline constexpr std::uint32_t ntlmssp_anonymous = 0x0000'0800;// J
inline constexpr std::uint32_t ntlmssp_negotiate_oem_domain_supplied = 0x0000'1000;// K
inline constexpr std::uint32_t ntlmssp_negotiate_oem_workstation_supplied = 0x0000'2000;// L
inline constexpr std::uint32_t ntlmssp_negotiate_always_sign = 0x0000'8000;// M
inline constexpr std::uint32_t ntlmssp_target_type_domain = 0x0001'0000;// N
inline constexpr std::uint32_t ntlmssp_target_type_server = 0x0002'0000;// O
inline constexpr std::uint32_t ntlmssp_negotiate_extended_sessionsecurity = 0x0008'0000;// P
inline constexpr std::uint32_t ntlmssp_negotiate_identify = 0x0010'0000;// Q
inline constexpr std::uint32_t ntlmssp_request_non_nt_session_key = 0x0040'0000;// R
inline constexpr std::uint32_t ntlmssp_negotiate_target_info = 0x0080'0000;// S
inline constexpr std::uint32_t ntlmssp_negotiate_version = 0x0200'0000;// T
inline constexpr std::uint32_t ntlmssp_negotiate_128 = 0x2000'0000;// U
inline constexpr std::uint32_t ntlmssp_negotiate_key_exch = 0x4000'0000;// V
inline constexpr std::uint32_t ntlmssp_negotiate_56 = 0x8000'0000;// W

// The Signature of every NTLM message, and the MessageType values (MS-NLMP
// section 2.2.1).
inline constexpr std::string_view ntlmssp_signature{ "NTLMSSP\0", 8 };
inline constexpr std::uint32_t ntlm_negotiate_message_type = 1;
inline constexpr std::uint32_t ntlm_challenge_message_type = 2;
inline constexpr std::uint32_t ntlm_authenticate_message_type = 3;

// AvId (MS-NLMP section 2.2.2.1). Other values may come from a server and
// are kept as they are.
enum class ntlm_av_id : std::uint16_t {
	msv_av_eol = 0x0000,
	msv_av_nb_computer_name = 0x0001,
	msv_av_nb_domain_name = 0x0002,
	msv_av_dns_computer_name = 0x0003,
	msv_av_dns_domain_name = 0x0004,
	msv_av_dns_tree_name = 0x0005,
	msv_av_flags = 0x0006,
	msv_av_timestamp = 0x0007,
	msv_av_single_host = 0x0008,
	msv_av_target_name = 0x0009,
	msv_av_channel_bindings = 0x000A,
};

// MsvAvFlags bits (MS-NLMP section 2.2.2.1).
inline constexpr std::uint32_t msv_av_flags_constrained = 0x0000'0001;
inline constexpr std::uint32_t msv_av_flags_mic = 0x0000'0002;// the AUTHENTICATE_MESSAGE carries a MIC
inline constexpr std::uint32_t msv_av_flags_untrusted_spn = 0x0000'0004;

// One AV_PAIR: AvId, then Value (AvLen is its size).
struct ntlm_av_pair
{
	ntlm_av_id av_id = ntlm_av_id::msv_av_eol;
	std::string value{};
	friend auto operator==(const ntlm_av_pair &, const ntlm_av_pair &) -> bool = default;
};

// VERSION (MS-NLMP section 2.2.2.10): for debugging only. NTLMRevisionCurrent
// is NTLMSSP_REVISION_W2K3 (0x0F).
struct ntlm_version
{
	static constexpr std::uint8_t ntlmssp_revision_w2k3 = 0x0F;
	std::uint8_t product_major_version = 0;
	std::uint8_t product_minor_version = 0;
	std::uint16_t product_build = 0;
	std::uint8_t ntlm_revision_current = ntlmssp_revision_w2k3;
	friend auto operator==(const ntlm_version &, const ntlm_version &) -> bool = default;
};

// The size of the keys and hashes (MD4, MD5, HMAC-MD5 outputs).
inline constexpr std::size_t ntlm_key_size = 16;
using ntlm_key = std::array<unsigned char, ntlm_key_size>;

// The 8-octet challenges (ServerChallenge, ClientChallenge).
inline constexpr std::size_t ntlm_challenge_size = 8;
using ntlm_challenge = std::array<unsigned char, ntlm_challenge_size>;

// CHALLENGE_MESSAGE (MS-NLMP section 2.2.1.2), as parsed: TargetName (its
// bytes), NegotiateFlags, ServerChallenge, TargetInfo (the AV_PAIRs before
// MsvAvEOL) and Version (present exactly when NTLMSSP_NEGOTIATE_VERSION is
// set). Reserved is not kept.
struct ntlm_challenge_message
{
	std::string target_name{};
	std::uint32_t negotiate_flags = 0;
	ntlm_challenge server_challenge{};
	std::vector<ntlm_av_pair> target_info{};
	std::optional<ntlm_version> version{};
	friend auto operator==(const ntlm_challenge_message &, const ntlm_challenge_message &) -> bool = default;
};

// AUTHENTICATE_MESSAGE (MS-NLMP section 2.2.1.3): the payload fields'
// bytes, NegotiateFlags, Version (always sent by this client: the MIC
// follows it) and MIC.
struct ntlm_authenticate_message
{
	std::string lm_challenge_response{};
	std::string nt_challenge_response{};
	std::string domain_name{};
	std::string user_name{};
	std::string workstation{};
	std::string encrypted_random_session_key{};
	std::uint32_t negotiate_flags = 0;
	ntlm_version version{};
	ntlm_key mic{};
	friend auto operator==(const ntlm_authenticate_message &, const ntlm_authenticate_message &) -> bool = default;
};

// Where the MIC is in an AUTHENTICATE_MESSAGE with a Version (MS-NLMP
// section 2.2.1.3), and the size of its fixed part.
inline constexpr std::size_t ntlm_authenticate_mic_offset = 72;
inline constexpr std::size_t ntlm_authenticate_header_size = 88;

// NEGOTIATE_MESSAGE (MS-NLMP section 2.2.1.1) with `negotiate_flags`, no
// DomainName nor Workstation, and `version` (sent whatever the flags say,
// as the layout with a Version has it).
[[nodiscard]] auto encode_ntlm_negotiate(std::uint32_t negotiate_flags, const ntlm_version &version) -> std::string;

// Parses a CHALLENGE_MESSAGE: the "NTLMSSP\0" signature, MessageType 2,
// the fixed part (48 octets, 56 with NTLMSSP_NEGOTIATE_VERSION), every
// payload field's offset and length within the message, the AV_PAIR list
// up to its MsvAvEOL (AvLen 0; MsvAvEOL ends the list, section 2.2.2.1, so
// what follows it in the field is ignored), each pair within the field,
// MsvAvFlags of 4 octets and MsvAvTimestamp of 8, at most once each.
// client_errc::decode_error otherwise, the context saying what is wrong
// ("CHALLENGE_MESSAGE: ...").
[[nodiscard]] auto parse_ntlm_challenge(std::string_view message) -> result<ntlm_challenge_message>;

// Encodes a CHALLENGE_MESSAGE (a test server's side; parse_ntlm_challenge
// reads it back equal when the flags say whether a Version is there):
// TargetName then TargetInfo (MsvAvEOL appended) in the payload, written
// when the list is not empty or NTLMSSP_NEGOTIATE_TARGET_INFO is set.
[[nodiscard]] auto encode_ntlm_challenge(const ntlm_challenge_message &message) -> std::string;

// The AV_PAIR list as TargetInfo carries it, MsvAvEOL appended.
[[nodiscard]] auto encode_ntlm_av_pairs(std::span<const ntlm_av_pair> pairs) -> std::string;

// The MsvAvTimestamp of `pairs` (a FILETIME, 100 ns units since 1601-01-01
// UTC), nullopt when there is none.
[[nodiscard]] auto ntlm_timestamp(std::span<const ntlm_av_pair> pairs) -> std::optional<std::uint64_t>;

// The client's TargetInfo for its NTLMv2_CLIENT_CHALLENGE (MS-NLMP section
// 3.1.5.1.2): the server's AV_PAIRs in their order, without any
// MsvAvChannelBindings or MsvAvTargetName of its own; MsvAvFlags with
// msv_av_flags_mic or'ed in when `mic` (added after the server's pairs when
// it sent none); then MsvAvChannelBindings (`channel_bindings`, Z(16) for
// none); then MsvAvTargetName when `target_name` (UTF-16LE) is not empty.
[[nodiscard]] auto ntlm_client_target_info(std::span<const ntlm_av_pair> server,
  bool mic,
  const ntlm_key &channel_bindings,
  std::string_view target_name) -> std::vector<ntlm_av_pair>;

// Encodes an AUTHENTICATE_MESSAGE: the fixed part with Version and MIC
// (88 octets), then DomainName, UserName, Workstation,
// LmChallengeResponse, NtChallengeResponse and EncryptedRandomSessionKey.
// client_errc::encode_error when a field is longer than 65535 octets.
[[nodiscard]] auto encode_ntlm_authenticate(const ntlm_authenticate_message &message) -> result<std::string>;

// Parses an AUTHENTICATE_MESSAGE with a Version and MIC (a test server's
// side), bounds-checked as parse_ntlm_challenge is.
[[nodiscard]] auto parse_ntlm_authenticate(std::string_view message) -> result<ntlm_authenticate_message>;

// UNICODE(s) of MS-NLMP (section 3.1.5.1.2 and the NTOWFv2 of 3.3.2): the
// UTF-8 text `utf8` as UTF-16LE. client_errc::encode_error for ill-formed
// UTF-8. Every code point is kept as it is (no normalization: Windows
// derives the NT hash from the password's UTF-16 as typed).
[[nodiscard]] auto ntlm_unicode(std::string_view utf8) -> result<std::string>;

// UNICODE(Uppercase(s)), the user name of NTOWFv2: each code point of the
// Basic Multilingual Plane by its simple (one-to-one) uppercase mapping
// (ICU's u_toupper, UnicodeData's Simple_Uppercase_Mapping), then UTF-16LE.
// That is what Windows does (RtlUpcaseUnicodeString maps one UTF-16 unit to
// one: no "SS" for U+00DF, and the units of a surrogate pair stay as they
// are, so code points above U+FFFF are not mapped). Windows' casing table
// follows the Unicode simple mappings of its own Unicode version: a letter
// whose mapping is newer may differ. client_errc::encode_error for
// ill-formed UTF-8.
[[nodiscard]] auto ntlm_uppercase_unicode(std::string_view utf8) -> result<std::string>;

// MD4 (RFC 1320) of `data`, into `out`. NTOWFv2's MD4(UNICODE(Passwd))
// needs it, and OpenSSL 3 has MD4 only in its legacy provider, often not
// available: this one is self-contained, so NTLM works whatever OpenSSL
// loads. Its working memory (the chaining state, each block's message
// words, the padded tail) is zeroed before it returns, and the digest goes
// straight into `out`, so no copy of the NT hash is left behind; values
// the compiler keeps in registers or spill slots are out of its reach.
void md4(std::span<const std::byte> data, ntlm_key &out) noexcept;

}// namespace jhetz::ldap::detail
