// The NTLM messages of MS-NLMP section 2.2 (NEGOTIATE, CHALLENGE,
// AUTHENTICATE, AV_PAIRs), MD4, RC4 and message signatures, for sasl_ntlm.
// Internal, exposed for the tests and the fuzz target. Strings are their
// wire bytes (UTF-16LE).
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

// Signature and MessageType values (MS-NLMP section 2.2.1).
inline constexpr std::string_view ntlmssp_signature{ "NTLMSSP\0", 8 };
inline constexpr std::uint32_t ntlm_negotiate_message_type = 1;
inline constexpr std::uint32_t ntlm_challenge_message_type = 2;
inline constexpr std::uint32_t ntlm_authenticate_message_type = 3;

// AvId (MS-NLMP section 2.2.2.1); unknown values are kept.
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

struct ntlm_av_pair
{
	ntlm_av_id av_id = ntlm_av_id::msv_av_eol;
	std::string value{};
	friend auto operator==(const ntlm_av_pair &, const ntlm_av_pair &) -> bool = default;
};

// VERSION (MS-NLMP section 2.2.2.10).
struct ntlm_version
{
	static constexpr std::uint8_t ntlmssp_revision_w2k3 = 0x0F;
	std::uint8_t product_major_version = 0;
	std::uint8_t product_minor_version = 0;
	std::uint16_t product_build = 0;
	std::uint8_t ntlm_revision_current = ntlmssp_revision_w2k3;
	friend auto operator==(const ntlm_version &, const ntlm_version &) -> bool = default;
};

inline constexpr std::size_t ntlm_key_size = 16;
using ntlm_key = std::array<unsigned char, ntlm_key_size>;

inline constexpr std::size_t ntlm_challenge_size = 8;
using ntlm_challenge = std::array<unsigned char, ntlm_challenge_size>;

// CHALLENGE_MESSAGE (MS-NLMP section 2.2.1.2), as parsed.
struct ntlm_challenge_message
{
	std::string target_name{};
	std::uint32_t negotiate_flags = 0;
	ntlm_challenge server_challenge{};
	std::vector<ntlm_av_pair> target_info{};
	std::optional<ntlm_version> version{};
	friend auto operator==(const ntlm_challenge_message &, const ntlm_challenge_message &) -> bool = default;
};

// AUTHENTICATE_MESSAGE (MS-NLMP section 2.2.1.3).
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

// The MIC's offset in an AUTHENTICATE_MESSAGE with a Version.
inline constexpr std::size_t ntlm_authenticate_mic_offset = 72;
inline constexpr std::size_t ntlm_authenticate_header_size = 88;

// NEGOTIATE_MESSAGE (MS-NLMP section 2.2.1.1), always with a Version.
[[nodiscard]] auto encode_ntlm_negotiate(std::uint32_t negotiate_flags, const ntlm_version &version) -> std::string;

// Parses and bounds-checks a CHALLENGE_MESSAGE; decode_error
// ("CHALLENGE_MESSAGE: ...") otherwise.
[[nodiscard]] auto parse_ntlm_challenge(std::string_view message) -> result<ntlm_challenge_message>;

// The AV_PAIR list as TargetInfo carries it, MsvAvEOL appended.
[[nodiscard]] auto encode_ntlm_av_pairs(std::span<const ntlm_av_pair> pairs) -> std::string;

// MsvAvTimestamp (a FILETIME), nullopt when absent.
[[nodiscard]] auto ntlm_timestamp(std::span<const ntlm_av_pair> pairs) -> std::optional<std::uint64_t>;

// The client's TargetInfo (MS-NLMP section 3.1.5.1.2): the server's pairs,
// MsvAvFlags, MsvAvChannelBindings (nullopt: left out), MsvAvTargetName.
[[nodiscard]] auto ntlm_client_target_info(std::span<const ntlm_av_pair> server,
  bool mic,
  const std::optional<ntlm_key> &channel_bindings,
  std::string_view target_name) -> std::vector<ntlm_av_pair>;

// Encodes an AUTHENTICATE_MESSAGE; encode_error for a field over 65535
// octets.
[[nodiscard]] auto encode_ntlm_authenticate(const ntlm_authenticate_message &message) -> result<std::string>;

// UNICODE(s) of MS-NLMP: UTF-8 to UTF-16LE, not normalized.
[[nodiscard]] auto ntlm_unicode(std::string_view utf8) -> result<std::string>;

// ntlm_unicode(utf8) into `out` without reallocation, for a secret the
// caller wipes; `out` should start empty with no capacity.
[[nodiscard]] auto ntlm_unicode(std::string_view utf8, std::string &out) -> result<void>;

// UNICODE(Uppercase(s)): the simple uppercase mapping of each BMP code
// point, as Windows does, then UTF-16LE.
[[nodiscard]] auto ntlm_uppercase_unicode(std::string_view utf8) -> result<std::string>;

// MD4 (RFC 1320) into `out`, self-contained; its working memory is zeroed.
void md4(std::span<const std::byte> data, ntlm_key &out) noexcept;

// RC4 (MS-NLMP section 6), self-contained, one state per direction; zeroed
// on destruction.
class ntlm_rc4
{
  public:
	// RC4Init(key): 1 to 256 octets.
	explicit ntlm_rc4(std::span<const unsigned char> key) noexcept;
	~ntlm_rc4();
	ntlm_rc4(const ntlm_rc4 &) = delete;
	ntlm_rc4(ntlm_rc4 &&) = delete;
	auto operator=(const ntlm_rc4 &) -> ntlm_rc4 & = delete;
	auto operator=(ntlm_rc4 &&) -> ntlm_rc4 & = delete;

	// RC4(handle, data): XORs the keystream into `data`, in place.
	void apply(std::span<unsigned char> data) noexcept;
	void apply(std::span<std::byte> data) noexcept;

  private:
	static constexpr std::size_t state_size = 256;
	std::array<unsigned char, state_size> s_{};
	unsigned char i_ = 0;
	unsigned char j_ = 0;
};

// NTLMSSP_MESSAGE_SIGNATURE with extended session security (MS-NLMP section
// 2.2.2.9.2).
inline constexpr std::size_t ntlm_signature_size = 16;
inline constexpr std::uint32_t ntlm_signature_version = 1;
inline constexpr std::size_t ntlm_checksum_size = 8;
// SeqNum's offset: the MAC covers the buffer from here on.
inline constexpr std::size_t ntlm_signature_seq_num_offset = 12;

struct ntlm_message_signature
{
	std::uint32_t version = ntlm_signature_version;
	std::array<unsigned char, ntlm_checksum_size> checksum{};
	std::uint32_t seq_num = 0;
	friend auto operator==(const ntlm_message_signature &, const ntlm_message_signature &) -> bool = default;
};

// Little-endian integers.
void encode_ntlm_signature(const ntlm_message_signature &signature,
  std::span<std::byte, ntlm_signature_size> out) noexcept;

// A protected buffer: the 16-octet signature, then the (sealed) message.
struct ntlm_protected_buffer
{
	ntlm_message_signature signature{};
	std::span<const std::byte> message{};
};

// Splits a protected buffer; decode_error unless at least 16 octets with a
// Version 1 signature.
[[nodiscard]] auto parse_ntlm_protected_buffer(std::span<const std::byte> buffer) -> result<ntlm_protected_buffer>;

}// namespace jhetz::ldap::detail
