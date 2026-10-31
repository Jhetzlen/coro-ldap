// libFuzzer target for the MS-NLMP message parsers (ntlm_message.hpp; also
// driven by ntlm_fuzz_replay): the CHALLENGE_MESSAGE a server sends, and the
// AUTHENTICATE_MESSAGE of a test server.
//
// For any input it must not crash, and:
// - rejected input fails with decode_error and a context naming the
//   message ("CHALLENGE_MESSAGE: ", "AUTHENTICATE_MESSAGE: ");
// - an accepted CHALLENGE_MESSAGE re-encodes to one that parses equal;
// - the client's TargetInfo built from its AV_PAIRs (MsvAvFlags with the
//   MIC bit, MsvAvChannelBindings) parses back as that list, with
//   MsvAvFlags and MsvAvChannelBindings once each and the MIC bit set;
// - an accepted AUTHENTICATE_MESSAGE re-encodes to one that parses equal;
// - a protected buffer of the NTLM security layer (its signature, then the
//   message) is refused only with decode_error ("NTLM protected buffer:
//   "); an accepted one's signature re-encodes to its first 16 octets and
//   the message is the rest;
// - RC4 keyed with the input's first octets, applied twice from a fresh
//   state, gives the input back. (The checksum and sequence number checks
//   need OpenSSL's HMAC-MD5, in jhetz::ldap_net: the unit tests cover them.)
#include "jhetz/ldap/ntlm_message.hpp"

#include "check.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>

constexpr jhetz::ldap::fuzz::checker check{ "ntlm_fuzz" };

namespace ldap = jhetz::ldap;
namespace detail = jhetz::ldap::detail;

extern "C" auto LLVMFuzzerTestOneInput(const std::uint8_t *data, std::size_t size) -> int
{
	const std::string_view bytes(reinterpret_cast<const char *>(data), size);

	const auto raw = std::as_bytes(std::span(data, size));
	auto protected_buffer = detail::parse_ntlm_protected_buffer(raw);
	if (!protected_buffer) {
		check(protected_buffer.error().code == ldap::client_errc::decode_error, "protected: decode_error");
		check(protected_buffer.error().context.starts_with("NTLM protected buffer: "),
		  "context starts with NTLM protected buffer");
	} else {
		std::array<std::byte, detail::ntlm_signature_size> sig{};
		detail::encode_ntlm_signature(protected_buffer->signature, sig);
		check(std::ranges::equal(sig, raw.first(detail::ntlm_signature_size)), "signature re-encodes");
		check(protected_buffer->message.data() == raw.data() + detail::ntlm_signature_size
				&& protected_buffer->message.size() == size - detail::ntlm_signature_size,
		  "message is the rest");
	}
	{
		const auto key = std::span(data, std::min<std::size_t>(size, detail::ntlm_key_size));
		std::string text(bytes);
		const auto text_bytes = std::span(reinterpret_cast<unsigned char *>(text.data()), text.size());
		detail::ntlm_rc4(key).apply(text_bytes);
		detail::ntlm_rc4(key).apply(text_bytes);
		check(text == bytes, "RC4 twice is the identity");
	}

	auto c = detail::parse_ntlm_challenge(bytes);
	if (!c) {
		check(c.error().code == ldap::client_errc::decode_error, "c.error().code == decode_error");
		check(c.error().context.starts_with("CHALLENGE_MESSAGE: "), "context starts with CHALLENGE_MESSAGE");
	} else {
		auto back = detail::parse_ntlm_challenge(detail::encode_ntlm_challenge(*c));
		check(back.has_value(), "back.has_value()");
		check(*back == *c, "*back == *c");

		detail::ntlm_key bindings{};
		bindings[0] = 0x5A;
		auto client = *c;
		client.target_info = detail::ntlm_client_target_info(c->target_info, true, bindings, {});
		client.negotiate_flags |= detail::ntlmssp_negotiate_target_info;
		if (detail::encode_ntlm_av_pairs(client.target_info).size() <= 0xFFFF) {
			auto info = detail::parse_ntlm_challenge(detail::encode_ntlm_challenge(client));
			check(info.has_value(), "info.has_value()");
			check(info->target_info == client.target_info, "info->target_info == client.target_info");
			int flags = 0;
			int channel_bindings = 0;
			for (const auto &p : info->target_info) {
				if (p.av_id == detail::ntlm_av_id::msv_av_flags) {
					++flags;
					check(
					  p.value.size() == 4 && (static_cast<unsigned char>(p.value[0]) & detail::msv_av_flags_mic) != 0,
					  "MsvAvFlags has the MIC bit");
				}
				if (p.av_id == detail::ntlm_av_id::msv_av_channel_bindings) {
					++channel_bindings;
				}
			}
			check(flags == 1 && channel_bindings == 1, "one MsvAvFlags, one MsvAvChannelBindings");
		}
	}

	auto a = detail::parse_ntlm_authenticate(bytes);
	if (!a) {
		check(a.error().code == ldap::client_errc::decode_error, "a.error().code == decode_error");
		check(a.error().context.starts_with("AUTHENTICATE_MESSAGE: "), "context starts with AUTHENTICATE_MESSAGE");
		return 0;
	}
	auto encoded = detail::encode_ntlm_authenticate(*a);
	check(encoded.has_value(), "encoded.has_value()");
	auto again = detail::parse_ntlm_authenticate(*encoded);
	check(again.has_value(), "again.has_value()");
	check(*again == *a, "*again == *a");
	return 0;
}
