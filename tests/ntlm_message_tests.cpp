// The MS-NLMP messages (ntlm_message.hpp): MD4, the UTF-16LE forms, the
// CHALLENGE_MESSAGE parser against MS-NLMP section 4.2.4.3 and malformed
// input, and the NEGOTIATE and AUTHENTICATE encoders.
#include "jhetz/ldap/ntlm_message.hpp"
#include "test_util.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace ldap = jhetz::ldap;
namespace detail = jhetz::ldap::detail;
using jhetz::ldap::test::from_hex;
using jhetz::ldap::test::hex;
using Catch::Matchers::ContainsSubstring;

namespace {

auto str(std::string_view hex_text) -> std::string
{
	const auto b = from_hex(hex_text);
	return { reinterpret_cast<const char *>(b.data()), b.size() };
}

auto hex_of(std::string_view s) -> std::string { return hex(std::as_bytes(std::span(s))); }

auto hex_of(const detail::ntlm_key &k) -> std::string { return hex(std::as_bytes(std::span(k))); }

auto md4_of(std::span<const std::byte> data) -> detail::ntlm_key
{
	detail::ntlm_key out{};
	detail::md4(data, out);
	return out;
}

auto md4_hex(std::string_view s) -> std::string { return hex_of(md4_of(std::as_bytes(std::span(s)))); }

// The CHALLENGE_MESSAGE of MS-NLMP section 4.2.4.3 (NTLMv2 authentication).
const std::string spec_challenge = str(
  "4e544c4d53535000 02000000 0c000c00 38000000 33828ae2 0123456789abcdef"
  "0000000000000000 24002400 44000000 060070170000000f"
  "53006500720076006500720002000c0044006f006d00610069006e00"
  "01000c00530065007200760065007200 00000000");

// MS-NLMP's AV_PAIR list of section 4.2.4 (MsvAvNbDomainName "Domain",
// MsvAvNbComputerName "Server").
const std::vector<detail::ntlm_av_pair> spec_pairs{
	{ .av_id = detail::ntlm_av_id::msv_av_nb_domain_name, .value = str("44006f006d00610069006e00") },
	{ .av_id = detail::ntlm_av_id::msv_av_nb_computer_name, .value = str("530065007200760065007200") },
};

auto parse_error(std::string_view message) -> std::string
{
	auto r = detail::parse_ntlm_challenge(message);
	REQUIRE_FALSE(r.has_value());
	CHECK(r.error().code == ldap::client_errc::decode_error);
	return std::string(r.error().context);
}

// A CHALLENGE_MESSAGE whose TargetInfo field holds `info` exactly (no
// MsvAvEOL appended).
auto with_raw_target_info(std::string_view info) -> std::string
{
	detail::ntlm_challenge_message c{ .negotiate_flags =
										detail::ntlmssp_negotiate_unicode | detail::ntlmssp_negotiate_target_info };
	auto m = detail::encode_ntlm_challenge(c);
	m.resize(m.size() - 4);// the MsvAvEOL encode_ntlm_challenge wrote
	m += info;
	m[40] = static_cast<char>(info.size() & 0xFF);
	m[41] = static_cast<char>(info.size() >> 8);
	m[42] = m[40];
	m[43] = m[41];
	return m;
}

}// namespace

TEST_CASE("ntlm: MD4, the RFC 1320 section A.5 test suite", "[ntlm][rfc]")
{
	CHECK(md4_hex("") == "31 D6 CF E0 D1 6A E9 31 B7 3C 59 D7 E0 C0 89 C0");
	CHECK(md4_hex("a") == "BD E5 2C B3 1D E3 3E 46 24 5E 05 FB DB D6 FB 24");
	CHECK(md4_hex("abc") == "A4 48 01 7A AF 21 D8 52 5F C1 0A E8 7A A6 72 9D");
	CHECK(md4_hex("message digest") == "D9 13 0A 81 64 54 9F E8 18 87 48 06 E1 C7 01 4B");
	CHECK(md4_hex("abcdefghijklmnopqrstuvwxyz") == "D7 9E 1C 30 8A A5 BB CD EE A8 ED 63 DF 41 2D A9");
	CHECK(md4_hex("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
		  == "04 3F 85 82 F2 41 DB 35 1C E6 27 E1 53 E7 F0 E4");
	CHECK(md4_hex("12345678901234567890123456789012345678901234567890123456789012345678901234567890")
		  == "E3 3B 4D DC 9C 38 F2 19 9C 3E 7B 16 4F CC 05 36");
	// Lengths around the padding boundaries, against a Python reference.
	CHECK(md4_hex(std::string(55, 'x')) == "92 F3 2B B8 2C 95 AD 10 E8 F8 7A E5 8A B0 68 07");
	CHECK(md4_hex(std::string(56, 'x')) == "37 4D 5F 08 10 3B 70 92 C8 3B 46 26 EB CE FF AB");
	CHECK(md4_hex(std::string(63, 'x')) == "28 70 45 25 96 E9 8F FF D4 83 32 28 9B 34 72 B9");
	CHECK(md4_hex(std::string(64, 'x')) == "B1 AB F9 56 A5 AE 6F 32 21 E5 FE 85 E3 00 FB B0");
	CHECK(md4_hex(std::string(65, 'x')) == "AF C1 A3 30 8F C1 76 A5 32 38 A0 9A ED DE C2 E6");
	CHECK(md4_hex(std::string(119, 'x')) == "B5 5A E1 5E 41 E5 56 43 B0 C3 DA AD 5E 05 C9 05");
	CHECK(md4_hex(std::string(120, 'x')) == "D8 F9 AD FC 41 EC 43 55 26 19 60 6C 70 CF D2 87");
}

TEST_CASE("ntlm: the NT hash of MS-NLMP section 4.2.2.1.2", "[ntlm][rfc]")
{
	auto pw = detail::ntlm_unicode("Password");
	REQUIRE(pw.has_value());
	CHECK(hex_of(md4_of(std::as_bytes(std::span(*pw)))) == "A4 F4 9C 40 65 10 BD CA B6 82 4E E7 C3 0F D8 52");
}

TEST_CASE("ntlm: UTF-8 to UTF-16LE, and the user name's uppercase", "[ntlm]")
{
	CHECK(detail::ntlm_unicode("Ab") == std::string("A\0b\0", 4));
	// U+00E9, U+20AC, U+1F600 (a surrogate pair).
	CHECK(hex_of(*detail::ntlm_unicode("\xC3\xA9\xE2\x82\xAC\xF0\x9F\x98\x80")) == "E9 00 AC 20 3D D8 00 DE");
	CHECK(detail::ntlm_unicode("") == std::string());
	for (const std::string_view bad : { "\xC3", "\xC0\xAF", "\xED\xA0\x80", "\xF4\x90\x80\x80", "a\xFF" }) {
		auto r = detail::ntlm_unicode(bad);
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == ldap::client_errc::encode_error);
		CHECK_FALSE(detail::ntlm_uppercase_unicode(bad).has_value());
		std::string into;
		auto in_place = detail::ntlm_unicode(bad, into);
		REQUIRE_FALSE(in_place.has_value());
		CHECK(in_place.error().code == ldap::client_errc::encode_error);
	}
	// The in-place form (the password's), reserved once for the longest
	// result: the four-octet sequence gives four octets too.
	for (const std::string_view text : { "", "Ab", "p\xC3\xA4sswort\xE2\x82\xAC", "\xF0\x9F\x98\x80" }) {
		std::string into;
		REQUIRE(detail::ntlm_unicode(text, into).has_value());
		CHECK(into == detail::ntlm_unicode(text));
		CHECK(into.capacity() >= text.size() * 2);
	}

	CHECK(detail::ntlm_uppercase_unicode("User") == detail::ntlm_unicode("USER"));
	// Simple mappings: é to É, ß unchanged (no "SS"), ÿ to Ÿ (U+0178), the
	// dotless ı to I, Cyrillic and Greek letters.
	CHECK(detail::ntlm_uppercase_unicode("jos\xC3\xA9") == detail::ntlm_unicode("JOS\xC3\x89"));
	CHECK(detail::ntlm_uppercase_unicode("stra\xC3\x9F"
										 "e")
		  == detail::ntlm_unicode("STRA\xC3\x9F"
								  "E"));
	CHECK(detail::ntlm_uppercase_unicode("\xC3\xBF") == detail::ntlm_unicode("\xC5\xB8"));
	CHECK(detail::ntlm_uppercase_unicode("\xC4\xB1") == detail::ntlm_unicode("I"));
	CHECK(detail::ntlm_uppercase_unicode("\xD0\xB8\xCF\x89") == detail::ntlm_unicode("\xD0\x98\xCE\xA9"));
	// Above U+FFFF Windows maps nothing (U+10428 DESERET SMALL LETTER LONG I
	// stays as it is).
	CHECK(detail::ntlm_uppercase_unicode("\xF0\x90\x90\xA8") == detail::ntlm_unicode("\xF0\x90\x90\xA8"));
}

TEST_CASE("ntlm: the CHALLENGE_MESSAGE of MS-NLMP section 4.2.4.3", "[ntlm][rfc]")
{
	auto c = detail::parse_ntlm_challenge(spec_challenge);
	REQUIRE(c.has_value());
	CHECK(c->negotiate_flags == 0xE28A'8233u);
	CHECK(hex_of(c->target_name) == hex_of(*detail::ntlm_unicode("Server")));
	CHECK(hex(std::as_bytes(std::span(c->server_challenge))) == "01 23 45 67 89 AB CD EF");
	CHECK(c->target_info == spec_pairs);
	REQUIRE(c->version.has_value());
	CHECK(
	  *c->version
	  == detail::ntlm_version{
		.product_major_version = 6, .product_minor_version = 0, .product_build = 6000, .ntlm_revision_current = 15 });
	CHECK_FALSE(detail::ntlm_timestamp(c->target_info).has_value());
	// encode_ntlm_challenge writes the same bytes.
	CHECK(hex_of(detail::encode_ntlm_challenge(*c)) == hex_of(spec_challenge));
	CHECK(hex_of(detail::encode_ntlm_av_pairs(spec_pairs))
		  == hex_of(str("02000c0044006f006d00610069006e0001000c00530065007200760065007200 00000000")));
}

TEST_CASE("ntlm: malformed CHALLENGE_MESSAGEs are refused", "[ntlm]")
{
	CHECK_THAT(parse_error(""), ContainsSubstring("0 octets, shorter than its 48-octet fixed part"));
	CHECK_THAT(parse_error(spec_challenge.substr(0, 47)), ContainsSubstring("shorter than its 48-octet"));
	// With NTLMSSP_NEGOTIATE_VERSION the Version must be there.
	CHECK_THAT(parse_error(spec_challenge.substr(0, 50)), ContainsSubstring("fixed part with a Version"));
	auto bad = spec_challenge;
	bad[7] = 'X';
	CHECK_THAT(parse_error(bad), ContainsSubstring("no \"NTLMSSP\" signature"));
	bad = spec_challenge;
	bad[8] = 3;
	CHECK(parse_error(bad) == "CHALLENGE_MESSAGE: MessageType 3, not 2");
	// TargetName past the end.
	bad = spec_challenge;
	bad[16] = static_cast<char>(0x60);
	CHECK(parse_error(bad)
		  == "CHALLENGE_MESSAGE: TargetName (12 octets at offset 96) runs past the end of the 104-octet message");
	// A huge offset does not wrap.
	bad = spec_challenge;
	bad[44] = bad[45] = bad[46] = bad[47] = static_cast<char>(0xFF);
	CHECK_THAT(parse_error(bad), ContainsSubstring("TargetInfo (36 octets at offset 4294967295) runs past"));
	// Truncated message: TargetInfo's last octets missing.
	CHECK_THAT(parse_error(spec_challenge.substr(0, spec_challenge.size() - 1)), ContainsSubstring("TargetInfo (36"));

	// The AV_PAIR list.
	CHECK(parse_error(with_raw_target_info(str("0200"))) == "CHALLENGE_MESSAGE: TargetInfo ends without MsvAvEOL");
	CHECK(
	  parse_error(with_raw_target_info(str("02000200 4100"))) == "CHALLENGE_MESSAGE: TargetInfo ends without MsvAvEOL");
	CHECK(parse_error(with_raw_target_info(str("02000900 4100 00000000")))
		  == "CHALLENGE_MESSAGE: AV_PAIR 2: AvLen 9 runs past the end of TargetInfo");
	CHECK(parse_error(with_raw_target_info(str("0000 0100 00"))) == "CHALLENGE_MESSAGE: MsvAvEOL with AvLen 1, not 0");
	CHECK(parse_error(with_raw_target_info(str("06000200 0000 00000000")))
		  == "CHALLENGE_MESSAGE: MsvAvFlags not of 4 octets");
	CHECK(parse_error(with_raw_target_info(str("06000400 00000000 06000400 00000000 00000000")))
		  == "CHALLENGE_MESSAGE: MsvAvFlags twice");
	CHECK(parse_error(with_raw_target_info(str("07000400 00000000 00000000")))
		  == "CHALLENGE_MESSAGE: MsvAvTimestamp not of 8 octets");
	CHECK(parse_error(with_raw_target_info(str("07000800 0102030405060708 07000800 0102030405060708 00000000")))
		  == "CHALLENGE_MESSAGE: MsvAvTimestamp twice");

	// Accepted: unknown AvIds kept, what follows MsvAvEOL ignored, an empty
	// TargetName with any offset.
	auto ok =
	  detail::parse_ntlm_challenge(with_raw_target_info(str("7F000100 41 07000800 0807060504030201 00000000 FFFF")));
	REQUIRE(ok.has_value());
	REQUIRE(ok->target_info.size() == 2);
	CHECK(ok->target_info[0] == detail::ntlm_av_pair{ .av_id = static_cast<detail::ntlm_av_id>(0x7F), .value = "A" });
	CHECK(detail::ntlm_timestamp(ok->target_info) == 0x0102'0304'0506'0708u);
	bad = spec_challenge;
	bad[12] = bad[13] = 0;// TargetName length 0, offset 56 kept
	bad[16] = static_cast<char>(0xF0);
	auto empty_name = detail::parse_ntlm_challenge(bad);
	REQUIRE(empty_name.has_value());
	CHECK(empty_name->target_name.empty());
}

TEST_CASE("ntlm: the client's TargetInfo", "[ntlm]")
{
	detail::ntlm_key bindings{};
	bindings[0] = 0xAB;
	const std::string spn = *detail::ntlm_unicode("ldap/dc1");
	std::vector<detail::ntlm_av_pair> server = spec_pairs;
	server.push_back({ .av_id = detail::ntlm_av_id::msv_av_target_name, .value = "drop me" });
	server.push_back({ .av_id = detail::ntlm_av_id::msv_av_channel_bindings, .value = "drop me" });

	auto info = detail::ntlm_client_target_info(server, true, bindings, spn);
	REQUIRE(info.size() == 5);
	CHECK(info[0] == spec_pairs[0]);
	CHECK(info[1] == spec_pairs[1]);
	CHECK(info[2] == detail::ntlm_av_pair{ .av_id = detail::ntlm_av_id::msv_av_flags, .value = str("02000000") });
	CHECK(info[3].av_id == detail::ntlm_av_id::msv_av_channel_bindings);
	CHECK(hex_of(info[3].value) == hex_of(bindings));
	CHECK(info[4] == detail::ntlm_av_pair{ .av_id = detail::ntlm_av_id::msv_av_target_name, .value = spn });

	// The server's MsvAvFlags keeps its place, the MIC bit or'ed in.
	server = { { .av_id = detail::ntlm_av_id::msv_av_flags, .value = str("01000000") }, spec_pairs[0] };
	info = detail::ntlm_client_target_info(server, true, bindings, {});
	REQUIRE(info.size() == 3);
	CHECK(info[0] == detail::ntlm_av_pair{ .av_id = detail::ntlm_av_id::msv_av_flags, .value = str("03000000") });
	CHECK(info[2].av_id == detail::ntlm_av_id::msv_av_channel_bindings);
	info = detail::ntlm_client_target_info(server, false, bindings, {});
	CHECK(info[0].value == str("01000000"));

	// No channel bindings: no MsvAvChannelBindings.
	info = detail::ntlm_client_target_info(server, true, std::nullopt, spn);
	REQUIRE(info.size() == 3);
	CHECK(info[1] == spec_pairs[0]);
	CHECK(info[2] == detail::ntlm_av_pair{ .av_id = detail::ntlm_av_id::msv_av_target_name, .value = spn });
}

TEST_CASE("ntlm: NEGOTIATE_MESSAGE and AUTHENTICATE_MESSAGE", "[ntlm]")
{
	const detail::ntlm_version v{ .product_major_version = 10, .product_build = 0x4A61 };
	CHECK(hex_of(detail::encode_ntlm_negotiate(0xE208'8297u, v))
		  == hex_of(str("4e544c4d53535000 01000000 978208e2 0000000028000000 0000000028000000 0a00614a0000000f")));

	detail::ntlm_authenticate_message a{ .lm_challenge_response = std::string(24, '\0'),
		.nt_challenge_response = "nt-response",
		.domain_name = *detail::ntlm_unicode("Domain"),
		.user_name = *detail::ntlm_unicode("User"),
		.workstation = *detail::ntlm_unicode("COMPUTER"),
		.encrypted_random_session_key = {},
		.negotiate_flags = 0xE288'8215u,
		.version = v,
		.mic = {} };
	a.mic[15] = 0x77;
	auto bytes = detail::encode_ntlm_authenticate(a);
	REQUIRE(bytes.has_value());
	REQUIRE(bytes->size() == detail::ntlm_authenticate_header_size + 12 + 8 + 16 + 24 + 11);
	// DomainNameFields: 12 octets at 88; UserNameFields at 100,
	// WorkstationFields at 108, LmChallengeResponseFields at 124,
	// NtChallengeResponseFields at 148, EncryptedRandomSessionKeyFields
	// empty at 159.
	CHECK(hex_of(bytes->substr(12, 48))
		  == hex_of(str("18001800 7c000000 0b000b00 94000000 0c000c00 58000000 08000800 64000000"
						"10001000 6c000000 00000000 9f000000")));
	CHECK(static_cast<unsigned char>((*bytes)[detail::ntlm_authenticate_mic_offset + 15]) == 0x77);
	auto back = detail::parse_ntlm_authenticate(*bytes);
	REQUIRE(back.has_value());
	CHECK(*back == a);

	a.user_name.assign(0x1'0000, 'u');
	auto too_long = detail::encode_ntlm_authenticate(a);
	REQUIRE_FALSE(too_long.has_value());
	CHECK(too_long.error().code == ldap::client_errc::encode_error);

	auto short_auth = detail::parse_ntlm_authenticate(bytes->substr(0, 87));
	REQUIRE_FALSE(short_auth.has_value());
	CHECK_THAT(std::string(short_auth.error().context), ContainsSubstring("AUTHENTICATE_MESSAGE: 87 octets"));
}

namespace {

// RC4's keystream: RC4 over zeros.
auto keystream(std::string_view key_hex, std::size_t n) -> std::vector<std::byte>
{
	const auto key = from_hex(key_hex);
	detail::ntlm_rc4 rc4(std::span(reinterpret_cast<const unsigned char *>(key.data()), key.size()));
	std::vector<std::byte> out(n);
	rc4.apply(out);
	return out;
}

auto at(const std::vector<std::byte> &s, std::size_t offset) -> std::string
{
	return hex(std::span(s).subspan(offset, 16));
}

}// namespace

TEST_CASE("ntlm: RC4, the RFC 6229 test vectors", "[ntlm][rfc]")
{
	// RFC 6229 section 2: the keystream at offsets 0, 16, 240 and 256.
	const auto k40 = keystream("0102030405", 272);
	CHECK(at(k40, 0) == "B2 39 63 05 F0 3D C0 27 CC C3 52 4A 0A 11 18 A8");
	CHECK(at(k40, 16) == "69 82 94 4F 18 FC 82 D5 89 C4 03 A4 7A 0D 09 19");
	CHECK(at(k40, 240) == "28 CB 11 32 C9 6C E2 86 42 1D CA AD B8 B6 9E AE");
	CHECK(at(k40, 256) == "1C FC F6 2B 03 ED DB 64 1D 77 DF CF 7F 8D 8C 93");
	const auto k128 = keystream("0102030405060708090a0b0c0d0e0f10", 272);
	CHECK(at(k128, 0) == "9A C7 CC 9A 60 9D 1E F7 B2 93 28 99 CD E4 1B 97");
	CHECK(at(k128, 16) == "52 48 C4 95 90 14 12 6A 6E 8A 84 F1 1D 1A 9E 1C");
	CHECK(at(k128, 240) == "06 59 02 E4 B6 20 F6 CC 36 C8 58 9F 66 43 2F 2B");
	CHECK(at(k128, 256) == "D3 9D 56 6B C6 BC E3 01 07 68 15 15 49 F3 87 3F");
	const auto k256 = keystream("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20", 272);
	CHECK(at(k256, 0) == "EA A6 BD 25 88 0B F9 3D 3F 5D 1E 4C A2 61 1D 91");
	CHECK(at(k256, 256) == "02 E1 E7 05 6B 0F 62 39 00 49 64 22 94 3E 97 B6");
	const auto other = keystream("ebb46227c6cc8b37641910833222772a", 272);
	CHECK(at(other, 0) == "72 0C 94 B6 3E DF 44 E1 31 D9 50 CA 21 1A 5A 30");
	CHECK(at(other, 256) == "48 47 D8 1D A4 94 2D BC 24 9D EF C4 8C 92 2B 9F");

	// The state runs on across calls: two pieces give the same keystream.
	const auto key = from_hex("0102030405");
	detail::ntlm_rc4 pieces(std::span(reinterpret_cast<const unsigned char *>(key.data()), key.size()));
	std::vector<std::byte> a(7);
	std::vector<std::byte> b(9);
	pieces.apply(a);
	pieces.apply(b);
	a.insert(a.end(), b.begin(), b.end());
	CHECK(hex(a) == at(k40, 0));
}

TEST_CASE("ntlm: the NTLMSSP_MESSAGE_SIGNATURE of a protected buffer", "[ntlm]")
{
	const detail::ntlm_message_signature sig{
		.version = 1, .checksum = { 0x7f, 0xb3, 0x8e, 0xc5, 0xc5, 0x5d, 0x49, 0x76 }, .seq_num = 0x0102'0304
	};
	std::vector<std::byte> buffer(16);
	detail::encode_ntlm_signature(sig, std::span(buffer).first<16>());
	CHECK(hex(buffer) == "01 00 00 00 7F B3 8E C5 C5 5D 49 76 04 03 02 01");
	buffer.push_back(std::byte{ 0x42 });
	auto parsed = detail::parse_ntlm_protected_buffer(buffer);
	REQUIRE(parsed.has_value());
	CHECK(parsed->signature == sig);
	CHECK(hex(parsed->message) == "42");

	auto short_buffer = detail::parse_ntlm_protected_buffer(std::span(buffer).first(15));
	REQUIRE_FALSE(short_buffer.has_value());
	CHECK(short_buffer.error().code == ldap::client_errc::decode_error);
	CHECK(short_buffer.error().context == "NTLM protected buffer: 15 octets, shorter than its 16-octet signature");
	buffer[0] = std::byte{ 2 };
	auto version = detail::parse_ntlm_protected_buffer(buffer);
	REQUIRE_FALSE(version.has_value());
	CHECK(version.error().context == "NTLM protected buffer: signature Version 2, not 1");
	// The signature alone: an empty message.
	buffer[0] = std::byte{ 1 };
	auto empty = detail::parse_ntlm_protected_buffer(std::span(buffer).first(16));
	REQUIRE(empty.has_value());
	CHECK(empty->message.empty());
}
