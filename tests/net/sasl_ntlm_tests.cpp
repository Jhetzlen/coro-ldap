// SASL NTLM (sasl_ntlm.hpp): the MS-NLMP section 4.2.4 NTLMv2 test
// vectors, the mechanism's checks and channel binding, and binds against
// the scripted mock server, which checks the NTProofStr and the MIC as a
// domain controller would; the security layer (signing and sealing, MS-NLMP
// section 3.4): the section 4.2.4.4 vector, a golden exchange and buffers,
// tampering and replays, and a bind and search through a mock domain
// controller whose own layer (dc_layer, written here from MS-NLMP) unwraps
// and checks the client's buffers.
#include "../../src/net/sasl_layer.hpp"
#include "../test_util.hpp"
#include "jhetz/ldap/connection.hpp"
#include "jhetz/ldap/ntlm_message.hpp"
#include "jhetz/ldap/sasl_ntlm.hpp"
#include "mock_ldap.hpp"
#include "net_test_support.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <openssl/evp.h>
#include <openssl/hmac.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <memory_resource>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace jhetz::ldap::detail {

// Tests only: a sasl_ntlm with a fixed ClientChallenge.
struct ntlm_test_access
{
	static auto with_challenge(std::string username,
	  std::string password,
	  sasl_ntlm_options options,
	  const ntlm_challenge &client_challenge) -> sasl_ntlm
	{
		return { std::move(username), std::move(password), std::move(options), client_challenge };
	}
	// A fixed ExportedSessionKey instead of a random one.
	static void set_session_key(sasl_ntlm &mech, const ntlm_key &key) { mech.fixed_session_key_ = key; }
};

}// namespace jhetz::ldap::detail

namespace ldap = jhetz::ldap;
namespace detail = jhetz::ldap::detail;
namespace net = jhetz::ldap::net;
using namespace jhetz::ldap::test;
using Catch::Matchers::ContainsSubstring;

namespace {

auto str(std::string_view hex_text) -> std::string
{
	const auto b = jhetz::ldap::test::from_hex(hex_text);
	return { reinterpret_cast<const char *>(b.data()), b.size() };
}

auto hex_of(std::string_view s) -> std::string { return jhetz::ldap::test::hex(std::as_bytes(std::span(s))); }

auto hex_of(const detail::ntlm_key &k) -> std::string { return jhetz::ldap::test::hex(std::as_bytes(std::span(k))); }

auto key_str(std::span<const unsigned char> k) -> std::string
{
	return { reinterpret_cast<const char *>(k.data()), k.size() };
}

constexpr detail::ntlm_challenge spec_server_challenge{ 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF };
constexpr detail::ntlm_challenge spec_client_challenge{ 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA };

auto u16(std::string_view utf8) -> std::string { return *detail::ntlm_unicode(utf8); }

// The out-parameter computations as values, for the checks.
auto hmac_md5(std::span<const unsigned char> key, std::string_view data) -> ldap::result<detail::ntlm_key>
{
	detail::ntlm_key out{};
	if (auto r = detail::ntlm_hmac_md5(key, data, out); !r) {
		return std::unexpected(std::move(r.error()));
	}
	return out;
}

auto ntowfv2(std::string_view password, std::string_view user, std::string_view domain)
  -> ldap::result<detail::ntlm_key>
{
	detail::ntlm_key out{};
	if (auto r = detail::ntowfv2(password, user, domain, out); !r) {
		return std::unexpected(std::move(r.error()));
	}
	return out;
}

auto compute_response(const detail::ntlm_key &key, std::string_view server_name, bool server_timestamp)
  -> ldap::result<detail::ntlm_responses>
{
	detail::ntlm_responses out;
	if (auto r = detail::ntlm_compute_response(
		  key, spec_server_challenge, spec_client_challenge, 0, server_name, server_timestamp, out);
	  !r) {
		return std::unexpected(std::move(r.error()));
	}
	return out;
}


// MS-NLMP section 4.2.4's AV_PAIRs: MsvAvNbDomainName "Domain",
// MsvAvNbComputerName "Server".
auto spec_pairs() -> std::vector<detail::ntlm_av_pair>
{
	return { { .av_id = detail::ntlm_av_id::msv_av_nb_domain_name, .value = u16("Domain") },
		{ .av_id = detail::ntlm_av_id::msv_av_nb_computer_name, .value = u16("Server") } };
}

constexpr std::uint64_t server_time = 0x01DB'2B3C'4D5E'6F70u;// a FILETIME in 2024

auto timestamp_pair(std::uint64_t t) -> detail::ntlm_av_pair
{
	std::string v;
	for (unsigned i = 0; i < 8; ++i) {
		v += static_cast<char>((t >> (8 * i)) & 0xFFu);
	}
	return { .av_id = detail::ntlm_av_id::msv_av_timestamp, .value = v };
}

// The flags of an NTLMv2 domain controller's CHALLENGE_MESSAGE.
constexpr std::uint32_t dc_flags =
  detail::ntlmssp_negotiate_unicode | detail::ntlmssp_request_target | detail::ntlmssp_negotiate_ntlm
  | detail::ntlmssp_negotiate_always_sign | detail::ntlmssp_target_type_domain
  | detail::ntlmssp_negotiate_extended_sessionsecurity | detail::ntlmssp_negotiate_target_info
  | detail::ntlmssp_negotiate_version | detail::ntlmssp_negotiate_128 | detail::ntlmssp_negotiate_56;

auto dc_challenge(std::uint32_t flags = dc_flags, bool with_timestamp = true) -> std::string
{
	auto pairs = spec_pairs();
	if (with_timestamp) {
		pairs.push_back(timestamp_pair(server_time));
	}
	return detail::encode_ntlm_challenge({ .target_name = u16("EXAMPLE"),
	  .negotiate_flags = flags,
	  .server_challenge = spec_server_challenge,
	  .target_info = std::move(pairs),
	  .version = detail::ntlm_version{ .product_major_version = 10, .product_build = 20348 } });
}

// The NEGOTIATE_MESSAGE the client sends: flags 0x22880205 (Unicode,
// RequestTarget, NTLM, extended session security, TargetInfo, Version,
// 128-bit), a Version of zeros with NTLMSSP_REVISION_W2K3.
const std::string expected_negotiate =
  str("4e544c4d53535000 01000000 05028822 0000000028000000 0000000028000000 000000000000000f");

auto sasl_resp(std::int32_t id, std::int32_t code, std::optional<std::string_view> creds = {}) -> ldap::message
{
	return ldap::message{ id, ldap::bind_response{ ldap::ldap_result{ code }, creds } };
}

auto sasl_creds(const ldap::message &m) -> std::string
{
	const auto &req = std::get<ldap::bind_request>(m.op);
	const auto &sasl = std::get<ldap::sasl_auth>(req.authentication);
	CHECK(sasl.mechanism == "GSS-SPNEGO");
	REQUIRE(sasl.credentials.has_value());
	return std::string(*sasl.credentials);
}

auto abort_req(std::int32_t id) -> ldap::message
{
	return ldap::message{ id, ldap::bind_request{ 3, "", ldap::simple_auth{ "" } } };
}

// What a domain controller checks, from what it knows (the user's NT
// hash, i.e. its password, and the messages): the NTProofStr over the
// client's temp structure, and the MIC keyed with the SessionBaseKey.
// Returns the client's AV_PAIR list (temp's ServerName) as encoded.
auto dc_verify(std::string_view negotiate,
  std::string_view challenge,
  std::string_view authenticate,
  std::string_view password,
  std::string_view user,
  std::string_view domain) -> std::string
{
	auto auth = detail::parse_ntlm_authenticate(authenticate);
	REQUIRE(auth.has_value());
	auto key = ntowfv2(password, user, domain);
	REQUIRE(key.has_value());
	const std::string &nt = auth->nt_challenge_response;
	REQUIRE(nt.size() > 16 + 28 + 4);
	const std::string temp = nt.substr(16);
	auto proof = hmac_md5(*key, key_str(spec_server_challenge) + temp);
	REQUIRE(proof.has_value());
	CHECK(hex_of(nt.substr(0, 16)) == hex_of(*proof));
	auto session = hmac_md5(*key, key_str(*proof));
	REQUIRE(session.has_value());
	std::string zeroed(authenticate);
	zeroed.replace(detail::ntlm_authenticate_mic_offset, 16, 16, '\0');
	auto mic = hmac_md5(*session, std::string(negotiate) + std::string(challenge) + zeroed);
	REQUIRE(mic.has_value());
	CHECK(hex_of(auth->mic) == hex_of(*mic));
	// temp: 01 01 Z(6) Time ClientChallenge Z(4) ServerName Z(4).
	CHECK(temp.substr(0, 8) == std::string("\x01\x01\0\0\0\0\0\0", 8));
	CHECK(temp.substr(temp.size() - 4) == std::string(4, '\0'));
	return temp.substr(28, temp.size() - 32);
}

auto mic_flags() -> detail::ntlm_av_pair
{
	return { .av_id = detail::ntlm_av_id::msv_av_flags, .value = std::string("\x02\0\0\0", 4) };
}

auto bindings_pair(std::string_view value) -> detail::ntlm_av_pair
{
	return { .av_id = detail::ntlm_av_id::msv_av_channel_bindings, .value = std::string(value) };
}

auto target_pair(std::string_view spn) -> detail::ntlm_av_pair
{
	return { .av_id = detail::ntlm_av_id::msv_av_target_name, .value = u16(spn) };
}

// The tls-server-end-point hash used for the TLS contexts: 00 01 .. 1F.
auto cert_hash() -> std::vector<std::byte>
{
	std::vector<std::byte> h;
	h.reserve(32);
	for (unsigned i = 0; i < 32; ++i) {
		h.push_back(static_cast<std::byte>(i));
	}
	return h;
}

// MD5(Z(16) || 41 00 00 00 || "tls-server-end-point:" 00 01 .. 1F),
// computed with Python's hashlib.
constexpr std::string_view expected_bindings_hash = "8F 12 14 C9 C9 CA B8 DC 3B F8 66 DA 9A BA 57 A7";

const ldap::sasl_ntlm_options plain{ .require_tls = false };

}// namespace

TEST_CASE("ntlm: the NTLMv2 test vectors of MS-NLMP section 4.2.4", "[sasl][ntlm][rfc]")
{
	// 4.2.4.1.1 NTOWFv2() and LMOWFv2().
	auto key = ntowfv2("Password", "User", "Domain");
	REQUIRE(key.has_value());
	CHECK(hex_of(*key) == "0C 86 8A 40 3B FD 7A 93 A3 00 1E F2 2E F0 2E 3F");
	// The user name is uppercased, the domain is not.
	CHECK(ntowfv2("Password", "USER", "Domain") == key);
	CHECK(ntowfv2("Password", "User", "DOMAIN") != key);

	const std::string server_name = detail::encode_ntlm_av_pairs(spec_pairs());
	auto r = compute_response(*key, server_name, false);
	REQUIRE(r.has_value());
	// 4.2.4.2.2 NTLMv2 Response: the NTProofStr, then temp.
	CHECK(hex_of(r->nt_challenge_response.substr(0, 16)) == "68 CD 0A B8 51 E5 1C 96 AA BC 92 7B EB EF 6A 1C");
	CHECK(hex_of(r->nt_challenge_response.substr(16))
		  == hex_of(std::string("\x01\x01", 2) + std::string(14, '\0') + std::string(8, '\xAA') + std::string(4, '\0')
					+ server_name + std::string(4, '\0')));
	// 4.2.4.1.2 Session Base Key.
	CHECK(hex_of(r->session_base_key) == "8D E4 0C CA DB C1 4A 82 F1 5C B0 AD 0D E9 5C A3");
	// 4.2.4.2.1 LMv2 Response.
	CHECK(
	  hex_of(r->lm_challenge_response) == "86 C3 50 97 AC 9C EC 10 25 54 76 4A 57 CC CC 19 AA AA AA AA AA AA AA AA");

	// With the server's MsvAvTimestamp the LmChallengeResponse is Z(24).
	auto with_time = compute_response(*key, server_name, true);
	REQUIRE(with_time.has_value());
	CHECK(with_time->lm_challenge_response == std::string(24, '\0'));
	CHECK(with_time->nt_challenge_response == r->nt_challenge_response);
}

TEST_CASE("ntlm: the channel bindings hash", "[sasl][ntlm]")
{
	const auto h = cert_hash();
	const std::string app = ldap::prefixed_channel_binding(ldap::channel_binding_type::tls_server_end_point, h);
	auto cb = detail::ntlm_channel_bindings_hash(app);
	REQUIRE(cb.has_value());
	CHECK(hex_of(*cb) == expected_bindings_hash);
}

TEST_CASE("ntlm: an NTLMv2 bind checked by the server", "[net][sasl][ntlm]")
{
	const std::string password = "p\xC3\xA4sswort\xE2\x82\xAC";// "pässwort€"
	const std::string challenge = dc_challenge();
	auto mech = detail::ntlm_test_access::with_challenge("EXAMPLE\\j\xC3\xB6rg",
	  password,
	  { .workstation = "WS01", .target = "ldap/dc1.example.org", .require_tls = false },
	  spec_client_challenge);
	mock_ldap m;
	m.serve({ answer({ sasl_resp(1, 14, challenge) }), answer({ sasl_resp(2, 0) }) });
	REQUIRE(m.run(m.conn.sasl_bind(mech)).has_value());
	m.check_server();
	REQUIRE(m.log.received.size() == 2);
	const std::string negotiate = sasl_creds(m.log.received[0]);
	CHECK(hex_of(negotiate) == hex_of(expected_negotiate));
	const std::string authenticate = sasl_creds(m.log.received[1]);

	auto auth = detail::parse_ntlm_authenticate(authenticate);
	REQUIRE(auth.has_value());
	CHECK(auth->user_name == u16("j\xC3\xB6rg"));
	CHECK(auth->domain_name == u16("EXAMPLE"));
	CHECK(auth->workstation == u16("WS01"));
	CHECK(auth->encrypted_random_session_key.empty());
	CHECK(auth->lm_challenge_response == std::string(24, '\0'));
	// The flags both sides set, no signing, sealing nor key exchange.
	CHECK(auth->negotiate_flags == 0x2288'0205u);
	CHECK(auth->version == detail::ntlm_version{});

	const std::string info = dc_verify(negotiate, challenge, authenticate, password, "j\xC3\xB6rg", "EXAMPLE");
	auto expected = spec_pairs();
	expected.push_back(timestamp_pair(server_time));
	expected.push_back(mic_flags());
	expected.push_back(bindings_pair(std::string(16, '\0')));// Z(16): no TLS
	expected.push_back(target_pair("ldap/dc1.example.org"));
	CHECK(hex_of(info) == hex_of(detail::encode_ntlm_av_pairs(expected)));
	// The server's timestamp and the client challenge.
	const std::string temp = auth->nt_challenge_response.substr(16);
	CHECK(temp.substr(8, 8) == timestamp_pair(server_time).value);
	CHECK(temp.substr(16, 8) == std::string(8, '\xAA'));
	CHECK(mech.channel_binding_used() == std::nullopt);

	SECTION("a wrong password does not verify")
	{
		auto wrong = ntowfv2("passwort", "j\xC3\xB6rg", "EXAMPLE");
		REQUIRE(wrong.has_value());
		auto proof = hmac_md5(*wrong, key_str(spec_server_challenge) + temp);
		REQUIRE(proof.has_value());
		CHECK(auth->nt_challenge_response.substr(0, 16) != key_str(*proof));
	}
}

TEST_CASE("ntlm: user names, domains and random client challenges", "[net][sasl][ntlm]")
{
	const auto bind = [](ldap::sasl_ntlm &mech, std::string_view challenge) -> std::string {
		mock_ldap m;
		m.serve({ answer({ sasl_resp(1, 14, challenge) }), answer({ sasl_resp(2, 0) }) });
		REQUIRE(m.run(m.conn.sasl_bind(mech)).has_value());
		m.check_server();
		REQUIRE(m.log.received.size() == 2);
		return sasl_creds(m.log.received[1]);
	};
	const std::string challenge = dc_challenge();

	SECTION("a UPN has no domain")
	{
		ldap::sasl_ntlm mech("jdoe@example.org", "secret", plain);
		auto auth = detail::parse_ntlm_authenticate(bind(mech, challenge));
		REQUIRE(auth.has_value());
		CHECK(auth->user_name == u16("jdoe@example.org"));
		CHECK(auth->domain_name.empty());
		CHECK(auth->workstation.empty());
		dc_verify(expected_negotiate, challenge, bind(mech, challenge), "secret", "jdoe@example.org", "");
	}
	SECTION("an explicit domain keeps the user name as given")
	{
		ldap::sasl_ntlm mech("a\\b", "secret", { .domain = "CORP", .require_tls = false });
		auto auth = detail::parse_ntlm_authenticate(bind(mech, challenge));
		REQUIRE(auth.has_value());
		CHECK(auth->user_name == u16("a\\b"));
		CHECK(auth->domain_name == u16("CORP"));
	}
	SECTION("two binds use two client challenges, and no MsvAvTargetName without a host")
	{
		ldap::sasl_ntlm mech("CORP\\jdoe", "secret", plain);
		const std::string first = bind(mech, challenge);
		const std::string second = bind(mech, challenge);
		auto a = detail::parse_ntlm_authenticate(first);
		auto b = detail::parse_ntlm_authenticate(second);
		REQUIRE(a.has_value());
		REQUIRE(b.has_value());
		CHECK(a->nt_challenge_response.substr(32, 8) != b->nt_challenge_response.substr(32, 8));
		const std::string info = dc_verify(expected_negotiate, challenge, second, "secret", "jdoe", "CORP");
		auto expected = spec_pairs();
		expected.push_back(timestamp_pair(server_time));
		expected.push_back(mic_flags());
		expected.push_back(bindings_pair(std::string(16, '\0')));
		CHECK(hex_of(info) == hex_of(detail::encode_ntlm_av_pairs(expected)));
	}
	SECTION("without the server's MsvAvTimestamp: the current time and the LMv2 response")
	{
		const std::string no_time = dc_challenge(dc_flags, false);
		auto mech = detail::ntlm_test_access::with_challenge("CORP\\jdoe", "secret", plain, spec_client_challenge);
		const std::string authenticate = bind(mech, no_time);
		auto auth = detail::parse_ntlm_authenticate(authenticate);
		REQUIRE(auth.has_value());
		REQUIRE(auth->lm_challenge_response.size() == 24);
		CHECK(auth->lm_challenge_response.substr(16) == std::string(8, '\xAA'));
		auto key = ntowfv2("secret", "jdoe", "CORP");
		REQUIRE(key.has_value());
		auto lm = hmac_md5(*key, key_str(spec_server_challenge) + std::string(8, '\xAA'));
		REQUIRE(lm.has_value());
		CHECK(auth->lm_challenge_response.substr(0, 16) == key_str(*lm));
		// A FILETIME after 2020-01-01 (132223104000000000).
		std::uint64_t t = 0;
		for (int i = 7; i >= 0; --i) {
			t = t << 8 | static_cast<unsigned char>(auth->nt_challenge_response[24 + static_cast<std::size_t>(i)]);
		}
		CHECK(t > 132'223'104'000'000'000u);
		dc_verify(expected_negotiate, no_time, authenticate, "secret", "jdoe", "CORP");
	}
}

TEST_CASE("ntlm: TLS is required by default", "[net][sasl][ntlm]")
{
	mock_ldap m;
	m.serve({ answer({ done_msg(1) }) });
	ldap::sasl_ntlm mech("CORP\\jdoe", "secret");
	auto r = m.run(m.conn.sasl_bind(mech));
	REQUIRE_FALSE(r.has_value());
	CHECK(r.error().code == ldap::client_errc::tls_required);
	CHECK(r.error().code == ldap::cond::access_denied);
	CHECK(r.error().context
		  == "sasl bind GSS-SPNEGO: NTLM needs a TLS-protected connection (sasl_ntlm_options::require_tls)");
	// Nothing was sent: the next request is the first.
	CHECK(m.run(m.conn.search({})).has_value());
	m.check_server();
	REQUIRE(m.log.received.size() == 1);
	CHECK(std::holds_alternative<ldap::search_request>(m.log.received[0].op));
}

TEST_CASE("ntlm: a golden AUTHENTICATE_MESSAGE from an independent implementation", "[sasl][ntlm][rfc]")
{
	// The three messages are the output of tests/net/ntlm_golden.py (run it
	// with python3 -I), a standalone script written from MS-NLMP alone
	// (stdlib hashlib/hmac, its own RFC 1320 MD4 checked against RFC 1320's
	// and MS-NLMP 4.2.4.1.1's vectors), none of this library's code: user
	// "CORP\jörg", password "pässwort€", workstation "WS01", MsvAvTargetName
	// "ldap/dc1.example.org", ClientChallenge AA*8, the server's
	// MsvAvTimestamp 0x01DB2B3C4D5E6F70 (so LmChallengeResponse is Z(24)),
	// MsvAvChannelBindings over tls-server-end-point 00 01 .. 1F.
	// Where MS-NLMP leaves the choice to the client, the script copies this
	// library's, so the vector does not anchor these:
	// - the NEGOTIATE_MESSAGE's flags and its zero Version;
	// - the AUTHENTICATE_MESSAGE's NegotiateFlags, (client & server) |
	//   VERSION (so no NEGOTIATE_56);
	// - "DOMAIN\user" split at the first backslash;
	// - the client's AV_PAIR order (2.2.2.1 allows any, MsvAvEOL last): the
	//   server's pairs, then MsvAvFlags, MsvAvChannelBindings,
	//   MsvAvTargetName;
	// - the payload order (2.2.1.3 allows any): DomainName, UserName,
	//   Workstation, LmChallengeResponse, NtChallengeResponse.
	// The rest follows the spec's formulas: NTOWFv2, temp (with its trailing
	// Z(4)), the NTProofStr, the LM Z(24), the SessionBaseKey, the
	// gss_channel_bindings_struct MD5 and the MIC (offset 72,
	// HMAC_MD5(ExportedSessionKey, NEGOTIATE || CHALLENGE || AUTHENTICATE
	// with a zero MIC)), which the 4.2.4 vectors do not cover.
	const std::string negotiate =
	  str("4e544c4d53535000010000000502882200000000280000000000000028000000000000000000000f");
	const std::string challenge = str(
	  "4e544c4d53535000020000000e000e0038000000058289a20123456789abcdef00000000000000003000300046000000"
	  "0a007c4f0000000f4500580041004d0050004c00450002000c0044006f006d00610069006e0001000c00530065007200"
	  "76006500720007000800706f5e4d3c2bdb0100000000");
	const std::string authenticate = str(
	  "4e544c4d53535000030000001800180070000000a800a800880000000800080058000000080008006000000008000800"
	  "68000000000000003001000005028822000000000000000f3431f2819f9924d547cca6a5d7d8da4f43004f0052005000"
	  "6a00f60072006700570053003000310000000000000000000000000000000000000000000000000081e0a00d437f04e2"
	  "9c8c6c576fe4a3460101000000000000706f5e4d3c2bdb01aaaaaaaaaaaaaaaa0000000002000c0044006f006d006100"
	  "69006e0001000c0053006500720076006500720007000800706f5e4d3c2bdb0106000400020000000a0010008f1214c9"
	  "c9cab8dc3bf866da9aba57a7090028006c006400610070002f006400630031002e006500780061006d0070006c006500"
	  "2e006f00720067000000000000000000");
	// The same CHALLENGE as the other tests build.
	CHECK(hex_of(dc_challenge()) == hex_of(challenge));

	const auto hash = cert_hash();
	auto mech = detail::ntlm_test_access::with_challenge(
	  "CORP\\j\xC3\xB6rg", "p\xC3\xA4sswort\xE2\x82\xAC", { .workstation = "WS01" }, spec_client_challenge);
	mech.prepare({ .host = "dc1.example.org",
	  .tls = true,
	  .bindings = { .tls_server_end_point = hash, .default_type = ldap::channel_binding_type::tls_server_end_point } });
	auto first = mech.start();
	REQUIRE(first.has_value());
	REQUIRE(first->has_value());
	CHECK(hex_of(**first) == hex_of(negotiate));
	auto second = mech.step(challenge);
	REQUIRE(second.has_value());
	REQUIRE(second->has_value());
	CHECK(hex_of(**second) == hex_of(authenticate));
	CHECK(mech.complete(std::nullopt).has_value());
}

TEST_CASE("ntlm: channel binding over TLS", "[sasl][ntlm]")
{
	const auto hash = cert_hash();
	const ldap::sasl_bind_context tls{ .host = "dc1.example.org",
		.tls = true,
		.bindings = {
		  .tls_server_end_point = hash, .default_type = ldap::channel_binding_type::tls_server_end_point } };
	const std::string challenge = dc_challenge();
	const auto exchange = [&](ldap::sasl_ntlm &mech, const ldap::sasl_bind_context &context) -> std::string {
		mech.prepare(context);
		auto first = mech.start();
		REQUIRE(first.has_value());
		REQUIRE(first->has_value());
		CHECK(hex_of(**first) == hex_of(expected_negotiate));
		auto second = mech.step(challenge);
		REQUIRE(second.has_value());
		REQUIRE(second->has_value());
		CHECK(mech.complete(std::nullopt).has_value());
		return dc_verify(expected_negotiate, challenge, **second, "secret", "jdoe", "CORP");
	};
	auto with = [&](std::string_view bindings, std::string_view spn) {
		auto pairs = spec_pairs();
		pairs.push_back(timestamp_pair(server_time));
		pairs.push_back(mic_flags());
		pairs.push_back(bindings_pair(bindings));
		pairs.push_back(target_pair(spn));
		return hex_of(detail::encode_ntlm_av_pairs(pairs));
	};

	SECTION("MsvAvChannelBindings over tls-server-end-point, the default target")
	{
		auto mech = detail::ntlm_test_access::with_challenge("CORP\\jdoe", "secret", {}, spec_client_challenge);
		CHECK(hex_of(exchange(mech, tls)) == with(str(expected_bindings_hash), "ldap/dc1.example.org"));
		CHECK(mech.channel_binding_used() == ldap::channel_binding_type::tls_server_end_point);
	}
	SECTION("ntlm_channel_binding::none: no MsvAvChannelBindings (Samba refuses an explicit Z(16) over TLS)")
	{
		ldap::sasl_ntlm mech("CORP\\jdoe", "secret", { .channel_binding = ldap::ntlm_channel_binding::none });
		auto pairs = spec_pairs();
		pairs.push_back(timestamp_pair(server_time));
		pairs.push_back(mic_flags());
		pairs.push_back(target_pair("ldap/dc1.example.org"));
		CHECK(hex_of(exchange(mech, tls)) == hex_of(detail::encode_ntlm_av_pairs(pairs)));
		CHECK(mech.channel_binding_used() == std::nullopt);
	}
	SECTION("no tls-server-end-point hash: refused before anything is sent")
	{
		ldap::sasl_ntlm mech("CORP\\jdoe", "secret");
		mech.prepare({ .host = "dc1", .tls = true });
		auto r = mech.start();
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == ldap::client_errc::tls_required);
		CHECK_THAT(std::string(r.error().context), ContainsSubstring("no tls-server-end-point channel binding data"));
		CHECK(mech.channel_binding_used() == std::nullopt);
		// Without TLS but allowed: no bindings needed.
		ldap::sasl_ntlm allowed("CORP\\jdoe", "secret", plain);
		allowed.prepare({ .host = "dc1" });
		CHECK(allowed.start().has_value());
	}
}

TEST_CASE("ntlm: challenges that do not offer NTLMv2 are refused", "[net][sasl][ntlm]")
{
	const auto refused = [](std::string_view challenge, ldap::client_errc code, std::string_view why) {
		mock_ldap m;
		m.serve({ answer({ sasl_resp(1, 14, challenge) }), answer({ bind_resp(2) }) });
		ldap::sasl_ntlm mech("CORP\\jdoe", "secret", plain);
		auto r = m.run(m.conn.sasl_bind(mech));
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == code);
		CHECK(std::string(r.error().context) == "sasl bind GSS-SPNEGO: " + std::string(why));
		CHECK(m.conn.is_open());
		m.check_server();
		REQUIRE(m.log.received.size() == 2);
		CHECK(m.log.received[1] == abort_req(2));
	};
	refused(dc_challenge(dc_flags & ~detail::ntlmssp_negotiate_extended_sessionsecurity),
	  ldap::client_errc::unexpected_response,
	  "the server does not offer NTLMv2 (no NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY)");
	refused(dc_challenge(dc_flags & ~detail::ntlmssp_negotiate_unicode),
	  ldap::client_errc::unexpected_response,
	  "the server does not offer Unicode (no NTLMSSP_NEGOTIATE_UNICODE)");
	refused(detail::encode_ntlm_challenge({ .negotiate_flags = dc_flags & ~detail::ntlmssp_negotiate_target_info,
			  .server_challenge = spec_server_challenge,
			  .version = detail::ntlm_version{} }),
	  ldap::client_errc::unexpected_response,
	  "the server does not offer NTLMv2 (no TargetInfo in the CHALLENGE_MESSAGE)");
	refused(
	  "NTLMSSP", ldap::client_errc::decode_error, "CHALLENGE_MESSAGE: 7 octets, shorter than its 48-octet fixed part");
}

TEST_CASE("ntlm: an exchange out of order", "[net][sasl][ntlm]")
{
	SECTION("success to the NEGOTIATE_MESSAGE closes the connection")
	{
		mock_ldap m;
		m.serve({ answer({ sasl_resp(1, 0) }) });
		ldap::sasl_ntlm mech("CORP\\jdoe", "secret", plain);
		auto r = m.run(m.conn.sasl_bind(mech));
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == ldap::client_errc::unexpected_response);
		CHECK(
		  r.error().context == "sasl bind GSS-SPNEGO: the server reported success before the exchange was complete");
		CHECK_FALSE(m.conn.is_open());
	}
	SECTION("a challenge after the AUTHENTICATE_MESSAGE")
	{
		mock_ldap m;
		m.serve({ answer({ sasl_resp(1, 14, dc_challenge()) }),
		  answer({ sasl_resp(2, 14, dc_challenge()) }),
		  answer({ bind_resp(3) }) });
		ldap::sasl_ntlm mech("CORP\\jdoe", "secret", plain);
		auto r = m.run(m.conn.sasl_bind(mech));
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().context == "sasl bind GSS-SPNEGO: a challenge after the AUTHENTICATE_MESSAGE");
		CHECK(m.conn.is_open());
		m.check_server();
	}
	SECTION("no challenge")
	{
		ldap::sasl_ntlm mech("CORP\\jdoe", "secret", plain);
		REQUIRE(mech.start().has_value());
		auto r = mech.step(std::nullopt);
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == ldap::client_errc::decode_error);
		CHECK(r.error().context == "no CHALLENGE_MESSAGE");
		CHECK_FALSE(mech.complete(std::nullopt).has_value());
	}
	SECTION("the server refuses the credentials")
	{
		mock_ldap m;
		m.serve({ answer({ sasl_resp(1, 14, dc_challenge()) }), answer({ sasl_resp(2, 49) }) });
		ldap::sasl_ntlm mech("CORP\\jdoe", "secret", plain);
		auto r = m.run(m.conn.sasl_bind(mech));
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == ldap::errc::invalid_credentials);
		CHECK(r.error().code == ldap::cond::auth_failed);
		CHECK(m.conn.is_open());
	}
}

TEST_CASE("ntlm: input checks", "[sasl][ntlm]")
{
	const auto start_error = [](ldap::sasl_ntlm &mech) -> std::string {
		mech.prepare({});
		auto r = mech.start();
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == ldap::client_errc::encode_error);
		CHECK(r.error().code == ldap::cond::invalid_input);
		return std::string(r.error().context);
	};
	ldap::sasl_ntlm empty("", "secret", plain);
	CHECK(start_error(empty) == "empty user name");
	ldap::sasl_ntlm empty_after_domain("CORP\\", "secret", plain);
	CHECK(start_error(empty_after_domain) == "empty user name");
	ldap::sasl_ntlm bad_user("CORP\\j\xFF", "secret", plain);
	CHECK(start_error(bad_user) == "the user name is not valid UTF-8");
	ldap::sasl_ntlm bad_domain("C\xC3\\jdoe", "secret", plain);
	CHECK(start_error(bad_domain) == "the domain is not valid UTF-8");
	ldap::sasl_ntlm bad_password("CORP\\jdoe", "se\xED\xA0\x80", plain);
	CHECK(start_error(bad_password) == "the password is not valid UTF-8");
	ldap::sasl_ntlm bad_workstation("CORP\\jdoe", "secret", { .workstation = "\xC0\x80", .require_tls = false });
	CHECK(start_error(bad_workstation) == "the workstation is not valid UTF-8");
	ldap::sasl_ntlm long_target("CORP\\jdoe", "secret", { .target = std::string(40'000, 't'), .require_tls = false });
	CHECK(start_error(long_target) == "the target is longer than 65535 octets in UTF-16");
	// An empty password is a password.
	ldap::sasl_ntlm no_password("CORP\\jdoe", "", plain);
	no_password.prepare({});
	CHECK(no_password.start().has_value());
}

// ---------------------------------------------------------------- security layer

namespace {

constexpr std::uint32_t layer_flags =
  detail::ntlmssp_negotiate_sign | detail::ntlmssp_negotiate_seal | detail::ntlmssp_negotiate_key_exch;

auto le32(std::uint32_t v) -> std::string
{
	std::string out;
	for (unsigned i = 0; i < 4; ++i) {
		out += static_cast<char>((v >> (8 * i)) & 0xFFu);
	}
	return out;
}

auto get_le32(std::string_view s) -> std::uint32_t
{
	std::uint32_t v = 0;
	for (std::size_t i = 4; i > 0; --i) {
		v = v << 8 | static_cast<unsigned char>(s[i - 1]);
	}
	return v;
}

auto bytes_str(std::span<const std::byte> b) -> std::string
{
	return { reinterpret_cast<const char *>(b.data()), b.size() };
}

auto uchars(std::string &s) -> std::span<unsigned char>
{
	return { reinterpret_cast<unsigned char *>(s.data()), s.size() };
}

// The domain controller's side, from OpenSSL and MS-NLMP directly (no
// library code but ntlm_rc4, which the RFC 6229 vectors check): MD5,
// HMAC-MD5, and SIGNKEY / SEALKEY with the magic constants.
auto dc_md5(std::string_view data) -> detail::ntlm_key
{
	detail::ntlm_key out{};
	unsigned int n = 0;
	REQUIRE(EVP_Digest(data.data(), data.size(), out.data(), &n, EVP_md5(), nullptr) == 1);
	return out;
}

auto dc_hmac(std::span<const unsigned char> key, std::string_view data) -> detail::ntlm_key
{
	detail::ntlm_key out{};
	unsigned int n = 0;
	REQUIRE(HMAC(EVP_md5(),
			  key.data(),
			  static_cast<int>(key.size()),
			  reinterpret_cast<const unsigned char *>(data.data()),
			  data.size(),
			  out.data(),
			  &n)
			!= nullptr);
	return out;
}

auto dc_subkey(const detail::ntlm_key &exported, std::string_view direction, std::string_view kind) -> detail::ntlm_key
{
	return dc_md5(key_str(exported) + "session key to " + std::string(direction) + " " + std::string(kind)
				  + " key magic constant" + std::string(1, '\0'));
}

// What a domain controller's layer does: wraps with the server-to-client
// keys, unwraps and checks with the client-to-server ones, each direction
// with its RC4 handle and sequence number. Logs the protected buffers.
class dc_layer final : public ldap::sasl_security_layer
{
  public:
	struct log
	{
		std::vector<std::string> received{};
		std::vector<std::string> sent{};
	};

	dc_layer(const detail::ntlm_key &exported,
	  ldap::sasl_protection protection,
	  std::shared_ptr<log> l = std::make_shared<log>())
	  : protection_(protection), send_sign_(dc_subkey(exported, "server-to-client", "signing")),
		receive_sign_(dc_subkey(exported, "client-to-server", "signing")),
		send_(dc_subkey(exported, "server-to-client", "sealing")),
		receive_(dc_subkey(exported, "client-to-server", "sealing")), log_(std::move(l))
	{}

	[[nodiscard]] auto protection() const noexcept -> ldap::sasl_protection override { return protection_; }
	[[nodiscard]] auto max_wrap_input() const noexcept -> std::size_t override { return std::size_t{ 1 } << 20; }
	[[nodiscard]] auto max_received() const noexcept -> std::size_t override { return std::size_t{ 1 } << 20; }

	[[nodiscard]] auto wrap(std::span<const std::byte> plaintext, std::pmr::vector<std::byte> &out)
	  -> ldap::result<void> override
	{
		std::string message = bytes_str(plaintext);
		const std::string seq = le32(send_seq_++);
		const auto mac = dc_hmac(send_sign_, seq + message);
		std::string checksum(reinterpret_cast<const char *>(mac.data()), 8);
		if (protection_ == ldap::sasl_protection::confidentiality) {
			send_.apply(uchars(message));
		}
		send_.apply(uchars(checksum));
		const std::string buffer = le32(1) + checksum + seq + message;
		log_->sent.push_back(buffer);
		const auto b = std::as_bytes(std::span(buffer));
		out.insert(out.end(), b.begin(), b.end());
		return {};
	}

	[[nodiscard]] auto unwrap(std::span<const std::byte> buffer, std::pmr::vector<std::byte> &out)
	  -> ldap::result<void> override
	{
		const std::string b = bytes_str(buffer);
		log_->received.push_back(b);
		if (b.size() < 16 || get_le32(b) != 1) {
			return ldap::fail(ldap::client_errc::decode_error, "dc: not a signature");
		}
		std::string checksum = b.substr(4, 8);
		const std::uint32_t seq = get_le32(b.substr(12, 4));
		std::string message = b.substr(16);
		if (protection_ == ldap::sasl_protection::confidentiality) {
			receive_.apply(uchars(message));
		}
		receive_.apply(uchars(checksum));
		if (seq != receive_seq_++) {
			return ldap::fail(ldap::client_errc::unexpected_response, "dc: wrong sequence number");
		}
		const auto mac = dc_hmac(receive_sign_, le32(seq) + message);
		if (checksum != std::string(reinterpret_cast<const char *>(mac.data()), 8)) {
			return ldap::fail(ldap::client_errc::unexpected_response, "dc: wrong checksum");
		}
		const auto m = std::as_bytes(std::span(message));
		out.insert(out.end(), m.begin(), m.end());
		return {};
	}

  private:
	ldap::sasl_protection protection_;
	detail::ntlm_key send_sign_;
	detail::ntlm_key receive_sign_;
	detail::ntlm_rc4 send_;
	detail::ntlm_rc4 receive_;
	std::uint32_t send_seq_ = 0;
	std::uint32_t receive_seq_ = 0;
	std::shared_ptr<log> log_;
};

// The library's client layer for `exported`.
auto client_layer(const detail::ntlm_key &exported, ldap::sasl_protection protection)
  -> std::unique_ptr<detail::ntlm_security_layer>
{
	detail::ntlm_session_keys keys;
	REQUIRE(detail::ntlm_derive_session_keys(exported, keys).has_value());
	return std::make_unique<detail::ntlm_security_layer>(keys, protection, std::size_t{ 1 } << 20);
}

auto wrap_with(ldap::sasl_security_layer &layer, std::string_view plaintext) -> std::string
{
	std::pmr::vector<std::byte> out;
	REQUIRE(layer.wrap(std::as_bytes(std::span(plaintext)), out).has_value());
	return bytes_str(out);
}

auto unwrap_with(ldap::sasl_security_layer &layer, std::string_view buffer) -> ldap::result<std::string>
{
	std::pmr::vector<std::byte> out;
	if (auto r = layer.unwrap(std::as_bytes(std::span(buffer)), out); !r) {
		return std::unexpected(std::move(r.error()));
	}
	return bytes_str(out);
}

constexpr detail::ntlm_key spec_random_session_key{ 0x55,
	0x55,
	0x55,
	0x55,
	0x55,
	0x55,
	0x55,
	0x55,
	0x55,
	0x55,
	0x55,
	0x55,
	0x55,
	0x55,
	0x55,
	0x55 };

constexpr detail::ntlm_key
  test_session_key{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF };

}// namespace

TEST_CASE("ntlm: the session security vectors of MS-NLMP section 4.2.4", "[sasl][ntlm][rfc]")
{
	// 4.2.4.2.3 Encrypted Session Key: RC4K(KeyExchangeKey,
	// RandomSessionKey), the KeyExchangeKey being 4.2.4.1.2's SessionBaseKey.
	const auto session_base_key = from_hex("8D E4 0C CA DB C1 4A 82 F1 5C B0 AD 0D E9 5C A3");
	detail::ntlm_key encrypted = spec_random_session_key;
	detail::ntlm_rc4(std::span(reinterpret_cast<const unsigned char *>(session_base_key.data()), 16)).apply(encrypted);
	CHECK(hex_of(encrypted) == "C5 DA D2 54 4F C9 79 90 94 CE 1C E9 0B C9 D0 3E");

	// 4.2.4.4 GSS_WrapEx: SEALKEY, SIGNKEY of the RandomSessionKey.
	detail::ntlm_session_keys keys;
	REQUIRE(detail::ntlm_derive_session_keys(spec_random_session_key, keys).has_value());
	CHECK(hex_of(keys.client_sealing_key) == "59 F6 00 97 3C C4 96 0A 25 48 0A 7C 19 6E 4C 58");
	CHECK(hex_of(keys.client_signing_key) == "47 88 DC 86 1B 47 82 F3 5D 43 FD 98 FE 1A 2D 39");
	// The server-to-client keys follow the same formula (no spec vector):
	// as the mock domain controller derives them.
	CHECK(keys.server_signing_key == dc_subkey(spec_random_session_key, "server-to-client", "signing"));
	CHECK(keys.server_sealing_key == dc_subkey(spec_random_session_key, "server-to-client", "sealing"));

	// The sealed "Plaintext" (UNICODE) and its signature, SeqNum 0: the
	// signature first, then the data.
	const std::string plaintext = u16("Plaintext");
	ldap::sasl_protection protection = ldap::sasl_protection::confidentiality;
	detail::ntlm_security_layer sealing(keys, protection, 1024);
	CHECK(sealing.protection() == protection);
	CHECK(sealing.max_received() == 1024);
	CHECK(sealing.max_wrap_input() == 131'072 - 16);
	CHECK(hex_of(wrap_with(sealing, plaintext))
		  == "01 00 00 00 7F B3 8E C5 C5 5D 49 76 00 00 00 00 "
			 "54 E5 01 65 BF 19 36 DC 99 60 20 C1 81 1B 0F 06 FB 5F");

	// Integrity only: the message in clear, the checksum (4.2.4.4's
	// HMAC_MD5(SigningKey, ConcatenationOf(SeqNum, Message))[0..7],
	// 70 35 28 51 F2 56 43 09) RC4-encrypted with a fresh handle.
	protection = ldap::sasl_protection::integrity;
	detail::ntlm_security_layer signing(keys, protection, 1024);
	std::string checksum = str("70 35 28 51 F2 56 43 09");
	detail::ntlm_rc4(keys.client_sealing_key).apply(uchars(checksum));
	CHECK(hex_of(wrap_with(signing, plaintext)) == hex_of(le32(1) + checksum + le32(0) + plaintext));
}

TEST_CASE("ntlm: a golden security layer from an independent implementation", "[sasl][ntlm][rfc]")
{
	// The output of tests/net/ntlm_golden.py's second part (see the golden
	// AUTHENTICATE_MESSAGE test for what it copies from the library): the
	// same user, password, workstation, target, challenges and timestamp,
	// no TLS (MsvAvChannelBindings Z(16)), confidentiality (ALWAYS_SIGN, SIGN,
	// SEAL, KEY_EXCH), the ExportedSessionKey 00 11 .. FF; then two client
	// buffers through one handle and the server's through the other.
	const std::string negotiate =
	  str("4e544c4d53535000010000003582886200000000280000000000000028000000000000000000000f");
	const std::string challenge = str(
	  "4e544c4d53535000020000000e000e0038000000358289e20123456789abcdef00000000000000003000300046000000"
	  "0a007c4f0000000f4500580041004d0050004c00450002000c0044006f006d00610069006e0001000c00530065007200"
	  "76006500720007000800706f5e4d3c2bdb0100000000");
	const std::string authenticate = str(
	  "4e544c4d53535000030000001800180070000000a800a800880000000800080058000000080008006000000008000800"
	  "68000000100010003001000035828862000000000000000f1a80c2321ae73df95f2fd245d2e3abd443004f0052005000"
	  "6a00f60072006700570053003000310000000000000000000000000000000000000000000000000016bbee80e7babb4c"
	  "50865c80b662ceeb0101000000000000706f5e4d3c2bdb01aaaaaaaaaaaaaaaa0000000002000c0044006f006d006100"
	  "69006e0001000c0053006500720076006500720007000800706f5e4d3c2bdb0106000400020000000a00100000000000"
	  "000000000000000000000000090028006c006400610070002f006400630031002e006500780061006d0070006c006500"
	  "2e006f00720067000000000000000000c9aad552e8cb224de9c0d0bfb5f496ad");
	const std::string client0 =
	  str("0100000000628de40a324257000000006ddb2dd6982411c1ba03715eaa0043eff5f6b1cd43b3c8a5d73508ea4cf487b8");
	const std::string client1 = str("010000006ef72d99b526a86a010000001acad06ca50462");
	const std::string server0 = str("01000000ff8e048cbe7d224f0000000021171bc7e7f69eaa710ca502d5fc7a2c6fd664332b1d");
	const std::string who_am_i = str("301e02010377198017") + "1.3.6.1.4.1.4203.1.11.3";
	const std::string unbind = str("30050201044200");
	const std::string answer = str("3014020103780f0a0100040004008b06") + "u:jdoe";
	CHECK(hex_of(dc_challenge(dc_flags | layer_flags)) == hex_of(challenge));

	// require_tls stays true: the layer stands in for it.
	auto mech = detail::ntlm_test_access::with_challenge("CORP\\j\xC3\xB6rg",
	  "p\xC3\xA4sswort\xE2\x82\xAC",
	  { .workstation = "WS01", .security_layer = ldap::sasl_protection::confidentiality },
	  spec_client_challenge);
	detail::ntlm_test_access::set_session_key(mech, test_session_key);
	mech.prepare({ .host = "dc1.example.org" });
	auto first = mech.start();
	REQUIRE(first.has_value());
	REQUIRE(first->has_value());
	CHECK(hex_of(**first) == hex_of(negotiate));
	CHECK(mech.take_security_layer() == nullptr);
	auto second = mech.step(challenge);
	REQUIRE(second.has_value());
	REQUIRE(second->has_value());
	CHECK(hex_of(**second) == hex_of(authenticate));
	auto layer = mech.take_security_layer();
	REQUIRE(layer != nullptr);
	CHECK(mech.take_security_layer() == nullptr);// once
	CHECK(mech.complete(std::nullopt).has_value());
	CHECK(layer->protection() == ldap::sasl_protection::confidentiality);
	CHECK(layer->max_received() == 0x0100'0000);
	CHECK(hex_of(wrap_with(*layer, who_am_i)) == hex_of(client0));
	CHECK(hex_of(wrap_with(*layer, unbind)) == hex_of(client1));
	auto plain_answer = unwrap_with(*layer, server0);
	REQUIRE(plain_answer.has_value());
	CHECK(hex_of(*plain_answer) == hex_of(answer));

	// A new bind starts afresh: no layer until its AUTHENTICATE_MESSAGE.
	REQUIRE(mech.start().has_value());
	CHECK(mech.take_security_layer() == nullptr);
}

TEST_CASE("ntlm: protected buffers both ways, tampered, replayed or reordered", "[sasl][ntlm]")
{
	for (const auto protection : { ldap::sasl_protection::integrity, ldap::sasl_protection::confidentiality }) {
		CAPTURE(protection);
		auto client = client_layer(test_session_key, protection);
		dc_layer dc(test_session_key, protection);

		// Round trips, the handles and sequence numbers running on.
		for (const std::string_view m :
		  { std::string_view("first PDU"), std::string_view(), std::string_view("third") }) {
			const std::string wrapped = wrap_with(*client, m);
			CHECK(wrapped.size() == 16 + m.size());
			CHECK((wrapped.substr(16) == m) == (protection == ldap::sasl_protection::integrity || m.empty()));
			auto at_dc = unwrap_with(dc, wrapped);
			REQUIRE(at_dc.has_value());
			CHECK(*at_dc == m);
			auto back = unwrap_with(*client, wrap_with(dc, std::string(m) + "!"));
			REQUIRE(back.has_value());
			CHECK(*back == std::string(m) + "!");
		}
		// Appended to what `out` holds already.
		std::pmr::vector<std::byte> out(3, std::byte{ 0x42 });
		const std::string pdu = wrap_with(dc, "more");
		REQUIRE(client->unwrap(std::as_bytes(std::span(pdu)), out).has_value());
		CHECK(bytes_str(out) == "BBBmore");

		const auto refused = [](ldap::result<std::string> r, std::string_view context) {
			REQUIRE_FALSE(r.has_value());
			CHECK(r.error().code == ldap::client_errc::unexpected_response);
			CHECK(r.error().context == context);
		};
		const std::string bad_checksum =
		  "NTLM: a buffer whose checksum does not verify (changed in transit, or not the server's)";
		SECTION("a changed message")
		{
			std::string b = wrap_with(dc, "payload");
			b[18] = static_cast<char>(static_cast<unsigned char>(b[18]) ^ 1U);
			refused(unwrap_with(*client, b), bad_checksum);
		}
		SECTION("a changed checksum")
		{
			std::string b = wrap_with(dc, "payload");
			b[4] = static_cast<char>(static_cast<unsigned char>(b[4]) ^ 0x80U);
			refused(unwrap_with(*client, b), bad_checksum);
		}
		SECTION("a buffer of the client's own (the other direction's keys)")
		{
			refused(unwrap_with(*client, wrap_with(*client, "payload")),
			  "NTLM: a buffer with sequence number 3, 4 expected (replayed, reordered or dropped)");
		}
		SECTION("a replayed buffer")
		{
			const std::string b = wrap_with(dc, "payload");
			REQUIRE(unwrap_with(*client, b).has_value());
			refused(unwrap_with(*client, b),
			  "NTLM: a buffer with sequence number 4, 5 expected (replayed, reordered or dropped)");
		}
		SECTION("a dropped buffer")
		{
			(void)wrap_with(dc, "dropped");
			refused(unwrap_with(*client, wrap_with(dc, "next")),
			  "NTLM: a buffer with sequence number 5, 4 expected (replayed, reordered or dropped)");
		}
		SECTION("a changed sequence number")
		{
			(void)wrap_with(dc, "dropped");
			std::string b = wrap_with(dc, "next");
			b.replace(12, 4, le32(4));
			refused(unwrap_with(*client, b), bad_checksum);
		}
		SECTION("a malformed buffer")
		{
			auto r = unwrap_with(*client, std::string(15, '\x01'));
			REQUIRE_FALSE(r.has_value());
			CHECK(r.error().code == ldap::client_errc::decode_error);
			std::string b = wrap_with(dc, "payload");
			b[0] = '\x02';
			auto v = unwrap_with(*client, b);
			REQUIRE_FALSE(v.has_value());
			CHECK(v.error().context == "NTLM protected buffer: signature Version 2, not 1");
		}
		SECTION("the server's buffers do not verify as the client's")
		{
			dc_layer other(test_session_key, protection);
			auto r = unwrap_with(other, wrap_with(dc, "payload"));
			REQUIRE_FALSE(r.has_value());
		}
	}
}

TEST_CASE("ntlm: a security layer the server does not grant", "[net][sasl][ntlm]")
{
	const auto refused = [](ldap::sasl_protection protection, std::uint32_t flags, std::string_view why) {
		mock_ldap m;
		m.serve({ answer({ sasl_resp(1, 14, dc_challenge(flags)) }), answer({ bind_resp(2) }) });
		ldap::sasl_ntlm mech("CORP\\jdoe", "secret", { .security_layer = protection });
		auto r = m.run(m.conn.sasl_bind(mech));
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == ldap::client_errc::security_layer_unavailable);
		CHECK(r.error().code == ldap::cond::access_denied);
		CHECK(std::string(r.error().context) == "sasl bind GSS-SPNEGO: " + std::string(why));
		CHECK(m.conn.is_open());
		CHECK(m.conn.security_layer() == ldap::sasl_protection::none);
		m.check_server();
		REQUIRE(m.log.received.size() == 2);
		CHECK(m.log.received[1] == abort_req(2));
	};
	refused(ldap::sasl_protection::confidentiality,
	  dc_flags | detail::ntlmssp_negotiate_sign | detail::ntlmssp_negotiate_key_exch,
	  "the server does not grant the confidentiality security layer (no NTLMSSP_NEGOTIATE_SEAL in the "
	  "CHALLENGE_MESSAGE)");
	refused(ldap::sasl_protection::integrity,
	  dc_flags | detail::ntlmssp_negotiate_key_exch,
	  "the server does not grant the integrity security layer (no NTLMSSP_NEGOTIATE_SIGN in the CHALLENGE_MESSAGE)");
	refused(ldap::sasl_protection::integrity,
	  (dc_flags | detail::ntlmssp_negotiate_sign) & ~detail::ntlmssp_negotiate_128,
	  "the server does not grant the integrity security layer (no NTLMSSP_NEGOTIATE_KEY_EXCH, "
	  "NTLMSSP_NEGOTIATE_128 in the CHALLENGE_MESSAGE)");
	// Integrity does not need NTLMSSP_NEGOTIATE_SEAL; the layer seals all
	// the same, as an LDAP DC expects.
	mock_ldap m;
	m.serve({ answer({ sasl_resp(
				1, 14, dc_challenge(dc_flags | detail::ntlmssp_negotiate_sign | detail::ntlmssp_negotiate_key_exch)) }),
	  answer({ sasl_resp(2, 0) }) });
	ldap::sasl_ntlm mech("CORP\\jdoe", "secret", { .security_layer = ldap::sasl_protection::integrity });
	REQUIRE(m.run(m.conn.sasl_bind(mech)).has_value());
	CHECK(m.conn.security_layer() == ldap::sasl_protection::confidentiality);
	REQUIRE(m.log.received.size() == 2);
	auto auth = detail::parse_ntlm_authenticate(sasl_creds(m.log.received[1]));
	REQUIRE(auth.has_value());
	// ALWAYS_SIGN, SIGN, KEY_EXCH and the rest both sides set.
	CHECK(auth->negotiate_flags == 0x6288'8215u);
	CHECK(auth->encrypted_random_session_key.size() == 16);
}

TEST_CASE("ntlm: a security layer only without TLS", "[sasl][ntlm]")
{
	const auto hash = cert_hash();
	ldap::sasl_ntlm mech("CORP\\jdoe", "secret", { .security_layer = ldap::sasl_protection::integrity });
	mech.prepare({ .host = "dc1",
	  .tls = true,
	  .bindings = { .tls_server_end_point = hash, .default_type = ldap::channel_binding_type::tls_server_end_point } });
	auto r = mech.start();
	REQUIRE_FALSE(r.has_value());
	CHECK(r.error().code == ldap::client_errc::security_layer_unavailable);
	CHECK(r.error().context
		  == "a SASL security layer cannot be used over TLS (Active Directory refuses one there; "
			 "sasl_ntlm_options::security_layer)");

	// Without TLS require_tls (true here) is not consulted, and the
	// NEGOTIATE_MESSAGE asks for ALWAYS_SIGN, SIGN and KEY_EXCH (and SEAL).
	mech.prepare({ .host = "dc1" });
	auto integrity = mech.start();
	REQUIRE(integrity.has_value());
	REQUIRE(integrity->has_value());
	CHECK(get_le32(std::string_view(**integrity).substr(12, 4)) == 0x6288'8215u);
	ldap::sasl_ntlm sealing("CORP\\jdoe", "secret", { .security_layer = ldap::sasl_protection::confidentiality });
	sealing.prepare({});
	auto confidentiality = sealing.start();
	REQUIRE(confidentiality.has_value());
	REQUIRE(confidentiality->has_value());
	CHECK(get_le32(std::string_view(**confidentiality).substr(12, 4)) == 0x6288'8235u);

	ldap::sasl_ntlm small(
	  "CORP\\jdoe", "secret", { .security_layer = ldap::sasl_protection::integrity, .max_receive_size = 15 });
	small.prepare({});
	auto too_small = small.start();
	REQUIRE_FALSE(too_small.has_value());
	CHECK(too_small.error().code == ldap::client_errc::encode_error);
	CHECK(too_small.error().context == "max_receive_size 15 out of range (16 to 4294967295)");
}

namespace {

auto creds_of(const ldap::message &m) -> std::optional<std::string>
{
	const auto *req = std::get_if<ldap::bind_request>(&m.op);
	if (req == nullptr) {
		return std::nullopt;
	}
	const auto *sasl = std::get_if<ldap::sasl_auth>(&req->authentication);
	if (sasl == nullptr || sasl->mechanism != "GSS-SPNEGO" || !sasl->credentials) {
		return std::nullopt;
	}
	return std::string(*sasl->credentials);
}

// What the mock domain controller learns from the AUTHENTICATE_MESSAGE:
// the ExportedSessionKey (EncryptedRandomSessionKey decrypted with the
// SessionBaseKey), after checking the NTProofStr and the MIC keyed with it.
auto dc_exported_key(std::string_view negotiate,
  std::string_view challenge,
  std::string_view authenticate,
  std::string &error) -> detail::ntlm_key
{
	auto auth = detail::parse_ntlm_authenticate(authenticate);
	auto key = ntowfv2("secret", "jdoe", "CORP");
	if (!auth || !key || auth->nt_challenge_response.size() < 48 || auth->encrypted_random_session_key.size() != 16) {
		error = "dc: a malformed AUTHENTICATE_MESSAGE";
		return {};
	}
	const std::string temp = auth->nt_challenge_response.substr(16);
	const auto proof = dc_hmac(*key, key_str(spec_server_challenge) + temp);
	if (auth->nt_challenge_response.substr(0, 16) != key_str(proof)) {
		error = "dc: wrong NTProofStr";
		return {};
	}
	const auto session_base_key = dc_hmac(*key, key_str(proof));
	std::string exported = auth->encrypted_random_session_key;
	detail::ntlm_rc4(session_base_key).apply(uchars(exported));
	std::string zeroed(authenticate);
	zeroed.replace(detail::ntlm_authenticate_mic_offset, 16, 16, '\0');
	const auto mic = dc_hmac(uchars(exported), std::string(negotiate) + std::string(challenge) + zeroed);
	if (key_str(auth->mic) != key_str(mic)) {
		error = "dc: wrong MIC";
		return {};
	}
	detail::ntlm_key out{};
	std::ranges::copy(uchars(exported), out.begin());
	return out;
}

// A domain controller: the NTLM exchange, success, then its layer on its
// end, and one search answered (an entry and its done) through it.
auto serve_ntlm_layer(net::transport t,
  ldap::sasl_protection protection,
  std::shared_ptr<dc_layer::log> log,
  std::string &error) -> capy::task<void>
{
	net::read_buffer buf;
	const std::string challenge = dc_challenge(dc_flags | layer_flags);
	auto first = co_await net::read_message(t, buf, as_server);
	const auto negotiate = first ? creds_of(*first) : std::nullopt;
	if (!negotiate) {
		error = "dc: no NEGOTIATE_MESSAGE";
		co_return;
	}
	if (!co_await net::write_message(t, sasl_resp(first->id, 14, challenge))) {
		error = "dc: write";
		co_return;
	}
	auto second = co_await net::read_message(t, buf, as_server);
	const auto authenticate = second ? creds_of(*second) : std::nullopt;
	if (!authenticate) {
		error = "dc: no AUTHENTICATE_MESSAGE";
		co_return;
	}
	const auto exported = dc_exported_key(*negotiate, challenge, *authenticate, error);
	if (!error.empty()) {
		co_return;
	}
	if (!co_await net::write_message(t, sasl_resp(second->id, 0))) {
		error = "dc: write";
		co_return;
	}
	if (!net::detail::install_security_layer(t, buf, std::make_unique<dc_layer>(exported, protection, log))) {
		error = "dc: install";
		co_return;
	}
	auto search = co_await net::read_message(t, buf, as_server);
	if (!search) {
		error = "dc: search read: " + std::string(search.error().message());
		co_return;
	}
	if (!std::holds_alternative<ldap::search_request>(search->op)) {
		error = "dc: not a search";
		co_return;
	}
	for (const auto &m :
	  { entry_msg(search->id, "uid=jdoe,ou=people,dc=example,dc=org", "Jdoe Sealed"), done_msg(search->id) }) {
		if (!co_await net::write_message(t, m)) {
			error = "dc: search write";
			co_return;
		}
	}
}

}// namespace

TEST_CASE("ntlm: a bind with a security layer, then a search through it", "[net][sasl][ntlm]")
{
	for (const auto protection : { ldap::sasl_protection::integrity, ldap::sasl_protection::confidentiality }) {
		CAPTURE(protection);
		mock_ldap m;
		std::string error;
		auto log = std::make_shared<dc_layer::log>();
		outcome<void> server;
		// The DC seals once SIGN is negotiated, SEAL or not (Samba's
		// force_wrap_seal for LDAP, as Windows), and so does the client.
		spawn(m.ioc, serve_ntlm_layer(m.server_end(), ldap::sasl_protection::confidentiality, log, error), server);
		ldap::sasl_ntlm mech("CORP\\jdoe", "secret", { .security_layer = protection });
		auto bound = m.run(m.conn.sasl_bind(mech));
		REQUIRE(bound.has_value());
		CHECK(m.conn.security_layer() == ldap::sasl_protection::confidentiality);
		auto found = m.run(m.conn.search(people_search()));
		drive_until(m.ioc, [&] { return server.done(); });
		CHECK(error.empty());
		REQUIRE(found.has_value());
		REQUIRE(found->size() == 1);
		CHECK((*found)[0].dn == "uid=jdoe,ou=people,dc=example,dc=org");

		// The server checked the search's buffer(s) and sent two of its own;
		// sealed, neither side's text shows on the wire.
		REQUIRE_FALSE(log->received.empty());
		REQUIRE(log->sent.size() == 2);
		std::string received;
		for (const auto &b : log->received) {
			received += b.substr(16);
		}
		CHECK_FALSE(received.contains("ou=people"));
		CHECK_FALSE(log->sent[0].contains("Jdoe Sealed"));

		// StartTLS would go below the layer.
		auto tls = m.run(m.conn.start_tls());
		REQUIRE_FALSE(tls.has_value());
		CHECK(tls.error().code == ldap::client_errc::security_layer_in_effect);
	}
}
