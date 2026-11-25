// Deterministic driver for ntlm_fuzz under ctest.
#include "../src/ntlm_message.hpp"
#include "jhetz/ldap/testing/server_codec.hpp"

#include "replay.hpp"

#include <array>
#include <string>
#include <string_view>

auto main(int argc, char **argv) -> int
{
	namespace fuzz = jhetz::ldap::fuzz;
	namespace detail = jhetz::ldap::detail;
	using namespace std::string_view_literals;
	const auto messages = std::to_array<std::string_view>({
	  // MS-NLMP section 4.2.4.3.
	  "NTLMSSP\0\x02\0\0\0\x0c\0\x0c\0\x38\0\0\0\x33\x82\x8a\xe2\x01\x23\x45\x67\x89\xab\xcd\xef"
	  "\0\0\0\0\0\0\0\0\x24\0\x24\0\x44\0\0\0\x06\0\x70\x17\0\0\0\x0f"
	  "S\0e\0r\0v\0e\0r\0\x02\0\x0c\0D\0o\0m\0a\0i\0n\0\x01\0\x0c\0S\0e\0r\0v\0e\0r\0\0\0\0\0"sv,
	  // MS-NLMP section 4.2.4.4: the signature, then the sealed data.
	  "\x01\0\0\0\x7f\xb3\x8e\xc5\xc5\x5d\x49\x76\0\0\0\0"
	  "\x54\xe5\x01\x65\xbf\x19\x36\xdc\x99\x60\x20\xc1\x81\x1b\x0f\x06\xfb\x5f"sv,
	});
	const detail::ntlm_challenge_message dc{ .target_name = std::string("E\0X\0", 4),
		.negotiate_flags = detail::ntlmssp_negotiate_unicode | detail::ntlmssp_negotiate_extended_sessionsecurity
						   | detail::ntlmssp_negotiate_target_info | detail::ntlmssp_negotiate_version,
		.server_challenge = { 1, 2, 3, 4, 5, 6, 7, 8 },
		.target_info = { { .av_id = detail::ntlm_av_id::msv_av_nb_domain_name, .value = std::string("E\0X\0", 4) },
		  { .av_id = detail::ntlm_av_id::msv_av_flags, .value = std::string("\x01\0\0\0", 4) },
		  { .av_id = detail::ntlm_av_id::msv_av_timestamp,
			.value = std::string("\x70\x6f\x5e\x4d\x3c\x2b\xdb\x01", 8) } },
		.version = detail::ntlm_version{ .product_major_version = 10 } };
	const detail::ntlm_authenticate_message auth{ .lm_challenge_response = std::string(24, '\0'),
		.nt_challenge_response = std::string(48, '\x11'),
		.domain_name = std::string("E\0X\0", 4),
		.user_name = std::string("j\0d\0", 4),
		.workstation = {},
		.encrypted_random_session_key = {},
		.negotiate_flags = 0x2288'0205u,
		.version = {},
		.mic = {} };
	fuzz::replay_config cfg{ .name = "ntlm_fuzz_replay",
		.extension = ".bin",
		.seeds = {},
		.interesting = { 0x00,
		  0x01,
		  0x02,
		  0x03,
		  0x04,
		  0x06,
		  0x07,
		  0x08,
		  0x09,
		  0x0A,
		  0x0C,
		  0x24,
		  0x38,
		  0x40,
		  0x58,
		  0xFF,
		  'N',
		  'T',
		  'L',
		  'M',
		  'S',
		  'P' },
		.mutation_runs = 150'000,
		.random_runs = 50'000,
		.max_random_size = 96,
		.rng_seed = 0x5EED'0A71'0000'0009ull };
	for (const auto m : messages) {
		cfg.seeds.push_back(fuzz::to_input(m));
	}
	cfg.seeds.push_back(fuzz::to_input(jhetz::ldap::testing::encode_ntlm_challenge(dc)));
	cfg.seeds.push_back(fuzz::to_input(*detail::encode_ntlm_authenticate(auth)));
	return fuzz::replay_main(argc, argv, cfg);
}
