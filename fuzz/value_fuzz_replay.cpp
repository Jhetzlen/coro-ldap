// Deterministic driver for value_fuzz under ctest.
#include "replay.hpp"

#include <array>
#include <string_view>

auto main(int argc, char **argv) -> int
{
	namespace fuzz = jhetz::ldap::fuzz;
	using namespace std::string_view_literals;
	const auto texts = std::to_array<std::string_view>({
	  "20240229123456Z",
	  "2024022912Z",
	  "202402291230Z",
	  "20240229123045.999Z",
	  "20240229123045,5Z",
	  "2024022912.5Z",
	  "202402291230.25Z",
	  "20240229140000+0200",
	  "20240229070000-05",
	  "20240229123060Z",
	  "00000101000000+2359",
	  "99991231235959-2359",
	  "-9223372036854775808",
	  "18446744073709551615",
	  "255",
	  "0",
	  "TRUE",
	  "FALSE",
	  "cn=Jane Doe+uid=jd,ou=people,dc=example,dc=org",
	  "cn=\\23x\\2C,dc=org",
	  "",
	  // FILETIME limits: lowest accepted date (ad::pwd_set_now), first
	  // rejected, highest date clock_cast, ad::never (not converted).
	  "-1",
	  "-2",
	  "9223372036854775806",
	  "9223372036854775807",
	  // userAccountControl: normal_account | account_disable, the 32-bit
	  // limits and the first values out of range.
	  "514",
	  "-2147483648",
	  "4294967295",
	  "-2147483649",
	  "4294967296",
	  // Binary SIDs: S-1-5-32-544, S-1-0, a domain SID, a hex authority.
	  "\x01\x02\x00\x00\x00\x00\x00\x05\x20\x00\x00\x00\x20\x02\x00\x00"sv,
	  "\x01\x00\x00\x00\x00\x00\x00\x00"sv,
	  "\x01\x05\x00\x00\x00\x00\x00\x05\x15\x00\x00\x00\xdc\xf4\xdc\x3b\x83\x3d\x2b\x46\x82\x8b\xa6\x28\x50\x04\x00\x00"sv,
	  "\x01\x01\x12\x34\x56\x78\x9a\xbc\x01\x00\x00\x00"sv,
	  // Text SIDs.
	  "S-1-5-32-544",
	  "S-1-0",
	  "S-1-5-21-1004336348-1177238915-682003330-1104",
	  "s-1-0x123456789ABC-1",
	  // Binary GUID of 00112233-4455-6677-8899-aabbccddeeff, then text GUIDs.
	  "\x33\x22\x11\x00\x55\x44\x77\x66\x88\x99\xaa\xbb\xcc\xdd\xee\xff"sv,
	  "00112233-4455-6677-8899-aabbccddeeff",
	  "{00112233-4455-6677-8899-AABBCCDDEEFF}",
	});
	fuzz::replay_config cfg{ .name = "value_fuzz_replay",
		.extension = ".txt",
		.seeds = {},
		.interesting = { '0',
		  '1',
		  '2',
		  '5',
		  '9',
		  'Z',
		  '+',
		  '-',
		  '.',
		  ',',
		  '=',
		  '\\',
		  ' ',
		  'T',
		  'F',
		  'S',
		  'x',
		  'a',
		  '{',
		  '}',
		  0x00,
		  0x01,
		  0x05,
		  0xff },
		.mutation_runs = 100'000,
		.random_runs = 30'000,
		.max_random_size = 32,
		.rng_seed = 0x5EED'0A71'0000'0006ull };
	for (const auto t : texts) {
		cfg.seeds.push_back(fuzz::to_input(t));
	}
	return fuzz::replay_main(argc, argv, cfg);
}
