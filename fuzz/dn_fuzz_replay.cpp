// Deterministic driver for dn_fuzz (see dn_fuzz.cpp), so its properties run
// under ctest with any compiler, without libFuzzer.
// Seeds: the RFC 4514 section 4 examples and escaping edge cases.
#include "replay.hpp"

#include <string_view>

auto main(int argc, char **argv) -> int
{
	namespace fuzz = jhetz::ldap::fuzz;
	const std::string_view texts[] = {
		"UID=jsmith,DC=example,DC=net",
		"OU=Sales+CN=J.  Smith,DC=example,DC=net",
		"CN=James \\\"Jim\\\" Smith\\, III,DC=example,DC=net",
		"CN=Before\\0dAfter,DC=example,DC=net",
		"1.3.6.1.4.1.1466.0=#04024869,DC=example,DC=com",
		"CN=Lu\\C4\\8Di\\C4\\87",
		"cn=\\ lead\\#x\\ ,dc=x",
		"cn = a + sn = b , dc = c",
		"",
	};
	fuzz::replay_config cfg{ .name = "dn_fuzz_replay",
		.extension = ".txt",
		.seeds = {},
		.interesting = { ',',
		  '+',
		  '=',
		  '\\',
		  '#',
		  '"',
		  ' ',
		  ';',
		  '<',
		  '>',
		  '.',
		  '-',
		  '0',
		  '1',
		  '9',
		  'a',
		  'c',
		  'f',
		  'n',
		  'A',
		  'F',
		  0x00,
		  0x0D,
		  0xC4 },
		.mutation_runs = 100'000,
		.random_runs = 50'000,
		.max_random_size = 40,
		.rng_seed = 0x5EED'1DA9'0000'0004ull };
	for (auto t : texts) {
		cfg.seeds.push_back(fuzz::to_input(t));
	}
	return fuzz::replay_main(argc, argv, cfg);
}
