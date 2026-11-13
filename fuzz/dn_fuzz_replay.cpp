// Deterministic driver for dn_fuzz under ctest.
#include "replay.hpp"

#include <array>
#include <string_view>

auto main(int argc, char **argv) -> int
{
	namespace fuzz = jhetz::ldap::fuzz;
	const auto texts = std::to_array<std::string_view>({
	  "UID=jsmith,DC=example,DC=net",
	  "OU=Sales+CN=J.  Smith,DC=example,DC=net",
	  R"(CN=James \"Jim\" Smith\, III,DC=example,DC=net)",
	  "CN=Before\\0dAfter,DC=example,DC=net",
	  "1.3.6.1.4.1.1466.0=#04024869,DC=example,DC=com",
	  R"(CN=Lu\C4\8Di\C4\87)",
	  R"(cn=\ lead\#x\ ,dc=x)",
	  "cn = a + sn = b , dc = c",
	  "",
	});
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
	for (const auto t : texts) {
		cfg.seeds.push_back(fuzz::to_input(t));
	}
	return fuzz::replay_main(argc, argv, cfg);
}
