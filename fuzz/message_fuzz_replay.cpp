// Deterministic driver for message_fuzz (see message_fuzz.cpp), so its
// properties run under ctest with any compiler, without libFuzzer.
// Seeds: every sample message of the unit tests, a few with controls.
#include "../tests/sample_messages.hpp"
#include "replay.hpp"

#include <cstdint>
#include <vector>

auto main(int argc, char **argv) -> int
{
	namespace ldap = jhetz::ldap;
	namespace fuzz = jhetz::ldap::fuzz;
	fuzz::replay_config cfg{ .name = "message_fuzz_replay",
		.extension = ".ber",
		.seeds = {},
		.interesting = { 0x00,
		  0x01,
		  0x02,
		  0x03,
		  0x04,
		  0x0A,
		  0x30,
		  0x31,
		  0x42,
		  0x4A,
		  0x50,
		  0x60,
		  0x61,
		  0x63,
		  0x64,
		  0x65,
		  0x66,
		  0x73,
		  0x77,
		  0x78,
		  0x79,
		  0x7F,
		  0x80,
		  0x81,
		  0x82,
		  0x84,
		  0x87,
		  0x8A,
		  0xA0,
		  0xA3,
		  0xA4,
		  0xA9,
		  0xFF },
		.mutation_runs = 150'000,
		.random_runs = 50'000,
		.max_random_size = 64,
		.rng_seed = 0x5EED'1DA9'0000'0002ull };
	std::size_t i = 0;
	for (auto m : ldap::test::sample_messages()) {
		if (i++ % 8 == 0) {
			m.controls = ldap::test::sample_controls();
		}
		auto bytes = ldap::encode(m);
		if (!bytes) {
			return 1;
		}
		cfg.seeds.push_back(fuzz::to_input(*bytes));
	}
	return fuzz::replay_main(argc, argv, cfg);
}
