// Deterministic driver for value_fuzz (see value_fuzz.cpp), so its
// properties run under ctest with any compiler, without libFuzzer.
// Seeds: GeneralizedTime in every form (RFC 4517 section 3.3.13), integers,
// booleans, DNs and the AD FILETIME limits.
#include "replay.hpp"

#include <string_view>

int main(int argc, char **argv)
{
	namespace fuzz = jhetz::ldap::fuzz;
	const std::string_view texts[] = {
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
	};
	fuzz::replay_config cfg{ .name = "value_fuzz_replay",
		.extension = ".txt",
		.seeds = {},
		.interesting = { '0', '1', '2', '5', '9', 'Z', '+', '-', '.', ',', '=', '\\', ' ', 'T', 'F', 0x00 },
		.mutation_runs = 100'000,
		.random_runs = 30'000,
		.max_random_size = 32,
		.rng_seed = 0x5EED'0A71'0000'0006ull };
	for (auto t : texts) {
		cfg.seeds.push_back(fuzz::to_input(t));
	}
	return fuzz::replay_main(argc, argv, cfg);
}
