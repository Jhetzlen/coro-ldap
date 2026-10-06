// Deterministic driver for schema_fuzz (see schema_fuzz.cpp), so its
// properties run under ctest with any compiler, without libFuzzer.
// Seeds: OpenLDAP and Active Directory definitions as servers send them.
#include "replay.hpp"

#include <string_view>

int main(int argc, char **argv)
{
	namespace fuzz = jhetz::ldap::fuzz;
	const std::string_view texts[] = {
		"( 2.5.4.3 NAME ( 'cn' 'commonName' ) DESC 'RFC4519: common name(s) for which the entity is known by' SUP name "
		")",
		"( 2.5.4.41 NAME 'name' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX "
		"1.3.6.1.4.1.1466.115.121.1.15{32768} )",
		"( 2.5.18.1 NAME 'createTimestamp' EQUALITY generalizedTimeMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.24 "
		"SINGLE-VALUE NO-USER-MODIFICATION USAGE directoryOperation )",
		"( 1.2.840.113556.1.2.102 NAME 'memberOf' SYNTAX '1.3.6.1.4.1.1466.115.121.1.12' NO-USER-MODIFICATION "
		"X-ORIGIN 'iPlanet' )",
		"( 1.3.6.1.4.1.42.2.27.8.1.1 NAME 'pwdAttribute' SYNTAX 1.3.6.1.4.1.1466.115.121.1.38 X-ORIGIN ( 'a' 'b' ) )",
		"( 2.5.6.6 NAME 'person' SUP top STRUCTURAL MUST ( sn $ cn ) MAY ( userPassword $ telephoneNumber ) )",
		"( 1.2.840.113556.1.5.9 NAME 'user' SUP organizationalPerson STRUCTURAL MUST (objectClass ) MAY (o $ b ) )",
		"( 1.2 NAME 'it\\27s' DESC 'back\\5cslash' )",
		"(1.2 NAME 'tight' SINGLE-VALUE)",
		"( 1.2.3 NAME 'unterminated )",
		"",
	};
	fuzz::replay_config cfg{ .name = "schema_fuzz_replay",
		.extension = ".txt",
		.seeds = {},
		.interesting = { '(', ')', '\'', '$', '{', '}', ' ', '\\', '.', '1', 'N', 'S', 'X', '-' },
		.mutation_runs = 100'000,
		.random_runs = 30'000,
		.max_random_size = 64,
		.rng_seed = 0x5EED'0A71'0000'0007ull };
	for (auto t : texts) cfg.seeds.push_back(fuzz::to_input(t));
	return fuzz::replay_main(argc, argv, cfg);
}
