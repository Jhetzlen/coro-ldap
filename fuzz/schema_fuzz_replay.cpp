// Deterministic driver for schema_fuzz under ctest.
#include "replay.hpp"

#include <array>
#include <string_view>

auto main(int argc, char **argv) -> int
{
	namespace fuzz = jhetz::ldap::fuzz;
	const auto texts = std::to_array<std::string_view>({
	  // NOLINTNEXTLINE(bugprone-suspicious-missing-comma): one definition, wrapped at the column limit
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
	  "( 2.5.6.0 NAME 'top' ABSTRACT MUST objectClass )",
	  "( 1.2.6 NAME 'self' SUP ( self $ missing $ 1.2.6 ) AUXILIARY MUST ( self $ 1.2.6 $ objectClass ) MAY x )",
	  "( 1.2.7 NAME ( 'a' 'b' ) sup b must ( a $ 'b' $ 1. ) )",
	  "( 1.2.8 NAME 'tight' SUP (top$person) MUST (sn$cn) MAY ( a$ b $c ) )",
	  "( 1.2.9 NAME 'bare' SUP top$person MUST sn$cn MAY a $ 'b' $c X-A x$y )",
	  "( 1.2 NAME 'it\\27s' DESC 'back\\5cslash' )",
	  "(1.2 NAME 'tight' SINGLE-VALUE)",
	  "( 1.2.4 NAME 'named' SYNTAX directoryString )",
	  "( 1.2.10 NAME 'spacelen' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 {256} SINGLE-VALUE )",
	  "( 1.2.11 NAME 'junklen' SYNTAX '1.3.6.1.4.1.1466.115.121.1.15{\r\nforged' X-NDS_SYNTAX '1' )",
	  "( 1.2.3 NAME 'unterminated )",
	  // Several definitions, one per line: a SUP chain into a cycle, an
	  // unknown superclass, MUSTs shared and objectClass by OID and alias.
	  "( 2.5.4.0 NAME ( 'objectClass' 'oc' ) SYNTAX 1.3.6.1.4.1.1466.115.121.1.38 )\n"
	  "( 2.5.6.0 NAME 'top' ABSTRACT MUST 2.5.4.0 )\n"
	  "( 1.3 NAME 'a' SUP (top$b) MUST (oc$cn$sn) )\n"
	  "( 1.4 NAME 'b' SUP ( a $ gone ) MUST ( SN $ 1.5 ) MAY cn )",
	  "",
	});
	fuzz::replay_config cfg{ .name = "schema_fuzz_replay",
		.extension = ".txt",
		.seeds = {},
		.interesting = { '(', ')', '\'', '$', '\n', '{', '}', ' ', '\\', '.', '1', 'N', 'S', 'X', '-' },
		.mutation_runs = 100'000,
		.random_runs = 30'000,
		.max_random_size = 64,
		.rng_seed = 0x5EED'0A71'0000'0007ull };
	for (const auto t : texts) {
		cfg.seeds.push_back(fuzz::to_input(t));
	}
	return fuzz::replay_main(argc, argv, cfg);
}
