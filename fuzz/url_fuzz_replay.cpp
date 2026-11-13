// Deterministic driver for url_fuzz under ctest.
#include "replay.hpp"

#include <array>
#include <string_view>

auto main(int argc, char **argv) -> int
{
	namespace fuzz = jhetz::ldap::fuzz;
	const auto texts = std::to_array<std::string_view>({
	  "ldap:///o=University%20of%20Michigan,c=US",
	  "ldap://ldap1.example.net/o=University%20of%20Michigan,c=US?postalAddress",
	  "ldap://ldap1.example.net:6666/o=University%20of%20Michigan,c=US??sub?(cn=Babs%20Jensen)",
	  "LDAP://ldap1.example.com/c=GB?objectClass?ONE",
	  "ldap://ldap2.example.com/o=Question%3f,c=US?mail",
	  // NOLINTNEXTLINE(bugprone-suspicious-missing-comma): one RFC 4516 URL, split so "???(" is no trigraph
	  "ldap://ldap3.example.com/o=Babsco,c=US???"
	  "(four-octet=%5c00%5c00%5c00%5c04)",
	  "ldap://ldap.example.com/o=An%20Example%5C2C%20Inc.,c=US",
	  "ldap:///??sub??"
	  "!e-bindname=cn=Manager%2cdc=example%2cdc=com",
	  "ldaps://[2001:db8::7]:1636/dc=x?cn,mail?one?(&(a=1)(!(b=*)))?x,!1.2.3=v",
	  "ldap://[fe80::1%25eth0]:389",
	  "ldap://[::ffff:192.0.2.1]/",
	  "ldapi://%2Fvar%2Frun%2Fslapd%2Fldapi",
	  "ldaps://127.0.0.1:636/cn=J%C3%BCrgen,dc=x",
	  "ldap://h/????x,y=a%2Cb",
	  "ldap://",
	  "ldap://[fe80::1%25a%3Ab]",// zone with an encoded ':'
	});
	fuzz::replay_config cfg{ .name = "url_fuzz_replay",
		.extension = ".txt",
		.seeds = {},
		.interesting = { ':',
		  '/',
		  '?',
		  ',',
		  '=',
		  '!',
		  '%',
		  '[',
		  ']',
		  '.',
		  '(',
		  ')',
		  '*',
		  '&',
		  '|',
		  '@',
		  '#',
		  ' ',
		  '\\',
		  '0',
		  '1',
		  '2',
		  '5',
		  '9',
		  'a',
		  'c',
		  'f',
		  'l',
		  'd',
		  'p',
		  's',
		  'i',
		  'A',
		  'F',
		  0x00,
		  0xC3 },
		.mutation_runs = 150'000,
		.random_runs = 50'000,
		.max_random_size = 48,
		.rng_seed = 0x5EED'0A71'0000'0005ull };
	for (const auto t : texts) {
		cfg.seeds.push_back(fuzz::to_input(t));
	}
	return fuzz::replay_main(argc, argv, cfg);
}
