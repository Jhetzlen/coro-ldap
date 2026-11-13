// Deterministic driver for matching_fuzz under ctest.
#include "replay.hpp"

#include <array>
#include <string>
#include <string_view>

auto main(int argc, char **argv) -> int
{
	namespace fuzz = jhetz::ldap::fuzz;
	using namespace std::string_view_literals;
	const auto texts = std::to_array<std::string_view>({
	  "\x09"
	  "foo bar  FOO BAR"sv,
	  "\x06"
	  "Stra\u00DFeSTRASSE"sv,
	  "\x02"
	  "\u0130i\u0307"sv,
	  "\x03"
	  "\uFB01fi"sv,
	  "\x05"
	  "caf\u00E9cafe\u0301"sv,
	  "\x02"
	  "a \u0301a\u0301"sv,
	  "\x04"
	  "a\uE000a\uFFFD"sv,
	  "\x01"
	  "\xC3\xED\xA0\x80"sv,
	  "\x03"
	  "\u05D0a1\u2163"sv,
	  "\x07"
	  "\u00AD\u200B\t\n\u3000x"sv,
	  "\x04"
	  "1000-0"sv,
	  "\x0F"
	  "+1 555-123-4567+15551234567"sv,
	  "\x10"
	  "CN=Jane Doe,DC=Examplecn=jane doe,dc=example"sv,
	  "\x00"
	  "cn=#0C044A616E65+sn=a\\2A*"sv,
	  "\x00"sv,
	  // Types by name and OID, resolved or not; a big #hex INTEGER; nested DNs.
	  "\x10"
	  "uid=a+cn=b+foo=cCN=B+userid=A+FOO=c"sv,
	  "\x0F"
	  "2.5.4.3=a+bar=bcommonName=a+1.2.3=b"sv,
	  "\x00"
	  "x=#0209FF0000000000000000+y=#020200FF"sv,
	  "\x00"
	  "member=member=uid\\=x\\,dc\\=y"sv,
	});
	fuzz::replay_config cfg{ .name = "matching_fuzz_replay",
		.extension = ".txt",
		.seeds = {},
		.interesting = { ' ',
		  'A',
		  'a',
		  'I',
		  'i',
		  '*',
		  '\\',
		  '-',
		  '0',
		  '=',
		  ',',
		  '+',
		  '#',
		  0x00,
		  0x09,
		  0xC3,
		  0x9F,
		  0xC4,
		  0xB0,
		  0xCC,
		  0x81,
		  0xE2,
		  0x80,
		  0x8B,
		  0xEF,
		  0xBF,
		  0xBD,
		  0xF0 },
		.mutation_runs = 30'000,
		.random_runs = 15'000,
		.max_random_size = 24,
		.rng_seed = 0x5EED'0A71'0000'0008ull };
	for (const auto t : texts) {
		cfg.seeds.push_back(fuzz::to_input(t));
	}
	return fuzz::replay_main(argc, argv, cfg);
}
