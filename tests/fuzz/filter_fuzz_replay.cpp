// Deterministic driver for filter_fuzz under ctest.
#include "jhetz/ldap/filter.hpp"
#include "replay.hpp"

#include <array>
#include <string_view>

auto main(int argc, char **argv) -> int
{
	namespace ldap = jhetz::ldap;
	namespace fuzz = jhetz::ldap::fuzz;
	const auto texts = std::to_array<std::string_view>({
	  "(&(objectClass=person)(|(uid=jdoe)(mail=j*@*.org))(!(disabled=TRUE)))",
	  "(cn=Jo*hn*Sm*ith)",
	  "(uidNumber>=1000)",
	  "(uidNumber<=2000)",
	  "(sn~=smyth)",
	  "(mail=*)",
	  "(cn:dn:2.5.13.5:=John)",
	  "(:caseExactMatch:=x\\2ay)",
	  "(:DN:2.4.6.8.10:=Dino)",
	  "(o=Parens R Us \\28for all your parenthetical needs\\29)",
	  R"((bin=\00\00\00\04))",
	  "(cn;lang-en=\\c4\\8d)",
	  "(2.5.4.3=x)",
	  "(&)",
	  "(|)",
	  "(!(&(|)))",
	  "uid=jdoe",
	  "(&(&(&(&(&(&(&(&(a=b)))))))))",
	});
	fuzz::replay_config cfg{ .name = "filter_fuzz_replay",
		.extension = ".txt",
		.seeds = {},
		.interesting = { '(',
		  ')',
		  '&',
		  '|',
		  '!',
		  '=',
		  '*',
		  '~',
		  '<',
		  '>',
		  ':',
		  '\\',
		  ';',
		  '.',
		  '-',
		  '0',
		  '1',
		  '2',
		  'a',
		  'c',
		  'd',
		  'n',
		  'f',
		  'D',
		  'N',
		  ' ',
		  0x00,
		  0x80,
		  0xA0,
		  0xA3,
		  0xA4,
		  0x87,
		  0x04,
		  0x30 },
		.mutation_runs = 30'000,// each input runs ~10 encode/decode/parse cycles
		.random_runs = 15'000,
		.max_random_size = 40,
		.rng_seed = 0x5EED'1DA9'0000'0003ull };
	for (const auto t : texts) {
		cfg.seeds.push_back(fuzz::to_input(t));
	}
	for (const auto t : { texts[0], texts[6], texts[1] }) {
		auto f = ldap::filter::parse(t);
		if (!f) {
			return 1;
		}
		ldap::ber::writer w;
		if (!ldap::encode_filter(w, *f)) {
			return 1;
		}
		cfg.seeds.push_back(fuzz::to_input(w.bytes()));
	}
	return fuzz::replay_main(argc, argv, cfg);
}
