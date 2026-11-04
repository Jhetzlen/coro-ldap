// Deterministic driver for ntlm_layer_fuzz (see ntlm_layer_fuzz.cpp), so its
// properties run under ctest with any compiler, without libFuzzer.
// Seeds: the server's first protected buffers, integrity and
// confidentiality, of a short message and of an LDAP whoami response (valid
// for the target's unwrap()), and messages to wrap: empty, one octet, and a
// 16-octet one shaped like a signature. The confidentiality whoami seed must
// equal the golden security layer test's server0 (the same keys), which the
// replay checks rather than adding it as a duplicate seed.
#include "jhetz/ldap/sasl_ntlm.hpp"

#include "ntlm_layer.hpp"
#include "replay.hpp"

#include <array>
#include <cstdio>
#include <memory_resource>
#include <print>
#include <span>
#include <string_view>

auto main(int argc, char **argv) -> int
{
	namespace fuzz = jhetz::ldap::fuzz;
	namespace ldap = jhetz::ldap;
	namespace detail = jhetz::ldap::detail;
	using namespace std::string_view_literals;
	const auto keys = fuzz::ntlm_layer_derive_keys();
	if (!keys) {
		std::println(stderr, "ntlm_layer_fuzz_replay: the session keys do not derive");
		return 1;
	}
	fuzz::replay_config cfg{ .name = "ntlm_layer_fuzz_replay",
		.extension = ".bin",
		.seeds = {},
		.interesting = { 0x00, 0x01, 0x02, 0x04, 0x10, 0x30, 0x7F, 0x80, 0xFF },
		.mutation_runs = 8'000,
		.random_runs = 4'000,
		.max_random_size = 64,
		.rng_seed = 0x5EED'0A71'0000'000Aull };
	const auto messages = std::to_array<std::string_view>({
	  "hello"sv,
	  // A WhoAmI response "u:jdoe" (message 3).
	  "\x30\x14\x02\x01\x03\x78\x0f\x0a\x01\x00\x04\x00\x04\x00\x8b\x06u:jdoe"sv,
	});
	for (const auto protection : { ldap::sasl_protection::integrity, ldap::sasl_protection::confidentiality }) {
		for (const auto m : messages) {
			detail::ntlm_security_layer server(keys->server, protection, fuzz::ntlm_layer_max_received);
			std::pmr::vector<std::byte> buffer;
			if (!server.wrap(std::as_bytes(std::span(m)), buffer)) {
				std::println(stderr, "ntlm_layer_fuzz_replay: a seed does not wrap");
				return 1;
			}
			cfg.seeds.push_back(fuzz::to_input(buffer));
		}
	}
	// The golden security layer test's server0: the confidentiality whoami seed.
	constexpr auto golden_server0 =
	  "\x01\0\0\0\xff\x8e\x04\x8c\xbe\x7d\x22\x4f\0\0\0\0"
	  "\x21\x17\x1b\xc7\xe7\xf6\x9e\xaa\x71\x0c\xa5\x02\xd5\xfc\x7a\x2c\x6f\xd6\x64\x33\x2b\x1d"sv;
	if (cfg.seeds.back() != fuzz::to_input(golden_server0)) {
		std::println(stderr, "ntlm_layer_fuzz_replay: the confidentiality whoami seed is not the golden server0");
		return 1;
	}
	const auto others = std::to_array<std::string_view>({
	  ""sv,
	  "\x01"sv,
	  "\x01\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0"sv,
	});
	for (const auto m : others) {
		cfg.seeds.push_back(fuzz::to_input(m));
	}
	return fuzz::replay_main(argc, argv, cfg);
}
