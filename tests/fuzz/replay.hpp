// Shared pieces of the deterministic fuzz replay drivers (*_fuzz_replay.cpp),
// which run a libFuzzer entry point under ctest with any compiler.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <format>
#include <print>
#include <span>
#include <string>
#include <string_view>
#include <vector>

extern "C" auto LLVMFuzzerTestOneInput(const std::uint8_t *data, std::size_t size) -> int;

namespace jhetz::ldap::fuzz {

// splitmix64: tiny, deterministic, good enough for input generation.
struct rng
{
	std::uint64_t state;
	auto next() -> std::uint64_t
	{
		std::uint64_t z = (state += 0x9E3779B97F4A7C15ull);
		z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
		z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
		return z ^ (z >> 31);
	}
	auto below(std::size_t n) -> std::size_t { return static_cast<std::size_t>(next() % n); }
	auto byte() -> std::uint8_t { return static_cast<std::uint8_t>(next() & 0xFFu); }
};

using input = std::vector<std::uint8_t>;

inline auto to_input(std::span<const std::byte> v) -> input
{
	input out(v.size());
	for (std::size_t i = 0; i < v.size(); ++i) {
		out[i] = std::to_integer<std::uint8_t>(v[i]);
	}
	return out;
}

inline auto to_input(std::string_view s) -> input { return { s.begin(), s.end() }; }

inline void run(const input &in) { LLVMFuzzerTestOneInput(in.data(), in.size()); }

// Random edits: bit flips, `interesting` bytes, insertions, deletions,
// truncation, random bytes.
inline void mutate(rng &r, input &v, std::span<const std::uint8_t> interesting)
{
	const std::size_t count = 1 + r.below(4);
	for (std::size_t i = 0; i < count; ++i) {
		switch (r.below(6)) {
		case 0:
			if (!v.empty()) {
				v[r.below(v.size())] ^= static_cast<std::uint8_t>(1u << r.below(8));
			}
			break;
		case 1:
			if (!v.empty()) {
				v[r.below(v.size())] = interesting[r.below(interesting.size())];
			}
			break;
		case 2:
			v.insert(v.begin() + static_cast<std::ptrdiff_t>(r.below(v.size() + 1)),
			  r.below(2) == 0 ? interesting[r.below(interesting.size())] : r.byte());
			break;
		case 3:
			if (!v.empty()) {
				v.erase(v.begin() + static_cast<std::ptrdiff_t>(r.below(v.size())));
			}
			break;
		case 4:
			if (!v.empty()) {
				v.resize(r.below(v.size()));
			}
			break;
		default:
			if (!v.empty()) {
				v[r.below(v.size())] = r.byte();
			}
			break;
		}
	}
}

// Writes seeds as DIR/seed-NN<extension> (the libFuzzer seed corpus).
inline auto write_seeds(const char *dir, const std::vector<input> &inputs, const char *extension) -> int
{
	for (std::size_t i = 0; i < inputs.size(); ++i) {
		const std::string path = std::format("{}/seed-{:02}{}", dir, i, extension);
		std::FILE *f = std::fopen(path.c_str(), "wb");
		if (f == nullptr) {
			std::perror(path.c_str());
			return 1;
		}
		const bool ok = inputs[i].empty() || std::fwrite(inputs[i].data(), 1, inputs[i].size(), f) == inputs[i].size();
		if (std::fclose(f) != 0 || !ok) {
			std::perror(path.c_str());
			return 1;
		}
	}
	std::println("wrote {} seeds to {}", inputs.size(), dir);
	return 0;
}

struct replay_config
{
	const char *name;// for messages
	const char *extension;// of the seed files
	std::vector<input> seeds;
	std::vector<std::uint8_t> interesting;// bytes favoured by mutations and random inputs
	std::size_t mutation_runs = 100'000;
	std::size_t random_runs = 50'000;
	std::size_t max_random_size = 48;
	std::uint64_t rng_seed = 1;
};

// `<name> --write-seeds DIR` writes the seeds and exits; otherwise runs the
// seeds, their prefixes and mutations, and random inputs.
inline auto replay_main(int argc, char **argv, const replay_config &cfg) -> int
{
	if (argc == 3 && std::string_view(argv[1]) == "--write-seeds") {
		return write_seeds(argv[2], cfg.seeds, cfg.extension);
	}
	if (argc != 1) {
		std::println(stderr, "usage: {} [--write-seeds DIR]", argv[0]);
		return 2;
	}
	rng r{ cfg.rng_seed };
	std::size_t runs = 0;
	for (const auto &s : cfg.seeds) {
		run(s);
		++runs;
		for (std::size_t n = 0; n < s.size(); ++n) {
			run(input(s.begin(), s.begin() + static_cast<std::ptrdiff_t>(n)));
			++runs;
		}
	}
	for (std::size_t i = 0; i < cfg.mutation_runs; ++i) {
		auto v = cfg.seeds[r.below(cfg.seeds.size())];
		mutate(r, v, cfg.interesting);
		run(v);
		++runs;
	}
	for (std::size_t i = 0; i < cfg.random_runs; ++i) {
		input v(r.below(cfg.max_random_size));
		for (auto &b : v) {
			b = r.below(4) != 0 ? cfg.interesting[r.below(cfg.interesting.size())] : r.byte();
		}
		run(v);
		++runs;
	}
	std::println("{}: {} inputs, no property violations", cfg.name, runs);
	return 0;
}

}// namespace jhetz::ldap::fuzz
