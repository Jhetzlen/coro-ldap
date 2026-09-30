// Deterministic driver for LLVMFuzzerTestOneInput (see ber_fuzz.cpp), so the
// fuzz properties run under ctest with any compiler, without libFuzzer.
//
// Inputs: pseudo-random buffers biased toward BER-looking bytes, plus random
// mutations (bit flips, interesting bytes, insertions, deletions, truncation)
// of valid encodings built with ber::writer.
#include "jhetz/ldap/ber.hpp"

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <limits>
#include <span>
#include <string>
#include <string_view>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *data, std::size_t size);

namespace {

namespace ber = jhetz::ldap::ber;

// splitmix64: tiny, deterministic, good enough for input generation.
struct rng
{
	std::uint64_t state;
	std::uint64_t next()
	{
		std::uint64_t z = (state += 0x9E3779B97F4A7C15ull);
		z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
		z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
		return z ^ (z >> 31);
	}
	std::size_t below(std::size_t n) { return static_cast<std::size_t>(next() % n); }
	std::uint8_t byte() { return static_cast<std::uint8_t>(next() & 0xFFu); }
};

std::vector<std::uint8_t> to_u8(std::span<const std::byte> v)
{
	std::vector<std::uint8_t> out(v.size());
	for (std::size_t i = 0; i < v.size(); ++i) out[i] = std::to_integer<std::uint8_t>(v[i]);
	return out;
}

std::vector<std::vector<std::uint8_t>> seeds()
{
	std::vector<std::vector<std::uint8_t>> out;
	ber::writer w;

	// Anonymous simple bind request.
	w.constructed(ber::tags::sequence, [](ber::writer &m) {
		m.integer(1);
		m.constructed(ber::application(0), [](ber::writer &b) {
			b.integer(3);
			b.octet_string(std::string_view{});
			b.octet_string(std::string_view{}, ber::context(0));
		});
	});
	out.push_back(to_u8(w.take()));

	// Search-request-like nesting with sets, enums, booleans and a long string.
	w.constructed(ber::tags::sequence, [](ber::writer &m) {
		m.integer(0x7FFF'FFFF);
		m.constructed(ber::application(3), [](ber::writer &s) {
			s.octet_string("ou=people,dc=example,dc=org");
			s.enumerated(2);
			s.enumerated(0);
			s.integer(500);
			s.integer(10);
			s.boolean(false);
			s.constructed(ber::context(0), [](ber::writer &f) {
				f.octet_string("objectClass", ber::context(3));
				f.constructed(ber::context(1), [](ber::writer &o) { o.null(ber::context(7)); });
			});
			s.constructed(ber::tags::sequence, [](ber::writer &a) {
				a.octet_string("uid");
				a.octet_string(std::string(200, 'x'));
			});
		});
		m.constructed(ber::context(0),
		  [](ber::writer &c) { c.constructed(ber::tags::set, [](ber::writer &x) { x.boolean(true); }); });
	});
	out.push_back(to_u8(w.take()));

	// Paged-results control: BER encapsulated in an OCTET STRING.
	{
		ber::writer inner;
		inner.constructed(ber::tags::sequence, [](ber::writer &v) {
			v.integer(100);
			v.octet_string("cookie");
		});
		const auto value = inner.take();
		w.constructed(ber::tags::sequence, [&](ber::writer &c) {
			c.octet_string("1.2.840.113556.1.4.319");
			c.boolean(true);
			c.octet_string(std::span<const std::byte>(value));
		});
		out.push_back(to_u8(w.take()));
	}

	// Integers at the interesting boundaries.
	constexpr auto lo = std::numeric_limits<std::int64_t>::min();
	constexpr auto hi = std::numeric_limits<std::int64_t>::max();
	for (std::int64_t v : { std::int64_t{ 0 },
		   std::int64_t{ -1 },
		   std::int64_t{ 127 },
		   std::int64_t{ 128 },
		   std::int64_t{ -129 },
		   lo,
		   hi }) {
		w.integer(v);
		out.push_back(to_u8(w.take()));
	}

	// Deep nesting (beyond the default limit of 32), built inside out.
	std::vector<std::uint8_t> deep{ 0x05, 0x00 };
	for (int i = 0; i < 40; ++i) { deep.insert(deep.begin(), { 0x30, static_cast<std::uint8_t>(deep.size()) }); }
	out.push_back(deep);
	return out;
}

void run(const std::vector<std::uint8_t> &input) { LLVMFuzzerTestOneInput(input.data(), input.size()); }

void mutate(rng &r, std::vector<std::uint8_t> &v)
{
	static constexpr std::array<std::uint8_t, 12> interesting{
		0x00, 0x01, 0x1F, 0x30, 0x7F, 0x80, 0x81, 0x82, 0x84, 0x85, 0xFE, 0xFF
	};
	const std::size_t count = 1 + r.below(4);
	for (std::size_t i = 0; i < count; ++i) {
		switch (r.below(6)) {
		case 0:
			if (!v.empty()) v[r.below(v.size())] ^= static_cast<std::uint8_t>(1u << r.below(8));
			break;
		case 1:
			if (!v.empty()) v[r.below(v.size())] = interesting[r.below(interesting.size())];
			break;
		case 2:
			v.insert(v.begin() + static_cast<std::ptrdiff_t>(r.below(v.size() + 1)), r.byte());
			break;
		case 3:
			if (!v.empty()) v.erase(v.begin() + static_cast<std::ptrdiff_t>(r.below(v.size())));
			break;
		case 4:
			if (!v.empty()) v.resize(r.below(v.size()));
			break;
		default:
			if (!v.empty()) v[r.below(v.size())] = r.byte();
			break;
		}
	}
}

}// namespace

// `ber_fuzz_replay --write-seeds DIR` writes the seed inputs to DIR (used to
// refresh ldap/fuzz/corpus/ber_fuzz/, the libFuzzer seed corpus) and exits.
static int write_seeds(const char *dir)
{
	const auto inputs = seeds();
	for (std::size_t i = 0; i < inputs.size(); ++i) {
		char name[64];
		std::snprintf(name, sizeof name, "/seed-%02zu.ber", i);
		const std::string path = std::string(dir) + name;
		std::FILE *f = std::fopen(path.c_str(), "wb");
		if (f == nullptr) {
			std::perror(path.c_str());
			return 1;
		}
		const bool ok = std::fwrite(inputs[i].data(), 1, inputs[i].size(), f) == inputs[i].size();
		if (std::fclose(f) != 0 || !ok) {
			std::perror(path.c_str());
			return 1;
		}
	}
	std::printf("wrote %zu seeds to %s\n", inputs.size(), dir);
	return 0;
}

int main(int argc, char **argv)
{
	if (argc == 3 && std::string_view(argv[1]) == "--write-seeds") return write_seeds(argv[2]);
	if (argc != 1) {
		std::fprintf(stderr, "usage: %s [--write-seeds DIR]\n", argv[0]);
		return 2;
	}

	rng r{ 0x5EED'1DA9'0000'0001ull };
	const auto seed_inputs = seeds();
	std::size_t runs = 0;

	for (const auto &s : seed_inputs) {
		run(s);
		++runs;
		// Every prefix: exercises the framer's "need more bytes" paths.
		for (std::size_t n = 0; n < s.size(); ++n) {
			run(std::vector<std::uint8_t>(s.begin(), s.begin() + static_cast<std::ptrdiff_t>(n)));
			++runs;
		}
	}

	constexpr std::size_t mutation_runs = 200'000;
	for (std::size_t i = 0; i < mutation_runs; ++i) {
		auto v = seed_inputs[r.below(seed_inputs.size())];
		mutate(r, v);
		run(v);
		++runs;
	}

	constexpr std::size_t random_runs = 100'000;
	static constexpr std::array<std::uint8_t, 10> ber_like{
		0x01, 0x02, 0x04, 0x05, 0x0A, 0x30, 0x31, 0x60, 0x80, 0xA0
	};
	for (std::size_t i = 0; i < random_runs; ++i) {
		std::vector<std::uint8_t> v(r.below(48));
		for (auto &b : v)
			b = r.below(2) == 0 ? ber_like[r.below(ber_like.size())] : static_cast<std::uint8_t>(r.below(8));
		for (std::size_t k = 0; k < v.size() / 4; ++k)
			if (!v.empty()) v[r.below(v.size())] = r.byte();
		run(v);
		++runs;
	}

	std::printf("ber_fuzz_replay: %zu inputs, no property violations\n", runs);
	return 0;
}
