// Deterministic driver for ber_fuzz under ctest: random BER-like buffers
// and mutations of valid encodings.
#include "jhetz/ldap/ber.hpp"

#include "replay.hpp"

#include <array>
#include <cstdint>
#include <limits>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace {

namespace ber = jhetz::ldap::ber;
namespace fuzz = jhetz::ldap::fuzz;

auto seeds() -> std::vector<fuzz::input>
{
	std::vector<fuzz::input> out;
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
	out.push_back(fuzz::to_input(w.take()));

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
	out.push_back(fuzz::to_input(w.take()));

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
		out.push_back(fuzz::to_input(w.take()));
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
		out.push_back(fuzz::to_input(w.take()));
	}

	// Deep nesting (beyond the default limit of 32), built inside out.
	fuzz::input deep{ 0x05, 0x00 };
	for (int i = 0; i < 40; ++i) {
		deep.insert(deep.begin(), { 0x30, static_cast<std::uint8_t>(deep.size()) });
	}
	out.push_back(deep);
	return out;
}

}// namespace

auto main(int argc, char **argv) -> int
{
	// The mutations' bytes, then BER tags for the random inputs.
	static constexpr std::array<std::uint8_t, 19> interesting{
		0x00, 0x01, 0x1F, 0x30, 0x7F, 0x80, 0x81, 0x82, 0x84, 0x85, 0xFE, 0xFF, 0x02, 0x04, 0x05, 0x0A, 0x31, 0x60, 0xA0
	};
	return fuzz::replay_main(argc,
	  argv,
	  { .name = "ber_fuzz_replay",
		.extension = ".ber",
		.seeds = seeds(),
		.interesting = { interesting.begin(), interesting.end() },
		.mutation_runs = 200'000,
		.random_runs = 100'000,
		.max_random_size = 48,
		.rng_seed = 0x5EED'1DA9'0000'0001ull });
}
