// Decode benchmark (DESIGN.md section 8): a stream of large SearchResultEntry
// messages decoded
//   1. with the default resource (the heap), as decode() does by default;
//   2. into one std::pmr::monotonic_buffer_resource with an initial buffer,
//      release()d after each message (what a connection would do per response);
//   3. the same without an initial buffer (release() then returns the chunks
//      to the heap, so each message allocates them again).
// Reports the best wall time of several runs over the whole stream and the
// number of allocations that reach the heap (operator new).
//
//   jhetz_ldap_decode_bench [entries=1000] [attributes=30] [values=3] [runs=15]
//
// Built with -DJHETZ_LDAP_BUILD_BENCH=ON (off by default, not part of ctest);
// use an optimized build without sanitizers for meaningful numbers.
#include "jhetz/ldap/message.hpp"

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <memory_resource>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace ldap = jhetz::ldap;

namespace {

class counting_resource final : public std::pmr::memory_resource
{
  public:
	std::size_t allocations = 0;
	std::size_t bytes = 0;

  private:
	void *do_allocate(std::size_t n, std::size_t align) override
	{
		++allocations;
		bytes += n;
		return std::pmr::new_delete_resource()->allocate(n, align);
	}
	void do_deallocate(void *p, std::size_t n, std::size_t align) override
	{
		std::pmr::new_delete_resource()->deallocate(p, n, align);
	}
	bool do_is_equal(const std::pmr::memory_resource &other) const noexcept override { return this == &other; }
};

struct stream
{
	std::vector<std::byte> bytes;
	std::vector<std::span<const std::byte>> pdus;
	std::size_t values = 0;
};

// `entries` entries of `attributes` attributes with `values` values each
// (10 to 60 bytes, like names, mail addresses, descriptions); every 20th entry
// also carries a 64 KiB jpegPhoto and a 4 KiB userCertificate.
stream make_stream(std::size_t entries, std::size_t attributes, std::size_t values)
{
	stream s;
	std::vector<std::size_t> sizes;
	for (std::size_t i = 0; i < entries; ++i) {
		ldap::search_result_entry e;
		e.object_name = "uid=user" + std::to_string(i) + ",ou=people,ou=engineering,dc=example,dc=org";
		for (std::size_t a = 0; a < attributes; ++a) {
			auto &pa = e.attributes.emplace_back();
			pa.type = "attribute" + std::to_string(a);
			for (std::size_t v = 0; v < values; ++v) {
				pa.values.emplace_back(10 + (i * 7 + a * 13 + v * 29) % 51, static_cast<char>('a' + (a + v) % 26));
				++s.values;
			}
		}
		if (i % 20 == 0) {
			auto &photo = e.attributes.emplace_back();
			photo.type = "jpegPhoto";
			photo.values.emplace_back(64 * 1024, '\xff');
			auto &cert = e.attributes.emplace_back();
			cert.type = "userCertificate;binary";
			cert.values.emplace_back(4 * 1024, '\x30');
			s.values += 2;
		}
		const auto bytes = ldap::encode(ldap::message{ static_cast<std::int32_t>(i + 1), std::move(e) }).value();
		s.bytes.insert(s.bytes.end(), bytes.begin(), bytes.end());
		sizes.push_back(bytes.size());
	}
	std::size_t offset = 0;
	for (auto n : sizes) {
		s.pdus.push_back(std::span<const std::byte>(s.bytes).subspan(offset, n));
		offset += n;
	}
	return s;
}

// Touches the decoded data so nothing is optimized away.
std::size_t consume(const ldap::message &m)
{
	const auto &e = std::get<ldap::search_result_entry>(m.op);
	std::size_t n = e.object_name.size();
	for (const auto &a : e.attributes)
		for (const auto &v : a.values) n += v.size() + static_cast<unsigned char>(v.empty() ? 0 : v[0]);
	return n;
}

struct outcome
{
	double best_ms = 0;
	double median_ms = 0;
	std::size_t allocations = 0;// heap allocations over one pass of the stream
	std::size_t allocated_bytes = 0;
	std::size_t checksum = 0;
};

enum class mode { heap, arena_with_buffer, arena_without_buffer };

// One pass over the stream. The arena lives across messages and is released
// after each, as a connection would do per response.
std::size_t pass(const stream &s, mode how, std::vector<std::byte> &buffer)
{
	std::size_t sum = 0;
	if (how == mode::heap) {
		for (auto pdu : s.pdus) sum += consume(ldap::decode(pdu).value());
		return sum;
	}
	std::optional<std::pmr::monotonic_buffer_resource> arena;
	if (how == mode::arena_with_buffer)
		arena.emplace(buffer.data(), buffer.size());
	else
		arena.emplace();
	ldap::decode_options options;
	options.memory = &*arena;
	for (auto pdu : s.pdus) {
		{
			const auto m = ldap::decode(pdu, options).value();
			sum += consume(m);
		}
		arena->release();
	}
	return sum;
}

outcome measure(const stream &s, mode how, int runs)
{
	std::vector<std::byte> buffer(how == mode::arena_with_buffer ? 256 * 1024 : 0);
	outcome out;
	{
		counting_resource counting;
		auto *old = std::pmr::set_default_resource(&counting);
		out.checksum = pass(s, how, buffer);
		std::pmr::set_default_resource(old);
		out.allocations = counting.allocations;
		out.allocated_bytes = counting.bytes;
	}
	std::vector<double> times;
	for (int r = 0; r < runs; ++r) {
		const auto start = std::chrono::steady_clock::now();
		const auto sum = pass(s, how, buffer);
		const auto end = std::chrono::steady_clock::now();
		if (sum != out.checksum) std::abort();
		times.push_back(std::chrono::duration<double, std::milli>(end - start).count());
	}
	std::sort(times.begin(), times.end());
	out.best_ms = times.front();
	out.median_ms = times[times.size() / 2];
	return out;
}

std::size_t arg(int argc, char **argv, int i, std::size_t fallback)
{
	return argc > i ? static_cast<std::size_t>(std::strtoull(argv[i], nullptr, 10)) : fallback;
}

}// namespace

int main(int argc, char **argv)
{
	const std::size_t entries = arg(argc, argv, 1, 1000);
	const std::size_t attributes = arg(argc, argv, 2, 30);
	const std::size_t values = arg(argc, argv, 3, 3);
	const int runs = static_cast<int>(arg(argc, argv, 4, 15));
	if (entries == 0 || runs == 0) return 2;

	const auto s = make_stream(entries, attributes, values);
	std::printf(
	  "stream: %zu SearchResultEntry PDUs, %zu attributes x %zu values each (+ jpegPhoto and\n"
	  "userCertificate every 20th entry), %zu values, %.1f MiB; best / median of %d runs\n\n",
	  s.pdus.size(),
	  attributes,
	  values,
	  s.values,
	  static_cast<double>(s.bytes.size()) / (1024.0 * 1024.0),
	  runs);
	std::printf("%-44s %9s %9s %13s %11s %12s\n", "mode", "best ms", "median", "heap allocs", "per entry", "heap MiB");
	const struct
	{
		const char *name;
		mode how;
	} modes[] = {
		{ "default resource (heap)", mode::heap },
		{ "monotonic arena, 256 KiB buffer, release()", mode::arena_with_buffer },
		{ "monotonic arena, no buffer, release()", mode::arena_without_buffer },
	};
	for (const auto &m : modes) {
		const auto o = measure(s, m.how, runs);
		std::printf("%-44s %9.2f %9.2f %13zu %11.1f %12.1f\n",
		  m.name,
		  o.best_ms,
		  o.median_ms,
		  o.allocations,
		  static_cast<double>(o.allocations) / static_cast<double>(s.pdus.size()),
		  static_cast<double>(o.allocated_bytes) / (1024.0 * 1024.0));
	}
	return 0;
}
