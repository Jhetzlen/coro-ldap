// Paged search benchmark: ldap::search_paged against an in-process server,
// for several page sizes.
//   jhetz_ldap_paged_bench [entries=20000] [runs=9]
#include "jhetz/ldap/controls.hpp"

#include "socket_pair.hpp"

#include <algorithm>
#include <array>
#include <charconv>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <format>
#include <print>
#include <string>
#include <variant>
#include <vector>

namespace ldap = jhetz::ldap;
namespace net = jhetz::ldap::net;
namespace capy = boost::capy;
namespace corosio = boost::corosio;

namespace {

using clock = std::chrono::steady_clock;

auto offset_of(std::string_view cookie) -> std::size_t
{
	std::size_t n = 0;
	(void)std::from_chars(cookie.data(), cookie.data() + cookie.size(), n);
	return n;
}

// The page `r` asks for and the next cookie, in `bytes`; null on failure.
auto page(const ldap::message &r, std::size_t total, std::vector<std::byte> &bytes) -> const std::vector<std::byte> *
{
	auto pr = ldap::find_paged(r.controls);
	if (!pr || !*pr) {
		return nullptr;
	}
	const std::size_t from = offset_of((*pr)->cookie);
	const std::size_t to = std::min(total, from + static_cast<std::size_t>((*pr)->size));
	bytes.clear();
	for (std::size_t i = from; i < to; ++i) {
		const std::string dn = std::format("uid=u{},ou=people,dc=example,dc=org", i);
		auto e = ldap::encode(
		  ldap::message{ r.id, ldap::search_result_entry{ dn, { ldap::partial_attribute{ "cn", { "User" } } } } });
		if (!e) {
			return nullptr;
		}
		bytes.insert(bytes.end(), e->begin(), e->end());
	}
	ldap::message done{ r.id, ldap::search_result_done{ ldap::ldap_result{ 0 } } };
	const std::string next = to < total ? std::to_string(to) : std::string();
	done.controls.push_back(*ldap::encode_paged_results({ 0, next }));
	auto d = ldap::encode(done);
	if (!d) {
		return nullptr;
	}
	bytes.insert(bytes.end(), d->begin(), d->end());
	return &bytes;
}

// Answers every paged SearchRequest with its page and the next cookie.
auto serve(net::transport t, std::size_t total) -> capy::task<void>
{
	std::vector<std::byte> bytes;
	co_await ldap::bench::serve_each<ldap::search_request>(
	  std::move(t), [total, &bytes](const ldap::message &r) { return page(r, total, bytes); });
}

auto drain(ldap::connection &c, std::int32_t page_size, std::size_t &entries) -> capy::task<bool>
{
	entries = 0;
	auto s = co_await ldap::search_paged(c, { .base = ldap::dn{ "ou=people,dc=example,dc=org" } }, page_size);
	if (!s) {
		co_return false;
	}
	while (true) {
		auto e = co_await s->next();
		if (!e) {
			co_return false;
		}
		if (!*e) {
			co_return true;
		}
		++entries;
	}
}

struct timings
{
	std::vector<double> ns_per_page{};
	std::vector<double> ns_per_entry{};
	bool ok = true;

	// NOLINTNEXTLINE(bugprone-easily-swappable-parameters): pages, then entries, as printed
	void add(clock::duration d, std::size_t pages, std::size_t entries)
	{
		const auto ns = static_cast<double>(std::chrono::duration_cast<std::chrono::nanoseconds>(d).count());
		ns_per_page.push_back(ns / static_cast<double>(pages));
		ns_per_entry.push_back(ns / static_cast<double>(entries));
	}
	void print(std::int32_t page_size)
	{
		std::ranges::sort(ns_per_page);
		std::ranges::sort(ns_per_entry);
		std::println(
		  "page size {:<5} best {:9.0f} ns/page {:7.0f} ns/entry   median {:9.0f} ns/page {:7.0f} ns/entry{}",
		  page_size,
		  ns_per_page.front(),
		  ns_per_entry.front(),
		  ns_per_page[ns_per_page.size() / 2],
		  ns_per_entry[ns_per_entry.size() / 2],
		  ok ? "" : "   (FAILED)");
	}
};

constexpr std::array<std::int32_t, 3> page_sizes{ 1, 10, 100 };

auto drive(ldap::connection &c,
  corosio::local_stream_socket &server,
  std::size_t total,
  int runs,
  std::array<timings, page_sizes.size()> &out) -> capy::task<void>
{
	for (int run = 0; run < runs; ++run) {
		for (std::size_t i = 0; i < page_sizes.size(); ++i) {
			std::size_t entries = 0;
			const auto start = clock::now();
			out[i].ok = co_await drain(c, page_sizes[i], entries) && entries == total && out[i].ok;
			const auto size = static_cast<std::size_t>(page_sizes[i]);
			out[i].add(clock::now() - start, (total + size - 1) / size, total);
		}
	}
	c.close();
	server.close();
}

}// namespace

// NOLINTNEXTLINE(bugprone-exception-escape): a benchmark, terminating on an exception is fine
auto main(int argc, char *const *argv) -> int
{
	constexpr std::size_t default_entries = 20000;
	constexpr std::size_t default_runs = 9;
	const std::size_t total = std::max<std::size_t>(ldap::bench::arg(argc, argv, 1, default_entries), 1);
	const int runs = static_cast<int>(std::max<std::size_t>(ldap::bench::arg(argc, argv, 2, default_runs), 1));

	std::array<timings, page_sizes.size()> out;
	if (!ldap::bench::run_pair([total](net::transport t) { return serve(std::move(t), total); },
		  [&](const corosio::io_context & /*ioc*/, ldap::connection &c, auto &server) {
			  return drive(c, server, total, runs, out);
		  })) {
		return EXIT_FAILURE;
	}

	std::println("{} entries per search, {} runs, one thread", total, runs);
	bool ok = true;
	for (std::size_t i = 0; i < page_sizes.size(); ++i) {
		out[i].print(page_sizes[i]);
		ok = ok && out[i].ok;
	}
	return ok ? EXIT_SUCCESS : EXIT_FAILURE;
}
