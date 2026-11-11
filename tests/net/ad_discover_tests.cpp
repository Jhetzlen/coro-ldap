// ad::order_srv (RFC 2782) and ad::discover_domain_controllers /
// discover_global_catalogs with a scripted resolver: the SRV names asked
// for, the URLs built, sites, internationalized names and errors.
#include "jhetz/ldap/ad/discover.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <cstdint>
#include <limits>
#include <map>
#include <string>
#include <string_view>
#include <vector>

namespace ldap = jhetz::ldap;
namespace ad = jhetz::ldap::ad;
using Catch::Matchers::ContainsSubstring;

namespace {

// A generator returning the scripted values in turn, then 0.
struct scripted
{
	using result_type = std::uint32_t;
	std::vector<std::uint32_t> values;
	std::size_t next = 0;
	static constexpr auto min() -> result_type { return 0; }
	static constexpr auto max() -> result_type { return std::numeric_limits<result_type>::max(); }
	auto operator()() -> result_type { return next < values.size() ? values[next++] : 0; }
};

auto targets(const std::vector<ad::srv_record> &records) -> std::vector<std::string>
{
	std::vector<std::string> out;
	out.reserve(records.size());
	for (const auto &r : records) {
		out.push_back(r.target);
	}
	return out;
}

auto texts(const std::vector<ldap::url> &urls) -> std::vector<std::string>
{
	std::vector<std::string> out;
	out.reserve(urls.size());
	for (const auto &u : urls) {
		out.emplace_back(u.to_string());
	}
	return out;
}

// A resolver answering from `zone` and logging the names asked for.
struct fake_dns
{
	std::map<std::string, std::vector<ad::srv_record>> zone;
	std::vector<std::string> asked{};

	auto resolver() -> ad::srv_resolver
	{
		return [this](std::string_view name) -> ldap::result<std::vector<ad::srv_record>> {
			asked.emplace_back(name);
			const auto it = zone.find(std::string(name));
			return it == zone.end() ? std::vector<ad::srv_record>{} : it->second;
		};
	}
};

}// namespace

TEST_CASE("ad::order_srv: priority first, then weighted (RFC 2782)", "[ad][discover]")
{
	const std::vector<ad::srv_record> records{ { .priority = 10, .weight = 0, .target = "c" },
		{ .priority = 0, .weight = 60, .target = "a1" },
		{ .priority = 0, .weight = 40, .target = "a2" },
		{ .priority = 5, .weight = 0, .target = "b" } };
	// Draws modulo the total weight + 1: 0..60 picks a1, 61..100 picks a2.
	scripted low{ .values = { 30 } };
	CHECK(targets(ad::order_srv(records, low)) == std::vector<std::string>{ "a1", "a2", "b", "c" });
	scripted high{ .values = { 61 } };
	CHECK(targets(ad::order_srv(records, high)) == std::vector<std::string>{ "a2", "a1", "b", "c" });
	scripted wrap{ .values = { 101 + 99 } };// 200 % 101 = 99: a2
	CHECK(targets(ad::order_srv(records, wrap)).front() == "a2");

	// Weight 0 is picked first only by a draw of 0.
	const std::vector<ad::srv_record> zero{ { .weight = 5, .target = "w" }, { .weight = 0, .target = "z" } };
	scripted zero_draw{ .values = { 0 } };
	CHECK(targets(ad::order_srv(zero, zero_draw)) == std::vector<std::string>{ "z", "w" });
	scripted one{ .values = { 1 } };
	CHECK(targets(ad::order_srv(zero, one)) == std::vector<std::string>{ "w", "z" });

	// All weights 0: listed order.
	const std::vector<ad::srv_record> flat{ { .target = "x" }, { .target = "y" } };
	scripted any{ .values = { 7 } };
	CHECK(targets(ad::order_srv(flat, any)) == std::vector<std::string>{ "x", "y" });
	CHECK(ad::order_srv({}, any).empty());
}

TEST_CASE("ad::discover_domain_controllers: URLs from the SRV records", "[ad][discover]")
{
	fake_dns dns{ .zone = { { "_ldap._tcp.dc._msdcs.example.org",
					{ { .priority = 1, .port = 389, .target = "dc2.example.org" },
					  { .priority = 0, .port = 389, .target = "dc1.example.org" },
					  { .priority = 0, .port = 389, .target = "dc1.example.org" } } } } };
	auto r = ad::discover_domain_controllers("example.org", { .resolver = dns.resolver() });
	REQUIRE(r.has_value());
	CHECK(texts(*r) == std::vector<std::string>{ "ldap://dc1.example.org:389", "ldap://dc2.example.org:389" });
	CHECK(dns.asked == std::vector<std::string>{ "_ldap._tcp.dc._msdcs.example.org" });

	auto tls = ad::discover_domain_controllers("example.org", { .tls = true, .resolver = dns.resolver() });
	REQUIRE(tls.has_value());
	CHECK(texts(*tls) == std::vector<std::string>{ "ldaps://dc1.example.org:636", "ldaps://dc2.example.org:636" });
}

TEST_CASE("ad::discover_domain_controllers: the site's DCs first", "[ad][discover]")
{
	// UTS #46 maps the names to lower case.
	fake_dns dns{
		.zone = { { "_ldap._tcp.berlin._sites.dc._msdcs.example.org",
					{ { .port = 389, .target = "dc3.example.org" } } },
		  { "_ldap._tcp.dc._msdcs.example.org",
			{ { .port = 389, .target = "dc1.example.org" }, { .port = 389, .target = "dc3.example.org" } } } }
	};
	auto r = ad::discover_domain_controllers("example.org", { .site = "Berlin", .resolver = dns.resolver() });
	REQUIRE(r.has_value());
	CHECK(texts(*r) == std::vector<std::string>{ "ldap://dc3.example.org:389", "ldap://dc1.example.org:389" });
	CHECK(dns.asked
		  == std::vector<std::string>{
			"_ldap._tcp.berlin._sites.dc._msdcs.example.org", "_ldap._tcp.dc._msdcs.example.org" });

	// A site without records of its own: the domain's.
	auto other = ad::discover_domain_controllers("example.org", { .site = "Paris", .resolver = dns.resolver() });
	REQUIRE(other.has_value());
	CHECK(other->size() == 2);
}

TEST_CASE("ad::discover_global_catalogs: port 3268, or 3269 with TLS", "[ad][discover]")
{
	fake_dns dns{ .zone = {
					{ "_ldap._tcp.gc._msdcs.example.org", { { .port = 3268, .target = "gc.example.org" } } } } };
	auto r = ad::discover_global_catalogs("example.org", { .resolver = dns.resolver() });
	REQUIRE(r.has_value());
	CHECK(texts(*r) == std::vector<std::string>{ "ldap://gc.example.org:3268" });
	auto tls = ad::discover_global_catalogs("example.org", { .tls = true, .resolver = dns.resolver() });
	REQUIRE(tls.has_value());
	CHECK(texts(*tls) == std::vector<std::string>{ "ldaps://gc.example.org:3269" });
}

TEST_CASE("ad::discover_domain_controllers: internationalized names as A-labels", "[ad][discover]")
{
	fake_dns dns{ .zone = { { "_ldap._tcp.xn--mnchen-3ya._sites.dc._msdcs.xn--bcher-kva.example",
					{ { .port = 389, .target = "dc.xn--bcher-kva.example" } } } } };
	auto r = ad::discover_domain_controllers("Bücher.example", { .site = "München", .resolver = dns.resolver() });
	REQUIRE(r.has_value());
	CHECK(texts(*r) == std::vector<std::string>{ "ldap://dc.xn--bcher-kva.example:389" });
}

TEST_CASE("ad::discover_domain_controllers: errors", "[ad][discover]")
{
	fake_dns dns{ .zone = { { "_ldap._tcp.dc._msdcs.dot.example", { { .port = 389, .target = "." } } } } };
	SECTION("no records, or only '.'")
	{
		for (const char *domain : { "none.example", "dot.example" }) {
			CAPTURE(domain);
			auto r = ad::discover_domain_controllers(domain, { .resolver = dns.resolver() });
			REQUIRE_FALSE(r.has_value());
			CHECK(r.error().code == std::errc::host_unreachable);
			CHECK(r.error().code == ldap::cond::busy_or_unavailable);
			CHECK_THAT(std::string(r.error().context), ContainsSubstring("discover domain controllers of "));
		}
	}
	SECTION("an empty domain")
	{
		auto r = ad::discover_domain_controllers("", { .resolver = dns.resolver() });
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == std::errc::invalid_argument);
		CHECK(dns.asked.empty());
	}
	SECTION("a name UTS #46 refuses")
	{
		auto r = ad::discover_domain_controllers("a..b", { .resolver = dns.resolver() });
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == ldap::client_errc::string_prep_failed);
	}
	SECTION("the resolver's error")
	{
		auto r = ad::discover_domain_controllers(
		  "example.org", { .resolver = [](std::string_view) -> ldap::result<std::vector<ad::srv_record>> {
			  return ldap::fail(std::make_error_code(std::errc::resource_unavailable_try_again), "dns");
		  } });
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == std::errc::resource_unavailable_try_again);
		CHECK_THAT(std::string(r.error().context), ContainsSubstring("SRV _ldap._tcp.dc._msdcs.example.org"));
	}
}

TEST_CASE("ad::resolve_srv: a name that does not exist", "[ad][discover][dns]")
{
	// RFC 6761: .invalid never resolves. Without DNS at all the lookup may
	// fail instead; either way there are no records.
	auto r = ad::resolve_srv("_ldap._tcp.dc._msdcs.coro-ldap.invalid");
	if (r) {
		CHECK(r->empty());
	}
}
