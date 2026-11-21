// ad::order_srv and DC discovery with a scripted resolver.
#include "jhetz/ldap/ad/discover.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <array>
#include <cstdint>
#include <limits>
#include <map>
#include <string>
#include <string_view>
#include <vector>

#ifndef _WIN32
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

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

TEST_CASE("ad::discover_domain_controllers: duplicate targets ignore case", "[ad][discover]")
{
	fake_dns dns{ .zone = { { "_ldap._tcp.berlin._sites.dc._msdcs.example.org",
							  { { .port = 389, .target = "DC1.Example.ORG" } } },
					{ "_ldap._tcp.dc._msdcs.example.org",
					  { { .port = 389, .target = "dc1.example.org" },
						{ .port = 3268, .target = "dc1.example.org" },
						{ .port = 389, .target = "dc2.example.org" },
						{ .port = 389, .target = "DC2.EXAMPLE.ORG" } } } } };
	auto r = ad::discover_domain_controllers("example.org", { .site = "berlin", .resolver = dns.resolver() });
	REQUIRE(r.has_value());
	REQUIRE(r->size() == 3);
	CHECK(texts(*r).front() == "ldap://dc1.example.org:389");// A-labels: lower case
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

TEST_CASE("ad::discover_domain_controllers: with TLS, targets outside the domain are skipped", "[ad][discover]")
{
	fake_dns dns{ .zone = { { "_ldap._tcp.dc._msdcs.example.org",
					{ { .priority = 0, .port = 389, .target = "dc.attacker.example" },
					  { .priority = 1, .port = 389, .target = "dc.evilexample.org" },
					  { .priority = 2, .port = 389, .target = "DC1.Sub.EXAMPLE.org" },
					  { .priority = 3, .port = 389, .target = "example.org" } } } } };
	auto tls = ad::discover_domain_controllers("Example.ORG", { .tls = true, .resolver = dns.resolver() });
	REQUIRE(tls.has_value());
	CHECK(texts(*tls) == std::vector<std::string>{ "ldaps://dc1.sub.example.org:636", "ldaps://example.org:636" });

	const std::vector<std::string> all{ "ldaps://dc.attacker.example:636",
		"ldaps://dc.evilexample.org:636",
		"ldaps://dc1.sub.example.org:636",
		"ldaps://example.org:636" };
	auto kept = ad::discover_domain_controllers(
	  "example.org", { .tls = true, .require_target_in_domain = false, .resolver = dns.resolver() });
	REQUIRE(kept.has_value());
	CHECK(texts(*kept) == all);
	auto plain = ad::discover_domain_controllers("example.org", { .resolver = dns.resolver() });
	REQUIRE(plain.has_value());
	CHECK(plain->size() == 4);

	SECTION("internationalized: compared as A-labels")
	{
		fake_dns idn{ .zone = { { "_ldap._tcp.dc._msdcs.xn--bcher-kva.example",
						{ { .port = 389,
							.target = "dc.B\xC3\xBC"
									  "cher.example" },
						  { .port = 389, .target = "dc.xn--bcher-kva.example" },
						  { .port = 389, .target = "dc.xn--bcher-kva.example.evil" } } } } };
		auto r = ad::discover_domain_controllers(
		  "b\xC3\xBC"
		  "cher.example",
		  { .tls = true, .resolver = idn.resolver() });
		REQUIRE(r.has_value());
		CHECK(texts(*r) == std::vector<std::string>{ "ldaps://dc.xn--bcher-kva.example:636" });
	}
	SECTION("only targets outside the domain: an error saying so")
	{
		fake_dns outside{
			.zone = { { "_ldap._tcp.dc._msdcs.example.org", { { .port = 389, .target = "dc.attacker.example" } } } }
		};
		auto r = ad::discover_domain_controllers("example.org", { .tls = true, .resolver = outside.resolver() });
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == std::errc::host_unreachable);
		CHECK(std::string(r.error().context)
			  == "discover domain controllers of example.org: no usable SRV record (dc.attacker.example: outside "
				 "the domain)");
	}
}

TEST_CASE("ad::discover_domain_controllers: unusable records are skipped", "[ad][discover]")
{
	SECTION("a bad record among good ones")
	{
		fake_dns dns{ .zone = { { "_ldap._tcp.dc._msdcs.example.org",
						{ { .priority = 0, .port = 389, .target = "bad..example.org" },
						  { .priority = 1, .port = 389, .target = "dc1.example.org/dc=x?cn" },
						  { .priority = 2, .port = 0, .target = "dc0.example.org" },
						  { .priority = 3, .port = 389, .target = "dc2.example.org" } } } } };
		auto r = ad::discover_domain_controllers("example.org", { .resolver = dns.resolver() });
		REQUIRE(r.has_value());
		CHECK(texts(*r) == std::vector<std::string>{ "ldap://dc2.example.org:389" });
	}
	SECTION("an underscore in a host name: kept; other characters a host name cannot have: skipped")
	{
		fake_dns dns{ .zone = { { "_ldap._tcp.dc._msdcs.example.org",
						{ { .priority = 0, .port = 389, .target = "dc_01.example.org" },
						  { .priority = 1, .port = 389, .target = "dc/1.example.org" },
						  { .priority = 2, .port = 389, .target = "dc 2.example.org" },
						  { .priority = 3, .port = 389, .target = "dc3:389.example.org" },
						  { .priority = 4,
							.port = 389,
							.target = "dc\x01"
									  "4.example.org" } } } } };
		auto r = ad::discover_domain_controllers("example.org", { .tls = true, .resolver = dns.resolver() });
		REQUIRE(r.has_value());
		CHECK(texts(*r) == std::vector<std::string>{ "ldaps://dc_01.example.org:636" });
	}
	SECTION("a trailing dot: the same host as without")
	{
		fake_dns dns{ .zone = { { "_ldap._tcp.dc._msdcs.example.org",
						{ { .priority = 0, .port = 389, .target = "dc1.example.org." },
						  { .priority = 1, .port = 389, .target = "DC1.example.org" },
						  { .priority = 2, .port = 389, .target = "dc2.example.org." } } } } };
		auto r = ad::discover_domain_controllers("example.org", { .resolver = dns.resolver() });
		REQUIRE(r.has_value());
		CHECK(texts(*r) == std::vector<std::string>{ "ldap://dc1.example.org:389", "ldap://dc2.example.org:389" });
	}
	SECTION("all records bad: an error naming each")
	{
		fake_dns dns{ .zone = { { "_ldap._tcp.dc._msdcs.example.org",
						{ { .priority = 0, .port = 389, .target = "bad..example.org" },
						  { .priority = 1, .port = 0, .target = "dc0.example.org" },
						  { .priority = 2, .port = 389, .target = "dc\n1.example.org" } } } } };
		auto r = ad::discover_domain_controllers("example.org", { .resolver = dns.resolver() });
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == std::errc::host_unreachable);
		CHECK(r.error().code == ldap::cond::busy_or_unavailable);
		CHECK(std::string(r.error().context)
			  == "discover domain controllers of example.org: no usable SRV record (bad..example.org: not a valid "
				 "domain name; dc0.example.org: url: port 0; dc\xEF\xBF\xBD" "1.example.org: not a valid domain name)");
	}
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

#ifndef _WIN32
TEST_CASE("ad::resolve_srv: a failing res_ninit leaves descriptor 0 open", "[ad][discover][dns]")
{
	// In a child with no free descriptor, res_ninit fails. Exit status 0: fd 0
	// still open, 1: closed, 2: res_ninit did not fail.
	const pid_t pid = fork();
	REQUIRE(pid >= 0);
	if (pid == 0) {
		struct stat st{};
		std::array<int, 2> pipe_fds{};
		if (fstat(0, &st) != 0 && (pipe(pipe_fds.data()) != 0 || pipe_fds[0] != 0)) {
			_exit(3);
		}
		const int lowest_free = dup(0);
		if (lowest_free < 0) {
			_exit(3);
		}
		close(lowest_free);
		rlimit limit{};
		getrlimit(RLIMIT_NOFILE, &limit);
		limit.rlim_cur = static_cast<rlim_t>(lowest_free);
		if (setrlimit(RLIMIT_NOFILE, &limit) != 0) {
			_exit(3);
		}
		auto r = ad::resolve_srv("_ldap._tcp.dc._msdcs.coro-ldap.invalid");
		if (r || !std::string(r.error().context).contains("res_ninit")) {
			_exit(2);
		}
		_exit(fstat(0, &st) != 0 ? 1 : 0);
	}
	int status = 0;
	REQUIRE(waitpid(pid, &status, 0) == pid);
	REQUIRE(WIFEXITED(status));
	if (WEXITSTATUS(status) == 2) {
		SKIP("res_ninit did not need a new descriptor here");
	}
	CHECK(WEXITSTATUS(status) == 0);
}
#endif
