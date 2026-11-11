// Domain controller discovery from DNS (MS-ADTS 6.3.2.3, the DC locator's
// SRV records; RFC 2782 ordering): the URLs of a domain's DCs or a forest's
// Global Catalog servers, for client_options::servers. Part of
// jhetz::ldap_ad.
//
//   auto dcs = ldap::ad::discover_domain_controllers("example.org", {.site = "Berlin", .tls = true});
//   if (!dcs) ...
//   ldap::client pool(ioc, {.servers = std::move(*dcs), ...});
//
// Blocking: the system resolver (res_nquery on Linux, DnsQuery on Windows)
// waits for DNS. Call it before building a client, or off the I/O thread.
#pragma once

#include "jhetz/ldap/error.hpp"
#include "jhetz/ldap/url.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <random>
#include <string>
#include <string_view>
#include <vector>

namespace jhetz::ldap::ad {

// One SRV resource record's data (RFC 2782).
struct srv_record
{
	std::uint16_t priority = 0;
	std::uint16_t weight = 0;
	std::uint16_t port = 0;
	std::string target{};// a host name without the final dot; "." for none

	friend auto operator==(const srv_record &, const srv_record &) -> bool = default;
};

// Looks up the SRV records of `name` (an ASCII DNS name). An empty list
// when the name or its SRV records do not exist (NXDOMAIN, NODATA); an
// error for anything else.
using srv_resolver = std::function<result<std::vector<srv_record>>(std::string_view name)>;

// The system resolver: res_nquery (Linux, libresolv) or DnsQuery_UTF8
// (Windows). Fails with std::errc::resource_unavailable_try_again for a
// temporary DNS failure, client_errc::decode_error for an answer it cannot
// parse, std::errc::io_error (or the Windows DNS status) otherwise.
[[nodiscard]] auto resolve_srv(std::string_view name) -> result<std::vector<srv_record>>;

// RFC 2782's order: by priority, lowest first; within a priority, a
// weighted random order (each record picked with a chance proportional to
// its weight, records of weight 0 rarely first). `g` gives the randomness.
template<std::uniform_random_bit_generator G>
[[nodiscard]] auto order_srv(std::vector<srv_record> records, G &g) -> std::vector<srv_record>
{
	std::ranges::stable_sort(records, {}, &srv_record::priority);
	std::vector<srv_record> out;
	out.reserve(records.size());
	auto first = records.begin();
	while (first != records.end()) {
		const auto last = std::ranges::find_if(
		  first, records.end(), [&](const srv_record &r) { return r.priority != first->priority; });
		std::vector<srv_record> group(first, last);
		// Weight 0 first, so a pick of 0 selects one of them.
		std::ranges::stable_partition(group, [](const srv_record &r) { return r.weight == 0; });
		while (!group.empty()) {
			std::uint64_t total = 0;
			for (const auto &r : group) {
				total += r.weight;
			}
			const auto draw = static_cast<std::uint64_t>(g() - G::min());
			const std::uint64_t pick = draw % (total + 1);
			std::uint64_t running = 0;
			std::size_t chosen = group.size() - 1;
			for (std::size_t i = 0; i < group.size(); ++i) {
				running += group[i].weight;
				if (running >= pick) {
					chosen = i;
					break;
				}
			}
			out.push_back(std::move(group[chosen]));
			group.erase(group.begin() + static_cast<std::ptrdiff_t>(chosen));
		}
		first = last;
	}
	return out;
}

struct discover_options
{
	// The client's AD site: its DCs come first, then the domain's others.
	// Empty: the domain's DCs only.
	std::string site{};
	// ldaps:// URLs on the LDAPS ports (636 for a DC, 3269 for a Global
	// Catalog) instead of ldap:// on the ports the SRV records name.
	bool tls = false;
	// Empty: resolve_srv.
	srv_resolver resolver{};
};

// The LDAP URLs of `domain`'s domain controllers, from the SRV records of
// _ldap._tcp.dc._msdcs.<domain> (with a site, first those of
// _ldap._tcp.<site>._sites.dc._msdcs.<domain>), each list in RFC 2782 order,
// without duplicates or the "." target. `domain` and `site` may be
// internationalized (UTF-8): they are converted to A-labels (UTS #46).
// Fails with std::errc::invalid_argument for an empty domain,
// client_errc::string_prep_failed for a name UTS #46 refuses,
// std::errc::host_unreachable when no record names a DC, the resolver's
// error, or client_errc::invalid_url for a target that is no URL host.
// Errors have the context "discover domain controllers of <domain>".
[[nodiscard]] auto discover_domain_controllers(std::string_view domain, const discover_options &options = {})
  -> result<std::vector<url>>;

// As above for the Global Catalog servers of the forest whose root domain
// is `forest`: _ldap._tcp.gc._msdcs.<forest> (with a site,
// _ldap._tcp.<site>._sites.gc._msdcs.<forest> first), port 3268, or 3269
// with tls.
[[nodiscard]] auto discover_global_catalogs(std::string_view forest, const discover_options &options = {})
  -> result<std::vector<url>>;

}// namespace jhetz::ldap::ad
