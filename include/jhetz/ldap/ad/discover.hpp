// Domain controller discovery from DNS SRV records (MS-ADTS 6.3.2.3, RFC
// 2782 order), for client_options::servers. Blocking.
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

// One SRV record's data (RFC 2782).
struct srv_record
{
	std::uint16_t priority = 0;
	std::uint16_t weight = 0;
	std::uint16_t port = 0;
	std::string target{};// without the final dot; "." for none

	friend auto operator==(const srv_record &, const srv_record &) -> bool = default;
};

// SRV records of an ASCII DNS name; empty when it has none.
using srv_resolver = std::function<result<std::vector<srv_record>>(std::string_view name)>;

// The system resolver: res_nquery (Linux) or DnsQuery_UTF8 (Windows).
[[nodiscard]] auto resolve_srv(std::string_view name) -> result<std::vector<srv_record>>;

// RFC 2782 order: by priority, then weighted random within a priority.
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
	// That site's DCs first; empty: the domain's only.
	std::string site{};
	// ldaps:// on 636 (3269 for a Global Catalog).
	bool tls = false;
	// With tls: SRV targets outside the queried domain are skipped (RFC
	// 6125 section 6.2.1 comparison); false keeps them.
	bool require_target_in_domain = true;
	// Empty: resolve_srv.
	srv_resolver resolver{};
};

// The LDAP URLs of `domain`'s domain controllers, without duplicates;
// internationalized names are converted to A-labels.
[[nodiscard]] auto discover_domain_controllers(std::string_view domain, const discover_options &options = {})
  -> result<std::vector<url>>;

// The Global Catalog servers of `forest` (port 3268, or 3269 with tls).
[[nodiscard]] auto discover_global_catalogs(std::string_view forest, const discover_options &options = {})
  -> result<std::vector<url>>;

}// namespace jhetz::ldap::ad
