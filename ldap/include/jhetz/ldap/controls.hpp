// Typed request controls (DESIGN.md section 3): what callers put in the
// `.controls` of a request, encoded to the wire-level ldap::control
// (message.hpp) when the request is sent.
//
//   co_await conn.search({
//       .base     = base,
//       .controls = {ldap::manage_dsa_it{}, ldap::control{"1.2.3.4", true, "raw"}},
//   });
//
// ldap::control itself is the escape hatch for anything not typed here.
// Controls the server returns stay wire-level (std::pmr::vector<control>);
// find_paged() reads the paged results one.
#pragma once

#include "jhetz/ldap/error.hpp"
#include "jhetz/ldap/message.hpp"

#include <cstdint>
#include <memory_resource>
#include <optional>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace jhetz::ldap {

// Simple Paged Results (RFC 2696, OID paged_results_oid): ask for at most
// `page_size` entries; `cookie` is empty for the first page and the
// server's cookie for the next ones. connection::search_paged() manages it.
struct paged
{
	std::int32_t page_size = 0;
	std::string cookie{};
	bool critical = false;
};

// ManageDsaIT (RFC 3296): treat referral objects as ordinary entries. No value.
inline constexpr std::string_view manage_dsa_it_oid = "2.16.840.1.113730.3.4.2";
struct manage_dsa_it
{
	bool critical = false;
};

// Proxied Authorization (RFC 4370): run the operation as `authz_id`
// ("dn:<dn>", "u:<user>", or "" for anonymous). Always critical (RFC 4370
// section 3).
inline constexpr std::string_view proxied_authorization_oid = "2.16.840.1.113730.3.4.18";
struct proxied_authorization
{
	std::string authz_id{};
};

using request_control = std::variant<control, paged, manage_dsa_it, proxied_authorization>;
using request_controls = std::vector<request_control>;

// The wire form of `c`, on `mr`. Fails with encode_error for a negative
// page size.
result<control> to_control(const request_control &c, std::pmr::memory_resource *mr = std::pmr::get_default_resource());

// Appends the wire form of every control to `out`.
result<void> append_controls(const request_controls &controls, std::pmr::vector<control> &out);

// The paged results control among `controls` (e.g. a SearchResultDone's),
// nullopt if there is none, or decode_error if it is malformed.
result<std::optional<paged_results>> find_paged(const std::pmr::vector<control> &controls,
  std::pmr::memory_resource *mr = std::pmr::get_default_resource());

}// namespace jhetz::ldap
