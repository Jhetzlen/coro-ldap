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
// Controls the server returns stay wire-level (std::pmr::vector<control>,
// in connection::response, extended_result and search_stream::controls());
// find_paged(), find_sort_result(), find_pre_read() and find_post_read()
// read the typed ones:
//
//   auto r = co_await conn.modify({.object = dn, .changes = ...,
//                                  .controls = {ldap::post_read{.attributes = {"modifyTimestamp"}}}});
//   if (r) if (auto e = ldap::find_post_read(r->controls); e && *e) use((*e)->find("modifyTimestamp"));
#pragma once

#include "jhetz/ldap/entry.hpp"
#include "jhetz/ldap/error.hpp"
#include "jhetz/ldap/filter.hpp"
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

// Server Side Sorting (RFC 2891, OID sort_request_oid): sort the search's
// entries by `keys`, the first one most significant. RFC 2891 section 2
// says a server that supports the control but cannot sort SHOULD fail the
// search if it is critical and should return the entries unsorted if not,
// with a sort result control on the SearchResultDone, though scenario 6
// lets the server omit that control when the search fails or returns no
// entries; a server without sort support ignores a non-critical control
// and sends none. A server may accept only one key. Servers deviate:
// OpenLDAP 2.7's sssvlv fails an unsortable search with 18
// inappropriateMatching and no sort result even when not critical, and
// answers every multi-key sort with 2 protocolError ("decoding error") and
// no sort result, even when not critical (libldap's own requests too). So
// check the search's result, and treat find_sort_result() returning
// nullopt as "not known to be sorted". Fails with encode_error,
// before anything is sent, if there are no keys or a key has no attribute.
struct sort_key
{
	std::string attribute{};// attributeType: an attribute description
	std::string ordering_rule{};// orderingRule [0]: a matching rule; empty = the attribute's ORDERING
	bool reverse = false;// reverseOrder [1]: descending
};
struct server_side_sort
{
	std::vector<sort_key> keys{};
	bool critical = false;
};

// Assertion (RFC 4528, OID assertion_oid): perform the operation only if
// `filter` matches the target entry (for a search: the base object), else
// fail with errc::assertion_failed (122). Critical by default: a server that
// does not know the control then refuses the operation
// (unavailable_critical_extension) instead of ignoring the condition. An
// empty filter fails with invalid_filter when encoded.
inline constexpr std::string_view assertion_oid = "1.3.6.1.1.12";
struct assertion
{
	ldap::filter filter{};
	bool critical = true;
};

// Pre-Read / Post-Read (RFC 4527, OIDs pre_read_oid / post_read_oid): on an
// add, delete, modify or modify DN, return the target entry as it was
// before / is after the update, with the given attributes (as in a search:
// empty means all user attributes, "+" operational ones). The entry comes
// back in a response control: find_pre_read / find_post_read.
struct pre_read
{
	std::vector<std::string> attributes{};
	bool critical = false;
};
struct post_read
{
	std::vector<std::string> attributes{};
	bool critical = false;
};

using request_control =
  std::variant<control, paged, manage_dsa_it, proxied_authorization, server_side_sort, assertion, pre_read, post_read>;
using request_controls = std::vector<request_control>;

// The wire form of `c`, on `mr`. Fails with encode_error for a negative
// page size or an invalid sort, invalid_filter for an empty (or too large)
// assertion filter.
result<control> to_control(const request_control &c, std::pmr::memory_resource *mr = std::pmr::get_default_resource());

// Appends the wire form of every control to `out`.
result<void> append_controls(const request_controls &controls, std::pmr::vector<control> &out);

// The paged results control among `controls` (e.g. a SearchResultDone's),
// nullopt if there is none, or decode_error if it is malformed.
result<std::optional<paged_results>> find_paged(const std::pmr::vector<control> &controls,
  std::pmr::memory_resource *mr = std::pmr::get_default_resource());

// The sort result control among `controls` (a SearchResultDone's), nullopt
// if there is none, or decode_error if it is malformed. nullopt is a normal
// answer, even to a search that sent server_side_sort (see there): callers
// must handle it, as "not known to be sorted".
result<std::optional<sort_result>> find_sort_result(const std::pmr::vector<control> &controls,
  std::pmr::memory_resource *mr = std::pmr::get_default_resource());

// The entry of the pre-read / post-read response control among `controls`
// (an add, delete, modify or modify DN response's), nullopt if there is
// none, or an error if it is malformed (decode_error, or message_too_large
// beyond decode_options' default element limit). The entry is allocated
// from `mr`.
result<std::optional<entry>> find_pre_read(const std::pmr::vector<control> &controls,
  std::pmr::memory_resource *mr = std::pmr::get_default_resource());
result<std::optional<entry>> find_post_read(const std::pmr::vector<control> &controls,
  std::pmr::memory_resource *mr = std::pmr::get_default_resource());

}// namespace jhetz::ldap
