// Building the request that progresses an operation at the target of a
// referral (RFC 4511 section 4.1.10) or a search continuation reference
// (section 4.5.3), from the LDAP URL the server returned and the request
// that got it. Part of jhetz::ldap (the codec): these only build requests,
// they never send anything. chase_search and chase_compare
// (referral_chase.hpp, jhetz::ldap_net) use them to follow referrals; for
// the updates, which are never chased, they let a caller build the request
// to send elsewhere itself (a referral result means the update was not
// performed, section 4.1.10).
//
//   auto refs = ldap::url::parse_list(err.referrals);
//   for (const ldap::url &u : refs) {
//       auto next = ldap::referral_target(u, request);   // result<search_params>
//       if (next) ...                                     // send *next to u's server
//   }
//
// Rules (RFC 4511 sections 4.1.10 and 4.5.3):
// - DN: the URL's <dn> if it is present and not empty, else the original
//   request's. A continuation reference's URL must carry a DN (section 4.5.3:
//   "The <dn> part of the LDAP URL MUST be present"): without one the
//   reference cannot be followed (invalid_url). An empty <dn> (`ldap://host/`)
//   counts as absent: RFC 4516 section 3 defaults a missing DN to the
//   zero-length one, which section 4.1.10 overrides for referrals.
// - Search scope: the URL's <scope> if present. Absent: the original
//   search's, except that a continuation reference returned for a
//   singleLevel search is followed with baseObject (section 4.5.3: "If the
//   originating search scope was singleLevel, the <scope> part of the LDAP
//   URL will be 'base'"; the reference names the subordinate entry itself).
// - Search filter: the URL's <filter> if present, else the original's.
// - Everything else is the original request's: the attribute list (section
//   4.1.10 names only the DN, scope and filter as taken from the URL; the
//   URL's <attributes> are ignored), alias dereferencing, limits, controls,
//   timeout, and for the other operations their own fields (the compared
//   assertion, the changes, the new RDN and superior).
// - Extensions (RFC 4516 section 2): none is implemented, so a URL with a
//   critical one ('!') must not be processed: invalid_url, naming it. Other
//   extensions are ignored.
// The URL's scheme, host and port name the server to send the request to;
// they are not checked here (see make_same_policy_connector for a policy).
#pragma once

#include "jhetz/ldap/error.hpp"
#include "jhetz/ldap/operations.hpp"
#include "jhetz/ldap/url.hpp"

#include <cstdint>

namespace jhetz::ldap {

// Where a URL came from: what to do with an absent DN and scope depends on it.
enum class reference_kind : std::uint8_t {
	referral,// the referral field of an LDAPResult (RFC 4511 section 4.1.10)
	continuation_reference,// a SearchResultReference (section 4.5.3)
};

// The search to send to `target`'s server. Fails with client_errc::invalid_url
// for a URL with a critical extension, or a continuation reference without a
// DN.
[[nodiscard]] auto referral_target(const url &target,
  search_params original,
  reference_kind kind = reference_kind::referral) -> result<search_params>;

// The other operations: only the DN comes from the URL (the entry compared,
// added, modified, deleted or renamed); a referral for them is always a
// referral result. Fails with client_errc::invalid_url for a URL with a
// critical extension.
[[nodiscard]] auto referral_target(const url &target, compare_params original) -> result<compare_params>;
[[nodiscard]] auto referral_target(const url &target, add_params original) -> result<add_params>;
[[nodiscard]] auto referral_target(const url &target, modify_params original) -> result<modify_params>;
[[nodiscard]] auto referral_target(const url &target, del_params original) -> result<del_params>;
[[nodiscard]] auto referral_target(const url &target, modify_dn_params original) -> result<modify_dn_params>;

}// namespace jhetz::ldap
