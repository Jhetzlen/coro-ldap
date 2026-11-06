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
// - Search scope: the URL's <scope> if present, else the original
//   search's, for a continuation reference too (section 4.5.3: "In the
//   absence of a <scope> part, the scope of the original Search request is
//   assumed"). A server answering a singleLevel search is the one to put
//   "base" in the URL (same section); the client does not guess it.
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
//
// Also here, as plain data (so that client.hpp can name them without the
// chasing code): the limits of a chase (referral_policy) and what it
// returns (referral_attempt, chased_search, chased_compare). chase_search,
// chase_compare and their rules are in referral_chase.hpp.
#pragma once

#include "jhetz/ldap/entry.hpp"
#include "jhetz/ldap/error.hpp"
#include "jhetz/ldap/operations.hpp"
#include "jhetz/ldap/url.hpp"

#include <cstddef>
#include <cstdint>
#include <memory_resource>
#include <optional>
#include <string>
#include <vector>

namespace jhetz::ldap {

// Where a URL came from: what to do with an absent DN depends on it.
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

// ---------------------------------------------------------------- chase results (referral_chase.hpp)

struct referral_policy
{
	// RFC 4511 sections 4.1.10 and 4.5.3: a client that counts hops "MUST be
	// able to handle at least ten nested referrals".
	static constexpr std::size_t default_max_hops = 10;
	static constexpr std::size_t default_max_targets = 64;
	static constexpr std::size_t default_max_attempts = 256;

	// Deepest URL followed: 1 follows only what the origin returned; 0
	// follows nothing.
	std::size_t max_hops = default_max_hops;
	// Most URIs handed to the connector in one chase.
	std::size_t max_targets = default_max_targets;
	// Most referral_attempt entries in a result (chased_*::referrals); the
	// URIs considered beyond them are only counted (chased_*::unlisted).
	std::size_t max_attempts = default_max_attempts;
};

// What became of one URI of a referral or continuation reference.
enum class referral_outcome : std::uint8_t {
	// The request was sent to the target and answered: a result, or a
	// referral that was chased in turn (the next attempts, one hop deeper).
	followed,
	skipped_policy,// the connector returned null
	skipped_loop,// that server already got the same request in this chase
	limit_reached,// over max_hops or max_targets, or the timeout was spent
	unparseable,// not an LDAP URL, or one that cannot be followed (referral_target): see failure
	failed,// the connector or the request failed: see failure
};

// One URI that was considered, in the order the chase got to it. URIs not
// tried because an earlier alternative of the same reference was followed,
// or was over a limit, are not listed.
struct referral_attempt
{
	std::string uri{};// as the server sent it
	reference_kind kind = reference_kind::referral;
	std::size_t depth = 1;// 1: returned by the origin's server
	referral_outcome outcome = referral_outcome::followed;
	std::optional<error> failure{};// unparseable and failed: why
};

struct chased_search
{
	// The origin's entries (or, after a referral result, the target's), then
	// those of each continuation reference followed, in the order followed.
	std::pmr::vector<entry> entries{};
	// The SearchResultDone of the origin's search (or, after a referral
	// result, the target's), as search_result's: success, or a limit code
	// (sizeLimitExceeded, timeLimitExceeded, adminLimitExceeded) with the
	// entries received before it.
	std::int32_t result_code = 0;
	std::pmr::string matched_dn{};
	std::pmr::string diagnostic_message{};
	std::pmr::vector<control> controls{};
	std::vector<referral_attempt> referrals{};
	// URIs not in `referrals`: those beyond referral_policy::max_attempts,
	// and those of the references left unexamined when the chase stopped
	// (max_targets reached or the timeout spent), or not followed at all
	// (ldap::client with referral_options::follow_references off).
	std::size_t unlisted = 0;
	// False when the entries are partial: a search ended with a limit
	// code (the origin's, a referral target's or a followed continuation
	// reference's), or some continuation reference was not followed by any
	// of its URIs (skipped, unparseable, over a limit, failed, left
	// unexamined when the chase stopped, or not followed at all). A
	// reference skipped only as a loop leaves it true (its server already
	// got that search; loops are recognized before max_targets and the
	// budget are checked), but one over max_hops or left unexamined clears
	// it (whether it was a loop is not known).
	bool complete = true;
};

struct chased_compare
{
	bool value = false;// compareTrue: true, compareFalse: false
	std::vector<referral_attempt> referrals{};
	std::size_t unlisted = 0;// URIs beyond referral_policy::max_attempts
};

}// namespace jhetz::ldap
