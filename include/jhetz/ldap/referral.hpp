// The request that progresses an operation at a referral's target (RFC 4511
// sections 4.1.10, 4.5.3), built from the URL and the original request;
// nothing is sent (docs/API.md, "jhetz/ldap/referral.hpp").
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

// The search to send to `target`'s server; invalid_url for a critical
// extension, or a continuation reference without a DN.
[[nodiscard]] auto referral_target(const url &target,
  search_params original,
  reference_kind kind = reference_kind::referral) -> result<search_params>;

// The other operations: only the DN comes from the URL.
[[nodiscard]] auto referral_target(const url &target, compare_params original) -> result<compare_params>;
[[nodiscard]] auto referral_target(const url &target, add_params original) -> result<add_params>;
[[nodiscard]] auto referral_target(const url &target, modify_params original) -> result<modify_params>;
[[nodiscard]] auto referral_target(const url &target, del_params original) -> result<del_params>;
[[nodiscard]] auto referral_target(const url &target, modify_dn_params original) -> result<modify_dn_params>;

// ---------------------------------------------------------------- chase limits (referral_chase.hpp)

struct referral_policy
{
	// RFC 4511 sections 4.1.10 and 4.5.3: at least ten nested referrals.
	static constexpr std::size_t default_max_hops = 10;
	static constexpr std::size_t default_max_targets = 64;
	static constexpr std::size_t default_max_attempts = 256;

	// 1: only what the origin returned; 0: nothing.
	std::size_t max_hops = default_max_hops;
	// Most URIs handed to the connector in one chase.
	std::size_t max_targets = default_max_targets;
	// Most referral_attempt entries in a result; the rest are counted in
	// `unlisted`.
	std::size_t max_attempts = default_max_attempts;
};

}// namespace jhetz::ldap
