// Internal: the pieces of referral chasing (referral_chase.hpp) that
// ldap::client builds its referral policy on (client.hpp, "Referrals").
#pragma once

#include "jhetz/ldap/client.hpp"
#include "jhetz/ldap/referral_chase.hpp"

#include <boost/capy/task.hpp>
#include <boost/corosio/io_context.hpp>

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory_resource>
#include <optional>
#include <span>
#include <string>

namespace jhetz::ldap::detail {

// What a chase follows, and who hears of each attempt.
struct chase_settings
{
	bool referrals = true;// referral results (RFC 4511 section 4.1.10)
	// Continuation references (section 4.5.3). Off: their URIs are counted
	// in chased_search::unlisted, and they clear `complete`.
	bool references = true;
	// Called with each attempt as it is decided (also those beyond
	// max_attempts, which are not listed).
	std::function<void(const referral_attempt &)> on_attempt{};
};

// A chase's outcome, and whether its failure is the origin's own
// operation's (not a referral target's, nor the chase's): only those may
// be retried on another connection of the origin's pool.
template<class T> struct chase_result
{
	result<T> value;
	bool origin_failed = false;
};

auto chase_search(connection &origin,
  search_params request,
  referral_connector connector,
  referral_policy policy,
  std::pmr::memory_resource *mr,
  chase_settings settings) -> boost::capy::task<chase_result<chased_search>>;

auto chase_compare(connection &origin,
  compare_params request,
  referral_connector connector,
  referral_policy policy,
  chase_settings settings) -> boost::capy::task<chase_result<chased_compare>>;

// make_same_policy_connector's allow-list check: `target`'s host (and
// port, the scheme's default or `origin_port` unless an entry names it)
// is in `allowed`, and is a plausible host name.
[[nodiscard]] auto referral_server_allowed(const url &target,
  std::span<const std::string> allowed,
  std::optional<std::uint16_t> origin_port) -> bool;

// How a referred connection is bound: `setup` runs on each new one;
// `identity` tells the kept connections apart (one per server and
// identity). `client_certificate`: the TLS client certificate of the
// connector's options (tls_options::cert_file, key_file) is presented;
// else it is left out, so a connection meant to be anonymous does not
// authenticate by TLS (mutual TLS, a server mapping the certificate to an
// identity, SASL EXTERNAL).
struct referral_identity
{
	std::size_t identity = 0;
	session_setup setup{};
	bool client_certificate = false;
};

// The URL and options a policy connector connects to `target` with, as
// `chosen` binds it: nullopt when its host cannot be used.
[[nodiscard]] auto
  referral_plan(const url &target, bool origin_tls, const connection_options &options, const referral_identity &chosen)
	-> std::optional<referral_connect_plan>;

// Decides for a URL that passed the connector's fixed rules (no ldapi://,
// a plausible host, see make_same_policy_connector): nullopt skips it.
using referral_chooser = std::function<std::optional<referral_identity>(const url &target, std::size_t depth)>;

// make_same_policy_connector with `choose` deciding which servers to
// contact and how to bind, instead of an allow-list and one setup. The TLS
// rules (no downgrade, the referred host checked) are the same.
[[nodiscard]] auto make_policy_connector(boost::corosio::io_context &ioc,
  bool origin_tls,
  connection_options options,
  referral_chooser choose,
  std::pmr::memory_resource *mr) -> referral_connector;

}// namespace jhetz::ldap::detail
