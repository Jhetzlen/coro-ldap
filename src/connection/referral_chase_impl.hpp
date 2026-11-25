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
	// in search_result::unlisted, and kept in its references.
	bool references = true;
	// Called with each attempt as it is decided (also those beyond
	// max_attempts, which are not listed).
	std::function<void(const referral_attempt &)> on_attempt{};
};

// A chase's outcome, and whether its failure is the origin's own operation's
// (the only one retried).
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
  chase_settings settings) -> boost::capy::task<chase_result<search_result>>;

auto chase_compare(connection &origin,
  compare_params request,
  referral_connector connector,
  referral_policy policy,
  chase_settings settings) -> boost::capy::task<chase_result<compare_result>>;

// How a policy connector connects to a server.
struct referral_connect_plan
{
	url server{};
	connection_options options{};
};

// make_same_policy_connector's allow-list check of `target`'s host and port.
[[nodiscard]] auto referral_server_allowed(const url &target,
  std::span<const std::string> allowed,
  std::optional<std::uint16_t> origin_port) -> bool;

// How a referred connection is bound: `setup`, the `identity` keying kept
// connections, and whether the TLS client certificate is presented.
struct referral_identity
{
	std::size_t identity = 0;
	session_setup setup{};
	bool client_certificate = false;
};

// `setup` on each connection, the client certificate only with a setup.
[[nodiscard]] auto same_policy_identity(session_setup setup) -> referral_identity;

// How referral_options::authorize's answer binds a referred connection;
// nullopt for refuse.
[[nodiscard]] auto client_referral_identity(referral_binding binding, const session_setup &client_setup)
  -> std::optional<referral_identity>;

// TLS, ldapi://, or a SASL confidentiality layer.
[[nodiscard]] auto origin_protected(const connection &origin) -> bool;

// The URL and options a policy connector connects to `target` with, as
// `chosen` binds it: nullopt when its host cannot be used.
[[nodiscard]] auto referral_plan(const url &target,
  bool origin_protected,
  const connection_options &options,
  const referral_identity &chosen) -> std::optional<referral_connect_plan>;

// Decides for a URL that passed the fixed rules; nullopt skips it.
using referral_chooser = std::function<std::optional<referral_identity>(const url &target, std::size_t depth)>;

// make_same_policy_connector with `choose` deciding servers and binding.
[[nodiscard]] auto make_policy_connector(boost::corosio::io_context &ioc,
  bool origin_protected,
  connection_options options,
  referral_chooser choose,
  std::pmr::memory_resource *mr) -> referral_connector;

}// namespace jhetz::ldap::detail
