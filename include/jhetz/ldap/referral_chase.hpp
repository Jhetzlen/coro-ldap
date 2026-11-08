// Opt-in referral chasing for searches and compares (RFC 4511 sections
// 4.1.10 and 4.5.3). Part of jhetz::ldap_net. A connection never chases by
// itself. chase_search and chase_compare run the operation, then follow what
// it returned through a caller-supplied connector that decides which servers
// are contacted and how they are bound (the library never forwards
// credentials by itself).
//
//   auto chased = co_await ldap::chase_search(conn, {
//       .base   = ldap::dn{"dc=example,dc=org"},
//       .filter = ldap::filters::attr("uid") == "jdoe",
//   }, connector);
//   if (!chased) ...                       // the search itself failed
//   if (!chased->complete) ...             // some references could not be followed
//   for (const ldap::entry &e : chased->entries) ...
//
// Following a reference: each URI is parsed, its request built with
// referral_target (referral.hpp), and the connector asked for a connection
// (null skips the URI). The URIs of one referral or reference are
// alternatives, tried in order until one is followed.
//
// Referral results (origin or target fails with errc::referral): chased
// recursively. If no URI answers, the call fails with the last target or
// connector error, else with the original referral error; its context counts
// the outcomes ("referral chase (URIs: 1 failed, 2 skipped_policy)") instead
// of an attempt list, and the original referral error keeps its URIs in
// `referrals`. Writes are never chased; referral_target builds them for a
// caller that wants to.
//
// Continuation references (search only): followed breadth first after the
// search ended, entries appended in that order. A reference that cannot be
// followed clears chased_search::complete instead of failing the search;
// only a cancellation stops the chase with an error.
//
// Limits (referral_policy): max_hops bounds the nesting (depth 1: a URL the
// origin returned; default 10). max_targets bounds connector calls per
// chase. The request's timeout is the budget of the whole chase: it cancels
// the connector's task through its stop token (that URI fails with a
// timeout; a connector ignoring it is bounded only by itself, and its
// connection is then not used), and each target request gets what is left.
// Without a timeout, each request has its connection's operation_timeout.
// Once max_targets or the budget is spent, the URI at hand is limit_reached
// and waiting references are counted in `unlisted` (clearing `complete`);
// over max_hops a reference gets one limit_reached entry. The attempt list
// keeps at most max_attempts entries; the rest are counted in `unlisted`.
//
// Loops: a URI whose server (scheme, host, port) and request (DN; for a
// search, scope and filter) match one already sent in this chase, the
// origin's included, is skipped_loop without asking the connector. Hosts
// compare in ASCII form, case-insensitively; DNs by distinguishedNameMatch;
// filters as trees.
//
// Threading: the connector's connections must belong to the origin's
// executor; every task runs on it. `origin` and the connector's connections
// must outlive the task.
//
// make_same_policy_connector (below) keeps the origin's security:
//
//   auto connector = ldap::make_same_policy_connector(ioc, conn, options, {"example.org"},
//       ldap::simple_bind_setup(ldap::dn{"cn=reader,dc=example,dc=org"}, password));
#pragma once

#include "jhetz/ldap/client.hpp"
#include "jhetz/ldap/connection.hpp"
#include "jhetz/ldap/connection_options.hpp"
#include "jhetz/ldap/entry.hpp"
#include "jhetz/ldap/error.hpp"
#include "jhetz/ldap/operations.hpp"
#include "jhetz/ldap/referral.hpp"
#include "jhetz/ldap/url.hpp"

#include <boost/capy/task.hpp>
#include <boost/corosio/io_context.hpp>

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory_resource>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace jhetz::ldap {

// Gives the connection to send a referred request on: the server that
// `target` names (scheme, host, port; the rest of the URL is the request's
// business), at `depth` (1 for a URL the origin returned). Returning null
// skips the URI (a policy refusal); an error is that URI's failure. The
// connector decides trust and binding: open a connection or reuse one,
// bind it as the caller sees fit, or refuse. It must outlive the chase
// task's use of the connection it returns. make_same_policy_connector
// builds one.
using referral_connector = std::function<boost::capy::task<result<connection *>>(const url &target, std::size_t depth)>;

// referral_policy, referral_attempt, chased_search and chased_compare are in
// referral.hpp (plain data, so client.hpp can name them).

// connection::search, chasing referral results and continuation references
// as described above. The entries are allocated from `mr`, as search()'s.
// A result code other than success, referral or a limit code
// (sizeLimitExceeded, timeLimitExceeded, adminLimitExceeded: the entries
// received are kept, as search() keeps them) fails the call, on the origin
// or on the target of a referral result (as search() does); on the target
// of a continuation reference it only makes that URI failed. A limit code
// anywhere keeps the entries received and clears `complete`.
auto chase_search(connection &origin,
  search_params request,
  referral_connector connector,
  referral_policy policy = {},
  std::pmr::memory_resource *mr = std::pmr::get_default_resource()) -> boost::capy::task<result<chased_search>>;

// connection::compare, chasing referral results.
auto chase_compare(connection &origin,
  compare_params request,
  referral_connector connector,
  referral_policy policy = {}) -> boost::capy::task<result<chased_compare>>;

// A connector that opens connections to referred servers with the origin's
// security policy, reusing them for later calls (one per scheme, host and
// port; reopened once closed). It skips (returns null for):
// - ldapi:// URLs and URLs without a host;
// - hosts outside `allowed_host_suffixes`: a name matches an entry equal to
//   it or of which it is a subdomain (`example.org` allows
//   `ldap.eu.example.org`, not `badexample.org`), compared in ASCII form
//   (RFC 4513 section 3.1.3.1: IDNA ToASCII with UseSTD3ASCIIRules, then
//   case-insensitively, one trailing dot ignored); an IP address matches only
//   the same address text. Empty (default): everything is skipped. Hosts with
//   bytes no host name has (controls, space, '%', '/', ...) or an IPv6 zone
//   identifier are skipped too;
// - ports other than the scheme's default (389, 636) and the origin's,
//   unless the matching entry names it (`host:port`, `10.0.0.1:port`,
//   `[::1]:port`; `example.org:1389` also allows 1389 on its subdomains).
// No TLS downgrade: if `origin` is TLS-protected (is_tls(), read once), an
// ldaps:// target stays TLS and an ldap:// one uses StartTLS (a failure fails
// the URI); otherwise `options` apply as given. The certificate is checked as
// `options.tls` says against the referred host (tls_options::server_name
// cleared; an internationalized name connected to in ASCII form).
// `setup` runs on each new connection; the TLS client certificate of
// `options.tls` is presented only with a setup. Empty: anonymous, without a
// client certificate. To present the certificate pass a setup, e.g.
// sasl_bind_setup with EXTERNAL, or no_bind_setup(). A connect, StartTLS or
// setup failure fails the URI; they stop when the chase's budget is spent.
// The connections close (without an UnbindRequest) when the last copy of the
// connector is destroyed; `ioc` must outlive it.
[[nodiscard]] auto make_same_policy_connector(boost::corosio::io_context &ioc,
  const connection &origin,
  connection_options options,
  std::vector<std::string> allowed_host_suffixes,
  session_setup setup = {}) -> referral_connector;

namespace detail {
	// For tests: the URL and options make_same_policy_connector connects
	// to `target` with, or nullopt when it skips it.
	struct referral_connect_plan
	{
		url server{};
		connection_options options{};
	};
	[[nodiscard]] auto same_policy_plan(const url &target,
	  bool origin_tls,
	  const connection_options &options,
	  std::span<const std::string> allowed_host_suffixes,
	  std::optional<std::uint16_t> origin_port = std::nullopt) -> std::optional<referral_connect_plan>;
}// namespace detail

}// namespace jhetz::ldap
