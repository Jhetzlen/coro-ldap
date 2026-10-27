// Opt-in referral chasing for searches and compares (RFC 4511 sections
// 4.1.10 and 4.5.3). Part of jhetz::ldap_net. A connection never chases by
// itself: its operations return referrals (errc::referral, the URIs in
// error::referrals) and continuation references (search_stream) as they
// are. chase_search and chase_compare run the operation on a connection and
// then follow what it returned, through a caller-supplied connector that
// decides which servers may be contacted and how the connections to them are
// bound (the library never forwards credentials by itself).
//
//   auto chased = co_await ldap::chase_search(conn, {
//       .base   = ldap::dn{"dc=example,dc=org"},
//       .filter = ldap::filters::attr("uid") == "jdoe",
//   }, connector);
//   if (!chased) ...                       // the search itself failed
//   if (!chased->complete) ...             // some references could not be followed
//   for (const ldap::entry &e : chased->entries) ...
//
// Following one reference: each URI is parsed (url::parse) and the request
// for its server built with referral_target (referral.hpp). The connector
// is then asked for a connection to the URL's server; null skips that URI.
// The request is sent there with the connection's own operation (search
// streams the entries, compare), so its replies follow the usual rules. A
// referral or continuation reference holds alternatives (RFC 4511: "any
// supported URI may be used"): its URIs are tried in order until one is
// followed, and the rest are not used.
//
// Referral results: when the operation (on the origin or on a target)
// fails with errc::referral, its URIs are tried in order, recursively: the
// first that answers ends the chase of that referral (a further referral is
// chased one hop deeper). When none does, the operation fails: with the
// last error a target or the connector returned, else with the original
// referral error (every URI skipped, unparseable, a loop or over a limit).
// The attempt list is not returned then: the error's context counts the
// outcomes instead ("referral chase (URIs: 1 failed, 2 skipped_policy)"),
// and when the error is the original referral, its URIs are in `referrals`.
// Writes are never chased (a referral result means the update was not
// performed); referral_target builds them for a caller that wants to.
//
// Continuation references (search only): followed after the search that
// returned them ended, one after another, breadth first; the entries of
// every target are appended in that order, and a target's own references
// are followed one hop deeper. A reference that cannot be followed never
// fails the search: it clears chased_search::complete instead, so partial
// results are never reported as a plain success. Only a cancellation stops
// the chase (the call then fails with it).
//
// Limits (referral_policy): max_hops bounds the nesting (a URL the origin
// returned is at depth 1); RFC 4511 asks clients that count hops to handle
// at least ten, the default. max_targets bounds the connector calls of one
// chase. The original request's timeout (search_params / compare_params
// ::timeout) is the budget of the whole chase, measured from the call. The
// connector's task is cancelled (through its stop token) when the budget
// runs out while it works, and that URI is then failed with a timeout
// error; each request sent to a target gets what is left of the budget once
// the connector returned. A connector that ignores cancellation is bounded
// only by itself (its connection is then not used). Without a timeout each
// request has its connection's operation_timeout and the chase has no
// overall limit.
// Once max_targets is reached or the budget spent the chase stops: the URI
// at hand is limit_reached, and the continuation references still waiting
// are not parsed (their URIs are counted in `unlisted`, and they clear
// `complete`). Over max_hops, a reference gets one limit_reached entry,
// not one per URI. The attempt list keeps at most max_attempts entries;
// the URIs considered beyond them are counted in `unlisted` too, so a
// server streaming references cannot make the list grow without bound.
//
// Loops (RFC 4511: clients "MUST NOT repeatedly contact the same server for
// the same request with the same parameters"): a URI whose server (scheme,
// host, port) and request (DN, and for a search scope and filter) match one
// already sent in this chase, the origin's own request included when the
// origin's name() is a URL, is skipped_loop without asking the connector.
// Hosts compare in their ASCII form (IDNA ToASCII for internationalized
// names, then ASCII case-insensitively), DNs by distinguishedNameMatch,
// filters as trees.
//
// Threading: the connections the connector returns must belong to the
// origin's executor, and every task here runs on it. `origin`, and the
// connections the connector returns, must outlive the task.
//
// make_same_policy_connector (below) builds a connector that keeps the
// origin's security: no TLS downgrade, an allow-list of hosts, the
// certificate checked against the referred host, and a bind only through
// the caller's session_setup:
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
	std::vector<referral_attempt> referrals{};
	// URIs not in `referrals`: those beyond referral_policy::max_attempts,
	// and those of the references left unexamined when the chase stopped
	// (max_targets reached or the timeout spent).
	std::size_t unlisted = 0;
	// False if some continuation reference was not followed by any of its
	// URIs (skipped, unparseable, over a limit, failed, or left unexamined
	// when the chase stopped): the entries are then partial. A reference
	// skipped only as a loop leaves it true (its server already got that
	// search; loops are recognized before the limits are checked), but one
	// left unexamined clears it (whether it was a loop is not known).
	bool complete = true;
};

struct chased_compare
{
	bool value = false;// compareTrue: true, compareFalse: false
	std::vector<referral_attempt> referrals{};
	std::size_t unlisted = 0;// URIs beyond referral_policy::max_attempts
};

// connection::search, chasing referral results and continuation references
// as described above. The entries are allocated from `mr`, as search()'s.
// A result code other than success or referral fails the call, on the
// origin or on the target of a referral result (as search() does); on the
// target of a continuation reference it only makes that URI failed.
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
// security policy, and keeps them for its later calls (one per scheme, host
// and port; reopened once closed). It returns null (skips the URI) for:
// - an ldapi:// URL (a server's URL must not reach a local socket), or one
//   without a host;
// - a host outside `allowed_host_suffixes`: a name matches an entry equal
//   to it or of which it is a subdomain (`example.org` allows
//   `example.org` and `ldap.eu.example.org`, not `badexample.org`), both
//   compared in their ASCII form (RFC 4513 section 3.1.3.1: IDNA ToASCII
//   with UseSTD3ASCIIRules for an internationalized name, then ASCII
//   case-insensitively; one trailing dot ignored). An IP address matches
//   only an entry that is the same address text. Empty (the default):
//   every URI is skipped. A host with bytes no host name has (a decoded
//   NUL or other control, space, '%', '/', ...; non-ASCII is left to IDNA)
//   or an IPv6 zone identifier is skipped too;
// - a port other than the scheme's default (389, 636) and the origin's
//   (when its name() is a URL), unless an entry for that host names it:
//   `host:port`, `10.0.0.1:port`, `[::1]:port` (a bare IPv6 address takes
//   no port). An entry with a port allows that port on top of the usual
//   ones: the setup's credentials go to whatever listens on the port a
//   server's URL names, so other ports are opt-in.
// No TLS downgrade: when `origin` is TLS-protected (is_tls(), read here,
// once), an ldaps:// target is opened as such and an ldap:// one with
// StartTLS (connection_options::start_tls); a failed StartTLS fails the URI
// (the error, never a plain connection). Otherwise `options` apply as given
// (an ldaps:// target is still TLS). The server certificate is checked as
// `options.tls` says, against the referred host (RFC 4513 section 3.1.3: the
// reference identity is the host the URL names): tls_options::server_name is
// cleared, and an internationalized name is connected to in its ASCII form.
// Binding: `setup` runs on each new connection (simple_bind_setup,
// sasl_bind_setup, or any session_setup; it may bind with other
// credentials, or look at connection::name() to choose); empty: the
// connection stays anonymous. The library never sends the origin's
// credentials by itself. A connect, StartTLS or setup failure fails the URI.
// Its connect, StartTLS and setup stop when the chase's budget is spent.
// The connections close when the last copy of the connector is destroyed
// (without an UnbindRequest), so keep it as long as the results need no
// more of them; `ioc` must outlive it.
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
