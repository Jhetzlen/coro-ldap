// make_same_policy_connector (referral_chase.hpp): a referral_connector
// that keeps the origin's security policy.
#include "jhetz/ldap/referral_chase.hpp"

#include "../net/host_name.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace capy = boost::capy;
namespace corosio = boost::corosio;

namespace jhetz::ldap {
namespace {

	// Dotted decimal: an IPv4 literal, which matches only itself (a suffix
	// match would let "0.0.1" allow "10.0.0.1").
	auto is_ipv4_literal(std::string_view host) -> bool
	{
		return !host.empty() && std::ranges::all_of(host, [](char c) { return (c >= '0' && c <= '9') || c == '.'; });
	}

	// `host` (a URL's, decoded) is in the allow-list.
	auto host_allowed(const url &target, std::span<const std::string> allowed) -> bool
	{
		const std::string_view host = target.host();
		if (target.host_is_ipv6() || is_ipv4_literal(host)) {
			const auto lowered = net::detail::ascii_host_name(host);
			return lowered && std::ranges::any_of(allowed, [&lowered](const std::string &entry) {
				std::string_view e = entry;
				if (e.starts_with('[') && e.ends_with(']')) {
					e = e.substr(1, e.size() - 2);
				}
				return net::detail::ascii_host_name(e) == lowered;
			});
		}
		const auto name = net::detail::ascii_host_name(host);
		if (!name || name->empty()) {
			return false;
		}
		return std::ranges::any_of(allowed, [&name](const std::string &entry) {
			std::string_view e = entry;
			if (e.starts_with('.')) {
				e.remove_prefix(1);
			}
			const auto suffix = net::detail::ascii_host_name(e);
			if (!suffix || suffix->empty() || is_ipv4_literal(*suffix)) {
				return false;
			}
			return *name == *suffix
				   || (name->size() > suffix->size() && name->ends_with(*suffix)
					   && (*name)[name->size() - suffix->size() - 1] == '.');
		});
	}

	// The URL to connect to: `target` itself, or for an internationalized
	// name the same server under its ASCII name (what DNS, SNI and the
	// certificate check expect, RFC 4513 section 3.1.3.1).
	auto connect_url(const url &target) -> std::optional<url>
	{
		const auto ascii = net::detail::ascii_host_name(target.host());
		if (!ascii) {
			return std::nullopt;
		}
		if (net::detail::is_ascii(target.host())) {
			return target;
		}
		auto u = url::parse(
		  std::string(to_string(target.scheme())) + "://" + *ascii + ":" + std::to_string(target.port_or_default()));
		if (!u) {
			return std::nullopt;
		}
		return std::move(*u);
	}

	struct pooled
	{
		url_scheme scheme;
		std::string host;
		std::uint16_t port;
		std::unique_ptr<connection> conn;
	};

	struct connector_state
	{
		corosio::io_context *ioc;
		bool origin_tls;
		connection_options options;
		std::vector<std::string> allowed;
		session_setup setup;
		std::vector<pooled> connections{};
	};

	auto connect_to(std::shared_ptr<connector_state> st, url target) -> capy::task<result<connection *>>
	{
		auto plan = detail::same_policy_plan(target, st->origin_tls, st->options, st->allowed);
		if (!plan) {
			co_return nullptr;
		}
		const url &server = plan->server;
		// The plan's host converts: the allow-list check did.
		const std::string host = net::detail::ascii_host_name(server.host()).value_or(std::string(server.host()));
		const auto same = [&server, &host](const pooled &p) {
			return p.scheme == server.scheme() && p.host == host && p.port == server.port_or_default();
		};
		std::erase_if(st->connections, [](const pooled &p) { return !p.conn->is_open(); });
		if (const auto it = std::ranges::find_if(st->connections, same); it != st->connections.end()) {
			co_return it->conn.get();
		}
		auto c = co_await ldap::connect(*st->ioc, server, std::move(plan->options));
		if (!c) {
			co_return std::unexpected(std::move(c.error()));
		}
		auto conn = std::make_unique<connection>(std::move(*c));
		if (st->setup) {
			if (auto s = co_await st->setup(*conn); !s) {
				co_return std::unexpected(std::move(s.error()));
			}
		}
		connection *out = conn.get();
		st->connections.push_back(
		  { .scheme = server.scheme(), .host = host, .port = server.port_or_default(), .conn = std::move(conn) });
		co_return out;
	}

}// namespace

namespace detail {

	auto same_policy_plan(const url &target,
	  bool origin_tls,
	  const connection_options &options,
	  std::span<const std::string> allowed_host_suffixes) -> std::optional<referral_connect_plan>
	{
		if (target.scheme() == url_scheme::ldapi || target.host().empty()
			|| !host_allowed(target, allowed_host_suffixes)) {
			return std::nullopt;
		}
		auto server = connect_url(target);
		if (!server) {
			return std::nullopt;
		}
		referral_connect_plan plan{ .server = std::move(*server), .options = options };
		plan.options.tls.server_name.clear();
		if (target.scheme() == url_scheme::ldaps) {
			plan.options.start_tls = false;
		} else if (origin_tls) {
			plan.options.start_tls = true;
		}
		return plan;
	}

}// namespace detail

auto make_same_policy_connector(corosio::io_context &ioc,
  const connection &origin,
  connection_options options,
  std::vector<std::string> allowed_host_suffixes,
  session_setup setup) -> referral_connector
{
	auto st = std::make_shared<connector_state>(connector_state{ .ioc = &ioc,
	  .origin_tls = origin.is_tls(),
	  .options = std::move(options),
	  .allowed = std::move(allowed_host_suffixes),
	  .setup = std::move(setup) });
	return [st = std::move(st)](const url &target, std::size_t /*depth*/) { return connect_to(st, target); };
}

}// namespace jhetz::ldap
