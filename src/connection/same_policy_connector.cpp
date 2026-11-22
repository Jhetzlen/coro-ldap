// make_same_policy_connector (referral_chase.hpp): a referral_connector
// that keeps the origin's security policy.
#include "jhetz/ldap/referral_chase.hpp"

#include "../net/host_name.hpp"
#include "referral_chase_impl.hpp"

#include <boost/capy/error.hpp>
#include <boost/capy/ex/this_coro.hpp>

#include <algorithm>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <memory_resource>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

namespace capy = boost::capy;
namespace corosio = boost::corosio;

namespace jhetz::ldap {
namespace {

	constexpr unsigned char first_non_ascii = 0x80;

	// Dotted decimal: an IPv4 literal, matching only itself.
	auto is_ipv4_literal(std::string_view host) -> bool
	{
		return !host.empty() && std::ranges::all_of(host, [](char c) { return (c >= '0' && c <= '9') || c == '.'; });
	}

	// A decoded reg-name with only host name bytes: ASCII letters, digits, '-',
	// '.', '_', and UTF-8.
	auto plausible_name(std::string_view host) -> bool
	{
		return std::ranges::all_of(host, [](char c) {
			const auto u = static_cast<unsigned char>(c);
			return u >= first_non_ascii || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
				   || c == '-' || c == '.' || c == '_';
		});
	}

	// An IPv6 address as a URL holds it (no zone identifier).
	auto plausible_ipv6(std::string_view host) -> bool
	{
		return !host.empty() && std::ranges::all_of(host, [](char c) {
			return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') || c == ':' || c == '.';
		});
	}

	// An allow-list entry: a host and the one extra port it allows, if any.
	struct allowed_entry
	{
		std::string_view host{};
		std::optional<std::uint16_t> port{};
	};

	auto parse_port(std::string_view text) -> std::optional<std::uint16_t>
	{
		std::uint16_t port = 0;
		const auto [ptr, ec] = std::from_chars(text.data(), text.data() + text.size(), port);
		if (text.empty() || ec != std::errc{} || ptr != text.data() + text.size() || port == 0) {
			return std::nullopt;
		}
		return port;
	}

	// nullopt for an entry that cannot be read (it then allows nothing).
	auto split_entry(std::string_view e) -> std::optional<allowed_entry>
	{
		if (e.starts_with('[')) {
			const auto close = e.find(']');
			if (close == std::string_view::npos) {
				return std::nullopt;
			}
			const auto rest = e.substr(close + 1);
			allowed_entry out{ .host = e.substr(1, close - 1) };
			if (rest.empty()) {
				return out;
			}
			if (!rest.starts_with(':')) {
				return std::nullopt;
			}
			out.port = parse_port(rest.substr(1));
			if (!out.port) {
				return std::nullopt;
			}
			return out;
		}
		const auto colon = e.find(':');
		if (colon == std::string_view::npos || e.find(':', colon + 1) != std::string_view::npos) {
			return allowed_entry{ .host = e };
		}
		const auto port = parse_port(e.substr(colon + 1));
		if (!port) {
			return std::nullopt;
		}
		return allowed_entry{ .host = e.substr(0, colon), .port = port };
	}

	auto default_port(url_scheme scheme) -> std::uint16_t
	{
		return scheme == url_scheme::ldaps ? url::default_ldaps_port : url::default_ldap_port;
	}

	// `entry` names `name` (the target's host in ASCII form): the same
	// address for an IP address, else the same name or a subdomain of it.
	auto host_matches(std::string_view name, bool ip, std::string_view entry) -> bool
	{
		if (ip) {
			return net::detail::ascii_host_name(entry) == name;
		}
		if (entry.starts_with('.')) {
			entry.remove_prefix(1);
		}
		const auto suffix = net::detail::ascii_host_name(entry);
		if (!suffix || suffix->empty() || is_ipv4_literal(*suffix)) {
			return false;
		}
		return name == *suffix
			   || (name.size() > suffix->size() && name.ends_with(*suffix)
				   && name[name.size() - suffix->size() - 1] == '.');
	}

	// `target`'s host in ASCII form, if it may be contacted at all.
	auto usable_host(const url &target) -> std::optional<std::string>
	{
		const std::string_view host = target.host();
		if (target.scheme() == url_scheme::ldapi || host.empty()
			|| (target.host_is_ipv6() ? !plausible_ipv6(host) : !plausible_name(host))) {
			return std::nullopt;
		}
		auto name = net::detail::ascii_host_name(host);
		if (!name || name->empty()) {
			return std::nullopt;
		}
		return name;
	}

	// `target`'s host and port are allowed.
	auto server_allowed(const url &target,
	  std::span<const std::string> allowed,
	  std::optional<std::uint16_t> origin_port) -> bool
	{
		const auto name = usable_host(target);
		if (!name) {
			return false;
		}
		const bool ip = target.host_is_ipv6() || is_ipv4_literal(target.host());
		const std::uint16_t port = target.port_or_default();
		const bool usual_port = port == default_port(target.scheme()) || port == origin_port;
		return std::ranges::any_of(allowed, [&](const std::string &text) {
			const auto entry = split_entry(text);
			return entry && (usual_port || entry->port == port) && host_matches(*name, ip, entry->host);
		});
	}

	// `target`, or the same server under its ASCII name (RFC 4513 section
	// 3.1.3.1).
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

	// The connect plan for `target`, without the allow-list: nullopt when
	// its host cannot be used (usable_host).
	auto connect_plan(const url &target, bool origin_protected, const connection_options &options)
	  -> std::optional<detail::referral_connect_plan>
	{
		if (!usable_host(target)) {
			return std::nullopt;
		}
		auto server = connect_url(target);
		if (!server) {
			return std::nullopt;
		}
		detail::referral_connect_plan plan{ .server = std::move(*server), .options = options };
		plan.options.tls.server_name.clear();
		if (target.scheme() == url_scheme::ldaps) {
			plan.options.start_tls = false;
		} else if (origin_protected) {
			plan.options.start_tls = true;
		}
		return plan;
	}

	struct pooled
	{
		url_scheme scheme;
		std::string host;
		std::uint16_t port;
		std::size_t identity;
		std::unique_ptr<connection> conn;
	};

	struct connector_state
	{
		corosio::io_context *ioc;
		bool origin_protected;
		connection_options options;
		detail::referral_chooser choose;
		std::pmr::memory_resource *mr;
		std::vector<pooled> connections{};
	};

	auto connect_to(std::shared_ptr<connector_state> st, url target, std::size_t depth)
	  -> capy::task<result<connection *>>
	{
		if (!usable_host(target)) {
			co_return nullptr;
		}
		auto chosen = st->choose(target, depth);
		if (!chosen) {
			co_return nullptr;
		}
		// The chooser may have stopped the chase: contact nothing then.
		// NOLINTNEXTLINE(clang-analyzer-core.uninitialized.Branch): false positive
		if ((co_await capy::this_coro::stop_token).stop_requested()) {
			co_return std::unexpected(make_error(capy::error::canceled, "referral connect"));
		}
		auto plan = detail::referral_plan(target, st->origin_protected, st->options, *chosen);
		if (!plan) {
			co_return nullptr;
		}
		const url &server = plan->server;
		// The plan's host converts: usable_host checked.
		const std::string host = net::detail::ascii_host_name(server.host()).value_or(std::string(server.host()));
		const auto same = [&server, &host, &chosen](const pooled &p) {
			return p.scheme == server.scheme() && p.host == host && p.port == server.port_or_default()
				   && p.identity == chosen->identity;
		};
		std::erase_if(st->connections, [](const pooled &p) { return !p.conn->is_open(); });
		if (const auto it = std::ranges::find_if(st->connections, same); it != st->connections.end()) {
			co_return it->conn.get();
		}
		auto c = co_await ldap::connect(*st->ioc, server, std::move(plan->options), st->mr);
		if (!c) {
			co_return std::unexpected(std::move(c.error()));
		}
		auto conn = std::make_unique<connection>(std::move(*c));
		if (chosen->setup) {
			if (auto s = co_await chosen->setup(*conn); !s) {
				co_return std::unexpected(std::move(s.error()));
			}
		}
		connection *out = conn.get();
		st->connections.push_back({ .scheme = server.scheme(),
		  .host = host,
		  .port = server.port_or_default(),
		  .identity = chosen->identity,
		  .conn = std::move(conn) });
		co_return out;
	}

}// namespace

namespace detail {

	auto same_policy_plan(const url &target,
	  bool origin_protected,
	  const connection_options &options,
	  std::span<const std::string> allowed_host_suffixes,
	  std::optional<std::uint16_t> origin_port) -> std::optional<referral_connect_plan>
	{
		if (!server_allowed(target, allowed_host_suffixes, origin_port)) {
			return std::nullopt;
		}
		return connect_plan(target, origin_protected, options);
	}

	auto origin_protected(const connection &origin) -> bool
	{
		if (origin.is_tls() || origin.security_layer() == sasl_protection::confidentiality) {
			return true;
		}
		const auto u = url::parse(origin.name());
		return u && u->scheme() == url_scheme::ldapi;
	}

	auto referral_plan(const url &target,
	  bool origin_protected,
	  const connection_options &options,
	  const referral_identity &chosen) -> std::optional<referral_connect_plan>
	{
		auto plan = connect_plan(target, origin_protected, options);
		if (plan && !chosen.client_certificate) {
			plan->options.tls.cert_file.clear();
			plan->options.tls.key_file.clear();
		}
		return plan;
	}

	auto same_policy_identity(session_setup setup) -> referral_identity
	{
		const bool bound = static_cast<bool>(setup);
		return { .setup = std::move(setup), .client_certificate = bound };
	}

	auto referral_server_allowed(const url &target,
	  std::span<const std::string> allowed,
	  std::optional<std::uint16_t> origin_port) -> bool
	{
		return server_allowed(target, allowed, origin_port);
	}

	auto make_policy_connector(corosio::io_context &ioc,
	  bool origin_protected,
	  connection_options options,
	  referral_chooser choose,
	  std::pmr::memory_resource *mr) -> referral_connector
	{
		auto st = std::make_shared<connector_state>(connector_state{ .ioc = &ioc,
		  .origin_protected = origin_protected,
		  .options = std::move(options),
		  .choose = std::move(choose),
		  .mr = mr });
		return [st = std::move(st)](const url &target, std::size_t depth) { return connect_to(st, target, depth); };
	}

}// namespace detail

auto make_same_policy_connector(corosio::io_context &ioc,
  const connection &origin,
  connection_options options,
  std::vector<std::string> allowed_host_suffixes,
  session_setup setup) -> referral_connector
{
	std::optional<std::uint16_t> origin_port;
	if (const auto u = url::parse(origin.name()); u && u->scheme() != url_scheme::ldapi) {
		origin_port = u->port_or_default();
	}
	auto choose = [allowed = std::move(allowed_host_suffixes), origin_port, setup = std::move(setup)](
					const url &target, std::size_t /*depth*/) -> std::optional<detail::referral_identity> {
		if (!server_allowed(target, allowed, origin_port)) {
			return std::nullopt;
		}
		return detail::same_policy_identity(setup);
	};
	return detail::make_policy_connector(
	  ioc, detail::origin_protected(origin), std::move(options), std::move(choose), std::pmr::get_default_resource());
}

}// namespace jhetz::ldap
