// LDAP URLs (RFC 4516): parsed, percent-decoded and validated; absent and
// empty parts kept apart for referrals (docs/API.md, DESIGN.md section 1).
#pragma once

#include "jhetz/ldap/dn.hpp"
#include "jhetz/ldap/error.hpp"
#include "jhetz/ldap/filter.hpp"
#include "jhetz/ldap/message.hpp"

#include <concepts>
#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <memory_resource>
#include <optional>
#include <ranges>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace jhetz::ldap {

enum class url_scheme : std::uint8_t {
	ldap,// default port 389
	ldaps,// TLS, default port 636
	ldapi,
};

[[nodiscard]] auto to_string(url_scheme s) noexcept -> std::string_view;

namespace detail {

	// RFC 3986 section 2 character classes.
	constexpr auto is_url_unreserved(char c) noexcept -> bool
	{
		return is_alpha(c) || is_digit(c) || c == '-' || c == '.' || c == '_' || c == '~';
	}

	constexpr auto is_url_sub_delim(char c) noexcept -> bool
	{
		switch (c) {
		case '!':
		case '$':
		case '&':
		case '\'':
		case '(':
		case ')':
		case '*':
		case '+':
		case ',':
		case ';':
		case '=':
			return true;
		default:
			return false;
		}
	}

	constexpr auto is_url_reg_name_char(char c) noexcept -> bool { return is_url_unreserved(c) || is_url_sub_delim(c); }

	// dec-octet "." dec-octet "." dec-octet "." dec-octet, no leading zeros.
	constexpr auto is_ipv4(std::string_view s) noexcept -> bool
	{
		constexpr unsigned max_octet = 255;
		constexpr std::size_t max_octet_digits = 3;
		constexpr int ipv4_parts = 4;
		int parts = 0;
		std::size_t i = 0;
		while (true) {
			const std::size_t start = i;
			unsigned value = 0;
			while (i < s.size() && is_digit(s[i]) && i - start < max_octet_digits) {
				value = (value * 10) + static_cast<unsigned>(s[i++] - '0');
			}
			const std::size_t len = i - start;
			if (len == 0 || value > max_octet || (len > 1 && s[start] == '0')) {
				return false;
			}
			++parts;
			if (parts == ipv4_parts) {
				return i == s.size();
			}
			if (i == s.size() || s[i] != '.') {
				return false;
			}
			++i;
		}
	}

	// RFC 3986 IPv6address.
	constexpr auto is_ipv6(std::string_view s) noexcept -> bool
	{
		constexpr int ipv6_groups = 8;
		constexpr std::size_t max_group_digits = 4;
		const std::size_t n = s.size();
		std::size_t i = 0;
		int groups = 0;
		bool compressed = false;
		if (n >= 2 && s[0] == ':' && s[1] == ':') {
			compressed = true;
			i = 2;
			if (i == n) {
				return true;
			}
		} else if (n == 0 || s[0] == ':') {
			return false;
		}
		while (true) {
			const std::size_t start = i;
			while (i < n && is_hex(s[i]) && i - start <= max_group_digits) {
				++i;
			}
			if (i < n && s[i] == '.') {
				if (!is_ipv4(s.substr(start))) {
					return false;
				}
				groups += 2;
				break;
			}
			const std::size_t len = i - start;
			if (len == 0 || len > max_group_digits) {
				return false;
			}
			++groups;
			if (i == n) {
				break;
			}
			if (s[i] != ':') {
				return false;
			}
			++i;
			if (i < n && s[i] == ':') {
				if (compressed) {
					return false;
				}
				compressed = true;
				++i;
				if (i == n) {
					break;
				}
			} else if (i == n) {
				return false;
			}
		}
		return compressed ? groups < ipv6_groups : groups == ipv6_groups;
	}

	// Only `allowed` characters and %XX triplets, decoding to at least one byte
	// without C0 or DEL, and with `utf8` to well-formed UTF-8.
	template<class Allowed>
	constexpr auto is_encoded_host_text(std::string_view s, const Allowed &allowed, bool utf8) noexcept -> bool
	{
		constexpr unsigned delete_octet = 0x7F;
		constexpr unsigned ascii_end = 0x80;
		if (s.empty()) {
			return false;
		}
		std::size_t pending = 0;
		unsigned next_first = utf8_continuation_first;
		unsigned next_last = utf8_continuation_last;
		for (std::size_t i = 0; i < s.size(); ++i) {
			unsigned byte = static_cast<unsigned char>(s[i]);
			if (s[i] == '%') {
				if (i + 2 >= s.size() || !is_hex(s[i + 1]) || !is_hex(s[i + 2])) {
					return false;
				}
				byte = (hex_value(s[i + 1]) << 4) | hex_value(s[i + 2]);
				i += 2;
			} else if (!allowed(s[i])) {
				return false;
			}
			if (byte < ' ' || byte == delete_octet) {
				return false;
			}
			if (!utf8 || (pending == 0 && byte < ascii_end)) {
				continue;
			}
			if (pending > 0) {
				if (byte < next_first || byte > next_last) {
					return false;
				}
				--pending;
				next_first = utf8_continuation_first;
				next_last = utf8_continuation_last;
				continue;
			}
			utf8_lead_range lead{};
			for (const auto &r : utf8_lead_ranges) {
				if (byte >= r.lead_first && byte <= r.lead_last) {
					lead = r;
				}
			}
			if (lead.length == 0) {
				return false;
			}
			pending = lead.length - 1;
			next_first = lead.second_first;
			next_last = lead.second_last;
		}
		return pending == 0;
	}

	// RFC 3986 port: digits, 1..65535; empty: the scheme's default.
	constexpr auto is_url_port(std::string_view s) noexcept -> bool
	{
		constexpr unsigned max_port = 65535;
		unsigned value = 0;
		for (const char c : s) {
			if (!is_digit(c)) {
				return false;
			}
			value = (value * 10) + static_cast<unsigned>(c - '0');
			if (value > max_port) {
				return false;
			}
		}
		return s.empty() || value != 0;
	}

	// `e` with "servers[index]: " before its context.
	[[nodiscard]] auto server_list_error(error e, std::size_t index) -> error;

	// The text the server url literal accepts: `scheme://host[:port]`, an
	// optional '/'.
	constexpr auto is_server_url_literal(std::string_view s) noexcept -> bool
	{
		const std::size_t sep = s.find("://");
		if (sep == std::string_view::npos) {
			return false;
		}
		const std::string_view scheme = s.substr(0, sep);
		const bool ldapi = iequals(scheme, "ldapi");
		if (!ldapi && !iequals(scheme, "ldap") && !iequals(scheme, "ldaps")) {
			return false;
		}
		std::string_view authority = s.substr(sep + 3);
		if (!authority.empty() && authority.back() == '/') {
			authority.remove_suffix(1);
		}
		std::string_view port;
		bool has_port = false;
		if (!authority.empty() && authority.front() == '[') {
			const std::size_t close = authority.find(']');
			if (ldapi || close == std::string_view::npos) {
				return false;
			}
			const std::string_view literal = authority.substr(1, close - 1);
			const std::size_t zone = literal.find("%25");
			if (!is_ipv6(literal.substr(0, zone))) {
				return false;
			}
			if (zone != std::string_view::npos
				&& !is_encoded_host_text(literal.substr(zone + 3), is_url_unreserved, true)) {
				return false;
			}
			const std::string_view rest = authority.substr(close + 1);
			if (!rest.empty()) {
				if (rest.front() != ':') {
					return false;
				}
				has_port = true;
				port = rest.substr(1);
			}
		} else {
			const std::size_t colon = authority.find(':');
			if (!is_encoded_host_text(authority.substr(0, colon), is_url_reg_name_char, !ldapi)) {
				return false;
			}
			if (colon != std::string_view::npos) {
				has_port = true;
				port = authority.substr(colon + 1);
			}
		}
		return !has_port || (!ldapi && is_url_port(port));
	}

}// namespace detail

// One RFC 4516 extension: `[!]type[=value]`.
struct url_extension
{
	using allocator_type = std::pmr::polymorphic_allocator<>;

	std::pmr::string type{};// descriptor or numeric OID
	std::optional<std::pmr::string> value{};// decoded; nullopt without '='
	bool critical = false;// '!' prefix

	url_extension() = default;
	explicit url_extension(const allocator_type &alloc) : type(alloc) {}
	explicit url_extension(std::string_view type_,
	  std::optional<std::string_view> value_ = std::nullopt,
	  bool critical_ = false,
	  const allocator_type &alloc = {});
	url_extension(const url_extension &) = default;// default resource, like any pmr copy
	url_extension(url_extension &&) noexcept = default;
	url_extension(const url_extension &other, const allocator_type &alloc);
	url_extension(url_extension &&other, const allocator_type &alloc);
	auto operator=(const url_extension &other) -> url_extension &;
	auto operator=(url_extension &&other) -> url_extension &;
	~url_extension() = default;

	[[nodiscard]] auto get_allocator() const noexcept -> allocator_type { return type.get_allocator(); }

	friend auto operator==(const url_extension &, const url_extension &) -> bool = default;
};

class url
{
  public:
	using allocator_type = std::pmr::polymorphic_allocator<>;

	static constexpr std::uint16_t default_ldap_port = 389;
	static constexpr std::uint16_t default_ldaps_port = 636;

	// A server URL literal checked at compile time.
	struct literal
	{
		// NOLINTNEXTLINE(cppcoreguidelines-explicit-constructor,misc-explicit-constructor)
		consteval literal(const char *s) : text(s)
		{
			if (!detail::is_server_url_literal(s)) {
				// NOLINTNEXTLINE(bugprone-std-exception-baseclass): consteval, fails compilation with this text
				throw "ldap::url: not a server URL (scheme://host[:port])";
			}
		}
		const char *text;
	};

	// `ldap://`
	url() = default;
	explicit url(const allocator_type &alloc);
	explicit url(literal l, const allocator_type &alloc = {});
	url(const url &) = default;// default resource, like any pmr copy
	url(url &&) noexcept = default;
	url(const url &other, const allocator_type &alloc);
	url(url &&other, const allocator_type &alloc);
	auto operator=(const url &other) -> url &;
	auto operator=(url &&other) -> url &;
	~url() = default;

	[[nodiscard]] auto get_allocator() const noexcept -> allocator_type { return host_.get_allocator(); }

	// Parses RFC 4516 text into `mr`; invalid_url on bad input.
	[[nodiscard]] static auto parse(std::string_view text,
	  std::pmr::memory_resource *mr = std::pmr::get_default_resource()) -> result<url>;
	// parse(), then check_server().
	[[nodiscard]] static auto parse_server(std::string_view text,
	  std::pmr::memory_resource *mr = std::pmr::get_default_resource()) -> result<url>;
	// parse_server() on each text; the context names the failing index.
	template<std::ranges::input_range R>
		requires std::convertible_to<std::ranges::range_reference_t<const R>, std::string_view>
	[[nodiscard]] static auto parse_servers(const R &texts,
	  std::pmr::memory_resource *mr = std::pmr::get_default_resource()) -> result<std::vector<url>>
	{
		std::vector<url> out;
		std::size_t index = 0;
		for (const auto &text : texts) {
			auto u = parse_server(std::string_view(text), mr);
			if (!u) {
				return std::unexpected(detail::server_list_error(std::move(u.error()), index));
			}
			out.push_back(std::move(*u));
			++index;
		}
		return out;
	}
	[[nodiscard]] static auto parse_servers(std::initializer_list<std::string_view> texts,
	  std::pmr::memory_resource *mr = std::pmr::get_default_resource()) -> result<std::vector<url>>
	{
		return parse_servers<std::initializer_list<std::string_view>>(texts, mr);
	}
	// The valid LDAP URLs among `uris`, in order.
	[[nodiscard]] static auto parse_list(const std::pmr::vector<std::pmr::string> &uris,
	  std::pmr::memory_resource *mr = std::pmr::get_default_resource()) -> std::pmr::vector<url>;

	// Canonical RFC 4516 text; parse(to_string()) == *this.
	[[nodiscard]] auto to_string(std::pmr::memory_resource *mr = std::pmr::get_default_resource()) const
	  -> std::pmr::string;

	[[nodiscard]] auto scheme() const noexcept -> url_scheme { return scheme_; }
	// Decoded: a name, IPv4, IPv6 without brackets, or the ldapi socket path.
	[[nodiscard]] auto host() const noexcept -> const std::pmr::string & { return host_; }
	[[nodiscard]] auto host_is_ipv6() const noexcept -> bool { return host_is_ipv6_; }
	// nullopt when absent (always for ldapi).
	[[nodiscard]] auto port() const noexcept -> std::optional<std::uint16_t> { return port_; }
	// 389 for ldap, 636 for ldaps, 0 for ldapi when no port is given.
	[[nodiscard]] auto port_or_default() const noexcept -> std::uint16_t;
	// Encoded `host:port` (`[::1]:389`), or the ldapi path; for logs.
	[[nodiscard]] auto authority(std::pmr::memory_resource *mr = std::pmr::get_default_resource()) const
	  -> std::pmr::string;

	// nullopt without "/".
	[[nodiscard]] auto base_dn() const noexcept -> const std::optional<dn> & { return dn_; }
	[[nodiscard]] auto attributes() const noexcept -> const std::pmr::vector<std::pmr::string> & { return attributes_; }
	[[nodiscard]] auto scope() const noexcept -> std::optional<search_scope> { return scope_; }
	[[nodiscard]] auto search_filter() const noexcept -> const std::optional<ldap::filter> & { return filter_; }
	[[nodiscard]] auto extensions() const noexcept -> const std::pmr::vector<url_extension> & { return extensions_; }
	// Such a URL must not be used (RFC 4516 section 2.1): none is known.
	[[nodiscard]] auto has_critical_extension() const noexcept -> bool;

	// A URL to connect to: a non-empty host and nothing after it but an empty
	// DN; invalid_url naming the broken rule.
	[[nodiscard]] auto check_server() const -> result<void>;

	friend auto operator==(const url &, const url &) -> bool = default;

  private:
	url_scheme scheme_ = url_scheme::ldap;
	std::pmr::string host_{};
	bool host_is_ipv6_ = false;
	std::optional<std::uint16_t> port_{};
	std::optional<dn> dn_{};
	std::pmr::vector<std::pmr::string> attributes_{};
	std::optional<search_scope> scope_{};
	std::optional<ldap::filter> filter_{};
	std::pmr::vector<url_extension> extensions_{};
};

namespace detail {

	// The host and extension part of check_server(), shared with net::connect().
	[[nodiscard]] auto check_server_address(const url &u) -> result<void>;

}// namespace detail

}// namespace jhetz::ldap
