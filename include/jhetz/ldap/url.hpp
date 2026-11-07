// LDAP URLs (RFC 4516), DESIGN.md section 1: the server to connect to, and
// later the targets of referrals and search continuation references.
//
//   ldapurl = scheme "://" [host [":" port]]
//             ["/" dn ["?" [attributes] ["?" [scope] ["?" [filter] ["?" extensions]]]]]
//
// Schemes: `ldap` (plain TCP, default port 389), `ldaps` (TLS from the first
// byte, default port 636) and `ldapi` (Unix domain socket; the host part is
// the percent-encoded socket path, e.g. `ldapi://%2Fvar%2Frun%2Fslapd%2Fldapi`,
// and a port is not allowed). Scheme names are case-insensitive.
//
// Host: reg-name, IPv4 or bracketed IPv6 (`[::1]`, also with an RFC 6874 zone
// `[fe80::1%25eth0]`); IPvFuture and userinfo (`user@host`) are rejected. The
// host may be empty (`ldap:///dc=example`, `ldapi://`): RFC 4516 leaves the
// server to client configuration then. parse() accepts it, so referrals can be
// represented; net::connect() rejects it (see net/connect.hpp).
//
// Every part is percent-decoded when parsed and stored decoded; to_string()
// encodes again. Absent and present-but-empty parts are kept apart where RFC
// 4511 gives them different meanings for referrals (section 4.1.10: an absent
// DN, scope or filter means "same as the original request"):
// - base_dn(): nullopt without "/", the (possibly empty) DN after "/";
// - scope(), search_filter(): nullopt when absent or empty;
// - port(): nullopt when absent or empty (`host:`), port_or_default() applies
//   the scheme's default.
// Attributes and extensions are lists; absent and empty are the same.
//
// Validation: the DN must be RFC 4514 (dn::parse), the filter RFC 4515
// (filter::raw), scope one of base/one/sub (case-insensitive), extension
// types descriptors or numeric OIDs, attribute selectors non-empty. The port
// must be 1..65535. Characters outside RFC 3986 are rejected, except that
// unencoded spaces and bytes >= 0x80 are accepted in the DN, attribute, scope,
// filter and extension parts (some servers send them); a '#' (fragment) is
// always rejected. After percent-decoding, the attribute, filter and
// extension parts must be well-formed UTF-8 (RFC 4516 section 2), like the
// DN (dn::parse). Errors are client_errc::invalid_url with the reason and
// offset in the context.
//
// Comparison is syntactic on the decoded parts: host names are compared
// exactly (no case folding), the DN with dn's equality, the filter as a tree
// (so `cn=x` and `(cn=x)` are the same filter). to_string() writes the
// filter's canonical text (filter::to_string), so it is canonical too.
//
// Memory (DESIGN.md section 8): url is allocator-aware. Everything it owns
// (strings, lists, the DN and the filter tree) uses the resource given to
// parse() or the constructor (default: std::pmr::get_default_resource(),
// i.e. the heap); a plain copy uses the default resource, the
// allocator-extended copy the one given, as for any pmr container, and
// assignment keeps this url's resource.
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
	ldap,// TCP, default port 389
	ldaps,// TLS over TCP, default port 636
	ldapi,// Unix domain socket
};

// "ldap", "ldaps" or "ldapi".
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

	// dec-octet "." dec-octet "." dec-octet "." dec-octet (no leading zeros).
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

	// RFC 3986 IPv6address: eight 16-bit groups, at most one "::" standing for
	// one or more zero groups, optionally ending in an IPv4 address (two groups).
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

	// `s` holds only characters `allowed` accepts and %XX triplets, decodes
	// to at least one byte, and no decoded byte is a C0 control or DEL.
	template<class Allowed>
	constexpr auto is_encoded_host_text(std::string_view s, const Allowed &allowed) noexcept -> bool
	{
		constexpr unsigned ascii_delete = 0x7F;
		if (s.empty()) {
			return false;
		}
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
			if (byte < ' ' || byte == ascii_delete) {
				return false;
			}
		}
		return true;
	}

	// RFC 3986 port: digits, 1..65535; empty means the scheme's default.
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

	// The text of the server url literal: `scheme://host[:port]`, optionally
	// followed by one '/', where the host is a reg-name, a bracketed IPv6
	// address (with an optional "%25" zone) or, for ldapi, the encoded
	// socket path (no port). url::parse_server accepts everything this does.
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
			if (zone != std::string_view::npos && !is_encoded_host_text(literal.substr(zone + 3), is_url_unreserved)) {
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
			if (!is_encoded_host_text(authority.substr(0, colon), is_url_reg_name_char)) {
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
// Allocator-aware like url: in a url (a pmr::vector<url_extension>) the
// strings live on the url's resource; assignment keeps the target's resource.
struct url_extension
{
	using allocator_type = std::pmr::polymorphic_allocator<>;

	std::pmr::string type{};// descriptor or numeric OID, e.g. "bindname", "1.2.3.4"
	std::optional<std::pmr::string> value{};// decoded; nullopt without '=', "" for "type="
	bool critical = false;// '!' prefix: a client that does not know it must not use the URL

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

	// Compile-time checked server URL literal:
	// `ldap::url{"ldaps://ldap.example.org"}` (consteval: text that is not
	// `scheme://host[:port]` with an optional trailing '/' fails to compile,
	// see detail::is_server_url_literal; other text uses parse_server()).
	struct literal
	{
		// Implicit on purpose: `"..."` converts to the literal, checked at compile time.
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

	// `ldap://` (no host, nothing else).
	url() = default;
	explicit url(const allocator_type &alloc);
	explicit url(literal l, const allocator_type &alloc = {});
	url(const url &) = default;// default resource, like any pmr container copy
	url(url &&) noexcept = default;
	url(const url &other, const allocator_type &alloc);
	url(url &&other, const allocator_type &alloc);
	// Assignment keeps this url's resource for everything it owns.
	auto operator=(const url &other) -> url &;
	auto operator=(url &&other) -> url &;
	~url() = default;

	[[nodiscard]] auto get_allocator() const noexcept -> allocator_type { return host_.get_allocator(); }

	// Parses RFC 4516 text; fails with invalid_url (never throws on bad input).
	// The url's strings and lists are allocated from `mr`.
	[[nodiscard]] static auto parse(std::string_view text,
	  std::pmr::memory_resource *mr = std::pmr::get_default_resource()) -> result<url>;
	// parse(), then check_server(): a URL to connect to, as
	// client_options::servers needs. Fails with invalid_url.
	[[nodiscard]] static auto parse_server(std::string_view text,
	  std::pmr::memory_resource *mr = std::pmr::get_default_resource()) -> result<url>;
	// parse_server() on each text, in order; the first failure is returned,
	// its context naming the text's index.
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
	// Parses each URI (e.g. the referral or continuation references of a
	// result) and returns those that are valid LDAP URLs, in order; the
	// others are left out (servers may send any URI scheme).
	[[nodiscard]] static auto parse_list(const std::pmr::vector<std::pmr::string> &uris,
	  std::pmr::memory_resource *mr = std::pmr::get_default_resource()) -> std::pmr::vector<url>;

	// RFC 4516 text: lower-case scheme, IPv6 in brackets, the port only if
	// one was given, then only as many parts as needed to carry the ones that
	// are set. Characters that are not unreserved (RFC 3986) and would be
	// ambiguous in their part are percent-encoded (always `%`, `?`, `#`, and
	// `,` inside attributes and extension values; `/` in an ldapi path).
	// parse(to_string()) == *this.
	[[nodiscard]] auto to_string(std::pmr::memory_resource *mr = std::pmr::get_default_resource()) const
	  -> std::pmr::string;

	[[nodiscard]] auto scheme() const noexcept -> url_scheme { return scheme_; }
	// Decoded host: a name, an IPv4 address, an IPv6 address without the
	// brackets (zone after '%'), or for ldapi the socket path. May be empty.
	[[nodiscard]] auto host() const noexcept -> const std::pmr::string & { return host_; }
	// The host was written as a bracketed IPv6 literal.
	[[nodiscard]] auto host_is_ipv6() const noexcept -> bool { return host_is_ipv6_; }
	// The port as written; nullopt when absent (always for ldapi).
	[[nodiscard]] auto port() const noexcept -> std::optional<std::uint16_t> { return port_; }
	// port(), or 389 for ldap and 636 for ldaps; 0 for ldapi.
	[[nodiscard]] auto port_or_default() const noexcept -> std::uint16_t;
	// Encoded `host:port` with the port made explicit (`[::1]:389`), or the
	// encoded socket path for ldapi. For error messages and logs.
	[[nodiscard]] auto authority(std::pmr::memory_resource *mr = std::pmr::get_default_resource()) const
	  -> std::pmr::string;

	// nullopt when the URL has no "/" (then no later part either).
	[[nodiscard]] auto base_dn() const noexcept -> const std::optional<dn> & { return dn_; }
	// Attribute selectors as written (decoded): descriptions, "*", "+", "1.1".
	[[nodiscard]] auto attributes() const noexcept -> const std::pmr::vector<std::pmr::string> & { return attributes_; }
	[[nodiscard]] auto scope() const noexcept -> std::optional<search_scope> { return scope_; }
	[[nodiscard]] auto search_filter() const noexcept -> const std::optional<ldap::filter> & { return filter_; }
	[[nodiscard]] auto extensions() const noexcept -> const std::pmr::vector<url_extension> & { return extensions_; }
	// True if some extension is marked critical ('!'). This library knows no
	// extension yet, so such a URL must not be used (RFC 4516 section 2.1).
	[[nodiscard]] auto has_critical_extension() const noexcept -> bool;

	// The server rule, for a URL to connect to (client_options::servers):
	// a non-empty host (for ldapi, a socket path) without control characters
	// once decoded (a leading NUL in an ldapi path, a Linux abstract socket,
	// is allowed on Linux), no critical extension, and no DN, attributes,
	// scope or filter (an empty DN, `ldap://host/`, is allowed). Fails with
	// invalid_url naming the broken rule. net::connect() checks the same
	// host and extensions but ignores the DN and later parts.
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

	// The host and extension part of url::check_server(), shared with
	// net::connect(); the context is the bare reason.
	[[nodiscard]] auto check_server_address(const url &u) -> result<void>;

}// namespace detail

}// namespace jhetz::ldap
