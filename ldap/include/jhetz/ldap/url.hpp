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
// (encode_filter), scope one of base/one/sub (case-insensitive), extension
// types descriptors or numeric OIDs, attribute selectors non-empty. The port
// must be 1..65535. Characters outside RFC 3986 are rejected, except that
// unencoded spaces and bytes >= 0x80 are accepted in the DN, attribute, scope,
// filter and extension parts (some servers send them); a '#' (fragment) is
// always rejected. Errors are client_errc::invalid_url with the reason and
// offset in the context.
//
// Comparison is syntactic on the decoded parts: host names are compared
// exactly (no case folding), the DN with dn's equality, the filter as text.
//
// Memory (DESIGN.md section 8): url is allocator-aware. Its own strings and
// lists are std::pmr containers using the resource given to parse() or the
// constructor (default: std::pmr::get_default_resource(), i.e. the heap); a
// plain copy uses the default resource, the allocator-extended copy the one
// given, as for any pmr container. The DN and filter are still the step 3
// types and allocate from the default resource.
// TODO(4b): dn and filter become pmr-aware and take the url's resource.
#pragma once

#include "jhetz/ldap/dn.hpp"
#include "jhetz/ldap/error.hpp"
#include "jhetz/ldap/filter.hpp"
#include "jhetz/ldap/message.hpp"

#include <cstdint>
#include <memory_resource>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace jhetz::ldap {

enum class url_scheme : std::uint8_t {
	ldap,// TCP, default port 389
	ldaps,// TLS over TCP, default port 636
	ldapi,// Unix domain socket
};

// "ldap", "ldaps" or "ldapi".
std::string_view to_string(url_scheme s) noexcept;

// One RFC 4516 extension: `[!]type[=value]`.
// An aggregate; url copies it into its own resource.
struct url_extension
{
	std::pmr::string type{};// descriptor or numeric OID, e.g. "bindname", "1.2.3.4"
	std::optional<std::pmr::string> value{};// decoded; nullopt without '=', "" for "type="
	bool critical = false;// '!' prefix: a client that does not know it must not use the URL

	friend bool operator==(const url_extension &, const url_extension &) = default;
};

class url
{
  public:
	using allocator_type = std::pmr::polymorphic_allocator<>;

	static constexpr std::uint16_t default_ldap_port = 389;
	static constexpr std::uint16_t default_ldaps_port = 636;

	// `ldap://` (no host, nothing else).
	url() = default;
	explicit url(const allocator_type &alloc);
	url(const url &) = default;// default resource, like any pmr container copy
	url(url &&) noexcept = default;
	url(const url &other, const allocator_type &alloc);
	url(url &&other, const allocator_type &alloc);
	url &operator=(const url &) = default;
	url &operator=(url &&) = default;
	~url() = default;

	allocator_type get_allocator() const noexcept { return host_.get_allocator(); }

	// Parses RFC 4516 text; fails with invalid_url (never throws on bad input).
	// The url's strings and lists are allocated from `mr`.
	static result<url> parse(std::string_view text, std::pmr::memory_resource *mr = std::pmr::get_default_resource());

	// RFC 4516 text: lower-case scheme, IPv6 in brackets, the port only if
	// one was given, then only as many parts as needed to carry the ones that
	// are set. Characters that are not unreserved (RFC 3986) and would be
	// ambiguous in their part are percent-encoded (always `%`, `?`, `#`, and
	// `,` inside attributes and extension values; `/` in an ldapi path).
	// parse(to_string()) == *this.
	std::pmr::string to_string(std::pmr::memory_resource *mr = std::pmr::get_default_resource()) const;

	url_scheme scheme() const noexcept { return scheme_; }
	// Decoded host: a name, an IPv4 address, an IPv6 address without the
	// brackets (zone after '%'), or for ldapi the socket path. May be empty.
	const std::pmr::string &host() const noexcept { return host_; }
	// The host was written as a bracketed IPv6 literal.
	bool host_is_ipv6() const noexcept { return host_is_ipv6_; }
	// The port as written; nullopt when absent (always for ldapi).
	std::optional<std::uint16_t> port() const noexcept { return port_; }
	// port(), or 389 for ldap and 636 for ldaps; 0 for ldapi.
	std::uint16_t port_or_default() const noexcept;
	// Encoded `host:port` with the port made explicit (`[::1]:389`), or the
	// encoded socket path for ldapi. For error messages and logs.
	std::pmr::string authority(std::pmr::memory_resource *mr = std::pmr::get_default_resource()) const;

	// nullopt when the URL has no "/" (then no later part either).
	const std::optional<dn> &base_dn() const noexcept { return dn_; }
	// Attribute selectors as written (decoded): descriptions, "*", "+", "1.1".
	const std::pmr::vector<std::pmr::string> &attributes() const noexcept { return attributes_; }
	std::optional<search_scope> scope() const noexcept { return scope_; }
	const std::optional<ldap::filter> &search_filter() const noexcept { return filter_; }
	const std::pmr::vector<url_extension> &extensions() const noexcept { return extensions_; }
	// True if some extension is marked critical ('!'). This library knows no
	// extension yet, so such a URL must not be used (RFC 4516 section 2.1).
	bool has_critical_extension() const noexcept;

	friend bool operator==(const url &, const url &) = default;

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

}// namespace jhetz::ldap
