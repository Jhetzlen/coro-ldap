#include "jhetz/ldap/url.hpp"

#include "format_util.hpp"
#include "pmr_util.hpp"

#include <algorithm>
#include <cstddef>
#include <string>
#include <string_view>
#include <utility>

namespace jhetz::ldap {
namespace {

	using detail::hex_value;
	using detail::iequals;
	using detail::is_alpha;
	using detail::is_digit;
	using detail::is_hex;

	// ------------------------------------------------------------ character classes (RFC 3986 section 2)

	constexpr auto is_unreserved(char c) noexcept -> bool
	{
		return is_alpha(c) || is_digit(c) || c == '-' || c == '.' || c == '_' || c == '~';
	}

	constexpr auto is_sub_delim(char c) noexcept -> bool
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

	// pchar / "/" (without '%', handled as pct-encoded): what may appear
	// unencoded in the path and query of a URI. '?' is the RFC 4516 part
	// separator and is excluded.
	constexpr auto is_part_char(char c) noexcept -> bool
	{
		return is_unreserved(c) || is_sub_delim(c) || c == ':' || c == '@' || c == '/';
	}

	// Leniency in the parts after the host: unencoded spaces and non-ASCII
	// bytes are unambiguous, and some servers send them.
	constexpr auto is_lenient_part_char(char c) noexcept -> bool
	{
		return is_part_char(c) || c == ' ' || static_cast<unsigned char>(c) >= 0x80;
	}

	constexpr auto is_reg_name_char(char c) noexcept -> bool { return is_unreserved(c) || is_sub_delim(c); }

	// ------------------------------------------------------------ errors

	auto bad(std::string_view what, std::size_t offset) -> std::unexpected<error>
	{
		return fail(client_errc::invalid_url, detail::format("url: {} at offset {}", what, offset));
	}

	// ------------------------------------------------------------ percent-encoding

	// Checks `s` (starting at `offset` in the URL) against `allowed` plus
	// pct-encoded triplets, and returns the decoded bytes.
	template<class Allowed>
	auto
	  decode(std::string_view s, std::size_t offset, const char *what, Allowed allowed, std::pmr::memory_resource *mr)
		-> result<std::pmr::string>
	{
		std::pmr::string out(mr);
		out.reserve(s.size());
		for (std::size_t i = 0; i < s.size(); ++i) {
			const char c = s[i];
			if (c == '%') {
				if (i + 2 >= s.size()) {
					return bad(detail::format("truncated percent-encoding in {}", what), offset + i);
				}
				if (!is_hex(s[i + 1]) || !is_hex(s[i + 2])) {
					return bad(detail::format("invalid percent-encoding in {}", what), offset + i);
				}
				out += static_cast<char>((hex_value(s[i + 1]) << 4) | hex_value(s[i + 2]));
				i += 2;
			} else if (allowed(c)) {
				out += c;
			} else {
				return bad(detail::format("character not allowed in {}", what), offset + i);
			}
		}
		return out;
	}

	constexpr auto hex_digit(unsigned v) noexcept -> char { return "0123456789ABCDEF"[v & 0xFu]; }

	// Percent-encodes every byte for which `keep` is false.
	template<class Keep> void encode(std::pmr::string &out, std::string_view s, Keep keep)
	{
		for (char c : s) {
			if (keep(c)) {
				out += c;
			} else {
				const auto b = static_cast<unsigned char>(c);
				out += '%';
				out += hex_digit(b >> 4);
				out += hex_digit(b);
			}
		}
	}

	// ------------------------------------------------------------ addresses

	// dec-octet "." dec-octet "." dec-octet "." dec-octet (no leading zeros).
	auto is_ipv4(std::string_view s) noexcept -> bool
	{
		int parts = 0;
		std::size_t i = 0;
		while (true) {
			const std::size_t start = i;
			unsigned value = 0;
			while (i < s.size() && is_digit(s[i]) && i - start < 3) {
				value = (value * 10) + static_cast<unsigned>(s[i++] - '0');
			}
			const std::size_t len = i - start;
			if (len == 0 || value > 255 || (len > 1 && s[start] == '0')) {
				return false;
			}
			++parts;
			if (parts == 4) {
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
	auto is_ipv6(std::string_view s) noexcept -> bool
	{
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
			while (i < n && is_hex(s[i]) && i - start < 5) {
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
			if (len == 0 || len > 4) {
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
				return false;// trailing single ':'
			}
		}
		return compressed ? groups <= 7 : groups == 8;
	}

	// ------------------------------------------------------------ parts

	auto scope_name(search_scope s) noexcept -> std::string_view
	{
		switch (s) {
		case search_scope::base_object:
			return "base";
		case search_scope::single_level:
			return "one";
		case search_scope::whole_subtree:
			return "sub";
		case search_scope::subordinate_subtree:
			break;// RFC 4516 has no name for it; parse() never produces it
		}
		return {};
	}

	// Splits `s` on `sep`, calling on(piece, offset of piece in the URL).
	template<class F> auto split(std::string_view s, std::size_t offset, char sep, const F &on) -> result<void>
	{
		std::size_t start = 0;
		while (true) {
			const std::size_t end = s.find(sep, start);
			const std::string_view piece = s.substr(start, end == std::string_view::npos ? end : end - start);
			if (auto r = on(piece, offset + start); !r) {
				return r;
			}
			if (end == std::string_view::npos) {
				return {};
			}
			start = end + 1;
		}
	}

	// Encoded host as it appears in the URL (brackets for IPv6).
	void append_host(std::pmr::string &out, url_scheme scheme, std::string_view host, bool ipv6)
	{
		if (ipv6) {
			// address%zone: ':' stays literal in the address only; the zone
			// (RFC 6874 ZoneID = 1*(unreserved / pct-encoded)) encodes it.
			const std::size_t zone = host.find('%');
			out += '[';
			encode(out, host.substr(0, zone), [](char c) { return is_unreserved(c) || c == ':'; });
			if (zone != std::string_view::npos) {
				out += "%25";
				encode(out, host.substr(zone + 1), is_unreserved);
			}
			out += ']';
		} else if (scheme == url_scheme::ldapi) {
			encode(out, host, is_unreserved);// '/' becomes %2F
		} else {
			encode(out, host, is_reg_name_char);
		}
	}

}// namespace

url_extension::url_extension(std::string_view type_,
  std::optional<std::string_view> value_,
  bool critical_,
  const allocator_type &alloc)
  : type(type_, alloc), critical(critical_)
{
	if (value_) {
		value.emplace(*value_, alloc);
	}
}

url_extension::url_extension(const url_extension &other, const allocator_type &alloc)
  : type(other.type, alloc), critical(other.critical)
{
	if (other.value) {
		value.emplace(*other.value, alloc);
	}
}

url_extension::url_extension(url_extension &&other, const allocator_type &alloc)
  : type(std::move(other.type), alloc), critical(other.critical)
{
	if (other.value) {
		value.emplace(std::move(*other.value), alloc);
	}
}

// std::optional's own assignment would copy-construct a missing value on the
// default resource; keep it on this extension's resource instead.
auto url_extension::operator=(const url_extension &other) -> url_extension &
{
	if (this == &other) {
		return *this;
	}
	type = other.type;
	if (!other.value) {
		value.reset();
	} else if (value) {
		*value = *other.value;
	} else {
		value.emplace(*other.value, type.get_allocator());
	}
	critical = other.critical;
	return *this;
}

auto url_extension::operator=(url_extension &&other) -> url_extension &
{
	if (this == &other) {
		return *this;
	}
	type = std::move(other.type);
	if (!other.value) {
		value.reset();
	} else if (value) {
		*value = std::move(*other.value);
	} else {
		value.emplace(std::move(*other.value), type.get_allocator());
	}
	critical = other.critical;
	return *this;
}

url::url(const allocator_type &alloc) : host_(alloc), attributes_(alloc), extensions_(alloc) {}

url::url(const url &other, const allocator_type &alloc)
  : scheme_(other.scheme_), host_(other.host_, alloc), host_is_ipv6_(other.host_is_ipv6_), port_(other.port_),
	dn_(detail::optional_with(other.dn_, alloc)), attributes_(other.attributes_, alloc), scope_(other.scope_),
	filter_(detail::optional_with(other.filter_, alloc)), extensions_(other.extensions_, alloc)
{}

// std::optional's own assignment would construct a missing DN or filter on
// the source's (or the default) resource; keep them on this url's resource.
auto url::operator=(const url &other) -> url &
{
	if (this == &other) {
		return *this;
	}
	scheme_ = other.scheme_;
	host_ = other.host_;
	host_is_ipv6_ = other.host_is_ipv6_;
	port_ = other.port_;
	detail::assign_optional(dn_, other.dn_, get_allocator());
	attributes_ = other.attributes_;
	scope_ = other.scope_;
	detail::assign_optional(filter_, other.filter_, get_allocator());
	extensions_ = other.extensions_;
	return *this;
}

auto url::operator=(url &&other) -> url &
{
	if (this == &other) {
		return *this;
	}
	scheme_ = other.scheme_;
	host_ = std::move(other.host_);
	host_is_ipv6_ = other.host_is_ipv6_;
	port_ = other.port_;
	detail::assign_optional(dn_, std::move(other.dn_), get_allocator());
	attributes_ = std::move(other.attributes_);
	scope_ = other.scope_;
	detail::assign_optional(filter_, std::move(other.filter_), get_allocator());
	extensions_ = std::move(other.extensions_);
	return *this;
}

url::url(url &&other, const allocator_type &alloc)
  : url(other.get_allocator() == alloc ? url(std::move(other)) : url(other, alloc))
{}

auto to_string(url_scheme s) noexcept -> std::string_view
{
	switch (s) {
	case url_scheme::ldap:
		return "ldap";
	case url_scheme::ldaps:
		return "ldaps";
	case url_scheme::ldapi:
		return "ldapi";
	}
	return "ldap";
}

auto url::port_or_default() const noexcept -> std::uint16_t
{
	if (port_) {
		return *port_;
	}
	switch (scheme_) {
	case url_scheme::ldap:
		return default_ldap_port;
	case url_scheme::ldaps:
		return default_ldaps_port;
	case url_scheme::ldapi:
		return 0;
	}
	return 0;
}

auto url::has_critical_extension() const noexcept -> bool
{
	return std::ranges::any_of(extensions_, &url_extension::critical);
}

auto url::parse(std::string_view text, std::pmr::memory_resource *mr) -> result<url>
{
	url u{ allocator_type(mr) };

	// ---- scheme
	const std::size_t sep = text.find("://");
	if (sep == std::string_view::npos) {
		return bad("missing \"://\" after the scheme", 0);
	}
	const std::string_view scheme = text.substr(0, sep);
	if (iequals(scheme, "ldap")) {
		u.scheme_ = url_scheme::ldap;
	} else if (iequals(scheme, "ldaps")) {
		u.scheme_ = url_scheme::ldaps;
	} else if (iequals(scheme, "ldapi")) {
		u.scheme_ = url_scheme::ldapi;
	} else {
		return bad("scheme is not ldap, ldaps or ldapi", 0);
	}

	// ---- authority: up to the first '/', or the end
	const std::size_t auth_begin = sep + 3;
	const std::size_t auth_end = text.find_first_of("/?#", auth_begin);
	if (auth_end != std::string_view::npos && text[auth_end] != '/') {
		return bad(
		  text[auth_end] == '#' ? "fragment ('#') not allowed" : "'?' before the DN (\"/\" missing)", auth_end);
	}
	const std::string_view authority =
	  text.substr(auth_begin, auth_end == std::string_view::npos ? std::string_view::npos : auth_end - auth_begin);

	std::string_view port_text;
	std::size_t port_offset = 0;
	bool has_port = false;
	if (!authority.empty() && authority[0] == '[') {
		if (u.scheme_ == url_scheme::ldapi) {
			return bad("IP literal in an ldapi URL", auth_begin);
		}
		const std::size_t close = authority.find(']');
		if (close == std::string_view::npos) {
			return bad("missing ']' after IPv6 address", auth_begin);
		}
		const std::string_view literal = authority.substr(1, close - 1);
		if (!literal.empty() && (literal[0] == 'v' || literal[0] == 'V')) {
			return bad("IPvFuture addresses are not supported", auth_begin + 1);
		}
		// RFC 6874: IPv6address "%25" ZoneID
		const std::size_t zone = literal.find("%25");
		const std::string_view address = literal.substr(0, zone);
		if (!is_ipv6(address)) {
			return bad("invalid IPv6 address", auth_begin + 1);
		}
		u.host_.assign(address);
		if (zone != std::string_view::npos) {
			const std::string_view zone_id = literal.substr(zone + 3);
			if (zone_id.empty()) {
				return bad("empty IPv6 zone", auth_begin + 1 + zone);
			}
			auto z = decode(zone_id, auth_begin + 1 + zone + 3, "IPv6 zone", is_unreserved, mr);
			if (!z) {
				return std::unexpected(std::move(z.error()));
			}
			u.host_ += '%';
			u.host_ += *z;
		}
		u.host_is_ipv6_ = true;
		const std::string_view rest = authority.substr(close + 1);
		if (!rest.empty()) {
			if (rest[0] != ':') {
				return bad("unexpected character after ']'", auth_begin + close + 1);
			}
			has_port = true;
			port_text = rest.substr(1);
			port_offset = auth_begin + close + 2;
		}
	} else {
		const std::size_t colon = authority.find(':');
		const std::string_view host = authority.substr(0, colon);
		if (const auto at = host.find('@'); at != std::string_view::npos) {
			return bad("userinfo ('@') not allowed", auth_begin + at);
		}
		auto h = decode(host, auth_begin, "host", is_reg_name_char, mr);
		if (!h) {
			return std::unexpected(std::move(h.error()));
		}
		u.host_ = std::move(*h);
		if (colon != std::string_view::npos) {
			has_port = true;
			port_text = authority.substr(colon + 1);
			port_offset = auth_begin + colon + 1;
		}
	}

	if (has_port) {
		if (u.scheme_ == url_scheme::ldapi) {
			return bad("port not allowed in an ldapi URL", port_offset - 1);
		}
		// RFC 3986: port = *DIGIT; an empty port means the default.
		if (!port_text.empty()) {
			std::uint32_t value = 0;
			for (std::size_t i = 0; i < port_text.size(); ++i) {
				if (!is_digit(port_text[i])) {
					return bad("invalid port", port_offset + i);
				}
				value = (value * 10) + static_cast<std::uint32_t>(port_text[i] - '0');
				if (value > 65535) {
					return bad("port above 65535", port_offset);
				}
			}
			if (value == 0) {
				return bad("port 0", port_offset);
			}
			u.port_ = static_cast<std::uint16_t>(value);
		}
	}

	if (auth_end == std::string_view::npos) {
		return u;
	}

	// ---- "/" dn ["?" attributes ["?" scope ["?" filter ["?" extensions]]]]
	const std::size_t path_begin = auth_end + 1;
	const std::string_view path = text.substr(path_begin);
	if (const auto hash = path.find('#'); hash != std::string_view::npos) {
		return bad("fragment ('#') not allowed", path_begin + hash);
	}

	std::string_view parts[5];
	std::size_t offsets[5] = {};
	std::size_t count = 0;
	{
		std::size_t start = 0;
		while (true) {
			if (count == 5) {
				return bad("more than four '?'", path_begin + start - 1);
			}
			const std::size_t q = path.find('?', start);
			parts[count] = path.substr(start, q == std::string_view::npos ? q : q - start);
			offsets[count] = path_begin + start;
			++count;
			if (q == std::string_view::npos) {
				break;
			}
			start = q + 1;
		}
	}

	// dn
	{
		auto text_dn = decode(parts[0], offsets[0], "DN", is_lenient_part_char, mr);
		if (!text_dn) {
			return std::unexpected(std::move(text_dn.error()));
		}
		auto d = dn::parse(*text_dn, mr);
		if (!d) {
			return bad(detail::format("invalid DN ({})", d.error().context), offsets[0]);
		}
		u.dn_ = std::move(*d);
	}

	// attributes
	if (count > 1 && !parts[1].empty()) {
		auto r = split(parts[1], offsets[1], ',', [&](std::string_view piece, std::size_t off) -> result<void> {
			if (piece.empty()) {
				return bad("empty attribute", off);
			}
			auto a = decode(piece, off, "attribute", is_lenient_part_char, mr);
			if (!a) {
				return std::unexpected(std::move(a.error()));
			}
			if (a->empty()) {
				return bad("empty attribute", off);
			}
			u.attributes_.push_back(std::move(*a));
			return {};
		});
		if (!r) {
			return std::unexpected(std::move(r.error()));
		}
	}

	// scope
	if (count > 2 && !parts[2].empty()) {
		auto s = decode(parts[2], offsets[2], "scope", is_lenient_part_char, mr);
		if (!s) {
			return std::unexpected(std::move(s.error()));
		}
		if (iequals(*s, "base")) {
			u.scope_ = search_scope::base_object;
		} else if (iequals(*s, "one")) {
			u.scope_ = search_scope::single_level;
		} else if (iequals(*s, "sub")) {
			u.scope_ = search_scope::whole_subtree;
		} else {
			return bad("scope is not base, one or sub", offsets[2]);
		}
	}

	// filter
	if (count > 3 && !parts[3].empty()) {
		auto f = decode(parts[3], offsets[3], "filter", is_lenient_part_char, mr);
		if (!f) {
			return std::unexpected(std::move(f.error()));
		}
		auto parsed = filter::raw(*f, mr);
		if (!parsed) {
			return bad(detail::format("invalid filter ({})", parsed.error().context), offsets[3]);
		}
		u.filter_ = std::move(*parsed);
	}

	// extensions
	if (count > 4 && !parts[4].empty()) {
		auto r = split(parts[4], offsets[4], ',', [&](std::string_view piece, std::size_t off) -> result<void> {
			url_extension e{ allocator_type(mr) };
			if (!piece.empty() && piece[0] == '!') {
				e.critical = true;
				piece.remove_prefix(1);
				++off;
			}
			const std::size_t eq = piece.find('=');
			auto type = decode(piece.substr(0, eq), off, "extension type", is_lenient_part_char, mr);
			if (!type) {
				return std::unexpected(std::move(type.error()));
			}
			if (!detail::is_oid(*type)) {
				return bad("extension type is not a descriptor or numeric OID", off);
			}
			e.type = std::move(*type);
			if (eq != std::string_view::npos) {
				auto value = decode(piece.substr(eq + 1), off + eq + 1, "extension value", is_lenient_part_char, mr);
				if (!value) {
					return std::unexpected(std::move(value.error()));
				}
				e.value.emplace(std::move(*value));
			}
			u.extensions_.push_back(std::move(e));
			return {};
		});
		if (!r) {
			return std::unexpected(std::move(r.error()));
		}
	}

	return u;
}

auto url::authority(std::pmr::memory_resource *mr) const -> std::pmr::string
{
	std::pmr::string out(mr);
	append_host(out, scheme_, host_, host_is_ipv6_);
	if (scheme_ != url_scheme::ldapi) {
		out += ':';
		out += std::to_string(port_or_default());
	}
	return out;
}

auto url::to_string(std::pmr::memory_resource *mr) const -> std::pmr::string
{
	std::pmr::string out(ldap::to_string(scheme_), mr);
	out += "://";
	append_host(out, scheme_, host_, host_is_ipv6_);
	if (port_) {
		out += ':';
		out += std::to_string(*port_);
	}

	// Index of the last part that must be written: 0 dn .. 4 extensions.
	int last = -1;
	if (dn_) {
		last = 0;
	}
	if (!attributes_.empty()) {
		last = 1;
	}
	if (scope_) {
		last = 2;
	}
	if (filter_) {
		last = 3;
	}
	if (!extensions_.empty()) {
		last = 4;
	}
	if (last < 0) {
		return out;
	}

	const auto part = [](char c) { return is_part_char(c); };
	const auto list_item = [](char c) { return is_part_char(c) && c != ','; };

	out += '/';
	if (dn_) {
		encode(out, dn_->to_string(mr), part);
	}
	if (last >= 1) {
		out += '?';
		for (std::size_t i = 0; i < attributes_.size(); ++i) {
			if (i != 0) {
				out += ',';
			}
			encode(out, attributes_[i], list_item);
		}
	}
	if (last >= 2) {
		out += '?';
		if (scope_) {
			out += scope_name(*scope_);
		}
	}
	if (last >= 3) {
		out += '?';
		if (filter_) {
			encode(out, filter_->to_string(mr), part);
		}
	}
	if (last >= 4) {
		out += '?';
		for (std::size_t i = 0; i < extensions_.size(); ++i) {
			const auto &e = extensions_[i];
			if (i != 0) {
				out += ',';
			}
			if (e.critical) {
				out += '!';
			}
			encode(out, e.type, list_item);
			if (e.value) {
				out += '=';
				encode(out, *e.value, list_item);
			}
		}
	}
	return out;
}

auto url::parse_list(const std::pmr::vector<std::pmr::string> &uris, std::pmr::memory_resource *mr)
  -> std::pmr::vector<url>
{
	std::pmr::vector<url> out(mr);
	for (const auto &u : uris) {
		if (auto parsed = parse(u, mr)) {
			out.push_back(std::move(*parsed));
		}
	}
	return out;
}

}// namespace jhetz::ldap
