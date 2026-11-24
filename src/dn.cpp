#include "jhetz/ldap/dn.hpp"

#include "format_util.hpp"

#include <algorithm>
#include <array>
#include <compare>
#include <cstddef>
#include <memory_resource>
#include <ranges>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>
#include <vector>

namespace jhetz::ldap {
namespace {

	// Unescapes a value the scanner has already validated.
	auto unescape(const detail::dn_token &tok, std::pmr::memory_resource *mr) -> std::pmr::string
	{
		const std::string_view raw = tok.raw_value;
		std::pmr::string out(mr);
		out.reserve(raw.size());
		if (tok.hex) {
			for (std::size_t i = 0; i + 1 < raw.size(); i += 2) {
				out += static_cast<char>((detail::hex_value(raw[i]) << 4) | detail::hex_value(raw[i + 1]));
			}
			return out;
		}
		for (std::size_t i = 0; i < raw.size(); ++i) {
			if (raw[i] != '\\') {
				out += raw[i];
			} else if (detail::is_dn_escapable(raw[i + 1])) {
				out += raw[i + 1];
				++i;
			} else {
				out += static_cast<char>((detail::hex_value(raw[i + 1]) << 4) | detail::hex_value(raw[i + 2]));
				i += 2;
			}
		}
		return out;
	}

	// RFC 4514 section 2.4 escaping of a string value, shared by to_string()
	// and escape_dn_value().
	void append_escaped(std::pmr::string &out, std::string_view v)
	{
		for (std::size_t i = 0; i < v.size(); ++i) {
			const char c = v[i];
			const auto u = static_cast<unsigned char>(c);
			if (u >= 0x80u) {
				// RFC 4514 section 2: the output is UTF-8; other octets are escaped.
				const std::size_t len = detail::utf8_sequence_length(v, i);
				if (len == 0) {
					out += '\\';
					detail::append_hex_octet(out, u);
				} else {
					out += v.substr(i, len);
					i += len - 1;
				}
				continue;
			}
			switch (c) {
			case ',':
			case '+':
			case '"':
			case '\\':
			case '<':
			case '>':
			case ';':
				out += '\\';
				out += c;
				continue;
			default:
				break;
			}
			if (detail::is_ascii_control(u)) {
				out += '\\';
				detail::append_hex_octet(out, u);
			} else if ((c == ' ' && (i == 0 || i + 1 == v.size())) || (c == '#' && i == 0)) {
				out += '\\';
				out += c;
			} else {
				out += c;
			}
		}
	}

	void append_value(std::pmr::string &out, const ava &a)
	{
		if (a.hex_form) {
			out += '#';
			for (const char c : a.value) {
				detail::append_hex_octet(out, static_cast<unsigned char>(c));
			}
			return;
		}
		append_escaped(out, a.value);
	}

	void append_rdn(std::pmr::string &out, const rdn &r)
	{
		for (std::size_t j = 0; j < r.avas.size(); ++j) {
			if (j != 0) {
				out += '+';
			}
			out += r.avas[j].type.name();
			out += '=';
			append_value(out, r.avas[j]);
		}
	}

	// The AVA of `tok`, allocated on `mr`.
	void append_ava(rdn &r, const detail::dn_token &tok, std::pmr::memory_resource *mr)
	{
		auto &a = r.avas.emplace_back();// uses-allocator: on r's resource
		a.type = attribute::unchecked(tok.type, mr);
		a.value = unescape(tok, mr);
		a.hex_form = tok.hex;
	}

	// A total order consistent with ava::operator==.
	auto ava_less(const ava &a, const ava &b) -> bool
	{
		const auto c = a.type <=> b.type;
		if (std::is_neq(c)) {
			return std::is_lt(c);
		}
		return std::tie(a.hex_form, a.value) < std::tie(b.hex_form, b.value);
	}

}// namespace

auto escape_dn_value(std::string_view value, std::pmr::memory_resource *mr) -> std::pmr::string
{
	std::pmr::string out(mr);
	out.reserve(value.size());
	append_escaped(out, value);
	return out;
}

auto operator==(const rdn &a, const rdn &b) -> bool
{
	if (a.avas.size() != b.avas.size()) {
		return false;
	}
	if (a.avas.size() == 1) {
		return a.avas[0] == b.avas[0];
	}
	// Sorted pointer copies in a small stack buffer, heap for long ones.
	// NOLINTNEXTLINE(cppcoreguidelines-pro-type-member-init): raw arena storage
	std::array<std::byte, (2uz * 16 * sizeof(const ava *)) + 64> buffer;
	std::pmr::monotonic_buffer_resource scratch(buffer.data(), buffer.size());
	std::pmr::vector<const ava *> x(&scratch);
	std::pmr::vector<const ava *> y(&scratch);
	x.reserve(a.avas.size());
	y.reserve(b.avas.size());
	for (const auto &v : a.avas) {
		x.push_back(&v);
	}
	for (const auto &v : b.avas) {
		y.push_back(&v);
	}
	const auto less = [](const ava *p, const ava *q) { return ava_less(*p, *q); };
	std::ranges::sort(x, less);
	std::ranges::sort(y, less);
	return std::ranges::equal(x, y, [](const ava *p, const ava *q) { return *p == *q; });
}

rdn::rdn(literal l, const allocator_type &alloc) : avas(alloc)
{
	avas = std::move(parse(l.text, alloc.resource()).value().avas);// same resource: no copy
}

auto rdn::parse(std::string_view text, std::pmr::memory_resource *mr) -> result<rdn>
{
	rdn out{ allocator_type(mr) };
	std::size_t rdns = 0;
	const std::size_t err = detail::scan_dn(text, [&](const detail::dn_token &tok) {
		if (tok.new_rdn) {
			++rdns;
		}
		if (rdns == 1) {
			append_ava(out, tok, mr);// later RDNs are only counted
		}
	});
	if (err != std::string_view::npos) {
		return fail(client_errc::invalid_dn, detail::format("rdn: syntax error at position {}", err));
	}
	if (rdns == 0) {
		return fail(client_errc::invalid_dn, "rdn: empty");
	}
	if (rdns > 1) {
		return fail(client_errc::invalid_dn, detail::format("rdn: {} RDNs where one is expected", rdns));
	}
	return out;
}

auto rdn::to_string(std::pmr::memory_resource *mr) const -> std::pmr::string
{
	std::pmr::string out(mr);
	append_rdn(out, *this);
	return out;
}

dn::dn(literal l, const allocator_type &alloc) : rdns_(alloc)
{
	rdns_ = std::move(parse(l.text, alloc.resource()).value().rdns_);// same resource: no copy
}

auto dn::parse(std::string_view text, std::pmr::memory_resource *mr) -> result<dn>
{
	dn out{ allocator_type(mr) };
	const std::size_t err = detail::scan_dn(text, [&](const detail::dn_token &tok) {
		if (tok.new_rdn || out.rdns_.empty()) {
			out.rdns_.emplace_back();// uses-allocator: on mr
		}
		append_ava(out.rdns_.back(), tok, mr);
	});
	if (err != std::string_view::npos) {
		return fail(client_errc::invalid_dn, detail::format("dn: syntax error at position {}", err));
	}
	return out;
}

auto dn::to_string(std::pmr::memory_resource *mr) const -> std::pmr::string
{
	std::pmr::string out(mr);
	for (std::size_t i = 0; i < rdns_.size(); ++i) {
		if (i != 0) {
			out += ',';
		}
		append_rdn(out, rdns_[i]);
	}
	return out;
}

auto dn::parent() const -> dn
{
	dn out(get_allocator());
	out.rdns_.assign_range(rdns_ | std::views::drop(1));
	return out;
}

auto dn::child(const rdn &r) const -> result<dn>
{
	return child(rdn(r, get_allocator()));// copied straight onto this DN's resource
}

auto dn::child(rdn &&r) const -> result<dn>
{
	// The result would not survive to_string()/parse().
	if (r.avas.empty()) {
		return fail(client_errc::invalid_dn, "dn::child: empty RDN");
	}
	for (const auto &a : r.avas) {
		if (!detail::is_oid(a.type.name())) {
			return fail(client_errc::invalid_dn, "dn::child: invalid attribute type");
		}
		if (a.hex_form && a.value.empty()) {
			return fail(client_errc::invalid_dn, "dn::child: empty #hex value");
		}
	}
	dn out(get_allocator());
	out.rdns_.reserve(rdns_.size() + 1);
	out.rdns_.push_back(std::move(r));
	out.rdns_.append_range(rdns_);
	return out;
}

auto dn::child(const dn &relative) const -> dn
{
	// No checks: every RDN of a dn is valid (parse, the literal and
	// child(rdn) guarantee it).
	dn out(get_allocator());
	out.rdns_.reserve(relative.rdns_.size() + rdns_.size());
	out.rdns_.append_range(relative.rdns_);
	out.rdns_.append_range(rdns_);
	return out;
}

}// namespace jhetz::ldap
