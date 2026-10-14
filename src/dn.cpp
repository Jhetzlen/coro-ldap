#include "jhetz/ldap/dn.hpp"

#include "format_util.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <memory_resource>
#include <ranges>
#include <stdexcept>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

namespace jhetz::ldap {
namespace {

	// Unescapes a value the scanner has already validated.
	std::pmr::string unescape(const detail::dn_token &tok, std::pmr::memory_resource *mr)
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

	constexpr char hex_digits[] = "0123456789abcdef";

	void append_hex(std::pmr::string &out, unsigned char c)
	{
		out += hex_digits[c >> 4];
		out += hex_digits[c & 0xFu];
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
					append_hex(out, u);
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
			if (u < 0x20u || u == 0x7Fu) {
				out += '\\';
				append_hex(out, u);
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
			for (char c : a.value) {
				append_hex(out, static_cast<unsigned char>(c));
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

	// Case-insensitive type, then form, then value: a total order consistent
	// with ava::operator==, used to compare RDNs as sets.
	bool ava_less(const ava &a, const ava &b)
	{
		const auto c = a.type <=> b.type;
		if (c != 0) {
			return c < 0;
		}
		return std::tie(a.hex_form, a.value) < std::tie(b.hex_form, b.value);
	}

}// namespace

std::pmr::string escape_dn_value(std::string_view value, std::pmr::memory_resource *mr)
{
	std::pmr::string out(mr);
	out.reserve(value.size());
	append_escaped(out, value);
	return out;
}

bool operator==(const rdn &a, const rdn &b)
{
	if (a.avas.size() != b.avas.size()) {
		return false;
	}
	if (a.avas.size() == 1) {
		return a.avas[0] == b.avas[0];
	}
	// Sorted pointer copies in a small stack buffer (multi-valued RDNs are
	// short); unusually long ones fall back to the heap.
	std::array<std::byte, 2 * 16 * sizeof(const ava *) + 64> buffer;
	std::pmr::monotonic_buffer_resource scratch(buffer.data(), buffer.size());
	std::pmr::vector<const ava *> x(&scratch);
	std::pmr::vector<const ava *> y(&scratch);
	x.reserve(a.avas.size());
	y.reserve(b.avas.size());
	// Loops: append_range(avas | views::transform(...)) measured about 13%
	// slower on this hot path.
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
	auto parsed = parse(l.text, alloc.resource());
	// Unreachable: the literal was validated at compile time with the same scanner.
	if (!parsed) {
		throw std::invalid_argument("ldap::rdn: invalid relative distinguished name");
	}
	avas = std::move(parsed->avas);// same resource: no copy
}

result<rdn> rdn::parse(std::string_view text, std::pmr::memory_resource *mr)
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

std::pmr::string rdn::to_string(std::pmr::memory_resource *mr) const
{
	std::pmr::string out(mr);
	append_rdn(out, *this);
	return out;
}

dn::dn(literal l, const allocator_type &alloc) : rdns_(alloc)
{
	auto parsed = parse(l.text, alloc.resource());
	// Unreachable: the literal was validated at compile time with the same scanner.
	if (!parsed) {
		throw std::invalid_argument("ldap::dn: invalid distinguished name");
	}
	rdns_ = std::move(parsed->rdns_);// same resource: no copy
}

result<dn> dn::parse(std::string_view text, std::pmr::memory_resource *mr)
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

std::pmr::string dn::to_string(std::pmr::memory_resource *mr) const
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

dn dn::parent() const
{
	dn out(get_allocator());
	out.rdns_.assign_range(rdns_ | std::views::drop(1));
	return out;
}

dn dn::child(const rdn &r) const
{
	return child(rdn(r, get_allocator()));// copied straight onto this DN's resource
}

dn dn::child(rdn &&r) const
{
	// Programming errors: the result would not survive to_string()/parse().
	if (r.avas.empty()) {
		throw std::invalid_argument("ldap::dn::child: empty RDN");
	}
	for (const auto &a : r.avas) {
		if (!detail::is_oid(a.type.name())) {
			throw std::invalid_argument("ldap::dn::child: invalid attribute type");
		}
		if (a.hex_form && a.value.empty()) {
			throw std::invalid_argument("ldap::dn::child: empty #hex value");
		}
	}
	dn out(get_allocator());
	out.rdns_.reserve(rdns_.size() + 1);
	out.rdns_.push_back(std::move(r));
	out.rdns_.append_range(rdns_);
	return out;
}

dn dn::child(const dn &relative) const
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
