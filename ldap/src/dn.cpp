#include "jhetz/ldap/dn.hpp"

#include <algorithm>
#include <stdexcept>
#include <tuple>

namespace jhetz::ldap {
namespace {

	// Unescapes a value the scanner has already validated.
	std::string unescape(const detail::dn_token &tok)
	{
		const std::string_view raw = tok.raw_value;
		std::string out;
		out.reserve(raw.size());
		if (tok.hex) {
			for (std::size_t i = 0; i + 1 < raw.size(); i += 2)
				out += static_cast<char>((detail::hex_value(raw[i]) << 4) | detail::hex_value(raw[i + 1]));
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

	void append_hex(std::string &out, unsigned char c)
	{
		out += hex_digits[c >> 4];
		out += hex_digits[c & 0xFu];
	}

	void append_value(std::string &out, const ava &a)
	{
		if (a.hex_form) {
			out += '#';
			for (char c : a.value) append_hex(out, static_cast<unsigned char>(c));
			return;
		}
		const std::string_view v = a.value;
		for (std::size_t i = 0; i < v.size(); ++i) {
			const char c = v[i];
			const auto u = static_cast<unsigned char>(c);
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

	// Case-insensitive type, then form, then value: a total order consistent
	// with ava::operator==, used to compare RDNs as sets.
	bool ava_less(const ava &a, const ava &b)
	{
		const auto c = a.type <=> b.type;
		if (c != 0) return c < 0;
		return std::tie(a.hex_form, a.value) < std::tie(b.hex_form, b.value);
	}

}// namespace

bool operator==(const rdn &a, const rdn &b)
{
	if (a.avas.size() != b.avas.size()) return false;
	if (a.avas.size() == 1) return a.avas[0] == b.avas[0];
	auto x = a.avas;
	auto y = b.avas;
	std::sort(x.begin(), x.end(), ava_less);
	std::sort(y.begin(), y.end(), ava_less);
	return x == y;
}

dn::dn(literal l)
{
	auto parsed = parse(l.text);
	// Unreachable: the literal was validated at compile time with the same scanner.
	if (!parsed) throw std::invalid_argument("ldap::dn: invalid distinguished name");
	*this = std::move(*parsed);
}

result<dn> dn::parse(std::string_view text)
{
	dn out;
	const std::size_t err = detail::scan_dn(text, [&](const detail::dn_token &tok) {
		ava a{ attribute::unchecked(std::string(tok.type)), unescape(tok), tok.hex };
		if (tok.new_rdn || out.rdns_.empty())
			out.rdns_.push_back(rdn{ { std::move(a) } });
		else
			out.rdns_.back().avas.push_back(std::move(a));
	});
	if (err != std::string_view::npos)
		return fail(client_errc::invalid_dn, "dn: syntax error at position " + std::to_string(err));
	return out;
}

std::string dn::to_string() const
{
	std::string out;
	for (std::size_t i = 0; i < rdns_.size(); ++i) {
		if (i != 0) out += ',';
		const auto &avas = rdns_[i].avas;
		for (std::size_t j = 0; j < avas.size(); ++j) {
			if (j != 0) out += '+';
			out += avas[j].type.name();
			out += '=';
			append_value(out, avas[j]);
		}
	}
	return out;
}

dn dn::parent() const
{
	dn out;
	if (rdns_.size() > 1) out.rdns_.assign(rdns_.begin() + 1, rdns_.end());
	return out;
}

dn dn::child(rdn r) const
{
	// Programming errors: the result would not survive to_string()/parse().
	if (r.avas.empty()) throw std::invalid_argument("ldap::dn::child: empty RDN");
	for (const auto &a : r.avas) {
		if (!detail::is_oid(a.type.name())) throw std::invalid_argument("ldap::dn::child: invalid attribute type");
		if (a.hex_form && a.value.empty()) throw std::invalid_argument("ldap::dn::child: empty #hex value");
	}
	dn out;
	out.rdns_.reserve(rdns_.size() + 1);
	out.rdns_.push_back(std::move(r));
	out.rdns_.insert(out.rdns_.end(), rdns_.begin(), rdns_.end());
	return out;
}

}// namespace jhetz::ldap
