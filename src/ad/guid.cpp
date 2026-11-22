#include "jhetz/ldap/ad/guid.hpp"

#include "../format_util.hpp"

#include "jhetz/ldap/attribute.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace jhetz::ldap::ad {

namespace {

	constexpr std::size_t binary_size = 16;
	constexpr std::size_t text_size = 36;
	constexpr std::size_t data2_offset = 4;
	constexpr std::size_t data3_offset = 6;
	constexpr std::size_t data4_offset = 8;
	constexpr unsigned bits_per_octet = 8;
	constexpr unsigned bits_per_digit = 4;
	// Where each group of the string form starts; a hyphen precedes each but
	// the first.
	constexpr std::size_t data2_text = 9;
	constexpr std::size_t data3_text = 14;
	constexpr std::size_t data4_text = 19;
	constexpr std::size_t node_text = 24;
	constexpr std::array<std::size_t, 4> hyphens{ data2_text - 1, data3_text - 1, data4_text - 1, node_text - 1 };

	// The first `Digits` hex digits of `text`, as a number.
	template<std::size_t Digits> auto read_hex(std::string_view text) -> std::optional<std::uint64_t>
	{
		std::uint64_t v = 0;
		for (std::size_t i = 0; i < Digits; ++i) {
			if (!ldap::detail::is_hex(text[i])) {
				return std::nullopt;
			}
			v = (v << bits_per_digit) | ldap::detail::hex_value(text[i]);
		}
		return v;
	}

	template<std::size_t Digits> void append_hex(std::string &out, std::uint64_t v)
	{
		for (std::size_t i = Digits; i-- > 0;) {
			out += ldap::detail::hex_digit(static_cast<unsigned>(v >> (i * bits_per_digit)));
		}
	}

	// The first `N` octets of `raw`, little-endian.
	template<std::size_t N> auto little_endian(std::string_view raw) -> std::uint32_t
	{
		std::uint32_t v = 0;
		for (std::size_t i = N; i-- > 0;) {
			v = (v << bits_per_octet) | static_cast<unsigned char>(raw[i]);
		}
		return v;
	}

	template<std::size_t N> void append_little_endian(std::string &out, std::uint32_t v)
	{
		for (std::size_t i = 0; i < N; ++i) {
			out += static_cast<char>(static_cast<unsigned char>(v >> (i * bits_per_octet)));
		}
	}

}// namespace

auto guid::parse(std::string_view text) -> result<guid>
{
	const auto bad = [text] { return std::unexpected(detail::conversion_error("not a GUID", text)); };
	std::string_view body = text;
	if (body.size() == text_size + 2 && body.front() == '{' && body.back() == '}') {
		body = body.substr(1, text_size);
	}
	if (body.size() != text_size) {
		return bad();
	}
	for (const std::size_t at : hyphens) {
		if (body[at] != '-') {
			return bad();
		}
	}
	const auto d1 = read_hex<8>(body);
	const auto d2 = read_hex<4>(body.substr(data2_text));
	const auto d3 = read_hex<4>(body.substr(data3_text));
	if (!d1 || !d2 || !d3) {
		return bad();
	}
	guid g{ .data1 = static_cast<std::uint32_t>(*d1),
		.data2 = static_cast<std::uint16_t>(*d2),
		.data3 = static_cast<std::uint16_t>(*d3) };
	std::size_t at = data4_text;
	for (std::uint8_t &octet : g.data4) {
		if (at == node_text - 1) {
			++at;
		}
		const auto b = read_hex<2>(body.substr(at));
		if (!b) {
			return bad();
		}
		octet = static_cast<std::uint8_t>(*b);
		at += 2;
	}
	return g;
}

auto guid::from_binary(std::string_view raw) -> result<guid>
{
	if (raw.size() != binary_size) {
		return std::unexpected(detail::conversion_error("not a 16-octet GUID", raw));
	}
	guid g{ .data1 = little_endian<4>(raw),
		.data2 = static_cast<std::uint16_t>(little_endian<2>(raw.substr(data2_offset))),
		.data3 = static_cast<std::uint16_t>(little_endian<2>(raw.substr(data3_offset))) };
	for (std::size_t i = 0; i < g.data4.size(); ++i) {
		g.data4.at(i) = static_cast<unsigned char>(raw[data4_offset + i]);
	}
	return g;
}

auto guid::to_string() const -> std::string
{
	std::string out;
	out.reserve(text_size);
	append_hex<8>(out, data1);
	out += '-';
	append_hex<4>(out, data2);
	out += '-';
	append_hex<4>(out, data3);
	out += '-';
	for (std::size_t i = 0; i < data4.size(); ++i) {
		if (i == 2) {
			out += '-';
		}
		append_hex<2>(out, data4.at(i));
	}
	return out;
}

auto guid::to_binary() const -> std::string
{
	std::string out;
	out.reserve(binary_size);
	append_little_endian<4>(out, data1);
	append_little_endian<2>(out, data2);
	append_little_endian<2>(out, data3);
	for (const std::uint8_t b : data4) {
		out += static_cast<char>(b);
	}
	return out;
}

}// namespace jhetz::ldap::ad
