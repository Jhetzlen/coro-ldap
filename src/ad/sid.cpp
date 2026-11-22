#include "jhetz/ldap/ad/sid.hpp"

#include "../format_util.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>

namespace jhetz::ldap::ad {

namespace {

	constexpr std::uint8_t revision = 1;
	constexpr std::size_t header_size = 8;
	constexpr std::size_t authority_size = 6;
	constexpr std::size_t sub_authority_size = 4;
	constexpr std::size_t hex_authority_digits = 12;
	constexpr int decimal_base = 10;
	constexpr int hex_base = 16;
	constexpr unsigned bits_per_octet = 8;
	constexpr std::uint64_t max_decimal_authority = std::numeric_limits<std::uint32_t>::max();

	auto octet(std::string_view raw, std::size_t i) -> std::uint64_t { return static_cast<unsigned char>(raw[i]); }

	// An unsigned decimal or hex number taking all of `text`.
	template<class T> auto parse_number(std::string_view text, int base) -> std::optional<T>
	{
		if (text.empty()) {
			return std::nullopt;
		}
		T v{};
		const char *end = text.data() + text.size();
		// NOLINTNEXTLINE(bugprone-suspicious-stringview-data-usage): bounded by end, no terminator read
		const auto [p, ec] = std::from_chars(text.data(), end, v, base);
		if (ec != std::errc{} || p != end) {
			return std::nullopt;
		}
		return v;
	}

	auto parse_authority(std::string_view text) -> std::optional<std::uint64_t>
	{
		if (text.size() > 2 && text[0] == '0' && (text[1] == 'x' || text[1] == 'X')) {
			const std::string_view digits = text.substr(2);
			if (digits.size() != hex_authority_digits || !std::ranges::all_of(digits, [](char c) {
					return std::isxdigit(static_cast<unsigned char>(c)) != 0;
				})) {
				return std::nullopt;
			}
			return parse_number<std::uint64_t>(digits, hex_base);
		}
		if (!std::ranges::all_of(text, [](char c) { return c >= '0' && c <= '9'; })) {
			return std::nullopt;
		}
		auto v = parse_number<std::uint64_t>(text, decimal_base);
		if (!v || *v > max_decimal_authority) {
			return std::nullopt;
		}
		return v;
	}

}// namespace

auto sid::make(std::uint64_t identifier_authority, std::span<const std::uint32_t> sub_authorities) -> result<sid>
{
	if (identifier_authority > max_identifier_authority) {
		return fail(std::make_error_code(std::errc::invalid_argument), "SID identifier authority above 2^48 - 1");
	}
	if (sub_authorities.size() > max_sub_authorities) {
		return fail(std::make_error_code(std::errc::invalid_argument), "SID with more than 15 sub-authorities");
	}
	sid s;
	s.authority_ = identifier_authority;
	std::ranges::copy(sub_authorities, s.sub_.begin());
	s.count_ = static_cast<std::uint8_t>(sub_authorities.size());
	return s;
}

auto sid::parse(std::string_view text) -> result<sid>
{
	const auto bad = [text] { return std::unexpected(detail::conversion_error("not a SID", text)); };
	if (text.size() < 4 || (text[0] != 'S' && text[0] != 's') || text.substr(1, 3) != "-1-") {
		return bad();
	}
	std::string_view rest = text.substr(4);
	const auto next = [&rest] {
		const auto dash = rest.find('-');
		const std::string_view part = rest.substr(0, dash);
		rest = dash == std::string_view::npos ? std::string_view() : rest.substr(dash + 1);
		return std::pair{ part, dash != std::string_view::npos };
	};
	auto [authority_text, more] = next();
	const auto authority = parse_authority(authority_text);
	if (!authority) {
		return bad();
	}
	sid s;
	s.authority_ = *authority;
	while (more) {
		auto [part, has_more] = next();
		more = has_more;
		if (s.count_ == max_sub_authorities
			|| !std::ranges::all_of(part, [](char c) { return c >= '0' && c <= '9'; })) {
			return bad();
		}
		const auto v = parse_number<std::uint32_t>(part, decimal_base);
		if (!v) {
			return bad();
		}
		s.sub_.at(s.count_++) = *v;
	}
	return s;
}

auto sid::from_binary(std::string_view raw) -> result<sid>
{
	if (raw.size() < header_size || octet(raw, 0) != revision || octet(raw, 1) > max_sub_authorities
		|| raw.size() != header_size + (sub_authority_size * octet(raw, 1))) {
		return std::unexpected(detail::conversion_error("not a binary SID", raw));
	}
	sid s;
	for (std::size_t i = 0; i < authority_size; ++i) {
		s.authority_ = (s.authority_ << bits_per_octet) | octet(raw, 2 + i);
	}
	s.count_ = static_cast<std::uint8_t>(octet(raw, 1));
	for (std::size_t n = 0; n < s.count_; ++n) {
		const std::size_t at = header_size + (n * sub_authority_size);
		std::uint32_t v = 0;
		for (std::size_t i = sub_authority_size; i-- > 0;) {
			v = (v << bits_per_octet) | static_cast<std::uint32_t>(octet(raw, at + i));
		}
		s.sub_.at(n) = v;
	}
	return s;
}

auto sid::to_string() const -> std::string
{
	std::string out = "S-1-";
	if (authority_ > max_decimal_authority) {
		std::array<char, hex_authority_digits> digits{};
		std::uint64_t v = authority_;
		for (std::size_t i = hex_authority_digits; i-- > 0;) {
			digits.at(i) = ldap::detail::upper_hex_digit(static_cast<unsigned>(v % hex_base));
			v /= hex_base;
		}
		out += "0x";
		out.append(digits.data(), digits.size());
	} else {
		out += std::to_string(authority_);
	}
	for (const std::uint32_t v : sub_authorities()) {
		out += '-';
		out += std::to_string(v);
	}
	return out;
}

auto sid::to_binary() const -> std::string
{
	std::string out;
	out.reserve(header_size + (sub_authority_size * count_));
	out += static_cast<char>(revision);
	out += static_cast<char>(count_);
	for (std::size_t i = authority_size; i-- > 0;) {
		out += static_cast<char>(static_cast<unsigned char>(authority_ >> (i * bits_per_octet)));
	}
	for (const std::uint32_t v : sub_authorities()) {
		for (std::size_t i = 0; i < sub_authority_size; ++i) {
			out += static_cast<char>(static_cast<unsigned char>(v >> (i * bits_per_octet)));
		}
	}
	return out;
}

}// namespace jhetz::ldap::ad
