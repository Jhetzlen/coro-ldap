#pragma once

#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace jhetz::ldap::test {

// bytes({0x30, 0x0C, ...})
inline auto bytes(std::initializer_list<unsigned> values) -> std::vector<std::byte>
{
	std::vector<std::byte> out;
	out.reserve(values.size());
	for (unsigned v : values) {
		out.push_back(static_cast<std::byte>(v & 0xFFu));
	}
	return out;
}

// "30 0C 02 01" - compared as strings so Catch2 prints readable diffs.
inline auto hex(std::span<const std::byte> data) -> std::string
{
	static constexpr char digits[] = "0123456789ABCDEF";
	std::string out;
	for (std::size_t i = 0; i < data.size(); ++i) {
		if (i != 0) {
			out += ' ';
		}
		const auto b = std::to_integer<unsigned>(data[i]);
		out += digits[b >> 4];
		out += digits[b & 0xFu];
	}
	return out;
}

// from_hex("3005 0201") - whitespace ignored; throws on malformed input.
inline auto from_hex(std::string_view text) -> std::vector<std::byte>
{
	auto nibble = [](char c) -> unsigned {
		if (c >= '0' && c <= '9') {
			return static_cast<unsigned>(c - '0');
		}
		if (c >= 'a' && c <= 'f') {
			return static_cast<unsigned>(c - 'a' + 10);
		}
		if (c >= 'A' && c <= 'F') {
			return static_cast<unsigned>(c - 'A' + 10);
		}
		throw std::invalid_argument("from_hex: not a hex digit");
	};
	std::vector<std::byte> out;
	int pending = -1;
	for (char c : text) {
		if (c == ' ' || c == '\n' || c == '\t') {
			continue;
		}
		if (pending < 0) {
			pending = static_cast<int>(nibble(c));
		} else {
			out.push_back(static_cast<std::byte>((static_cast<unsigned>(pending) << 4) | nibble(c)));
			pending = -1;
		}
	}
	if (pending >= 0) {
		throw std::invalid_argument("from_hex: odd number of digits");
	}
	return out;
}

// Bytes of a std::string (binary values in the message model).
inline auto bytes_of(std::string_view s) -> std::vector<std::byte>
{
	const auto b = std::as_bytes(std::span(s));
	return { b.begin(), b.end() };
}

}// namespace jhetz::ldap::test
