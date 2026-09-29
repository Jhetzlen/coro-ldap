#pragma once

#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <span>
#include <string>
#include <vector>

namespace jhetz::ldap::test {

// bytes({0x30, 0x0C, ...})
inline std::vector<std::byte> bytes(std::initializer_list<unsigned> values)
{
	std::vector<std::byte> out;
	out.reserve(values.size());
	for (unsigned v : values) out.push_back(static_cast<std::byte>(v & 0xFFu));
	return out;
}

// "30 0C 02 01" - compared as strings so Catch2 prints readable diffs.
inline std::string hex(std::span<const std::byte> data)
{
	static constexpr char digits[] = "0123456789ABCDEF";
	std::string out;
	for (std::size_t i = 0; i < data.size(); ++i) {
		if (i != 0) out += ' ';
		const auto b = std::to_integer<unsigned>(data[i]);
		out += digits[b >> 4];
		out += digits[b & 0xFu];
	}
	return out;
}

}// namespace jhetz::ldap::test
