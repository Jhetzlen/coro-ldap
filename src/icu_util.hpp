// Internal: ICU helpers shared by the translation units that call ICU, in
// jhetz::ldap (the codec) and jhetz::ldap_net.
#pragma once

#include <unicode/umachine.h>
#include <unicode/utf8.h>
#include <unicode/utypes.h>

#include <cstddef>
#include <cstdint>
#include <string_view>

namespace jhetz::ldap::detail {

// ICU's U_FAILURE as a bool (it yields UBool, an integer type). Not
// constexpr: in C++ U_FAILURE is a non-constexpr inline function, which MSVC
// refuses in a constexpr function (GCC and Clang accept it, P2448).
inline auto icu_failed(UErrorCode status) noexcept -> bool { return U_FAILURE(status) != 0; }

// One step of UTF-8 decoding at s[i] with ICU's U8_NEXT: the code point, or a
// negative value if the octets there are ill-formed (overlong, surrogate,
// above U+10FFFF, truncated, stray trail octet), and the octets read: the
// whole sequence, or its maximal subpart when ill-formed (Unicode section
// 3.9, at least one octet), which one U+FFFD replaces. Precondition:
// i < s.size().
struct utf8_step
{
	UChar32 code_point;
	std::size_t length;
};
inline auto utf8_next(std::string_view s, std::size_t i) noexcept -> utf8_step
{
	// U8_NEXT reads octets as uint8_t; the offsets are std::size_t, so a
	// string longer than INT32_MAX is fine.
	const auto *octets = reinterpret_cast<const std::uint8_t *>(s.data());
	const std::size_t length = s.size();
	std::size_t next = i;
	UChar32 c = 0;
	// NOLINTNEXTLINE(bugprone-inc-dec-in-conditions): ICU's macro, the increments in its conditions are sequenced by &&
	U8_NEXT(octets, next, length, c);
	return { .code_point = c, .length = next - i };
}

}// namespace jhetz::ldap::detail
