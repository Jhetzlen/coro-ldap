// Internal: ICU helpers shared by the translation units that call ICU, in
// jhetz::ldap_core (the codec) and jhetz::ldap.
#pragma once

#include <unicode/umachine.h>
#include <unicode/usprep.h>
#include <unicode/ustring.h>
#include <unicode/utf8.h>
#include <unicode/utypes.h>

#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace jhetz::ldap::detail {

// U_FAILURE as a bool; not constexpr (MSVC).
inline auto icu_failed(UErrorCode status) noexcept -> bool { return U_FAILURE(status) != 0; }

// The status u_strFromUTF8 gives for ill-formed UTF-8 (overlong forms,
// surrogates, code points above U+10FFFF, truncated sequences).
inline auto is_invalid_utf8(UErrorCode status) noexcept -> bool
{
	return status == U_INVALID_CHAR_FOUND || status == U_ILLEGAL_CHAR_FOUND;
}

// The conversions below write into an empty `out`, resized once.
// Precondition: the input and output sizes fit in int32_t.

// UTF-8 to UTF-16.
inline auto to_utf16(std::string_view in, std::vector<UChar> &out) -> UErrorCode
{
	const auto length = static_cast<int32_t>(in.size());
	UErrorCode status = U_ZERO_ERROR;
	int32_t n = 0;
	// NOLINTNEXTLINE(bugprone-suspicious-stringview-data-usage): sized by length, no terminator read
	u_strFromUTF8(nullptr, 0, &n, in.data(), length, &status);
	if (status != U_BUFFER_OVERFLOW_ERROR && icu_failed(status)) {
		return status;
	}
	out.resize(static_cast<std::size_t>(n));
	status = U_ZERO_ERROR;
	if (n > 0) {
		// NOLINTNEXTLINE(bugprone-suspicious-stringview-data-usage): sized by length, no terminator read
		u_strFromUTF8(out.data(), n, &n, in.data(), length, &status);
	}
	return status;
}

// UTF-16 to UTF-8.
inline auto to_utf8(std::span<const UChar> in, std::string &out) -> UErrorCode
{
	const auto length = static_cast<int32_t>(in.size());
	UErrorCode status = U_ZERO_ERROR;
	int32_t n = 0;
	u_strToUTF8(nullptr, 0, &n, in.data(), length, &status);
	if (status != U_BUFFER_OVERFLOW_ERROR && icu_failed(status)) {
		return status;
	}
	out.resize(static_cast<std::size_t>(n));
	status = U_ZERO_ERROR;
	if (n > 0) {
		u_strToUTF8(out.data(), n, &n, in.data(), length, &status);
	}
	return status;
}

// RFC 3454 preparation of `in` with `profile` and usprep_prepare's `options`.
inline auto
  stringprep(const UStringPrepProfile *profile, int32_t options, std::span<const UChar> in, std::vector<UChar> &out)
	-> UErrorCode
{
	const auto length = static_cast<int32_t>(in.size());
	const auto prepare = [&](UChar *dest, int32_t capacity, UErrorCode &status) {
		UParseError where{};
		status = U_ZERO_ERROR;
		return usprep_prepare(profile, in.data(), length, dest, capacity, options, &where, &status);
	};
	UErrorCode status = U_ZERO_ERROR;
	const int32_t n = prepare(nullptr, 0, status);
	if (status != U_BUFFER_OVERFLOW_ERROR && icu_failed(status)) {
		return status;
	}
	out.resize(static_cast<std::size_t>(n));
	status = U_ZERO_ERROR;
	if (n > 0) {
		prepare(out.data(), n, status);
	}
	return status;
}

struct usprep_closer
{
	void operator()(UStringPrepProfile *p) const noexcept { usprep_close(p); }
};
using usprep_ptr = std::unique_ptr<UStringPrepProfile, usprep_closer>;

// One U8_NEXT step at s[i]: the code point (negative if ill-formed) and the
// octets read. Precondition: i < s.size().
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
