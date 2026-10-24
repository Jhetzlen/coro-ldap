// LDAP string preparation (RFC 4518) and the RFC 4517 matching rules
// (matching.hpp).
#include "jhetz/ldap/matching.hpp"

#include "jhetz/ldap/ber.hpp"
#include "jhetz/ldap/schema.hpp"

#include "icu_util.hpp"

#include <unicode/umachine.h>
#include <unicode/usprep.h>
#include <unicode/ustring.h>
#include <unicode/utypes.h>

#include <algorithm>
#include <array>
#include <compare>
#include <cstddef>
#include <cstdint>
#include <iterator>
#include <memory>
#include <memory_resource>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace jhetz::ldap {

namespace {

	// ------------------------------------------------------------ RFC 4518 Appendix A

	struct code_point_range
	{
		UChar32 first;
		UChar32 last;
	};

	// The combining marks (Mn, Mc, Me) of Unicode 3.2, RFC 4518 Appendix A
	// ("definitive for the purposes of implementation"), sorted.
	constexpr auto combining_marks = std::to_array<code_point_range>({ { .first = 0x0300, .last = 0x034F },
	  { .first = 0x0360, .last = 0x036F },
	  { .first = 0x0483, .last = 0x0486 },
	  { .first = 0x0488, .last = 0x0489 },
	  { .first = 0x0591, .last = 0x05A1 },
	  { .first = 0x05A3, .last = 0x05B9 },
	  { .first = 0x05BB, .last = 0x05BC },
	  { .first = 0x05BF, .last = 0x05BF },
	  { .first = 0x05C1, .last = 0x05C2 },
	  { .first = 0x05C4, .last = 0x05C4 },
	  { .first = 0x064B, .last = 0x0655 },
	  { .first = 0x0670, .last = 0x0670 },
	  { .first = 0x06D6, .last = 0x06DC },
	  { .first = 0x06DE, .last = 0x06E4 },
	  { .first = 0x06E7, .last = 0x06E8 },
	  { .first = 0x06EA, .last = 0x06ED },
	  { .first = 0x0711, .last = 0x0711 },
	  { .first = 0x0730, .last = 0x074A },
	  { .first = 0x07A6, .last = 0x07B0 },
	  { .first = 0x0901, .last = 0x0903 },
	  { .first = 0x093C, .last = 0x093C },
	  { .first = 0x093E, .last = 0x094F },
	  { .first = 0x0951, .last = 0x0954 },
	  { .first = 0x0962, .last = 0x0963 },
	  { .first = 0x0981, .last = 0x0983 },
	  { .first = 0x09BC, .last = 0x09BC },
	  { .first = 0x09BE, .last = 0x09C4 },
	  { .first = 0x09C7, .last = 0x09C8 },
	  { .first = 0x09CB, .last = 0x09CD },
	  { .first = 0x09D7, .last = 0x09D7 },
	  { .first = 0x09E2, .last = 0x09E3 },
	  { .first = 0x0A02, .last = 0x0A02 },
	  { .first = 0x0A3C, .last = 0x0A3C },
	  { .first = 0x0A3E, .last = 0x0A42 },
	  { .first = 0x0A47, .last = 0x0A48 },
	  { .first = 0x0A4B, .last = 0x0A4D },
	  { .first = 0x0A70, .last = 0x0A71 },
	  { .first = 0x0A81, .last = 0x0A83 },
	  { .first = 0x0ABC, .last = 0x0ABC },
	  { .first = 0x0ABE, .last = 0x0AC5 },
	  { .first = 0x0AC7, .last = 0x0AC9 },
	  { .first = 0x0ACB, .last = 0x0ACD },
	  { .first = 0x0B01, .last = 0x0B03 },
	  { .first = 0x0B3C, .last = 0x0B3C },
	  { .first = 0x0B3E, .last = 0x0B43 },
	  { .first = 0x0B47, .last = 0x0B48 },
	  { .first = 0x0B4B, .last = 0x0B4D },
	  { .first = 0x0B56, .last = 0x0B57 },
	  { .first = 0x0B82, .last = 0x0B82 },
	  { .first = 0x0BBE, .last = 0x0BC2 },
	  { .first = 0x0BC6, .last = 0x0BC8 },
	  { .first = 0x0BCA, .last = 0x0BCD },
	  { .first = 0x0BD7, .last = 0x0BD7 },
	  { .first = 0x0C01, .last = 0x0C03 },
	  { .first = 0x0C3E, .last = 0x0C44 },
	  { .first = 0x0C46, .last = 0x0C48 },
	  { .first = 0x0C4A, .last = 0x0C4D },
	  { .first = 0x0C55, .last = 0x0C56 },
	  { .first = 0x0C82, .last = 0x0C83 },
	  { .first = 0x0CBE, .last = 0x0CC4 },
	  { .first = 0x0CC6, .last = 0x0CC8 },
	  { .first = 0x0CCA, .last = 0x0CCD },
	  { .first = 0x0CD5, .last = 0x0CD6 },
	  { .first = 0x0D02, .last = 0x0D03 },
	  { .first = 0x0D3E, .last = 0x0D43 },
	  { .first = 0x0D46, .last = 0x0D48 },
	  { .first = 0x0D4A, .last = 0x0D4D },
	  { .first = 0x0D57, .last = 0x0D57 },
	  { .first = 0x0D82, .last = 0x0D83 },
	  { .first = 0x0DCA, .last = 0x0DCA },
	  { .first = 0x0DCF, .last = 0x0DD4 },
	  { .first = 0x0DD6, .last = 0x0DD6 },
	  { .first = 0x0DD8, .last = 0x0DDF },
	  { .first = 0x0DF2, .last = 0x0DF3 },
	  { .first = 0x0E31, .last = 0x0E31 },
	  { .first = 0x0E34, .last = 0x0E3A },
	  { .first = 0x0E47, .last = 0x0E4E },
	  { .first = 0x0EB1, .last = 0x0EB1 },
	  { .first = 0x0EB4, .last = 0x0EB9 },
	  { .first = 0x0EBB, .last = 0x0EBC },
	  { .first = 0x0EC8, .last = 0x0ECD },
	  { .first = 0x0F18, .last = 0x0F19 },
	  { .first = 0x0F35, .last = 0x0F35 },
	  { .first = 0x0F37, .last = 0x0F37 },
	  { .first = 0x0F39, .last = 0x0F39 },
	  { .first = 0x0F3E, .last = 0x0F3F },
	  { .first = 0x0F71, .last = 0x0F84 },
	  { .first = 0x0F86, .last = 0x0F87 },
	  { .first = 0x0F90, .last = 0x0F97 },
	  { .first = 0x0F99, .last = 0x0FBC },
	  { .first = 0x0FC6, .last = 0x0FC6 },
	  { .first = 0x102C, .last = 0x1032 },
	  { .first = 0x1036, .last = 0x1039 },
	  { .first = 0x1056, .last = 0x1059 },
	  { .first = 0x1712, .last = 0x1714 },
	  { .first = 0x1732, .last = 0x1734 },
	  { .first = 0x1752, .last = 0x1753 },
	  { .first = 0x1772, .last = 0x1773 },
	  { .first = 0x17B4, .last = 0x17D3 },
	  { .first = 0x180B, .last = 0x180D },
	  { .first = 0x18A9, .last = 0x18A9 },
	  { .first = 0x20D0, .last = 0x20EA },
	  { .first = 0x302A, .last = 0x302F },
	  { .first = 0x3099, .last = 0x309A },
	  { .first = 0xFB1E, .last = 0xFB1E },
	  { .first = 0xFE00, .last = 0xFE0F },
	  { .first = 0xFE20, .last = 0xFE23 },
	  { .first = 0x1D165, .last = 0x1D169 },
	  { .first = 0x1D16D, .last = 0x1D172 },
	  { .first = 0x1D17B, .last = 0x1D182 },
	  { .first = 0x1D185, .last = 0x1D18B },
	  { .first = 0x1D1AA, .last = 0x1D1AD } });
	static_assert(std::ranges::is_sorted(combining_marks, {}, &code_point_range::first));

	auto is_combining_mark(UChar32 c) noexcept -> bool
	{
		const auto *const it = std::ranges::upper_bound(combining_marks, c, {}, &code_point_range::first);
		return it != combining_marks.begin() && c <= std::prev(it)->last;
	}

	// ------------------------------------------------------------ steps 2.2 - 2.5 (ICU)

	struct usprep_closer
	{
		void operator()(UStringPrepProfile *p) const noexcept { usprep_close(p); }
	};
	using profile_ptr = std::unique_ptr<UStringPrepProfile, usprep_closer>;

	auto open_profile(UStringPrepProfileType type) noexcept -> profile_ptr
	{
		UErrorCode status = U_ZERO_ERROR;
		profile_ptr p(usprep_openByType(type, &status));
		if (detail::icu_failed(status)) {
			return nullptr;
		}
		return p;
	}

	// ICU's RFC 4518 profiles, opened once (usprep_prepare does not modify a
	// profile, so threads share them). nullptr if ICU cannot load its data,
	// and then for good: a failed open is not retried (ICU's data does not
	// appear later in a process). The profiles are closed at static
	// destruction; a program that calls u_cleanup() must do so after its last
	// match, as ICU requires of every ICU object.
	auto ldap_profile(bool case_fold) noexcept -> const UStringPrepProfile *
	{
		static const profile_ptr exact = open_profile(USPREP_RFC4518_LDAP);
		static const profile_ptr folded = open_profile(USPREP_RFC4518_LDAP_CI);
		return case_fold ? folded.get() : exact.get();
	}

	enum class prep_status : std::uint8_t {
		ok,
		invalid_utf8,
		prohibited,
		unassigned,
		replacement_character,
		too_long,
		icu
	};

	constexpr UChar replacement_character = 0xFFFD;
	// ICU counts in int32_t. One UTF-8 octet gives at most one UTF-16 unit;
	// table B.2 maps a code point to at most 3, NFKC expands one to at most
	// 18 (U+FDFA), and a UTF-16 unit gives at most 3 UTF-8 octets: about
	// 13 MB of input keeps every count below INT32_MAX.
	constexpr std::size_t max_case_fold_expansion = 3;
	constexpr std::size_t max_nfkc_expansion = 18;
	constexpr std::size_t max_utf8_per_utf16 = 3;
	constexpr std::size_t max_input =
	  static_cast<std::size_t>(INT32_MAX) / (max_case_fold_expansion * max_nfkc_expansion * max_utf8_per_utf16);

	// Printable ASCII (0x20-0x7E) is the identity for steps 2.2 to 2.5 except
	// case folding (table B.2 maps only A-Z there): no ICU call needed.
	auto is_printable_ascii(std::string_view s) noexcept -> bool
	{
		constexpr unsigned char first = 0x20;
		constexpr unsigned char last = 0x7E;
		return std::ranges::all_of(s, [](char c) {
			const auto u = static_cast<unsigned char>(c);
			return u >= first && u <= last;
		});
	}

	auto ascii_fold(char c) noexcept -> char { return c >= 'A' && c <= 'Z' ? static_cast<char>(c - 'A' + 'a') : c; }

	// ICU's statuses for a count past int32_t, should the bound above ever
	// be wrong: the value is too long, not an ICU failure. Any other status
	// (U_ILLEGAL_ARGUMENT_ERROR included: a misuse of ICU) is an ICU error.
	auto is_icu_overflow(UErrorCode status) noexcept -> bool
	{
		return status == U_INDEX_OUTOFBOUNDS_ERROR || status == U_INPUT_TOO_LONG_ERROR;
	}

	auto icu_status(UErrorCode status) noexcept -> prep_status
	{
		return is_icu_overflow(status) ? prep_status::too_long : prep_status::icu;
	}

	// Steps 2.1 to 2.5: `in` (UTF-8) transcoded, mapped, NFKC normalized and
	// checked, into `out` (UTF-8).
	auto map_normalize_prohibit(std::string_view in, bool case_fold, std::string &out) -> prep_status
	{
		// 2.1 Transcode: UTF-8 -> UTF-16. u_strFromUTF8 refuses ill-formed
		// UTF-8 (overlong forms, surrogates, above U+10FFFF, truncated).
		UErrorCode status = U_ZERO_ERROR;
		int32_t n16 = 0;
		u_strFromUTF8(nullptr, 0, &n16, in.data(), static_cast<int32_t>(in.size()), &status);
		if (status == U_INVALID_CHAR_FOUND || status == U_ILLEGAL_CHAR_FOUND) {
			return prep_status::invalid_utf8;
		}
		if (status != U_BUFFER_OVERFLOW_ERROR && detail::icu_failed(status)) {
			return icu_status(status);
		}
		std::vector<UChar> utf16(static_cast<std::size_t>(n16));
		status = U_ZERO_ERROR;
		u_strFromUTF8(utf16.data(), n16, &n16, in.data(), static_cast<int32_t>(in.size()), &status);
		if (detail::icu_failed(status)) {
			return icu_status(status);
		}

		// 2.2 Map, 2.3 Normalize (NFKC), 2.4 Prohibit and 2.5 Check bidi
		// (none) with ICU's RFC 4518 profiles. USPREP_DEFAULT refuses the
		// code points unassigned in Unicode 3.2 (table A.1), which RFC 4518
		// prohibits for every string (it has no "query" strings).
		const UStringPrepProfile *profile = ldap_profile(case_fold);
		if (profile == nullptr) {
			return prep_status::icu;
		}
		const auto prepare = [&](UChar *dest, int32_t capacity) {
			UParseError where{};
			status = U_ZERO_ERROR;
			return usprep_prepare(profile, utf16.data(), n16, dest, capacity, USPREP_DEFAULT, &where, &status);
		};
		int32_t nprep = prepare(nullptr, 0);
		switch (status) {
		case U_BUFFER_OVERFLOW_ERROR:
		case U_STRING_NOT_TERMINATED_WARNING:
		case U_ZERO_ERROR:
			break;
		case U_STRINGPREP_PROHIBITED_ERROR:
			return prep_status::prohibited;
		case U_STRINGPREP_UNASSIGNED_ERROR:
			return prep_status::unassigned;
		default:
			return icu_status(status);
		}
		std::vector<UChar> prepared(static_cast<std::size_t>(nprep));
		if (nprep > 0) {
			nprep = prepare(prepared.data(), nprep);
			if (detail::icu_failed(status)) {
				return icu_status(status);
			}
		}
		// 2.4: RFC 4518 also prohibits U+FFFD, which ICU's profiles let through.
		if (std::ranges::contains(prepared, replacement_character)) {
			return prep_status::replacement_character;
		}

		// UTF-16 -> UTF-8.
		status = U_ZERO_ERROR;
		int32_t n8 = 0;
		u_strToUTF8(nullptr, 0, &n8, prepared.data(), nprep, &status);
		if (status != U_BUFFER_OVERFLOW_ERROR && detail::icu_failed(status)) {
			return icu_status(status);
		}
		out.resize(static_cast<std::size_t>(n8));
		status = U_ZERO_ERROR;
		u_strToUTF8(out.data(), n8, &n8, prepared.data(), nprep, &status);
		if (detail::icu_failed(status)) {
			return icu_status(status);
		}
		return prep_status::ok;
	}

	// ------------------------------------------------------------ step 2.6

	// The code point at s[i] is followed by a combining mark (s is valid UTF-8).
	auto followed_by_mark(std::string_view s, std::size_t next) noexcept -> bool
	{
		return next < s.size() && is_combining_mark(detail::utf8_next(s, next).code_point);
	}

	// HYPHEN-MINUS, ARMENIAN HYPHEN, HYPHEN, NON-BREAKING HYPHEN, MINUS SIGN,
	// SMALL HYPHEN-MINUS, FULLWIDTH HYPHEN-MINUS (section 2.6.3).
	constexpr auto hyphens = std::to_array<UChar32>({ 0x002D, 0x058A, 0x2010, 0x2011, 0x2212, 0xFE63, 0xFF0D });

	// 2.6.1 Insignificant Space Handling. A space is a SPACE followed by no
	// combining mark; a SPACE followed by one is an ordinary character.
	void handle_spaces(std::string_view s, prep_input input, std::pmr::string &out)
	{
		const auto is_space = [&](std::size_t i) { return s[i] == ' ' && !followed_by_mark(s, i + 1); };
		const bool substring = input != prep_input::value;
		std::size_t i = 0;
		bool leading = false;
		while (i < s.size() && is_space(i)) {
			++i;
			leading = true;
		}
		if (i == s.size()) {
			// No non-space character: two SPACEs, one for a substring.
			out.assign(substring ? 1 : 2, ' ');
			return;
		}
		// With errata 1757 and 1758, every input starts and ends the same way
		// except for the substring rules below, and inner runs become two
		// SPACEs.
		const bool starts_with_space =
		  input == prep_input::value || input == prep_input::initial_substring
		  || (leading && (input == prep_input::any_substring || input == prep_input::final_substring));
		if (starts_with_space) {
			out += ' ';
		}
		bool pending = false;// a run of spaces since the last character
		while (i < s.size()) {
			if (is_space(i)) {
				pending = true;
				++i;
				continue;
			}
			if (pending) {
				out += "  ";
				pending = false;
			}
			const std::size_t len = detail::utf8_next(s, i).length;
			out.append(s.substr(i, len));
			i += len;
		}
		const bool ends_with_space =
		  input == prep_input::value || input == prep_input::final_substring
		  || (pending && (input == prep_input::initial_substring || input == prep_input::any_substring));
		if (ends_with_space) {
			out += ' ';
		}
	}

	// 2.6.2 and 2.6.3: every space (and hyphen) removed.
	void remove_insignificant(std::string_view s, bool hyphens_too, std::pmr::string &out)
	{
		std::size_t i = 0;
		while (i < s.size()) {
			const auto [c, len] = detail::utf8_next(s, i);
			const bool removable = c == ' ' || (hyphens_too && std::ranges::contains(hyphens, c));
			if (!removable || followed_by_mark(s, i + len)) {
				out.append(s.substr(i, len));
			}
			i += len;
		}
	}

	auto prepare_into(std::string_view in, const prep_options &options, std::pmr::string &out) -> prep_status
	{
		out.clear();
		if (in.size() > max_input) {
			return prep_status::too_long;
		}
		std::string buffer;
		std::string_view mapped = in;
		if (is_printable_ascii(in)) {
			if (options.case_fold) {
				buffer.resize(in.size());
				std::ranges::transform(in, buffer.begin(), ascii_fold);
				mapped = buffer;
			}
		} else {
			if (const auto status = map_normalize_prohibit(in, options.case_fold, buffer); status != prep_status::ok) {
				return status;
			}
			mapped = buffer;
		}
		switch (options.handling) {
		case insignificant_handling::space:
			handle_spaces(mapped, options.input, out);
			break;
		case insignificant_handling::numeric_string:
			remove_insignificant(mapped, false, out);
			break;
		case insignificant_handling::telephone_number:
			remove_insignificant(mapped, true, out);
			break;
		}
		return prep_status::ok;
	}

	// ------------------------------------------------------------ string rules

	// The syntax of a string rule's values, checked on the value as given,
	// before preparation (RFC 4517 section 3.3).
	enum class string_syntax : std::uint8_t {
		directory_string,// 3.3.6: 1*UTF8 (UTF-8 validity is checked by preparation)
		ia5_string,// 3.3.15: *(%x00-7F)
		numeric_string,// 3.3.23: 1*(DIGIT / SPACE)
		telephone_number,// 3.3.31: a PrintableString, 1*PrintableCharacter
	};

	// What a string matching rule prepares, and the syntax it checks.
	struct string_rule
	{
		bool case_fold = false;
		insignificant_handling handling = insignificant_handling::space;
		string_syntax syntax = string_syntax::directory_string;
	};

	constexpr string_rule case_ignore{ .case_fold = true,
		.handling = insignificant_handling::space,
		.syntax = string_syntax::directory_string };
	constexpr string_rule case_exact{ .case_fold = false,
		.handling = insignificant_handling::space,
		.syntax = string_syntax::directory_string };
	constexpr string_rule case_ignore_ia5{ .case_fold = true,
		.handling = insignificant_handling::space,
		.syntax = string_syntax::ia5_string };
	constexpr string_rule case_exact_ia5{ .case_fold = false,
		.handling = insignificant_handling::space,
		.syntax = string_syntax::ia5_string };
	constexpr string_rule numeric_string{ .case_fold = false,
		.handling = insignificant_handling::numeric_string,
		.syntax = string_syntax::numeric_string };
	constexpr string_rule telephone_number{ .case_fold = true,
		.handling = insignificant_handling::telephone_number,
		.syntax = string_syntax::telephone_number };

	auto is_ia5(std::string_view s) noexcept -> bool
	{
		return std::ranges::none_of(s, [](char c) { return static_cast<unsigned char>(c) >= 0x80u; });
	}

	auto is_digits(std::string_view s) noexcept -> bool
	{
		return std::ranges::all_of(s, [](char c) { return c >= '0' && c <= '9'; });
	}

	// NumericString characters, ASCII only (RFC 4517 section 3.3.23): a
	// fullwidth digit is not one, although NFKC would make it a digit.
	auto is_numeric_string_chars(std::string_view s) noexcept -> bool
	{
		return std::ranges::all_of(s, [](char c) { return (c >= '0' && c <= '9') || c == ' '; });
	}

	// Whether `v`, a value or one substring as given, is of the syntax.
	// Substrings are never empty here (an empty one is absent).
	auto has_syntax(std::string_view v, string_syntax syntax) noexcept -> bool
	{
		switch (syntax) {
		case string_syntax::directory_string:
			return !v.empty();
		case string_syntax::ia5_string:
			return is_ia5(v);
		case string_syntax::numeric_string:
			return !v.empty() && is_numeric_string_chars(v);
		case string_syntax::telephone_number:
			// Not empty. The characters are not checked: RFC 4518 section
			// 2.6.3 removes hyphens that no PrintableString holds, so
			// servers take more than PrintableString here.
			return !v.empty();
		}
		return false;
	}

	// Prepares `v` for `rule`; false if the match must be Undefined.
	auto prepare_for(std::string_view v, const string_rule &rule, prep_input input, std::pmr::string &out) -> bool
	{
		if (!has_syntax(v, rule.syntax)) {
			return false;
		}
		const prep_options options{ .case_fold = rule.case_fold, .handling = rule.handling, .input = input };
		return prepare_into(v, options, out) == prep_status::ok;
	}

	auto to_result(bool b) noexcept -> match_result { return b ? match_result::true_value : match_result::false_value; }

	auto string_equality(const string_rule &rule, std::string_view a, std::string_view b) -> match_result
	{
		std::pmr::string pa;
		std::pmr::string pb;
		if (!prepare_for(a, rule, prep_input::value, pa) || !prepare_for(b, rule, prep_input::value, pb)) {
			return match_result::undefined;
		}
		return to_result(pa == pb);
	}

	auto string_ordering(const string_rule &rule, std::string_view a, std::string_view b) -> match_result
	{
		std::pmr::string pa;
		std::pmr::string pb;
		if (!prepare_for(a, rule, prep_input::value, pa) || !prepare_for(b, rule, prep_input::value, pb)) {
			return match_result::undefined;
		}
		// char_traits<char> compares as unsigned char: UTF-8 octet order is
		// code point order.
		return to_result(pa < pb);
	}

	// The first occurrence of `needle` in `text` at or after `from`, in
	// linear time: string_view::find is O(text * needle) at worst ("a...ab"
	// in "a...a"), so a long needle is searched with Knuth-Morris-Pratt.
	auto find_first(std::string_view text, std::string_view needle, std::size_t from) -> std::size_t
	{
		constexpr std::size_t short_needle = 16;
		if (needle.size() <= short_needle) {
			return text.find(needle, from);
		}
		// failure[i]: the length of the longest proper prefix of
		// needle[0..i] that is also its suffix.
		std::vector<std::size_t> failure(needle.size(), 0);
		std::size_t k = 0;
		for (std::size_t i = 1; i < needle.size(); ++i) {
			while (k > 0 && needle[i] != needle[k]) {
				k = failure[k - 1];
			}
			if (needle[i] == needle[k]) {
				++k;
			}
			failure[i] = k;
		}
		k = 0;
		for (std::size_t i = from; i < text.size(); ++i) {
			while (k > 0 && text[i] != needle[k]) {
				k = failure[k - 1];
			}
			if (text[i] == needle[k]) {
				++k;
			}
			if (k == needle.size()) {
				return i + 1 - needle.size();
			}
		}
		return std::string_view::npos;
	}

	auto string_substrings(const string_rule &rule, std::string_view value, const substring_assertion &assertion)
	  -> match_result
	{
		std::pmr::string v;
		if (!prepare_for(value, rule, prep_input::value, v)) {
			return match_result::undefined;
		}
		std::pmr::string initial;
		std::pmr::string final;
		if (!assertion.initial.empty()
			&& !prepare_for(assertion.initial, rule, prep_input::initial_substring, initial)) {
			return match_result::undefined;
		}
		if (!assertion.final.empty() && !prepare_for(assertion.final, rule, prep_input::final_substring, final)) {
			return match_result::undefined;
		}
		std::vector<std::pmr::string> any;
		for (const auto part : assertion.any) {
			if (part.empty()) {
				continue;
			}
			if (!prepare_for(part, rule, prep_input::any_substring, any.emplace_back())) {
				return match_result::undefined;
			}
		}
		// Leftmost matches: initial at the start, final at the end, each any
		// part at its first place after the previous one. Valid UTF-8 needles
		// only match whole characters.
		const std::string_view text = v;
		if (!assertion.initial.empty() && !text.starts_with(initial)) {
			return match_result::false_value;
		}
		std::size_t pos = assertion.initial.empty() ? 0 : initial.size();
		std::size_t end = text.size();
		if (!assertion.final.empty()) {
			if (end - pos < final.size() || !text.ends_with(final)) {
				return match_result::false_value;
			}
			end -= final.size();
		}
		for (const auto &part : any) {
			const std::size_t at = find_first(text.substr(0, end), part, pos);
			if (at == std::string_view::npos) {
				return match_result::false_value;
			}
			pos = at + part.size();
		}
		return match_result::true_value;
	}

	// ------------------------------------------------------------ Integer

	// RFC 4517 section 3.3.16: Integer = ( HYPHEN LDIGIT *DIGIT ) / number.
	auto is_integer(std::string_view s) noexcept -> bool
	{
		const std::string_view digits = s.starts_with('-') ? s.substr(1) : s;
		if (digits.empty() || !is_digits(digits)) {
			return false;
		}
		if (digits.front() == '0') {
			return digits.size() == 1 && digits.size() == s.size();// "0", not "-0" or "01"
		}
		return true;
	}

	// a < b for two valid Integers.
	auto integer_less(std::string_view a, std::string_view b) noexcept -> bool
	{
		const bool neg_a = a.starts_with('-');
		const bool neg_b = b.starts_with('-');
		if (neg_a != neg_b) {
			return neg_a;
		}
		const std::string_view ma = neg_a ? a.substr(1) : a;
		const std::string_view mb = neg_b ? b.substr(1) : b;
		if (ma == mb) {
			return false;
		}
		const bool smaller = ma.size() != mb.size() ? ma.size() < mb.size() : ma < mb;
		return neg_a ? !smaller : smaller;
	}

	// ------------------------------------------------------------ Substring Assertion

	// RFC 4517 section 3.3.30, decoded: `initial*any*...*final`, "\2A" and
	// "\5C" (hex digits in either case, ABNF strings are case-insensitive)
	// for "*" and "\". false if malformed.
	struct parsed_substrings
	{
		std::vector<std::string> parts;// initial, any..., final
		std::vector<std::string_view> any;
	};

	auto parse_substring_assertion(std::string_view text, parsed_substrings &out) -> bool
	{
		out.parts.emplace_back();
		for (std::size_t i = 0; i < text.size(); ++i) {
			const char c = text[i];
			if (c == '*') {
				out.parts.emplace_back();
			} else if (c == '\\') {
				const std::string_view esc = text.substr(i + 1, 2);
				if (detail::iequals(esc, "2A")) {
					out.parts.back() += '*';
				} else if (detail::iequals(esc, "5C")) {
					out.parts.back() += '\\';
				} else {
					return false;
				}
				i += 2;
			} else {
				out.parts.back() += c;
			}
		}
		if (out.parts.size() < 2) {
			return false;// no ASTERISK
		}
		for (std::size_t k = 1; k + 1 < out.parts.size(); ++k) {
			if (out.parts[k].empty()) {
				return false;// a zero-length substring
			}
			out.any.emplace_back(out.parts[k]);
		}
		return true;
	}

	// A matching rule's attribute value and assertion value, RFC 4517 order.
	template<auto Rule>
	// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
	auto substrings_from_text(std::string_view value, std::string_view assertion_text) -> match_result
	{
		parsed_substrings p;
		if (!parse_substring_assertion(assertion_text, p)) {
			return match_result::undefined;
		}
		return Rule(value, { .initial = p.parts.front(), .any = p.any, .final = p.parts.back() });
	}

	// NOLINTNEXTLINE(bugprone-easily-swappable-parameters): attribute value, assertion value
	auto dn_from_text(std::string_view a, std::string_view b) -> match_result
	{
		const auto da = dn::parse(a);
		const auto db = dn::parse(b);
		if (!da || !db) {
			return match_result::undefined;
		}
		return distinguished_name_match(*da, *db);
	}

	// ------------------------------------------------------------ rule table

	enum class rule_kind : std::uint8_t { equality, ordering, substrings };

	struct rule_entry
	{
		std::string_view name;
		std::string_view oid;
		rule_kind kind;
		match_result (*fn)(std::string_view, std::string_view);
	};

	// RFC 4517 section 4.2 (and 4.2.15 for distinguishedNameMatch).
	constexpr auto rules = std::to_array<rule_entry>({
	  { .name = "caseIgnoreMatch", .oid = "2.5.13.2", .kind = rule_kind::equality, .fn = case_ignore_match },
	  { .name = "caseExactMatch", .oid = "2.5.13.5", .kind = rule_kind::equality, .fn = case_exact_match },
	  { .name = "caseIgnoreIA5Match",
		.oid = "1.3.6.1.4.1.1466.109.114.2",
		.kind = rule_kind::equality,
		.fn = case_ignore_ia5_match },
	  { .name = "caseExactIA5Match",
		.oid = "1.3.6.1.4.1.1466.109.114.1",
		.kind = rule_kind::equality,
		.fn = case_exact_ia5_match },
	  { .name = "numericStringMatch", .oid = "2.5.13.8", .kind = rule_kind::equality, .fn = numeric_string_match },
	  { .name = "telephoneNumberMatch", .oid = "2.5.13.20", .kind = rule_kind::equality, .fn = telephone_number_match },
	  { .name = "octetStringMatch", .oid = "2.5.13.17", .kind = rule_kind::equality, .fn = octet_string_match },
	  { .name = "integerMatch", .oid = "2.5.13.14", .kind = rule_kind::equality, .fn = integer_match },
	  { .name = "booleanMatch", .oid = "2.5.13.13", .kind = rule_kind::equality, .fn = boolean_match },
	  { .name = "distinguishedNameMatch", .oid = "2.5.13.1", .kind = rule_kind::equality, .fn = dn_from_text },
	  { .name = "caseIgnoreOrderingMatch",
		.oid = "2.5.13.3",
		.kind = rule_kind::ordering,
		.fn = case_ignore_ordering_match },
	  { .name = "caseExactOrderingMatch",
		.oid = "2.5.13.6",
		.kind = rule_kind::ordering,
		.fn = case_exact_ordering_match },
	  { .name = "numericStringOrderingMatch",
		.oid = "2.5.13.9",
		.kind = rule_kind::ordering,
		.fn = numeric_string_ordering_match },
	  { .name = "octetStringOrderingMatch",
		.oid = "2.5.13.18",
		.kind = rule_kind::ordering,
		.fn = octet_string_ordering_match },
	  { .name = "integerOrderingMatch", .oid = "2.5.13.15", .kind = rule_kind::ordering, .fn = integer_ordering_match },
	  { .name = "caseIgnoreSubstringsMatch",
		.oid = "2.5.13.4",
		.kind = rule_kind::substrings,
		.fn = substrings_from_text<case_ignore_substrings_match> },
	  { .name = "caseExactSubstringsMatch",
		.oid = "2.5.13.7",
		.kind = rule_kind::substrings,
		.fn = substrings_from_text<case_exact_substrings_match> },
	  { .name = "caseIgnoreIA5SubstringsMatch",
		.oid = "1.3.6.1.4.1.1466.109.114.3",
		.kind = rule_kind::substrings,
		.fn = substrings_from_text<case_ignore_ia5_substrings_match> },
	  { .name = "numericStringSubstringsMatch",
		.oid = "2.5.13.10",
		.kind = rule_kind::substrings,
		.fn = substrings_from_text<numeric_string_substrings_match> },
	  { .name = "telephoneNumberSubstringsMatch",
		.oid = "2.5.13.21",
		.kind = rule_kind::substrings,
		.fn = substrings_from_text<telephone_number_substrings_match> },
	});

	auto find_rule(std::string_view rule) noexcept -> const rule_entry *
	{
		const auto *const it = std::ranges::find_if(
		  rules, [rule](const rule_entry &e) { return e.oid == rule || detail::iequals(e.name, rule); });
		return it == rules.end() ? nullptr : &*it;
	}

	// ------------------------------------------------------------ DN AVAs

	void append_utf8(std::string &out, char32_t c)
	{
		constexpr char32_t one = 0x80;
		constexpr char32_t two = 0x800;
		constexpr char32_t three = 0x10000;
		// A continuation octet is 10xxxxxx; the lead octet of a sequence
		// with `extra` continuation octets is 110xxxxx, 1110xxxx or 11110xxx.
		constexpr unsigned continuation_bits = 6;
		constexpr char32_t continuation_tag = 0x80;
		constexpr char32_t continuation_mask = 0x3F;
		constexpr std::array<char32_t, 3> lead_tags{ 0xC0, 0xE0, 0xF0 };
		const auto octet = [&out](char32_t v) { out += static_cast<char>(static_cast<unsigned char>(v)); };
		if (c < one) {
			octet(c);
			return;
		}
		std::size_t extra = 1;
		if (c >= two) {
			extra = c < three ? 2 : 3;
		}
		octet(lead_tags[extra - 1] | (c >> (continuation_bits * extra)));
		for (std::size_t k = extra; k-- > 0;) {
			octet(continuation_tag | ((c >> (continuation_bits * k)) & continuation_mask));
		}
	}

	// Big-endian UCS-2 (BMPString) or UCS-4 (UniversalString) to UTF-8; false
	// for a partial unit, a surrogate or a value above U+10FFFF.
	auto transcode_ucs(std::span<const std::byte> content, std::size_t unit, std::string &out) -> bool
	{
		constexpr char32_t surrogate_first = 0xD800;
		constexpr char32_t surrogate_last = 0xDFFF;
		constexpr char32_t max_code_point = 0x10FFFF;
		if (content.size() % unit != 0) {
			return false;
		}
		for (std::size_t i = 0; i < content.size(); i += unit) {
			char32_t c = 0;
			for (std::size_t k = 0; k < unit; ++k) {
				c = (c << 8u) | std::to_integer<char32_t>(content[i + k]);
			}
			if ((c >= surrogate_first && c <= surrogate_last) || c > max_code_point) {
				return false;
			}
			append_utf8(out, c);
		}
		return true;
	}

	// The longest INTEGER content decoded to decimal: the conversion below is
	// quadratic in the length, and a DN can be megabytes long (cf. CPython's
	// int-to-str digit limit for CVE-2020-10735). 4096 octets are 9865
	// decimal digits.
	constexpr std::size_t max_integer_octets = 4096;

	// X.690 section 8.3: an INTEGER's content octets, two's complement and
	// minimal (8.3.2), in decimal (the Integer syntax, RFC 4517 section
	// 3.3.16). false if empty, not minimal or longer than max_integer_octets.
	auto ber_integer_to_decimal(std::span<const std::byte> content, std::string &out) -> bool
	{
		constexpr unsigned sign_bit = 0x80;
		constexpr unsigned all_ones = 0xFF;
		constexpr unsigned octet_bits = 8;
		constexpr std::size_t octets_per_limb = 4;
		constexpr std::uint64_t chunk_base = 1'000'000'000;// 9 decimal digits per chunk
		constexpr int chunk_digits = 9;
		if (content.empty() || content.size() > max_integer_octets) {
			return false;
		}
		const auto octet = [&](std::size_t i) { return std::to_integer<unsigned>(content[i]); };
		if (content.size() > 1) {
			const bool second_sign = (octet(1) & sign_bit) != 0;
			if ((octet(0) == 0 && !second_sign) || (octet(0) == all_ones && second_sign)) {
				return false;
			}
		}
		// The magnitude, big-endian: a negative number negated (invert, add 1).
		const bool negative = (octet(0) & sign_bit) != 0;
		std::vector<unsigned> magnitude(content.size());
		for (std::size_t i = 0; i < content.size(); ++i) {
			magnitude[i] = negative ? (~octet(i) & all_ones) : octet(i);
		}
		if (negative) {
			for (std::size_t i = magnitude.size(); i-- > 0;) {
				magnitude[i] = (magnitude[i] + 1) & all_ones;
				if (magnitude[i] != 0) {
					break;
				}
			}
		}
		// 32-bit limbs, most significant first, divided by 10^9 until zero.
		std::vector<std::uint32_t> limbs((magnitude.size() + octets_per_limb - 1) / octets_per_limb, 0);
		for (std::size_t i = 0; i < magnitude.size(); ++i) {
			const std::size_t from_end = magnitude.size() - 1 - i;
			limbs[limbs.size() - 1 - (from_end / octets_per_limb)] |= static_cast<std::uint32_t>(magnitude[i])
																	  << (octet_bits * (from_end % octets_per_limb));
		}
		std::vector<std::uint32_t> chunks;// least significant first
		std::size_t first = 0;
		while (true) {
			while (first < limbs.size() && limbs[first] == 0) {
				++first;
			}
			if (first == limbs.size()) {
				break;
			}
			std::uint64_t remainder = 0;
			for (std::size_t k = first; k < limbs.size(); ++k) {
				const std::uint64_t cur = (remainder << (octet_bits * octets_per_limb)) | limbs[k];
				limbs[k] = static_cast<std::uint32_t>(cur / chunk_base);
				remainder = cur % chunk_base;
			}
			chunks.push_back(static_cast<std::uint32_t>(remainder));
		}
		out.clear();
		if (chunks.empty()) {
			out = "0";
			return true;
		}
		if (negative) {
			out += '-';
		}
		out += std::to_string(chunks.back());
		for (std::size_t k = chunks.size() - 1; k-- > 0;) {
			const std::string digits = std::to_string(chunks[k]);
			out.append(static_cast<std::size_t>(chunk_digits) - digits.size(), '0');
			out += digits;
		}
		return true;
	}

	// X.680 character sets of the restricted string types.
	auto is_printable_string_char(char c) noexcept -> bool
	{
		constexpr std::string_view punctuation = "'()+,-./:=? ";
		return detail::is_alpha(c) || detail::is_digit(c) || punctuation.contains(c);
	}

	auto is_visible_string_char(char c) noexcept -> bool
	{
		constexpr unsigned char first = 0x20;
		constexpr unsigned char last = 0x7E;
		const auto u = static_cast<unsigned char>(c);
		return u >= first && u <= last;
	}

	// The value of a `#hex` AVA (BER, RFC 4514 section 2.4) as the text the
	// rules take: string types and OCTET STRING by their content (NumericString,
	// PrintableString, IA5String and VisibleString checked against their
	// character sets), BMPString and UniversalString transcoded to UTF-8 (RFC
	// 4518 section 2.1), INTEGER in decimal (up to max_integer_octets content
	// octets), BOOLEAN as TRUE or FALSE. false for anything else,
	// TeletexString included (its transcoding is a local matter).
	auto decode_hex_value(std::string_view ber_value, std::string &out) -> bool
	{
		// Universal tag numbers (X.680).
		constexpr std::uint8_t boolean = 1;
		constexpr std::uint8_t integer = 2;
		constexpr std::uint8_t octet_string = 4;
		constexpr std::uint8_t utf8_string = 12;
		constexpr std::uint8_t numeric_string_tag = 18;
		constexpr std::uint8_t printable_string = 19;
		constexpr std::uint8_t ia5_string = 22;
		constexpr std::uint8_t visible_string = 26;
		constexpr std::uint8_t universal_string = 28;
		constexpr std::uint8_t bmp_string = 30;
		const std::span<const std::byte> bytes = std::as_bytes(std::span(ber_value));
		ber::reader r(bytes);
		const auto e = r.read();
		if (!e || !r.empty() || e->t.cls != ber::tag_class::universal || e->t.constructed) {
			return false;
		}
		const auto text = [&](auto &&valid) {
			out.assign(reinterpret_cast<const char *>(e->content.data()), e->content.size());
			return std::ranges::all_of(out, valid);
		};
		switch (e->t.number) {
		case octet_string:
		case utf8_string:
			return text([](char) { return true; });
		case numeric_string_tag:
			return text([](char c) { return detail::is_digit(c) || c == ' '; });
		case printable_string:
			return text(is_printable_string_char);
		case ia5_string:
			return text([](char c) { return static_cast<unsigned char>(c) < 0x80u; });
		case visible_string:
			return text(is_visible_string_char);
		case bmp_string:
			return transcode_ucs(e->content, 2, out);
		case universal_string:
			return transcode_ucs(e->content, 4, out);
		case integer:
			return ber_integer_to_decimal(e->content, out);
		case boolean: {
			ber::reader again(bytes);
			const auto b = again.read_boolean();
			if (!b) {
				return false;
			}
			out = *b ? "TRUE" : "FALSE";
			return true;
		}
		default:
			return false;
		}
	}

	// ------------------------------------------------------------ AVA types

	// The attribute types of RFC 4519 by every name it gives them (section
	// 4's registrations, and section 2's X.500 names "stateOrProvinceName"
	// and "streetAddress"), so that `cn`, `commonName` and `2.5.4.3` are one
	// type without a schema. Sorted by name, case-insensitively.
	struct type_name
	{
		std::string_view name;
		std::string_view oid;
	};

	constexpr auto rfc4519_types = std::to_array<type_name>({
	  { .name = "businessCategory", .oid = "2.5.4.15" },
	  { .name = "c", .oid = "2.5.4.6" },
	  { .name = "cn", .oid = "2.5.4.3" },
	  { .name = "commonName", .oid = "2.5.4.3" },
	  { .name = "countryName", .oid = "2.5.4.6" },
	  { .name = "dc", .oid = "0.9.2342.19200300.100.1.25" },
	  { .name = "description", .oid = "2.5.4.13" },
	  { .name = "destinationIndicator", .oid = "2.5.4.27" },
	  { .name = "distinguishedName", .oid = "2.5.4.49" },
	  { .name = "dnQualifier", .oid = "2.5.4.46" },
	  { .name = "domainComponent", .oid = "0.9.2342.19200300.100.1.25" },
	  { .name = "enhancedSearchGuide", .oid = "2.5.4.47" },
	  { .name = "facsimileTelephoneNumber", .oid = "2.5.4.23" },
	  { .name = "generationQualifier", .oid = "2.5.4.44" },
	  { .name = "givenName", .oid = "2.5.4.42" },
	  { .name = "houseIdentifier", .oid = "2.5.4.51" },
	  { .name = "initials", .oid = "2.5.4.43" },
	  { .name = "internationalISDNNumber", .oid = "2.5.4.25" },
	  { .name = "l", .oid = "2.5.4.7" },
	  { .name = "localityName", .oid = "2.5.4.7" },
	  { .name = "member", .oid = "2.5.4.31" },
	  { .name = "name", .oid = "2.5.4.41" },
	  { .name = "o", .oid = "2.5.4.10" },
	  { .name = "organizationalUnitName", .oid = "2.5.4.11" },
	  { .name = "organizationName", .oid = "2.5.4.10" },
	  { .name = "ou", .oid = "2.5.4.11" },
	  { .name = "owner", .oid = "2.5.4.32" },
	  { .name = "physicalDeliveryOfficeName", .oid = "2.5.4.19" },
	  { .name = "postalAddress", .oid = "2.5.4.16" },
	  { .name = "postalCode", .oid = "2.5.4.17" },
	  { .name = "postOfficeBox", .oid = "2.5.4.18" },
	  { .name = "preferredDeliveryMethod", .oid = "2.5.4.28" },
	  { .name = "registeredAddress", .oid = "2.5.4.26" },
	  { .name = "roleOccupant", .oid = "2.5.4.33" },
	  { .name = "searchGuide", .oid = "2.5.4.14" },
	  { .name = "seeAlso", .oid = "2.5.4.34" },
	  { .name = "serialNumber", .oid = "2.5.4.5" },
	  { .name = "sn", .oid = "2.5.4.4" },
	  { .name = "st", .oid = "2.5.4.8" },
	  { .name = "stateOrProvinceName", .oid = "2.5.4.8" },
	  { .name = "street", .oid = "2.5.4.9" },
	  { .name = "streetAddress", .oid = "2.5.4.9" },
	  { .name = "surname", .oid = "2.5.4.4" },
	  { .name = "telephoneNumber", .oid = "2.5.4.20" },
	  { .name = "teletexTerminalIdentifier", .oid = "2.5.4.22" },
	  { .name = "telexNumber", .oid = "2.5.4.21" },
	  { .name = "title", .oid = "2.5.4.12" },
	  { .name = "uid", .oid = "0.9.2342.19200300.100.1.1" },
	  { .name = "uniqueMember", .oid = "2.5.4.50" },
	  { .name = "userid", .oid = "0.9.2342.19200300.100.1.1" },
	  { .name = "userPassword", .oid = "2.5.4.35" },
	  { .name = "x121Address", .oid = "2.5.4.24" },
	  { .name = "x500UniqueIdentifier", .oid = "2.5.4.45" },
	});

	// A-Z folded, then octet order.
	constexpr auto ci_compare(std::string_view a, std::string_view b) noexcept -> std::strong_ordering
	{
		const std::size_t n = std::min(a.size(), b.size());
		for (std::size_t i = 0; i < n; ++i) {
			const auto ca = static_cast<unsigned char>(detail::ascii_lower(a[i]));
			const auto cb = static_cast<unsigned char>(detail::ascii_lower(b[i]));
			if (ca != cb) {
				return ca <=> cb;
			}
		}
		return a.size() <=> b.size();
	}

	static_assert(std::ranges::is_sorted(
	  rfc4519_types,
	  [](std::string_view a, std::string_view b) { return std::is_lt(ci_compare(a, b)); },
	  &type_name::name));

	auto rfc4519_oid(std::string_view name) noexcept -> std::string_view
	{
		const auto *const it = std::ranges::lower_bound(
		  rfc4519_types,
		  name,
		  [](std::string_view a, std::string_view b) { return std::is_lt(ci_compare(a, b)); },
		  &type_name::name);
		return it != rfc4519_types.end() && detail::iequals(it->name, name) ? it->oid : std::string_view{};
	}

	// An AVA's attribute type as far as it can be identified: the OID of its
	// definition (resolved), or the name itself when neither the schema nor
	// RFC 4519 knows it. Two resolved keys name the same type exactly when
	// equal; a name that is not resolved might be another name of any type.
	struct type_key
	{
		std::string_view text;
		bool resolved = false;
	};

	auto operator<=>(const type_key &a, const type_key &b) noexcept -> std::strong_ordering
	{
		if (a.resolved != b.resolved) {
			return a.resolved ? std::strong_ordering::less : std::strong_ordering::greater;
		}
		return ci_compare(a.text, b.text);
	}

	auto operator==(const type_key &a, const type_key &b) noexcept -> bool { return std::is_eq(a <=> b); }

	// distinguishedNameMatch inside an AVA value nests DNs; deeper than this
	// is Undefined (each level is linear work and a stack frame).
	constexpr std::size_t max_dn_nesting = 8;

	struct dn_context
	{
		detail::equality_rule_lookup lookup;
		const void *context;
		const server_schema *schema;
		std::size_t depth = 0;

		[[nodiscard]] auto key_of(const attribute &type) const noexcept -> type_key
		{
			const std::string_view name = type.name();
			if (schema != nullptr) {
				if (const attribute_type *t = schema->find_attribute(name)) {
					return { .text = t->oid, .resolved = true };
				}
			}
			if (detail::is_numericoid(name)) {
				return { .text = name, .resolved = true };
			}
			if (const std::string_view oid = rfc4519_oid(name); !oid.empty()) {
				return { .text = oid, .resolved = true };
			}
			return { .text = name, .resolved = false };
		}
	};

	auto combine(match_result &acc, match_result r) noexcept -> bool
	{
		if (r == match_result::false_value) {
			acc = r;
			return false;// FALSE decides
		}
		if (r == match_result::undefined) {
			acc = r;
		}
		return true;
	}

	auto dn_match(const dn &a, const dn &b, const dn_context &ctx) -> match_result;

	// distinguishedNameMatch on two AVA values, with the outer DN's context.
	// NOLINTNEXTLINE(bugprone-easily-swappable-parameters): attribute value, assertion value
	auto nested_dn_match(std::string_view a, std::string_view b, const dn_context &ctx) -> match_result
	{
		if (ctx.depth >= max_dn_nesting) {
			return match_result::undefined;
		}
		const auto da = dn::parse(a);
		const auto db = dn::parse(b);
		if (!da || !db) {
			return match_result::undefined;
		}
		dn_context inner = ctx;
		++inner.depth;
		return dn_match(*da, *db, inner);
	}

	// The equality rule the lookup gives `type`; null for a rule match() does
	// not implement. The rule's text is read before the next lookup call.
	auto rule_of(const attribute &type, const dn_context &ctx) -> const rule_entry *
	{
		const std::string_view rule = ctx.lookup(ctx.context, type);
		return find_rule(rule.empty() ? std::string_view{ "caseIgnoreMatch" } : rule);
	}

	// x and y were paired by type key, but their type names may differ
	// (`uid` and `userid`, a name and its OID): each name is looked up, and
	// two rules that are not the same rule give Undefined, so the result does
	// not depend on which side is the attribute value.
	auto ava_match(const ava &x, const ava &y, const dn_context &ctx) -> match_result
	{
		const rule_entry *e = rule_of(x.type, ctx);
		if (x.type.name() != y.type.name() && rule_of(y.type, ctx) != e) {
			return match_result::undefined;
		}
		if (e == nullptr || e->kind != rule_kind::equality) {
			return match_result::undefined;
		}
		std::string bx;
		std::string by;
		std::string_view vx = x.value;
		std::string_view vy = y.value;
		if (x.hex_form) {
			if (!decode_hex_value(x.value, bx)) {
				return match_result::undefined;
			}
			vx = bx;
		}
		if (y.hex_form) {
			if (!decode_hex_value(y.value, by)) {
				return match_result::undefined;
			}
			vy = by;
		}
		if (e->fn == dn_from_text) {
			return nested_dn_match(vx, vy, ctx);
		}
		return e->fn(vx, vy);
	}

	struct keyed_ava
	{
		type_key key;
		const ava *value;
	};

	// r's AVAs sorted by type key; false if a type is there twice.
	auto sorted_by_type(const rdn &r, const dn_context &ctx, std::vector<keyed_ava> &out) -> bool
	{
		out.reserve(r.avas.size());
		for (const ava &a : r.avas) {
			out.push_back({ .key = ctx.key_of(a.type), .value = &a });
		}
		std::ranges::sort(out, {}, &keyed_ava::key);
		return std::ranges::adjacent_find(out, {}, &keyed_ava::key) == out.end();
	}

	// Each type's key is resolved once, both RDNs are sorted by key and
	// merged: O(n log n) in the number of AVAs.
	auto rdn_match(const rdn &a, const rdn &b, const dn_context &ctx) -> match_result
	{
		if (a.avas.size() != b.avas.size()) {
			return match_result::false_value;
		}
		std::vector<keyed_ava> ka;
		std::vector<keyed_ava> kb;
		const bool a_ok = sorted_by_type(a, ctx, ka);
		if (!sorted_by_type(b, ctx, kb) || !a_ok) {
			return match_result::undefined;
		}
		// Pair the AVAs of the same type; note what is left on each side.
		struct leftovers
		{
			bool resolved = false;
			bool unresolved = false;
			void add(const type_key &k) noexcept { (k.resolved ? resolved : unresolved) = true; }
		};
		leftovers left_a;
		leftovers left_b;
		std::vector<std::pair<const ava *, const ava *>> pairs;
		std::size_t i = 0;
		std::size_t k = 0;
		while (i < ka.size() && k < kb.size()) {
			const auto order = ka[i].key <=> kb[k].key;
			if (std::is_eq(order)) {
				pairs.emplace_back(ka[i++].value, kb[k++].value);
			} else if (std::is_lt(order)) {
				left_a.add(ka[i++].key);
			} else {
				left_b.add(kb[k++].key);
			}
		}
		for (; i < ka.size(); ++i) {
			left_a.add(ka[i].key);
		}
		for (; k < kb.size(); ++k) {
			left_b.add(kb[k].key);
		}
		// A resolved type left over can only be the same type as a name left
		// over on the other side: with none there, the RDNs differ (FALSE).
		// Otherwise the types cannot be told apart or proved different.
		match_result acc = match_result::true_value;
		if (left_a.resolved || left_a.unresolved) {
			if ((left_a.resolved && !left_b.unresolved) || (left_b.resolved && !left_a.unresolved)) {
				return match_result::false_value;
			}
			acc = match_result::undefined;
		}
		for (const auto &[x, y] : pairs) {
			if (!combine(acc, ava_match(*x, *y, ctx))) {
				return acc;
			}
		}
		return acc;
	}

	auto dn_match(const dn &a, const dn &b, const dn_context &ctx) -> match_result
	{
		const auto &ra = a.rdns();
		const auto &rb = b.rdns();
		if (ra.size() != rb.size()) {
			return match_result::false_value;
		}
		match_result acc = match_result::true_value;
		for (std::size_t i = 0; i < ra.size(); ++i) {
			if (!combine(acc, rdn_match(ra[i], rb[i], ctx))) {
				return acc;
			}
		}
		return acc;
	}

	auto status_error(prep_status s) -> std::unexpected<error>
	{
		switch (s) {
		case prep_status::invalid_utf8:
			return fail(client_errc::string_prep_failed, "RFC 4518 section 2.1: the value is not valid UTF-8");
		case prep_status::prohibited:
			return fail(client_errc::string_prep_failed,
			  "RFC 4518 section 2.4: the value contains a prohibited code point (private use, non-character, "
			  "surrogate or table C.8)");
		case prep_status::unassigned:
			return fail(client_errc::string_prep_failed,
			  "RFC 4518 section 2.4: the value contains a code point unassigned in Unicode 3.2");
		case prep_status::replacement_character:
			return fail(
			  client_errc::string_prep_failed, "RFC 4518 section 2.4: the value contains U+FFFD REPLACEMENT CHARACTER");
		case prep_status::too_long:
			return fail(client_errc::string_prep_failed, "RFC 4518: the value is too long to prepare");
		case prep_status::ok:
		case prep_status::icu:
			break;
		}
		return fail(client_errc::internal_error, "RFC 4518 string preparation: ICU failed");
	}

}// namespace

// ---------------------------------------------------------------- public API

auto prepare_string(std::string_view value, const prep_options &options, std::pmr::memory_resource *mr)
  -> result<std::pmr::string>
{
	std::pmr::string out(mr);
	if (const auto s = prepare_into(value, options, out); s != prep_status::ok) {
		return status_error(s);
	}
	return out;
}

auto case_ignore_match(std::string_view attribute_value, std::string_view assertion_value) -> match_result
{
	return string_equality(case_ignore, attribute_value, assertion_value);
}

auto case_exact_match(std::string_view attribute_value, std::string_view assertion_value) -> match_result
{
	return string_equality(case_exact, attribute_value, assertion_value);
}

auto case_ignore_ia5_match(std::string_view attribute_value, std::string_view assertion_value) -> match_result
{
	return string_equality(case_ignore_ia5, attribute_value, assertion_value);
}

auto case_exact_ia5_match(std::string_view attribute_value, std::string_view assertion_value) -> match_result
{
	return string_equality(case_exact_ia5, attribute_value, assertion_value);
}

auto numeric_string_match(std::string_view attribute_value, std::string_view assertion_value) -> match_result
{
	return string_equality(numeric_string, attribute_value, assertion_value);
}

auto telephone_number_match(std::string_view attribute_value, std::string_view assertion_value) -> match_result
{
	return string_equality(telephone_number, attribute_value, assertion_value);
}

auto case_ignore_ordering_match(std::string_view attribute_value, std::string_view assertion_value) -> match_result
{
	return string_ordering(case_ignore, attribute_value, assertion_value);
}

auto case_exact_ordering_match(std::string_view attribute_value, std::string_view assertion_value) -> match_result
{
	return string_ordering(case_exact, attribute_value, assertion_value);
}

auto numeric_string_ordering_match(std::string_view attribute_value, std::string_view assertion_value) -> match_result
{
	return string_ordering(numeric_string, attribute_value, assertion_value);
}

auto case_ignore_substrings_match(std::string_view attribute_value, const substring_assertion &assertion)
  -> match_result
{
	return string_substrings(case_ignore, attribute_value, assertion);
}

auto case_exact_substrings_match(std::string_view attribute_value, const substring_assertion &assertion) -> match_result
{
	return string_substrings(case_exact, attribute_value, assertion);
}

auto case_ignore_ia5_substrings_match(std::string_view attribute_value, const substring_assertion &assertion)
  -> match_result
{
	return string_substrings(case_ignore_ia5, attribute_value, assertion);
}

auto numeric_string_substrings_match(std::string_view attribute_value, const substring_assertion &assertion)
  -> match_result
{
	return string_substrings(numeric_string, attribute_value, assertion);
}

auto telephone_number_substrings_match(std::string_view attribute_value, const substring_assertion &assertion)
  -> match_result
{
	return string_substrings(telephone_number, attribute_value, assertion);
}

auto octet_string_match(std::string_view attribute_value, std::string_view assertion_value) -> match_result
{
	return to_result(attribute_value == assertion_value);
}

auto octet_string_ordering_match(std::string_view attribute_value, std::string_view assertion_value) -> match_result
{
	// Octet by octet, most significant bit first, a prefix first (RFC 4517
	// section 4.2.28): char_traits<char> compares as unsigned char.
	return to_result(attribute_value < assertion_value);
}

auto integer_match(std::string_view attribute_value, std::string_view assertion_value) -> match_result
{
	if (!is_integer(attribute_value) || !is_integer(assertion_value)) {
		return match_result::undefined;
	}
	// The Integer syntax has one form per number.
	return to_result(attribute_value == assertion_value);
}

auto integer_ordering_match(std::string_view attribute_value, std::string_view assertion_value) -> match_result
{
	if (!is_integer(attribute_value) || !is_integer(assertion_value)) {
		return match_result::undefined;
	}
	return to_result(integer_less(attribute_value, assertion_value));
}

auto boolean_match(std::string_view attribute_value, std::string_view assertion_value) -> match_result
{
	// Boolean = "TRUE" / "FALSE" (RFC 4517 section 3.3.3): ABNF quoted
	// strings are case-insensitive (RFC 4234 section 2.3), so "true" is TRUE.
	const auto is_boolean = [](
							  std::string_view s) { return detail::iequals(s, "TRUE") || detail::iequals(s, "FALSE"); };
	if (!is_boolean(attribute_value) || !is_boolean(assertion_value)) {
		return match_result::undefined;
	}
	return to_result(detail::iequals(attribute_value, assertion_value));
}

// The rule, then the attribute value and the assertion value (RFC 4511
// MatchingRuleAssertion order).
// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
auto match(std::string_view rule, std::string_view attribute_value, std::string_view assertion_value) -> match_result
{
	const rule_entry *e = find_rule(rule);
	return e == nullptr ? match_result::undefined : e->fn(attribute_value, assertion_value);
}

auto is_known_matching_rule(std::string_view rule) noexcept -> bool { return find_rule(rule) != nullptr; }

namespace detail {

	auto distinguished_name_match(const dn &attribute_value,
	  const dn &assertion_value,
	  equality_rule_lookup lookup,
	  const void *context,
	  const server_schema *schema) -> match_result
	{
		return dn_match(
		  attribute_value, assertion_value, { .lookup = lookup, .context = context, .schema = schema, .depth = 0 });
	}

}// namespace detail

auto distinguished_name_match(const dn &attribute_value, const dn &assertion_value) -> match_result
{
	const detail::equality_rule_lookup lookup = [](const void *, const attribute &) -> std::string_view { return {}; };
	return detail::distinguished_name_match(attribute_value, assertion_value, lookup, nullptr, nullptr);
}

auto distinguished_name_match(const dn &attribute_value, const dn &assertion_value, const server_schema &schema)
  -> match_result
{
	const detail::equality_rule_lookup lookup = [](const void *context, const attribute &type) -> std::string_view {
		const auto &s = *static_cast<const server_schema *>(context);
		const attribute_type *t = s.find_attribute(type.name());
		if (t == nullptr) {
			// An RFC 4519 name the schema does not list (`userid`) is the
			// type of its OID, as for type identity (dn_context::key_of).
			if (const std::string_view oid = rfc4519_oid(type.name()); !oid.empty()) {
				t = s.find_attribute(oid);
			}
		}
		if (t == nullptr) {
			return {};
		}
		const std::string *rule = s.equality_of(*t);
		return rule == nullptr ? std::string_view{} : std::string_view{ *rule };
	};
	return detail::distinguished_name_match(attribute_value, assertion_value, lookup, &schema, &schema);
}

}// namespace jhetz::ldap
