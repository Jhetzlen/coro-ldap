#include "jhetz/ldap/mapping.hpp"

#include "format_util.hpp"
#include "generalized_time.hpp"

#include <string>

namespace jhetz::ldap {

namespace detail {

	auto conversion_error(std::string_view what, std::string_view raw) -> error
	{
		std::string text = detail::format("{}: \"", what);
		detail::append_sanitized(text, raw, 64);
		text += '"';
		return make_error(client_errc::conversion_failed, text);
	}

	auto utf8_conversion_error(std::size_t offset) -> error
	{
		return make_error(
		  client_errc::conversion_failed, detail::format("not valid UTF-8 (ill-formed sequence at offset {})", offset));
	}

	auto utf8_encode_error(std::size_t offset) -> error
	{
		return make_error(
		  client_errc::encode_error, detail::format("not valid UTF-8 (ill-formed sequence at offset {})", offset));
	}

	auto enum_encode_error(std::intmax_t value) -> error
	{
		return make_error(client_errc::encode_error, detail::format("value {} is not in ldap::enum_names", value));
	}

	auto change_context(modify_operation op, std::string_view attribute) -> std::string
	{
		// The RFC 4511 section 4.6 operation names.
		std::string_view name;
		switch (op) {
		case modify_operation::add:
			name = "add";
			break;
		case modify_operation::delete_:
			name = "delete";
			break;
		case modify_operation::replace:
			name = "replace";
			break;
		case modify_operation::increment:
			name = "increment";
			break;
		}
		return detail::format("{} {}", name, attribute);
	}

	// A swap only garbles the context of a diagnostic; one caller (mapping.hpp).
	// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
	auto entry_context(std::string_view dn, std::string_view attribute) -> std::string
	{
		// The DN is the server's text.
		std::string text = "entry ";
		if (dn.empty()) {
			text += "\"\"";
		} else {
			detail::append_sanitized(text, dn, 256);
		}
		detail::format_to(text, ": attribute {}", attribute);
		return text;
	}

}// namespace detail

auto value_traits<dn>::decode(std::string_view raw) -> result<dn>
{
	return dn::parse(raw).transform_error(
	  [raw](const error &) { return detail::conversion_error("not a distinguished name", raw); });
}

// ---------------------------------------------------------------- GeneralizedTime

namespace {

	using namespace std::chrono;

	// GeneralizedTime's field limits (RFC 4517 section 3.3.13); 60 is a leap
	// second.
	constexpr int max_year = 9999;
	constexpr int max_month = 12;
	constexpr int max_hour = 23;
	constexpr int max_minute = 59;
	constexpr int max_second = 60;

	// Reads `n` digits at `pos`; nullopt if they are not all digits.
	auto digits(std::string_view s, std::size_t &pos, std::size_t n) -> std::optional<int>
	{
		if (s.size() - pos < n) {
			return std::nullopt;
		}
		int v = 0;
		for (std::size_t i = 0; i < n; ++i) {
			const char c = s[pos + i];
			if (c < '0' || c > '9') {
				return std::nullopt;
			}
			v = (v * 10) + (c - '0');
		}
		pos += n;
		return v;
	}

	auto next_is_digit(std::string_view s, std::size_t pos) -> bool
	{
		return pos < s.size() && s[pos] >= '0' && s[pos] <= '9';
	}

	// The fraction's digits starting at `pos` (after '.' or ','). The error
	// is the reason for parse_generalized_time.
	auto read_fraction(std::string_view text, std::size_t &pos) -> std::expected<std::string_view, const char *>
	{
		const std::size_t start = pos;
		while (next_is_digit(text, pos)) {
			++pos;
		}
		if (pos == start) {
			return std::unexpected("fraction");
		}
		return text.substr(start, pos - start);
	}

	// g-time-zone at `pos`: "Z" or a differential (+|-)HH[MM], as the offset
	// from UTC. The error is the reason for parse_generalized_time.
	auto read_time_zone(std::string_view text, std::size_t &pos) -> std::expected<minutes, const char *>
	{
		if (pos >= text.size()) {
			return std::unexpected("time zone missing");
		}
		if (text[pos] == 'Z') {
			++pos;
			return minutes{ 0 };
		}
		if (text[pos] != '+' && text[pos] != '-') {
			return std::unexpected("time zone");
		}
		const int sign = text[pos] == '-' ? -1 : 1;
		++pos;
		const auto oh = digits(text, pos, 2);
		if (!oh || *oh > max_hour) {
			return std::unexpected("time zone hour");
		}
		int om = 0;
		if (next_is_digit(text, pos)) {
			const auto m = digits(text, pos, 2);
			if (!m || *m > max_minute) {
				return std::unexpected("time zone minute");
			}
			om = *m;
		}
		return sign * (hours(*oh) + minutes(om));
	}

	// `fraction` (decimal digits) of `unit`, truncated to whole seconds;
	// digits past nanoseconds are ignored.
	auto fraction_seconds(std::string_view fraction, seconds unit) -> seconds
	{
		std::int64_t num = 0;
		std::int64_t den = 1;
		for (const char c : fraction) {
			if (den >= std::nano::den) {// enough precision; the rest is truncated
				break;
			}
			num = (num * 10) + (c - '0');
			den *= 10;
		}
		return seconds(unit.count() * num / den);
	}

}// namespace

namespace detail {

	auto parse_generalized_time_fields(std::string_view text) -> std::expected<generalized_time_fields, const char *>
	{
		std::size_t pos = 0;
		const auto year = digits(text, pos, 4);
		const auto month = digits(text, pos, 2);
		const auto day = digits(text, pos, 2);
		const auto hour = digits(text, pos, 2);
		if (!year || !month || !day || !hour) {
			return std::unexpected("date and hour");
		}
		generalized_time_fields f{ .hour = *hour };
		if (next_is_digit(text, pos)) {
			f.minute = digits(text, pos, 2);
			if (!f.minute) {
				return std::unexpected("minute");
			}
			if (next_is_digit(text, pos)) {
				f.second = digits(text, pos, 2);
				if (!f.second) {
					return std::unexpected("second");
				}
			}
		}
		if (pos < text.size() && (text[pos] == '.' || text[pos] == ',')) {
			++pos;
			const auto digits_read = read_fraction(text, pos);
			if (!digits_read) {
				return std::unexpected(digits_read.error());
			}
			f.fraction = *digits_read;
		}
		if (*month < 1 || *month > max_month || *hour > max_hour || (f.minute && *f.minute > max_minute)
			|| (f.second && *f.second > max_second)) {
			return std::unexpected("field out of range");
		}
		f.date = year_month_day{ std::chrono::year(*year),
			std::chrono::month(static_cast<unsigned>(*month)),
			std::chrono::day(static_cast<unsigned>(*day)) };
		if (!f.date.ok()) {
			return std::unexpected("no such date");
		}
		const auto offset = read_time_zone(text, pos);
		if (!offset) {
			return std::unexpected(offset.error());
		}
		f.offset = *offset;
		if (pos != text.size()) {
			return std::unexpected("trailing characters");
		}
		return f;
	}

}// namespace detail

auto parse_generalized_time(std::string_view text) -> result<sys_seconds>
{
	const auto f = detail::parse_generalized_time_fields(text);
	if (!f) {
		return std::unexpected(detail::conversion_error(detail::format("not a GeneralizedTime ({})", f.error()), text));
	}
	// A fraction applies to the last unit given (hour, minute or second).
	seconds unit = hours(1);
	if (f->second) {
		unit = seconds(1);
	} else if (f->minute) {
		unit = minutes(1);
	}
	// A leap second (60) rolls into the next minute: sys_seconds has no 23:59:60.
	const sys_seconds local = sys_days(f->date) + hours(f->hour) + minutes(f->minute.value_or(0))
							  + seconds(f->second.value_or(0)) + fraction_seconds(f->fraction, unit);
	return local - f->offset;
}

auto format_generalized_time(sys_seconds t) -> result<std::string>
{
	const sys_days day = floor<days>(t);
	const year_month_day ymd(day);
	const int y = static_cast<int>(ymd.year());
	if (y < 0 || y > max_year) {
		return fail(client_errc::encode_error, detail::format("GeneralizedTime: year {} outside 0000-9999", y));
	}
	// Plain integers rather than the chrono formatter ("{:%Y%m%d%H%M%S}Z"),
	// which costs this file seconds of compile time for the same output.
	const hh_mm_ss hms(t - day);
	return detail::format("{:04}{:02}{:02}{:02}{:02}{:02}Z",
	  y,
	  static_cast<unsigned>(ymd.month()),
	  static_cast<unsigned>(ymd.day()),
	  hms.hours().count(),
	  hms.minutes().count(),
	  hms.seconds().count());
}

}// namespace jhetz::ldap
