#include "jhetz/ldap/mapping.hpp"

#include "format_util.hpp"

#include <stdexcept>
#include <string>

namespace jhetz::ldap {

namespace detail {

	error conversion_error(std::string_view what, std::string_view raw)
	{
		std::string text = detail::format("{}: \"", what);
		detail::append_sanitized(text, raw, 64);
		text += '"';
		return make_error(client_errc::conversion_failed, text);
	}

	error with_context(error e, std::string_view prefix)
	{
		if (e.context.empty()) {
			e.context.assign(prefix);
		} else {
			e.context.insert(0, ": ");
			e.context.insert(0, prefix);
		}
		return e;
	}

	std::string entry_context(std::string_view dn, std::string_view attribute)
	{
		// The DN is the server's text.
		std::string text = "entry ";
		if (dn.empty())
			text += "\"\"";
		else
			detail::append_sanitized(text, dn, 256);
		detail::format_to(text, ": attribute {}", attribute);
		return text;
	}

}// namespace detail

result<dn> value_traits<dn>::decode(std::string_view raw)
{
	return dn::parse(raw).transform_error(
	  [raw](const error &) { return detail::conversion_error("not a distinguished name", raw); });
}

// ---------------------------------------------------------------- GeneralizedTime

namespace {

	using namespace std::chrono;

	// Reads `n` digits at `pos`; nullopt if they are not all digits.
	std::optional<int> digits(std::string_view s, std::size_t &pos, std::size_t n)
	{
		if (s.size() - pos < n) return std::nullopt;
		int v = 0;
		for (std::size_t i = 0; i < n; ++i) {
			const char c = s[pos + i];
			if (c < '0' || c > '9') return std::nullopt;
			v = v * 10 + (c - '0');
		}
		pos += n;
		return v;
	}

	bool next_is_digit(std::string_view s, std::size_t pos) { return pos < s.size() && s[pos] >= '0' && s[pos] <= '9'; }

}// namespace

result<sys_seconds> parse_generalized_time(std::string_view s)
{
	auto bad = [&](const char *why) {
		return std::unexpected(detail::conversion_error(detail::format("not a GeneralizedTime ({})", why), s));
	};
	std::size_t pos = 0;
	const auto year = digits(s, pos, 4);
	const auto month = digits(s, pos, 2);
	const auto day = digits(s, pos, 2);
	const auto hour = digits(s, pos, 2);
	if (!year || !month || !day || !hour) return bad("date and hour");
	std::optional<int> minute, second;
	if (next_is_digit(s, pos)) {
		minute = digits(s, pos, 2);
		if (!minute) return bad("minute");
		if (next_is_digit(s, pos)) {
			second = digits(s, pos, 2);
			if (!second) return bad("second");
		}
	}
	// A fraction applies to the last unit given (hour, minute or second).
	seconds fraction{ 0 };
	if (pos < s.size() && (s[pos] == '.' || s[pos] == ',')) {
		++pos;
		if (!next_is_digit(s, pos)) return bad("fraction");
		const seconds unit = second ? seconds(1) : minute ? seconds(60) : seconds(3600);
		std::int64_t num = 0, den = 1;
		while (next_is_digit(s, pos)) {
			if (den < 1'000'000'000) {// enough precision; the rest is truncated
				num = num * 10 + (s[pos] - '0');
				den *= 10;
			}
			++pos;
		}
		fraction = seconds(unit.count() * num / den);
	}
	if (*month < 1 || *month > 12 || *hour > 23 || (minute && *minute > 59) || (second && *second > 60))
		return bad("field out of range");
	const year_month_day ymd{ std::chrono::year(*year),
		std::chrono::month(static_cast<unsigned>(*month)),
		std::chrono::day(static_cast<unsigned>(*day)) };
	if (!ymd.ok()) return bad("no such date");

	// g-time-zone: "Z" or a differential (+|-)HH[MM].
	if (pos >= s.size()) return bad("time zone missing");
	seconds offset{ 0 };
	if (s[pos] == 'Z') {
		++pos;
	} else if (s[pos] == '+' || s[pos] == '-') {
		const int sign = s[pos] == '-' ? -1 : 1;
		++pos;
		const auto oh = digits(s, pos, 2);
		if (!oh || *oh > 23) return bad("time zone hour");
		int om = 0;
		if (next_is_digit(s, pos)) {
			const auto m = digits(s, pos, 2);
			if (!m || *m > 59) return bad("time zone minute");
			om = *m;
		}
		offset = seconds(sign * (*oh * 3600 + om * 60));
	} else {
		return bad("time zone");
	}
	if (pos != s.size()) return bad("trailing characters");

	// A leap second (60) rolls into the next minute: sys_seconds has no 23:59:60.
	const sys_seconds local =
	  sys_days(ymd) + hours(*hour) + minutes(minute.value_or(0)) + seconds(second.value_or(0)) + fraction;
	return local - offset;
}

result<std::string> format_generalized_time(sys_seconds t)
{
	const sys_days day = floor<days>(t);
	const year_month_day ymd(day);
	const int y = static_cast<int>(ymd.year());
	if (y < 0 || y > 9999)
		return fail(client_errc::encode_error, detail::format("GeneralizedTime: year {} outside 0000-9999", y));
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

std::string value_traits<sys_seconds>::encode(sys_seconds v)
{
	auto s = format_generalized_time(v);
	if (!s) throw std::out_of_range(std::string(s.error().message()));
	return std::move(*s);
}

}// namespace jhetz::ldap
