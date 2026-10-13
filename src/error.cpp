#include "jhetz/ldap/error.hpp"

#include "jhetz/ldap/attribute.hpp"

#include "format_util.hpp"

#include <cstddef>
#include <iterator>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

namespace jhetz::ldap {
namespace {

	std::string_view result_text(int value) noexcept
	{
		switch (value) {
		case 0:
			return "success";
		case 1:
			return "operations error";
		case 2:
			return "protocol error";
		case 3:
			return "time limit exceeded";
		case 4:
			return "size limit exceeded";
		case 5:
			return "compare false";
		case 6:
			return "compare true";
		case 7:
			return "authentication method not supported";
		case 8:
			return "stronger authentication required";
		case 10:
			return "referral";
		case 11:
			return "administrative limit exceeded";
		case 12:
			return "unavailable critical extension";
		case 13:
			return "confidentiality required";
		case 14:
			return "SASL bind in progress";
		case 16:
			return "no such attribute";
		case 17:
			return "undefined attribute type";
		case 18:
			return "inappropriate matching";
		case 19:
			return "constraint violation";
		case 20:
			return "attribute or value exists";
		case 21:
			return "invalid attribute syntax";
		case 32:
			return "no such object";
		case 33:
			return "alias problem";
		case 34:
			return "invalid DN syntax";
		case 36:
			return "alias dereferencing problem";
		case 48:
			return "inappropriate authentication";
		case 49:
			return "invalid credentials";
		case 50:
			return "insufficient access rights";
		case 51:
			return "busy";
		case 52:
			return "unavailable";
		case 53:
			return "unwilling to perform";
		case 54:
			return "loop detected";
		case 64:
			return "naming violation";
		case 65:
			return "object class violation";
		case 66:
			return "not allowed on non-leaf";
		case 67:
			return "not allowed on RDN";
		case 68:
			return "entry already exists";
		case 69:
			return "object class modifications prohibited";
		case 71:
			return "affects multiple DSAs";
		case 80:
			return "other";
		case 122:
			return "assertion failed";
		default:
			return {};
		}
	}

	std::string_view client_text(int value) noexcept
	{
		switch (static_cast<client_errc>(value)) {
		case client_errc::decode_error:
			return "malformed protocol data";
		case client_errc::message_too_large:
			return "message too large";
		case client_errc::nesting_too_deep:
			return "elements nested too deeply";
		case client_errc::unsupported_tag:
			return "unsupported tag";
		case client_errc::integer_overflow:
			return "integer does not fit in 64 bits";
		case client_errc::invalid_filter:
			return "invalid search filter";
		case client_errc::missing_attribute:
			return "required attribute missing";
		case client_errc::too_many_values:
			return "too many values for a single-valued attribute";
		case client_errc::conversion_failed:
			return "value conversion failed";
		case client_errc::schema_mismatch:
			return "mapping does not match the server schema";
		case client_errc::would_deadlock:
			return "blocking call from the sync::connection's own I/O thread would deadlock";
		case client_errc::unexpected_tag:
			return "unexpected tag";
		case client_errc::unsupported_operation:
			return "unsupported LDAP operation";
		case client_errc::invalid_dn:
			return "invalid distinguished name";
		case client_errc::invalid_attribute:
			return "invalid attribute description";
		case client_errc::encode_error:
			return "value cannot be encoded in an LDAP message";
		case client_errc::invalid_url:
			return "invalid LDAP URL";
		case client_errc::unexpected_response:
			return "unexpected response from the server";
		case client_errc::not_connected:
			return "not connected";
		case client_errc::operation_in_progress:
			return "another operation is in progress on this connection";
		case client_errc::unauthenticated_bind:
			return "simple bind with a name but no password (unauthenticated bind)";
		case client_errc::tls_required:
			return "the connection must be protected by TLS";
		case client_errc::no_password_method:
			return "no known password-change method on this server";
		case client_errc::gssapi_failure:
			return "GSS-API failure";
		case client_errc::security_layer_required:
			return "the server requires a SASL security layer";
		}
		return {};
	}

	// The condition of each code (DESIGN.md section 5), nullopt for none.
	std::optional<cond> result_cond(int value) noexcept
	{
		switch (static_cast<errc>(value)) {
		case errc::no_such_object:
		case errc::no_such_attribute:
			return cond::not_found;
		case errc::invalid_credentials:
		case errc::inappropriate_authentication:
		case errc::auth_method_not_supported:
			return cond::auth_failed;
		case errc::time_limit_exceeded:
			return cond::timeout;
		case errc::protocol_error:
			return cond::protocol_error;
		case errc::busy:
		case errc::unavailable:
			return cond::busy_or_unavailable;
		case errc::insufficient_access_rights:
		case errc::stronger_auth_required:
		case errc::confidentiality_required:
			return cond::access_denied;
		case errc::entry_already_exists:
		case errc::attribute_or_value_exists:
			return cond::already_exists;
		case errc::undefined_attribute_type:
		case errc::inappropriate_matching:
		case errc::constraint_violation:
		case errc::invalid_attribute_syntax:
		case errc::invalid_dn_syntax:
		case errc::naming_violation:
		case errc::object_class_violation:
			return cond::invalid_input;
		default:
			return std::nullopt;
		}
	}

	std::optional<cond> client_cond(int value) noexcept
	{
		switch (static_cast<client_errc>(value)) {
		case client_errc::decode_error:
		case client_errc::message_too_large:
		case client_errc::nesting_too_deep:
		case client_errc::unsupported_tag:
		case client_errc::integer_overflow:
		case client_errc::unexpected_tag:
		case client_errc::unsupported_operation:
		case client_errc::unexpected_response:
			return cond::protocol_error;
		case client_errc::invalid_filter:
		case client_errc::invalid_dn:
		case client_errc::invalid_attribute:
		case client_errc::encode_error:
		case client_errc::invalid_url:
			return cond::invalid_input;
		case client_errc::not_connected:
			return cond::connection_lost;
		case client_errc::unauthenticated_bind:
		case client_errc::gssapi_failure:
			return cond::auth_failed;
		case client_errc::tls_required:
		case client_errc::security_layer_required:
			return cond::access_denied;
		default:
			return std::nullopt;
		}
	}

	// Codes of other categories: by generic condition, or by category name
	// for Capy and Corosio (this library does not link them).
	std::optional<cond> foreign_cond(const std::error_code &ec) noexcept
	{
		const std::string_view category = ec.category().name();
		if (category == "boost.capy") {
			// boost::capy::error: eof = 1, stream_truncated = 4 (canceled and
			// timeout map to generic conditions, below).
			if (ec.value() == 1 || ec.value() == 4) return cond::connection_lost;
		}
		if (category == "corosio.openssl" || category == "corosio.wolfssl") return cond::tls_failure;

		const std::error_condition g = ec.default_error_condition();
		if (g.category() != std::generic_category()) return std::nullopt;
		switch (static_cast<std::errc>(g.value())) {
		case std::errc::timed_out:
			return cond::timeout;
		case std::errc::operation_canceled:
			return cond::canceled;
		case std::errc::connection_reset:
		case std::errc::connection_aborted:
		case std::errc::broken_pipe:
		case std::errc::not_connected:
			return cond::connection_lost;
		case std::errc::connection_refused:
		case std::errc::host_unreachable:
		case std::errc::network_unreachable:
		case std::errc::network_down:
			return cond::busy_or_unavailable;
		case std::errc::permission_denied:
			return cond::access_denied;
		// Configuration problems (a missing CA file, a bad PEM): not
		// not_found, which callers use for directory entries.
		case std::errc::no_such_file_or_directory:
		case std::errc::not_a_directory:
		case std::errc::filename_too_long:
		case std::errc::invalid_argument:
			return cond::invalid_input;
		default:
			return std::nullopt;
		}
	}

	std::string_view cond_text(int value) noexcept
	{
		switch (static_cast<cond>(value)) {
		case cond::not_found:
			return "not found";
		case cond::auth_failed:
			return "authentication failed";
		case cond::timeout:
			return "timed out";
		case cond::canceled:
			return "canceled";
		case cond::connection_lost:
			return "connection lost";
		case cond::tls_failure:
			return "TLS failure";
		case cond::protocol_error:
			return "protocol error";
		case cond::busy_or_unavailable:
			return "server busy or unavailable";
		case cond::access_denied:
			return "access denied";
		case cond::already_exists:
			return "already exists";
		case cond::invalid_input:
			return "invalid input";
		}
		return {};
	}

	class result_category_impl final : public std::error_category
	{
	  public:
		const char *name() const noexcept override { return "ldap.result"; }

		std::string message(int value) const override
		{
			auto text = result_text(value);
			if (text.empty()) return detail::format("unknown LDAP result code {}", value);
			return std::string(text);
		}
	};

	class client_category_impl final : public std::error_category
	{
	  public:
		const char *name() const noexcept override { return "ldap.client"; }

		std::string message(int value) const override
		{
			auto text = client_text(value);
			if (text.empty()) return detail::format("unknown LDAP client error {}", value);
			return std::string(text);
		}
	};

	class cond_category_impl final : public std::error_category
	{
	  public:
		const char *name() const noexcept override { return "ldap.cond"; }

		std::string message(int value) const override
		{
			auto text = cond_text(value);
			if (text.empty()) return detail::format("unknown LDAP error condition {}", value);
			return std::string(text);
		}

		bool equivalent(const std::error_code &ec, int condition) const noexcept override
		{
			std::optional<cond> c;
			if (ec.category() == result_category())
				c = result_cond(ec.value());
			else if (ec.category() == client_category())
				c = client_cond(ec.value());
			else
				c = foreign_cond(ec);
			return c && std::to_underlying(*c) == condition;
		}
	};

}// namespace

const std::error_category &result_category() noexcept
{
	static const result_category_impl instance;
	return instance;
}

const std::error_category &client_category() noexcept
{
	static const client_category_impl instance;
	return instance;
}

const std::error_category &cond_category() noexcept
{
	static const cond_category_impl instance;
	return instance;
}

namespace detail {

	std::string vformat(std::string_view fmt, std::format_args args) { return std::vformat(fmt, args); }

	void vformat_to(std::string &out, std::string_view fmt, std::format_args args)
	{
		std::vformat_to(std::back_inserter(out), fmt, args);
	}

	namespace {

		// The code point of a well-formed UTF-8 sequence.
		constexpr char32_t code_point(std::string_view seq) noexcept
		{
			const auto b = [&](std::size_t k) { return char32_t{ static_cast<unsigned char>(seq[k]) }; };
			switch (seq.size()) {
			case 1:
				return b(0);
			case 2:
				return (b(0) & 0x1Fu) << 6 | (b(1) & 0x3Fu);
			case 3:
				return (b(0) & 0x0Fu) << 12 | (b(1) & 0x3Fu) << 6 | (b(2) & 0x3Fu);
			default:
				return (b(0) & 0x07u) << 18 | (b(1) & 0x3Fu) << 12 | (b(2) & 0x3Fu) << 6 | (b(3) & 0x3Fu);
			}
		}

		// C0, DEL, C1, Bidi_Control and U+2028/U+2029 (append_sanitized).
		constexpr bool replaced(char32_t c) noexcept
		{
			return c < 0x20 || (c >= 0x7F && c < 0xA0) || c == 0x061C || c == 0x200E || c == 0x200F
				   || (c >= 0x2028 && c <= 0x202E)// U+2028, U+2029, U+202A-U+202E
				   || (c >= 0x2066 && c <= 0x2069);
		}

		template<class String> void append_sanitized_to(String &out, std::string_view s, std::size_t max_bytes)
		{
			constexpr std::string_view replacement = "\xEF\xBF\xBD";// U+FFFD
			std::size_t i = 0;
			while (i < s.size()) {
				const auto [n, well_formed] = utf8_sequence_at(s, i);
				if (n > max_bytes - i) break;// i <= max_bytes here
				const std::string_view seq = s.substr(i, n);
				if (!well_formed || replaced(code_point(seq)))
					out += replacement;
				else
					out += seq;
				i += n;
			}
			if (i < s.size()) out += "...";
		}

	}// namespace

	void append_sanitized(std::string &out, std::string_view s, std::size_t max_bytes)
	{
		append_sanitized_to(out, s, max_bytes);
	}

	void append_sanitized(std::pmr::string &out, std::string_view s, std::size_t max_bytes)
	{
		append_sanitized_to(out, s, max_bytes);
	}

}// namespace detail

std::pmr::string error::message(std::pmr::memory_resource *mr) const
{
	// "<context>: <code message> [<category>:<value>]; server: ...; matched DN: ...; referrals: ..."
	// The server's text is sanitized and cut (error.hpp).
	constexpr std::size_t max_shown = 256;// bytes of each server string
	constexpr std::size_t max_referrals = 8;
	std::pmr::string out(mr);
	if (!context.empty()) {
		out += context;
		out += ": ";
	}
	out += code.message();
	out += " [";
	out += code.category().name();
	out += ':';
	out += std::to_string(code.value());
	out += ']';
	if (!diagnostic.empty()) {
		out += "; server: ";
		detail::append_sanitized(out, diagnostic, max_shown);
	}
	if (matched_dn && !matched_dn->empty()) {
		out += "; matched DN: ";
		detail::append_sanitized(out, *matched_dn, max_shown);
	}
	if (!referrals.empty()) {
		out += "; referrals:";
		for (std::size_t i = 0; i < referrals.size() && i < max_referrals; ++i) {
			out += ' ';
			detail::append_sanitized(out, referrals[i], max_shown);
		}
		if (referrals.size() > max_referrals) {
			out += " (and ";
			out += std::to_string(referrals.size() - max_referrals);
			out += " more)";
		}
	}
	return out;
}

}// namespace jhetz::ldap
