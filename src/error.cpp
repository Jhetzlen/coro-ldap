#include "jhetz/ldap/error.hpp"

#include "jhetz/ldap/attribute.hpp"

#include "format_util.hpp"
#include "icu_util.hpp"

#include <unicode/uchar.h>

#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

namespace jhetz::ldap {
namespace {

	auto result_text(int value) noexcept -> std::string_view
	{
		if (value == 0) {
			return "success";
		}
		switch (static_cast<errc>(value)) {
		case errc::operations_error:
			return "operations error";
		case errc::protocol_error:
			return "protocol error";
		case errc::time_limit_exceeded:
			return "time limit exceeded";
		case errc::size_limit_exceeded:
			return "size limit exceeded";
		case errc::compare_false:
			return "compare false";
		case errc::compare_true:
			return "compare true";
		case errc::auth_method_not_supported:
			return "authentication method not supported";
		case errc::stronger_auth_required:
			return "stronger authentication required";
		case errc::referral:
			return "referral";
		case errc::admin_limit_exceeded:
			return "administrative limit exceeded";
		case errc::unavailable_critical_extension:
			return "unavailable critical extension";
		case errc::confidentiality_required:
			return "confidentiality required";
		case errc::sasl_bind_in_progress:
			return "SASL bind in progress";
		case errc::no_such_attribute:
			return "no such attribute";
		case errc::undefined_attribute_type:
			return "undefined attribute type";
		case errc::inappropriate_matching:
			return "inappropriate matching";
		case errc::constraint_violation:
			return "constraint violation";
		case errc::attribute_or_value_exists:
			return "attribute or value exists";
		case errc::invalid_attribute_syntax:
			return "invalid attribute syntax";
		case errc::no_such_object:
			return "no such object";
		case errc::alias_problem:
			return "alias problem";
		case errc::invalid_dn_syntax:
			return "invalid DN syntax";
		case errc::alias_dereferencing_problem:
			return "alias dereferencing problem";
		case errc::inappropriate_authentication:
			return "inappropriate authentication";
		case errc::invalid_credentials:
			return "invalid credentials";
		case errc::insufficient_access_rights:
			return "insufficient access rights";
		case errc::busy:
			return "busy";
		case errc::unavailable:
			return "unavailable";
		case errc::unwilling_to_perform:
			return "unwilling to perform";
		case errc::loop_detect:
			return "loop detected";
		case errc::naming_violation:
			return "naming violation";
		case errc::object_class_violation:
			return "object class violation";
		case errc::not_allowed_on_non_leaf:
			return "not allowed on non-leaf";
		case errc::not_allowed_on_rdn:
			return "not allowed on RDN";
		case errc::entry_already_exists:
			return "entry already exists";
		case errc::object_class_mods_prohibited:
			return "object class modifications prohibited";
		case errc::affects_multiple_dsas:
			return "affects multiple DSAs";
		case errc::other:
			return "other";
		case errc::assertion_failed:
			return "assertion failed";
		case errc::e_sync_refresh_required:
			return "content synchronization refresh required";
		default:
			return {};
		}
	}

	auto client_text(int value) noexcept -> std::string_view
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
		case client_errc::internal_error:
			return "a library the client uses failed";
		case client_errc::string_prep_failed:
			return "string preparation (RFC 4518) failed";
		}
		return {};
	}

	// The condition of each code (DESIGN.md section 5), nullopt for none.
	auto result_cond(int value) noexcept -> std::optional<cond>
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

	auto client_cond(int value) noexcept -> std::optional<cond>
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
		case client_errc::string_prep_failed:
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
	auto foreign_cond(const std::error_code &ec) noexcept -> std::optional<cond>
	{
		const std::string_view category = ec.category().name();
		// boost::capy::error: eof = 1, stream_truncated = 4 (canceled and
		// timeout map to generic conditions, below).
		if (category == "boost.capy" && (ec.value() == 1 || ec.value() == 4)) {
			return cond::connection_lost;
		}
		if (category == "corosio.openssl" || category == "corosio.wolfssl") {
			return cond::tls_failure;
		}

		const std::error_condition g = ec.default_error_condition();
		if (g.category() != std::generic_category()) {
			return std::nullopt;
		}
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

	auto cond_text(int value) noexcept -> std::string_view
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
		[[nodiscard]] auto name() const noexcept -> const char * override { return "ldap.result"; }

		[[nodiscard]] auto message(int value) const -> std::string override
		{
			const auto text = result_text(value);
			if (text.empty()) {
				return detail::format("unknown LDAP result code {}", value);
			}
			return std::string(text);
		}
	};

	class client_category_impl final : public std::error_category
	{
	  public:
		[[nodiscard]] auto name() const noexcept -> const char * override { return "ldap.client"; }

		[[nodiscard]] auto message(int value) const -> std::string override
		{
			const auto text = client_text(value);
			if (text.empty()) {
				return detail::format("unknown LDAP client error {}", value);
			}
			return std::string(text);
		}
	};

	class cond_category_impl final : public std::error_category
	{
	  public:
		[[nodiscard]] auto name() const noexcept -> const char * override { return "ldap.cond"; }

		[[nodiscard]] auto message(int value) const -> std::string override
		{
			const auto text = cond_text(value);
			if (text.empty()) {
				return detail::format("unknown LDAP error condition {}", value);
			}
			return std::string(text);
		}

		[[nodiscard]] auto equivalent(const std::error_code &ec, int condition) const noexcept -> bool override
		{
			std::optional<cond> c;
			if (ec.category() == result_category()) {
				c = result_cond(ec.value());
			} else if (ec.category() == client_category()) {
				c = client_cond(ec.value());
			} else {
				c = foreign_cond(ec);
			}
			return c && std::to_underlying(*c) == condition;
		}
	};

}// namespace

auto result_category() noexcept -> const std::error_category &
{
	static const result_category_impl instance;
	return instance;
}

auto client_category() noexcept -> const std::error_category &
{
	static const client_category_impl instance;
	return instance;
}

auto cond_category() noexcept -> const std::error_category &
{
	static const cond_category_impl instance;
	return instance;
}

namespace detail {

	namespace {

		// What append_sanitized replaces besides ill-formed UTF-8: control
		// characters (General_Category Cc: C0, DEL, C1), Bidi_Control, and
		// LINE / PARAGRAPH SEPARATOR (the only characters of Zl and Zp).
		auto replaced(UChar32 c) noexcept -> bool
		{
			const auto type = static_cast<UCharCategory>(u_charType(c));
			return type == U_CONTROL_CHAR || type == U_LINE_SEPARATOR || type == U_PARAGRAPH_SEPARATOR
				   || u_hasBinaryProperty(c, UCHAR_BIDI_CONTROL) != 0;
		}

		template<class String> void append_sanitized_to(String &out, std::string_view s, std::size_t max_bytes)
		{
			constexpr std::string_view replacement = "\xEF\xBF\xBD";// U+FFFD
			std::size_t i = 0;
			while (i < s.size()) {
				const auto [c, n] = utf8_next(s, i);
				if (n > max_bytes - i) {
					break;// i <= max_bytes here
				}
				if (c < 0 || replaced(c)) {
					out += replacement;
				} else {
					out += s.substr(i, n);
				}
				i += n;
			}
			if (i < s.size()) {
				out += "...";
			}
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

auto error::message(std::pmr::memory_resource *mr) const -> std::pmr::string
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
