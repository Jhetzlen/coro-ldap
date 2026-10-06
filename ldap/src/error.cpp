#include "jhetz/ldap/error.hpp"

#include <optional>
#include <string>
#include <string_view>

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
			return "blocking call from the client's own I/O thread would deadlock";
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
			return cond::auth_failed;
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
			if (text.empty()) return "unknown LDAP result code " + std::to_string(value);
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
			if (text.empty()) return "unknown LDAP client error " + std::to_string(value);
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
			if (text.empty()) return "unknown LDAP error condition " + std::to_string(value);
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
			return c && static_cast<int>(*c) == condition;
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

std::pmr::string error::message(std::pmr::memory_resource *mr) const
{
	// "<context>: <code message> [<category>:<value>]; server: ...; matched DN: ...; referrals: ..."
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
		out += diagnostic;
	}
	if (matched_dn && !matched_dn->empty()) {
		out += "; matched DN: ";
		out += *matched_dn;
	}
	if (!referrals.empty()) {
		out += "; referrals:";
		for (const auto &r : referrals) {
			out += ' ';
			out += r;
		}
	}
	return out;
}

}// namespace jhetz::ldap
