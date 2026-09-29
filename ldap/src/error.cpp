#include "jhetz/ldap/error.hpp"

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

std::string error::message() const
{
	// "<context>: <code message> [<category>:<value>]; server: ...; matched DN: ...; referrals: ..."
	std::string out;
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
