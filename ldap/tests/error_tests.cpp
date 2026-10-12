#include "jhetz/ldap/error.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cerrno>
#include <cstddef>
#include <iterator>
#include <optional>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

namespace ldap = jhetz::ldap;

// All 38 non-success resultCodes of RFC 4511 section 4.1.9 / Appendix A, plus
// assertionFailed (122, RFC 4528).
TEST_CASE("ldap::errc keeps RFC 4511 resultCode numbers", "[error]")
{
	STATIC_REQUIRE(std::to_underlying(ldap::errc::operations_error) == 1);
	STATIC_REQUIRE(std::to_underlying(ldap::errc::protocol_error) == 2);
	STATIC_REQUIRE(std::to_underlying(ldap::errc::time_limit_exceeded) == 3);
	STATIC_REQUIRE(std::to_underlying(ldap::errc::size_limit_exceeded) == 4);
	STATIC_REQUIRE(std::to_underlying(ldap::errc::compare_false) == 5);
	STATIC_REQUIRE(std::to_underlying(ldap::errc::compare_true) == 6);
	STATIC_REQUIRE(std::to_underlying(ldap::errc::auth_method_not_supported) == 7);
	STATIC_REQUIRE(std::to_underlying(ldap::errc::stronger_auth_required) == 8);
	STATIC_REQUIRE(std::to_underlying(ldap::errc::referral) == 10);
	STATIC_REQUIRE(std::to_underlying(ldap::errc::admin_limit_exceeded) == 11);
	STATIC_REQUIRE(std::to_underlying(ldap::errc::unavailable_critical_extension) == 12);
	STATIC_REQUIRE(std::to_underlying(ldap::errc::confidentiality_required) == 13);
	STATIC_REQUIRE(std::to_underlying(ldap::errc::sasl_bind_in_progress) == 14);
	STATIC_REQUIRE(std::to_underlying(ldap::errc::no_such_attribute) == 16);
	STATIC_REQUIRE(std::to_underlying(ldap::errc::undefined_attribute_type) == 17);
	STATIC_REQUIRE(std::to_underlying(ldap::errc::inappropriate_matching) == 18);
	STATIC_REQUIRE(std::to_underlying(ldap::errc::constraint_violation) == 19);
	STATIC_REQUIRE(std::to_underlying(ldap::errc::attribute_or_value_exists) == 20);
	STATIC_REQUIRE(std::to_underlying(ldap::errc::invalid_attribute_syntax) == 21);
	STATIC_REQUIRE(std::to_underlying(ldap::errc::no_such_object) == 32);
	STATIC_REQUIRE(std::to_underlying(ldap::errc::alias_problem) == 33);
	STATIC_REQUIRE(std::to_underlying(ldap::errc::invalid_dn_syntax) == 34);
	STATIC_REQUIRE(std::to_underlying(ldap::errc::alias_dereferencing_problem) == 36);
	STATIC_REQUIRE(std::to_underlying(ldap::errc::inappropriate_authentication) == 48);
	STATIC_REQUIRE(std::to_underlying(ldap::errc::invalid_credentials) == 49);
	STATIC_REQUIRE(std::to_underlying(ldap::errc::insufficient_access_rights) == 50);
	STATIC_REQUIRE(std::to_underlying(ldap::errc::busy) == 51);
	STATIC_REQUIRE(std::to_underlying(ldap::errc::unavailable) == 52);
	STATIC_REQUIRE(std::to_underlying(ldap::errc::unwilling_to_perform) == 53);
	STATIC_REQUIRE(std::to_underlying(ldap::errc::loop_detect) == 54);
	STATIC_REQUIRE(std::to_underlying(ldap::errc::naming_violation) == 64);
	STATIC_REQUIRE(std::to_underlying(ldap::errc::object_class_violation) == 65);
	STATIC_REQUIRE(std::to_underlying(ldap::errc::not_allowed_on_non_leaf) == 66);
	STATIC_REQUIRE(std::to_underlying(ldap::errc::not_allowed_on_rdn) == 67);
	STATIC_REQUIRE(std::to_underlying(ldap::errc::entry_already_exists) == 68);
	STATIC_REQUIRE(std::to_underlying(ldap::errc::object_class_mods_prohibited) == 69);
	STATIC_REQUIRE(std::to_underlying(ldap::errc::affects_multiple_dsas) == 71);
	STATIC_REQUIRE(std::to_underlying(ldap::errc::other) == 80);
	STATIC_REQUIRE(std::to_underlying(ldap::errc::assertion_failed) == 122);
}

TEST_CASE("every errc and client_errc has a real message", "[error]")
{
	constexpr ldap::errc all[] = {
		ldap::errc::operations_error,
		ldap::errc::protocol_error,
		ldap::errc::time_limit_exceeded,
		ldap::errc::size_limit_exceeded,
		ldap::errc::compare_false,
		ldap::errc::compare_true,
		ldap::errc::auth_method_not_supported,
		ldap::errc::stronger_auth_required,
		ldap::errc::referral,
		ldap::errc::admin_limit_exceeded,
		ldap::errc::unavailable_critical_extension,
		ldap::errc::confidentiality_required,
		ldap::errc::sasl_bind_in_progress,
		ldap::errc::no_such_attribute,
		ldap::errc::undefined_attribute_type,
		ldap::errc::inappropriate_matching,
		ldap::errc::constraint_violation,
		ldap::errc::attribute_or_value_exists,
		ldap::errc::invalid_attribute_syntax,
		ldap::errc::no_such_object,
		ldap::errc::alias_problem,
		ldap::errc::invalid_dn_syntax,
		ldap::errc::alias_dereferencing_problem,
		ldap::errc::inappropriate_authentication,
		ldap::errc::invalid_credentials,
		ldap::errc::insufficient_access_rights,
		ldap::errc::busy,
		ldap::errc::unavailable,
		ldap::errc::unwilling_to_perform,
		ldap::errc::loop_detect,
		ldap::errc::naming_violation,
		ldap::errc::object_class_violation,
		ldap::errc::not_allowed_on_non_leaf,
		ldap::errc::not_allowed_on_rdn,
		ldap::errc::entry_already_exists,
		ldap::errc::object_class_mods_prohibited,
		ldap::errc::affects_multiple_dsas,
		ldap::errc::other,
		ldap::errc::assertion_failed,
	};
	STATIC_REQUIRE(std::size(all) == 39);
	for (auto e : all) {
		const auto text = std::error_code(e).message();
		INFO("errc " << std::to_underlying(e) << ": " << text);
		CHECK_FALSE(text.empty());
		CHECK_FALSE(text.contains("unknown"));
	}
	for (int v = 1; v <= std::to_underlying(ldap::client_errc::unauthenticated_bind); ++v) {
		const auto text = std::error_code(static_cast<ldap::client_errc>(v)).message();
		INFO("client_errc " << v << ": " << text);
		CHECK_FALSE(text.empty());
		CHECK_FALSE(text.contains("unknown"));
	}
}

TEST_CASE("ldap error categories", "[error]")
{
	std::error_code rc = ldap::errc::invalid_credentials;
	CHECK(rc.value() == 49);
	CHECK(std::string(rc.category().name()) == "ldap.result");
	CHECK(rc.message() == "invalid credentials");
	CHECK(std::error_code(ldap::errc::no_such_object).message() == "no such object");
	CHECK(ldap::result_category().message(0) == "success");
	CHECK(ldap::result_category().message(9) == "unknown LDAP result code 9");

	std::error_code cc = ldap::client_errc::decode_error;
	CHECK(cc.value() == 1);
	CHECK(std::string(cc.category().name()) == "ldap.client");
	CHECK(cc.message() == "malformed protocol data");
	CHECK(ldap::client_category().message(999) == "unknown LDAP client error 999");

	// Same number, different category: not equal.
	CHECK(std::error_code(ldap::errc::operations_error) != std::error_code(ldap::client_errc::decode_error));
	CHECK(rc == ldap::errc::invalid_credentials);
	CHECK(cc == ldap::client_errc::decode_error);
}

TEST_CASE("ldap::error message and helpers", "[error]")
{
	ldap::error e = ldap::make_error(ldap::client_errc::integer_overflow, "ber: INTEGER at offset 12");
	CHECK(e.code == ldap::client_errc::integer_overflow);
	CHECK(e.message() == "ber: INTEGER at offset 12: integer does not fit in 64 bits [ldap.client:5]");

	ldap::error s;
	s.code = ldap::errc::no_such_object;
	s.diagnostic = "entry not found";
	s.matched_dn = "dc=example,dc=org";
	s.referrals = { "ldap://a.example.org", "ldap://b.example.org" };
	CHECK(s.message()
      == "no such object [ldap.result:32]; server: entry not found; matched DN: dc=example,dc=org; "
         "referrals: ldap://a.example.org ldap://b.example.org");

	ldap::result<int> r = ldap::fail(ldap::client_errc::would_deadlock, "sync");
	REQUIRE_FALSE(r);
	CHECK(r.error().code == ldap::client_errc::would_deadlock);
	CHECK(r.error().context == "sync");

	ldap::error copy = s;
	CHECK(copy == s);
}

// ---------------------------------------------------------------- ldap::cond

namespace {

constexpr ldap::cond all_conds[] = {
	ldap::cond::not_found,
	ldap::cond::auth_failed,
	ldap::cond::timeout,
	ldap::cond::canceled,
	ldap::cond::connection_lost,
	ldap::cond::tls_failure,
	ldap::cond::protocol_error,
	ldap::cond::busy_or_unavailable,
	ldap::cond::access_denied,
	ldap::cond::already_exists,
	ldap::cond::invalid_input,
};

// The one condition `ec` matches, or nullopt; fails the test if it matches several.
std::optional<ldap::cond> cond_of(std::error_code ec)
{
	std::optional<ldap::cond> found;
	for (auto c : all_conds) {
		if (ec != c) continue;
		if (found)
			FAIL_CHECK(
			  ec.message() << " matches both " << std::to_underlying(*found) << " and " << std::to_underlying(c));
		found = c;
	}
	return found;
}

// Stands in for Capy's and Corosio's categories, which jhetz::ldap does not link.
class named_category final : public std::error_category
{
  public:
	explicit named_category(const char *name) : name_(name) {}
	const char *name() const noexcept override { return name_; }
	std::string message(int value) const override { return std::string(name_) + " " + std::to_string(value); }

  private:
	const char *name_;
};

}// namespace

TEST_CASE("every errc maps to its documented condition", "[error][cond]")
{
	using ldap::cond;
	using ldap::errc;
	const std::vector<std::pair<errc, std::optional<cond>>> table{
		{ errc::operations_error, std::nullopt },
		{ errc::protocol_error, cond::protocol_error },
		{ errc::time_limit_exceeded, cond::timeout },
		{ errc::size_limit_exceeded, std::nullopt },
		{ errc::compare_false, std::nullopt },
		{ errc::compare_true, std::nullopt },
		{ errc::auth_method_not_supported, cond::auth_failed },
		{ errc::stronger_auth_required, cond::access_denied },
		{ errc::referral, std::nullopt },
		{ errc::admin_limit_exceeded, std::nullopt },
		{ errc::unavailable_critical_extension, std::nullopt },
		{ errc::confidentiality_required, cond::access_denied },
		{ errc::sasl_bind_in_progress, std::nullopt },
		{ errc::no_such_attribute, cond::not_found },
		{ errc::undefined_attribute_type, cond::invalid_input },
		{ errc::inappropriate_matching, cond::invalid_input },
		{ errc::constraint_violation, cond::invalid_input },
		{ errc::attribute_or_value_exists, cond::already_exists },
		{ errc::invalid_attribute_syntax, cond::invalid_input },
		{ errc::no_such_object, cond::not_found },
		{ errc::alias_problem, std::nullopt },
		{ errc::invalid_dn_syntax, cond::invalid_input },
		{ errc::alias_dereferencing_problem, std::nullopt },
		{ errc::inappropriate_authentication, cond::auth_failed },
		{ errc::invalid_credentials, cond::auth_failed },
		{ errc::insufficient_access_rights, cond::access_denied },
		{ errc::busy, cond::busy_or_unavailable },
		{ errc::unavailable, cond::busy_or_unavailable },
		{ errc::unwilling_to_perform, std::nullopt },
		{ errc::loop_detect, std::nullopt },
		{ errc::naming_violation, cond::invalid_input },
		{ errc::object_class_violation, cond::invalid_input },
		{ errc::not_allowed_on_non_leaf, std::nullopt },
		{ errc::not_allowed_on_rdn, std::nullopt },
		{ errc::entry_already_exists, cond::already_exists },
		{ errc::object_class_mods_prohibited, std::nullopt },
		{ errc::affects_multiple_dsas, std::nullopt },
		{ errc::other, std::nullopt },
		{ errc::assertion_failed, std::nullopt },
	};
	CHECK(table.size() == 39);// every non-success resultCode
	for (const auto &[e, expected] : table) {
		INFO("errc " << std::to_underlying(e) << " " << std::error_code(e).message());
		CHECK(cond_of(e) == expected);
	}
	// Unknown result codes (servers may send any value) match nothing.
	CHECK(cond_of(std::error_code(4711, ldap::result_category())) == std::nullopt);
}

TEST_CASE("every client_errc maps to its documented condition", "[error][cond]")
{
	using ldap::client_errc;
	using ldap::cond;
	const std::vector<std::pair<client_errc, std::optional<cond>>> table{
		{ client_errc::decode_error, cond::protocol_error },
		{ client_errc::message_too_large, cond::protocol_error },
		{ client_errc::nesting_too_deep, cond::protocol_error },
		{ client_errc::unsupported_tag, cond::protocol_error },
		{ client_errc::integer_overflow, cond::protocol_error },
		{ client_errc::invalid_filter, cond::invalid_input },
		{ client_errc::missing_attribute, std::nullopt },
		{ client_errc::too_many_values, std::nullopt },
		{ client_errc::conversion_failed, std::nullopt },
		{ client_errc::schema_mismatch, std::nullopt },
		{ client_errc::would_deadlock, std::nullopt },
		{ client_errc::unexpected_tag, cond::protocol_error },
		{ client_errc::unsupported_operation, cond::protocol_error },
		{ client_errc::invalid_dn, cond::invalid_input },
		{ client_errc::invalid_attribute, cond::invalid_input },
		{ client_errc::encode_error, cond::invalid_input },
		{ client_errc::invalid_url, cond::invalid_input },
		{ client_errc::unexpected_response, cond::protocol_error },
		{ client_errc::not_connected, cond::connection_lost },
		{ client_errc::operation_in_progress, std::nullopt },
		{ client_errc::unauthenticated_bind, cond::auth_failed },
	};
	// Every value, in order: a new client_errc must be added here.
	REQUIRE(table.size() == static_cast<std::size_t>(client_errc::unauthenticated_bind));
	for (std::size_t i = 0; i < table.size(); ++i) {
		const auto &[e, expected] = table[i];
		INFO("client_errc " << std::to_underlying(e) << " " << std::error_code(e).message());
		CHECK(static_cast<std::size_t>(e) == i + 1);
		CHECK(cond_of(e) == expected);
	}
}

TEST_CASE("system, Capy and TLS codes map to conditions", "[error][cond]")
{
	using ldap::cond;
	CHECK(cond_of(std::make_error_code(std::errc::timed_out)) == cond::timeout);
	CHECK(cond_of(std::make_error_code(std::errc::operation_canceled)) == cond::canceled);
	CHECK(cond_of(std::make_error_code(std::errc::connection_reset)) == cond::connection_lost);
	CHECK(cond_of(std::make_error_code(std::errc::broken_pipe)) == cond::connection_lost);
	CHECK(cond_of(std::make_error_code(std::errc::connection_refused)) == cond::busy_or_unavailable);
	CHECK(cond_of(std::make_error_code(std::errc::host_unreachable)) == cond::busy_or_unavailable);
	CHECK(cond_of(std::make_error_code(std::errc::permission_denied)) == cond::access_denied);
	CHECK(cond_of(std::make_error_code(std::errc::no_such_file_or_directory)) == cond::invalid_input);
	CHECK(cond_of(std::make_error_code(std::errc::invalid_argument)) == cond::invalid_input);
	CHECK(cond_of(std::make_error_code(std::errc::not_enough_memory)) == std::nullopt);
	// The system category, as the network layer reports errno values.
	CHECK(cond_of(std::error_code(ETIMEDOUT, std::system_category())) == cond::timeout);
	CHECK(cond_of(std::error_code(ECONNRESET, std::system_category())) == cond::connection_lost);

	const named_category capy("boost.capy");
	CHECK(cond_of(std::error_code(1, capy)) == cond::connection_lost);// eof
	CHECK(cond_of(std::error_code(4, capy)) == cond::connection_lost);// stream_truncated
	CHECK(cond_of(std::error_code(3, capy)) == std::nullopt);// test_failure
	const named_category openssl("corosio.openssl");
	CHECK(cond_of(std::error_code(0x0A000086, openssl)) == cond::tls_failure);
	const named_category other("something.else");
	CHECK(cond_of(std::error_code(1, other)) == std::nullopt);
	CHECK(cond_of(std::error_code{}) == std::nullopt);
}

TEST_CASE("ldap::cond category", "[error][cond]")
{
	CHECK(std::string(ldap::cond_category().name()) == "ldap.cond");
	for (auto c : all_conds) {
		const std::error_condition ec = c;
		CHECK(&ec.category() == &ldap::cond_category());
		CHECK_FALSE(ec.message().empty());
		CHECK_FALSE(ec.message().contains("unknown"));
	}
	// Works through ldap::error, as callers write it.
	const ldap::error e = ldap::make_error(ldap::errc::invalid_credentials, "bind cn=x");
	CHECK(e.code == ldap::cond::auth_failed);
	CHECK(e.code != ldap::cond::not_found);
}
