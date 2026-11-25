// SASL GSSAPI's SSPI backend without a domain: status codes as errors, and
// calls without a security context.
#include "../../src/sasl_gssapi_context.hpp"
#include "jhetz/ldap/error.hpp"

#include <catch2/catch_test_macros.hpp>

#include <windows.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory_resource>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace ldap = jhetz::ldap;

TEST_CASE("sspi: status codes as errors", "[net][sasl][gssapi][sspi]")
{
	using ldap::detail::sspi_failure;
	const auto context = [](std::string_view call, HRESULT status) {
		const auto e = sspi_failure(call, static_cast<std::int32_t>(status)).error();
		CHECK(e.code == ldap::client_errc::gssapi_failure);
		CHECK(e.code == ldap::cond::auth_failed);
		return std::string(e.context);
	};
	CHECK(context("InitializeSecurityContextW", SEC_E_LOGON_DENIED)
		  == "InitializeSecurityContextW: SEC_E_LOGON_DENIED (0x8009030C): logon denied");
	CHECK(context("InitializeSecurityContextW", SEC_E_TARGET_UNKNOWN)
		  == "InitializeSecurityContextW: SEC_E_TARGET_UNKNOWN (0x80090303): unknown target (no such service "
			 "principal)");
	CHECK(context("AcquireCredentialsHandleW", SEC_E_NO_CREDENTIALS)
		  == "AcquireCredentialsHandleW: SEC_E_NO_CREDENTIALS (0x8009030E): no credentials");
	CHECK(context("InitializeSecurityContextW", SEC_E_NO_AUTHENTICATING_AUTHORITY)
		  == "InitializeSecurityContextW: SEC_E_NO_AUTHENTICATING_AUTHORITY (0x80090311): no domain controller "
			 "(KDC) could be contacted");
	CHECK(context("DecryptMessage", SEC_E_OUT_OF_SEQUENCE)
		  == "DecryptMessage: SEC_E_OUT_OF_SEQUENCE (0x80090310): message replayed or out of sequence");
	CHECK(context("DecryptMessage", SEC_E_MESSAGE_ALTERED)
		  == "DecryptMessage: SEC_E_MESSAGE_ALTERED (0x8009030F): message altered (integrity check failed)");
	CHECK(context("InitializeSecurityContextW", SEC_E_BAD_BINDINGS)
		  == "InitializeSecurityContextW: SEC_E_BAD_BINDINGS (0x80090346): channel bindings do not match");
	// Unknown: the value alone.
	CHECK(context("EncryptMessage", static_cast<HRESULT>(0x8009FFFFUL)) == "EncryptMessage: 0x8009FFFF");
}

TEST_CASE("sspi: no security context", "[net][sasl][gssapi][sspi]")
{
	ldap::detail::gssapi_context c;
	CHECK_FALSE(c.established());
	const auto flags = c.flags();
	CHECK_FALSE(flags.integrity);
	CHECK_FALSE(flags.confidentiality);
	CHECK_FALSE(flags.sequence);
	auto init = c.init(std::nullopt);
	REQUIRE_FALSE(init.has_value());
	CHECK(init.error().code == ldap::client_errc::internal_error);
	std::pmr::vector<std::byte> out;
	const std::array<std::byte, 2> data{ std::byte{ 1 }, std::byte{ 2 } };
	CHECK_FALSE(c.wrap(data, true, out).has_value());
	bool confidential = false;
	CHECK_FALSE(c.unwrap(data, out, confidential).has_value());
	CHECK_FALSE(c.wrap_size_limit(true, 1024).has_value());
	CHECK(out.empty());
}

TEST_CASE("sspi: the target name is checked before any credentials", "[net][sasl][gssapi][sspi]")
{
	ldap::detail::gssapi_context c;
	auto r = c.acquire({ .target = "ldap@\xFF", .principal = "", .password = "", .bindings = "", .layer = false });
	REQUIRE_FALSE(r.has_value());
	CHECK(r.error().code == ldap::client_errc::encode_error);
	CHECK(r.error().context == "target is not valid UTF-8");
	CHECK_FALSE(c.established());
}
