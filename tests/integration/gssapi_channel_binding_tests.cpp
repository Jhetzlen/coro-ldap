// SASL GSSAPI channel bindings, end to end without slapd (whose acceptor is
// given none, see sasl_gssapi.hpp): sasl_gssapi's tokens go straight to an
// in-process MIT krb5 acceptor (gss_accept_sec_context), given bindings or
// not, under a throwaway KDC:
//
//   tests/integration/run_kdc.sh ctest --test-dir build -L kerberos
//
// run_kdc.sh puts ldap/localhost's key in KRB5_KTNAME (the acceptor's
// credentials) and user007's ticket in KRB5CCNAME (the initiator's).
// Skipped without it.
#include "jhetz/ldap/channel_binding.hpp"
#include "jhetz/ldap/sasl_gssapi.hpp"

#include <catch2/catch_test_macros.hpp>

#include <gssapi/gssapi.h>

#include <array>
#include <cstddef>
#include <cstdlib>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>

namespace ldap = jhetz::ldap;
using namespace std::string_literals;

namespace {

auto env(const char *name) -> std::string
{
	// NOLINTNEXTLINE(concurrency-mt-unsafe): nothing in this binary calls setenv while tests run
	const char *v = std::getenv(name);
	return v == nullptr ? std::string() : std::string(v);
}

// GSS_C_CHANNEL_BOUND_FLAG (MIT gssapi_ext.h, Heimdal gssapi.h): set in the
// acceptor's ret_flags when the initiator's bindings matched its own (MIT
// accept_sec_context.c process_checksum).
constexpr OM_uint32 channel_bound_flag = 2048;

struct accepted
{
	OM_uint32 major = 0;
	OM_uint32 flags = 0;
	std::string token;// the AP-REP, for the initiator's step()
};

// One gss_accept_sec_context call with the default acceptor credentials
// (KRB5_KTNAME) on `token`, given `bindings` as application_data (no
// addresses, as sasl_gssapi sends them), or none.
auto accept(std::string token, std::optional<std::string> bindings) -> accepted
{
	gss_channel_bindings_struct cb{ .initiator_addrtype = GSS_C_AF_UNSPEC,
		.initiator_address = { .length = 0, .value = nullptr },
		.acceptor_addrtype = GSS_C_AF_UNSPEC,
		.acceptor_address = { .length = 0, .value = nullptr },
		.application_data = { .length = 0, .value = nullptr } };
	if (bindings) {
		cb.application_data = { .length = bindings->size(), .value = bindings->data() };
	}
	gss_buffer_desc in{ .length = token.size(), .value = token.data() };
	gss_buffer_desc out{ .length = 0, .value = nullptr };
	gss_ctx_id_t context = GSS_C_NO_CONTEXT;
	OM_uint32 minor = 0;
	accepted a;
	a.major = gss_accept_sec_context(&minor,
	  &context,
	  GSS_C_NO_CREDENTIAL,
	  &in,
	  bindings ? &cb : GSS_C_NO_CHANNEL_BINDINGS,
	  nullptr,
	  nullptr,
	  &out,
	  &a.flags,
	  nullptr,
	  nullptr);
	if (out.value != nullptr) {
		a.token.assign(static_cast<const char *>(out.value), out.length);
	}
	gss_release_buffer(&minor, &out);
	gss_delete_sec_context(&minor, &context, GSS_C_NO_BUFFER);
	return a;
}

// The initiator's first token (sasl_gssapi::start(), the AP-REQ) for a TLS
// connection to localhost whose tls-server-end-point hash is `hash`.
auto first_token(ldap::sasl_gssapi &mech, std::span<const std::byte> hash) -> std::string
{
	ldap::sasl_bind_context context{ .host = "localhost", .tls = true };
	context.bindings.tls_server_end_point = hash;
	mech.prepare(context);
	auto t = mech.start();
	if (!t) {
		FAIL("start: " << t.error().message());
	}
	REQUIRE(t->has_value());
	return std::move(**t);
}

}// namespace

TEST_CASE("kerberos: GSSAPI channel bindings against an MIT acceptor", "[integration][sasl][gssapi][channel_binding]")
{
	if (env("JHETZ_LDAP_IT_KRB5_REALM").empty() || env("KRB5_KTNAME").empty()) {
		SKIP("no KDC: run under run_kdc.sh");
	}
	const std::array<std::byte, 4> hash{ std::byte{ 0x01 }, std::byte{ 0x00 }, std::byte{ 0xfe }, std::byte{ 0x7f } };
	// The bytes Active Directory and libldap expect, spelled out.
	const std::string ours = "tls-server-end-point:\x01\x00\xfe\x7f"s;
	const std::string theirs = "tls-server-end-point:\x01\x00\xfe\x80"s;

	SECTION("bindings, acceptor given none (slapd): accepted")
	{
		ldap::sasl_gssapi mech;
		const auto a = accept(first_token(mech, hash), std::nullopt);
		CHECK(a.major == GSS_S_COMPLETE);
		CHECK((a.flags & channel_bound_flag) == 0);
		// The initiator takes the acceptor's AP-REP (mutual authentication).
		CHECK(mech.step(a.token).has_value());
	}
	SECTION("bindings, acceptor given the same: accepted, the context channel bound")
	{
		ldap::sasl_gssapi mech;
		const auto a = accept(first_token(mech, hash), ours);
		CHECK(mech.channel_binding_used() == ldap::channel_binding_type::tls_server_end_point);
		CHECK(a.major == GSS_S_COMPLETE);
		// MIT sets GSS_C_CHANNEL_BOUND_FLAG in ret_flags whenever the
		// bindings match, whether or not the initiator asserted
		// KERB_AP_OPTIONS_CBT: the bit reflects the match, so this does not
		// show that the client passes the flag with bindings (an acceptor
		// cannot observe it then). Only the last section (no bindings, the
		// acceptor given some) constrains the client's flag.
		CHECK((a.flags & channel_bound_flag) != 0);
		CHECK(mech.step(a.token).has_value());
	}
	SECTION("bindings, acceptor given others (a TLS-terminating proxy, a man in the middle): refused")
	{
		ldap::sasl_gssapi mech;
		const auto a = accept(first_token(mech, hash), theirs);
		CHECK(a.major == GSS_S_BAD_BINDINGS);
	}
	SECTION("none, acceptor given bindings: accepted, the client asserts no binding")
	{
		ldap::sasl_gssapi mech({ .channel_binding = ldap::gssapi_channel_binding::none });
		const auto a = accept(first_token(mech, hash), ours);
		CHECK_FALSE(mech.channel_binding_used().has_value());
		CHECK(a.major == GSS_S_COMPLETE);
		CHECK((a.flags & channel_bound_flag) == 0);
		CHECK(mech.step(a.token).has_value());
	}
}
