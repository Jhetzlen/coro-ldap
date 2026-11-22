// SASL GSSAPI security layers against an in-process LDAP server with an
// MIT krb5 acceptor, under a throwaway KDC:
//   tests/integration/run_kdc.sh ctest --test-dir build -L kerberos
// Skipped without it.
#include "../../src/net/sasl_layer.hpp"
#include "../net/mock_ldap.hpp"
#include "jhetz/ldap/connection.hpp"
#include "jhetz/ldap/sasl_gssapi.hpp"
#include "jhetz/ldap/testing/message_io.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <gssapi/gssapi.h>

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <memory>
#include <memory_resource>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace ldap = jhetz::ldap;
namespace net = jhetz::ldap::net;
using namespace jhetz::ldap::test;
using Catch::Matchers::StartsWith;

namespace {

auto env(const char *name) -> std::string
{
	// NOLINTNEXTLINE(concurrency-mt-unsafe): nothing in this binary calls setenv while tests run
	const char *v = std::getenv(name);
	return v == nullptr ? std::string() : std::string(v);
}

auto view(const gss_buffer_desc &b) -> std::string
{
	return b.value == nullptr ? std::string() : std::string(static_cast<const char *>(b.value), b.length);
}

// The acceptor's security context, deleted with it.
struct acceptor_context
{
	gss_ctx_id_t handle = GSS_C_NO_CONTEXT;
	acceptor_context() = default;
	acceptor_context(const acceptor_context &) = delete;
	auto operator=(const acceptor_context &) -> acceptor_context & = delete;
	~acceptor_context()
	{
		OM_uint32 minor = 0;
		gss_delete_sec_context(&minor, &handle, GSS_C_NO_BUFFER);
	}
};

// gss_wrap / gss_unwrap on `in`; throws on a GSS-API error.
auto acceptor_wrap(gss_ctx_id_t c, bool conf, std::string in, int *conf_state = nullptr) -> std::string
{
	OM_uint32 minor = 0;
	gss_buffer_desc i{ .length = in.size(), .value = in.data() };
	gss_buffer_desc o{ .length = 0, .value = nullptr };
	const OM_uint32 major = gss_wrap(&minor, c, conf ? 1 : 0, GSS_C_QOP_DEFAULT, &i, conf_state, &o);
	std::string out = view(o);
	gss_release_buffer(&minor, &o);
	if (GSS_ERROR(major) != 0) {
		throw std::runtime_error("acceptor gss_wrap failed");
	}
	return out;
}
auto acceptor_unwrap(gss_ctx_id_t c, std::string in, int *conf_state = nullptr) -> std::string
{
	OM_uint32 minor = 0;
	gss_buffer_desc i{ .length = in.size(), .value = in.data() };
	gss_buffer_desc o{ .length = 0, .value = nullptr };
	const OM_uint32 major = gss_unwrap(&minor, c, &i, &o, conf_state, nullptr);
	std::string out = view(o);
	gss_release_buffer(&minor, &o);
	if (GSS_ERROR(major) != 0) {
		throw std::runtime_error("acceptor gss_unwrap failed");
	}
	return out;
}

// The server's half of the layer; records whether every client buffer was
// encrypted.
class acceptor_layer final : public ldap::sasl_security_layer
{
  public:
	struct seen
	{
		int buffers = 0;
		int encrypted = 0;
		std::size_t largest = 0;// protected buffer received
	};

	acceptor_layer(gss_ctx_id_t c, bool conf, std::size_t max_wrap_input, std::shared_ptr<seen> s)
	  : c_(c), conf_(conf), max_wrap_input_(max_wrap_input), seen_(std::move(s))
	{}
	[[nodiscard]] auto protection() const noexcept -> ldap::sasl_protection override
	{
		return conf_ ? ldap::sasl_protection::confidentiality : ldap::sasl_protection::integrity;
	}
	[[nodiscard]] auto max_wrap_input() const noexcept -> std::size_t override { return max_wrap_input_; }
	[[nodiscard]] auto max_received() const noexcept -> std::size_t override { return std::size_t{ 1 } << 24; }
	[[nodiscard]] auto wrap(std::span<const std::byte> plaintext, std::pmr::vector<std::byte> &out)
	  -> ldap::result<void> override
	{
		append(out, acceptor_wrap(c_, conf_, text(plaintext)));
		return {};
	}
	[[nodiscard]] auto unwrap(std::span<const std::byte> buffer, std::pmr::vector<std::byte> &out)
	  -> ldap::result<void> override
	{
		int conf_state = 0;
		append(out, acceptor_unwrap(c_, text(buffer), &conf_state));
		++seen_->buffers;
		seen_->encrypted += conf_state != 0 ? 1 : 0;
		seen_->largest = std::max(seen_->largest, buffer.size());
		return {};
	}

  private:
	static auto text(std::span<const std::byte> b) -> std::string
	{
		return { reinterpret_cast<const char *>(b.data()), b.size() };
	}
	static void append(std::pmr::vector<std::byte> &out, const std::string &s)
	{
		const auto b = std::as_bytes(std::span(s));
		out.insert(out.end(), b.begin(), b.end());
	}

	gss_ctx_id_t c_;
	bool conf_;
	std::size_t max_wrap_input_;
	std::shared_ptr<seen> seen_;
};

constexpr std::uint8_t offer_all = 7;

// What the server saw of the exchange.
struct server_view
{
	std::string error{};
	std::uint8_t selected = 0;// the client's layer byte
	std::uint32_t client_max = 0;
	std::shared_ptr<acceptor_layer::seen> seen = std::make_shared<acceptor_layer::seen>();
	std::string search_filter_attr{};
};

auto sasl_creds(const ldap::message &m) -> std::string
{
	const auto &b = std::get<ldap::bind_request>(m.op);
	const auto &s = std::get<ldap::sasl_auth>(b.authentication);
	return s.credentials ? std::string(*s.credentials) : std::string();
}

auto in_progress(std::int32_t id, std::string creds) -> ldap::message
{
	return ldap::message{ id, ldap::bind_response{ ldap::ldap_result{ 14 }, creds } };
}

// The server: the Kerberos exchange, the offer, and through the selected
// layer one search answered with a large entry.
auto serve(net::transport t, std::uint8_t offer, std::uint32_t server_max, std::string value, server_view &v)
  -> capy::task<void>
{
	try {
		net::read_buffer buf;
		acceptor_context ctx;
		// The AP-REQ, answered with the AP-REP.
		auto first = co_await ldap::testing::read_message(t, buf, as_server);
		if (!first) {
			throw std::runtime_error("read AP-REQ");
		}
		std::string token = sasl_creds(*first);
		gss_buffer_desc in{ .length = token.size(), .value = token.data() };
		gss_buffer_desc out{ .length = 0, .value = nullptr };
		OM_uint32 minor = 0;
		OM_uint32 flags = 0;
		const OM_uint32 major = gss_accept_sec_context(&minor,
		  &ctx.handle,
		  GSS_C_NO_CREDENTIAL,
		  &in,
		  GSS_C_NO_CHANNEL_BINDINGS,
		  nullptr,
		  nullptr,
		  &out,
		  &flags,
		  nullptr,
		  nullptr);
		const std::string ap_rep = view(out);
		gss_release_buffer(&minor, &out);
		if (major != GSS_S_COMPLETE) {
			throw std::runtime_error("gss_accept_sec_context did not complete");
		}
		(void)co_await net::write_message(t, in_progress(first->id, ap_rep));
		// The client's last (empty) token, answered with the wrapped offer.
		auto empty = co_await ldap::testing::read_message(t, buf, as_server);
		if (!empty) {
			throw std::runtime_error("read the empty token");
		}
		const std::string offer_text{ static_cast<char>(offer),
			static_cast<char>(server_max >> 16),
			static_cast<char>(server_max >> 8),
			static_cast<char>(server_max) };
		(void)co_await net::write_message(t, in_progress(empty->id, acceptor_wrap(ctx.handle, false, offer_text)));
		// The wrapped reply: the layer and the client's maximum.
		auto reply = co_await ldap::testing::read_message(t, buf, as_server);
		if (!reply) {
			throw std::runtime_error("read the reply");
		}
		if (std::holds_alternative<ldap::bind_request>(reply->op)
			&& std::holds_alternative<ldap::simple_auth>(std::get<ldap::bind_request>(reply->op).authentication)) {
			// The client aborted the exchange (it refused the offer).
			(void)co_await net::write_message(t, bind_resp(reply->id));
			co_return;
		}
		const std::string text = acceptor_unwrap(ctx.handle, sasl_creds(*reply));
		if (text.size() < 4) {
			throw std::runtime_error("short reply");
		}
		v.selected = static_cast<std::uint8_t>(text[0]);
		v.client_max = (std::uint32_t{ static_cast<unsigned char>(text[1]) } << 16)
					   | (std::uint32_t{ static_cast<unsigned char>(text[2]) } << 8)
					   | std::uint32_t{ static_cast<unsigned char>(text[3]) };
		(void)co_await net::write_message(t, bind_resp(reply->id));
		if (v.selected == 1) {
			co_return;
		}
		const bool conf = v.selected == 4;
		OM_uint32 max_input = 0;
		gss_wrap_size_limit(&minor, ctx.handle, conf ? 1 : 0, GSS_C_QOP_DEFAULT, v.client_max, &max_input);
		if (auto l = net::detail::install_security_layer(
			  t, buf, std::make_unique<acceptor_layer>(ctx.handle, conf, max_input, v.seen));
		  !l) {
			throw std::runtime_error("install");
		}
		auto search = co_await ldap::testing::read_message(t, buf, as_server);
		if (!search) {
			throw std::runtime_error("read the search: " + std::string(search.error().message()));
		}
		const auto &f = std::get<ldap::search_request>(search->op).filter;
		v.search_filter_attr = std::string(f.to_string());
		ldap::message entry{ search->id,
			ldap::search_result_entry{
			  "uid=user007,ou=people,dc=example,dc=org", { ldap::partial_attribute{ "description", { value } } } } };
		(void)co_await net::write_message(t, entry);
		(void)co_await net::write_message(t, done_msg(search->id));
		// Keep the context until the client is done reading.
		(void)co_await ldap::testing::read_message(t, buf, as_server);
	} catch (const std::exception &e) {
		v.error = e.what();
	}
}

void require_kdc()
{
	if (env("JHETZ_LDAP_IT_KRB5_REALM").empty() || env("KRB5_KTNAME").empty()) {
		SKIP("no KDC: run under run_kdc.sh");
	}
}

auto user_search() -> ldap::search_params
{
	return { .base = ldap::dn{ "ou=people,dc=example,dc=org" }, .filter = ldap::filters::attr("uid") == "user007" };
}

}// namespace

TEST_CASE("kerberos: GSSAPI security layers against an MIT acceptor", "[integration][sasl][gssapi][sasl_layer]")
{
	require_kdc();
	mock_ldap m;
	server_view v;
	outcome<void> server;
	// Larger than the client's maximum buffer size (4096 below), so the
	// server sends it in several buffers.
	const std::string value(10000, 'v');
	const auto bind_and_search = [&](ldap::sasl_gssapi &mech) {
		auto b = finish(m.ioc, m.conn.sasl_bind(mech));
		if (!b) {
			FAIL("sasl bind: " << b.error().message() << " (server: " << v.error << ")");
		}
		auto s = finish(m.ioc, m.conn.search(user_search()));
		if (!s) {
			FAIL("search: " << s.error().message() << " (server: " << v.error << ")");
		}
		REQUIRE(s->entries.size() == 1);
		const auto *d = s->entries[0].find("description");
		REQUIRE(d != nullptr);
		CHECK(std::string_view((*d)[0]) == value);
		CHECK(v.search_filter_attr == "(uid=user007)");
	};

	SECTION("integrity")
	{
		spawn(m.ioc, serve(m.server_end(), offer_all, 1024, value, v), server);
		ldap::sasl_gssapi mech({ .target = "ldap@localhost",
		  .security_layer = ldap::gssapi_security_layer::integrity,
		  .max_receive_size = 4096 });
		bind_and_search(mech);
		CHECK(v.selected == 2);
		CHECK(v.client_max == 4096);
		CHECK(m.conn.security_layer() == ldap::sasl_protection::integrity);
		CHECK(v.seen->buffers >= 1);
		CHECK(v.seen->encrypted == 0);
		CHECK(v.seen->largest <= 1024);// the server's maximum
	}
	SECTION("confidentiality, a search larger than the server's maximum")
	{
		spawn(m.ioc, serve(m.server_end(), offer_all, 64, value, v), server);
		ldap::sasl_gssapi mech({ .target = "ldap@localhost",
		  .security_layer = ldap::gssapi_security_layer::confidentiality,
		  .max_receive_size = 4096 });
		bind_and_search(mech);
		CHECK(v.selected == 4);
		CHECK(m.conn.security_layer() == ldap::sasl_protection::confidentiality);
		CHECK(v.seen->buffers > 1);// the SearchRequest did not fit in 64 octets
		CHECK(v.seen->encrypted == v.seen->buffers);
		CHECK(v.seen->largest <= 64);
	}
	SECTION("best offered without TLS: confidentiality")
	{
		spawn(m.ioc, serve(m.server_end(), offer_all, 4096, value, v), server);
		ldap::sasl_gssapi mech({ .target = "ldap@localhost",
		  .security_layer = ldap::gssapi_security_layer::best_offered,
		  .max_receive_size = 4096 });
		bind_and_search(mech);
		CHECK(v.selected == 4);
		CHECK(v.seen->encrypted == v.seen->buffers);
	}
	SECTION("integrity asked, only no layer offered: refused, the exchange aborted")
	{
		spawn(m.ioc, serve(m.server_end(), 1, 0, value, v), server);
		ldap::sasl_gssapi mech(
		  { .target = "ldap@localhost", .security_layer = ldap::gssapi_security_layer::integrity });
		auto b = finish(m.ioc, m.conn.sasl_bind(mech));
		REQUIRE_FALSE(b.has_value());
		CHECK(b.error().code == ldap::client_errc::security_layer_unavailable);
		CHECK_THAT(std::string(b.error().context), StartsWith("sasl bind GSSAPI: the server offers neither"));
		CHECK(m.conn.is_open());
		CHECK(m.conn.security_layer() == ldap::sasl_protection::none);
	}
	SECTION("no layer by default (require_tls = false over plain LDAP)")
	{
		spawn(m.ioc, serve(m.server_end(), offer_all, 4096, value, v), server);
		ldap::sasl_gssapi mech({ .target = "ldap@localhost", .require_tls = false });
		REQUIRE(finish(m.ioc, m.conn.sasl_bind(mech)).has_value());
		CHECK(v.selected == 1);
		CHECK(v.client_max == 0);
		CHECK(m.conn.security_layer() == ldap::sasl_protection::none);
	}
	CHECK(v.error.empty());
}
