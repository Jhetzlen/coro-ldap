// change_password / reset_password (password_method) against the scripted
// mock server: the method picked from the root DSE (RFC 3062, Active
// Directory, neither, both), explicit methods that skip the root DSE, the
// unicodePwd ModifyRequests over TLS and their refusal without it, and
// ad_password_value's UTF-16LE encoding.
#include "jhetz/ldap/connection.hpp"
#include "mock_ldap.hpp"
#include "net_test_support.hpp"

#include <boost/corosio/endpoint.hpp>
#include <boost/corosio/ipv4_address.hpp>
#include <boost/corosio/openssl_stream.hpp>
#include <boost/corosio/tcp_acceptor.hpp>
#include <boost/corosio/tcp_socket.hpp>
#include <boost/corosio/tls_context.hpp>

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <cstdint>
#include <initializer_list>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <variant>
#include <vector>

namespace ldap = jhetz::ldap;
namespace net = jhetz::ldap::net;
using namespace jhetz::ldap::test;
using namespace std::literals;
using Catch::Matchers::ContainsSubstring;
using ldap::client_errc;
using ldap::password_method;

namespace {

const ldap::dn jdoe{ "uid=jdoe,ou=people,dc=example,dc=org" };
const std::string jdoe_context = "uid=jdoe,ou=people,dc=example,dc=org";
constexpr std::string_view old_pw = "Old-S3cret";
constexpr std::string_view new_pw = "New-S3cret";

// The root DSE's entry, with the attributes that are given.
ldap::message root_dse(std::int32_t id,
  std::initializer_list<std::string_view> extensions,
  std::initializer_list<std::string_view> capabilities = {})
{
	ldap::search_result_entry e{ "" };
	if (extensions.size() != 0) e.attributes.emplace_back("supportedExtension", extensions);
	if (capabilities.size() != 0) e.attributes.emplace_back("supportedCapabilities", capabilities);
	return ldap::message{ id, std::move(e) };
}

ldap::message extended_ok(std::int32_t id)
{
	return ldap::message{ id, ldap::extended_response{ ldap::ldap_result{ 0 } } };
}

ldap::message modify_result(std::int32_t id, std::int32_t code = 0, std::string_view diagnostic = {})
{
	return ldap::message{ id, ldap::modify_response{ ldap::ldap_result{ code, "", diagnostic } } };
}

ldap::message start_tls_ok(std::int32_t id)
{
	return ldap::message{ id, ldap::extended_response{ ldap::ldap_result{ 0 }, std::string(ldap::start_tls_oid) } };
}

// The search change_password sends in automatic mode.
void check_root_dse_search(const ldap::message &m)
{
	const auto *s = std::get_if<ldap::search_request>(&m.op);
	REQUIRE(s != nullptr);
	CHECK(s->base_object == "");
	CHECK(s->scope == ldap::search_scope::base_object);
	CHECK(s->attributes == ldap::string_list{ "supportedExtension", "supportedCapabilities" });
}

// SEQUENCE { [0] jdoe, [1] old_pw, [2] new_pw } and SEQUENCE { [0] jdoe, [2] new_pw }.
const std::string change_value =
  "\x30\x3e\x80\x24uid=jdoe,ou=people,dc=example,dc=org\x81\x0aOld-S3cret\x82\x0aNew-S3cret"s;
const std::string reset_value = "\x30\x32\x80\x24uid=jdoe,ou=people,dc=example,dc=org\x82\x0aNew-S3cret"s;

ldap::message password_modify_request(std::int32_t id, const std::string &value)
{
	return ldap::message{ id, ldap::extended_request{ ldap::password_modify_oid, value } };
}

// The unicodePwd value of an ASCII password: quoted, UTF-16LE.
std::string utf16le_quoted(std::string_view ascii)
{
	std::string out = "\"\0"s;
	for (const char c : ascii) {
		out += c;
		out += '\0';
	}
	return out + "\"\0"s;
}

// No password in the error, in any of its parts.
void check_no_password(const ldap::error &e)
{
	const std::string text(e.message());
	CHECK_FALSE(text.contains(old_pw));
	CHECK_FALSE(text.contains(new_pw));
}

// ---------------------------------------------------------------- TLS server

test_pki &pki()
{
	static test_pki instance("jhetz-ldap password test CA");
	return instance;
}

corosio::tls_context server_context()
{
	static const auto leaf = pki().issue("localhost", "DNS:localhost,IP:127.0.0.1");
	corosio::tls_context ctx;
	REQUIRE_FALSE(ctx.use_certificate(leaf.cert_pem, corosio::tls_file_format::pem));
	REQUIRE_FALSE(ctx.use_private_key(leaf.key_pem, corosio::tls_file_format::pem));
	return ctx;
}

// Serves `clear` in clear, the last step of which answers a StartTLS
// request, then runs the server side of the handshake and serves `secure`
// over TLS.
capy::task<void> serve_upgrading(corosio::tcp_acceptor &acc,
  corosio::tls_context ctx,
  std::vector<step> clear,
  std::vector<step> secure,
  server_log &log)
{
	auto [ec, peer] = co_await acc.accept();
	if (ec) {
		log.error = "accept: " + ec.message();
		co_return;
	}
	co_await serve_script(net::transport::wrap(socket_ref{ &peer }, "server"), std::move(clear), log);
	if (!log.error.empty()) co_return;
	corosio::openssl_stream tls(&peer, ctx);
	auto [hec] = co_await tls.handshake(corosio::tls_role::server);
	if (hec) {
		log.error = "server handshake: " + hec.message();
		co_return;
	}
	co_await serve_script(net::transport::wrap(socket_ref{ &tls }, "server tls"), std::move(secure), log);
}

// A connection over loopback TCP to serve_upgrading(), trusting its CA.
struct tls_mock
{
	corosio::io_context ioc{};
	corosio::tcp_acceptor acc{ ioc, corosio::endpoint(corosio::ipv4_address::loopback(), 0), 1 };
	server_log log{};
	outcome<void> server{};
	ldap::connection conn{};

	tls_mock(std::vector<step> clear, std::vector<step> secure)
	{
		log.hang_up = [] {};
		spawn(ioc, serve_upgrading(acc, server_context(), std::move(clear), std::move(secure), log), server);
	}

	tls_mock(const tls_mock &) = delete;
	tls_mock &operator=(const tls_mock &) = delete;

	~tls_mock()
	{
		conn.close();
		acc.close();
		drive(ioc);
	}

	ldap::result<void> connect(ldap::connection_options o = {})
	{
		o.tls.ca_pem = std::pmr::string(pki().ca_pem());
		auto u = ldap::url::parse("ldap://127.0.0.1:" + std::to_string(acc.local_endpoint().port()));
		REQUIRE(u.has_value());
		auto c = finish(ioc, ldap::connect(ioc, *u, o));
		if (!c) return std::unexpected(std::move(c.error()));
		conn = std::move(*c);
		return {};
	}

	template<class T> T run(capy::task<T> t) { return finish(ioc, std::move(t)); }

	void check_server()
	{
		drive_until(ioc, [this] { return server.done(); });
		CHECK(log.error == "");
		CHECK(server.done());
	}
};

ldap::connection_options upgraded(password_method method = password_method::automatic)
{
	return { .start_tls = true, .password_method = method };
}

// The ModifyRequest of unicodePwd that change_password and reset_password
// send for jdoe.
void check_change_shape(const ldap::message &m)
{
	const auto *r = std::get_if<ldap::modify_request>(&m.op);
	REQUIRE(r != nullptr);
	CHECK(std::string_view(r->object) == jdoe_context);
	REQUIRE(r->changes.size() == 2);
	CHECK(r->changes[0].operation == ldap::modify_operation::delete_);
	CHECK(r->changes[0].modification == ldap::partial_attribute{ "unicodePwd", { utf16le_quoted(old_pw) } });
	CHECK(r->changes[1].operation == ldap::modify_operation::add);
	CHECK(r->changes[1].modification == ldap::partial_attribute{ "unicodePwd", { utf16le_quoted(new_pw) } });
}

void check_reset_shape(const ldap::message &m)
{
	const auto *r = std::get_if<ldap::modify_request>(&m.op);
	REQUIRE(r != nullptr);
	CHECK(std::string_view(r->object) == jdoe_context);
	REQUIRE(r->changes.size() == 1);
	CHECK(r->changes[0].operation == ldap::modify_operation::replace);
	CHECK(r->changes[0].modification == ldap::partial_attribute{ "unicodePwd", { utf16le_quoted(new_pw) } });
}

}// namespace

// ---------------------------------------------------------------- the value

TEST_CASE("ad_password_value: quoted UTF-16LE, full Unicode", "[net][password]")
{
	CHECK(ldap::ad_password_value("") == "\"\0\"\0"s);
	CHECK(ldap::ad_password_value("ab") == "\"\0a\0b\0\"\0"s);
	// U+00E9, U+20AC, U+65E5 and U+1F600 (outside the BMP: a surrogate pair,
	// D83D DE00, each unit little-endian).
	CHECK(ldap::ad_password_value("\xC3\xA9\xE2\x82\xAC\xE6\x97\xA5\xF0\x9F\x98\x80")
		  == "\"\0\xE9\0\xAC\x20\xE5\x65\x3D\xD8\x00\xDE\"\0"s);
	// A quote inside the password is just a character.
	CHECK(ldap::ad_password_value("a\"b") == "\"\0a\0\"\0b\0\"\0"s);

	// Ill-formed UTF-8: a truncated sequence, an overlong form, a
	// surrogate, a code point above U+10FFFF. The password is never quoted.
	for (std::string_view bad :
	  { "S3cret\xC3"sv, "S3cret\xC0\xAF"sv, "S3cret\xED\xA0\x80"sv, "S3cret\xF4\x90\x80\x80"sv }) {
		auto r = ldap::ad_password_value(bad);
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == client_errc::encode_error);
		CHECK(std::string(r.error().context) == "Active Directory password value: the password is not valid UTF-8");
	}
}

// ---------------------------------------------------------------- automatic

TEST_CASE("change_password: RFC 3062 advertised, the root DSE read once", "[net][password]")
{
	mock_ldap m;
	m.serve({ answer({ root_dse(1, { ldap::who_am_i_oid, ldap::password_modify_oid }), done_msg(1) }),
	  answer({ extended_ok(2) }),
	  answer({ extended_ok(3) }) });
	CHECK(m.run(m.conn.change_password(jdoe, std::string(old_pw), std::string(new_pw))).has_value());
	CHECK(m.run(m.conn.reset_password(jdoe, std::string(new_pw))).has_value());
	m.check_server();

	REQUIRE(m.log.received.size() == 3);
	check_root_dse_search(m.log.received[0]);
	CHECK(m.log.received[1] == password_modify_request(2, change_value));
	CHECK(m.log.received[2] == password_modify_request(3, reset_value));
}

TEST_CASE("change_password: a server advertising both gets RFC 3062", "[net][password]")
{
	mock_ldap m;
	m.serve(
	  { answer({ root_dse(1, { ldap::password_modify_oid }, { ldap::active_directory_capability_oid }), done_msg(1) }),
		answer({ extended_ok(2) }) });
	// Not over TLS: RFC 3062 does not need it (the AD path would refuse).
	CHECK(m.run(m.conn.change_password(jdoe, std::string(old_pw), std::string(new_pw))).has_value());
	m.check_server();
	REQUIRE(m.log.received.size() == 2);
	CHECK(m.log.received[1] == password_modify_request(2, change_value));
}

TEST_CASE("change_password: the AD capability over TLS sends unicodePwd modifies", "[net][password]")
{
	tls_mock f({ answer({ start_tls_ok(1) }) },
	  { answer(
		  { root_dse(2, { ldap::who_am_i_oid }, { "1.2.840.113556.1.4.1791", ldap::active_directory_capability_oid }),
			done_msg(2) }),
		answer({ modify_result(3) }),
		answer({ modify_result(4) }) });
	REQUIRE(f.connect(upgraded()).has_value());
	REQUIRE(f.conn.is_tls());
	CHECK(f.run(f.conn.change_password(jdoe, std::string(old_pw), std::string(new_pw))).has_value());
	CHECK(f.run(f.conn.reset_password(jdoe, std::string(new_pw))).has_value());
	f.check_server();

	REQUIRE(f.log.received.size() == 4);
	check_root_dse_search(f.log.received[1]);
	// A change deletes the old value and adds the new one, in one modify; a
	// reset replaces.
	check_change_shape(f.log.received[2]);
	check_reset_shape(f.log.received[3]);
}

TEST_CASE("change_password: the AD capability without TLS is refused before sending", "[net][password]")
{
	mock_ldap m;
	m.serve({ answer({ root_dse(1, {}, { ldap::active_directory_capability_oid }), done_msg(1) }) });
	for (int i = 0; i < 2; ++i) {// the second time from the cache: no search
		auto r = m.run(m.conn.change_password(jdoe, std::string(old_pw), std::string(new_pw)));
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == client_errc::tls_required);
		CHECK(r.error().code == ldap::cond::access_denied);
		CHECK(std::string(r.error().context)
			  == "change password " + jdoe_context
				   + ": Active Directory sets unicodePwd only over TLS (ldaps:// or start_tls())");
		check_no_password(r.error());
	}
	CHECK(m.conn.is_open());
	m.check_server();
	REQUIRE(m.log.received.size() == 1);
	check_root_dse_search(m.log.received[0]);
}

TEST_CASE("change_password: no known method, or a hidden root DSE", "[net][password]")
{
	mock_ldap m;
	m.serve({ answer({ root_dse(1, { ldap::who_am_i_oid }, { "1.2.840.113556.1.4.1791" }), done_msg(1) }),
	  answer({ done_msg(2) }),// no entry: hidden by access controls
	  answer({ done_msg(3, 50, "", "no access") }) });
	const std::string advice =
	  "choose the method with connection_options::password_method or the method argument "
	  "(ldap::password_method::rfc3062 or active_directory)";

	// Neither advertised. Not cached: each call reads the root DSE again.
	for (int i = 0; i < 2; ++i) {
		auto r = i == 0 ? m.run(m.conn.change_password(jdoe, std::string(old_pw), std::string(new_pw)))
						: m.run(m.conn.reset_password(jdoe, std::string(new_pw)));
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == client_errc::no_password_method);
		CHECK(std::string(r.error().context)
			  == (i == 0 ? "change password " : "reset password ") + jdoe_context
				   + ": the root DSE advertises neither the RFC 3062 password modify extension nor Active Directory "
					 "(it may be hidden by access controls): "
				   + advice + ", or call password_modify()");
		check_no_password(r.error());
	}
	// The root DSE cannot be read: the server's error, with the advice.
	auto refused = m.run(m.conn.change_password(jdoe, std::string(old_pw), std::string(new_pw)));
	REQUIRE_FALSE(refused.has_value());
	CHECK(refused.error().code == ldap::errc::insufficient_access_rights);
	CHECK(std::string(refused.error().context)
		  == "change password " + jdoe_context + ": reading the root DSE to pick the method failed (" + advice
			   + " to skip it): search \"\"");
	CHECK(std::string(refused.error().diagnostic) == "no access");
	check_no_password(refused.error());
	CHECK(m.conn.is_open());
	m.check_server();
	REQUIRE(m.log.received.size() == 3);
	for (const auto &r : m.log.received) check_root_dse_search(r);
}

TEST_CASE("change_password: the root DSE is read again after StartTLS", "[net][password][starttls]")
{
	// In clear the root DSE says RFC 3062; over TLS, Active Directory.
	tls_mock f({ answer({ root_dse(1, { ldap::password_modify_oid }), done_msg(1) }),
				 answer({ extended_ok(2) }),
				 answer({ start_tls_ok(3) }) },
	  { answer({ root_dse(4, {}, { ldap::active_directory_capability_oid }), done_msg(4) }),
		answer({ modify_result(5) }) });
	REQUIRE(f.connect().has_value());
	CHECK(f.run(f.conn.change_password(jdoe, std::string(old_pw), std::string(new_pw))).has_value());
	REQUIRE(f.run(f.conn.start_tls({ .ca_pem = std::pmr::string(pki().ca_pem()) })).has_value());
	CHECK(f.run(f.conn.change_password(jdoe, std::string(old_pw), std::string(new_pw))).has_value());
	f.check_server();

	REQUIRE(f.log.received.size() == 5);
	check_root_dse_search(f.log.received[0]);
	CHECK(f.log.received[1] == password_modify_request(2, change_value));
	check_root_dse_search(f.log.received[3]);
	check_change_shape(f.log.received[4]);
}

// ---------------------------------------------------------------- explicit methods

TEST_CASE("change_password: an explicit method never reads the root DSE", "[net][password]")
{
	SECTION("rfc3062 for the connection")
	{
		mock_ldap m({ .password_method = password_method::rfc3062 });
		m.serve({ answer({ extended_ok(1) }) });
		CHECK(m.run(m.conn.change_password(jdoe, std::string(old_pw), std::string(new_pw))).has_value());
		m.check_server();
		REQUIRE(m.log.received.size() == 1);
		CHECK(m.log.received[0] == password_modify_request(1, change_value));
	}
	SECTION("rfc3062 for one call, overriding the connection's")
	{
		mock_ldap m({ .password_method = password_method::active_directory });
		m.serve({ answer({ extended_ok(1) }) });
		CHECK(m.run(m.conn.reset_password(jdoe, std::string(new_pw), password_method::rfc3062)).has_value());
		m.check_server();
		REQUIRE(m.log.received.size() == 1);
		CHECK(m.log.received[0] == password_modify_request(1, reset_value));
	}
	SECTION("rfc3062 for the bound user: no userIdentity")
	{
		mock_ldap m;
		m.serve({ answer({ extended_ok(1) }) });
		CHECK(m.run(m.conn.change_password({}, "o", "n", password_method::rfc3062)).has_value());
		m.check_server();
		REQUIRE(m.log.received.size() == 1);
		CHECK(m.log.received[0] == password_modify_request(1, "\x30\x06\x81\x01o\x82\x01n"s));
	}
	SECTION("active_directory for the connection, over TLS")
	{
		tls_mock f({ answer({ start_tls_ok(1) }) }, { answer({ modify_result(2) }), answer({ modify_result(3) }) });
		REQUIRE(f.connect(upgraded(password_method::active_directory)).has_value());
		CHECK(f.run(f.conn.change_password(jdoe, std::string(old_pw), std::string(new_pw))).has_value());
		CHECK(f.run(f.conn.reset_password(jdoe, std::string(new_pw))).has_value());
		f.check_server();
		REQUIRE(f.log.received.size() == 3);
		check_change_shape(f.log.received[1]);
		check_reset_shape(f.log.received[2]);
	}
	SECTION("active_directory for one call, over TLS")
	{
		tls_mock f({ answer({ start_tls_ok(1) }) }, { answer({ modify_result(2) }) });
		REQUIRE(f.connect(upgraded(password_method::rfc3062)).has_value());
		CHECK(f.run(f.conn.reset_password(jdoe, std::string(new_pw), password_method::active_directory)).has_value());
		f.check_server();
		REQUIRE(f.log.received.size() == 2);
		check_reset_shape(f.log.received[1]);
	}
	SECTION("active_directory without TLS: nothing is sent")
	{
		mock_ldap m({ .password_method = password_method::active_directory });
		m.serve({});
		auto r = m.run(m.conn.reset_password(jdoe, std::string(new_pw)));
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == client_errc::tls_required);
		auto c = m.run(
		  m.conn.change_password(jdoe, std::string(old_pw), std::string(new_pw), password_method::active_directory));
		REQUIRE_FALSE(c.has_value());
		CHECK(c.error().code == client_errc::tls_required);
		check_no_password(c.error());
		CHECK(m.conn.is_open());
		m.check_server();
		CHECK(m.log.received.empty());
	}
	SECTION("automatic for one call, overriding the connection's")
	{
		mock_ldap m({ .password_method = password_method::active_directory });
		m.serve({ answer({ root_dse(1, { ldap::password_modify_oid }), done_msg(1) }), answer({ extended_ok(2) }) });
		CHECK(m.run(m.conn.reset_password(jdoe, std::string(new_pw), password_method::automatic)).has_value());
		m.check_server();
		REQUIRE(m.log.received.size() == 2);
		check_root_dse_search(m.log.received[0]);
	}
}

// ---------------------------------------------------------------- errors

TEST_CASE("change_password: refused before sending", "[net][password]")
{
	mock_ldap m;
	m.serve({});
	const auto invalid = std::make_error_code(std::errc::invalid_argument);
	auto no_new = m.run(m.conn.change_password(jdoe, std::string(old_pw), ""));
	REQUIRE_FALSE(no_new.has_value());
	CHECK(no_new.error().code == invalid);
	CHECK(std::string(no_new.error().context) == "change password " + jdoe_context + ": empty new password");
	auto no_old = m.run(m.conn.change_password(jdoe, "", std::string(new_pw)));
	REQUIRE_FALSE(no_old.has_value());
	CHECK(no_old.error().code == invalid);
	CHECK(std::string(no_old.error().context)
		  == "change password " + jdoe_context + ": empty old password (reset_password() sets one without it)");
	auto reset = m.run(m.conn.reset_password(jdoe, "", password_method::rfc3062));
	REQUIRE_FALSE(reset.has_value());
	CHECK(reset.error().code == invalid);
	// Active Directory names the entry to modify.
	auto no_dn = m.run(m.conn.reset_password({}, std::string(new_pw), password_method::active_directory));
	REQUIRE_FALSE(no_dn.has_value());
	CHECK(no_dn.error().code == client_errc::invalid_dn);
	CHECK(std::string(no_dn.error().context) == "reset password \"\": Active Directory needs the user's DN");
	// Ill-formed UTF-8 cannot become UTF-16.
	tls_mock f({ answer({ start_tls_ok(1) }) }, {});
	REQUIRE(f.connect(upgraded(password_method::active_directory)).has_value());
	auto bad = f.run(f.conn.reset_password(jdoe, "S3cret\xFF"));
	REQUIRE_FALSE(bad.has_value());
	CHECK(bad.error().code == client_errc::encode_error);
	CHECK(std::string(bad.error().context)
		  == "reset password " + jdoe_context + ": Active Directory password value: the password is not valid UTF-8");
	CHECK(m.conn.is_open());
	m.check_server();
	CHECK(m.log.received.empty());
	f.check_server();
	CHECK(f.log.received.size() == 1);// the StartTLS request

	ldap::connection none;
	auto closed = m.run(none.change_password(jdoe, std::string(old_pw), std::string(new_pw)));
	REQUIRE_FALSE(closed.has_value());
	CHECK(closed.error().code == client_errc::not_connected);
}

TEST_CASE("change_password: server errors, AD diagnostics explained", "[net][password]")
{
	SECTION("RFC 3062")
	{
		mock_ldap m({ .password_method = password_method::rfc3062 });
		m.serve({ answer({ ldap::message{ 1, ldap::extended_response{ ldap::ldap_result{ 49, "", "wrong" } } } }) });
		auto r = m.run(m.conn.change_password(jdoe, std::string(old_pw), std::string(new_pw)));
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == ldap::errc::invalid_credentials);
		CHECK(std::string(r.error().context) == "change password " + jdoe_context + ": password modify (RFC 3062)");
		check_no_password(r.error());
		m.check_server();
	}
	SECTION("Active Directory")
	{
		const std::string policy =
		  "0000052D: Constraint violation - check_password_restrictions: the password does not meet the complexity "
		  "criteria!";
		const std::string wrong_old =
		  "00000056: AtrErr: DSID-03190F80, #1:\n\t0: 00000056: DSID-03190F80, problem 1005 (CONSTRAINT_ATT_TYPE), "
		  "data 0, Att 9005a (unicodePwd)\n";
		tls_mock f({ answer({ start_tls_ok(1) }) },
		  { answer({ modify_result(2, 19, policy) }),
			answer({ modify_result(3, 19, wrong_old) }),
			answer({ modify_result(4, 53, "00002077: SvcErr: DSID-03190EF9, problem 5003 (WILL_NOT_PERFORM)") }),
			answer({ modify_result(5, 50, "insufficient access") }) });
		REQUIRE(f.connect(upgraded(password_method::active_directory)).has_value());
		const std::string context = "change password " + jdoe_context + ": modify unicodePwd";

		auto weak = f.run(f.conn.change_password(jdoe, std::string(old_pw), std::string(new_pw)));
		REQUIRE_FALSE(weak.has_value());
		CHECK(weak.error().code == ldap::errc::constraint_violation);
		CHECK(std::string(weak.error().context)
			  == context
				   + ": the new password does not meet the password policy (length, complexity, history or minimum "
					 "age) (Active Directory error 0000052D)");
		CHECK(std::string(weak.error().diagnostic) == policy);// kept as sent
		check_no_password(weak.error());

		auto old = f.run(f.conn.change_password(jdoe, std::string(old_pw), std::string(new_pw)));
		REQUIRE_FALSE(old.has_value());
		CHECK(std::string(old.error().context)
			  == context + ": the old password is wrong (Active Directory error 00000056)");
		CHECK(std::string(old.error().diagnostic) == wrong_old);

		// Codes it does not explain, and diagnostics that are not AD's.
		auto other = f.run(f.conn.change_password(jdoe, std::string(old_pw), std::string(new_pw)));
		REQUIRE_FALSE(other.has_value());
		CHECK(other.error().code == ldap::errc::unwilling_to_perform);
		CHECK(std::string(other.error().context) == context);
		auto plain = f.run(f.conn.change_password(jdoe, std::string(old_pw), std::string(new_pw)));
		REQUIRE_FALSE(plain.has_value());
		CHECK(std::string(plain.error().context) == context);
		CHECK(f.conn.is_open());
		f.check_server();
	}
}
