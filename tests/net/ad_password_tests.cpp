// ad::change_password / ad::reset_password (unicodePwd modifies) against
// the scripted mock server: the ModifyRequests over TLS (StartTLS or
// ldaps://), their refusal without it or during StartTLS, the refusals
// before sending, and the server's AD diagnostics explained.
#include "jhetz/ldap/ad/password.hpp"
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
#include <catch2/matchers/catch_matchers_container_properties.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <cstddef>
#include <cstdint>
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
using Catch::Matchers::IsEmpty;
using ldap::client_errc;

namespace {

const ldap::dn jdoe{ "uid=jdoe,ou=people,dc=example,dc=org" };
const std::string jdoe_context = "uid=jdoe,ou=people,dc=example,dc=org";
constexpr std::string_view old_pw = "Old-S3cret";
constexpr std::string_view new_pw = "New-S3cret";

auto modify_result(std::int32_t id, std::int32_t code = 0, std::string_view diagnostic = {}) -> ldap::message
{
	return ldap::message{ id, ldap::modify_response{ ldap::ldap_result{ code, "", diagnostic } } };
}

auto start_tls_ok(std::int32_t id) -> ldap::message
{
	return ldap::message{ id, ldap::extended_response{ ldap::ldap_result{ 0 }, std::string(ldap::start_tls_oid) } };
}

// The unicodePwd value of an ASCII password: quoted, UTF-16LE.
auto utf16le_quoted(std::string_view ascii) -> std::string
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

auto pki() -> test_pki &
{
	static test_pki instance("jhetz-ldap password test CA");
	return instance;
}

auto server_context() -> corosio::tls_context
{
	static const auto leaf = pki().issue("localhost", "DNS:localhost,IP:127.0.0.1");
	corosio::tls_context ctx;
	REQUIRE_FALSE(ctx.use_certificate(leaf.cert_pem, corosio::tls_file_format::pem));
	REQUIRE_FALSE(ctx.use_private_key(leaf.key_pem, corosio::tls_file_format::pem));
	return ctx;
}

// Serves `clear` in clear, the last step of which answers a StartTLS
// request, then runs the server side of the handshake and serves `secure`
// over TLS. With `clear` empty: an ldaps:// server.
auto serve_upgrading(corosio::tcp_acceptor &acc,
  corosio::tls_context ctx,
  std::vector<step> clear,
  std::vector<step> secure,
  server_log &log) -> capy::task<void>
{
	auto [ec, peer] = co_await acc.accept();
	if (ec) {
		log.error = "accept: " + ec.message();
		co_return;
	}
	co_await serve_script(net::transport::wrap(socket_ref{ &peer }, "server"), std::move(clear), log);
	if (!log.error.empty()) {
		co_return;
	}
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
	auto operator=(const tls_mock &) -> tls_mock & = delete;

	~tls_mock()
	{
		conn.close();
		acc.close();
		drive(ioc);
	}

	// `scheme` "ldaps": TLS from the start (tls_mock({}, secure)).
	auto connect(ldap::connection_options o = {}, std::string_view scheme = "ldap") -> ldap::result<void>
	{
		o.tls.ca_pem = std::pmr::string(pki().ca_pem());
		auto u = ldap::url::parse(std::string(scheme) + "://127.0.0.1:" + std::to_string(acc.local_endpoint().port()));
		REQUIRE(u.has_value());
		auto c = finish(ioc, ldap::connect(ioc, *u, o));
		if (!c) {
			return std::unexpected(std::move(c.error()));
		}
		conn = std::move(*c);
		return {};
	}

	template<class T> auto run(capy::task<T> t) -> T { return finish(ioc, std::move(t)); }

	void check_server()
	{
		drive_until(ioc, [this] { return server.done(); });
		CHECK_THAT(log.error, IsEmpty());
		CHECK(server.done());
	}
};

auto upgraded() -> ldap::connection_options { return { .start_tls = true }; }

// The ModifyRequest of unicodePwd that ad::change_password and
// ad::reset_password send for jdoe.
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

TEST_CASE("ad::change_password: over StartTLS, unicodePwd modifies", "[net][password][ad]")
{
	tls_mock f({ answer({ start_tls_ok(1) }) }, { answer({ modify_result(2) }), answer({ modify_result(3) }) });
	REQUIRE(f.connect(upgraded()).has_value());
	REQUIRE(f.conn.is_tls());
	CHECK(f.run(ldap::ad::change_password(f.conn, jdoe, std::string(old_pw), std::string(new_pw))).has_value());
	CHECK(f.run(ldap::ad::reset_password(f.conn, jdoe, std::string(new_pw))).has_value());
	f.check_server();

	REQUIRE(f.log.received.size() == 3);
	// A change deletes the old value and adds the new one, in one modify; a
	// reset replaces.
	check_change_shape(f.log.received[1]);
	check_reset_shape(f.log.received[2]);
}

TEST_CASE("ad::change_password: over ldaps://, unicodePwd modifies", "[net][password][ad]")
{
	tls_mock f({}, { answer({ modify_result(1) }), answer({ modify_result(2) }) });
	REQUIRE(f.connect({}, "ldaps").has_value());
	REQUIRE(f.conn.is_tls());
	CHECK(f.run(ldap::ad::change_password(f.conn, jdoe, std::string(old_pw), std::string(new_pw))).has_value());
	CHECK(f.run(ldap::ad::reset_password(f.conn, jdoe, std::string(new_pw))).has_value());
	f.check_server();

	REQUIRE(f.log.received.size() == 2);
	check_change_shape(f.log.received[0]);
	check_reset_shape(f.log.received[1]);
}

TEST_CASE("ad::change_password: without TLS, refused before sending", "[net][password][ad]")
{
	mock_ldap m;
	m.serve({});
	auto r = m.run(ldap::ad::reset_password(m.conn, jdoe, std::string(new_pw)));
	REQUIRE_FALSE(r.has_value());
	CHECK(r.error().code == client_errc::tls_required);
	CHECK(r.error().code == ldap::cond::access_denied);
	CHECK(std::string(r.error().context)
		  == "reset password " + jdoe_context
			   + ": Active Directory sets unicodePwd only over an encrypted connection (ldaps://, start_tls() or a SASL "
				 "confidentiality layer)");
	auto c = m.run(ldap::ad::change_password(m.conn, jdoe, std::string(old_pw), std::string(new_pw)));
	REQUIRE_FALSE(c.has_value());
	CHECK(c.error().code == client_errc::tls_required);
	check_no_password(c.error());
	CHECK(m.conn.is_open());
	m.check_server();
	CHECK(m.log.received.empty());
}

namespace {

// Reads what the server's end receives, up to `limit` bytes (the client's
// first write, at least) or, with no limit, until the client hangs up.
auto raw_bytes(corosio::tcp_socket &peer, std::size_t limit = 0) -> capy::task<std::string>
{
	std::string out;
	char buf[4096];
	while (true) {
		auto [ec, n] = co_await peer.read_some(capy::mutable_buffer(buf, sizeof buf));
		out.append(buf, n);
		if (ec || n == 0 || (limit != 0 && out.size() >= limit)) {
			co_return out;
		}
	}
}

// `bytes` is whole TLS records, all of them handshake records (content
// type 22): no LDAP message in clear.
auto only_tls_handshake_records(std::string_view bytes) -> bool
{
	while (!bytes.empty()) {
		if (bytes.size() < 5 || bytes[0] != '\x16') {
			return false;
		}
		const std::size_t length =
		  (std::size_t{ static_cast<unsigned char>(bytes[3]) } * 256) + static_cast<unsigned char>(bytes[4]);
		if (bytes.size() < 5 + length) {
			return false;
		}
		bytes.remove_prefix(5 + length);
	}
	return true;
}

}// namespace

// StartTLS accepted, the client's handshake under way: the transport
// already has its TLS layer (it is undone if the handshake fails), but
// is_tls() is false until start_tls() returns. A password change then is
// refused, and nothing is sent.
TEST_CASE("ad::change_password: during StartTLS, refused before sending", "[net][password][starttls]")
{
	outcome<ldap::result<void>> tls;// outlive `m`
	outcome<std::string> hello;
	outcome<std::string> rest;
	tcp_mock_ldap m;
	m.serve({ step{} });// reads the StartTLS request, answered below
	spawn(m.ioc, m.conn.start_tls({ .ca_pem = std::pmr::string(pki().ca_pem()) }), tls);
	m.check_server();
	spawn(m.ioc, raw_bytes(m.peer, 1), hello);
	while (m.ioc.poll() != 0) {}// parks the reader and the server's read
	m.ioc.restart();
	const std::string accepted = bytes_of(start_tls_ok(1));
	REQUIRE(raw_send(m.peer.native_handle(), accepted));
	// The ClientHello arrives: the client waits for the server's answer.
	drive_until(m.ioc, [&hello] { return hello.done(); });
	REQUIRE(hello.done());
	REQUIRE_FALSE(tls.done());
	CHECK_FALSE(m.conn.is_tls());

	auto reset = m.run(ldap::ad::reset_password(m.conn, jdoe, std::string(new_pw)));
	REQUIRE_FALSE(reset.has_value());
	CHECK(reset.error().code == client_errc::tls_required);
	CHECK(std::string(reset.error().context)
		  == "reset password " + jdoe_context
			   + ": Active Directory sets unicodePwd only over an encrypted connection (ldaps://, start_tls() or a SASL "
				 "confidentiality layer)");
	auto change = m.run(ldap::ad::change_password(m.conn, jdoe, std::string(old_pw), std::string(new_pw)));
	REQUIRE_FALSE(change.has_value());
	CHECK(change.error().code == client_errc::tls_required);
	check_no_password(change.error());
	REQUIRE_FALSE(tls.done());

	m.conn.close();
	spawn(m.ioc, raw_bytes(m.peer), rest);
	drive_until(m.ioc, [&] { return tls.done() && rest.done(); });
	REQUIRE_FALSE(tls.get().has_value());
	CHECK(tls.get().error().code == client_errc::not_connected);
	// After the StartTLS request: the handshake's records, nothing else.
	CHECK(only_tls_handshake_records(hello.get() + rest.get()));
	REQUIRE(m.log.received.size() == 1);
	const auto *x = std::get_if<ldap::extended_request>(&m.log.received[0].op);
	REQUIRE(x != nullptr);
	CHECK(x->request_name == ldap::start_tls_oid);
}

TEST_CASE("ad::change_password: refused before sending", "[net][password][ad]")
{
	mock_ldap m;
	m.serve({});
	const auto invalid = std::make_error_code(std::errc::invalid_argument);
	auto no_new = m.run(ldap::ad::change_password(m.conn, jdoe, std::string(old_pw), ""));
	REQUIRE_FALSE(no_new.has_value());
	CHECK(no_new.error().code == invalid);
	CHECK(std::string(no_new.error().context) == "change password " + jdoe_context + ": empty new password");
	auto no_old = m.run(ldap::ad::change_password(m.conn, jdoe, "", std::string(new_pw)));
	REQUIRE_FALSE(no_old.has_value());
	CHECK(no_old.error().code == invalid);
	CHECK(std::string(no_old.error().context)
		  == "change password " + jdoe_context + ": empty old password (reset_password() sets one without it)");
	auto reset = m.run(ldap::ad::reset_password(m.conn, jdoe, ""));
	REQUIRE_FALSE(reset.has_value());
	CHECK(reset.error().code == invalid);
	auto no_dn = m.run(ldap::ad::reset_password(m.conn, {}, std::string(new_pw)));
	REQUIRE_FALSE(no_dn.has_value());
	CHECK(no_dn.error().code == client_errc::invalid_dn);
	CHECK(std::string(no_dn.error().context) == "reset password \"\": Active Directory needs the user's DN");
	// Ill-formed UTF-8 cannot become UTF-16.
	auto bad = m.run(ldap::ad::reset_password(m.conn, jdoe, "S3cret\xFF"));
	REQUIRE_FALSE(bad.has_value());
	CHECK(bad.error().code == client_errc::encode_error);
	CHECK(std::string(bad.error().context)
		  == "reset password " + jdoe_context + ": Active Directory password value: the password is not valid UTF-8");
	auto bad_old = m.run(ldap::ad::change_password(m.conn, jdoe, "0ld\xFF", std::string(new_pw)));
	REQUIRE_FALSE(bad_old.has_value());
	CHECK(bad_old.error().code == client_errc::encode_error);
	CHECK(std::string(bad_old.error().context)
		  == "change password " + jdoe_context + ": Active Directory password value: the password is not valid UTF-8");
	CHECK(m.conn.is_open());
	m.check_server();
	CHECK(m.log.received.empty());

	ldap::connection none;
	auto closed = m.run(ldap::ad::change_password(none, jdoe, std::string(old_pw), std::string(new_pw)));
	REQUIRE_FALSE(closed.has_value());
	CHECK(closed.error().code == client_errc::not_connected);
	CHECK(std::string(closed.error().context) == "change password " + jdoe_context + ": modify unicodePwd");
}

TEST_CASE("ad::change_password: server errors, AD diagnostics explained", "[net][password][ad]")
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
		answer({ modify_result(5, 50, "insufficient access") }),
		answer({ modify_result(6, 50, "00000005: SecErr: DSID-031A11E5, problem 4003 (INSUFF_ACCESS_RIGHTS)") }),
		answer({ modify_result(7, 19, "00000775: account locked out") }),
		answer({ modify_result(8, 19, "0000002G: not hexadecimal") }) });
	REQUIRE(f.connect(upgraded()).has_value());
	const std::string context = "change password " + jdoe_context + ": modify unicodePwd";

	auto weak = f.run(ldap::ad::change_password(f.conn, jdoe, std::string(old_pw), std::string(new_pw)));
	REQUIRE_FALSE(weak.has_value());
	CHECK(weak.error().code == ldap::errc::constraint_violation);
	CHECK(std::string(weak.error().context)
		  == context
			   + ": the new password does not meet the password policy (length, complexity, history or minimum "
				 "age) (Active Directory error 0000052D)");
	CHECK(std::string(weak.error().diagnostic) == policy);// kept as sent
	check_no_password(weak.error());

	auto old = f.run(ldap::ad::change_password(f.conn, jdoe, std::string(old_pw), std::string(new_pw)));
	REQUIRE_FALSE(old.has_value());
	CHECK(
	  std::string(old.error().context) == context + ": the old password is wrong (Active Directory error 00000056)");
	CHECK(std::string(old.error().diagnostic) == wrong_old);

	// Codes it does not explain, and diagnostics that are not AD's.
	auto other = f.run(ldap::ad::change_password(f.conn, jdoe, std::string(old_pw), std::string(new_pw)));
	REQUIRE_FALSE(other.has_value());
	CHECK(other.error().code == ldap::errc::unwilling_to_perform);
	CHECK(std::string(other.error().context) == context);
	auto plain = f.run(ldap::ad::change_password(f.conn, jdoe, std::string(old_pw), std::string(new_pw)));
	REQUIRE_FALSE(plain.has_value());
	CHECK(std::string(plain.error().context) == context);
	auto denied = f.run(ldap::ad::change_password(f.conn, jdoe, std::string(old_pw), std::string(new_pw)));
	REQUIRE_FALSE(denied.has_value());
	CHECK(std::string(denied.error().context)
		  == context + ": not allowed to set this user's password (Active Directory error 00000005)");
	auto locked = f.run(ldap::ad::change_password(f.conn, jdoe, std::string(old_pw), std::string(new_pw)));
	REQUIRE_FALSE(locked.has_value());
	CHECK(
	  std::string(locked.error().context) == context + ": the account is locked out (Active Directory error 00000775)");
	auto not_hex = f.run(ldap::ad::change_password(f.conn, jdoe, std::string(old_pw), std::string(new_pw)));
	REQUIRE_FALSE(not_hex.has_value());
	CHECK(std::string(not_hex.error().context) == context);
	CHECK(f.conn.is_open());
	f.check_server();
}
