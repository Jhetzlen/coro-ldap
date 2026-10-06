// ldap::connection against a scripted in-process LDAP server: the server end
// decodes requests with origin::client and answers with encoded responses
// from a script, over a Unix socket pair (and once over loopback TCP,
// through ldap::connect).
//
// Not capy::test::stream: at the pinned Capy commit its wake() posts the
// parked continuation by reference and then clears the handle while it is
// still queued, so a reader woken by the peer resumes a null handle. Its
// provide()-before-read use in message_io_tests.cpp never parks a reader.
#include "../counting_resource.hpp"
#include "jhetz/ldap/connection.hpp"
#include "jhetz/ldap/net/message_io.hpp"
#include "net_test_support.hpp"

#include <boost/capy/buffers.hpp>
#include <boost/capy/cond.hpp>
#include <boost/corosio/endpoint.hpp>
#include <boost/corosio/ipv4_address.hpp>
#include <boost/corosio/local_connect_pair.hpp>
#include <boost/corosio/local_stream_socket.hpp>
#include <boost/corosio/tcp_acceptor.hpp>
#include <boost/corosio/tcp_socket.hpp>

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <cstdint>
#include <functional>
#include <memory_resource>
#include <optional>
#include <span>
#include <stop_token>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

namespace ldap = jhetz::ldap;
namespace net = jhetz::ldap::net;
namespace capy = boost::capy;
namespace corosio = boost::corosio;
using namespace jhetz::ldap::test;
using Catch::Matchers::ContainsSubstring;
using Catch::Matchers::StartsWith;
using ldap::client_errc;
using ldap::errc;

namespace {

const net::read_options as_server{ .decode = { .from = ldap::origin::client } };
constexpr std::string_view admin = "cn=admin,dc=example,dc=org";
constexpr std::string_view people = "ou=people,dc=example,dc=org";

// ---------------------------------------------------------------- messages

ldap::message bind_resp(std::int32_t id, std::int32_t code = 0, std::string_view diagnostic = {})
{
	return ldap::message{ id, ldap::bind_response{ ldap::ldap_result{ code, "", diagnostic } } };
}

ldap::message entry_msg(std::int32_t id, std::string_view dn, std::string_view cn)
{
	return ldap::message{
		id,
		ldap::search_result_entry{ dn,
		  { ldap::partial_attribute{ "cn", { cn } }, ldap::partial_attribute{ "objectClass", { "person", "top" } } } }
	};
}

ldap::entry expected_entry(std::string_view dn, std::string_view cn)
{
	return ldap::entry::from(std::get<ldap::search_result_entry>(entry_msg(1, dn, cn).op));
}

ldap::message done_msg(std::int32_t id,
  std::int32_t code = 0,
  std::string_view matched = {},
  std::string_view diagnostic = {},
  std::initializer_list<std::string_view> referrals = {})
{
	return ldap::message{ id, ldap::search_result_done{ ldap::ldap_result{ code, matched, diagnostic, referrals } } };
}

ldap::message ref_msg(std::int32_t id, ldap::string_list uris)
{
	return ldap::message{ id, ldap::search_result_reference{ std::move(uris) } };
}

// ---------------------------------------------------------------- server

// One step of a server script: optionally wait for one request, then send
// `replies` (each written separately), then optionally hang up.
struct step
{
	bool read_request = true;
	std::vector<std::string> replies{};
	bool close_after = false;
};

step answer(std::initializer_list<ldap::message> replies, bool close_after = false)
{
	step s;
	for (const auto &m : replies) s.replies.push_back(bytes_of(m));
	s.close_after = close_after;
	return s;
}

struct server_log
{
	std::vector<ldap::message> received{};
	std::string error{};
	std::function<void()> hang_up{};
};

capy::task<void> serve_script(net::transport t, std::vector<step> script, server_log &log)
{
	net::read_buffer buf;
	for (auto &st : script) {
		if (st.read_request) {
			auto r = co_await net::read_message(t, buf, as_server);
			if (!r) {
				log.error = "server read: " + std::string(r.error().message());
				co_return;
			}
			log.received.push_back(std::move(*r));
		}
		for (const auto &bytes : st.replies) {
			if (auto w = co_await net::write_bytes(t, std::as_bytes(std::span(bytes))); !w) {
				log.error = "server write: " + std::string(w.error().message());
				co_return;
			}
		}
		if (st.close_after) {
			log.hang_up();
			co_return;
		}
	}
}

// Forwards to a socket owned elsewhere, so the test can still close it
// (transport::close() does nothing on a wrapped stream).
struct socket_ref
{
	corosio::local_stream_socket *s;
	template<capy::MutableBufferSequence MB> auto read_some(MB buffers) { return s->read_some(buffers); }
	template<capy::ConstBufferSequence CB> auto write_some(CB buffers) { return s->write_some(buffers); }
};

// Two connected Unix domain sockets.
struct socket_pair
{
	corosio::local_stream_socket client;
	corosio::local_stream_socket server;

	explicit socket_pair(corosio::io_context &ioc) : client(ioc), server(ioc)
	{
		const auto ec = corosio::connect_pair(client, server);
		if (ec) throw std::system_error(ec, "connect_pair");
	}
};

// A connection over a socket pair, and a scripted server on the other end.
struct mock_ldap
{
	corosio::io_context ioc{};
	socket_pair sockets{ ioc };
	ldap::connection conn{};
	server_log log{};
	outcome<void> server{};

	explicit mock_ldap(ldap::connection_options options = {},
	  std::pmr::memory_resource *mr = std::pmr::get_default_resource())
	  : conn(net::transport::wrap(socket_ref{ &sockets.client }, "mock"), options, mr)
	{
		log.hang_up = [this] { sockets.server.close(); };
	}

	mock_ldap(const mock_ldap &) = delete;
	mock_ldap &operator=(const mock_ldap &) = delete;

	~mock_ldap()
	{
		// Wake whatever still waits, so no coroutine is left suspended.
		sockets.client.close();
		sockets.server.close();
		drive(ioc);
	}

	void serve(std::vector<step> script)
	{
		spawn(ioc,
		  serve_script(net::transport::wrap(socket_ref{ &sockets.server }, "server"), std::move(script), log),
		  server);
	}

	// Runs `t` until it finishes; the server, parked on its next request,
	// is left as is.
	template<class T> T run(capy::task<T> t)
	{
		outcome<T> out;
		spawn(ioc, std::move(t), out);
		drive_until(ioc, [&out] { return out.done(); });
		if constexpr (std::is_void_v<T>)
			out.get();
		else
			return std::move(out.get());
	}

	// The script ran to its end without errors.
	void check_server()
	{
		drive_until(ioc, [this] { return server.done(); });
		CHECK(log.error == "");
		CHECK(server.done());
	}
};

ldap::search_params people_search()
{
	return { .base = ldap::dn{ "ou=people,dc=example,dc=org" }, .filter = ldap::filters::attr("uid") == "jdoe" };
}

// Reads a stream to its end: the entries, or the first error.
capy::task<ldap::result<std::vector<ldap::entry>>> drain_stream(ldap::search_stream &s)
{
	std::vector<ldap::entry> out;
	while (true) {
		auto e = co_await s.next();
		if (!e) co_return std::unexpected(std::move(e.error()));
		if (!*e) co_return out;
		out.push_back(std::move(**e));
	}
}

}// namespace

// ---------------------------------------------------------------- bind

TEST_CASE("connection: simple bind", "[net][connection]")
{
	mock_ldap m;
	m.serve({ answer({ bind_resp(1) }) });
	auto r = m.run(m.conn.simple_bind(ldap::dn{ "cn=admin,dc=example,dc=org" }, "secret"));
	REQUIRE(r.has_value());
	m.check_server();
	REQUIRE(m.log.received.size() == 1);
	CHECK(m.log.received[0] == bind_request_msg(1));// version 3, simple auth, id 1
	CHECK(m.conn.is_open());
	CHECK(m.conn.name() == "mock");
}

TEST_CASE("connection: bind errors keep the connection usable", "[net][connection]")
{
	mock_ldap m;
	m.serve({ answer({ bind_resp(1, 49, "bad password") }), answer({ bind_resp(2) }) });
	auto bad = m.run(m.conn.simple_bind(ldap::dn{ "cn=admin,dc=example,dc=org" }, "wrong"));
	REQUIRE_FALSE(bad.has_value());
	CHECK(bad.error().code == errc::invalid_credentials);
	CHECK(bad.error().code == ldap::cond::auth_failed);
	CHECK(bad.error().diagnostic == "bad password");
	CHECK(bad.error().context == "bind cn=admin,dc=example,dc=org");
	CHECK(m.conn.is_open());

	auto good = m.run(m.conn.simple_bind(ldap::dn{ "cn=admin,dc=example,dc=org" }, "secret"));
	CHECK(good.has_value());
	m.check_server();
	REQUIRE(m.log.received.size() == 2);
	CHECK(m.log.received[1].id == 2);
}

TEST_CASE("connection: anonymous and unauthenticated binds", "[net][connection]")
{
	mock_ldap m;
	m.serve({ answer({ bind_resp(1) }) });
	// A name without a password is refused before anything is sent.
	auto unauth = m.run(m.conn.simple_bind(ldap::dn{ "cn=admin,dc=example,dc=org" }, ""));
	REQUIRE_FALSE(unauth.has_value());
	CHECK(unauth.error().code == client_errc::unauthenticated_bind);
	CHECK(unauth.error().code == ldap::cond::auth_failed);
	CHECK(m.log.received.empty());
	CHECK(m.conn.is_open());

	auto anon = m.run(m.conn.simple_bind(ldap::dn{}, ""));
	REQUIRE(anon.has_value());
	m.check_server();
	REQUIRE(m.log.received.size() == 1);
	CHECK(m.log.received[0] == ldap::message{ 1, ldap::bind_request{ 3, "", ldap::simple_auth{ "" } } });
}

// ---------------------------------------------------------------- search

TEST_CASE("connection: search sends the request and collects the entries", "[net][connection]")
{
	mock_ldap m;
	m.serve({ answer({ entry_msg(1, "uid=a,ou=people,dc=example,dc=org", "A"),
	  ref_msg(1, { "ldap://other.example.org/ou=people,dc=example,dc=org" }),
	  entry_msg(1, "uid=b,ou=people,dc=example,dc=org", "B"),
	  done_msg(1) }) });

	auto r = m.run(m.conn.search({
	  .base = ldap::dn{ "ou=people,dc=example,dc=org" },
	  .scope = ldap::search_scope::single_level,
	  .filter = ldap::filters::attr("objectClass") == "person" && ldap::filters::attr("uid").present(),
	  .attributes = { "cn", "mail" },
	  .deref = ldap::deref_aliases::always,
	  .size_limit = 10,
	  .time_limit = std::chrono::seconds(5),
	  .types_only = false,
	  .controls = { ldap::control{ "1.2.3.4", true, "v" } },
	}));
	REQUIRE(r.has_value());
	REQUIRE(r->size() == 2);
	CHECK((*r)[0] == expected_entry("uid=a,ou=people,dc=example,dc=org", "A"));
	CHECK((*r)[1] == expected_entry("uid=b,ou=people,dc=example,dc=org", "B"));
	m.check_server();

	ldap::search_request wire{ people,
		ldap::search_scope::single_level,
		ldap::deref_aliases::always,
		10,
		5,
		false,
		ldap::filter::raw("(&(objectClass=person)(uid=*))").value(),
		{ "cn", "mail" } };
	REQUIRE(m.log.received.size() == 1);
	CHECK(m.log.received[0] == ldap::message{ 1, wire, { ldap::control{ "1.2.3.4", true, "v" } } });
}

TEST_CASE("connection: search defaults", "[net][connection]")
{
	mock_ldap m;
	m.serve({ answer({ done_msg(1) }) });
	auto r = m.run(m.conn.search({}));
	REQUIRE(r.has_value());
	CHECK(r->empty());
	m.check_server();
	REQUIRE(m.log.received.size() == 1);
	// Root DSE base, subtree, (objectClass=*), all user attributes, no limits.
	CHECK(
	  m.log.received[0]
	  == ldap::message{ 1,
		ldap::search_request{ "", ldap::search_scope::whole_subtree, ldap::filters::attr("objectClass").present() } });
}

TEST_CASE("connection: search result errors", "[net][connection]")
{
	mock_ldap m;
	m.serve({ answer({ done_msg(1, 32, "dc=example,dc=org", "no such entry") }),
	  answer({ done_msg(2, 10, "", "go elsewhere", { "ldap://b.example.org/ou=missing,dc=example,dc=org" }) }),
	  answer({ done_msg(3) }) });

	auto r = m.run(m.conn.search({ .base = ldap::dn{ "ou=missing,dc=example,dc=org" } }));
	REQUIRE_FALSE(r.has_value());
	CHECK(r.error().code == errc::no_such_object);
	CHECK(r.error().code == ldap::cond::not_found);
	CHECK(r.error().matched_dn == "dc=example,dc=org");
	CHECK(r.error().diagnostic == "no such entry");
	CHECK(r.error().context == "search ou=missing,dc=example,dc=org");
	CHECK(m.conn.is_open());

	auto referral = m.run(m.conn.search({ .base = ldap::dn{ "ou=missing,dc=example,dc=org" } }));
	REQUIRE_FALSE(referral.has_value());
	CHECK(referral.error().code == errc::referral);
	CHECK(referral.error().referrals == ldap::string_list{ "ldap://b.example.org/ou=missing,dc=example,dc=org" });
	CHECK_FALSE(referral.error().matched_dn.has_value());

	// Still usable.
	CHECK(m.run(m.conn.search({})).has_value());
	m.check_server();
}

TEST_CASE("connection: requests that cannot be encoded are not sent", "[net][connection]")
{
	mock_ldap m;
	m.serve({ answer({ done_msg(1) }) });

	auto negative = m.run(m.conn.search({ .size_limit = -1 }));
	REQUIRE_FALSE(negative.has_value());
	CHECK(negative.error().code == client_errc::encode_error);

	auto too_long = m.run(m.conn.search({ .time_limit = std::chrono::seconds(std::int64_t{ 1 } << 31) }));
	REQUIRE_FALSE(too_long.has_value());
	CHECK(too_long.error().code == client_errc::encode_error);
	CHECK_THAT(std::string(too_long.error().context), StartsWith("search \"\": time_limit"));

	auto empty_filter = m.run(m.conn.search({ .filter = ldap::filter{} }));
	REQUIRE_FALSE(empty_filter.has_value());
	CHECK(empty_filter.error().code == client_errc::invalid_filter);

	CHECK(m.conn.is_open());
	CHECK(m.log.received.empty());
	// Failed encodes do not use up message ids: the next request gets 1.
	CHECK(m.run(m.conn.search({})).has_value());
	m.check_server();
	REQUIRE(m.log.received.size() == 1);
	CHECK(m.log.received[0].id == 1);
}

// ---------------------------------------------------------------- streaming

TEST_CASE("connection: search_stream yields entries one at a time", "[net][connection]")
{
	mock_ldap m;
	ldap::message done = done_msg(1);
	done.controls.push_back(*ldap::encode_paged_results({ 0, "cookie" }));
	m.serve({ answer({ entry_msg(1, "uid=a,ou=people,dc=example,dc=org", "A"),
	  ref_msg(1, { "ldap://r1.example.org/", "ldap://r2.example.org/" }),
	  entry_msg(1, "uid=b,ou=people,dc=example,dc=org", "B"),
	  done }) });

	auto s = m.run(m.conn.search_stream(people_search()));
	REQUIRE(s.has_value());
	CHECK_FALSE(s->done());

	auto a = m.run(s->next());
	REQUIRE(a.has_value());
	REQUIRE(a->has_value());
	CHECK(**a == expected_entry("uid=a,ou=people,dc=example,dc=org", "A"));
	CHECK(s->references().empty());

	auto b = m.run(s->next());
	REQUIRE(b.has_value());
	REQUIRE(b->has_value());
	CHECK(**b == expected_entry("uid=b,ou=people,dc=example,dc=org", "B"));
	CHECK(s->references() == ldap::string_list{ "ldap://r1.example.org/", "ldap://r2.example.org/" });

	auto end = m.run(s->next());
	REQUIRE(end.has_value());
	CHECK_FALSE(end->has_value());
	CHECK(s->done());
	REQUIRE(s->controls().size() == 1);
	CHECK(ldap::decode_paged_results(s->controls()[0])->cookie == "cookie");

	// The end repeats without I/O.
	auto again = m.run(s->next());
	REQUIRE(again.has_value());
	CHECK_FALSE(again->has_value());
	m.check_server();
}

TEST_CASE("connection: search_stream keeps the entries before an error", "[net][connection]")
{
	mock_ldap m;
	m.serve({ answer({ entry_msg(1, "uid=a,ou=people,dc=example,dc=org", "A"), done_msg(1, 4, "", "limit") }),
	  answer({ bind_resp(2) }) });
	auto s = m.run(m.conn.search_stream(people_search()));
	REQUIRE(s.has_value());
	auto entries = m.run(drain_stream(*s));
	REQUIRE_FALSE(entries.has_value());
	CHECK(entries.error().code == errc::size_limit_exceeded);
	CHECK(s->done());
	auto a = m.run(s->next());// the error repeats
	REQUIRE_FALSE(a.has_value());
	CHECK(a.error().code == errc::size_limit_exceeded);

	// The search is over, so the connection is free again.
	CHECK(m.run(m.conn.simple_bind(ldap::dn{ "cn=admin,dc=example,dc=org" }, "secret")).has_value());
	m.check_server();
}

TEST_CASE("connection: one operation at a time", "[net][connection]")
{
	mock_ldap m;
	m.serve(
	  { answer({ entry_msg(1, "uid=a,ou=people,dc=example,dc=org", "A"), done_msg(1) }), answer({ bind_resp(2) }) });
	auto s = m.run(m.conn.search_stream(people_search()));
	REQUIRE(s.has_value());

	auto busy = m.run(m.conn.simple_bind(ldap::dn{ "cn=admin,dc=example,dc=org" }, "secret"));
	REQUIRE_FALSE(busy.has_value());
	CHECK(busy.error().code == client_errc::operation_in_progress);
	auto busy_search = m.run(m.conn.search({}));
	REQUIRE_FALSE(busy_search.has_value());
	CHECK(busy_search.error().code == client_errc::operation_in_progress);

	auto entries = m.run(drain_stream(*s));
	REQUIRE(entries.has_value());
	CHECK(entries->size() == 1);
	CHECK(m.run(m.conn.simple_bind(ldap::dn{ "cn=admin,dc=example,dc=org" }, "secret")).has_value());
	m.check_server();
	REQUIRE(m.log.received.size() == 2);
}

TEST_CASE("connection: a stream destroyed early is drained by the next operation", "[net][connection]")
{
	mock_ldap m;
	m.serve({ answer({ entry_msg(1, "uid=a,ou=people,dc=example,dc=org", "A"),
				entry_msg(1, "uid=b,ou=people,dc=example,dc=org", "B"),
				ref_msg(1, { "ldap://r.example.org/" }),
				done_msg(1, 4) }),
	  answer({ bind_resp(2) }) });
	{
		auto s = m.run(m.conn.search_stream(people_search()));
		REQUIRE(s.has_value());
		auto a = m.run(s->next());
		REQUIRE(a.has_value());
		REQUIRE(a->has_value());
	}// the rest of the search (B, the reference, the done) is still coming
	auto b = m.run(m.conn.simple_bind(ldap::dn{ "cn=admin,dc=example,dc=org" }, "secret"));
	CHECK(b.has_value());
	m.check_server();
	REQUIRE(m.log.received.size() == 2);
	CHECK(m.log.received[1] == bind_request_msg(2));
}

TEST_CASE("connection: moving connections and streams", "[net][connection]")
{
	SECTION("a stream survives moves of itself and its connection")
	{
		mock_ldap m;
		m.serve({ answer({ entry_msg(1, "uid=a,ou=people,dc=example,dc=org", "A"), done_msg(1) }) });
		auto s = m.run(m.conn.search_stream(people_search()));
		REQUIRE(s.has_value());
		ldap::connection moved = std::move(m.conn);
		CHECK_FALSE(m.conn.is_open());
		ldap::search_stream s2 = std::move(*s);
		ldap::search_stream s3;
		s3 = std::move(s2);
		auto entries = m.run(drain_stream(s3));
		REQUIRE(entries.has_value());
		CHECK(entries->size() == 1);
		m.check_server();
		// A default or moved-from stream and connection.
		ldap::search_stream empty;
		auto e = m.run(empty.next());
		REQUIRE_FALSE(e.has_value());
		CHECK(e.error().code == client_errc::not_connected);
		auto nc = m.run(m.conn.search({}));
		REQUIRE_FALSE(nc.has_value());
		CHECK(nc.error().code == client_errc::not_connected);
	}
	SECTION("a stream outliving its connection")
	{
		mock_ldap m;
		m.serve({ answer({ entry_msg(1, "uid=a,ou=people,dc=example,dc=org", "A"), done_msg(1) }) });
		auto s = m.run(m.conn.search_stream(people_search()));
		REQUIRE(s.has_value());
		m.conn = ldap::connection{};
		auto e = m.run(s->next());
		REQUIRE_FALSE(e.has_value());
		CHECK(e.error().code == client_errc::not_connected);
		CHECK(s->done());
	}
}

// ---------------------------------------------------------------- unbind

TEST_CASE("connection: unbind", "[net][connection]")
{
	mock_ldap m;
	m.serve({ answer({ bind_resp(1) }), step{} });
	REQUIRE(m.run(m.conn.simple_bind(ldap::dn{ "cn=admin,dc=example,dc=org" }, "secret")).has_value());
	auto u = m.run(m.conn.unbind());
	REQUIRE(u.has_value());
	CHECK_FALSE(m.conn.is_open());
	m.check_server();
	REQUIRE(m.log.received.size() == 2);
	CHECK(m.log.received[1] == ldap::message{ 2, ldap::unbind_request{} });

	auto after = m.run(m.conn.search({}));
	REQUIRE_FALSE(after.has_value());
	CHECK(after.error().code == client_errc::not_connected);
	CHECK(after.error().context == "search \"\": connection closed");
	auto twice = m.run(m.conn.unbind());
	REQUIRE_FALSE(twice.has_value());
	CHECK(twice.error().code == client_errc::not_connected);
	m.conn.close();// idempotent
}

TEST_CASE("connection: unbind with a stream open ends the stream", "[net][connection]")
{
	mock_ldap m;
	m.serve({ answer({ entry_msg(1, "uid=a,ou=people,dc=example,dc=org", "A") }), step{} });
	auto s = m.run(m.conn.search_stream(people_search()));
	REQUIRE(s.has_value());
	REQUIRE(m.run(s->next()).has_value());
	REQUIRE(m.run(m.conn.unbind()).has_value());
	auto e = m.run(s->next());
	REQUIRE_FALSE(e.has_value());
	CHECK(e.error().code == client_errc::not_connected);
	m.check_server();
	REQUIRE(m.log.received.size() == 2);
	CHECK(std::holds_alternative<ldap::unbind_request>(m.log.received[1].op));
}

TEST_CASE("connection: message ids increase per request", "[net][connection]")
{
	mock_ldap m;
	m.serve({ answer({ bind_resp(1) }),
	  answer({ done_msg(2) }),
	  answer({ entry_msg(3, "uid=a,ou=people,dc=example,dc=org", "A"), done_msg(3) }),
	  answer({ bind_resp(4) }),
	  step{} });
	CHECK(m.run(m.conn.simple_bind(ldap::dn{ "cn=admin,dc=example,dc=org" }, "secret")).has_value());
	CHECK(m.run(m.conn.search({})).has_value());
	CHECK(m.run(m.conn.search(people_search())).has_value());
	CHECK(m.run(m.conn.simple_bind(ldap::dn{}, "")).has_value());
	CHECK(m.run(m.conn.unbind()).has_value());
	m.check_server();
	REQUIRE(m.log.received.size() == 5);
	for (std::size_t i = 0; i < m.log.received.size(); ++i)
		CHECK(m.log.received[i].id == static_cast<std::int32_t>(i + 1));
}

// ---------------------------------------------------------------- server misbehaving

TEST_CASE("connection: protocol violations close the connection", "[net][connection]")
{
	struct case_t
	{
		const char *name;
		std::vector<std::string> replies;
		std::error_code code;
		const char *context;
	};
	const std::vector<case_t> cases{
		{ "wrong message id",
		  { bytes_of(bind_resp(7)) },
		  client_errc::unexpected_response,
		  "bind cn=admin,dc=example,dc=org: BindResponse with message id 7, expected 1" },
		{ "wrong operation",
		  { bytes_of(done_msg(1)) },
		  client_errc::unexpected_response,
		  "bind cn=admin,dc=example,dc=org: SearchResultDone in response to a BindRequest" },
		{ "entry for a bind",
		  { bytes_of(entry_msg(1, "cn=x", "x")) },
		  client_errc::unexpected_response,
		  "bind cn=admin,dc=example,dc=org: SearchResultEntry in response to a BindRequest" },
		{ "request operation from the server",
		  { bytes_of(bind_request_msg(1)) },
		  client_errc::unsupported_operation,
		  nullptr },
		{ "id 0 that is not a notification",
		  { bytes_of(bind_resp(0)) },
		  client_errc::unexpected_response,
		  "bind cn=admin,dc=example,dc=org: BindResponse with message id 0" },
		{ "not a PDU", { std::string("\x04\x01\x00", 3) }, client_errc::decode_error, nullptr },
	};
	for (const auto &c : cases) {
		DYNAMIC_SECTION(c.name)
		{
			mock_ldap m;
			step s;
			s.replies = c.replies;
			m.serve({ s });
			auto r = m.run(m.conn.simple_bind(ldap::dn{ "cn=admin,dc=example,dc=org" }, "secret"));
			REQUIRE_FALSE(r.has_value());
			CHECK(r.error().code == c.code);
			CHECK(r.error().code == ldap::cond::protocol_error);
			if (c.context != nullptr) CHECK(r.error().context == c.context);
			CHECK_FALSE(m.conn.is_open());
			m.check_server();

			auto later = m.run(m.conn.search({}));
			REQUIRE_FALSE(later.has_value());
			CHECK(later.error().code == client_errc::not_connected);
			CHECK_THAT(
			  std::string(later.error().context), StartsWith("search \"\": connection closed by an earlier error: "));
		}
	}
}

TEST_CASE("connection: wrong operation inside a search", "[net][connection]")
{
	mock_ldap m;
	m.serve({ answer({ entry_msg(1, "uid=a,ou=people,dc=example,dc=org", "A"), bind_resp(1) }) });
	auto r = m.run(m.conn.search(people_search()));
	REQUIRE_FALSE(r.has_value());
	CHECK(r.error().code == client_errc::unexpected_response);
	CHECK(r.error().context == "search ou=people,dc=example,dc=org: BindResponse in response to a SearchRequest");
	CHECK_FALSE(m.conn.is_open());
}

TEST_CASE("connection: oversized responses are rejected from the header", "[net][connection]")
{
	mock_ldap m({ .max_message_size = 1024 });
	m.serve({ answer({ entry_msg(1, "uid=a,ou=people,dc=example,dc=org", std::string(2000, 'x')), done_msg(1) }) });
	auto r = m.run(m.conn.search(people_search()));
	REQUIRE_FALSE(r.has_value());
	CHECK(r.error().code == client_errc::message_too_large);
	CHECK_THAT(std::string(r.error().context), StartsWith("search ou=people,dc=example,dc=org: read mock"));
	CHECK_FALSE(m.conn.is_open());
}

TEST_CASE("connection: server closing mid-search", "[net][connection]")
{
	SECTION("between PDUs")
	{
		mock_ldap m;
		m.serve({ answer({ entry_msg(1, "uid=a,ou=people,dc=example,dc=org", "A") }, true) });
		auto r = m.run(m.conn.search(people_search()));
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == capy::cond::eof);
		CHECK(r.error().code == ldap::cond::connection_lost);
		CHECK(r.error().context == "search ou=people,dc=example,dc=org: read mock: connection closed");
		CHECK_FALSE(m.conn.is_open());
		m.check_server();
	}
	SECTION("inside a PDU, streaming")
	{
		mock_ldap m;
		const auto second = bytes_of(entry_msg(1, "uid=b,ou=people,dc=example,dc=org", "B"));
		step s = answer({ entry_msg(1, "uid=a,ou=people,dc=example,dc=org", "A") }, true);
		s.replies.push_back(second.substr(0, 10));
		m.serve({ s });
		auto st = m.run(m.conn.search_stream(people_search()));
		REQUIRE(st.has_value());
		auto a = m.run(st->next());
		REQUIRE(a.has_value());
		REQUIRE(a->has_value());
		auto b = m.run(st->next());
		REQUIRE_FALSE(b.has_value());
		CHECK(b.error().code == capy::cond::eof);
		CHECK_THAT(std::string(b.error().context), ContainsSubstring("connection closed after 10 of"));
		CHECK(st->done());
		auto later = m.run(m.conn.simple_bind(ldap::dn{}, ""));
		REQUIRE_FALSE(later.has_value());
		CHECK(later.error().code == client_errc::not_connected);
		CHECK(later.error().code == ldap::cond::connection_lost);
		CHECK_THAT(std::string(later.error().context), ContainsSubstring("connection closed after 10 of"));
	}
}

TEST_CASE("connection: unsolicited notifications and intermediate responses", "[net][connection]")
{
	SECTION("notice of disconnection")
	{
		mock_ldap m;
		m.serve({ answer({ ldap::message{ 0,
		  ldap::extended_response{
			ldap::ldap_result{ 52, "", "shutting down" }, std::string(ldap::notice_of_disconnection_oid) } } }) });
		auto r = m.run(m.conn.search(people_search()));
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == errc::unavailable);
		CHECK(r.error().code == ldap::cond::busy_or_unavailable);
		CHECK(r.error().diagnostic == "shutting down");
		CHECK(r.error().context == "search ou=people,dc=example,dc=org: notice of disconnection");
		CHECK_FALSE(m.conn.is_open());
	}
	SECTION("notice of disconnection claiming success")
	{
		mock_ldap m;
		m.serve({ answer({ ldap::message{
		  0, ldap::extended_response{ ldap::ldap_result{ 0 }, std::string(ldap::notice_of_disconnection_oid) } } }) });
		auto r = m.run(m.conn.simple_bind(ldap::dn{}, ""));
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == errc::unavailable);
		CHECK_FALSE(m.conn.is_open());
	}
	SECTION("other notifications and intermediate responses are skipped")
	{
		mock_ldap m;
		m.serve({ answer({ ldap::message{ 0, ldap::extended_response{ ldap::ldap_result{ 0 }, "1.2.3.4" } },
		  ldap::message{ 1, ldap::intermediate_response{ "1.2.3.5", "x" } },
		  entry_msg(1, "uid=a,ou=people,dc=example,dc=org", "A"),
		  ldap::message{ 1, ldap::intermediate_response{} },
		  done_msg(1) }) });
		auto r = m.run(m.conn.search(people_search()));
		REQUIRE(r.has_value());
		CHECK(r->size() == 1);
		CHECK(m.conn.is_open());
		m.check_server();
	}
}

TEST_CASE("connection: a cancelled operation closes the connection", "[net][connection]")
{
	mock_ldap m;
	m.serve({ step{} });// reads the request, never answers
	std::stop_source stop;
	outcome<ldap::result<std::vector<ldap::entry>>> out;
	auto search = [](ldap::connection &c) -> capy::task<ldap::result<std::vector<ldap::entry>>> {
		auto r = co_await c.search({});
		if (!r) co_return std::unexpected(std::move(r.error()));
		co_return std::vector<ldap::entry>(r->begin(), r->end());
	};
	capy::run_async(
	  m.ioc.get_executor(),
	  stop.get_token(),
	  [&out](ldap::result<std::vector<ldap::entry>> v) { out.value.emplace(std::move(v)); },
	  [&out](std::exception_ptr e) { out.error = e; })(search(m.conn));
	drive_until(m.ioc, [&m] { return !m.log.received.empty(); });
	REQUIRE(m.log.received.size() == 1);
	CHECK_FALSE(out.done());
	stop.request_stop();
	drive_until(m.ioc, [&out] { return out.done(); });
	auto &r = out.get();
	REQUIRE_FALSE(r.has_value());
	CHECK(r.error().code == capy::cond::canceled);
	CHECK(r.error().code == ldap::cond::canceled);
	CHECK_FALSE(m.conn.is_open());
	m.check_server();
}

// Deterministic fuzzing of the response path: a valid search answer with
// bytes flipped, dropped, inserted or cut off. The client must finish every
// time (the server hangs up at the end), with entries or an error; a
// transport or protocol error closes the connection, a server result error
// does not.
TEST_CASE("connection: mutated server responses", "[net][connection]")
{
	std::string wire;
	for (const auto &msg : { entry_msg(1, "uid=a,ou=people,dc=example,dc=org", "A"),
		   ref_msg(1, { "ldap://r.example.org/" }),
		   ldap::message{ 1, ldap::intermediate_response{ "1.2.3" } },
		   entry_msg(1, "uid=b,ou=people,dc=example,dc=org", std::string(300, 'b')),
		   done_msg(1, 0, "dc=example,dc=org", "ok") })
		wire += bytes_of(msg);

	std::uint64_t state = 0x9e3779b97f4a7c15u;
	auto next = [&state](std::size_t bound) {
		state = state * 6364136223846793005u + 1442695040888963407u;
		return static_cast<std::size_t>((state >> 33) % bound);
	};
	std::size_t ok = 0, server_error = 0, broken = 0;
	corosio::io_context ioc;
	for (int i = 0; i < 1500; ++i) {
		std::string bytes = wire;
		const std::size_t edits = 1 + next(4);
		for (std::size_t e = 0; e < edits && !bytes.empty(); ++e) {
			const std::size_t at = next(bytes.size());
			switch (next(4)) {
			case 0:
				bytes[at] = static_cast<char>(next(256));
				break;
			case 1:
				bytes.erase(at, 1 + next(8));
				break;
			case 2:
				bytes.insert(at, 1, static_cast<char>(next(256)));
				break;
			default:
				bytes.resize(at);
				break;
			}
		}
		socket_pair sp(ioc);
		server_log log;
		log.hang_up = [&sp] { sp.server.close(); };
		ldap::connection conn(net::transport::wrap(socket_ref{ &sp.client }, "mock"));
		step s;
		s.replies.push_back(bytes);
		s.close_after = true;
		outcome<void> server;
		spawn(ioc, serve_script(net::transport::wrap(socket_ref{ &sp.server }, "server"), { s }, log), server);
		auto r = run(ioc, conn.search(people_search()));
		if (r) {
			++ok;
		} else if (&r.error().code.category() == &ldap::result_category()) {
			++server_error;
			CHECK(conn.is_open());
		} else {
			++broken;
			CHECK_FALSE(conn.is_open());
		}
		sp.client.close();
		sp.server.close();
		drive(ioc);
		CHECK(server.done());
	}
	WARN("ok " << ok << " server_error " << server_error << " broken " << broken);
	CHECK(ok + server_error + broken == 1500);
	CHECK(broken > 0);
}

// ---------------------------------------------------------------- memory

TEST_CASE("connection: entries live on the resource given to search", "[net][connection][pmr]")
{
	counting_resource conn_mr;
	counting_resource results;
	{
		mock_ldap m({}, &conn_mr);
		m.serve({ answer({ entry_msg(1, "uid=a,ou=people,dc=example,dc=org", "A"),
					entry_msg(1, "uid=b,ou=people,dc=example,dc=org", "B"),
					done_msg(1) }),
		  answer({ entry_msg(2, "uid=c,ou=people,dc=example,dc=org", "C"), done_msg(2) }) });
		CHECK(conn_mr.allocations() > 0);// the connection's state

		auto r = m.run(m.conn.search(people_search(), &results));
		REQUIRE(r.has_value());
		REQUIRE(r->size() == 2);
		CHECK(r->get_allocator().resource() == &results);
		for (const auto &e : *r) {
			CHECK(e.get_allocator().resource() == &results);
			CHECK(e.attributes.get_allocator().resource() == &results);
			CHECK(e.attributes[0].values[0].get_allocator().resource() == &results);
		}
		CHECK((*r)[1] == expected_entry("uid=b,ou=people,dc=example,dc=org", "B"));

		std::pmr::monotonic_buffer_resource arena;
		auto s = m.run(m.conn.search_stream(people_search(), &arena));
		REQUIRE(s.has_value());
		auto c = m.run(s->next());
		REQUIRE(c.has_value());
		REQUIRE(c->has_value());
		CHECK((*c)->get_allocator().resource() == &arena);
		CHECK(m.run(s->next()).has_value());
		m.check_server();
	}
	CHECK(conn_mr.outstanding() == 0);
	CHECK(results.outstanding() == 0);
}

// ---------------------------------------------------------------- over TCP

namespace {

capy::task<void> accept_and_serve(corosio::tcp_acceptor &acc, std::vector<step> script, server_log &log)
{
	auto [ec, peer] = co_await acc.accept();
	if (ec) {
		log.error = "accept: " + ec.message();
		co_return;
	}
	net::transport t = net::transport::wrap(std::move(peer), "server");
	co_await serve_script(std::move(t), std::move(script), log);
}

capy::task<std::string> tcp_session(corosio::io_context &ioc, std::string text)
{
	auto u = ldap::url::parse(text);
	if (!u) co_return "url: " + std::string(u.error().message());
	auto c = co_await ldap::connect(ioc, *u, { .timeout = std::chrono::seconds(10) });
	if (!c) co_return "connect: " + std::string(c.error().message());
	if (!c->is_open() || c->name() != text) co_return "unexpected connection state";
	if (auto b = co_await c->simple_bind(ldap::dn{ "cn=admin,dc=example,dc=org" }, "secret"); !b)
		co_return "bind: " + std::string(b.error().message());
	auto r = co_await c->search(people_search());
	if (!r) co_return "search: " + std::string(r.error().message());
	if (r->size() != 1 || (*r)[0] != expected_entry("uid=jdoe,ou=people,dc=example,dc=org", "J"))
		co_return "unexpected entries";
	if (auto u2 = co_await c->unbind(); !u2) co_return "unbind: " + std::string(u2.error().message());
	co_return "";
}

}// namespace

TEST_CASE("connection: ldap::connect, bind, search and unbind over TCP", "[net][connection]")
{
	corosio::io_context ioc;
	corosio::tcp_acceptor acc(ioc, corosio::endpoint(corosio::ipv4_address::loopback(), 0), 16);
	const std::string url = "ldap://127.0.0.1:" + std::to_string(acc.local_endpoint().port());

	server_log log;
	log.hang_up = [] {};
	outcome<void> server;
	spawn(ioc,
	  accept_and_serve(acc,
		{ answer({ bind_resp(1) }),
		  answer({ entry_msg(2, "uid=jdoe,ou=people,dc=example,dc=org", "J"), done_msg(2) }),
		  step{} },
		log),
	  server);
	CHECK(run(ioc, tcp_session(ioc, url)) == "");
	CHECK(log.error == "");
	CHECK(server.done());
	REQUIRE(log.received.size() == 3);
	CHECK(std::holds_alternative<ldap::unbind_request>(log.received[2].op));
}

TEST_CASE("connection: ldap::connect failures", "[net][connection]")
{
	corosio::io_context ioc;
	std::uint16_t port = 0;
	{
		corosio::tcp_acceptor acc(ioc, corosio::endpoint(corosio::ipv4_address::loopback(), 0), 1);
		port = acc.local_endpoint().port();
	}// closed: nothing listens there now
	auto u = ldap::url::parse("ldap://127.0.0.1:" + std::to_string(port));
	REQUIRE(u.has_value());
	auto c = run(ioc, ldap::connect(ioc, *u));
	REQUIRE_FALSE(c.has_value());
	CHECK(c.error().code == std::errc::connection_refused);
	CHECK(c.error().code == ldap::cond::busy_or_unavailable);
	CHECK_THAT(std::string(c.error().context), StartsWith("connect ldap://127.0.0.1:"));

	auto bad = ldap::url::parse("ldap://127.0.0.1:1/??sub?(cn=x)?!unknown-ext");
	REQUIRE(bad.has_value());
	auto refused = run(ioc, ldap::connect(ioc, *bad));
	REQUIRE_FALSE(refused.has_value());
	CHECK(refused.error().code == client_errc::invalid_url);
}
