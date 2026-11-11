// ad::notification_search over a search_stream against the scripted mock
// server: the request AD expects, changes long after the operation
// timeout, and the AbandonRequest that ends it.
#include "jhetz/ldap/ad/controls.hpp"
#include "jhetz/ldap/connection.hpp"
#include "mock_ldap.hpp"
#include "net_test_support.hpp"

#include <boost/corosio/delay.hpp>

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <span>
#include <stdexcept>
#include <string>
#include <variant>

namespace ldap = jhetz::ldap;
namespace ad = jhetz::ldap::ad;
using namespace jhetz::ldap::test;

namespace {

auto send_later(net::transport t, ldap::message m, std::chrono::milliseconds after) -> capy::task<void>
{
	co_await corosio::delay(after);
	const auto bytes = bytes_of(m);
	if (auto w = co_await net::write_bytes(t, std::as_bytes(std::span(bytes))); !w) {
		throw std::runtime_error("write: " + std::string(w.error().message()));
	}
}

}// namespace

TEST_CASE("ad::notification_search: a change notification stream", "[net][ad][notification]")
{
	// The connection's timeout is 50 ms; the changes come after 150 ms.
	mock_ldap m({ .operation_timeout = std::chrono::milliseconds(50) });
	m.serve({ step{}, step{} });// the search, then the abandon
	const ldap::dn users{ "cn=users,dc=example,dc=org" };
	auto s = m.run(m.conn.search_stream(ad::notification_search(users, ldap::search_scope::single_level, { "cn" })));
	REQUIRE(s.has_value());

	for (const char *who : { "cn=a,cn=users,dc=example,dc=org", "cn=b,cn=users,dc=example,dc=org" }) {
		outcome<void> sent;
		spawn(m.ioc, send_later(m.server_end(), entry_msg(1, who, "x"), std::chrono::milliseconds(150)), sent);
		auto e = m.run(s->next());
		REQUIRE(e.has_value());
		REQUIRE(e->has_value());
		CHECK((*e)->dn == who);
		drive_until(m.ioc, [&sent] { return sent.done(); });
		sent.get();
	}
	CHECK_FALSE(s->done());

	*s = ldap::search_stream{};
	m.check_server();
	REQUIRE(m.log.received.size() == 2);
	const auto *request = std::get_if<ldap::search_request>(&m.log.received[0].op);
	REQUIRE(request != nullptr);
	CHECK(request->scope == ldap::search_scope::single_level);
	CHECK(std::string(request->base_object) == "cn=users,dc=example,dc=org");
	CHECK(m.log.received[0].controls == std::pmr::vector<ldap::control>{ ldap::control{ ad::notification_oid, true } });
	CHECK(m.log.received[1] == ldap::message{ 2, ldap::abandon_request{ 1 } });
}
