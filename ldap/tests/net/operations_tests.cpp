// Step 6 operations against the scripted mock server (mock_ldap.hpp): add,
// modify, delete, modify DN, compare, extended / who am I, typed controls,
// paged search and referrals.
#include "jhetz/ldap/connection.hpp"
#include "jhetz/ldap/controls.hpp"
#include "mock_ldap.hpp"
#include "net_test_support.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <cstdint>
#include <optional>
#include <string>
#include <variant>
#include <vector>

namespace ldap = jhetz::ldap;
using namespace jhetz::ldap::test;
using Catch::Matchers::ContainsSubstring;
using ldap::client_errc;
using ldap::errc;

namespace {

template<class Response>
ldap::message result_msg(std::int32_t id, std::int32_t code = 0, std::string_view diagnostic = {})
{
	return ldap::message{ id, Response{ ldap::ldap_result{ code, "", diagnostic } } };
}

const ldap::dn jdoe{ "uid=jdoe,ou=people,dc=example,dc=org" };

ldap::control post_read_control() { return ldap::control{ "1.3.6.1.1.13.2", false, "entry" }; }

}// namespace

// ---------------------------------------------------------------- add

TEST_CASE("operations: add", "[net][operations]")
{
	mock_ldap m;
	ldap::message ok = result_msg<ldap::add_response>(1);
	ok.controls.push_back(post_read_control());
	m.serve({ answer({ ok }), answer({ result_msg<ldap::add_response>(2, 68, "exists") }) });

	auto r = m.run(m.conn.add({
	  .entry = jdoe,
	  .attributes = { { "objectClass", { "inetOrgPerson" } }, { "cn", { "John Doe" } }, { "sn", { "Doe" } } },
	  .controls = { ldap::manage_dsa_it{} },
	}));
	REQUIRE(r.has_value());
	REQUIRE(r->controls.size() == 1);
	CHECK(r->controls[0] == post_read_control());

	auto again = m.run(m.conn.add({ .entry = jdoe, .attributes = { { "cn", { "John Doe" } } } }));
	REQUIRE_FALSE(again.has_value());
	CHECK(again.error().code == errc::entry_already_exists);
	CHECK(again.error().code == ldap::cond::already_exists);
	CHECK(again.error().context == "add uid=jdoe,ou=people,dc=example,dc=org");
	CHECK(again.error().diagnostic == "exists");
	CHECK(m.conn.is_open());
	m.check_server();

	REQUIRE(m.log.received.size() == 2);
	CHECK(m.log.received[0]
		  == ldap::message{ 1,
			ldap::add_request{ "uid=jdoe,ou=people,dc=example,dc=org",
			  { { "objectClass", { "inetOrgPerson" } }, { "cn", { "John Doe" } }, { "sn", { "Doe" } } } },
			{ ldap::control{ ldap::manage_dsa_it_oid } } });
}

TEST_CASE("operations: an attribute without values is not sent", "[net][operations]")
{
	mock_ldap m;
	m.serve({ answer({ result_msg<ldap::add_response>(1) }) });
	auto r = m.run(m.conn.add({ .entry = jdoe, .attributes = { { "cn", {} } } }));
	REQUIRE_FALSE(r.has_value());
	CHECK(r.error().code == client_errc::encode_error);
	CHECK(m.log.received.empty());
	// The id was not used up.
	CHECK(m.run(m.conn.add({ .entry = jdoe, .attributes = { { "cn", { "x" } } } })).has_value());
	m.check_server();
	CHECK(m.log.received[0].id == 1);
}

// ---------------------------------------------------------------- modify

TEST_CASE("operations: modify", "[net][operations]")
{
	mock_ldap m;
	m.serve({ answer({ result_msg<ldap::modify_response>(1) }),
	  answer({ result_msg<ldap::modify_response>(2, 50, "no write access") }) });
	auto r = m.run(m.conn.modify({
	  .object = jdoe,
	  .changes = { ldap::mod::add("mail", { "jdoe@example.org", "john@example.org" }),
		ldap::mod::remove("description"),
		ldap::mod::remove("telephoneNumber", { "+1 555 0100" }),
		ldap::mod::replace("sn", { "Doe" }),
		ldap::mod::increment("uidNumber", "2") },
	}));
	REQUIRE(r.has_value());
	CHECK(r->controls.empty());

	auto denied = m.run(m.conn.modify({ .object = jdoe, .changes = { ldap::mod::replace("sn", { "X" }) } }));
	REQUIRE_FALSE(denied.has_value());
	CHECK(denied.error().code == ldap::cond::access_denied);
	CHECK(denied.error().context == "modify uid=jdoe,ou=people,dc=example,dc=org");
	m.check_server();

	using op = ldap::modify_operation;
	REQUIRE(m.log.received.size() == 2);
	CHECK(m.log.received[0]
		  == ldap::message{ 1,
			ldap::modify_request{ "uid=jdoe,ou=people,dc=example,dc=org",
			  { { op::add, { "mail", { "jdoe@example.org", "john@example.org" } } },
				{ op::delete_, { "description", {} } },
				{ op::delete_, { "telephoneNumber", { "+1 555 0100" } } },
				{ op::replace, { "sn", { "Doe" } } },
				{ op::increment, { "uidNumber", { "2" } } } } } });
}

// ---------------------------------------------------------------- delete

TEST_CASE("operations: delete", "[net][operations]")
{
	mock_ldap m;
	m.serve({ answer({ result_msg<ldap::del_response>(1) }),
	  answer({ result_msg<ldap::del_response>(2, 66, "has children") }) });
	REQUIRE(m.run(m.conn.del({ .entry = jdoe })).has_value());
	auto busy = m.run(m.conn.del({ .entry = ldap::dn{ "ou=people,dc=example,dc=org" } }));
	REQUIRE_FALSE(busy.has_value());
	CHECK(busy.error().code == errc::not_allowed_on_non_leaf);
	CHECK(busy.error().context == "delete ou=people,dc=example,dc=org");
	m.check_server();
	REQUIRE(m.log.received.size() == 2);
	CHECK(m.log.received[0] == ldap::message{ 1, ldap::del_request{ "uid=jdoe,ou=people,dc=example,dc=org" } });
}

// ---------------------------------------------------------------- modify DN

TEST_CASE("operations: modify DN", "[net][operations]")
{
	mock_ldap m;
	m.serve(
	  { answer({ result_msg<ldap::modify_dn_response>(1) }), answer({ result_msg<ldap::modify_dn_response>(2) }) });
	// Rename, keeping the old RDN value.
	REQUIRE(m.run(m.conn.modify_dn({
					.entry = jdoe,
					.new_rdn = ldap::dn{ "uid=john.doe" }.rdns().front(),
					.delete_old_rdn = false,
				  }))
			  .has_value());
	// Move under another parent, same RDN.
	REQUIRE(m.run(m.conn.modify_dn({
					.entry = jdoe,
					.new_rdn = jdoe.rdns().front(),
					.new_superior = ldap::dn{ "ou=alumni,dc=example,dc=org" },
				  }))
			  .has_value());
	m.check_server();
	REQUIRE(m.log.received.size() == 2);
	CHECK(
	  m.log.received[0]
	  == ldap::message{ 1, ldap::modify_dn_request{ "uid=jdoe,ou=people,dc=example,dc=org", "uid=john.doe", false } });
	CHECK(m.log.received[1]
		  == ldap::message{ 2,
			ldap::modify_dn_request{
			  "uid=jdoe,ou=people,dc=example,dc=org", "uid=jdoe", true, "ou=alumni,dc=example,dc=org" } });

	auto empty = m.run(m.conn.modify_dn({ .entry = jdoe }));
	REQUIRE_FALSE(empty.has_value());
	CHECK(empty.error().code == client_errc::invalid_dn);
}

// ---------------------------------------------------------------- compare

TEST_CASE("operations: compare", "[net][operations]")
{
	mock_ldap m;
	m.serve({ answer({ result_msg<ldap::compare_response>(1, 6) }),
	  answer({ result_msg<ldap::compare_response>(2, 5) }),
	  answer({ result_msg<ldap::compare_response>(3, 16, "no such attribute") }),
	  answer({ result_msg<ldap::compare_response>(4, 0) }) });
	auto yes = m.run(m.conn.compare({ .entry = jdoe, .attribute = "mail", .value = "jdoe@example.org" }));
	REQUIRE(yes.has_value());
	CHECK(*yes);
	auto no = m.run(m.conn.compare({ .entry = jdoe, .attribute = "mail", .value = "other@example.org" }));
	REQUIRE(no.has_value());
	CHECK_FALSE(*no);
	auto missing = m.run(m.conn.compare({ .entry = jdoe, .attribute = "pager", .value = "1" }));
	REQUIRE_FALSE(missing.has_value());
	CHECK(missing.error().code == ldap::cond::not_found);
	CHECK(missing.error().context == "compare uid=jdoe,ou=people,dc=example,dc=org");
	// success is not an answer to a compare
	auto odd = m.run(m.conn.compare({ .entry = jdoe, .attribute = "mail", .value = "x" }));
	REQUIRE_FALSE(odd.has_value());
	CHECK(odd.error().code.value() == 0);
	CHECK(m.conn.is_open());
	m.check_server();
	REQUIRE(m.log.received.size() == 4);
	CHECK(m.log.received[0]
		  == ldap::message{
			1, ldap::compare_request{ "uid=jdoe,ou=people,dc=example,dc=org", { "mail", "jdoe@example.org" } } });
}

// ---------------------------------------------------------------- extended

TEST_CASE("operations: extended operations and who am I", "[net][operations]")
{
	mock_ldap m;
	m.serve({ answer({ ldap::message{
				1, ldap::extended_response{ ldap::ldap_result{ 0 }, "1.2.3.4.5", std::string("\x04\x01x", 3) } } }),
	  answer({ ldap::message{
		2, ldap::extended_response{ ldap::ldap_result{ 0 }, std::nullopt, "dn:cn=admin,dc=example,dc=org" } } }),
	  answer({ ldap::message{ 3, ldap::extended_response{ ldap::ldap_result{ 0 } } } }),
	  answer({ ldap::message{
		4, ldap::extended_response{ ldap::ldap_result{ 2, "", "unsupported extended operation" } } } }) });

	auto x = m.run(m.conn.extended({ .name = "1.2.3.4", .value = std::string("\x30\x00", 2) }));
	REQUIRE(x.has_value());
	CHECK(x->name == "1.2.3.4.5");
	CHECK(x->value == std::pmr::string("\x04\x01x", 3));

	auto me = m.run(m.conn.who_am_i());
	REQUIRE(me.has_value());
	CHECK(*me == "dn:cn=admin,dc=example,dc=org");
	auto anon = m.run(m.conn.who_am_i());
	REQUIRE(anon.has_value());
	CHECK(*anon == "");

	auto unknown = m.run(m.conn.extended({ .name = "1.9.9" }));
	REQUIRE_FALSE(unknown.has_value());
	CHECK(unknown.error().code == errc::protocol_error);
	CHECK(unknown.error().context == "extended operation 1.9.9");
	CHECK(m.conn.is_open());
	m.check_server();

	REQUIRE(m.log.received.size() == 4);
	CHECK(m.log.received[0] == ldap::message{ 1, ldap::extended_request{ "1.2.3.4", std::string("\x30\x00", 2) } });
	CHECK(m.log.received[1] == ldap::message{ 2, ldap::extended_request{ ldap::who_am_i_oid } });
}

TEST_CASE("operations: a response of the wrong type is a protocol error", "[net][operations]")
{
	mock_ldap m;
	m.serve({ answer({ result_msg<ldap::modify_response>(1) }) });
	auto r = m.run(m.conn.add({ .entry = jdoe, .attributes = { { "cn", { "x" } } } }));
	REQUIRE_FALSE(r.has_value());
	CHECK(r.error().code == client_errc::unexpected_response);
	CHECK_THAT(std::string(r.error().context),
	  ContainsSubstring("ModifyResponse with message id 1 in response to a AddRequest"));
	CHECK_FALSE(m.conn.is_open());
}

// ---------------------------------------------------------------- controls

TEST_CASE("operations: typed controls on the wire", "[net][operations][controls]")
{
	mock_ldap m;
	m.serve({ answer({ done_msg(1) }) });
	REQUIRE(m.run(m.conn.search({
					.controls = { ldap::proxied_authorization{ "dn:uid=jdoe,ou=people,dc=example,dc=org" },
					  ldap::manage_dsa_it{ .critical = true },
					  ldap::paged{ .page_size = 10, .cookie = "c" },
					  ldap::control{ "1.2.3.4", false, "raw" } },
				  }))
			  .has_value());
	m.check_server();
	REQUIRE(m.log.received.size() == 1);
	const auto &cs = m.log.received[0].controls;
	REQUIRE(cs.size() == 4);
	CHECK(cs[0] == ldap::control{ ldap::proxied_authorization_oid, true, "dn:uid=jdoe,ou=people,dc=example,dc=org" });
	CHECK(cs[1] == ldap::control{ ldap::manage_dsa_it_oid, true });
	CHECK(cs[2] == *ldap::encode_paged_results({ 10, "c" }));
	CHECK(cs[3] == ldap::control{ "1.2.3.4", false, "raw" });

	auto bad = m.run(m.conn.search({ .controls = { ldap::paged{ .page_size = -1 } } }));
	REQUIRE_FALSE(bad.has_value());
	CHECK(bad.error().code == client_errc::encode_error);
}

// ---------------------------------------------------------------- paged search

namespace {

ldap::message paged_done(std::int32_t id, std::string_view cookie)
{
	ldap::message m = done_msg(id);
	m.controls.push_back(*ldap::encode_paged_results({ 0, cookie }));
	return m;
}

capy::task<ldap::result<std::vector<std::string>>> drain_paged(ldap::paged_search &s)
{
	std::vector<std::string> dns;
	while (true) {
		auto e = co_await s.next();
		if (!e) co_return std::unexpected(std::move(e.error()));
		if (!*e) co_return dns;
		dns.emplace_back((*e)->dn);
	}
}

}// namespace

TEST_CASE("operations: paged search follows the cookie", "[net][operations][paged]")
{
	mock_ldap m;
	m.serve({ answer({ entry_msg(1, "uid=a,ou=people,dc=example,dc=org", "A"),
				entry_msg(1, "uid=b,ou=people,dc=example,dc=org", "B"),
				paged_done(1, "page2") }),
	  answer({ entry_msg(2, "uid=c,ou=people,dc=example,dc=org", "C"),
		ref_msg(2, { "ldap://other.example.org/ou=people,dc=example,dc=org", "https://not-ldap.example.org/" }),
		entry_msg(2, "uid=d,ou=people,dc=example,dc=org", "D"),
		paged_done(2, "page3") }),
	  answer({ entry_msg(3, "uid=e,ou=people,dc=example,dc=org", "E"), paged_done(3, "") }) });

	auto s = m.run(m.conn.search_paged(people_search(), 2));
	REQUIRE(s.has_value());
	CHECK(s->pages() == 1);
	auto dns = m.run(drain_paged(*s));
	REQUIRE(dns.has_value());
	CHECK(*dns
		  == std::vector<std::string>{ "uid=a,ou=people,dc=example,dc=org",
			"uid=b,ou=people,dc=example,dc=org",
			"uid=c,ou=people,dc=example,dc=org",
			"uid=d,ou=people,dc=example,dc=org",
			"uid=e,ou=people,dc=example,dc=org" });
	CHECK(s->done());
	CHECK(s->pages() == 3);
	REQUIRE(s->references().size() == 2);
	auto urls = s->reference_urls();
	REQUIRE(urls.size() == 1);// the https:// one is not an LDAP URL
	CHECK(urls[0].host() == "other.example.org");
	m.check_server();

	// Each page is the same search with the page size and the last cookie.
	REQUIRE(m.log.received.size() == 3);
	const char *cookies[] = { "", "page2", "page3" };
	for (std::size_t i = 0; i < 3; ++i) {
		INFO("page " << i);
		const auto &req = m.log.received[i];
		CHECK(req.id == static_cast<std::int32_t>(i + 1));
		CHECK(req.op == m.log.received[0].op);
		REQUIRE(req.controls.size() == 1);
		auto p = ldap::decode_paged_results(req.controls[0]);
		REQUIRE(p.has_value());
		CHECK(p->size == 2);
		CHECK(p->cookie == cookies[i]);
	}
}

TEST_CASE("operations: paged search against a server without paging", "[net][operations][paged]")
{
	mock_ldap m;
	m.serve({ answer({ entry_msg(1, "uid=a,ou=people,dc=example,dc=org", "A"),
	  entry_msg(1, "uid=b,ou=people,dc=example,dc=org", "B"),
	  entry_msg(1, "uid=c,ou=people,dc=example,dc=org", "C"),
	  done_msg(1) }) });// no paged control in the done: everything was one page
	auto s = m.run(m.conn.search_paged(people_search(), 2));
	REQUIRE(s.has_value());
	auto dns = m.run(drain_paged(*s));
	REQUIRE(dns.has_value());
	CHECK(dns->size() == 3);
	CHECK(s->pages() == 1);
	m.check_server();
}

TEST_CASE("operations: paged search errors", "[net][operations][paged]")
{
	SECTION("a malformed paged results control")
	{
		mock_ldap m;
		ldap::message done = done_msg(1);
		done.controls.push_back(ldap::control{ ldap::paged_results_oid, false, "garbage" });
		m.serve({ answer({ done }) });
		auto s = m.run(m.conn.search_paged(people_search(), 2));
		REQUIRE(s.has_value());
		auto r = m.run(drain_paged(*s));
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == ldap::cond::protocol_error);
		CHECK(s->done());
	}
	SECTION("a server error on a later page")
	{
		mock_ldap m;
		m.serve({ answer({ entry_msg(1, "uid=a,ou=people,dc=example,dc=org", "A"), paged_done(1, "next") }),
		  answer({ done_msg(2, 51, "", "busy") }) });
		auto s = m.run(m.conn.search_paged(people_search(), 1));
		REQUIRE(s.has_value());
		auto first = m.run(s->next());
		REQUIRE(first.has_value());
		REQUIRE(first->has_value());
		auto second = m.run(s->next());
		REQUIRE_FALSE(second.has_value());
		CHECK(second.error().code == errc::busy);
		CHECK(m.conn.is_open());
	}
	SECTION("a page size that is not positive")
	{
		mock_ldap m;
		auto s = m.run(m.conn.search_paged(people_search(), 0));
		REQUIRE_FALSE(s.has_value());
		CHECK(s.error().code == client_errc::encode_error);
		CHECK(m.log.received.empty());
	}
}

// ---------------------------------------------------------------- referrals

TEST_CASE("operations: referrals are returned, not chased", "[net][operations][referrals]")
{
	mock_ldap m;
	m.serve({ answer({ ldap::message{ 1,
	  ldap::modify_response{ ldap::ldap_result{ 10,
		"",
		"go elsewhere",
		{ "ldap://b.example.org/uid=jdoe,ou=people,dc=example,dc=org", "not a url" } } } } }) });
	auto r = m.run(m.conn.modify({ .object = jdoe, .changes = { ldap::mod::replace("sn", { "Doe" }) } }));
	REQUIRE_FALSE(r.has_value());
	CHECK(r.error().code == errc::referral);
	REQUIRE(r.error().referrals.size() == 2);
	auto urls = ldap::url::parse_list(r.error().referrals);
	REQUIRE(urls.size() == 1);
	CHECK(urls[0].host() == "b.example.org");
	CHECK(urls[0].base_dn() == jdoe);
	CHECK(m.conn.is_open());
	m.check_server();
}
