// Step 6 operations against the scripted mock server (mock_ldap.hpp): add,
// modify, delete, modify DN, compare, extended / who am I, typed controls,
// paged search and referrals.
#include "jhetz/ldap/connection.hpp"
#include "jhetz/ldap/controls.hpp"
#include "mock_ldap.hpp"
#include "net_test_support.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <variant>
#include <vector>

namespace ldap = jhetz::ldap;
using namespace jhetz::ldap::test;
using Catch::Matchers::ContainsSubstring;
using Catch::Matchers::StartsWith;
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
					.new_rdn = ldap::rdn{ "uid=john.doe" },
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

TEST_CASE("operations: assertion and pre/post-read on a modify", "[net][operations][controls]")
{
	mock_ldap m;
	ldap::message ok = result_msg<ldap::modify_response>(1);
	ok.controls.push_back(*ldap::encode_read_entry(ldap::pre_read_oid,
	  ldap::search_result_entry{ "uid=jdoe,ou=people,dc=example,dc=org", { { "sn", { "Doe" } } } }));
	ok.controls.push_back(*ldap::encode_read_entry(ldap::post_read_oid,
	  ldap::search_result_entry{ "uid=jdoe,ou=people,dc=example,dc=org", { { "sn", { "Roe" } } } }));
	m.serve({ answer({ ok }), answer({ result_msg<ldap::modify_response>(2, 122, "assertion failed") }) });

	const auto assert_doe = ldap::filters::attr("sn") == "Doe";
	auto r = m.run(m.conn.modify({
	  .object = jdoe,
	  .changes = { ldap::mod::replace("sn", { "Roe" }) },
	  .controls = { ldap::assertion{ .filter = assert_doe },
		ldap::pre_read{ .attributes = { "sn" } },
		ldap::post_read{ .attributes = { "sn" } } },
	}));
	REQUIRE(r.has_value());
	auto before = ldap::find_pre_read(r->controls);
	REQUIRE(before.has_value());
	REQUIRE(before->has_value());
	CHECK((*before)->dn == "uid=jdoe,ou=people,dc=example,dc=org");
	CHECK(*(*before)->find("sn") == ldap::string_list{ "Doe" });
	auto after = ldap::find_post_read(r->controls);
	REQUIRE(after.has_value());
	REQUIRE(after->has_value());
	CHECK(*(*after)->find("sn") == ldap::string_list{ "Roe" });

	auto failed = m.run(m.conn.modify({
	  .object = jdoe,
	  .changes = { ldap::mod::replace("sn", { "Roe" }) },
	  .controls = { ldap::assertion{ .filter = assert_doe } },
	}));
	REQUIRE_FALSE(failed.has_value());
	CHECK(failed.error().code == errc::assertion_failed);
	CHECK(m.conn.is_open());
	m.check_server();

	REQUIRE(m.log.received.size() == 2);
	const auto &cs = m.log.received[0].controls;
	REQUIRE(cs.size() == 3);
	CHECK(cs[0] == ldap::to_control(ldap::assertion{ .filter = assert_doe }).value());
	CHECK(cs[0].criticality);
	CHECK(cs[1] == ldap::to_control(ldap::pre_read{ .attributes = { "sn" } }).value());
	CHECK(cs[2] == ldap::to_control(ldap::post_read{ .attributes = { "sn" } }).value());
}

TEST_CASE("operations: server side sort result of a search", "[net][operations][controls]")
{
	mock_ldap m;
	ldap::message sorted = done_msg(1);
	sorted.controls.push_back(*ldap::encode_sort_result({ 0 }));
	ldap::message unsorted = done_msg(2);
	unsorted.controls.push_back(*ldap::encode_sort_result({ 18, "cn" }));
	ldap::message garbage = done_msg(3);
	garbage.controls.push_back(ldap::control{ ldap::sort_response_oid, false, "x" });
	m.serve({ answer({ entry_msg(1, "uid=b,ou=people,dc=example,dc=org", "B"),
				entry_msg(1, "uid=a,ou=people,dc=example,dc=org", "A"),
				sorted }),
	  answer({ unsorted }),
	  answer({ garbage }) });

	const ldap::server_side_sort by_cn{ .keys = { { .attribute = "cn", .reverse = true } } };
	auto s = m.run(m.conn.search_stream({ .base = ldap::dn{ "ou=people,dc=example,dc=org" }, .controls = { by_cn } }));
	REQUIRE(s.has_value());
	auto first = m.run(s->next());
	REQUIRE(first.has_value());
	REQUIRE(first->has_value());
	CHECK((*first)->dn == "uid=b,ou=people,dc=example,dc=org");
	while (true) {
		auto e = m.run(s->next());
		REQUIRE(e.has_value());
		if (!e->has_value()) break;
	}
	auto ok = ldap::find_sort_result(s->controls());
	REQUIRE(ok.has_value());
	REQUIRE(ok->has_value());
	CHECK((*ok)->is_success());

	auto s2 = m.run(m.conn.search_stream({ .base = ldap::dn{ "ou=people,dc=example,dc=org" }, .controls = { by_cn } }));
	REQUIRE(s2.has_value());
	REQUIRE(m.run(s2->next()).has_value());
	auto not_sorted = ldap::find_sort_result(s2->controls());
	REQUIRE(not_sorted.has_value());
	REQUIRE(not_sorted->has_value());
	CHECK((*not_sorted)->result_code == 18);
	CHECK((*not_sorted)->attribute_type == "cn");

	auto s3 = m.run(m.conn.search_stream({ .base = ldap::dn{ "ou=people,dc=example,dc=org" }, .controls = { by_cn } }));
	REQUIRE(s3.has_value());
	REQUIRE(m.run(s3->next()).has_value());
	auto bad = ldap::find_sort_result(s3->controls());
	REQUIRE_FALSE(bad.has_value());
	CHECK(bad.error().code == ldap::cond::protocol_error);
	m.check_server();

	REQUIRE(m.log.received.size() == 3);
	REQUIRE(m.log.received[0].controls.size() == 1);
	CHECK(m.log.received[0].controls[0] == ldap::to_control(by_cn).value());

	// Invalid typed controls fail before anything is sent.
	auto no_keys = m.run(m.conn.search({ .controls = { ldap::server_side_sort{} } }));
	REQUIRE_FALSE(no_keys.has_value());
	CHECK(no_keys.error().code == client_errc::encode_error);
	auto no_filter = m.run(m.conn.del({ .entry = jdoe, .controls = { ldap::assertion{} } }));
	REQUIRE_FALSE(no_filter.has_value());
	CHECK(no_filter.error().code == client_errc::invalid_filter);
	CHECK(m.log.received.size() == 3);
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

// ---------------------------------------------------------------- paged search release

namespace {

// `req` is the first page's search with page size 0 and `cookie` (RFC 2696
// section 3: the release of the server's paging state).
void check_release(const ldap::message &req, const ldap::message &first, std::string_view cookie)
{
	CHECK(req.op == first.op);
	REQUIRE(req.controls.size() == 1);
	auto p = ldap::decode_paged_results(req.controls[0]);
	REQUIRE(p.has_value());
	CHECK(p->size == 0);
	CHECK(p->cookie == cookie);
}

capy::task<ldap::result<void>> bind_admin(ldap::connection &c)
{
	co_return co_await c.simple_bind(*ldap::dn::parse(admin), "secret");
}

}// namespace

TEST_CASE("operations: a paged search stopped between pages releases the server's state", "[net][operations][paged]")
{
	mock_ldap m;
	m.serve({ answer({ entry_msg(1, "uid=a,ou=people,dc=example,dc=org", "A"), paged_done(1, "page2") }),
	  answer({ entry_msg(2, "uid=b,ou=people,dc=example,dc=org", "B"), paged_done(2, "page3") }),
	  answer({ paged_done(3, "") }),// the release's answer: dropped
	  answer({ bind_resp(4) }) });
	{
		auto s = m.run(m.conn.search_paged(people_search(), 1));
		REQUIRE(s.has_value());
		for (int i = 0; i < 2; ++i) {
			auto e = m.run(s->next());
			REQUIRE(e.has_value());
			REQUIRE(e->has_value());
		}
		// Page 2 ended (its SearchResultDone is queued), next() not called.
		drive_until(m.ioc, [&m] { return m.conn.outstanding() == 0; });
		CHECK(s->pages() == 2);
	}
	CHECK(m.conn.outstanding() == 0);
	auto b = m.run(bind_admin(m.conn));
	CHECK(b.has_value());
	CHECK(m.conn.is_open());
	m.check_server();
	REQUIRE(m.log.received.size() == 4);// no AbandonRequest: the page had ended
	CHECK(m.log.received[2].id == 3);
	check_release(m.log.received[2], m.log.received[0], "page3");
	CHECK(m.log.received[3] == bind_request_msg(4));
}

TEST_CASE("operations: a paged search stopped mid-page abandons it, then releases", "[net][operations][paged]")
{
	SECTION("a later page: released with the last cookie the server returned")
	{
		mock_ldap m;
		m.serve({ answer({ entry_msg(1, "uid=a,ou=people,dc=example,dc=org", "A"), paged_done(1, "page2") }),
		  answer({ entry_msg(2, "uid=b,ou=people,dc=example,dc=org", "B") }),
		  answer({ paged_done(2, "page3") }),// reads the AbandonRequest; a late done, dropped
		  answer({ paged_done(4, "") }),// the release's answer: dropped
		  answer({ bind_resp(5) }) });
		{
			auto s = m.run(m.conn.search_paged(people_search(), 1));
			REQUIRE(s.has_value());
			for (int i = 0; i < 2; ++i) {
				auto e = m.run(s->next());
				REQUIRE(e.has_value());
				REQUIRE(e->has_value());
			}
			CHECK(m.conn.outstanding() == 1);
		}
		CHECK(m.conn.outstanding() == 0);
		auto b = m.run(bind_admin(m.conn));
		CHECK(b.has_value());
		CHECK(m.conn.is_open());
		m.check_server();
		REQUIRE(m.log.received.size() == 5);
		CHECK(m.log.received[2] == ldap::message{ 3, ldap::abandon_request{ 2 } });
		CHECK(m.log.received[3].id == 4);
		check_release(m.log.received[3], m.log.received[0], "page2");
		CHECK(m.log.received[4] == bind_request_msg(5));
	}
	SECTION("a page stopped with with_stop: abandoned; the destructor releases")
	{
		mock_ldap m;
		m.serve({ answer({ entry_msg(1, "uid=a,ou=people,dc=example,dc=org", "A"), paged_done(1, "page2") }),
		  answer({ entry_msg(2, "uid=b,ou=people,dc=example,dc=org", "B") }),
		  step{},// reads the AbandonRequest
		  answer({ paged_done(4, "") }),// the release's answer: dropped
		  answer({ bind_resp(5) }) });
		{
			auto s = m.run(m.conn.search_paged(people_search(), 1));
			REQUIRE(s.has_value());
			for (int i = 0; i < 2; ++i) {
				auto e = m.run(s->next());
				REQUIRE(e.has_value());
				REQUIRE(e->has_value());
			}
			std::stop_source cancel;
			outcome<ldap::result<std::optional<ldap::entry>>> out;
			spawn(m.ioc, ldap::with_stop(cancel.get_token(), s->next()), out);
			cancel.request_stop();
			drive_until(m.ioc, [&out] { return out.done(); });
			REQUIRE_FALSE(out.get().has_value());
			CHECK(out.get().error().code == ldap::cond::canceled);
			CHECK(out.get().error().context == "search ou=people,dc=example,dc=org (abandoned)");
			CHECK(s->done());
			CHECK(m.conn.outstanding() == 0);
			drive_until(m.ioc, [&m] { return m.log.received.size() == 3; });
			CHECK(m.log.received[2] == ldap::message{ 3, ldap::abandon_request{ 2 } });
		}
		auto b = m.run(bind_admin(m.conn));
		CHECK(b.has_value());
		CHECK(m.conn.is_open());
		m.check_server();
		REQUIRE(m.log.received.size() == 5);
		CHECK(m.log.received[3].id == 4);
		check_release(m.log.received[3], m.log.received[0], "page2");
		CHECK(m.log.received[4] == bind_request_msg(5));
	}
	SECTION("the first page: no cookie yet, only abandoned")
	{
		mock_ldap m;
		m.serve({ answer({ entry_msg(1, "uid=a,ou=people,dc=example,dc=org", "A") }),
		  answer({ paged_done(1, "page2") }),// reads the AbandonRequest; a late done, dropped
		  answer({ bind_resp(3) }) });
		{
			auto s = m.run(m.conn.search_paged(people_search(), 1));
			REQUIRE(s.has_value());
			auto e = m.run(s->next());
			REQUIRE(e.has_value());
			REQUIRE(e->has_value());
		}
		auto b = m.run(bind_admin(m.conn));
		CHECK(b.has_value());
		m.check_server();
		REQUIRE(m.log.received.size() == 3);
		CHECK(m.log.received[1] == ldap::message{ 2, ldap::abandon_request{ 1 } });
		CHECK(m.log.received[2] == bind_request_msg(3));
	}
	SECTION("a page that timed out")
	{
		mock_ldap m;
		m.serve({ answer({ entry_msg(1, "uid=a,ou=people,dc=example,dc=org", "A"), paged_done(1, "page2") }),
		  step{},// reads page 2's search, does not answer
		  step{},// reads its AbandonRequest
		  answer({ paged_done(4, "") }),// the release's answer: dropped
		  answer({ bind_resp(5) }) });
		{
			auto p = people_search();
			p.timeout = std::chrono::milliseconds(50);
			auto s = m.run(m.conn.search_paged(std::move(p), 1));
			REQUIRE(s.has_value());
			auto e = m.run(s->next());
			REQUIRE(e.has_value());
			REQUIRE(e->has_value());
			auto late = m.run(s->next());
			REQUIRE_FALSE(late.has_value());
			CHECK(late.error().code == ldap::cond::timeout);
			CHECK(s->done());
		}
		auto b = m.run(bind_admin(m.conn));
		CHECK(b.has_value());
		m.check_server();
		REQUIRE(m.log.received.size() == 5);
		CHECK(m.log.received[2] == ldap::message{ 3, ldap::abandon_request{ 2 } });
		check_release(m.log.received[3], m.log.received[0], "page2");
		CHECK(m.log.received[4] == bind_request_msg(5));
	}
}

TEST_CASE("operations: a paged search that ended sends no release", "[net][operations][paged]")
{
	SECTION("ran to completion (empty cookie)")
	{
		mock_ldap m;
		m.serve({ answer({ entry_msg(1, "uid=a,ou=people,dc=example,dc=org", "A"), paged_done(1, "page2") }),
		  answer({ entry_msg(2, "uid=b,ou=people,dc=example,dc=org", "B"), paged_done(2, "") }),
		  answer({ bind_resp(3) }) });
		{
			auto s = m.run(m.conn.search_paged(people_search(), 1));
			REQUIRE(s.has_value());
			auto dns = m.run(drain_paged(*s));
			REQUIRE(dns.has_value());
			CHECK(dns->size() == 2);
		}
		auto b = m.run(bind_admin(m.conn));
		CHECK(b.has_value());
		m.check_server();
		REQUIRE(m.log.received.size() == 3);
		CHECK(m.log.received[2] == bind_request_msg(3));
	}
	SECTION("the last page ended, next() not called")
	{
		mock_ldap m;
		m.serve({ answer({ entry_msg(1, "uid=a,ou=people,dc=example,dc=org", "A"), paged_done(1, "") }),
		  answer({ bind_resp(2) }) });
		{
			auto s = m.run(m.conn.search_paged(people_search(), 1));
			REQUIRE(s.has_value());
			auto e = m.run(s->next());
			REQUIRE(e.has_value());
			REQUIRE(e->has_value());
			drive_until(m.ioc, [&m] { return m.conn.outstanding() == 0; });
		}
		auto b = m.run(bind_admin(m.conn));
		CHECK(b.has_value());
		m.check_server();
		REQUIRE(m.log.received.size() == 2);
		CHECK(m.log.received[1] == bind_request_msg(2));
	}
	SECTION("a server error")
	{
		mock_ldap m;
		m.serve({ answer({ entry_msg(1, "uid=a,ou=people,dc=example,dc=org", "A"), paged_done(1, "next") }),
		  answer({ done_msg(2, 51, "", "busy") }),
		  answer({ bind_resp(3) }) });
		{
			auto s = m.run(m.conn.search_paged(people_search(), 1));
			REQUIRE(s.has_value());
			auto r = m.run(drain_paged(*s));
			REQUIRE_FALSE(r.has_value());
			CHECK(r.error().code == errc::busy);
		}
		auto b = m.run(bind_admin(m.conn));
		CHECK(b.has_value());
		m.check_server();
		REQUIRE(m.log.received.size() == 3);
		CHECK(m.log.received[2] == bind_request_msg(3));
	}
	SECTION("the connection is closed")
	{
		mock_ldap m;
		m.serve({ answer({ entry_msg(1, "uid=a,ou=people,dc=example,dc=org", "A"), paged_done(1, "page2") }),
		  step{} });// would read a release
		{
			auto s = m.run(m.conn.search_paged(people_search(), 1));
			REQUIRE(s.has_value());
			auto e = m.run(s->next());
			REQUIRE(e.has_value());
			REQUIRE(e->has_value());
			drive_until(m.ioc, [&m] { return m.conn.outstanding() == 0; });
			m.conn.close();
		}
		m.sockets.client.close();// closing a wrapped transport leaves the socket open
		drive_until(m.ioc, [&m] { return m.server.done(); });
		CHECK_THAT(m.log.error, StartsWith("server read: "));
		CHECK(m.log.received.size() == 1);
		CHECK_FALSE(m.conn.is_open());
	}
}

TEST_CASE("operations: a paged search release and the connection's state", "[net][operations][paged]")
{
	SECTION("during a bind: held until the bind ends, like any request")
	{
		mock_ldap m;
		m.serve({ answer({ entry_msg(1, "uid=a,ou=people,dc=example,dc=org", "A"), paged_done(1, "page2") }),
		  step{},// reads the BindRequest, does not answer yet
		  step{ .read_request = false, .replies = { bytes_of(bind_resp(2)) } },
		  answer({ paged_done(3, "") }),// the release's answer: dropped
		  answer({ bind_resp(4) }) });
		outcome<ldap::result<void>> bound;
		{
			auto s = m.run(m.conn.search_paged(people_search(), 1));
			REQUIRE(s.has_value());
			auto e = m.run(s->next());
			REQUIRE(e.has_value());
			REQUIRE(e->has_value());
			drive_until(m.ioc, [&m] { return m.conn.outstanding() == 0; });
			spawn(m.ioc, bind_admin(m.conn), bound);
			drive_until(m.ioc, [&m] { return m.log.received.size() == 2; });
			CHECK_FALSE(bound.done());
		}// destroyed while the bind is outstanding
		drive_until(m.ioc, [&bound] { return bound.done(); });
		CHECK(bound.get().has_value());
		auto b = m.run(bind_admin(m.conn));
		CHECK(b.has_value());
		m.check_server();
		REQUIRE(m.log.received.size() == 4);
		CHECK(m.log.received[1] == bind_request_msg(2));
		CHECK(m.log.received[2].id == 3);
		check_release(m.log.received[2], m.log.received[0], "page2");
		CHECK(m.log.received[3] == bind_request_msg(4));
	}
	SECTION("the connection destroyed right after: nothing outlives it")
	{
		mock_ldap m;
		m.serve({ answer({ entry_msg(1, "uid=a,ou=people,dc=example,dc=org", "A"), paged_done(1, "page2") }),
		  step{} });// may read the release
		{
			auto s = m.run(m.conn.search_paged(people_search(), 1));
			REQUIRE(s.has_value());
			auto e = m.run(s->next());
			REQUIRE(e.has_value());
			REQUIRE(e->has_value());
			drive_until(m.ioc, [&m] { return m.conn.outstanding() == 0; });
			ldap::connection gone = std::move(m.conn);
			*s = ldap::paged_search{};// queues the release
		}// the connection is destroyed: closed
		m.sockets.client.close();// closing a wrapped transport leaves the socket open
		drive_until(m.ioc, [&m] { return m.server.done(); });
		CHECK(m.log.received.size() <= 2);
		if (m.log.received.size() == 2) check_release(m.log.received[1], m.log.received[0], "page2");
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

// ---------------------------------------------------------------- password modify

TEST_CASE("operations: password modify (RFC 3062)", "[net][operations]")
{
	using namespace std::string_literals;
	const auto ok = [](std::int32_t id, std::optional<std::string_view> value = {}) {
		return ldap::message{ id, ldap::extended_response{ ldap::ldap_result{ 0 }, std::nullopt, value } };
	};
	mock_ldap m;
	m.serve({ answer({ ok(1) }),
	  answer({ ok(2, "\x30\x07\x80\x05s3cr3"s) }),
	  answer({ ok(3, "\x30\x00"s) }),
	  answer({ ldap::message{ 4, ldap::extended_response{ ldap::ldap_result{ 49, "", "old password wrong" } } } }),
	  answer({ ok(5, "\x04\x00"s) }) });

	// All fields: no generated password.
	auto set = m.run(m.conn.password_modify(
	  { .user = "uid=jdoe,ou=people,dc=example,dc=org", .old_password = "old", .new_password = "new" }));
	REQUIRE(set.has_value());
	CHECK_FALSE(set->has_value());
	// No new password: the server generates one.
	auto generated = m.run(m.conn.password_modify({}));
	REQUIRE(generated.has_value());
	CHECK(*generated == "s3cr3");
	auto empty = m.run(m.conn.password_modify({ .new_password = "x" }));
	REQUIRE(empty.has_value());
	CHECK_FALSE(empty->has_value());
	// Server errors name the operation and the user, never a password.
	auto refused = m.run(m.conn.password_modify({ .user = "uid=jdoe", .old_password = "bad", .new_password = "new" }));
	REQUIRE_FALSE(refused.has_value());
	CHECK(refused.error().code == errc::invalid_credentials);
	CHECK(refused.error().context == "password modify uid=jdoe");
	CHECK(refused.error().diagnostic == "old password wrong");
	// A malformed response value.
	auto bad = m.run(m.conn.password_modify({}));
	REQUIRE_FALSE(bad.has_value());
	CHECK(bad.error().code == ldap::cond::protocol_error);
	CHECK_THAT(std::string(bad.error().context), StartsWith("password modify: response value"));
	CHECK(m.conn.is_open());
	m.check_server();

	REQUIRE(m.log.received.size() == 5);
	// SEQUENCE { [0] user, [1] old, [2] new }
	CHECK(m.log.received[0]
		  == ldap::message{ 1,
			ldap::extended_request{ ldap::password_modify_oid,
			  "\x30\x30\x80\x24uid=jdoe,ou=people,dc=example,dc=org\x81\x03old\x82\x03new"s } });
	// Nothing to send: no requestValue at all.
	CHECK(m.log.received[1] == ldap::message{ 2, ldap::extended_request{ ldap::password_modify_oid } });
	CHECK(m.log.received[2]
		  == ldap::message{ 3, ldap::extended_request{ ldap::password_modify_oid, "\x30\x03\x82\x01x"s } });
}
