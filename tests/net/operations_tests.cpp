// Step 6 operations against the scripted mock server (mock_ldap.hpp): add,
// modify, delete, modify DN, compare, extended / who am I, typed controls,
// paged search and referrals.
#include "jhetz/ldap/connection.hpp"
#include "jhetz/ldap/controls.hpp"
#include "jhetz/ldap/extended_operations.hpp"
#include "jhetz/ldap/sync.hpp"
#include "mock_ldap.hpp"
#include "net_test_support.hpp"

#include <boost/capy/ex/frame_allocator.hpp>

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>
#include <catch2/matchers/catch_matchers_container_properties.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <memory_resource>
#include <new>
#include <optional>
#include <span>
#include <stop_token>
#include <string>
#include <system_error>
#include <thread>
#include <variant>
#include <vector>

namespace ldap = jhetz::ldap;
using namespace jhetz::ldap::test;
using Catch::Matchers::ContainsSubstring;
using Catch::Matchers::IsEmpty;
using Catch::Matchers::StartsWith;
using ldap::client_errc;
using ldap::errc;

namespace {

template<class Response>
auto result_msg(std::int32_t id, std::int32_t code = 0, std::string_view diagnostic = {}) -> ldap::message
{
	return ldap::message{ id, Response{ ldap::ldap_result{ code, "", diagnostic } } };
}

const ldap::dn jdoe{ "uid=jdoe,ou=people,dc=example,dc=org" };

auto post_read_control() -> ldap::control { return ldap::control{ "1.3.6.1.1.13.2", false, "entry" }; }

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

// The operation's DN is often one the server returned (an entry's, a
// referral's): the context quotes it sanitized (valid UTF-8 kept, C1 and
// bidi controls shown as U+FFFD) and cut at 256 bytes, as an entry's. So
// is a password modify's user.
TEST_CASE("operations: the context quotes the DN sanitized", "[net][operations]")
{
	mock_ldap m;
	m.serve({ answer({ result_msg<ldap::modify_response>(1, 50, "no write access") }),
	  answer({ ldap::message{ 2, ldap::extended_response{ ldap::ldap_result{ 50 } } } }) });
	// 16 bytes: U+202E, U+0085 (C1), accents and CJK; then z up to the cut.
	auto parsed = ldap::dn::parse(
	  "cn=\xE2\x80\xAE\xC2\x85\xC3\xA9\xE6\x97\xA5\xE6\x9C\xAC" + std::string(1000, 'z') + ",dc=example,dc=org");
	REQUIRE(parsed.has_value());
	const ldap::dn target = std::move(*parsed);
	auto r = m.run(m.conn.modify({ .object = target, .changes = { ldap::mod::replace("sn", { "X" }) } }));
	REQUIRE_FALSE(r.has_value());
	CHECK(r.error().code == ldap::cond::access_denied);
	const std::string fffd = "\xEF\xBF\xBD";
	CHECK(std::string(r.error().context)
		  == "modify cn=" + fffd + fffd + "\xC3\xA9\xE6\x97\xA5\xE6\x9C\xAC" + std::string(256 - 16, 'z') + "...");
	// A password modify's user, usually a DN, likewise.
	auto pw =
	  m.run(ldap::password_modify(m.conn, { .user = "uid=\r\n\xE2\x80\xA8j\xC3\xB6rg", .new_password = "new" }));
	REQUIRE_FALSE(pw.has_value());
	CHECK(pw.error().code == ldap::cond::access_denied);
	CHECK(std::string(pw.error().context) == "password modify uid=" + fffd + fffd + fffd + "j\xC3\xB6rg");
	m.check_server();
	REQUIRE(m.log.received.size() == 2);
	// The request carries the DN as given.
	CHECK(std::get<ldap::modify_request>(m.log.received[0].op).object == target.to_string());
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
	REQUIRE(
	  m.run(m.conn.modify_dn({
			  .entry = jdoe,
			  .new_rdn = ldap::rdn{ "uid=john.doe" },
			  .delete_old_rdn = false,
			}))
		.has_value());
	// Move under another parent, same RDN.
	REQUIRE(
	  m.run(m.conn.modify_dn({
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

	auto me = m.run(ldap::who_am_i(m.conn));
	REQUIRE(me.has_value());
	CHECK(*me == "dn:cn=admin,dc=example,dc=org");
	auto anon = m.run(ldap::who_am_i(m.conn));
	REQUIRE(anon.has_value());
	CHECK(anon->empty());

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

// The authzId is an LDAPString (RFC 4532 section 2.2): UTF-8, checked as
// a mapped string value is; the connection stays usable.
TEST_CASE("operations: who am I with an authzId that is not UTF-8", "[net][operations]")
{
	mock_ldap m;
	m.serve(
	  { answer({ ldap::message{ 1, ldap::extended_response{ ldap::ldap_result{ 0 }, std::nullopt, "u:caf\xE9" } } }),
		answer({ ldap::message{
		  2, ldap::extended_response{ ldap::ldap_result{ 0 }, std::nullopt, "u:caf\xC3\xA9 \xE6\x97\xA5" } } }) });

	auto bad = m.run(ldap::who_am_i(m.conn));
	REQUIRE_FALSE(bad.has_value());
	CHECK(bad.error().code == client_errc::conversion_failed);
	CHECK(bad.error().context == "who_am_i authzId: not valid UTF-8 (ill-formed sequence at offset 5)");
	CHECK(m.conn.is_open());

	auto good = m.run(ldap::who_am_i(m.conn));
	REQUIRE(good.has_value());
	CHECK(*good == "u:caf\xC3\xA9 \xE6\x97\xA5");
	m.check_server();
}

TEST_CASE("operations: extended() refuses StartTLS before sending", "[net][operations]")
{
	mock_ldap m;
	m.serve({ answer({ ldap::message{ 1, ldap::extended_response{ ldap::ldap_result{ 0 } } } }) });
	auto tls = m.run(m.conn.extended(
	  { .name = std::string(ldap::start_tls_oid), .controls = { ldap::proxied_authorization{ "dn:cn=x" } } }));
	REQUIRE_FALSE(tls.has_value());
	CHECK(tls.error().code == client_errc::encode_error);
	CHECK(tls.error().context == "extended operation 1.3.6.1.4.1.1466.20037: use start_tls()");
	CHECK(m.log.received.empty());
	CHECK(m.conn.is_open());
	// The id was not used up.
	CHECK(m.run(m.conn.extended({ .name = "1.2.3.4" })).has_value());
	m.check_server();
	REQUIRE(m.log.received.size() == 1);
	CHECK(m.log.received[0] == ldap::message{ 1, ldap::extended_request{ "1.2.3.4" } });
}

TEST_CASE("operations: extended operations with intermediate responses", "[net][operations][intermediate]")
{
	ldap::message with_control{ 1, ldap::intermediate_response{} };
	with_control.controls.emplace_back("1.2.3.7", false, "c");
	auto script = [&](std::int32_t id, std::int32_t code = 0) {
		with_control.id = id;
		return answer({ ldap::message{ id, ldap::intermediate_response{ "1.2.3.6", "first" } },
		  with_control,
		  ldap::message{ id, ldap::intermediate_response{ std::nullopt, "third" } },
		  ldap::message{ id, ldap::extended_response{ ldap::ldap_result{ code }, "1.2.3.5", "done" } } });
	};

	SECTION("collected in order for a caller that asks")
	{
		mock_ldap m;
		m.serve({ script(1) });
		auto x = m.run(m.conn.extended({ .name = "1.2.3.4", .intermediate_responses = true }));
		REQUIRE(x.has_value());
		CHECK(x->name == "1.2.3.5");
		CHECK(x->value == "done");
		REQUIRE(x->intermediates.size() == 3);
		CHECK(x->intermediates[0].response_name == "1.2.3.6");
		CHECK(x->intermediates[0].response_value == "first");
		CHECK(x->intermediates[0].controls.empty());
		CHECK_FALSE(x->intermediates[1].response_name.has_value());
		CHECK_FALSE(x->intermediates[1].response_value.has_value());
		REQUIRE(x->intermediates[1].controls.size() == 1);
		CHECK(x->intermediates[1].controls[0] == ldap::control{ "1.2.3.7", false, "c" });
		CHECK_FALSE(x->intermediates[2].response_name.has_value());
		CHECK(x->intermediates[2].response_value == "third");
		CHECK(m.conn.is_open());
		m.check_server();
	}
	SECTION("skipped for a caller that does not")
	{
		mock_ldap m;
		m.serve({ script(1), script(2) });
		auto x = m.run(m.conn.extended({ .name = "1.2.3.4" }));
		REQUIRE(x.has_value());
		CHECK(x->name == "1.2.3.5");
		CHECK(x->value == "done");
		CHECK(x->intermediates.empty());
		auto me = m.run(ldap::who_am_i(m.conn));
		REQUIRE(me.has_value());
		CHECK(*me == "done");
		CHECK(m.conn.is_open());
		m.check_server();
	}
	SECTION("a server error still fails the operation")
	{
		mock_ldap m;
		m.serve({ script(1, 53) });
		auto x = m.run(m.conn.extended({ .name = "1.2.3.4", .intermediate_responses = true }));
		REQUIRE_FALSE(x.has_value());
		CHECK(x.error().code == errc::unwilling_to_perform);
		CHECK(m.conn.is_open());
		m.check_server();
	}
	SECTION("late ones after an abandon are dropped, and so is the final response")
	{
		// The server sends them racing the AbandonRequest: an
		// IntermediateResponse is not the last answer to the abandoned
		// request, so its ExtendedResponse is still recognized and dropped.
		mock_ldap m;
		m.serve({ step{},// reads the extended request, does not answer yet
		  script(1),// reads its AbandonRequest, answers the abandoned request late
		  answer({ ldap::message{ 3, ldap::extended_response{ ldap::ldap_result{ 0 }, std::nullopt, "dn:x" } } }) });
		auto x = m.run(m.conn.extended(
		  { .name = "1.2.3.4", .timeout = std::chrono::milliseconds(50), .intermediate_responses = true }));
		REQUIRE_FALSE(x.has_value());
		CHECK(x.error().code == ldap::cond::timeout);
		auto me = m.run(ldap::who_am_i(m.conn));
		REQUIRE(me.has_value());
		CHECK(*me == "dn:x");
		CHECK(m.conn.is_open());
		m.check_server();
		REQUIRE(m.log.received.size() == 3);
		CHECK(m.log.received[1] == ldap::message{ 2, ldap::abandon_request{ 1 } });
	}
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

TEST_CASE("operations: root_dse() reads the root DSE", "[net][operations]")
{
	mock_ldap m;
	m.serve({ answer({ entry_msg(1, "", "root"), done_msg(1) }) });
	auto r = m.run(m.conn.search(ldap::root_dse({ "namingContexts" })));
	REQUIRE(r.has_value());
	REQUIRE(r->entries.size() == 1);
	CHECK(r->entries[0].dn.empty());
	m.check_server();
	REQUIRE(m.log.received.size() == 1);
	const auto &sent = std::get<ldap::search_request>(m.log.received[0].op);
	CHECK(sent.base_object.empty());
	CHECK(sent.scope == ldap::search_scope::base_object);
	CHECK(sent.filter == ldap::filters::attr("objectClass").present());
	CHECK(sent.attributes == ldap::string_list{ "namingContexts" });
	CHECK(ldap::root_dse().attributes == ldap::string_list{ "*", "+" });
}

// ---------------------------------------------------------------- controls

TEST_CASE("operations: typed controls on the wire", "[net][operations][controls]")
{
	mock_ldap m;
	m.serve({ answer({ done_msg(1) }) });
	REQUIRE(
	  m.run(m.conn.search({
			  .base = ldap::dn{},
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

	auto bad = m.run(m.conn.search({ .base = ldap::dn{}, .controls = { ldap::paged{ .page_size = -1 } } }));
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
	sorted.controls.push_back(*ldap::encode_sort_result(ldap::sort_result{ 0 }));
	ldap::message unsorted = done_msg(2);
	unsorted.controls.push_back(*ldap::encode_sort_result({ 18, "cn" }));
	ldap::message garbage = done_msg(3);
	garbage.controls.emplace_back(ldap::sort_response_oid, false, "x");
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
		if (!e->has_value()) {
			break;
		}
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
	auto no_keys = m.run(m.conn.search({ .base = ldap::dn{}, .controls = { ldap::server_side_sort{} } }));
	REQUIRE_FALSE(no_keys.has_value());
	CHECK(no_keys.error().code == client_errc::encode_error);
	auto no_filter = m.run(m.conn.del({ .entry = jdoe, .controls = { ldap::assertion{} } }));
	REQUIRE_FALSE(no_filter.has_value());
	CHECK(no_filter.error().code == client_errc::invalid_filter);
	CHECK(m.log.received.size() == 3);
}

TEST_CASE("operations: matched values on a search", "[net][operations][controls]")
{
	mock_ldap m;
	// The server returns only the matching member value.
	m.serve({ answer({ ldap::message{ 1,
						 ldap::search_result_entry{ "cn=staff,ou=groups,dc=example,dc=org",
						   { ldap::partial_attribute{ "member", { jdoe.to_string() } } } } },
	  done_msg(1) }) });
	const ldap::matched_values only_jdoe{ .values_return_filter = {
											ldap::filters::attr("member") == jdoe.to_string() } };
	auto r = m.run(m.conn.search({ .base = ldap::dn{ "cn=staff,ou=groups,dc=example,dc=org" },
	  .scope = ldap::search_scope::base_object,
	  .attributes = { "member" },
	  .controls = { only_jdoe } }));
	REQUIRE(r.has_value());
	REQUIRE(r->entries.size() == 1);
	CHECK(*r->entries.front().find("member") == ldap::string_list{ jdoe.to_string() });
	m.check_server();

	// The server reads back what was sent.
	REQUIRE(m.log.received.size() == 1);
	REQUIRE(m.log.received[0].controls.size() == 1);
	const auto &sent = m.log.received[0].controls[0];
	CHECK(sent == ldap::to_control(only_jdoe).value());
	CHECK(ldap::decode_matched_values(sent).value() == only_jdoe);

	// An item RFC 3876 excludes fails before anything is sent.
	auto bad = m.run(m.conn.search({ .base = ldap::dn{},
	  .controls = { ldap::matched_values{ .values_return_filter = { ldap::filters::attr("member") == jdoe.to_string()
																	|| ldap::filters::attr("cn") == "x" } } } }));
	REQUIRE_FALSE(bad.has_value());
	CHECK(bad.error().code == client_errc::invalid_filter);
	CHECK_THAT(std::string(bad.error().context),
	  ContainsSubstring("matched values: item 1 is (|...), not a simple filter item (RFC 3876 section 2)"));
	CHECK(m.log.received.size() == 1);
}

TEST_CASE("operations: a virtual list view window", "[net][operations][controls]")
{
	mock_ldap m;
	ldap::message window = done_msg(1);
	window.controls.push_back(*ldap::encode_sort_result(ldap::sort_result{ 0 }));
	window.controls.push_back(*ldap::encode_vlv_response({ 2, 3, 0, "ctx" }));
	ldap::message out_of_range = done_msg(2, 76, "", "offset out of range");
	out_of_range.controls.push_back(*ldap::encode_vlv_response({ 0, 3, 61, "ctx" }));
	m.serve({ answer({ entry_msg(1, "uid=a,ou=people,dc=example,dc=org", "A"),
				entry_msg(1, "uid=b,ou=people,dc=example,dc=org", "B"),
				window }),
	  answer({ out_of_range }) });

	const ldap::server_side_sort by_cn{ .keys = { { .attribute = "cn" } } };
	const ldap::virtual_list_view around_second{ .before_count = 1, .target = ldap::vlv_by_offset{ .offset = 2 } };
	auto s = m.run(m.conn.search_stream(
	  { .base = ldap::dn{ "ou=people,dc=example,dc=org" }, .controls = { by_cn, around_second } }));
	REQUIRE(s.has_value());
	std::vector<std::string> dns;
	while (true) {
		auto e = m.run(s->next());
		REQUIRE(e.has_value());
		if (!e->has_value()) {
			break;
		}
		dns.emplace_back((*e)->dn);
	}
	CHECK(dns == std::vector<std::string>{ "uid=a,ou=people,dc=example,dc=org", "uid=b,ou=people,dc=example,dc=org" });
	auto r = ldap::find_vlv_response(s->controls());
	REQUIRE(r.has_value());
	REQUIRE(r->has_value());
	CHECK(**r == ldap::vlv_response{ 2, 3, 0, "ctx" });

	// The next window sends the server's count and contextID back; the
	// server refuses it with resultCode 76 and says why in the response
	// control, which the stream keeps with the error.
	const ldap::virtual_list_view beyond{ .target =
											ldap::vlv_by_offset{ .offset = 9, .content_count = (*r)->content_count },
		.context_id = std::string(*(*r)->context_id) };
	auto s2 =
	  m.run(m.conn.search_stream({ .base = ldap::dn{ "ou=people,dc=example,dc=org" }, .controls = { by_cn, beyond } }));
	REQUIRE(s2.has_value());
	auto failed = m.run(s2->next());
	REQUIRE_FALSE(failed.has_value());
	CHECK(failed.error().code == errc::virtual_list_view_error);
	CHECK(failed.error().diagnostic == "offset out of range");
	auto why = ldap::find_vlv_response(s2->controls());
	REQUIRE(why.has_value());
	REQUIRE(why->has_value());
	CHECK((*why)->result_code == 61);
	CHECK(m.conn.is_open());
	m.check_server();

	REQUIRE(m.log.received.size() == 2);
	REQUIRE(m.log.received[0].controls.size() == 2);
	CHECK(m.log.received[0].controls[0] == ldap::to_control(by_cn).value());
	CHECK(ldap::decode_virtual_list_view(m.log.received[0].controls[1]).value() == around_second);
	CHECK(ldap::decode_virtual_list_view(m.log.received[1].controls.at(1)).value() == beyond);

	// Without a sort control nothing is sent.
	auto alone = m.run(m.conn.search({ .base = ldap::dn{}, .controls = { around_second } }));
	REQUIRE_FALSE(alone.has_value());
	CHECK(alone.error().code == client_errc::encode_error);
	CHECK_THAT(
	  std::string(alone.error().context), ContainsSubstring("virtual_list_view needs a server_side_sort control"));
	CHECK(m.log.received.size() == 2);
}

// ---------------------------------------------------------------- paged search

namespace {

auto paged_done(std::int32_t id, std::string_view cookie) -> ldap::message
{
	ldap::message m = done_msg(id);
	m.controls.push_back(*ldap::encode_paged_results({ 0, cookie }));
	return m;
}

auto drain_paged(ldap::paged_search &s) -> capy::task<ldap::result<std::vector<std::string>>>
{
	std::vector<std::string> dns;
	while (true) {
		auto e = co_await s.next();
		if (!e) {
			co_return std::unexpected(std::move(e.error()));
		}
		if (!*e) {
			co_return dns;
		}
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
	std::int32_t id = 0;
	for (std::size_t i = 0; i < 3; ++i) {
		INFO("page " << i);
		const auto &req = m.log.received[i];
		CHECK(req.id == ++id);
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
		done.controls.emplace_back(ldap::paged_results_oid, false, "garbage");
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

TEST_CASE("operations: collected pages end with a limit code as search() does", "[net][operations][paged]")
{
	SECTION("a size limit on a later page keeps every page's entries")
	{
		mock_ldap m;
		m.serve({ answer({ entry_msg(1, "uid=a,ou=people,dc=example,dc=org", "A"),
					ref_msg(1, { "ldap://other.example.org/ou=people,dc=example,dc=org" }),
					paged_done(1, "next") }),
		  answer({ entry_msg(2, "uid=b,ou=people,dc=example,dc=org", "B"), done_msg(2, 4, "", "size limit") }) });
		auto r = m.run(ldap::sync::detail::collect_paged(m.conn, people_search(), 1, std::pmr::get_default_resource()));
		REQUIRE(r.has_value());
		CHECK(r->result_code == 4);
		CHECK(r->diagnostic_message == "size limit");
		REQUIRE(r->entries.size() == 2);
		CHECK(r->entries[1] == expected_entry("uid=b,ou=people,dc=example,dc=org", "B"));
		CHECK(r->references == ldap::string_list{ "ldap://other.example.org/ou=people,dc=example,dc=org" });
		m.check_server();
	}
	SECTION("a malformed paged results control stays an error")
	{
		mock_ldap m;
		ldap::message done = done_msg(1);
		done.controls.emplace_back(ldap::paged_results_oid, false, "garbage");
		m.serve({ answer({ entry_msg(1, "uid=a,ou=people,dc=example,dc=org", "A"), done }) });
		auto r = m.run(ldap::sync::detail::collect_paged(m.conn, people_search(), 1, std::pmr::get_default_resource()));
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == ldap::cond::protocol_error);
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

auto bind_admin(ldap::connection &c) -> capy::task<ldap::result<void>>
{
	co_return co_await c.simple_bind(*ldap::dn::parse(admin), "secret");
}

// Reads one entry of a paged search of page size 1 whose first page ends
// with cookie "page2", then destroys it: the release (id 2) is sent and
// read by the server's second step. `M` is mock_ldap or tcp_mock_ldap.
template<class M> void release_after_one_page(M &m, ldap::search_params params = people_search())
{
	auto s = m.run(m.conn.search_paged(std::move(params), 1));
	REQUIRE(s.has_value());
	auto e = m.run(s->next());
	REQUIRE(e.has_value());
	REQUIRE(e->has_value());
	drive_until(m.ioc, [&m] { return m.conn.outstanding() == 0; });
	*s = ldap::paged_search{};
	drive_until(m.ioc, [&m] { return m.log.received.size() == 2; });
	REQUIRE(m.log.received.size() == 2);
}

// Writes `msg` from the server's end, outside its script.
template<class M> void server_sends(M &m, const ldap::message &msg)
{
	auto t = m.server_end();
	const std::string bytes = bytes_of(msg);
	REQUIRE(m.run(net::write_bytes(t, std::as_bytes(std::span(bytes)))).has_value());
}

// Runs the io_context briefly (the reader stays parked): what is ready
// runs, and a request sent meanwhile reaches the server. 20 ms proves
// nothing positive under load: it only precedes checks that something did
// not happen (not done yet, nothing more sent).
template<class M> void settle(M &m)
{
	m.ioc.run_for(std::chrono::milliseconds(20));
	m.ioc.restart();
}

// The server's answer to StartTLS over tcp_mock_ldap, which does not speak
// TLS: a refusal, which leaves the connection usable in clear.
auto start_tls_refused(std::int32_t id) -> ldap::message
{
	return ldap::message{ id, ldap::extended_response{ ldap::ldap_result{ 52, "", "no TLS here" } } };
}

auto is_start_tls(const ldap::message &m) -> bool
{
	const auto *x = std::get_if<ldap::extended_request>(&m.op);
	return x != nullptr && x->request_name == ldap::start_tls_oid;
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
	CHECK(m.conn.outstanding() == 1);// the release's answer is due
	auto b = m.run(bind_admin(m.conn));
	CHECK(m.conn.outstanding() == 0);
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
		// The abandoned page is not counted (it may never be answered), the
		// release is (its answer is certain).
		CHECK(m.conn.outstanding() == 1);
		auto b = m.run(bind_admin(m.conn));
		CHECK(m.conn.outstanding() == 0);
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
			// Past the end: no more entries, nothing sent.
			auto after = m.run(s->next());
			REQUIRE(after.has_value());
			CHECK_FALSE(after->has_value());
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
			// The error again, nothing sent.
			auto again = m.run(s->next());
			REQUIRE_FALSE(again.has_value());
			CHECK(again.error().code == errc::busy);
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
		CHECK(m.conn.outstanding() == 2);// the bind, and the held release's answer
		drive_until(m.ioc, [&bound] { return bound.done(); });
		CHECK(bound.get().has_value());
		drive_until(m.ioc, [&m] { return m.conn.outstanding() == 0; });// sent after the bind, and answered
		CHECK(m.conn.outstanding() == 0);
		auto b = m.run(bind_admin(m.conn));
		CHECK(b.has_value());
		m.check_server();
		REQUIRE(m.log.received.size() == 4);
		CHECK(m.log.received[1] == bind_request_msg(2));
		CHECK(m.log.received[2].id == 3);
		check_release(m.log.received[2], m.log.received[0], "page2");
		CHECK(m.log.received[3] == bind_request_msg(4));
	}
	SECTION("closed while the release's answer is due: no longer counted")
	{
		mock_ldap m;
		m.serve({ answer({ entry_msg(1, "uid=a,ou=people,dc=example,dc=org", "A"), paged_done(1, "page2") }),
		  step{} });// reads the release, never answers
		release_after_one_page(m);
		CHECK(m.conn.outstanding() == 1);
		m.conn.close();
		CHECK(m.conn.outstanding() == 0);
		CHECK_FALSE(m.conn.is_open());
	}
	SECTION("sent as the reader stops (nothing else outstanding): a reader reads its answer")
	{
		mock_ldap m;
		m.serve({ answer({ entry_msg(1, "uid=a,ou=people,dc=example,dc=org", "A"), paged_done(1, "page2") }),
		  answer({ entry_msg(2, "uid=b,ou=people,dc=example,dc=org", "B") }),
		  step{},// reads the AbandonRequest
		  answer({ paged_done(4, "") }) });// the release's answer, the script's last step
		{
			auto s = m.run(m.conn.search_paged(people_search(), 1));
			REQUIRE(s.has_value());
			for (int i = 0; i < 2; ++i) {
				auto e = m.run(s->next());
				REQUIRE(e.has_value());
				REQUIRE(e->has_value());
			}
			CHECK(m.conn.outstanding() == 1);// page 2, read by the reader
		}// abandoning page 2 stops the reader; the release follows at once
		CHECK(m.conn.outstanding() == 1);
		// No other operation runs: only a reader restarted for the release
		// reads its answer (else the io_context runs out of work first).
		drive_until(m.ioc, [&m] { return m.conn.outstanding() == 0; });
		CHECK(m.conn.outstanding() == 0);
		CHECK(m.conn.is_open());
		m.check_server();
		REQUIRE(m.log.received.size() == 4);
		CHECK(m.log.received[2] == ldap::message{ 3, ldap::abandon_request{ 2 } });
		CHECK(m.log.received[3].id == 4);
		check_release(m.log.received[3], m.log.received[0], "page2");
	}
	// A lifetime test for ASan: whether the release was written before the
	// connection closed depends on scheduling, so both outcomes pass.
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
		if (m.log.received.size() == 2) {
			check_release(m.log.received[1], m.log.received[0], "page2");
		}
	}
}

// Two releases with deadlines: the second is sent while the due watcher
// already waits for the first, which recomputes its next deadline.
TEST_CASE("operations: two paged search releases due at once", "[net][operations][paged][timeout]")
{
	mock_ldap m;
	m.serve({ answer({ entry_msg(1, "uid=a,ou=people,dc=example,dc=org", "A"), paged_done(1, "a2") }),
	  answer({ entry_msg(2, "uid=b,ou=people,dc=example,dc=org", "B"), paged_done(2, "b2") }),
	  step{},// reads the first release, answers later
	  answer({ paged_done(3, ""), paged_done(4, "") }) });
	ldap::search_params p = people_search();
	p.timeout = std::chrono::seconds(30);
	{
		auto a = m.run(m.conn.search_paged(p, 1));
		REQUIRE(a.has_value());
		auto b = m.run(m.conn.search_paged(p, 1));
		REQUIRE(b.has_value());
		auto ea = m.run(a->next());
		REQUIRE(ea.has_value());
		REQUIRE(ea->has_value());
		auto eb = m.run(b->next());
		REQUIRE(eb.has_value());
		REQUIRE(eb->has_value());
		drive_until(m.ioc, [&m] { return m.conn.outstanding() == 0; });
		*a = ldap::paged_search{};
		CHECK(m.conn.outstanding() == 1);
		drive_until(m.ioc, [&m] { return m.log.received.size() == 3; });
		*b = ldap::paged_search{};
		CHECK(m.conn.outstanding() == 2);
	}
	drive_until(m.ioc, [&m] { return m.conn.outstanding() == 0; });
	CHECK(m.conn.outstanding() == 0);
	CHECK(m.conn.is_open());
	m.check_server();
	REQUIRE(m.log.received.size() == 4);
	check_release(m.log.received[2], m.log.received[0], "a2");
	check_release(m.log.received[3], m.log.received[1], "b2");
}

// RFC 4513 section 3.1.1: StartTLS is not sent while a response is still
// due, and the answer to a release is always due: StartTLS waits for it.
// Over tcp_mock_ldap StartTLS is sent once the wait ends, and the server
// refuses it (errc::unavailable), which leaves the connection usable.
TEST_CASE("operations: StartTLS waits for the answer to a paged search release", "[net][operations][paged][starttls]")
{
	SECTION("waits until the release's SearchResultDone arrives, then proceeds")
	{
		tcp_mock_ldap m;
		m.serve({ answer({ entry_msg(1, "uid=a,ou=people,dc=example,dc=org", "A"), paged_done(1, "page2") }),
		  step{},// reads the release, does not answer
		  answer({ start_tls_refused(3) }) });
		release_after_one_page(m);
		outcome<ldap::result<void>> tls;
		spawn(m.ioc, m.conn.start_tls(), tls);
		settle(m);
		CHECK_FALSE(tls.done());
		CHECK(m.conn.outstanding() == 1);
		CHECK(m.log.received.size() == 2);// no StartTLS yet

		server_sends(m, paged_done(2, ""));
		drive_until(m.ioc, [&tls] { return tls.done(); });
		REQUIRE_FALSE(tls.get().has_value());
		CHECK(tls.get().error().code == errc::unavailable);// sent, and refused
		CHECK(m.conn.outstanding() == 0);
		CHECK(m.conn.is_open());
		m.check_server();
		REQUIRE(m.log.received.size() == 3);
		check_release(m.log.received[1], m.log.received[0], "page2");
		CHECK(is_start_tls(m.log.received[2]));
	}
	SECTION("two StartTLS wait: one proceeds, the other is refused")
	{
		tcp_mock_ldap m;
		m.serve({ answer({ entry_msg(1, "uid=a,ou=people,dc=example,dc=org", "A"), paged_done(1, "page2") }),
		  step{},// reads the release, does not answer
		  answer({ start_tls_refused(3) }) });
		release_after_one_page(m);
		outcome<ldap::result<void>> first;
		outcome<ldap::result<void>> second;
		spawn(m.ioc, m.conn.start_tls(), first);
		spawn(m.ioc, m.conn.start_tls(), second);
		while (m.ioc.poll() != 0) {}
		m.ioc.restart();
		CHECK_FALSE(first.done());// both wait for the release's answer
		CHECK_FALSE(second.done());
		server_sends(m, paged_done(2, ""));
		drive_until(m.ioc, [&] { return first.done() && second.done(); });
		REQUIRE_FALSE(first.get().has_value());
		REQUIRE_FALSE(second.get().has_value());
		// Either may be woken first: exactly one is sent (and refused by the
		// server), the other then sees it running.
		const bool first_sent = first.get().error().code == errc::unavailable;
		const ldap::error &sent = (first_sent ? first : second).get().error();
		const ldap::error &refused = (first_sent ? second : first).get().error();
		CHECK(sent.code == errc::unavailable);
		CHECK(refused.code == client_errc::operation_in_progress);
		CHECK(refused.context == "start tls during an earlier StartTLS");
		CHECK(m.conn.is_open());
		CHECK(m.conn.outstanding() == 0);
		m.check_server();
		REQUIRE(m.log.received.size() == 3);// one StartTLS
		CHECK(is_start_tls(m.log.received[2]));
	}
	SECTION("not a plain TCP connection: refused at once, answers due or not")
	{
		mock_ldap m;// a wrapped custom stream
		m.serve({ answer({ entry_msg(1, "uid=a,ou=people,dc=example,dc=org", "A"), paged_done(1, "page2") }),
		  step{} });// reads the release, does not answer
		release_after_one_page(m);
		auto r = m.run(m.conn.start_tls());
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == std::errc::invalid_argument);
		CHECK(m.conn.outstanding() == 1);// still due
		server_sends(m, paged_done(2, ""));
		drive_until(m.ioc, [&m] { return m.conn.outstanding() == 0; });
		CHECK(m.conn.outstanding() == 0);
		CHECK(m.conn.is_open());
		m.check_server();
		CHECK(m.log.received.size() == 2);
	}
	SECTION("refused for a real operation, answers due or not")
	{
		mock_ldap m;
		m.serve({ answer({ entry_msg(1, "uid=a,ou=people,dc=example,dc=org", "A"), paged_done(1, "page2") }),
		  step{},// reads the release, does not answer
		  step{} });// reads the bind, does not answer
		release_after_one_page(m);
		outcome<ldap::result<void>> bound;
		spawn(m.ioc, bind_admin(m.conn), bound);
		drive_until(m.ioc, [&m] { return m.log.received.size() == 3; });
		auto r = m.run(m.conn.start_tls());
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == client_errc::operation_in_progress);
		CHECK(r.error().context == "start tls during a bind");
		server_sends(m, paged_done(2, ""));
		server_sends(m, bind_resp(3));
		drive_until(m.ioc, [&bound] { return bound.done(); });
		CHECK(bound.get().has_value());
		CHECK(m.conn.outstanding() == 0);
	}
	SECTION("a bind started while it waits: refused once the answer arrives, as if called then")
	{
		tcp_mock_ldap m;
		m.serve({ answer({ entry_msg(1, "uid=a,ou=people,dc=example,dc=org", "A"), paged_done(1, "page2") }),
		  step{},// reads the release, does not answer
		  step{} });// reads the bind, does not answer
		release_after_one_page(m);
		outcome<ldap::result<void>> tls;
		spawn(m.ioc, m.conn.start_tls(), tls);
		settle(m);
		CHECK_FALSE(tls.done());
		outcome<ldap::result<void>> bound;
		spawn(m.ioc, bind_admin(m.conn), bound);
		drive_until(m.ioc, [&m] { return m.log.received.size() == 3; });
		CHECK_FALSE(tls.done());
		server_sends(m, paged_done(2, ""));
		drive_until(m.ioc, [&tls] { return tls.done(); });
		REQUIRE_FALSE(tls.get().has_value());
		CHECK(tls.get().error().code == client_errc::operation_in_progress);
		CHECK(tls.get().error().context == "start tls during a bind");
		server_sends(m, bind_resp(3));
		drive_until(m.ioc, [&bound] { return bound.done(); });
		CHECK(bound.get().has_value());
		CHECK(m.conn.outstanding() == 0);
		CHECK(m.conn.is_open());
		m.check_server();
		CHECK(m.log.received.size() == 3);// no StartTLS
	}
	SECTION("the release's deadline passes: StartTLS proceeds, the reader stops, a late answer is dropped")
	{
		tcp_mock_ldap m;
		m.serve({ answer({ entry_msg(1, "uid=a,ou=people,dc=example,dc=org", "A"), paged_done(1, "page2") }),
		  step{},// reads the release, never answers in time
		  answer({ start_tls_refused(3) }) });
		auto p = people_search();
		p.timeout = std::chrono::milliseconds(100);// the page's limit, and the release's
		release_after_one_page(m, std::move(p));
		CHECK(m.conn.outstanding() == 1);
		const auto start = std::chrono::steady_clock::now();
		auto r = m.run(m.conn.start_tls());// no limit of its own
		CHECK(std::chrono::steady_clock::now() - start >= std::chrono::milliseconds(50));// most of the 100 ms
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == errc::unavailable);// sent, and refused
		CHECK(m.conn.outstanding() == 0);
		m.check_server();
		REQUIRE(m.log.received.size() == 3);
		CHECK(is_start_tls(m.log.received[2]));
		// Nothing left running: no reader parked on the socket, no timer.
		const auto idle = std::chrono::steady_clock::now();
		m.ioc.run_for(io_limit);
		m.ioc.restart();
		CHECK(std::chrono::steady_clock::now() - idle < io_limit / 2);

		// The release's id is still known: its late answer is dropped.
		server_sends(m, paged_done(2, ""));
		server_sends(m, bind_resp(4));// answers the bind below before it is read
		auto b = m.run(bind_admin(m.conn));
		CHECK(b.has_value());
		CHECK(m.conn.is_open());
		CHECK(m.conn.outstanding() == 0);
	}
	SECTION("the release's deadline from connection_options::operation_timeout")
	{
		mock_ldap m({ .operation_timeout = std::chrono::milliseconds(100) });
		m.serve({ answer({ entry_msg(1, "uid=a,ou=people,dc=example,dc=org", "A"), paged_done(1, "page2") }),
		  step{} });// reads the release, never answers
		release_after_one_page(m);
		CHECK(m.conn.outstanding() == 1);
		drive_until(m.ioc, [&m] { return m.conn.outstanding() == 0; });
		CHECK(m.conn.outstanding() == 0);
		CHECK(m.conn.is_open());
	}
	SECTION("its own timeout, or a stop, ends the wait; nothing is sent")
	{
		tcp_mock_ldap m;
		m.serve({ answer({ entry_msg(1, "uid=a,ou=people,dc=example,dc=org", "A"), paged_done(1, "page2") }),
		  step{} });// reads the release, does not answer
		release_after_one_page(m);
		auto r = m.run(m.conn.start_tls({}, std::chrono::milliseconds(30)));
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == ldap::cond::timeout);
		CHECK(r.error().context == "start tls (waiting for the answer to 1 paged search release)");

		std::stop_source cancel;
		outcome<ldap::result<void>> tls;
		spawn(m.ioc, ldap::with_stop(cancel.get_token(), m.conn.start_tls()), tls);
		settle(m);
		CHECK_FALSE(tls.done());
		cancel.request_stop();
		drive_until(m.ioc, [&tls] { return tls.done(); });
		REQUIRE_FALSE(tls.get().has_value());
		CHECK(tls.get().error().code == ldap::cond::canceled);
		CHECK(tls.get().error().context == "start tls (waiting for the answer to 1 paged search release)");

		CHECK(m.conn.is_open());
		CHECK(m.conn.outstanding() == 1);// still due
		server_sends(m, paged_done(2, ""));
		drive_until(m.ioc, [&m] { return m.conn.outstanding() == 0; });
		CHECK(m.conn.outstanding() == 0);
		m.check_server();
		settle(m);
		CHECK(m.log.received.size() == 2);// no StartTLS
	}
	SECTION("the connection closes while it waits")
	{
		tcp_mock_ldap m;
		m.serve({ answer({ entry_msg(1, "uid=a,ou=people,dc=example,dc=org", "A"), paged_done(1, "page2") }),
		  step{} });// reads the release, does not answer
		release_after_one_page(m);
		outcome<ldap::result<void>> tls;
		spawn(m.ioc, m.conn.start_tls(), tls);
		settle(m);
		CHECK_FALSE(tls.done());
		m.conn.close();
		drive_until(m.ioc, [&tls] { return tls.done(); });
		REQUIRE_FALSE(tls.get().has_value());
		CHECK(tls.get().error().code == client_errc::not_sent);
		CHECK(tls.get().error().context == "start tls: connection closed");
		CHECK(m.conn.outstanding() == 0);
	}
	SECTION("unbind while it waits: StartTLS is not sent after the UnbindRequest")
	{
		tcp_mock_ldap m;
		m.serve({ answer({ entry_msg(1, "uid=a,ou=people,dc=example,dc=org", "A"), paged_done(1, "page2") }),
		  step{},// reads the release, never answers
		  step{} });// reads the UnbindRequest
		release_after_one_page(m);
		outcome<ldap::result<void>> tls;
		spawn(m.ioc, m.conn.start_tls(), tls);
		settle(m);
		CHECK_FALSE(tls.done());
		CHECK(m.run(m.conn.unbind()).has_value());
		drive_until(m.ioc, [&tls] { return tls.done(); });
		REQUIRE_FALSE(tls.get().has_value());
		CHECK(tls.get().error().code == client_errc::not_sent);
		m.check_server();
		REQUIRE(m.log.received.size() == 3);
		CHECK(std::holds_alternative<ldap::unbind_request>(m.log.received[2].op));
	}
	SECTION("unbind while it waits, and its timeout passes meanwhile: StartTLS is not sent after the UnbindRequest")
	{
		tcp_mock_ldap m({}, socket_buffers::small);
		REQUIRE(m.buffered_at_most() < oversized_add_value);
		m.serve({ answer({ entry_msg(1, "uid=a,ou=people,dc=example,dc=org", "A"), paged_done(1, "page2") }),
		  step{} });// reads the release, never answers; nothing reads after it
		release_after_one_page(m);
		m.check_server();
		outcome<ldap::result<void>> tls;
		spawn(m.ioc, m.conn.start_tls({}, std::chrono::milliseconds(100)), tls);
		settle(m);
		CHECK_FALSE(tls.done());
		// The writer stays busy with the AddRequest (larger than the socket
		// buffers), so unbind() waits for it (the answers due no longer
		// counted) past StartTLS's timeout.
		outcome<ldap::result<ldap::response>> add;
		spawn(m.ioc, m.conn.add(oversized_add()), add);
		outcome<ldap::result<void>> unbind;
		spawn(m.ioc, m.conn.unbind(), unbind);
		drive_until(m.ioc, [&tls] { return tls.done(); });
		REQUIRE_FALSE(tls.get().has_value());
		CHECK(tls.get().error().code == client_errc::not_sent);
		CHECK(tls.get().error().context == "start tls: connection closing (unbind)");
		CHECK_FALSE(unbind.done());

		// The server reads again: the AddRequest, the UnbindRequest, the close.
		server_log drained;
		outcome<void> server;
		spawn(m.ioc, serve_script(m.server_end(), { step{}, step{}, client_hangs_up() }, drained), server);
		drive_until(m.ioc, [&] { return unbind.done() && server.done(); });
		CHECK(unbind.get().has_value());
		CHECK(add.done());
		server.get();
		CHECK_THAT(drained.error, IsEmpty());
		REQUIRE(drained.received.size() == 2);
		CHECK(std::holds_alternative<ldap::add_request>(drained.received[0].op));
		CHECK(std::holds_alternative<ldap::unbind_request>(drained.received[1].op));
	}
	SECTION("the answer is read with no other operation running")
	{
		tcp_mock_ldap m;
		m.serve({ answer({ entry_msg(1, "uid=a,ou=people,dc=example,dc=org", "A"), paged_done(1, "page2") }),
		  answer({ paged_done(2, "") }),// the release's answer: read and dropped
		  answer({ start_tls_refused(3) }) });
		{
			auto s = m.run(m.conn.search_paged(people_search(), 1));
			REQUIRE(s.has_value());
			auto e = m.run(s->next());
			REQUIRE(e.has_value());
			REQUIRE(e->has_value());
			drive_until(m.ioc, [&m] { return m.conn.outstanding() == 0; });
		}
		CHECK(m.conn.outstanding() == 1);
		drive_until(m.ioc, [&m] { return m.conn.outstanding() == 0; });
		CHECK(m.conn.outstanding() == 0);
		CHECK(m.conn.is_open());
		auto r = m.run(m.conn.start_tls());
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == errc::unavailable);// sent, and refused
		m.check_server();
		REQUIRE(m.log.received.size() == 3);
		check_release(m.log.received[1], m.log.received[0], "page2");
		CHECK(is_start_tls(m.log.received[2]));
	}
	SECTION("an abandoned search is not waited for: it may never be answered")
	{
		tcp_mock_ldap m;
		m.serve({ answer({ entry_msg(1, "uid=a,ou=people,dc=example,dc=org", "A") }),
		  step{},// reads the AbandonRequest, answers nothing
		  answer({ start_tls_refused(3) }) });
		{
			auto s = m.run(m.conn.search_stream(people_search()));
			REQUIRE(s.has_value());
			auto e = m.run(s->next());
			REQUIRE(e.has_value());
			REQUIRE(e->has_value());
		}
		CHECK(m.conn.outstanding() == 0);
		drive_until(m.ioc, [&m] { return m.log.received.size() == 2; });
		auto r = m.run(m.conn.start_tls());
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == errc::unavailable);// sent, and refused
		m.check_server();
		CHECK(m.log.received[1] == ldap::message{ 2, ldap::abandon_request{ 1 } });
		CHECK(is_start_tls(m.log.received[2]));
	}
	SECTION("unbind does not wait for the release's answer")
	{
		mock_ldap m;
		m.serve({ answer({ entry_msg(1, "uid=a,ou=people,dc=example,dc=org", "A"), paged_done(1, "page2") }),
		  step{},// reads the release, never answers
		  step{} });// reads the UnbindRequest
		{
			auto s = m.run(m.conn.search_paged(people_search(), 1));
			REQUIRE(s.has_value());
			auto e = m.run(s->next());
			REQUIRE(e.has_value());
			REQUIRE(e->has_value());
			drive_until(m.ioc, [&m] { return m.conn.outstanding() == 0; });
		}
		CHECK(m.conn.outstanding() == 1);
		CHECK(m.run(m.conn.unbind()).has_value());
		CHECK(m.conn.outstanding() == 0);
		CHECK_FALSE(m.conn.is_open());
		m.check_server();
		REQUIRE(m.log.received.size() == 3);
		CHECK(std::holds_alternative<ldap::unbind_request>(m.log.received[2].op));
	}
}

// The release's deadline and StartTLS's timeout are about the same here
// (both connection_options::operation_timeout), so the wait ends with
// little of StartTLS's timeout left: the ExtendedResponse gets a timeout of
// its own, since giving up on StartTLS closes the connection (RFC 4511
// section 4.11).
TEST_CASE("operations: StartTLS after waiting for a release's answer has its whole timeout",
  "[net][operations][paged][starttls][timeout]")
{
	tcp_mock_ldap m({ .operation_timeout = std::chrono::milliseconds(1000) });
	m.serve({ answer({ entry_msg(1, "uid=a,ou=people,dc=example,dc=org", "A"), paged_done(1, "page2") }),
	  step{},// reads the release, never answers
	  step{} });// reads StartTLS, answered late below
	release_after_one_page(m);
	outcome<ldap::result<void>> tls;
	spawn(m.ioc, m.conn.start_tls(), tls);
	drive_until(m.ioc, [&m] { return m.log.received.size() == 3; });// once the release's deadline passed
	REQUIRE(m.log.received.size() == 3);
	CHECK(is_start_tls(m.log.received[2]));
	// Much longer than what was left of StartTLS's timeout after the wait,
	// well within a whole one.
	m.ioc.run_for(std::chrono::milliseconds(300));
	m.ioc.restart();
	CHECK_FALSE(tls.done());
	server_sends(m, start_tls_refused(3));
	drive_until(m.ioc, [&tls] { return tls.done(); });
	REQUIRE_FALSE(tls.get().has_value());
	CHECK(tls.get().error().code == errc::unavailable);// answered in time, and refused
	CHECK(m.conn.is_open());
	CHECK(m.conn.outstanding() == 0);
	m.check_server();
	server_sends(m, bind_resp(4));// answers the bind below before it is read
	CHECK(m.run(bind_admin(m.conn)).has_value());
}

// The release's deadline and StartTLS's wait deadline (later by a little)
// have both passed when the io_context next runs: StartTLS's wait may time
// out before the due watcher expires the release's answer. It is expired
// then, and StartTLS proceeds.
TEST_CASE("operations: StartTLS whose wait times out with a release's deadline passed proceeds",
  "[net][operations][paged][starttls][timeout]")
{
	tcp_mock_ldap m({ .operation_timeout = std::chrono::milliseconds(300) });
	m.serve({ answer({ entry_msg(1, "uid=a,ou=people,dc=example,dc=org", "A"), paged_done(1, "page2") }),
	  step{},// reads the release, never answers
	  answer({ start_tls_refused(3) }) });
	const auto start = std::chrono::steady_clock::now();
	release_after_one_page(m);
	outcome<ldap::result<void>> tls;
	spawn(m.ioc, m.conn.start_tls(), tls);
	settle(m);// StartTLS waits for the release's answer
	// Only while the release's deadline is surely ahead: under load, the
	// setup may take longer than it.
	if (std::chrono::steady_clock::now() - start < std::chrono::milliseconds(200)) {
		CHECK_FALSE(tls.done());
		CHECK(m.log.received.size() == 2);
	}
	std::this_thread::sleep_for(std::chrono::milliseconds(400));// past both deadlines, the io_context idle
	drive_until(m.ioc, [&tls] { return tls.done(); });
	REQUIRE(tls.done());
	REQUIRE_FALSE(tls.get().has_value());
	CHECK(tls.get().error().code == errc::unavailable);// sent, and refused
	CHECK(m.conn.is_open());
	CHECK(m.conn.outstanding() == 0);
	m.check_server();
	REQUIRE(m.log.received.size() == 3);
	CHECK(is_start_tls(m.log.received[2]));
}

// StartTLS: nothing but the ExtendedRequest may be sent until it is
// answered (RFC 4511 section 4.14.1), so no release either.
TEST_CASE("operations: a paged search destroyed during StartTLS sends no release", "[net][operations][paged][starttls]")
{
	tcp_mock_ldap m;
	m.serve({ answer({ entry_msg(1, "uid=a,ou=people,dc=example,dc=org", "A"), paged_done(1, "page2") }),
	  step{},// reads StartTLS, answered below
	  answer({ bind_resp(3) }) });
	outcome<ldap::result<void>> tls;
	{
		auto s = m.run(m.conn.search_paged(people_search(), 1));
		REQUIRE(s.has_value());
		auto e = m.run(s->next());
		REQUIRE(e.has_value());
		REQUIRE(e->has_value());
		drive_until(m.ioc, [&m] { return m.conn.outstanding() == 0; });
		spawn(m.ioc, m.conn.start_tls(), tls);
		drive_until(m.ioc, [&m] { return m.log.received.size() == 2; });
		REQUIRE(m.log.received.size() == 2);
		CHECK(is_start_tls(m.log.received[1]));
	}// page 1 ended with a cookie: a release, if not for StartTLS
	CHECK(m.conn.outstanding() == 1);// StartTLS only
	server_sends(m, start_tls_refused(2));
	drive_until(m.ioc, [&tls] { return tls.done(); });
	REQUIRE_FALSE(tls.get().has_value());
	CHECK(tls.get().error().code == errc::unavailable);
	auto b = m.run(bind_admin(m.conn));
	CHECK(b.has_value());
	m.check_server();
	REQUIRE(m.log.received.size() == 3);
	CHECK(m.log.received[2] == bind_request_msg(3));// not a release
}

// The next page's request could not be sent (here: during StartTLS), so the
// server still holds the paging state of the page before: released.
TEST_CASE("operations: a paged search whose next page could not be sent releases the last cookie",
  "[net][operations][paged][starttls]")
{
	tcp_mock_ldap m;
	m.serve({ answer({ entry_msg(1, "uid=a,ou=people,dc=example,dc=org", "A"), paged_done(1, "page2") }),
	  step{},// reads StartTLS, answered below
	  answer({ paged_done(3, "") }),// the release's answer: dropped
	  answer({ bind_resp(4) }) });
	{
		auto s = m.run(m.conn.search_paged(people_search(), 1));
		REQUIRE(s.has_value());
		auto e = m.run(s->next());
		REQUIRE(e.has_value());
		REQUIRE(e->has_value());
		drive_until(m.ioc, [&m] { return m.conn.outstanding() == 0; });
		outcome<ldap::result<void>> tls;
		spawn(m.ioc, m.conn.start_tls(), tls);
		drive_until(m.ioc, [&m] { return m.log.received.size() == 2; });
		auto next = m.run(s->next());// page 1 ended: page 2 is refused
		REQUIRE_FALSE(next.has_value());
		CHECK(next.error().code == client_errc::operation_in_progress);
		CHECK(s->done());
		CHECK(s->pages() == 1);
		server_sends(m, start_tls_refused(2));
		drive_until(m.ioc, [&tls] { return tls.done(); });
		REQUIRE_FALSE(tls.get().has_value());
		CHECK(tls.get().error().code == errc::unavailable);// the connection stays usable, in clear
	}
	auto b = m.run(bind_admin(m.conn));
	CHECK(b.has_value());
	m.check_server();
	REQUIRE(m.log.received.size() == 4);
	CHECK(is_start_tls(m.log.received[1]));
	CHECK(m.log.received[2].id == 3);
	check_release(m.log.received[2], m.log.received[0], "page2");
	CHECK(m.log.received[3] == bind_request_msg(4));
}

// The current page's SearchResultDone was received but not read by next():
// if it failed or its paged control is malformed, the search ended on the
// server, and nothing is released.
TEST_CASE("operations: a paged search whose unread page failed sends no release", "[net][operations][paged]")
{
	const bool error_result = GENERATE(true, false);
	INFO((error_result ? "an error result" : "a malformed paged control"));
	ldap::message page2_done = error_result ? done_msg(2, 51, "", "busy") : done_msg(2);
	if (error_result) {
		page2_done.controls = paged_done(2, "page3").controls;// a cookie all the same
	} else {
		page2_done.controls.emplace_back(ldap::paged_results_oid, false, "garbage");
	}

	mock_ldap m;
	m.serve({ answer({ entry_msg(1, "uid=a,ou=people,dc=example,dc=org", "A"), paged_done(1, "page2") }),
	  answer({ entry_msg(2, "uid=b,ou=people,dc=example,dc=org", "B"), page2_done }),
	  answer({ bind_resp(3) }) });
	{
		auto s = m.run(m.conn.search_paged(people_search(), 1));
		REQUIRE(s.has_value());
		for (int i = 0; i < 2; ++i) {
			auto e = m.run(s->next());
			REQUIRE(e.has_value());
			REQUIRE(e->has_value());
		}
		drive_until(m.ioc, [&m] { return m.conn.outstanding() == 0; });// page 2's done queued, unread
		CHECK(s->pages() == 2);
	}
	CHECK(m.conn.outstanding() == 0);// nothing due
	auto b = m.run(bind_admin(m.conn));
	CHECK(b.has_value());
	m.check_server();
	REQUIRE(m.log.received.size() == 3);
	CHECK(m.log.received[2] == bind_request_msg(3));// not a release
}

// The due watcher ends when no due answer has a deadline, and starts again
// for a later one.
TEST_CASE("operations: release answers' deadlines", "[net][operations][paged][timeout]")
{
	SECTION("a release after the first one's answer arrived: its deadline is kept too")
	{
		mock_ldap m;
		m.serve({ answer({ entry_msg(1, "uid=a,ou=people,dc=example,dc=org", "A"), paged_done(1, "page2") }),
		  answer({ paged_done(2, "") }),// the first release's answer
		  answer({ paged_done(3, "page2") }),
		  step{} });// reads the second release, never answers
		auto p = people_search();
		p.timeout = std::chrono::milliseconds(50);// the pages' limit, and the releases'
		release_after_one_page(m, p);
		drive_until(m.ioc, [&m] { return m.conn.outstanding() == 0; });
		CHECK(m.conn.outstanding() == 0);
		while (m.ioc.poll() != 0) {}// the due watcher sees no deadline left, and ends
		m.ioc.restart();
		{
			auto s = m.run(m.conn.search_paged(p, 1));
			REQUIRE(s.has_value());
			drive_until(m.ioc, [&m] { return m.conn.outstanding() == 0; });
		}
		CHECK(m.conn.outstanding() == 1);
		drive_until(m.ioc, [&m] { return m.conn.outstanding() == 0; });// its deadline passes
		CHECK(m.conn.outstanding() == 0);
		CHECK(m.conn.is_open());
		m.check_server();
		REQUIRE(m.log.received.size() == 4);
		check_release(m.log.received[3], m.log.received[0], "page2");
	}
	SECTION("one with a deadline, one without: only the one with a deadline expires")
	{
		mock_ldap m;// no operation_timeout
		m.serve({ answer({ entry_msg(1, "uid=a,ou=people,dc=example,dc=org", "A"), paged_done(1, "page2") }),
		  step{},// reads the first release (no deadline), answered below
		  answer({ paged_done(3, "page2") }),
		  step{} });// reads the second release, answered late below
		release_after_one_page(m);
		{
			auto p = people_search();
			p.timeout = std::chrono::milliseconds(50);
			auto s = m.run(m.conn.search_paged(std::move(p), 1));
			REQUIRE(s.has_value());
			drive_until(m.ioc, [&m] { return m.conn.outstanding() == 1; });// page 3 ended
		}
		CHECK(m.conn.outstanding() == 2);
		drive_until(m.ioc, [&m] { return m.conn.outstanding() < 2; });// the second's deadline passes
		CHECK(m.conn.outstanding() == 1);
		m.check_server();
		server_sends(m, paged_done(2, ""));
		drive_until(m.ioc, [&m] { return m.conn.outstanding() == 0; });
		CHECK(m.conn.outstanding() == 0);
		// The second release's id is still known: its late answer is dropped.
		server_sends(m, paged_done(4, ""));
		server_sends(m, bind_resp(5));// answers the bind below before it is read
		CHECK(m.run(bind_admin(m.conn)).has_value());
		CHECK(m.conn.is_open());
		REQUIRE(m.log.received.size() == 4);
		check_release(m.log.received[1], m.log.received[0], "page2");
		check_release(m.log.received[3], m.log.received[2], "page2");
	}
}

namespace {

// Reads the first page of a paged search (page size 1, cookie "page2", the
// release's deadline `timeout`), waits until the reader and the writer are
// idle (every frame allocated since `frames` was set has been freed), then
// destroys it with the `failing`-th frame allocation failing. Returns the
// allocations tried. `M` is mock_ldap or tcp_mock_ldap.
template<class M>
auto release_failing(M &m,
  failing_frames &frames,
  std::size_t failing,
  std::optional<std::chrono::milliseconds> timeout) -> std::size_t
{
	auto p = people_search();
	p.timeout = timeout;
	auto s = m.run(m.conn.search_paged(std::move(p), 1));
	REQUIRE(s.has_value());
	auto e = m.run(s->next());
	REQUIRE(e.has_value());
	REQUIRE(e->has_value());
	drive_until(m.ioc, [&] { return frames.live() == 0; });
	REQUIRE(frames.live() == 0);
	frames.fail_at(failing);
	*s = ldap::paged_search{};
	const std::size_t attempted = frames.count();
	frames.fail_at(0);
	return attempted;
}

}// namespace

// A paged search's release starts the writer, the reader and the due
// watcher from a destructor (no operation running), in that order: each
// allocates its task's frame, then run_async's. Failing one of the task
// frames throws bad_alloc there (the release is best effort: swallowed);
// the flag that says the task runs must not be left set without it, or
// that task is never started again.
TEST_CASE("operations: a failed allocation for the writer, reader or due watcher wedges nothing",
  "[net][operations][paged][oom]")
{
	failing_frames frames;// outlives the io_context's coroutines
	const clear_frame_allocator clear;
	mock_ldap m;
	// The release's deadline: the due watcher runs.
	auto release_failing = [&](std::size_t failing) {
		return ::release_failing(m, frames, failing, std::chrono::milliseconds(100));
	};
	auto page = [](std::int32_t id) {
		return answer({ entry_msg(id, "uid=a,ou=people,dc=example,dc=org", "A"), paged_done(id, "page2") });
	};

	SECTION("nothing fails: the writer's frame, then the reader's, then the due watcher's, each with run_async's")
	{
		m.serve({ page(1), step{} });// reads the release
		m.ioc.set_frame_allocator(&frames);
		CHECK(release_failing(0) == 6);
		CHECK(m.conn.outstanding() == 1);
		m.check_server();
		check_release(m.log.received[1], m.log.received[0], "page2");
	}
	SECTION("the writer's: the release is not sent, later requests are")
	{
		m.serve({ page(1), answer({ bind_resp(3) }) });
		m.ioc.set_frame_allocator(&frames);
		CHECK(release_failing(1) == 1);
		CHECK(m.conn.outstanding() == 0);// nothing is due
		CHECK(m.run(bind_admin(m.conn)).has_value());
		m.check_server();
		REQUIRE(m.log.received.size() == 2);
		CHECK(m.log.received[1] == bind_request_msg(3));// the release's id is used up
	}
	SECTION("the reader's: the release is sent, the next operation's reader reads its answer")
	{
		m.serve({ page(1), answer({ paged_done(2, "") }), answer({ bind_resp(3) }) });
		m.ioc.set_frame_allocator(&frames);
		CHECK(release_failing(3) == 3);
		CHECK(m.conn.outstanding() == 1);// due, not read yet
		CHECK(m.run(bind_admin(m.conn)).has_value());
		CHECK(m.conn.outstanding() == 0);
		CHECK(m.conn.is_open());
		m.check_server();
		REQUIRE(m.log.received.size() == 3);
		check_release(m.log.received[1], m.log.received[0], "page2");
	}
	SECTION("the due watcher's: the next release starts one, which expires both answers")
	{
		m.serve({ page(1), step{}, page(3), step{} });// reads each release, never answers
		m.ioc.set_frame_allocator(&frames);
		CHECK(release_failing(5) == 5);
		CHECK(m.conn.outstanding() == 1);
		{
			auto p = people_search();
			p.timeout = std::chrono::milliseconds(100);
			auto s = m.run(m.conn.search_paged(std::move(p), 1));
			REQUIRE(s.has_value());
			drive_until(m.ioc, [&m] { return m.conn.outstanding() == 1; });// page 3 ended
		}
		CHECK(m.conn.outstanding() == 2);
		drive_until(m.ioc, [&m] { return m.conn.outstanding() == 0; });// both deadlines pass
		CHECK(m.conn.outstanding() == 0);
		CHECK(m.conn.is_open());
		m.check_server();
		REQUIRE(m.log.received.size() == 4);
		check_release(m.log.received[1], m.log.received[0], "page2");
		check_release(m.log.received[3], m.log.received[2], "page2");
	}
}

// send_unanswered() could not start the reader (the release's task frame
// failing, the due watcher's is then not tried): the release is sent, its
// answer due, and nothing reads it or applies its deadline. StartTLS, with
// no timeout of its own, waits for that answer: its wait starts them.
TEST_CASE("operations: StartTLS waits for a release's answer whose reader could not start",
  "[net][operations][paged][starttls][oom]")
{
	failing_frames frames;// outlives the io_context's coroutines
	const clear_frame_allocator clear;
	outcome<ldap::result<void>> tls;// outlives `m`: a StartTLS still waiting ends with it
	tcp_mock_ldap m;
	auto start_tls = [&m, &tls] {
		spawn(m.ioc, m.conn.start_tls(), tls);
		drive_until(m.ioc, [&tls] { return tls.done(); });
		REQUIRE(tls.done());
		return tls.get();
	};
	auto page = answer({ entry_msg(1, "uid=a,ou=people,dc=example,dc=org", "A"), paged_done(1, "page2") });

	SECTION("the answer comes: a reader reads it, then StartTLS is sent")
	{
		m.serve({ page, step{}, answer({ start_tls_refused(3) }) });// reads the release, answered below
		m.ioc.set_frame_allocator(&frames);
		CHECK(release_failing(m, frames, 3, std::nullopt) == 3);// the writer's, run_async's, the reader's
		drive_until(m.ioc, [&m] { return m.log.received.size() == 2; });
		CHECK(m.conn.outstanding() == 1);
		server_sends(m, paged_done(2, ""));
		auto r = start_tls();
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == errc::unavailable);// sent, and refused
		CHECK(m.conn.outstanding() == 0);
		CHECK(m.conn.is_open());
		m.check_server();
		REQUIRE(m.log.received.size() == 3);
		check_release(m.log.received[1], m.log.received[0], "page2");
		CHECK(is_start_tls(m.log.received[2]));
	}
	SECTION("the answer never comes: a due watcher expires it at its deadline, then StartTLS is sent")
	{
		m.serve({ page, step{}, answer({ start_tls_refused(3) }) });// reads the release, never answers
		m.ioc.set_frame_allocator(&frames);
		CHECK(release_failing(m, frames, 3, std::chrono::milliseconds(100)) == 3);
		drive_until(m.ioc, [&m] { return m.log.received.size() == 2; });
		CHECK(m.conn.outstanding() == 1);
		auto r = start_tls();
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == errc::unavailable);// sent, and refused
		CHECK(m.conn.outstanding() == 0);
		CHECK(m.conn.is_open());
		m.check_server();
		REQUIRE(m.log.received.size() == 3);
		CHECK(is_start_tls(m.log.received[2]));
	}
}

namespace {

// Writes `msgs` to the server's end at once, without the io_context: no
// coroutine frame is allocated (failing_frames may be set to fail one).
void server_writes_now(mock_ldap &m, std::initializer_list<ldap::message> msgs)
{
	for (const auto &msg : msgs) {
		const std::string bytes = bytes_of(msg);
		REQUIRE(raw_send(m.sockets.server.native_handle(), bytes));
	}
}

}// namespace

// Where no exception may go (a destructor, a detached task), a failed frame
// allocation closes the connection: what was to be sent or read is lost,
// and the operations fail with not_enough_memory instead of waiting for it
// (or the program ending). Nothing is spawned while an allocation is set to
// fail: run_async's own frame failing ends the program (made in a noexcept
// constructor, outside this library).
TEST_CASE("operations: a failed allocation where nothing may throw closes the connection", "[net][operations][oom]")
{
	failing_frames frames;// outlives the io_context's coroutines
	const clear_frame_allocator clear;
	mock_ldap m;
	m.ioc.set_frame_allocator(&frames);
	// Runs what is ready: requests are written, the reader parks.
	auto settle_now = [&m] {
		while (m.ioc.poll() != 0) {}
		m.ioc.restart();
	};
	const std::string_view base = "search ou=people,dc=example,dc=org";

	SECTION("the reader's next read: the operations fail")
	{
		auto s = m.run(m.conn.search_stream(people_search()));
		REQUIRE(s.has_value());
		settle_now();
		server_writes_now(m, { entry_msg(1, "uid=a,ou=people,dc=example,dc=org", "A"), done_msg(1) });
		frames.fail_at(1);// the reader routes the entry, then reads again
		drive_until(m.ioc, [&frames] { return frames.count() == 1; });
		frames.fail_at(0);
		CHECK_FALSE(m.conn.is_open());
		CHECK(m.conn.outstanding() == 0);
		auto e = m.run(s->next());
		REQUIRE(e.has_value());
		CHECK(e->has_value());// received before
		auto end = m.run(s->next());
		REQUIRE_FALSE(end.has_value());
		CHECK(end.error().code == std::errc::not_enough_memory);
		CHECK(end.error().context == base);
		auto later = m.run(m.conn.search(people_search()));
		REQUIRE_FALSE(later.has_value());
		CHECK(later.error().code == client_errc::not_sent);
		CHECK_THAT(std::string(later.error().context),
		  StartsWith(std::string(base) + ": connection closed by an earlier error: "));
	}
	SECTION("the reader restarted for a request registered as it stopped: the request fails")
	{
		// The writer stays busy with the SearchRequest (larger than the
		// socket buffers, and the server's end does not read): it cannot
		// resume, so the frame that fails is the reader's, not the writer's
		// next write.
		tcp_mock_ldap t({}, socket_buffers::small);
		REQUIRE(t.buffered_at_most() < oversized_add_value);
		t.ioc.set_frame_allocator(&frames);
		auto big = people_search();
		big.filter = ldap::filters::attr("description") == std::string(oversized_add_value, 'x');
		auto s = t.run(t.conn.search_stream(std::move(big)));
		REQUIRE(s.has_value());
		while (t.ioc.poll() != 0) {}// the reader parks on its read, the writer on its write
		t.ioc.restart();
		// In one go, so the reader cannot run in between: the stream is
		// abandoned (nothing is outstanding, the reader is told to stop),
		// then an AddRequest is registered while the reader still runs. The
		// reader then ends on its cancelled read and starts afresh for it.
		// body outlives its task: drive_until below runs the task to completion.
		// NOLINTNEXTLINE(cppcoreguidelines-avoid-capturing-lambda-coroutines): see above
		auto body = [&] -> capy::task<ldap::result<ldap::response>> {
			*s = ldap::search_stream{};
			auto add = t.conn.add({ .entry = jdoe });
			frames.fail_at(3);// the add's request_response and next_response, then the new reader's frame
			co_return co_await std::move(add);
		};
		outcome<ldap::result<ldap::response>> add;
		spawn(t.ioc, body(), add);
		drive_until(t.ioc, [&add] { return add.done(); });
		CHECK(frames.count() == 3);
		frames.fail_at(0);
		CHECK_FALSE(t.conn.is_open());
		CHECK(t.conn.outstanding() == 0);
		REQUIRE_FALSE(add.get().has_value());
		CHECK(add.get().error().code == std::errc::not_enough_memory);
		CHECK(add.get().error().context == "add uid=jdoe,ou=people,dc=example,dc=org");
	}
	SECTION("an AbandonRequest from a stream's destructor: the other operations fail")
	{
		auto first = m.run(m.conn.search_stream(people_search()));
		auto second = m.run(m.conn.search_stream(people_search()));
		REQUIRE(first.has_value());
		REQUIRE(second.has_value());
		settle_now();
		frames.fail_at(1);
		*first = ldap::search_stream{};// abandoned: the writer's frame fails
		CHECK(frames.count() == 1);
		frames.fail_at(0);
		CHECK_FALSE(m.conn.is_open());
		auto e = m.run(second->next());
		REQUIRE_FALSE(e.has_value());
		CHECK(e.error().code == std::errc::not_enough_memory);
	}
	SECTION("the writer's write of an AbandonRequest: the other operations fail")
	{
		auto first = m.run(m.conn.search_stream(people_search()));
		auto second = m.run(m.conn.search_stream(people_search()));
		REQUIRE(first.has_value());
		REQUIRE(second.has_value());
		settle_now();
		frames.fail_at(3);// the writer's frame, run_async's, then the writer's write
		*first = ldap::search_stream{};
		drive_until(m.ioc, [&frames] { return frames.count() == 3; });
		frames.fail_at(0);
		CHECK_FALSE(m.conn.is_open());
		auto e = m.run(second->next());
		REQUIRE_FALSE(e.has_value());
		CHECK(e.error().code == std::errc::not_enough_memory);
	}
	SECTION("the requests a bind held, sent as it ends: they fail")
	{
		outcome<ldap::result<void>> bind;
		spawn(m.ioc, bind_admin(m.conn), bind);
		settle_now();// the BindRequest is written
		outcome<ldap::result<ldap::response>> add;
		spawn(m.ioc, m.conn.add({ .entry = jdoe }), add);// held
		settle_now();
		server_writes_now(m, { bind_resp(1) });
		frames.fail_at(2);// the reader's next read, then the writer's frame for the held AddRequest
		drive_until(m.ioc, [&] { return bind.done() && add.done(); });
		CHECK(frames.count() == 2);
		frames.fail_at(0);
		CHECK(bind.get().has_value());
		REQUIRE_FALSE(add.get().has_value());
		CHECK(add.get().error().code == std::errc::not_enough_memory);
		CHECK(add.get().error().context == "add uid=jdoe,ou=people,dc=example,dc=org");
		CHECK_FALSE(m.conn.is_open());
	}
}

// Late responses are dropped for the last 1024 abandoned requests; when
// there are more, a due release answer is kept over older abandoned
// requests (which may never be answered).
TEST_CASE("operations: a due release answer outlives older abandoned requests", "[net][operations][paged]")
{
	constexpr int abandoned_searches = 1024;// with the release: one more than are kept
	mock_ldap m;
	std::vector<step> script{
		answer({ entry_msg(1, "uid=a,ou=people,dc=example,dc=org", "A"), paged_done(1, "page2") }), step{}
	};// reads the release, does not answer yet
	script.resize(script.size() + (2uz * abandoned_searches));// each search and its AbandonRequest
	m.serve(std::move(script));
	release_after_one_page(m);
	for (int i = 0; i < abandoned_searches; ++i) {
		auto s = m.run(m.conn.search_stream(people_search()));
		REQUIRE(s.has_value());
	}// each one abandoned
	drive_until(m.ioc, [&m] { return m.server.done(); });
	REQUIRE(m.log.received.size() == 2 + (2 * abandoned_searches));
	CHECK(m.conn.outstanding() == 1);

	server_sends(m, paged_done(2, ""));// still known: dropped
	drive_until(m.ioc, [&m] { return m.conn.outstanding() == 0; });
	CHECK(m.conn.outstanding() == 0);
	CHECK(m.conn.is_open());
	m.check_server();
}

// When every abandoned request kept is a due release answer, the oldest is
// forgotten for a new one: its answer is no longer counted.
TEST_CASE("operations: a due release answer forgotten past the limit is no longer counted", "[net][operations][paged]")
{
	constexpr int releases = 1024;// as many as are kept
	mock_ldap m;
	std::vector<step> script;
	for (int i = 0; i < releases; ++i) {
		script.push_back(answer({ paged_done((2 * i) + 1, "page2") }));
		script.push_back(step{});// reads the release, does not answer yet
	}
	script.resize(script.size() + 2);// a search and its AbandonRequest
	m.serve(std::move(script));
	for (int i = 0; i < releases; ++i) {
		auto s = m.run(m.conn.search_paged(people_search(), 1));
		REQUIRE(s.has_value());
		drive_until(m.ioc, [&m, i] { return m.conn.outstanding() == static_cast<std::size_t>(i); });// page ended
	}// each released
	CHECK(m.conn.outstanding() == releases);
	{
		auto s = m.run(m.conn.search_stream(people_search()));
		REQUIRE(s.has_value());
	}// abandoned: the first release (id 2) is forgotten
	CHECK(m.conn.outstanding() == releases - 1);
	drive_until(m.ioc, [&m] { return m.server.done(); });
	REQUIRE(m.log.received.size() == (2 * releases) + 2);

	std::string answers;// the other releases' answers, in one write
	for (int i = 1; i < releases; ++i) {
		answers += bytes_of(paged_done((2 * i) + 2, ""));
	}
	auto t = m.server_end();
	REQUIRE(m.run(net::write_bytes(t, std::as_bytes(std::span(answers)))).has_value());
	drive_until(m.ioc, [&m] { return m.conn.outstanding() == 0; });
	CHECK(m.conn.outstanding() == 0);
	CHECK(m.conn.is_open());
	m.check_server();
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
	auto set = m.run(ldap::password_modify(
	  m.conn, { .user = "uid=jdoe,ou=people,dc=example,dc=org", .old_password = "old", .new_password = "new" }));
	REQUIRE(set.has_value());
	CHECK_FALSE(set->has_value());
	// No new password: the server generates one.
	auto generated = m.run(ldap::password_modify(m.conn, {}));
	REQUIRE(generated.has_value());
	CHECK(*generated == "s3cr3");
	auto empty = m.run(ldap::password_modify(m.conn, { .new_password = "x" }));
	REQUIRE(empty.has_value());
	CHECK_FALSE(empty->has_value());
	// Server errors name the operation and the user, never a password.
	auto refused =
	  m.run(ldap::password_modify(m.conn, { .user = "uid=jdoe", .old_password = "bad", .new_password = "new" }));
	REQUIRE_FALSE(refused.has_value());
	CHECK(refused.error().code == errc::invalid_credentials);
	CHECK(refused.error().context == "password modify uid=jdoe");
	CHECK(refused.error().diagnostic == "old password wrong");
	// A malformed response value.
	auto bad = m.run(ldap::password_modify(m.conn, {}));
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
