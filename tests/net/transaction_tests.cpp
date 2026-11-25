// RFC 5805 transactions against the scripted mock server.
#include "jhetz/ldap/cancel.hpp"
#include "jhetz/ldap/connection.hpp"
#include "jhetz/ldap/controls.hpp"
#include "jhetz/ldap/extended_operations.hpp"
#include "jhetz/ldap/testing/server_codec.hpp"
#include "jhetz/ldap/transaction.hpp"
#include "mock_ldap.hpp"
#include "net_test_support.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <chrono>
#include <coroutine>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <stdexcept>
#include <stop_token>
#include <string>
#include <string_view>
#include <system_error>
#include <variant>

namespace ldap = jhetz::ldap;
namespace net = jhetz::ldap::net;
namespace capy = boost::capy;
namespace corosio = boost::corosio;
using namespace jhetz::ldap::test;
using ldap::client_errc;
using ldap::errc;

namespace {

const ldap::dn jdoe{ "uid=jdoe,ou=people,dc=example,dc=org" };
const ldap::dn group{ "cn=staff,ou=groups,dc=example,dc=org" };
constexpr std::string_view txn_id = "txn-1";

auto ext_resp(std::int32_t id,
  std::int32_t code = 0,
  std::optional<std::string_view> name = std::nullopt,
  std::optional<std::string_view> value = std::nullopt) -> ldap::message
{
	return ldap::message{ id, ldap::extended_response{ ldap::ldap_result{ code }, name, value } };
}

auto started(std::int32_t id) -> ldap::message { return ext_resp(id, 0, std::nullopt, txn_id); }

// An End Transaction response carrying `value` as its txnEndRes.
auto ended(std::int32_t id, std::int32_t code, const ldap::end_transaction_response &value) -> ldap::message
{
	const auto v = ldap::testing::encode_end_transaction_response(value);
	REQUIRE(v.has_value());
	if (!v->has_value()) {
		return ext_resp(id, code);
	}
	return ext_resp(id, code, std::nullopt, std::string_view(**v));
}

template<class Response> auto result_msg(std::int32_t id, std::int32_t code = 0) -> ldap::message
{
	return ldap::message{ id, Response{ ldap::ldap_result{ code } } };
}

auto spec_control() -> ldap::control { return ldap::control{ ldap::transaction_specification_oid, true, txn_id }; }

// The End Transaction request the server received.
auto end_request_of(const ldap::message &m) -> ldap::end_transaction_request
{
	const auto *x = std::get_if<ldap::extended_request>(&m.op);
	REQUIRE(x != nullptr);
	CHECK(x->request_name == ldap::end_transaction_oid);
	REQUIRE(x->request_value.has_value());
	CHECK(m.controls.empty());// RFC 5805 section 4: no control on End Transaction
	auto r = ldap::testing::decode_end_transaction_request(*x->request_value);
	REQUIRE(r.has_value());
	return *r;
}

auto post_read_entry() -> ldap::control
{
	return ldap::testing::encode_read_entry(ldap::post_read_oid,
	  ldap::search_result_entry{ jdoe.to_string(), { ldap::partial_attribute{ "uid", { "jdoe" } } } })
	  .value();
}

// A socket's write_some, or, once *broken, a broken_pipe completing at once
// (with no suspension, so a writer started inline fails inline).
template<class Inner> struct breakable_write
{
	std::optional<Inner> inner;

	[[nodiscard]] auto await_ready() -> bool { return !inner || inner->await_ready(); }
	auto await_suspend(std::coroutine_handle<> h, const capy::await_context *env) -> decltype(auto)
	{
		return inner->await_suspend(h, env);
	}
	auto await_resume() -> capy::results<std::size_t>
	{
		if (!inner) {
			return { std::make_error_code(std::errc::broken_pipe), 0 };
		}
		return inner->await_resume();
	}
};

// The client end of a socket pair whose writes fail once *broken is set.
struct breakable_stream
{
	corosio::local_stream_socket *s;
	const bool *broken;

	template<capy::MutableBufferSequence MB> auto read_some(MB buffers) { return s->read_some(buffers); }
	template<capy::ConstBufferSequence CB> auto write_some(CB buffers)
	{
		breakable_write<decltype(s->write_some(buffers))> w;
		if (!*broken) {
			w.inner.emplace(s->write_some(buffers));
		}
		return w;
	}
};

// Destroys `t` inside a coroutine on the connection's io_context, where
// the writer an abort starts runs inline.
}// namespace

TEST_CASE("transaction: deferred updates and their response controls at commit", "[net][transaction]")
{
	mock_ldap m;
	m.serve({ answer({ started(1) }),
	  answer({ result_msg<ldap::add_response>(2) }),
	  answer({ result_msg<ldap::modify_response>(3) }),
	  answer({ ended(4, 0, { std::nullopt, { ldap::update_controls{ 2, { post_read_entry() } } } }) }) });

	auto t = m.run(ldap::transaction::begin(m.conn));
	REQUIRE(t.has_value());
	CHECK(t->is_open());
	CHECK(t->identifier() == txn_id);
	auto a = m.run(t->add({ .entry = jdoe,
	  .attributes = { { "objectClass", { "inetOrgPerson" } }, { "uid", { "jdoe" } } },
	  .controls = { ldap::post_read{ .attributes = { "uid" } } } }));
	REQUIRE(a.has_value());
	CHECK(a->message_id == 2);
	CHECK(a->controls.empty());// deferred: the post-read entry comes with the commit
	auto mod = m.run(t->modify({ .object = group, .changes = { ldap::mod::add("member", { "uid=jdoe" }) } }));
	REQUIRE(mod.has_value());
	CHECK(mod->message_id == 3);

	auto done = m.run(t->commit());
	REQUIRE(done.has_value());
	CHECK_FALSE(t->is_open());
	const auto *controls = done->find_update_controls(a->message_id);
	REQUIRE(controls != nullptr);
	auto e = ldap::find_post_read(*controls);
	REQUIRE(e.has_value());
	REQUIRE(e->has_value());
	CHECK((*e)->dn == jdoe.to_string());
	CHECK(done->find_update_controls(mod->message_id) == nullptr);
	m.check_server();

	REQUIRE(m.log.received.size() == 4);
	CHECK(m.log.received[0] == ldap::message{ 1, ldap::extended_request{ ldap::start_transaction_oid } });
	// Each update carries the specification after its own controls.
	REQUIRE(m.log.received[1].controls.size() == 2);
	CHECK(m.log.received[1].controls[0].type == ldap::post_read_oid);
	CHECK(m.log.received[1].controls[1] == spec_control());
	CHECK(m.log.received[2].controls == std::pmr::vector<ldap::control>{ spec_control() });
	CHECK(end_request_of(m.log.received[3]) == ldap::end_transaction_request{ true, txn_id });
}

TEST_CASE("transaction: the primitives", "[net][transaction]")
{
	mock_ldap m;
	m.serve({ answer({ started(1) }),
	  answer({ result_msg<ldap::del_response>(2) }),
	  answer({ ended(3, 0, {}) }),
	  answer({ started(4) }),
	  answer({ ended(5, 68, ldap::end_transaction_response{ 7 }) }) });

	auto id = m.run(ldap::start_transaction(m.conn, { ldap::proxied_authorization{ "u:jdoe" } }));
	REQUIRE(id.has_value());
	CHECK(*id == txn_id);
	auto d =
	  m.run(m.conn.del({ .entry = jdoe, .controls = { ldap::transaction_specification{ .identifier = "txn-1" } } }));
	REQUIRE(d.has_value());
	CHECK(d->message_id == 2);
	auto ok = m.run(ldap::end_transaction(m.conn, *id));
	REQUIRE(ok.has_value());
	CHECK(ok->updates_controls.empty());

	auto again = m.run(ldap::start_transaction(m.conn));
	REQUIRE(again.has_value());
	auto refused = m.run(ldap::end_transaction(m.conn, *again));
	REQUIRE_FALSE(refused.has_value());
	CHECK(refused.error().code == errc::entry_already_exists);
	CHECK(refused.error().context == "end transaction: update message 7");
	CHECK(m.conn.is_open());
	m.check_server();

	REQUIRE(m.log.received.size() == 5);
	// RFC 5805 section 4.4: proxied authorization goes on Start Transaction.
	CHECK(m.log.received[0]
		  == ldap::message{ 1,
			ldap::extended_request{ ldap::start_transaction_oid },
			{ ldap::control{ ldap::proxied_authorization_oid, true, "u:jdoe" } } });
	CHECK(m.log.received[1].controls == std::pmr::vector<ldap::control>{ spec_control() });
	CHECK(end_request_of(m.log.received[2]) == ldap::end_transaction_request{ true, txn_id });
}

TEST_CASE("transaction: a failed commit names the update at fault", "[net][transaction]")
{
	mock_ldap m;
	m.serve({ answer({ started(1) }),
	  answer({ result_msg<ldap::add_response>(2) }),
	  answer({ result_msg<ldap::modify_dn_response>(3) }),
	  answer({ ended(4, 68, ldap::end_transaction_response{ 3 }) }),
	  answer({ started(5) }),
	  answer({ ended(6, 51, ldap::end_transaction_response{ 9 }) }),
	  answer({ started(7) }),
	  answer({ ended(8, 80, {}) }) });

	auto t = m.run(ldap::transaction::begin(m.conn));
	REQUIRE(t.has_value());
	REQUIRE(m.run(t->add({ .entry = jdoe, .attributes = { { "uid", { "jdoe" } } } })).has_value());
	REQUIRE(m.run(t->modify_dn({ .entry = jdoe, .new_rdn = ldap::rdn{ "uid=john" } })).has_value());
	auto c = m.run(t->commit());
	REQUIRE_FALSE(c.has_value());
	CHECK(c.error().code == errc::entry_already_exists);
	CHECK(c.error().context == "commit transaction: update message 3 (modify DN uid=jdoe,ou=people,dc=example,dc=org)");
	CHECK_FALSE(t->is_open());

	// An id this transaction did not send, and no id at all.
	auto u = m.run(ldap::transaction::begin(m.conn));
	REQUIRE(u.has_value());
	auto unknown = m.run(u->commit());
	REQUIRE_FALSE(unknown.has_value());
	CHECK(unknown.error().context == "commit transaction: update message 9");
	auto v = m.run(ldap::transaction::begin(m.conn));
	REQUIRE(v.has_value());
	auto plain = m.run(v->commit());
	REQUIRE_FALSE(plain.has_value());
	CHECK(plain.error().code == errc::other);
	CHECK(plain.error().context == "commit transaction");
	CHECK(m.conn.is_open());
	m.check_server();
}

TEST_CASE("transaction: an empty identifier", "[net][transaction]")
{
	mock_ldap m;
	m.serve({ answer({ ext_resp(1, 0, std::nullopt, "") }),
	  answer({ result_msg<ldap::del_response>(2) }),
	  answer({ ended(3, 0, {}) }) });

	auto t = m.run(ldap::transaction::begin(m.conn));
	REQUIRE(t.has_value());
	CHECK(t->is_open());
	CHECK(t->identifier().empty());
	REQUIRE(m.run(t->del({ .entry = jdoe })).has_value());
	REQUIRE(m.run(t->commit()).has_value());
	CHECK_FALSE(t->is_open());
	m.check_server();

	REQUIRE(m.log.received.size() == 3);
	const ldap::control empty_spec{ ldap::transaction_specification_oid, true, "" };
	REQUIRE(empty_spec.value.has_value());
	CHECK(m.log.received[1].controls == std::pmr::vector<ldap::control>{ empty_spec });
	CHECK(end_request_of(m.log.received[2]) == ldap::end_transaction_request{ true, "" });
}

TEST_CASE("transaction: abort, and a settled transaction refuses more", "[net][transaction]")
{
	mock_ldap m;
	m.serve({ answer({ started(1) }), answer({ result_msg<ldap::del_response>(2) }), answer({ ended(3, 0, {}) }) });

	auto t = m.run(ldap::transaction::begin(m.conn));
	REQUIRE(t.has_value());
	REQUIRE(m.run(t->del({ .entry = jdoe })).has_value());
	auto a = m.run(t->abort());
	REQUIRE(a.has_value());
	CHECK_FALSE(t->is_open());

	auto late = m.run(t->del({ .entry = jdoe }));
	REQUIRE_FALSE(late.has_value());
	CHECK(late.error().code == std::errc::invalid_argument);
	CHECK(late.error().context
		  == "delete uid=jdoe,ou=people,dc=example,dc=org: the transaction is already committed or aborted");
	CHECK(m.run(t->commit()).error().code == std::errc::invalid_argument);
	CHECK(m.run(t->abort()).error().code == std::errc::invalid_argument);

	// Not started: not connected.
	ldap::transaction none;
	CHECK_FALSE(none.is_open());
	CHECK(none.identifier().empty());
	CHECK(m.run(none.commit()).error().code == client_errc::not_connected);
	m.check_server();

	REQUIRE(m.log.received.size() == 3);
	CHECK(end_request_of(m.log.received[2]) == ldap::end_transaction_request{ false, txn_id });
}

TEST_CASE("transaction: destroyed while open, it is aborted without waiting", "[net][transaction]")
{
	mock_ldap m;
	m.serve({ answer({ started(1) }),
	  answer({ result_msg<ldap::add_response>(2) }),
	  answer({ ended(3, 0, {}) }),// the abort's answer: dropped
	  answer({ ext_resp(4, 0, std::nullopt, "dn:cn=admin,dc=example,dc=org") }) });
	{
		auto t = m.run(ldap::transaction::begin(m.conn));
		REQUIRE(t.has_value());
		ldap::transaction moved = std::move(*t);
		CHECK_FALSE(t->is_open());// moved from
		REQUIRE(m.run(moved.add({ .entry = jdoe, .attributes = { { "uid", { "jdoe" } } } })).has_value());
		run_on(m.ioc, m.conn.executor(), [&moved] { moved = ldap::transaction{}; });
	}
	CHECK(m.conn.outstanding() == 1);// the abort's answer is due
	auto me = m.run(ldap::who_am_i(m.conn));
	REQUIRE(me.has_value());
	CHECK(m.conn.outstanding() == 0);
	CHECK(m.conn.is_open());
	m.check_server();

	REQUIRE(m.log.received.size() == 4);
	CHECK(m.log.received[2].id == 3);
	CHECK(end_request_of(m.log.received[2]) == ldap::end_transaction_request{ false, txn_id });

	// Committed or aborted, or on a closed connection: nothing is sent.
	{
		ldap::transaction moved_from;
		auto t = ldap::transaction{};
		moved_from = std::move(t);
	}
	m.conn.close();
	CHECK(m.log.received.size() == 4);
}

TEST_CASE("transaction: destroyed during a bind that fails, it is still aborted", "[net][transaction]")
{
	mock_ldap m;
	m.serve({ answer({ started(1) }),
	  step{},// reads the BindRequest, does not answer yet
	  step{ .read_request = false, .replies = { bytes_of(bind_resp(2, 49)) } },
	  answer({ ended(3, 0, {}) }),// the abort's answer: dropped
	  answer({ started(4) }) });
	outcome<ldap::result<ldap::connection>> bound;
	{
		auto t = m.run(ldap::transaction::begin(m.conn));
		REQUIRE(t.has_value());
		spawn(m.ioc, m.conn.simple_bind(ldap::dn{ "cn=admin,dc=example,dc=org" }, "wrong"), bound);
		drive_until(m.ioc, [&m] { return m.log.received.size() == 2; });
		run_on(m.ioc, m.conn.executor(), [&t] { *t = ldap::transaction{}; });
	}
	drive_until(m.ioc, [&bound] { return bound.done(); });
	CHECK(bound.get().error().code == errc::invalid_credentials);
	drive_until(m.ioc, [&m] { return m.conn.outstanding() == 0; });
	CHECK(m.run(ldap::transaction::begin(m.conn)).has_value());
	m.check_server();
	REQUIRE(m.log.received.size() == 4);
	CHECK(m.log.received[2].id == 3);
	CHECK(end_request_of(m.log.received[2]) == ldap::end_transaction_request{ false, txn_id });
}

TEST_CASE("transaction: rejected updates leave it open", "[net][transaction]")
{
	mock_ldap m;
	m.serve({ answer({ started(1) }),
	  answer({ result_msg<ldap::add_response>(2, 53) }),
	  answer({ result_msg<ldap::add_response>(3) }),
	  answer({ ended(4, 0, {}) }) });

	auto t = m.run(ldap::transaction::begin(m.conn));
	REQUIRE(t.has_value());
	auto refused = m.run(t->add({ .entry = jdoe, .attributes = { { "uid", { "jdoe" } } } }));
	REQUIRE_FALSE(refused.has_value());
	CHECK(refused.error().code == errc::unwilling_to_perform);
	CHECK(refused.error().context == "add uid=jdoe,ou=people,dc=example,dc=org");
	CHECK(t->is_open());
	REQUIRE(m.run(t->add({ .entry = group, .attributes = { { "cn", { "staff" } } } })).has_value());

	// A specification already in the request, and proxied authorization,
	// fail before anything is sent (RFC 5805 section 4.4).
	auto twice = m.run(t->del({ .entry = jdoe, .controls = { ldap::transaction_specification{ .identifier = "x" } } }));
	REQUIRE_FALSE(twice.has_value());
	CHECK(twice.error().code == client_errc::encode_error);
	CHECK(twice.error().context
		  == "delete uid=jdoe,ou=people,dc=example,dc=org: the request already carries a transaction_specification");
	auto proxied = m.run(t->modify({ .object = jdoe,
	  .changes = { ldap::mod::replace("mail", { "j@example.org" }) },
	  .controls = { ldap::proxied_authorization{ "u:jdoe" } } }));
	REQUIRE_FALSE(proxied.has_value());
	CHECK(proxied.error().code == client_errc::encode_error);
	CHECK(proxied.error().context
		  == "modify uid=jdoe,ou=people,dc=example,dc=org: proxied_authorization is not valid on an update in a "
			 "transaction: put it on the Start Transaction request (RFC 5805 section 4.4)");
	auto raw = m.run(m.conn.add({ .entry = jdoe,
	  .attributes = { { "uid", { "jdoe" } } },
	  .controls = { ldap::control{ ldap::proxied_authorization_oid, true, "u:jdoe" },
		ldap::transaction_specification{ .identifier = "txn-1" } } }));
	REQUIRE_FALSE(raw.has_value());
	CHECK(raw.error().code == client_errc::encode_error);
	CHECK(t->is_open());

	REQUIRE(m.run(t->commit()).has_value());
	m.check_server();
	CHECK(m.log.received.size() == 4);// nothing sent for the refused requests
}

TEST_CASE("transaction: answers RFC 5805 section 2 does not allow", "[net][transaction]")
{
	mock_ldap m;
	m.serve({ answer({ ext_resp(1, 2, std::nullopt, std::nullopt) }),
	  answer({ ext_resp(2, 0, "1.3.6.1.1.21.1", txn_id) }),
	  answer({ ext_resp(3, 0) }),
	  answer({ started(4) }),
	  answer({ ext_resp(5, 0, "1.3.6.1.1.21.3") }),
	  answer({ started(6) }),
	  answer({ ext_resp(7, 0, std::nullopt, "not BER") }),
	  answer({ started(8) }),
	  answer({ ext_resp(9, 32, std::nullopt, "not BER") }) });

	auto unsupported = m.run(ldap::transaction::begin(m.conn));
	REQUIRE_FALSE(unsupported.has_value());
	CHECK(unsupported.error().code == errc::protocol_error);
	CHECK(unsupported.error().context == "start transaction");
	auto named = m.run(ldap::start_transaction(m.conn));
	REQUIRE_FALSE(named.has_value());
	CHECK(named.error().code == client_errc::decode_error);
	CHECK(named.error().context == "start transaction: the response has a responseName (RFC 5805 section 2.1)");
	auto no_id = m.run(ldap::start_transaction(m.conn));
	REQUIRE_FALSE(no_id.has_value());
	CHECK(
	  no_id.error().context == "start transaction: the response has no transaction identifier (RFC 5805 section 2.1)");

	auto t = m.run(ldap::transaction::begin(m.conn));
	REQUIRE(t.has_value());
	auto end_named = m.run(t->commit());
	REQUIRE_FALSE(end_named.has_value());
	CHECK(end_named.error().context == "commit transaction: the response has a responseName (RFC 5805 section 2.3)");
	auto u = m.run(ldap::transaction::begin(m.conn));
	REQUIRE(u.has_value());
	auto malformed = m.run(u->commit());
	REQUIRE_FALSE(malformed.has_value());
	CHECK(malformed.error().code == client_errc::decode_error);
	CHECK(malformed.error().context.starts_with("commit transaction: txnEndRes: "));
	// A refusal with a malformed txnEndRes keeps the server's code.
	auto v = m.run(ldap::transaction::begin(m.conn));
	REQUIRE(v.has_value());
	auto refused = m.run(v->commit());
	REQUIRE_FALSE(refused.has_value());
	CHECK(refused.error().code == errc::no_such_object);
	CHECK(refused.error().context == "commit transaction");
	CHECK(m.conn.is_open());
	m.check_server();
}

TEST_CASE("transaction: an End Transaction never sent leaves it to the destructor", "[net][transaction][cancel]")
{
	mock_ldap m;
	m.serve({ answer({ started(1) }),
	  answer({ ended(2, 0, {}) }),// the destructor's abort: dropped
	  answer({ ext_resp(3, 0, std::nullopt, "dn:cn=admin,dc=example,dc=org") }),
	  answer({ started(4) }),
	  answer({ ended(5, 0, {}) }) });
	{
		auto t = m.run(ldap::transaction::begin(m.conn));
		REQUIRE(t.has_value());
		std::stop_source stop;
		stop.request_stop();
		auto a = m.run(ldap::with_stop(stop.get_token(), t->abort()));
		REQUIRE_FALSE(a.has_value());
		CHECK(a.error().code == ldap::cond::canceled);
		CHECK_FALSE(t->is_open());// settled for the API...
		CHECK(m.log.received.size() == 1);// nothing was sent
		run_on(m.ioc, m.conn.executor(), [&t] { *t = ldap::transaction{}; });
	}
	// ...so the destructor still aborts it on the server.
	CHECK(m.conn.outstanding() == 1);
	REQUIRE(m.run(ldap::who_am_i(m.conn)).has_value());

	// Once the server answered, the destructor sends nothing more.
	{
		auto t = m.run(ldap::transaction::begin(m.conn));
		REQUIRE(t.has_value());
		REQUIRE(m.run(t->abort()).has_value());
	}
	CHECK(m.conn.outstanding() == 0);
	m.check_server();
	REQUIRE(m.log.received.size() == 5);
	CHECK(m.log.received[1].id == 2);
	CHECK(end_request_of(m.log.received[1]) == ldap::end_transaction_request{ false, txn_id });
	CHECK(end_request_of(m.log.received[4]) == ldap::end_transaction_request{ false, txn_id });
}

namespace {

auto send_reply(net::transport t, ldap::message m) -> capy::task<void>
{
	const auto bytes = bytes_of(m);
	if (auto w = co_await net::write_bytes(t, std::as_bytes(std::span(bytes))); !w) {
		throw std::runtime_error("write: " + std::string(w.error().message()));
	}
}

// Destroys a started transaction with `drop` and begins another: Start
// Transaction waits for the abort's answer.
template<class Drop> void drop_then_begin(Drop drop)
{
	mock_ldap m;
	m.serve({ answer({ started(1) }),
	  step{},// the destructor's abort, answered from outside the script
	  answer({ started(3) }),
	  answer({ ended(4, 0, {}) }) });
	auto t = m.run(ldap::transaction::begin(m.conn));
	REQUIRE(t.has_value());
	drop(m, *t);
	outcome<ldap::result<ldap::transaction>> next;
	spawn(m.ioc, ldap::transaction::begin(m.conn), next);
	drive_until(m.ioc, [&m] { return m.log.received.size() == 2; });
	m.ioc.run_for(std::chrono::milliseconds(50));
	m.ioc.restart();
	CHECK(m.log.received.size() == 2);
	CHECK_FALSE(next.done());

	outcome<void> sent;
	spawn(m.ioc, send_reply(m.server_end(), ended(2, 0, {})), sent);
	drive_until(m.ioc, [&next] { return next.done(); });
	auto &u = next.get();
	REQUIRE(u.has_value());
	CHECK(u->is_open());
	REQUIRE(m.run(u->abort()).has_value());
	m.check_server();
	REQUIRE(m.log.received.size() == 4);
	CHECK(end_request_of(m.log.received[1]) == ldap::end_transaction_request{ false, txn_id });
	const auto *start = std::get_if<ldap::extended_request>(&m.log.received[2].op);
	REQUIRE(start != nullptr);
	CHECK(start->request_name == ldap::start_transaction_oid);
}

}// namespace

TEST_CASE("transaction: begin waits for a destroyed transaction's abort", "[net][transaction]")
{
	SECTION("destroyed on the connection's strand")
	{
		drop_then_begin([](mock_ldap &m, ldap::transaction &t) {
			run_on(m.ioc, m.conn.executor(), [&t] { t = ldap::transaction{}; });
			CHECK(m.conn.outstanding() == 1);
		});
	}
	SECTION("destroyed off the strand")
	{
		drop_then_begin([](mock_ldap &, ldap::transaction &t) { t = ldap::transaction{}; });
	}
}

TEST_CASE("transaction: a stop while begin waits for the answers due sends nothing", "[net][transaction][cancel]")
{
	mock_ldap m;
	m.serve({ answer({ started(1) }), step{} });
	auto t = m.run(ldap::transaction::begin(m.conn));
	REQUIRE(t.has_value());
	run_on(m.ioc, m.conn.executor(), [&t] { *t = ldap::transaction{}; });
	std::stop_source stop;
	outcome<ldap::result<ldap::transaction>> next;
	spawn(m.ioc, stop.get_token(), ldap::transaction::begin(m.conn), next);
	drive_until(m.ioc, [&m] { return m.log.received.size() == 2; });
	stop.request_stop();
	drive_until(m.ioc, [&next] { return next.done(); });
	REQUIRE_FALSE(next.get().has_value());
	CHECK(next.get().error().code == ldap::cond::canceled);
	CHECK(next.get().error().context == "start transaction (waiting for 1 answer due)");
	CHECK(m.conn.is_open());
	CHECK(m.log.received.size() == 2);
}

TEST_CASE("transaction: commit refuses while an update is in flight", "[net][transaction]")
{
	mock_ldap m;
	m.serve({ answer({ started(1) }),
	  step{},// the add: answered with the abort below
	  answer({ result_msg<ldap::add_response>(2), ended(3, 0, {}) }) });

	auto t = m.run(ldap::transaction::begin(m.conn));
	REQUIRE(t.has_value());
	outcome<ldap::result<ldap::response>> add;
	spawn(m.ioc, t->add({ .entry = jdoe, .attributes = { { "uid", { "jdoe" } } } }), add);
	drive_until(m.ioc, [&m] { return m.log.received.size() == 2; });
	CHECK_FALSE(add.done());

	auto early = m.run(t->commit());
	REQUIRE_FALSE(early.has_value());
	CHECK(early.error().code == client_errc::operation_in_progress);
	CHECK(early.error().context == "commit transaction: 1 update(s) still in flight: await every update first");
	CHECK(t->is_open());// nothing sent: still open

	REQUIRE(m.run(t->abort()).has_value());
	REQUIRE(add.done());
	CHECK(add.get().has_value());
	m.check_server();
	REQUIRE(m.log.received.size() == 3);
	CHECK(end_request_of(m.log.received[2]) == ldap::end_transaction_request{ false, txn_id });
}

TEST_CASE("transaction: a raw transaction specification is refused too", "[net][transaction]")
{
	mock_ldap m;
	m.serve({ answer({ started(1) }), answer({ ended(2, 0, {}) }) });

	auto t = m.run(ldap::transaction::begin(m.conn));
	REQUIRE(t.has_value());
	auto raw = m.run(t->del({ .entry = jdoe, .controls = { spec_control() } }));
	REQUIRE_FALSE(raw.has_value());
	CHECK(raw.error().code == client_errc::encode_error);
	CHECK(raw.error().context
		  == "delete uid=jdoe,ou=people,dc=example,dc=org: the request already carries a transaction_specification");
	REQUIRE(m.run(t->commit()).has_value());
	m.check_server();
	CHECK(m.log.received.size() == 2);
}

TEST_CASE("transaction: an Aborted Transaction Notice is ignored", "[net][transaction]")
{
	mock_ldap m;
	m.serve({ answer({ started(1) }),
	  answer({ ldap::message{ 0,
				 ldap::extended_response{
				   ldap::ldap_result{ 51, "", "busy" }, std::string(ldap::aborted_transaction_notice_oid), txn_id } },
		result_msg<ldap::add_response>(2) }),
	  answer({ ended(3, 80, {}) }) });

	auto t = m.run(ldap::transaction::begin(m.conn));
	REQUIRE(t.has_value());
	REQUIRE(m.run(t->add({ .entry = jdoe, .attributes = { { "uid", { "jdoe" } } } })).has_value());
	CHECK(t->is_open());
	CHECK(m.conn.is_open());
	// The commit then fails with the server's error.
	auto c = m.run(t->commit());
	REQUIRE_FALSE(c.has_value());
	CHECK(c.error().code == errc::other);
	CHECK(m.conn.is_open());
	m.check_server();
}

TEST_CASE("transaction: destroyed while the abort's write fails inline", "[net][transaction]")
{
	corosio::io_context ioc;
	socket_pair sockets{ ioc };
	bool broken = false;
	ldap::connection conn(
	  ioc, net::transport::wrap(breakable_stream{ .s = &sockets.client, .broken = &broken }, "breakable"));
	server_log log;
	outcome<void> server;
	spawn(ioc,
	  serve_script(net::transport::wrap(socket_ref{ &sockets.server }, "server"), { answer({ started(1) }) }, log),
	  server);
	auto t = finish(ioc, ldap::transaction::begin(conn));
	REQUIRE(t.has_value());
	REQUIRE(t->is_open());
	drive_until(ioc, [&server] { return server.done(); });
	CHECK(log.error.empty());

	broken = true;
	run_on(ioc, conn.executor(), [&t] { *t = ldap::transaction{}; });
	CHECK_FALSE(conn.is_open());
	CHECK(conn.outstanding() == 0);
	CHECK(log.received.size() == 1);
	const auto me = finish(ioc, ldap::who_am_i(conn));
	REQUIRE_FALSE(me.has_value());
	CHECK(me.error().code == client_errc::not_sent);
	CHECK_THAT(std::string(me.error().context), Catch::Matchers::ContainsSubstring("write breakable"));

	sockets.client.close();
	sockets.server.close();
	drive(ioc);
}
