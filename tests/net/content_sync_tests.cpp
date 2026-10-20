// RFC 4533 content synchronization over search_stream::next_item(),
// against the scripted in-process server (mock_ldap.hpp): the refresh
// phase (entries with Sync State controls, Sync Info Messages), the Sync
// Done of a refreshOnly search, and the persist phase of a
// refreshAndPersist search outliving the operation timeout.
#include "jhetz/ldap/connection.hpp"
#include "jhetz/ldap/content_sync.hpp"
#include "jhetz/ldap/net/message_io.hpp"
#include "mock_ldap.hpp"
#include "net_test_support.hpp"

#include <boost/corosio/delay.hpp>

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace ldap = jhetz::ldap;
using namespace jhetz::ldap::test;

namespace {

auto uuid_of(std::uint8_t first) -> ldap::sync_uuid
{
	ldap::sync_uuid u;
	u.bytes[0] = static_cast<std::byte>(first);
	return u;
}

// A SearchResultEntry of search `id` with a Sync State control.
auto synced_entry(std::int32_t id,
  std::string_view dn,
  ldap::sync_state_type state,
  std::uint8_t uuid,
  std::optional<std::string_view> cookie = std::nullopt) -> ldap::message
{
	auto m = entry_msg(id, dn, "x");
	m.controls.push_back(ldap::encode_sync_state(ldap::sync_state{ state, uuid_of(uuid), cookie }).value());
	return m;
}

auto info_msg(std::int32_t id, const ldap::sync_info &info) -> ldap::message
{
	return ldap::message{ id, ldap::encode_sync_info(info).value() };
}

auto sync_done_msg(std::int32_t id, const ldap::sync_done &done) -> ldap::message
{
	auto m = done_msg(id);
	m.controls.push_back(ldap::encode_sync_done(done).value());
	return m;
}

// What a sync consumer keeps: the entries by state, and the latest cookie.
struct replica
{
	std::vector<std::pair<ldap::sync_state_type, std::string>> changes{};
	std::optional<std::string> cookie{};
	bool refresh_done = false;
	std::size_t infos = 0;
};

// Applies one item; false at the end of the search.
auto apply(replica &r, ldap::result<std::optional<ldap::search_stream::item>> &i) -> bool
{
	REQUIRE(i.has_value());
	if (!*i) {
		return false;
	}
	if (const auto *e = std::get_if<ldap::search_entry>(&**i)) {
		auto state = ldap::find_sync_state(e->controls);
		REQUIRE(state.has_value());
		REQUIRE(state->has_value());
		r.changes.emplace_back((*state)->state, e->dn);
		if ((*state)->cookie) {
			r.cookie = std::string(*(*state)->cookie);
		}
	} else if (const auto *m = std::get_if<ldap::intermediate>(&**i)) {
		auto info = ldap::decode_sync_info(*m);
		REQUIRE(info.has_value());
		++r.infos;
		if (info->cookie) {
			r.cookie = std::string(*info->cookie);
		}
		if (info->type == ldap::sync_info_type::refresh_delete || info->type == ldap::sync_info_type::refresh_present) {
			r.refresh_done = info->refresh_done;
		}
	} else {
		FAIL("unexpected reference");
	}
	return true;
}

// Writes `m` on the server's end after `after`, outside the script.
auto send_later(net::transport t, ldap::message m, std::chrono::milliseconds after) -> capy::task<void>
{
	co_await corosio::delay(after);
	const auto bytes = bytes_of(m);
	if (auto w = co_await net::write_bytes(t, std::as_bytes(std::span(bytes))); !w) {
		throw std::runtime_error("write: " + std::string(w.error().message()));
	}
}

const std::string a = "uid=a,ou=people,dc=example,dc=org";
const std::string b = "uid=b,ou=people,dc=example,dc=org";

}// namespace

TEST_CASE("content sync: a refreshOnly search", "[net][content_sync]")
{
	mock_ldap m;
	m.serve({ answer({ synced_entry(1, a, ldap::sync_state_type::add, 1),
	  info_msg(1, ldap::sync_info{ ldap::sync_info_type::new_cookie, "c1" }),
	  synced_entry(1, b, ldap::sync_state_type::present, 2),
	  sync_done_msg(1, ldap::sync_done{ "c2", true }) }) });
	auto s = m.run(m.conn.search_stream({ .base = ldap::dn::parse(people).value(),
	  .controls = { ldap::sync_request{ .cookie = "c0" } },
	  .intermediate_responses = true }));
	REQUIRE(s.has_value());
	replica r;
	while (true) {
		auto i = m.run(s->next_item());
		if (!apply(r, i)) {
			break;
		}
	}
	CHECK(r.changes
		  == std::vector<std::pair<ldap::sync_state_type, std::string>>{
			{ ldap::sync_state_type::add, a }, { ldap::sync_state_type::present, b } });
	CHECK(r.infos == 1);
	CHECK(r.cookie == "c1");
	auto done = ldap::find_sync_done(s->controls());
	REQUIRE(done.has_value());
	REQUIRE(done->has_value());
	CHECK((*done)->cookie == "c2");
	CHECK((*done)->refresh_deletes);
	m.check_server();

	// What the server got: the critical Sync Request control, refreshOnly from c0.
	REQUIRE(m.log.received.size() == 1);
	REQUIRE(m.log.received[0].controls.size() == 1);
	auto request = ldap::decode_sync_request(m.log.received[0].controls[0]);
	REQUIRE(request.has_value());
	CHECK(*request
		  == ldap::sync_request{
			.mode = ldap::sync_mode::refresh_only, .cookie = "c0", .reload_hint = false, .critical = true });
}

TEST_CASE("content sync: an outdated cookie fails with e-syncRefreshRequired", "[net][content_sync]")
{
	// RFC 4533 section 3.8: the Sync Done of the failed result carries the
	// cookie to resume from (none would mean a full reload).
	mock_ldap m;
	auto refresh_required = done_msg(1, 4096);
	refresh_required.controls.push_back(ldap::encode_sync_done(ldap::sync_done{ "resume" }).value());
	m.serve({ answer({ refresh_required }) });
	auto s = m.run(m.conn.search_stream({ .base = ldap::dn::parse(people).value(),
	  .controls = { ldap::sync_request{ .cookie = "old" } },
	  .intermediate_responses = true }));
	REQUIRE(s.has_value());
	auto i = m.run(s->next_item());
	REQUIRE_FALSE(i.has_value());
	CHECK(i.error().code == ldap::errc::e_sync_refresh_required);
	auto done = ldap::find_sync_done(s->controls());
	REQUIRE(done.has_value());
	REQUIRE(done->has_value());
	CHECK((*done)->cookie == "resume");
	CHECK_FALSE((*done)->refresh_deletes);
	m.check_server();
}

TEST_CASE("content sync: a refreshOnly present phase followed by a delete phase", "[net][content_sync]")
{
	// RFC 4533 section 3.3.2: a refreshPresent with refreshDone false ends
	// the present phase, the delete phase follows, then the Sync Done.
	mock_ldap m;
	ldap::sync_info present_end{ ldap::sync_info_type::refresh_present, "c1" };
	present_end.refresh_done = false;
	m.serve({ answer({ synced_entry(1, a, ldap::sync_state_type::present, 1),
	  info_msg(1, present_end),
	  synced_entry(1, b, ldap::sync_state_type::del, 2),
	  sync_done_msg(1, ldap::sync_done{ "c2", true }) }) });
	auto s = m.run(m.conn.search_stream({ .base = ldap::dn::parse(people).value(),
	  .controls = { ldap::sync_request{ .cookie = "c0" } },
	  .intermediate_responses = true }));
	REQUIRE(s.has_value());
	replica r;
	for (std::size_t n = 0;; ++n) {
		auto i = m.run(s->next_item());
		if (!apply(r, i)) {
			break;
		}
		if (n == 1) {
			// Right after the refreshPresent: more refresh content follows.
			CHECK_FALSE(r.refresh_done);
			CHECK(r.cookie == "c1");
		}
	}
	CHECK(r.changes
		  == std::vector<std::pair<ldap::sync_state_type, std::string>>{
			{ ldap::sync_state_type::present, a }, { ldap::sync_state_type::del, b } });
	auto done = ldap::find_sync_done(s->controls());
	REQUIRE(done.has_value());
	REQUIRE(done->has_value());
	CHECK((*done)->cookie == "c2");
	m.check_server();
}

TEST_CASE("content sync: refreshAndPersist outlives the operation timeout with no_timeout",
  "[net][content_sync][timeout]")
{
	// Any timeout of its own would end the persist phase: the connection's
	// is 50 ms, the change comes after 150 ms.
	mock_ldap m({ .operation_timeout = std::chrono::milliseconds(50) });
	m.serve({ answer({ synced_entry(1, a, ldap::sync_state_type::add, 1),
				info_msg(1,
				  [] {
					  ldap::sync_info end{ ldap::sync_info_type::refresh_present, "c1" };
					  end.refresh_done = true;
					  return end;
				  }()) }),
	  step{} });// then reads the abandon
	auto s = m.run(m.conn.search_stream({ .base = ldap::dn::parse(people).value(),
	  .controls = { ldap::sync_request{ .mode = ldap::sync_mode::refresh_and_persist } },
	  .timeout = ldap::no_timeout,
	  .intermediate_responses = true }));
	REQUIRE(s.has_value());
	replica r;
	for (int n = 0; n < 2; ++n) {
		auto i = m.run(s->next_item());
		REQUIRE(apply(r, i));
	}
	CHECK(r.refresh_done);
	CHECK(r.cookie == "c1");

	// The persist phase: a change, long after the connection's timeout.
	outcome<void> sent;
	spawn(m.ioc,
	  send_later(
		m.server_end(), synced_entry(1, b, ldap::sync_state_type::modify, 2, "c2"), std::chrono::milliseconds(150)),
	  sent);
	const auto start = std::chrono::steady_clock::now();
	auto change = m.run(s->next_item());
	CHECK(std::chrono::steady_clock::now() - start >= std::chrono::milliseconds(100));
	REQUIRE(apply(r, change));
	CHECK(r.changes.back() == std::pair{ ldap::sync_state_type::modify, b });
	CHECK(r.cookie == "c2");
	CHECK_FALSE(s->done());
	drive_until(m.ioc, [&sent] { return sent.done(); });
	sent.get();

	// Stopping: destroying the stream abandons the search.
	*s = ldap::search_stream{};
	m.check_server();
	REQUIRE(m.log.received.size() == 2);
	CHECK(m.log.received[1] == ldap::message{ 2, ldap::abandon_request{ 1 } });
}
