#include "jhetz/ldap/content_sync.hpp"
#include "jhetz/ldap/controls.hpp"

#include "counting_resource.hpp"
#include "test_util.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstddef>
#include <memory_resource>
#include <optional>
#include <span>
#include <string>
#include <string_view>

namespace ldap = jhetz::ldap;
using jhetz::ldap::test::from_hex;
using jhetz::ldap::test::hex;

namespace {

auto value_hex(const ldap::control &c) -> std::string
{
	REQUIRE(c.value.has_value());
	return hex(std::as_bytes(std::span(*c.value)));
}

auto with_value(std::string_view oid, std::string_view hex_value) -> ldap::control
{
	const auto b = from_hex(hex_value);
	return ldap::control{ oid, false, ldap::detail::as_text(b) };
}

auto info_with(std::string_view hex_value) -> ldap::intermediate_response
{
	const auto b = from_hex(hex_value);
	return ldap::intermediate_response{ ldap::sync_info_oid, ldap::detail::as_text(b) };
}

// 00 01 .. 0F
auto counting_uuid() -> ldap::sync_uuid
{
	ldap::sync_uuid u;
	for (std::size_t i = 0; i < u.bytes.size(); ++i) {
		u.bytes[i] = static_cast<std::byte>(i);
	}
	return u;
}

constexpr std::string_view counting_uuid_hex = "00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F";

}// namespace

TEST_CASE("RFC 4533: the OIDs", "[content_sync][rfc]")
{
	CHECK(ldap::sync_request_oid == "1.3.6.1.4.1.4203.1.9.1.1");
	CHECK(ldap::sync_state_oid == "1.3.6.1.4.1.4203.1.9.1.2");
	CHECK(ldap::sync_done_oid == "1.3.6.1.4.1.4203.1.9.1.3");
	CHECK(ldap::sync_info_oid == "1.3.6.1.4.1.4203.1.9.1.4");
}

TEST_CASE("sync request control", "[content_sync]")
{
	// Defaults: refreshOnly, no cookie, reloadHint FALSE left out, critical.
	const auto plain = ldap::to_control(ldap::sync_request{});
	REQUIRE(plain.has_value());
	CHECK(plain->type == ldap::sync_request_oid);
	CHECK(plain->criticality);
	CHECK(value_hex(*plain) == "30 03 0A 01 01");

	const ldap::sync_request full{
		.mode = ldap::sync_mode::refresh_and_persist, .cookie = "rid=000", .reload_hint = true, .critical = false
	};
	const auto c = ldap::to_control(full);
	REQUIRE(c.has_value());
	CHECK_FALSE(c->criticality);
	CHECK(value_hex(*c) == "30 0F 0A 01 03 04 07 72 69 64 3D 30 30 30 01 01 FF");
	CHECK(ldap::decode_sync_request(*c) == full);
	CHECK(ldap::decode_sync_request(*plain) == ldap::sync_request{});

	// An empty cookie is sent as such, apart from none.
	const auto empty_cookie = ldap::to_control(ldap::sync_request{ .cookie = "" });
	REQUIRE(empty_cookie.has_value());
	CHECK(value_hex(*empty_cookie) == "30 05 0A 01 01 04 00");
	CHECK(ldap::decode_sync_request(*empty_cookie)->cookie == std::optional<std::string>(""));

	// reloadHint FALSE sent explicitly is accepted.
	auto explicit_default = ldap::decode_sync_request(with_value(ldap::sync_request_oid, "30 06 0A 01 01 01 01 00"));
	REQUIRE(explicit_default.has_value());
	CHECK_FALSE(explicit_default->reload_hint);

	SECTION("an unknown mode does not encode")
	{
		auto bad = ldap::to_control(ldap::sync_request{ .mode = static_cast<ldap::sync_mode>(2) });
		REQUIRE_FALSE(bad.has_value());
		CHECK(bad.error().code == ldap::client_errc::encode_error);
	}
	SECTION("malformed values")
	{
		for (const auto *h :
		  { "30 03 0A 01 00", "30 03 0A 01 02", "30 00", "04 00", "30 03 0A 01 01 00", "30 03 02 01 01" }) {
			INFO(h);
			auto r = ldap::decode_sync_request(with_value(ldap::sync_request_oid, h));
			REQUIRE_FALSE(r.has_value());
			CHECK(r.error().context.starts_with("sync request"));
		}
		CHECK_FALSE(ldap::decode_sync_request(ldap::control{ ldap::sync_request_oid }).has_value());
		CHECK_FALSE(ldap::decode_sync_request(with_value(ldap::sync_state_oid, "30 03 0A 01 01")).has_value());
	}
}

TEST_CASE("sync state control", "[content_sync]")
{
	const ldap::sync_state added{ ldap::sync_state_type::add, counting_uuid(), "c" };
	const auto c = ldap::encode_sync_state(added);
	REQUIRE(c.has_value());
	CHECK(c->type == ldap::sync_state_oid);
	CHECK(value_hex(*c) == "30 18 0A 01 01 04 10 " + std::string(counting_uuid_hex) + " 04 01 63");
	CHECK(ldap::decode_sync_state(*c) == added);

	for (auto t : { ldap::sync_state_type::present,
		   ldap::sync_state_type::add,
		   ldap::sync_state_type::modify,
		   ldap::sync_state_type::del }) {
		const ldap::sync_state s{ t, counting_uuid() };
		auto back = ldap::decode_sync_state(ldap::encode_sync_state(s).value());
		REQUIRE(back.has_value());
		CHECK(*back == s);
		CHECK_FALSE(back->cookie.has_value());
	}

	// Unknown trailing elements are skipped.
	auto trailing = ldap::decode_sync_state(
	  with_value(ldap::sync_state_oid, "30 17 0A 01 03 04 10 " + std::string(counting_uuid_hex) + " 05 00"));
	REQUIRE(trailing.has_value());
	CHECK(trailing->state == ldap::sync_state_type::del);

	SECTION("malformed values")
	{
		const std::string uuid(counting_uuid_hex);
		for (const auto &h : { "30 15 0A 01 04 04 10 " + uuid,// state 4
			   "30 14 0A 01 01 04 0F " + uuid.substr(0, uuid.size() - 3),// 15-octet UUID
			   "30 16 0A 01 01 04 11 " + uuid + " 00",// 17-octet UUID
			   std::string("30 03 0A 01 01"),// no entryUUID
			   "30 15 0A 01 01 04 10 " + uuid + " 00",// trailing bytes after the SEQUENCE
			   std::string("") }) {
			INFO(h);
			auto r = ldap::decode_sync_state(with_value(ldap::sync_state_oid, h));
			REQUIRE_FALSE(r.has_value());
			CHECK(r.error().context.starts_with("sync state"));
		}
	}
}

TEST_CASE("sync done control", "[content_sync]")
{
	CHECK(value_hex(ldap::encode_sync_done(ldap::sync_done{}).value()) == "30 00");
	const ldap::sync_done full{ "c", true };
	const auto c = ldap::encode_sync_done(full);
	REQUIRE(c.has_value());
	CHECK(value_hex(*c) == "30 06 04 01 63 01 01 FF");
	CHECK(ldap::decode_sync_done(*c) == full);
	CHECK(ldap::decode_sync_done(with_value(ldap::sync_done_oid, "30 00")) == ldap::sync_done{});
	CHECK(ldap::decode_sync_done(with_value(ldap::sync_done_oid, "30 03 01 01 00")) == ldap::sync_done{});

	for (const auto *h : { "30 03 01 01", "31 00", "30 02 04 05", "30 00 00" }) {
		INFO(h);
		auto r = ldap::decode_sync_done(with_value(ldap::sync_done_oid, h));
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().context.starts_with("sync done"));
	}
}

TEST_CASE("find_sync_state and find_sync_done", "[content_sync]")
{
	std::pmr::vector<ldap::control> none{ ldap::control{ "1.2.3" } };
	CHECK(ldap::find_sync_state(none).value() == std::nullopt);
	CHECK(ldap::find_sync_done(none).value() == std::nullopt);

	const ldap::sync_state s{ ldap::sync_state_type::modify, counting_uuid() };
	std::pmr::vector<ldap::control> some{ ldap::control{ "1.2.3" },
		ldap::encode_sync_state(s).value(),
		ldap::encode_sync_done(ldap::sync_done{ "k" }).value() };
	CHECK(ldap::find_sync_state(some).value() == s);
	CHECK(ldap::find_sync_done(some).value() == ldap::sync_done{ "k" });

	std::pmr::vector<ldap::control> broken{ with_value(ldap::sync_state_oid, "30 00") };
	auto b = ldap::find_sync_state(broken);
	REQUIRE_FALSE(b.has_value());
	CHECK(b.error().code == ldap::client_errc::decode_error);
}

TEST_CASE("sync info message", "[content_sync]")
{
	const auto round_trip = [](const ldap::sync_info &info, std::string_view expected_hex) {
		const auto i = ldap::encode_sync_info(info);
		REQUIRE(i.has_value());
		CHECK(i->response_name == ldap::sync_info_oid);
		REQUIRE(i->response_value.has_value());
		CHECK(hex(std::as_bytes(std::span(*i->response_value))) == expected_hex);
		CHECK(ldap::decode_sync_info(*i) == info);
	};

	SECTION("newcookie [0]")
	{
		round_trip(ldap::sync_info{ ldap::sync_info_type::new_cookie, "c" }, "80 01 63");
		auto no_cookie = ldap::encode_sync_info(ldap::sync_info{ ldap::sync_info_type::new_cookie });
		REQUIRE_FALSE(no_cookie.has_value());
		CHECK(no_cookie.error().code == ldap::client_errc::encode_error);
	}
	SECTION("refreshDelete [1] and refreshPresent [2]: refreshDone DEFAULT TRUE")
	{
		round_trip(ldap::sync_info{ ldap::sync_info_type::refresh_delete }, "A1 00");
		ldap::sync_info present{ ldap::sync_info_type::refresh_present, "c" };
		present.refresh_done = false;
		round_trip(present, "A2 06 04 01 63 01 01 00");
		// TRUE sent explicitly.
		auto explicit_true = ldap::decode_sync_info(info_with("A1 03 01 01 FF"));
		REQUIRE(explicit_true.has_value());
		CHECK(explicit_true->type == ldap::sync_info_type::refresh_delete);
		CHECK(explicit_true->refresh_done);
		CHECK_FALSE(explicit_true->cookie.has_value());
	}
	SECTION("syncIdSet [3]")
	{
		ldap::sync_info set{ ldap::sync_info_type::sync_id_set };
		set.refresh_deletes = true;
		set.sync_uuids = { counting_uuid() };
		round_trip(set, "A3 17 01 01 FF 31 12 04 10 " + std::string(counting_uuid_hex));
		ldap::sync_info empty_set{ ldap::sync_info_type::sync_id_set, "c" };
		round_trip(empty_set, "A3 05 04 01 63 31 00");
	}
	SECTION("malformed values")
	{
		const std::string uuid(counting_uuid_hex);
		for (const auto &h : { std::string("A4 00"),// unknown alternative
			   std::string("04 01 63"),// not context-tagged
			   std::string("A0 01 63"),// newcookie constructed
			   std::string("81 00"),// refreshDelete primitive
			   std::string("80 01 63 00"),// trailing bytes
			   std::string("A3 00"),// syncIdSet without syncUUIDs
			   "A3 13 31 11 04 0F " + uuid.substr(0, uuid.size() - 3),// a 15-octet UUID
			   std::string("A1 03 01 01") }) {
			INFO(h);
			auto r = ldap::decode_sync_info(info_with(h));
			REQUIRE_FALSE(r.has_value());
			CHECK(r.error().context.starts_with("sync info"));
		}
		auto other = ldap::decode_sync_info(ldap::intermediate_response{ "1.2.3", "\x80\x00" });
		REQUIRE_FALSE(other.has_value());
		CHECK(other.error().code == ldap::client_errc::decode_error);
		CHECK_FALSE(ldap::decode_sync_info(ldap::intermediate_response{}).has_value());
		CHECK_FALSE(ldap::decode_sync_info(ldap::intermediate_response{ ldap::sync_info_oid }).has_value());
	}
}

TEST_CASE("sync_uuid prints as RFC 4122 text", "[content_sync]")
{
	CHECK(ldap::to_string(counting_uuid()) == "00010203-0405-0607-0809-0a0b0c0d0e0f");
	CHECK(ldap::to_string(ldap::sync_uuid{}) == "00000000-0000-0000-0000-000000000000");
}

TEST_CASE("sync values decode into the given resource", "[content_sync][pmr]")
{
	jhetz::ldap::test::counting_resource mr;
	const std::pmr::vector<ldap::control> in{
		ldap::encode_sync_state({ ldap::sync_state_type::add, counting_uuid(), std::string(64, 'c') }).value(),
		ldap::encode_sync_done(ldap::sync_done{ std::string(64, 'd') }).value()
	};
	auto s = ldap::find_sync_state(in, &mr);
	REQUIRE(s.has_value());
	REQUIRE(s->has_value());
	CHECK((*s)->get_allocator().resource() == &mr);
	CHECK((*s)->cookie->get_allocator().resource() == &mr);
	auto d = ldap::find_sync_done(in, &mr);
	REQUIRE(d.has_value());
	REQUIRE(d->has_value());
	CHECK((*d)->cookie->get_allocator().resource() == &mr);

	ldap::sync_info set{ ldap::sync_info_type::sync_id_set, std::string(64, 'i') };
	set.sync_uuids = { counting_uuid(), counting_uuid() };
	auto i = ldap::decode_sync_info(ldap::encode_sync_info(set).value(), &mr);
	REQUIRE(i.has_value());
	CHECK(i->get_allocator().resource() == &mr);
	CHECK(i->cookie->get_allocator().resource() == &mr);

	// Allocator-extended copies and assignment keep the target's resource.
	jhetz::ldap::test::counting_resource other;
	const ldap::sync_info copy(*i, &other);
	CHECK(copy == *i);
	CHECK(copy.cookie->get_allocator().resource() == &other);
	ldap::sync_state target{ ldap::sync_state::allocator_type(&other) };
	target = **s;
	CHECK(target == **s);
	CHECK(target.cookie->get_allocator().resource() == &other);
	ldap::sync_done done_target{ ldap::sync_done::allocator_type(&other) };
	done_target = **d;
	CHECK(done_target.cookie->get_allocator().resource() == &other);
}
