#include "jhetz/ldap/message.hpp"
#include "jhetz/ldap/operations.hpp"
#include "jhetz/ldap/testing/server_codec.hpp"
#include "sample_messages.hpp"
#include "test_util.hpp"

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <memory_resource>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace ber = jhetz::ldap::ber;
namespace ldap = jhetz::ldap;
using jhetz::ldap::client_errc;
using jhetz::ldap::test::hex;
using namespace std::string_literals;

namespace {

template<class T> auto code_of(const ldap::result<T> &r) -> std::error_code
{
	REQUIRE_FALSE(r.has_value());
	return r.error().code;
}

auto round_trip(const ldap::message &m) -> ldap::message
{
	auto bytes = ldap::encode(m);
	REQUIRE(bytes.has_value());
	auto size = ber::complete_message_size(*bytes);
	REQUIRE(size.has_value());
	REQUIRE(size->has_value());
	CHECK(**size == bytes->size());
	auto back = ldap::testing::decode(*bytes);
	REQUIRE(back.has_value());
	auto again = ldap::encode(*back);
	REQUIRE(again.has_value());
	CHECK(hex(*again) == hex(*bytes));
	return *back;
}

// LDAPMessage { id, <op built by body>, <extra built by tail> }
template<class Op, class Tail = void (*)(ber::writer &)>
auto raw_message(std::int64_t id, const Op &op, const Tail &tail = [](ber::writer &) {}) -> std::pmr::vector<std::byte>
{
	ber::writer w;
	w.constructed(ber::tags::sequence, [&](ber::writer &m) {
		m.integer(id);
		op(m);
		tail(m);
	});
	return w.take();
}

// A message with a default search request whose fields `edit` changes.
template<class F> auto search_message(F edit, std::int32_t id = 1) -> ldap::message
{
	ldap::search_request s;
	edit(s);
	return { id, std::move(s) };
}

auto search_message(ldap::filter f, std::int32_t id = 1) -> ldap::message
{
	return search_message([&](ldap::search_request &s) { s.filter = std::move(f); }, id);
}

auto raw(std::string_view text) -> ldap::filter { return ldap::filter::parse(text).value(); }

void write_result(ber::writer &o, std::int64_t code = 0)
{
	o.enumerated(code);
	o.octet_string("");
	o.octet_string("");
}

}// namespace

TEST_CASE("every protocolOp round-trips, without and with controls", "[message]")
{
	const auto samples = ldap::test::sample_messages();
	REQUIRE(samples.size() > 40);
	// Every alternative of the variant is covered.
	std::vector<bool> seen(std::variant_size_v<ldap::protocol_op>, false);
	for (const auto &m : samples) {
		seen[m.op.index()] = true;
		INFO("sample id " << m.id << ", op index " << m.op.index());
		CHECK(round_trip(m) == m);
		auto with_controls = m;
		with_controls.controls = ldap::test::sample_controls();
		CHECK(round_trip(with_controls) == with_controls);
	}
	for (std::size_t i = 0; i < seen.size(); ++i) {
		INFO("variant alternative " << i);
		CHECK(seen[i]);
	}
}

TEST_CASE("decoded filters are the same tree", "[message]")
{
	// Written as non-canonical text; the tree holds the unescaped value.
	const auto m = search_message(raw("uid=\\4A\\2A*"));
	auto back = ldap::testing::decode(*ldap::encode(m));
	REQUIRE(back);
	CHECK(*back == m);
	const auto &f = std::get<ldap::search_request>(back->op).filter;
	CHECK(f.to_string() == "(uid=J\\2a*)");
	CHECK(f.root().kind() == ldap::filter::kind::substrings);
	CHECK(f.root().initial() == "J*");
}

TEST_CASE("control criticality is omitted when false", "[message]")
{
	ldap::message m{ 1, ldap::unbind_request{}, { ldap::control{ "1.2" } } };
	auto bytes = ldap::encode(m);
	REQUIRE(bytes);
	CHECK(hex(*bytes) == "30 0E 02 01 01 42 00 A0 07 30 05 04 03 31 2E 32");
	m.controls[0].criticality = true;
	m.controls[0].value = "";
	bytes = ldap::encode(m);
	REQUIRE(bytes);
	CHECK(hex(*bytes) == "30 13 02 01 01 42 00 A0 0C 30 0A 04 03 31 2E 32 01 01 FF 04 00");
	// An explicit FALSE from a peer is accepted.
	auto raw = raw_message(
	  1,
	  [](ber::writer &o) { o.null(ber::application(2)); },
	  [](ber::writer &o) {
		  o.constructed(ber::context(0), [](ber::writer &list) {
			  list.constructed(ber::tags::sequence, [](ber::writer &c) {
				  c.octet_string("1.2");
				  c.boolean(false);
			  });
		  });
	  });
	auto decoded = ldap::testing::decode(raw);
	REQUIRE(decoded);
	REQUIRE(decoded->controls.size() == 1);
	CHECK_FALSE(decoded->controls[0].criticality);
	CHECK_FALSE(decoded->controls[0].value.has_value());
}

TEST_CASE("decode ignores unknown trailing SEQUENCE elements (RFC 4511 section 4)", "[message][extensibility]")
{
	SECTION("in an operation")
	{
		auto raw = raw_message(7, [](ber::writer &m) {
			m.constructed(ber::application(1), [](ber::writer &o) {
				write_result(o, 14);
				o.octet_string("creds", ber::context(7));
				o.octet_string("future", ber::context(30));
				o.constructed(ber::context(29), [](ber::writer &x) { x.integer(5); });
			});
		});
		auto m = ldap::testing::decode(raw);
		REQUIRE(m);
		CHECK(*m == ldap::message{ 7, ldap::bind_response{ ldap::ldap_result{ 14 }, "creds" } });
	}
	SECTION("in LDAPMessage, with and without controls")
	{
		auto no_controls = raw_message(
		  1,
		  [](ber::writer &m) { m.null(ber::application(2)); },
		  [](ber::writer &m) { m.octet_string("x", ber::context(5)); });
		auto decoded = ldap::testing::decode(no_controls);
		REQUIRE(decoded);
		CHECK(decoded->controls.empty());

		auto with_controls = raw_message(
		  1,
		  [](ber::writer &m) { m.null(ber::application(2)); },
		  [](ber::writer &m) {
			  m.constructed(ber::context(0), [](ber::writer &list) {
				  list.constructed(ber::tags::sequence, [](ber::writer &c) {
					  c.octet_string("1.2.3");
					  c.boolean(true);
					  c.octet_string("v");
					  c.integer(99);// unknown trailing element of Control
				  });
			  });
			  m.octet_string("x", ber::context(1));
		  });
		decoded = ldap::testing::decode(with_controls);
		REQUIRE(decoded);
		CHECK(decoded->controls == std::pmr::vector<ldap::control>{ { "1.2.3", true, "v" } });
	}
	SECTION("in a search request and a partial attribute")
	{
		auto raw = raw_message(2, [](ber::writer &m) {
			m.constructed(ber::application(4), [](ber::writer &o) {
				o.octet_string("dc=x");
				o.constructed(ber::tags::sequence, [](ber::writer &list) {
					list.constructed(ber::tags::sequence, [](ber::writer &pa) {
						pa.octet_string("cn");
						pa.constructed(ber::tags::set, [](ber::writer &v) { v.octet_string("a"); });
						pa.boolean(true);
					});
				});
				o.null();
			});
		});
		auto m = ldap::testing::decode(raw);
		REQUIRE(m);
		CHECK(*m == ldap::message{ 2, ldap::search_result_entry{ "dc=x", { { "cn", { "a" } } } } });
	}
	SECTION("optional components are only recognized in their defined order")
	{
		auto raw = raw_message(3, [](ber::writer &m) {
			m.constructed(ber::application(24), [](ber::writer &o) {
				write_result(o);
				o.octet_string("value", ber::context(11));
				o.octet_string("1.2.3", ber::context(10));// out of order: skipped
			});
		});
		auto m = ldap::testing::decode(raw);
		REQUIRE(m);
		const auto &x = std::get<ldap::extended_response>(m->op);
		CHECK_FALSE(x.response_name.has_value());
		CHECK(x.response_value == "value");
	}
}

TEST_CASE("decode rejects unknown operations", "[message][extensibility]")
{
	auto app20 = raw_message(1, [](ber::writer &m) { m.constructed(ber::application(20), [](ber::writer &) {}); });
	CHECK(code_of(ldap::testing::decode(app20)) == client_errc::unsupported_operation);
	auto app30 = raw_message(1, [](ber::writer &m) { m.null(ber::application(30)); });
	CHECK(code_of(ldap::testing::decode(app30)) == client_errc::unsupported_operation);
	auto ctx = raw_message(1, [](ber::writer &m) { m.null(ber::context(2)); });
	CHECK(code_of(ldap::testing::decode(ctx)) == client_errc::unsupported_operation);
	auto universal = raw_message(1, [](ber::writer &m) { m.octet_string("x"); });
	CHECK(code_of(ldap::testing::decode(universal)) == client_errc::unsupported_operation);
	auto missing = raw_message(1, [](ber::writer &) {});
	CHECK(code_of(ldap::testing::decode(missing)) == client_errc::decode_error);

	// Bind authentication choices other than simple and SASL (e.g. the
	// reserved Kerberos ones, or Active Directory's Sicily [9]).
	auto sicily = raw_message(1, [](ber::writer &m) {
		m.constructed(ber::application(0), [](ber::writer &o) {
			o.integer(3);
			o.octet_string("");
			o.octet_string("", ber::context(9));
		});
	});
	auto r = ldap::testing::decode(sicily);
	CHECK(code_of(r) == client_errc::unsupported_operation);
	CHECK(r.error().context == "message: bind authentication choice [CONTEXT 9] at offset 12");
}

TEST_CASE("decode checks enumerations and integer ranges", "[message]")
{
	auto search = [](std::int64_t scope, std::int64_t deref, std::int64_t size_limit) {
		return raw_message(1, [&](ber::writer &m) {
			m.constructed(ber::application(3), [&](ber::writer &o) {
				o.octet_string("");
				o.enumerated(scope);
				o.enumerated(deref);
				o.integer(size_limit);
				o.integer(0);
				o.boolean(false);
				o.octet_string("objectClass", ber::context(7));
				o.constructed(ber::tags::sequence, [](ber::writer &) {});
			});
		});
	};
	CHECK(ldap::testing::decode(search(3, 3, 0)).has_value());
	CHECK(code_of(ldap::testing::decode(search(4, 0, 0))) == client_errc::decode_error);
	CHECK(code_of(ldap::testing::decode(search(-1, 0, 0))) == client_errc::decode_error);
	CHECK(code_of(ldap::testing::decode(search(0, 4, 0))) == client_errc::decode_error);
	CHECK(code_of(ldap::testing::decode(search(0, 0, -1))) == client_errc::decode_error);
	CHECK(code_of(ldap::testing::decode(search(0, 0, 0x8000'0000LL))) == client_errc::decode_error);

	auto modify = [](std::int64_t op) {
		return raw_message(1, [&](ber::writer &m) {
			m.constructed(ber::application(6), [&](ber::writer &o) {
				o.octet_string("dc=x");
				o.constructed(ber::tags::sequence, [&](ber::writer &changes) {
					changes.constructed(ber::tags::sequence, [&](ber::writer &c) {
						c.enumerated(op);
						c.constructed(ber::tags::sequence, [](ber::writer &pa) {
							pa.octet_string("cn");
							pa.constructed(ber::tags::set, [](ber::writer &) {});
						});
					});
				});
			});
		});
	};
	CHECK(ldap::testing::decode(modify(3)).has_value());
	auto bad_op = ldap::testing::decode(modify(4));
	CHECK(code_of(bad_op) == client_errc::decode_error);
	CHECK(bad_op.error().context.contains("modify operation 4"));

	auto bind = [](std::int64_t version) {
		return raw_message(1, [&](ber::writer &m) {
			m.constructed(ber::application(0), [&](ber::writer &o) {
				o.integer(version);
				o.octet_string("");
				o.octet_string("", ber::context(0));
			});
		});
	};
	CHECK(ldap::testing::decode(bind(1)).has_value());
	CHECK(code_of(ldap::testing::decode(bind(0))) == client_errc::decode_error);
	CHECK(code_of(ldap::testing::decode(bind(128))) == client_errc::decode_error);

	auto unbind_with_id = [](std::int64_t id) {
		return raw_message(id, [](ber::writer &m) { m.null(ber::application(2)); });
	};
	CHECK(code_of(ldap::testing::decode(unbind_with_id(0))) == client_errc::decode_error);// reserved, RFC 4511 4.1.1
	CHECK(ldap::testing::decode(unbind_with_id(1)).has_value());
	CHECK(ldap::testing::decode(unbind_with_id(ldap::max_int)).has_value());
	CHECK(code_of(ldap::testing::decode(unbind_with_id(-1))) == client_errc::decode_error);
	CHECK(code_of(ldap::testing::decode(unbind_with_id(0x8000'0000LL))) == client_errc::decode_error);

	auto abandon = [](std::int64_t id) {
		return raw_message(1, [&](ber::writer &m) { m.integer(id, ber::application(16)); });
	};
	CHECK(code_of(ldap::testing::decode(abandon(-5))) == client_errc::decode_error);

	// Unknown result codes are kept.
	auto done = raw_message(
	  1, [](ber::writer &m) { m.constructed(ber::application(5), [](ber::writer &o) { write_result(o, 4711); }); });
	auto decoded = ldap::testing::decode(done);
	REQUIRE(decoded);
	CHECK(std::get<ldap::search_result_done>(decoded->op).result.result_code == 4711);
	auto huge = raw_message(1, [](ber::writer &m) {
		m.constructed(ber::application(5), [](ber::writer &o) { write_result(o, 0x1'0000'0000LL); });
	});
	CHECK(code_of(ldap::testing::decode(huge)) == client_errc::decode_error);
}

TEST_CASE("decode rejects malformed messages", "[message]")
{
	const auto samples = ldap::test::sample_messages();

	SECTION("trailing bytes")
	{
		auto bytes = *ldap::encode(samples.front());
		bytes.push_back(std::byte{ 0 });
		CHECK(code_of(ldap::testing::decode(bytes)) == client_errc::decode_error);
		auto twice = *ldap::encode(samples.front());
		twice.insert(twice.end(), twice.begin(), twice.end());
		CHECK(code_of(ldap::testing::decode(twice)) == client_errc::decode_error);
	}
	SECTION("every truncation of every sample")
	{
		for (auto m : samples) {
			m.controls = ldap::test::sample_controls();
			const auto bytes = *ldap::encode(m);
			for (std::size_t n = 0; n < bytes.size(); ++n) {
				INFO("sample " << m.id << " truncated to " << n);
				CHECK_FALSE(ldap::testing::decode(std::span(bytes).first(n)).has_value());
			}
		}
	}
	SECTION("wrong primitive/constructed form")
	{
		auto primitive_bind = raw_message(1, [](ber::writer &m) { m.octet_string("", ber::application(0)); });
		CHECK(code_of(ldap::testing::decode(primitive_bind)) == client_errc::unexpected_tag);
		auto constructed_unbind =
		  raw_message(1, [](ber::writer &m) { m.constructed(ber::application(2), [](ber::writer &) {}); });
		CHECK(code_of(ldap::testing::decode(constructed_unbind)) == client_errc::unexpected_tag);
	}
	SECTION("filters that have no RFC 4515 text")
	{
		auto raw = raw_message(1, [](ber::writer &m) {
			m.constructed(ber::application(3), [](ber::writer &o) {
				o.octet_string("");
				o.enumerated(0);
				o.enumerated(0);
				o.integer(0);
				o.integer(0);
				o.boolean(false);
				o.octet_string("bad attr", ber::context(7));
				o.constructed(ber::tags::sequence, [](ber::writer &) {});
			});
		});
		CHECK(code_of(ldap::testing::decode(raw)) == client_errc::decode_error);
	}
	SECTION("nesting beyond the reader's limit")
	{
		std::vector<std::byte> deep{ std::byte{ 0x05 }, std::byte{ 0x00 } };
		for (int i = 0; i < 40; ++i) {
			deep.insert(deep.begin(), { std::byte{ 0x30 }, static_cast<std::byte>(deep.size()) });
		}
		CHECK_FALSE(ldap::testing::decode(deep).has_value());
	}
}

TEST_CASE("a search request with the deepest allowed filter decodes", "[message]")
{
	// depth max_filter_depth: (&(&...(cn=a*b*c)...)) with a substrings leaf.
	std::string text;
	for (std::size_t i = 1; i < ldap::max_filter_depth; ++i) {
		text += "(&";
	}
	text += "(cn=a*b*c)";
	for (std::size_t i = 1; i < ldap::max_filter_depth; ++i) {
		text += ')';
	}
	const auto m = search_message(raw(text));
	CHECK(round_trip(m) == m);

	// One more level: rejected by raw(), and by encode() when built.
	CHECK(code_of(ldap::filter::parse("(!" + text + ")")) == client_errc::invalid_filter);
	const auto deeper = search_message(!raw(text));
	CHECK(std::get<ldap::search_request>(deeper.op).filter.depth() == ldap::max_filter_depth + 1);
	auto r = ldap::encode(deeper);
	CHECK(code_of(r) == client_errc::invalid_filter);
	CHECK(r.error().context == "filter: nested too deeply (25 levels, at most 24)");
}

TEST_CASE("encode rejects values the wire format cannot carry", "[message]")
{
	auto encode_error = [](const ldap::message &m) {
		auto r = ldap::encode(m);
		REQUIRE_FALSE(r);
		return r.error().code == client_errc::encode_error;
	};
	CHECK(encode_error({ -1, ldap::unbind_request{} }));
	CHECK(encode_error({ 1, ldap::bind_request{ 0 } }));
	CHECK(encode_error({ 1, ldap::bind_request{ 128 } }));
	CHECK(encode_error(search_message([](ldap::search_request &s) { s.size_limit = -1; })));
	CHECK(encode_error(search_message([](ldap::search_request &s) { s.time_limit = -1; })));
	CHECK(encode_error(search_message([](ldap::search_request &s) { s.scope = static_cast<ldap::search_scope>(9); })));
	CHECK(
	  encode_error(search_message([](ldap::search_request &s) { s.deref = static_cast<ldap::deref_aliases>(-1); })));
	CHECK(encode_error({ 1, ldap::abandon_request{ -1 } }));
	CHECK(
	  encode_error({ 1, ldap::modify_request{ "", { { static_cast<ldap::modify_operation>(4), { "cn", {} } } } } }));

	// Malformed filter text fails where it is parsed, not when encoding.
	auto bad_text = ldap::filter::parse("(cn=x");
	CHECK(code_of(bad_text) == client_errc::invalid_filter);
	CHECK(bad_text.error().context == "filter: unexpected end of filter at position 5");
	// The only filter encode() rejects besides over-limit ones: an empty one.
	auto empty = ldap::encode(search_message(ldap::filter{}));
	CHECK(code_of(empty) == client_errc::invalid_filter);
	CHECK(empty.error().context == "filter: empty");

	// Nothing is written on failure.
	ber::writer w;
	w.integer(1);
	const auto before = hex(w.bytes());
	CHECK_FALSE(ldap::encode(w, { -1, ldap::unbind_request{} }));
	CHECK_FALSE(ldap::encode(w, search_message(ldap::filter{})));
	CHECK(hex(w.bytes()) == before);
}

TEST_CASE("ldap_result::to_error", "[message][error]")
{
	SECTION("known code, matched DN, diagnostic, referrals")
	{
		const auto r = ldap::test::sample_result();
		CHECK_FALSE(r.is_success());
		CHECK(r.code() == ldap::errc::no_such_object);
		const auto e = r.to_error("search ou=people");
		CHECK(e.code == ldap::errc::no_such_object);
		CHECK(e.diagnostic_message == "no such entry");
		CHECK(e.matched_dn == "dc=example,dc=org");
		CHECK(e.referrals == ldap::string_list{ "ldap://a.example.org/", "ldap://b.example.org/" });
		CHECK(e.context == "search ou=people");
		CHECK(e.message()
		  == "search ou=people: no such object [ldap.result:32]; server: no such entry; matched DN: dc=example,dc=org; "
			 "referrals: ldap://a.example.org/ ldap://b.example.org/");
	}
	SECTION("unknown code")
	{
		const ldap::ldap_result r{ 4711 };
		const auto e = r.to_error();
		CHECK(e.code.value() == 4711);
		CHECK(r.code() == e.code);
		CHECK_FALSE(ldap::ldap_result{ 0 }.code());
		CHECK(&e.code.category() == &ldap::result_category());
		CHECK(e.matched_dn.empty());
		CHECK(e.message() == "unknown LDAP result code 4711 [ldap.result:4711]");
	}
	SECTION("referral and compare results")
	{
		CHECK(ldap::ldap_result{ 10 }.to_error().code == ldap::errc::referral);
		CHECK(ldap::ldap_result{ 6 }.to_error().code == ldap::errc::compare_true);
	}
	SECTION("success")
	{
		const ldap::ldap_result ok{};
		CHECK(ok.is_success());
		CHECK_FALSE(ok.to_error().code);// value 0: "no error"
	}
}

TEST_CASE("paged results control", "[message][control]")
{
	const ldap::paged_results p{ 250, "\0\x01\xff"s };
	const auto c = ldap::encode_paged_results(p, true).value();
	CHECK(c.type == ldap::paged_results_oid);
	CHECK(c.criticality);
	REQUIRE(c.value);
	CHECK(hex(ldap::test::bytes_of(*c.value)) == "30 09 02 02 00 FA 04 03 00 01 FF");
	CHECK(ldap::decode_paged_results(c) == p);
	CHECK_FALSE(ldap::encode_paged_results({})->criticality);
	CHECK(ldap::decode_paged_results(*ldap::encode_paged_results({})) == ldap::paged_results{});
	CHECK(code_of(ldap::encode_paged_results(ldap::paged_results{ -1 })) == client_errc::encode_error);

	auto value_of = [](auto body) {
		ber::writer w;
		body(w);
		const auto &b = w.bytes();
		return ldap::control{ ldap::paged_results_oid, false, ldap::detail::as_text(b) };
	};
	CHECK(code_of(ldap::decode_paged_results({ "1.2.3", false, c.value })) == client_errc::decode_error);
	CHECK(code_of(ldap::decode_paged_results(ldap::control{ ldap::paged_results_oid })) == client_errc::decode_error);
	CHECK_FALSE(ldap::decode_paged_results(value_of([](ber::writer &w) { w.integer(5); })));
	CHECK_FALSE(ldap::decode_paged_results(value_of([](ber::writer &w) {
		w.constructed(ber::tags::sequence, [](ber::writer &s) {
			s.integer(-1);
			s.octet_string("");
		});
	})));
	CHECK_FALSE(ldap::decode_paged_results(value_of([](ber::writer &w) {
		w.constructed(ber::tags::sequence, [](ber::writer &s) {
			s.integer(1);
			s.octet_string("");
		});
		w.null();// trailing bytes
	})));
	// Unknown trailing SEQUENCE elements are skipped.
	auto extended = ldap::decode_paged_results(value_of([](ber::writer &w) {
		w.constructed(ber::tags::sequence, [](ber::writer &s) {
			s.integer(7);
			s.octet_string("k");
			s.boolean(true);
		});
	}));
	CHECK(extended == ldap::paged_results{ 7, "k" });
}

TEST_CASE("decode(encode(m)) == m exactly and encode(decode(encode(m))) == encode(m)", "[message]")
{
	// Filters written as non-canonical text included: the tree does not
	// depend on the spelling, so nothing is canonicalized on the way.
	std::vector<ldap::message> all = ldap::test::sample_messages();
	for (const char *text : { "cn=x", "(cn=\\41)", "(cn=\\2A)", "(A:DN:=v)", "(a=b**c)" }) {
		all.push_back(search_message(raw(text), 9));
	}
	for (const auto &m : all) {
		INFO("sample id " << m.id << ", op index " << m.op.index());
		auto first = ldap::encode(m);
		REQUIRE(first);
		auto decoded = ldap::testing::decode(*first);
		REQUIRE(decoded);
		CHECK(*decoded == m);
		auto second = ldap::encode(*decoded);
		REQUIRE(second);
		CHECK(hex(*second) == hex(*first));
	}
	// Only the log text is canonical, and equal spellings give equal trees.
	auto canonical = [](const char *text) { return std::string(raw(text).to_string()); };
	CHECK(canonical("cn=x") == "(cn=x)");
	CHECK(canonical("(cn=\\41)") == "(cn=A)");
	CHECK(canonical("(cn=\\2A)") == "(cn=\\2a)");
	CHECK(canonical("(A:DN:=v)") == "(A:dn:=v)");
	CHECK(canonical("(a=b**c)") == "(a=b*c)");
	CHECK(raw("cn=x") == raw("(cn=x)"));
	CHECK(raw("(cn=\\41)") == raw("(cn=A)"));
	CHECK(raw("(A:DN:=v)") == raw("(A:dn:=v)"));
	CHECK(raw("(a=b**c)") == raw("(a=b*c)"));
}

TEST_CASE("decode_options::from rejects operations the peer may not send", "[message][options]")
{
	for (const auto &m : ldap::test::sample_messages()) {
		const auto bytes = *ldap::encode(m);
		const bool request =
		  std::holds_alternative<ldap::bind_request>(m.op) || std::holds_alternative<ldap::unbind_request>(m.op)
		  || std::holds_alternative<ldap::search_request>(m.op) || std::holds_alternative<ldap::modify_request>(m.op)
		  || std::holds_alternative<ldap::add_request>(m.op) || std::holds_alternative<ldap::del_request>(m.op)
		  || std::holds_alternative<ldap::modify_dn_request>(m.op)
		  || std::holds_alternative<ldap::compare_request>(m.op) || std::holds_alternative<ldap::abandon_request>(m.op)
		  || std::holds_alternative<ldap::extended_request>(m.op);
		INFO("sample id " << m.id << ", op index " << m.op.index());
		CHECK(ldap::testing::decode(bytes, { .from = ldap::testing::origin::any }) == m);
		auto from_server = ldap::decode(bytes);
		auto from_client = ldap::testing::decode(bytes, { .from = ldap::testing::origin::client });
		if (request) {
			CHECK(code_of(from_server) == client_errc::unsupported_operation);
			CHECK(from_client == m);
		} else {
			CHECK(from_server == m);
			CHECK(code_of(from_client) == client_errc::unsupported_operation);
		}
	}
}

TEST_CASE("decode_options limits", "[message][options]")
{
	const auto m = search_message(raw("(&(a=*)(b=*)(c=*))"));
	const auto bytes = *ldap::encode(m);
	CHECK(ldap::testing::decode(bytes).has_value());
	CHECK(code_of(ldap::testing::decode(bytes, { .filter = { .max_elements = 3 } })) == client_errc::decode_error);
	CHECK(code_of(ldap::testing::decode(bytes, { .filter = { .max_depth = 1 } })) == client_errc::nesting_too_deep);
	// Reader depth: LDAPMessage, SearchRequest and the AND need 3 levels.
	CHECK(ldap::testing::decode(bytes, { .max_depth = 3 }).has_value());
	CHECK(code_of(ldap::testing::decode(bytes, { .max_depth = 2 })) == client_errc::nesting_too_deep);
}

TEST_CASE("regression: a huge AND filter in a search request fails fast", "[message][options]")
{
	// A SearchRequest whose filter is an AND of about 350 000 (a=*): decoding
	// stops at element 10,001.
	constexpr std::size_t children = 350'000;
	auto bytes = raw_message(1, [&](ber::writer &m) {
		m.constructed(ber::application(3), [&](ber::writer &o) {
			o.octet_string("");
			o.enumerated(0);
			o.enumerated(0);
			o.integer(0);
			o.integer(0);
			o.boolean(false);
			o.constructed(ber::context(0), [&](ber::writer &a) {
				for (std::size_t i = 0; i < children; ++i) {
					a.octet_string("a", ber::context(7));
				}
			});
			o.constructed(ber::tags::sequence, [](ber::writer &) {});
		});
	});
	REQUIRE(bytes.size() > 1'000'000);
	auto r = ldap::testing::decode(bytes);
	REQUIRE_FALSE(r);
	CHECK(r.error().code == client_errc::decode_error);
	CHECK(r.error().context.contains("more than 10000 filter elements"));
	// ldap::decode (a client) does not look at the filter at all.
	CHECK(code_of(ldap::decode(bytes)) == client_errc::unsupported_operation);
}

TEST_CASE("regression: invalid list elements do not drive the reserve size", "[message][options]")
{
	// Many invalid elements decoded into a small arena: decode_error, not
	// bad_alloc.
	constexpr std::size_t count = 200'000;
	auto entry_with = [&](bool bad_attributes) {
		return raw_message(1, [&](ber::writer &m) {
			m.constructed(ber::application(4), [&](ber::writer &o) {
				o.octet_string("cn=x");
				o.constructed(ber::tags::sequence, [&](ber::writer &list) {
					if (bad_attributes) {
						for (std::size_t i = 0; i < count; ++i) {
							list.constructed(ber::tags::sequence, [](ber::writer &) {});
						}
						return;
					}
					list.constructed(ber::tags::sequence, [&](ber::writer &pa) {
						pa.octet_string("cn");
						pa.constructed(ber::tags::set, [&](ber::writer &vals) {
							for (std::size_t i = 0; i < count; ++i) {
								vals.null();
							}
						});
					});
				});
			});
		});
	};
	for (bool bad_attributes : { true, false }) {
		const auto bytes = entry_with(bad_attributes);
		// Far less than count * sizeof(element): a reserve sized by the
		// invalid elements would exhaust it and throw.
		std::vector<std::byte> buffer(64uz * 1024);
		std::pmr::monotonic_buffer_resource arena(buffer.data(), buffer.size(), std::pmr::null_memory_resource());
		ldap::result<ldap::message> r = std::unexpected(ldap::error{});
		REQUIRE_NOTHROW(r = ldap::decode(bytes, { .memory = &arena }));
		REQUIRE_FALSE(r);
		CHECK(r.error().code.category() == ldap::make_error_code(client_errc::decode_error).category());
	}
}

TEST_CASE("decode_options::max_elements bounds the strings of one message", "[message][options]")
{
	// Object name, one type, three values: 5 strings.
	ldap::search_result_entry e;
	e.object_name = "cn=x";
	e.attributes.push_back({ "cn", { "a", "b", "c" } });
	const auto entry = *ldap::encode(ldap::message{ 1, e });
	CHECK(ldap::testing::decode(entry, { .max_elements = 5 }).has_value());
	const auto over = ldap::testing::decode(entry, { .max_elements = 4 });
	REQUIRE_FALSE(over);
	CHECK(over.error().code == client_errc::message_too_large);
	CHECK(over.error().context.starts_with("message: more than 4 elements at offset "));
	// Referral URIs and control OIDs count too.
	ldap::search_result_done done{ { 10, "", "", { "ldap://a/", "ldap://b/" } } };
	const auto referral = *ldap::encode(ldap::message{ 2, done, { ldap::control{ "1.2.3" } } });
	CHECK(ldap::testing::decode(referral, { .max_elements = 5 }).has_value());
	CHECK(code_of(ldap::testing::decode(referral, { .max_elements = 4 })) == client_errc::message_too_large);
}

TEST_CASE("regression: many tiny values cannot multiply a message's size in memory", "[message][options]")
{
	// `count` empty values, or attributes: decoding stops at max_elements,
	// and so does the reserve.
	constexpr std::size_t count = 300'000;
	auto entry_with = [&](bool many_attributes) {
		return raw_message(1, [&](ber::writer &m) {
			m.constructed(ber::application(4), [&](ber::writer &o) {
				o.octet_string("cn=x");
				o.constructed(ber::tags::sequence, [&](ber::writer &list) {
					if (many_attributes) {
						for (std::size_t i = 0; i < count; ++i) {
							list.constructed(ber::tags::sequence, [](ber::writer &pa) {
								pa.octet_string("");
								pa.constructed(ber::tags::set, [](ber::writer &) {});
							});
						}
						return;
					}
					list.constructed(ber::tags::sequence, [&](ber::writer &pa) {
						pa.octet_string("cn");
						pa.constructed(ber::tags::set, [&](ber::writer &vals) {
							for (std::size_t i = 0; i < count; ++i) {
								vals.octet_string("");
							}
						});
					});
				});
			});
		});
	};
	for (bool many_attributes : { false, true }) {
		const auto bytes = entry_with(many_attributes);
		// Under the default limit it decodes.
		CHECK(ldap::testing::decode(bytes).has_value());
		std::vector<std::byte> buffer(256uz * 1024);
		std::pmr::monotonic_buffer_resource arena(buffer.data(), buffer.size(), std::pmr::null_memory_resource());
		ldap::result<ldap::message> r = std::unexpected(ldap::error{});
		REQUIRE_NOTHROW(r = ldap::decode(bytes, { .max_elements = 1000, .memory = &arena }));
		REQUIRE_FALSE(r);
		CHECK(r.error().code == client_errc::message_too_large);
	}
}

TEST_CASE("partial_attribute and ldap::mod take ranges of values", "[message]")
{
	const std::vector<std::string> mails{ "a@example.org", "b\xc3\xa9@example.org" };
	const ldap::partial_attribute expected{ "mail", { "a@example.org", "b\xc3\xa9@example.org" } };
	CHECK(ldap::partial_attribute("mail", mails) == expected);
	CHECK(ldap::partial_attribute("mail", std::vector<std::string>(mails)) == expected);
	const std::array<std::string_view, 2> views{ "a@example.org", "b\xc3\xa9@example.org" };
	CHECK(ldap::partial_attribute("mail", views) == expected);
	CHECK(ldap::partial_attribute("mail", std::vector<std::string>{}).values.empty());

	std::pmr::monotonic_buffer_resource mr;
	const ldap::partial_attribute on_mr("mail", mails, &mr);
	CHECK(on_mr.get_allocator().resource() == &mr);
	CHECK(on_mr.values.front().get_allocator().resource() == &mr);

	CHECK(ldap::mod::add("mail", mails) == ldap::modify_change{ ldap::modify_operation::add, expected });
	CHECK(ldap::mod::remove("mail", views) == ldap::modify_change{ ldap::modify_operation::delete_, expected });
	CHECK(ldap::mod::replace("mail", mails) == ldap::modify_change{ ldap::modify_operation::replace, expected });
	CHECK(ldap::mod::add("mail", { "a@example.org", "b\xc3\xa9@example.org" }) == ldap::mod::add("mail", mails));
	CHECK(ldap::mod::remove("mail").modification.values.empty());
}

TEST_CASE("add and modify-add values must not be empty", "[message]")
{
	const ldap::message empty_add{ 1, ldap::add_request{ "cn=x", { { "cn", { "x" } }, { "sn", {} } } } };
	CHECK(code_of(ldap::encode(empty_add)) == client_errc::encode_error);
	const ldap::message empty_mod_add{ 1,
		ldap::modify_request{ "cn=x", { { ldap::modify_operation::add, { "mail", {} } } } } };
	CHECK(code_of(ldap::encode(empty_mod_add)) == client_errc::encode_error);
	// delete / replace without values: delete or clear the whole attribute.
	for (auto op : { ldap::modify_operation::delete_, ldap::modify_operation::replace }) {
		const ldap::message ok{ 1, ldap::modify_request{ "cn=x", { { op, { "mail", {} } } } } };
		CHECK(round_trip(ok) == ok);
	}

	// The decoder rejects them too, so decode never accepts what encode refuses.
	auto add_bytes = raw_message(1, [](ber::writer &m) {
		m.constructed(ber::application(8), [](ber::writer &o) {
			o.octet_string("cn=x");
			o.constructed(ber::tags::sequence, [](ber::writer &list) {
				list.constructed(ber::tags::sequence, [](ber::writer &pa) {
					pa.octet_string("sn");
					pa.constructed(ber::tags::set, [](ber::writer &) {});
				});
			});
		});
	});
	CHECK(code_of(ldap::testing::decode(add_bytes)) == client_errc::decode_error);
	auto mod_bytes = raw_message(1, [](ber::writer &m) {
		m.constructed(ber::application(6), [](ber::writer &o) {
			o.octet_string("cn=x");
			o.constructed(ber::tags::sequence, [](ber::writer &changes) {
				changes.constructed(ber::tags::sequence, [](ber::writer &c) {
					c.enumerated(0);
					c.constructed(ber::tags::sequence, [](ber::writer &pa) {
						pa.octet_string("mail");
						pa.constructed(ber::tags::set, [](ber::writer &) {});
					});
				});
			});
		});
	});
	CHECK(code_of(ldap::testing::decode(mod_bytes)) == client_errc::decode_error);
}

TEST_CASE("decode errors show the peer's attribute and control type sanitized", "[message]")
{
	const std::string fffd = "\xEF\xBF\xBD";// U+FFFD
	const auto add_context = [](const std::string &type) {
		auto bytes = raw_message(1, [&](ber::writer &m) {
			m.constructed(ber::application(8), [&](ber::writer &o) {
				o.octet_string("cn=x");
				o.constructed(ber::tags::sequence, [&](ber::writer &list) {
					list.constructed(ber::tags::sequence, [&](ber::writer &pa) {
						pa.octet_string(type);
						pa.constructed(ber::tags::set, [](ber::writer &) {});
					});
				});
			});
		});
		auto r = ldap::testing::decode(bytes);
		REQUIRE_FALSE(r);
		return std::string(r.error().context);
	};
	// Valid non-ASCII UTF-8 is kept; CR LF, ESC and bidi controls are not.
	CHECK(add_context("n\xC3\xA9\xE6\x97\xA5\r\nx\x1B\xE2\x80\xAE")
		.starts_with("message: add request attribute 'n\xC3\xA9\xE6\x97\xA5" + fffd + fffd + "x" + fffd + fffd
					 + "' without values at offset "));
	// Cut at 64 bytes.
	CHECK(add_context(std::string(1000, 'a'))
		.starts_with("message: add request attribute '" + std::string(64, 'a') + "...' without values at offset "));

	const std::string paged =
	  std::string(ldap::decode_paged_results({ "1.2.3\r\n\xC3\xA9", false, "" }).error().context);
	CHECK(paged
		  == "paged results: control type is 1.2.3" + fffd + fffd + "\xC3\xA9, not "
			   + std::string(ldap::paged_results_oid));
}

TEST_CASE("peek_message_header reads the id and the operation tag only", "[message]")
{
	const auto bytes = ldap::encode(ldap::message{ 4711, ldap::search_result_done{ ldap::ldap_result{ 0 } } }).value();
	auto h = ldap::peek_message_header(bytes);
	REQUIRE(h.has_value());
	CHECK(h->id == 4711);
	CHECK(h->op == ldap::ber::application(5, true));

	const auto entry = ldap::encode(
	  ldap::message{ 1, ldap::search_result_entry{ "cn=x", { ldap::partial_attribute{ "cn", { "x" } } } } })
						 .value();
	CHECK(ldap::peek_message_header(entry)->op == ldap::ber::application(4, true));

	// Only the header is checked: a body decode() would reject still peeks.
	auto broken = bytes;
	broken.back() = std::byte{ 0xFF };
	CHECK(ldap::peek_message_header(broken).has_value());

	// Not a SEQUENCE, a negative id, no protocolOp, truncated.
	const std::byte not_seq[] = { std::byte{ 0x04 }, std::byte{ 0x00 } };
	CHECK_FALSE(ldap::peek_message_header(not_seq).has_value());
	const std::byte negative[] = {
		std::byte{ 0x30 }, std::byte{ 0x03 }, std::byte{ 0x02 }, std::byte{ 0x01 }, std::byte{ 0xFF }
	};
	CHECK_FALSE(ldap::peek_message_header(negative).has_value());
	const std::byte no_op[] = {
		std::byte{ 0x30 }, std::byte{ 0x03 }, std::byte{ 0x02 }, std::byte{ 0x01 }, std::byte{ 0x01 }
	};
	auto missing = ldap::peek_message_header(no_op);
	REQUIRE_FALSE(missing.has_value());
	CHECK(missing.error().code == ldap::client_errc::decode_error);
	CHECK_FALSE(ldap::peek_message_header(std::span(bytes).first(3)).has_value());
}

// ---------------------------------------------------------------- RFC conformance

// RFC 4511 section 4.1.1: "The messageID of a request MUST have a non-zero
// value"; zero is reserved for unsolicited notifications.
TEST_CASE("RFC 4511 4.1.1: requests never carry message id 0", "[message][rfc]")
{
	CHECK(code_of(ldap::encode(ldap::message{ 0, ldap::del_request{ "cn=x" } })) == client_errc::encode_error);
	CHECK(code_of(ldap::encode(ldap::message{ 0, ldap::unbind_request{} })) == client_errc::encode_error);
	auto del = raw_message(0, [](ber::writer &m) { m.octet_string("cn=x", ber::application(10)); });
	CHECK(code_of(ldap::testing::decode(del, { .from = ldap::testing::origin::client })) == client_errc::decode_error);
	CHECK(code_of(ldap::testing::decode(del)) == client_errc::decode_error);
	// Responses may: an unsolicited notification is an ExtendedResponse with id 0.
	const ldap::message notice{ 0, ldap::extended_response{ {}, ldap::notice_of_disconnection_oid } };
	CHECK(round_trip(notice) == notice);
}

TEST_CASE("RFC 4511 4.5.3: a SearchResultReference carries at least one URI", "[message][rfc]")
{
	auto empty = raw_message(2, [](ber::writer &m) { m.constructed(ber::application(19), [](ber::writer &) {}); });
	auto r = ldap::testing::decode(empty);
	CHECK(code_of(r) == client_errc::decode_error);
	CHECK(r.error().context.starts_with("message: search result reference without a URI at offset "));
	CHECK(code_of(ldap::encode(ldap::message{ 2, ldap::search_result_reference{} })) == client_errc::encode_error);
	const ldap::message one{ 2, ldap::search_result_reference{ { "ldap://a.example.org/" } } };
	CHECK(round_trip(one) == one);
}

TEST_CASE("encode of a valueless op with message id 0 throws", "[message]")
{
	struct throwing
	{
		[[noreturn]] explicit operator ldap::del_request() const { throw std::runtime_error("no del_request"); }
	};
	ldap::message m{ 0, ldap::unbind_request{} };
	CHECK_THROWS_AS(m.op.emplace<ldap::del_request>(throwing{}), std::runtime_error);
	REQUIRE(m.op.valueless_by_exception());
	CHECK_THROWS_AS(ldap::encode(m), std::bad_variant_access);
}

// ---------------------------------------------------------------- transactions (RFC 5805)

TEST_CASE("End Transaction request value (RFC 5805 section 2.3)", "[message][transaction]")
{
	const auto hex_of = [](const std::pmr::string &s) { return hex(ldap::test::bytes_of(s)); };
	// commit DEFAULT TRUE is left out; FALSE is written.
	CHECK(hex_of(ldap::encode_end_transaction_request({ true, "tx1" })) == "30 05 04 03 74 78 31");
	CHECK(hex_of(ldap::encode_end_transaction_request({ false, "tx1" })) == "30 08 01 01 00 04 03 74 78 31");

	const auto decoded = [](std::string_view hex_value) {
		const auto b = ldap::test::from_hex(hex_value);
		return ldap::testing::decode_end_transaction_request(ldap::detail::as_text(b));
	};
	CHECK(decoded("30 05 04 03 74 78 31") == ldap::end_transaction_request{ true, "tx1" });
	CHECK(decoded("30 08 01 01 FF 04 03 74 78 31") == ldap::end_transaction_request{ true, "tx1" });
	CHECK(decoded("30 08 01 01 00 04 03 74 78 31") == ldap::end_transaction_request{ false, "tx1" });
	// Unknown trailing elements are skipped; an empty identifier is kept.
	CHECK(decoded("30 04 04 00 05 00") == ldap::end_transaction_request{ true, "" });
	// No identifier, trailing bytes, not a SEQUENCE.
	CHECK(code_of(decoded("30 03 01 01 00")) == client_errc::decode_error);
	CHECK(code_of(decoded("30 02 04 00 00")) == client_errc::decode_error);
	CHECK(code_of(decoded("04 00")) == client_errc::unexpected_tag);
	CHECK(decoded("30 03 01 01 00").error().context.starts_with("txnEndReq: "));
}

TEST_CASE("End Transaction update_result value (RFC 5805 section 2.3)", "[message][transaction]")
{
	const auto hex_of = [](const ldap::result<std::optional<std::pmr::string>> &s) {
		REQUIRE(s.has_value());
		REQUIRE(s->has_value());
		return hex(ldap::test::bytes_of(**s));
	};
	// Both fields absent: no responseValue at all.
	const auto none = ldap::testing::encode_end_transaction_response({});
	REQUIRE(none.has_value());
	CHECK_FALSE(none->has_value());
	CHECK(
	  hex_of(ldap::testing::encode_end_transaction_response(ldap::end_transaction_response{ 5 })) == "30 03 02 01 05");
	const ldap::end_transaction_response full{ 5,
		{ ldap::update_controls{ 3, { ldap::control{ ldap::post_read_oid, false, "x" } } } } };
	constexpr std::string_view full_hex =
	  "30 21 02 01 05 30 1C 30 1A 02 01 03 30 15 30 13 04 0E 31 2E 33 2E 36 2E 31 2E 31 2E 31 33 2E 32 04 01 78";
	CHECK(hex_of(ldap::testing::encode_end_transaction_response(full)) == full_hex);
	CHECK(code_of(ldap::testing::encode_end_transaction_response(ldap::end_transaction_response{ -1 }))
		  == client_errc::encode_error);
	CHECK(code_of(ldap::testing::encode_end_transaction_response({ std::nullopt, { ldap::update_controls{ -2 } } }))
		  == client_errc::encode_error);

	const auto decoded = [](std::string_view hex_value, const ldap::decode_options &options = {}) {
		const auto b = ldap::test::from_hex(hex_value);
		return ldap::decode_end_transaction_response(ldap::detail::as_text(b), options);
	};
	CHECK(decoded(full_hex) == full);
	CHECK(decoded("30 03 02 01 05") == ldap::end_transaction_response{ 5 });
	CHECK(decoded("30 00") == ldap::end_transaction_response{});
	// updatesControls without a messageID; an empty Controls list.
	CHECK(decoded("30 09 30 07 30 05 02 01 07 30 00")
		  == ldap::end_transaction_response{ std::nullopt, { ldap::update_controls{ 7 } } });
	// Unknown trailing elements are skipped.
	CHECK(decoded("30 05 02 01 05 05 00") == ldap::end_transaction_response{ 5 });

	const auto context_of = [&](std::string_view hex_value) {
		auto r = decoded(hex_value);
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == ldap::cond::protocol_error);
		return std::string(r.error().context);
	};
	CHECK(context_of("30 03 02 01 FF") == "txnEndRes: message: messageID -1 outside 0..2147483647 at offset 2");
	CHECK(context_of("30 03 02 01 05 00").starts_with("txnEndRes: ber: "));// trailing bytes
	// updateControls without its Controls, a control that is not a Control.
	CHECK(context_of("30 07 30 05 30 03 02 01 07").starts_with("txnEndRes: "));
	CHECK(context_of("30 0B 30 09 30 07 02 01 07 30 02 04 00").starts_with("txnEndRes: "));
	CHECK(context_of("30 0B 30 09 30 07 02 01 07 30 02 30 00").starts_with("txnEndRes: "));

	// The strings count against max_elements.
	const auto limited = decoded(full_hex, { .max_elements = 1 });
	REQUIRE_FALSE(limited.has_value());
	CHECK(limited.error().code == client_errc::message_too_large);

	// On a caller's resource.
	std::pmr::monotonic_buffer_resource arena;
	const auto on_arena = decoded(full_hex, { .memory = &arena });
	REQUIRE(on_arena.has_value());
	CHECK(on_arena->get_allocator().resource() == &arena);
	CHECK(on_arena->updates_controls.at(0).controls.at(0).get_allocator().resource() == &arena);
}
