#include "jhetz/ldap/message.hpp"
#include "sample_messages.hpp"
#include "test_util.hpp"

#include <catch2/catch_test_macros.hpp>

#include <stdexcept>
#include <string>
#include <vector>

namespace ber = jhetz::ldap::ber;
namespace ldap = jhetz::ldap;
using jhetz::ldap::client_errc;
using jhetz::ldap::test::hex;
using namespace std::string_literals;

namespace {

template<class T> std::error_code code_of(const ldap::result<T> &r)
{
	REQUIRE_FALSE(r.has_value());
	return r.error().code;
}

ldap::message round_trip(const ldap::message &m)
{
	auto bytes = ldap::encode(m);
	REQUIRE(bytes.has_value());
	auto size = ber::complete_message_size(*bytes);
	REQUIRE(size.has_value());
	REQUIRE(size->has_value());
	CHECK(**size == bytes->size());
	auto back = ldap::decode(*bytes);
	REQUIRE(back.has_value());
	auto again = ldap::encode(*back);
	REQUIRE(again.has_value());
	CHECK(hex(*again) == hex(*bytes));
	return *back;
}

// LDAPMessage { id, <op built by body>, <extra built by tail> }
template<class Op, class Tail = void (*)(ber::writer &)>
std::vector<std::byte> raw_message(std::int64_t id, Op &&op, Tail &&tail = [](ber::writer &) {})
{
	ber::writer w;
	w.constructed(ber::tags::sequence, [&](ber::writer &m) {
		m.integer(id);
		op(m);
		tail(m);
	});
	return w.take();
}

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

TEST_CASE("decoded filters are canonical RFC 4515 text", "[message]")
{
	ldap::message m{ .id = 1, .op = ldap::search_request{ .filter = ldap::filter::raw("uid=\\4A\\2A*") } };
	auto back = ldap::decode(*ldap::encode(m));
	REQUIRE(back);
	CHECK(std::get<ldap::search_request>(back->op).filter.text == "(uid=J\\2a*)");
}

TEST_CASE("control criticality is omitted when false", "[message]")
{
	ldap::message m{ .id = 1, .op = ldap::unbind_request{}, .controls = { { .type = "1.2" } } };
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
	auto decoded = ldap::decode(raw);
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
		auto m = ldap::decode(raw);
		REQUIRE(m);
		CHECK(*m == ldap::message{ .id = 7, .op = ldap::bind_response{ { .result_code = 14 }, "creds" } });
	}
	SECTION("in LDAPMessage, with and without controls")
	{
		auto no_controls = raw_message(
		  1,
		  [](ber::writer &m) { m.null(ber::application(2)); },
		  [](ber::writer &m) { m.octet_string("x", ber::context(5)); });
		auto decoded = ldap::decode(no_controls);
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
		decoded = ldap::decode(with_controls);
		REQUIRE(decoded);
		CHECK(decoded->controls == std::vector<ldap::control>{ { "1.2.3", true, "v" } });
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
		auto m = ldap::decode(raw);
		REQUIRE(m);
		CHECK(*m == ldap::message{ .id = 2, .op = ldap::search_result_entry{ "dc=x", { { "cn", { "a" } } } } });
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
		auto m = ldap::decode(raw);
		REQUIRE(m);
		const auto &x = std::get<ldap::extended_response>(m->op);
		CHECK_FALSE(x.response_name.has_value());
		CHECK(x.response_value == "value");
	}
}

TEST_CASE("decode rejects unknown operations", "[message][extensibility]")
{
	auto app20 = raw_message(1, [](ber::writer &m) { m.constructed(ber::application(20), [](ber::writer &) {}); });
	CHECK(code_of(ldap::decode(app20)) == client_errc::unsupported_operation);
	auto app30 = raw_message(1, [](ber::writer &m) { m.null(ber::application(30)); });
	CHECK(code_of(ldap::decode(app30)) == client_errc::unsupported_operation);
	auto ctx = raw_message(1, [](ber::writer &m) { m.null(ber::context(2)); });
	CHECK(code_of(ldap::decode(ctx)) == client_errc::unsupported_operation);
	auto universal = raw_message(1, [](ber::writer &m) { m.octet_string("x"); });
	CHECK(code_of(ldap::decode(universal)) == client_errc::unsupported_operation);
	auto missing = raw_message(1, [](ber::writer &) {});
	CHECK(code_of(ldap::decode(missing)) == client_errc::decode_error);

	// Bind authentication choices other than simple and SASL (e.g. the
	// reserved Kerberos ones, or Active Directory's Sicily [9]).
	auto sicily = raw_message(1, [](ber::writer &m) {
		m.constructed(ber::application(0), [](ber::writer &o) {
			o.integer(3);
			o.octet_string("");
			o.octet_string("", ber::context(9));
		});
	});
	auto r = ldap::decode(sicily);
	CHECK(code_of(r) == client_errc::unsupported_operation);
	CHECK(r.error().context.find("offset") != std::string::npos);
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
	CHECK(ldap::decode(search(3, 3, 0)).has_value());
	CHECK(code_of(ldap::decode(search(4, 0, 0))) == client_errc::decode_error);
	CHECK(code_of(ldap::decode(search(-1, 0, 0))) == client_errc::decode_error);
	CHECK(code_of(ldap::decode(search(0, 4, 0))) == client_errc::decode_error);
	CHECK(code_of(ldap::decode(search(0, 0, -1))) == client_errc::decode_error);
	CHECK(code_of(ldap::decode(search(0, 0, 0x8000'0000LL))) == client_errc::decode_error);

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
	CHECK(ldap::decode(modify(3)).has_value());
	auto bad_op = ldap::decode(modify(4));
	CHECK(code_of(bad_op) == client_errc::decode_error);
	CHECK(bad_op.error().context.find("modify operation 4") != std::string::npos);

	auto bind = [](std::int64_t version) {
		return raw_message(1, [&](ber::writer &m) {
			m.constructed(ber::application(0), [&](ber::writer &o) {
				o.integer(version);
				o.octet_string("");
				o.octet_string("", ber::context(0));
			});
		});
	};
	CHECK(ldap::decode(bind(1)).has_value());
	CHECK(code_of(ldap::decode(bind(0))) == client_errc::decode_error);
	CHECK(code_of(ldap::decode(bind(128))) == client_errc::decode_error);

	auto unbind_with_id = [](std::int64_t id) {
		return raw_message(id, [](ber::writer &m) { m.null(ber::application(2)); });
	};
	CHECK(ldap::decode(unbind_with_id(0)).has_value());
	CHECK(ldap::decode(unbind_with_id(ldap::max_int)).has_value());
	CHECK(code_of(ldap::decode(unbind_with_id(-1))) == client_errc::decode_error);
	CHECK(code_of(ldap::decode(unbind_with_id(0x8000'0000LL))) == client_errc::decode_error);

	auto abandon = [](std::int64_t id) {
		return raw_message(1, [&](ber::writer &m) { m.integer(id, ber::application(16)); });
	};
	CHECK(code_of(ldap::decode(abandon(-5))) == client_errc::decode_error);

	// Unknown result codes are kept.
	auto done = raw_message(
	  1, [](ber::writer &m) { m.constructed(ber::application(5), [](ber::writer &o) { write_result(o, 4711); }); });
	auto decoded = ldap::decode(done);
	REQUIRE(decoded);
	CHECK(std::get<ldap::search_result_done>(decoded->op).result.result_code == 4711);
	auto huge = raw_message(1, [](ber::writer &m) {
		m.constructed(ber::application(5), [](ber::writer &o) { write_result(o, 0x1'0000'0000LL); });
	});
	CHECK(code_of(ldap::decode(huge)) == client_errc::decode_error);
}

TEST_CASE("decode rejects malformed messages", "[message]")
{
	const auto samples = ldap::test::sample_messages();

	SECTION("trailing bytes")
	{
		auto bytes = *ldap::encode(samples.front());
		bytes.push_back(std::byte{ 0 });
		CHECK(code_of(ldap::decode(bytes)) == client_errc::decode_error);
		auto twice = *ldap::encode(samples.front());
		twice.insert(twice.end(), twice.begin(), twice.end());
		CHECK(code_of(ldap::decode(twice)) == client_errc::decode_error);
	}
	SECTION("every truncation of every sample")
	{
		for (auto m : samples) {
			m.controls = ldap::test::sample_controls();
			const auto bytes = *ldap::encode(m);
			for (std::size_t n = 0; n < bytes.size(); ++n) {
				INFO("sample " << m.id << " truncated to " << n);
				CHECK_FALSE(ldap::decode(std::span(bytes).first(n)).has_value());
			}
		}
	}
	SECTION("wrong primitive/constructed form")
	{
		auto primitive_bind = raw_message(1, [](ber::writer &m) { m.octet_string("", ber::application(0)); });
		CHECK(code_of(ldap::decode(primitive_bind)) == client_errc::unexpected_tag);
		auto constructed_unbind =
		  raw_message(1, [](ber::writer &m) { m.constructed(ber::application(2), [](ber::writer &) {}); });
		CHECK(code_of(ldap::decode(constructed_unbind)) == client_errc::unexpected_tag);
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
		CHECK(code_of(ldap::decode(raw)) == client_errc::decode_error);
	}
	SECTION("nesting beyond the reader's limit")
	{
		std::vector<std::byte> deep{ std::byte{ 0x05 }, std::byte{ 0x00 } };
		for (int i = 0; i < 40; ++i) {
			deep.insert(deep.begin(), { std::byte{ 0x30 }, static_cast<std::byte>(deep.size()) });
		}
		CHECK_FALSE(ldap::decode(deep).has_value());
	}
}

TEST_CASE("a search request with the deepest allowed filter decodes", "[message]")
{
	// depth max_filter_depth: (&(&...(cn=a*b*c)...)) with a substrings leaf.
	std::string text;
	for (std::size_t i = 1; i < ldap::max_filter_depth; ++i) text += "(&";
	text += "(cn=a*b*c)";
	for (std::size_t i = 1; i < ldap::max_filter_depth; ++i) text += ")";
	ldap::message m{ .id = 1, .op = ldap::search_request{ .filter = ldap::filter::raw(text) } };
	CHECK(round_trip(m) == m);

	m.op = ldap::search_request{ .filter = ldap::filter::raw("(!" + text + ")") };
	CHECK(code_of(ldap::encode(m)) == client_errc::invalid_filter);
}

TEST_CASE("encode rejects values the wire format cannot carry", "[message]")
{
	auto encode_error = [](const ldap::message &m) {
		auto r = ldap::encode(m);
		REQUIRE_FALSE(r);
		return r.error().code == client_errc::encode_error;
	};
	CHECK(encode_error({ .id = -1, .op = ldap::unbind_request{} }));
	CHECK(encode_error({ .id = 1, .op = ldap::bind_request{ .version = 0 } }));
	CHECK(encode_error({ .id = 1, .op = ldap::bind_request{ .version = 128 } }));
	CHECK(encode_error({ .id = 1, .op = ldap::search_request{ .size_limit = -1 } }));
	CHECK(encode_error({ .id = 1, .op = ldap::search_request{ .time_limit = -1 } }));
	CHECK(encode_error({ .id = 1, .op = ldap::search_request{ .scope = static_cast<ldap::search_scope>(9) } }));
	CHECK(encode_error({ .id = 1, .op = ldap::search_request{ .deref = static_cast<ldap::deref_aliases>(-1) } }));
	CHECK(encode_error({ .id = 1, .op = ldap::abandon_request{ -1 } }));
	CHECK(encode_error({ .id = 1,
	  .op = ldap::modify_request{ .changes = { { static_cast<ldap::modify_operation>(4), { "cn", {} } } } } }));

	auto bad_filter = ldap::encode({ .id = 1, .op = ldap::search_request{ .filter = ldap::filter::raw("(cn=x") } });
	CHECK(code_of(bad_filter) == client_errc::invalid_filter);
	CHECK(bad_filter.error().context == "filter: unexpected end of filter at position 5");

	// Nothing is written on failure.
	ber::writer w;
	w.integer(1);
	const auto before = hex(w.bytes());
	CHECK_FALSE(ldap::encode(w, { .id = -1, .op = ldap::unbind_request{} }));
	CHECK_FALSE(ldap::encode(w, { .id = 1, .op = ldap::search_request{ .filter = ldap::filter::raw("") } }));
	CHECK(hex(w.bytes()) == before);
}

TEST_CASE("ldap_result::to_error", "[message][error]")
{
	SECTION("known code, matched DN, diagnostic, referrals")
	{
		const auto r = ldap::test::sample_result();
		CHECK_FALSE(r.is_success());
		const auto e = r.to_error("search ou=people");
		CHECK(e.code == ldap::errc::no_such_object);
		CHECK(e.diagnostic == "no such entry");
		CHECK(e.matched_dn == "dc=example,dc=org");
		CHECK(e.referrals == std::vector<std::string>{ "ldap://a.example.org/", "ldap://b.example.org/" });
		CHECK(e.context == "search ou=people");
		CHECK(e.message()
		  == "search ou=people: no such object [ldap.result:32]; server: no such entry; matched DN: dc=example,dc=org; "
			 "referrals: ldap://a.example.org/ ldap://b.example.org/");
	}
	SECTION("unknown code")
	{
		const ldap::ldap_result r{ .result_code = 4711 };
		const auto e = r.to_error();
		CHECK(e.code.value() == 4711);
		CHECK(&e.code.category() == &ldap::result_category());
		CHECK_FALSE(e.matched_dn.has_value());
		CHECK(e.message() == "unknown LDAP result code 4711 [ldap.result:4711]");
	}
	SECTION("referral and compare results")
	{
		CHECK(ldap::ldap_result{ .result_code = 10 }.to_error().code == ldap::errc::referral);
		CHECK(ldap::ldap_result{ .result_code = 6 }.to_error().code == ldap::errc::compare_true);
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
	const ldap::paged_results p{ .size = 250, .cookie = "\0\x01\xff"s };
	const auto c = ldap::encode_paged_results(p, true).value();
	CHECK(c.type == ldap::paged_results_oid);
	CHECK(c.criticality);
	REQUIRE(c.value);
	CHECK(hex(ldap::test::bytes_of(*c.value)) == "30 09 02 02 00 FA 04 03 00 01 FF");
	CHECK(ldap::decode_paged_results(c) == p);
	CHECK_FALSE(ldap::encode_paged_results({})->criticality);
	CHECK(ldap::decode_paged_results(*ldap::encode_paged_results({})) == ldap::paged_results{});
	CHECK(code_of(ldap::encode_paged_results({ .size = -1 })) == client_errc::encode_error);

	auto value_of = [](auto body) {
		ber::writer w;
		body(w);
		const auto &b = w.bytes();
		return ldap::control{
			std::string(ldap::paged_results_oid), false, std::string(reinterpret_cast<const char *>(b.data()), b.size())
		};
	};
	CHECK(code_of(ldap::decode_paged_results({ .type = "1.2.3", .value = c.value })) == client_errc::decode_error);
	CHECK(code_of(ldap::decode_paged_results({ .type = std::string(ldap::paged_results_oid) }))
		  == client_errc::decode_error);
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

TEST_CASE("encode(decode(encode(m))) == encode(m), also for non-canonical filters", "[message]")
{
	std::vector<ldap::message> all = ldap::test::sample_messages();
	for (const char *text : { "cn=x", "(cn=\\41)", "(cn=\\2A)", "(A:DN:=v)", "(a=b**c)" })
		all.push_back({ .id = 9, .op = ldap::search_request{ .filter = ldap::filter::raw(text) } });
	for (const auto &m : all) {
		INFO("sample id " << m.id << ", op index " << m.op.index());
		auto first = ldap::encode(m);
		REQUIRE(first);
		auto decoded = ldap::decode(*first);
		REQUIRE(decoded);
		auto second = ldap::encode(*decoded);
		REQUIRE(second);
		CHECK(hex(*second) == hex(*first));
	}
	// The filter text itself comes back canonical, not as written.
	auto canonical = [](const char *text) {
		auto m =
		  ldap::decode(*ldap::encode({ .id = 1, .op = ldap::search_request{ .filter = ldap::filter::raw(text) } }));
		REQUIRE(m);
		return std::get<ldap::search_request>(m->op).filter.text;
	};
	CHECK(canonical("cn=x") == "(cn=x)");
	CHECK(canonical("(cn=\\41)") == "(cn=A)");
	CHECK(canonical("(cn=\\2A)") == "(cn=\\2a)");
	CHECK(canonical("(A:DN:=v)") == "(A:dn:=v)");
	CHECK(canonical("(a=b**c)") == "(a=b*c)");
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
		CHECK(ldap::decode(bytes, { .from = ldap::origin::any }) == m);
		auto from_server = ldap::decode(bytes, { .from = ldap::origin::server });
		auto from_client = ldap::decode(bytes, { .from = ldap::origin::client });
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
	const ldap::message m{ .id = 1, .op = ldap::search_request{ .filter = ldap::filter::raw("(&(a=*)(b=*)(c=*))") } };
	const auto bytes = *ldap::encode(m);
	CHECK(ldap::decode(bytes).has_value());
	CHECK(code_of(ldap::decode(bytes, { .filter = { .max_elements = 3 } })) == client_errc::decode_error);
	CHECK(code_of(ldap::decode(bytes, { .filter = { .max_depth = 1 } })) == client_errc::nesting_too_deep);
	// Reader depth: LDAPMessage, SearchRequest and the AND need 3 levels.
	CHECK(ldap::decode(bytes, { .max_depth = 3 }).has_value());
	CHECK(code_of(ldap::decode(bytes, { .max_depth = 2 })) == client_errc::nesting_too_deep);
}

TEST_CASE("regression: a huge AND filter in a search request fails fast", "[message][options]")
{
	// Reviewer's shape: [APPLICATION 3] SearchRequest whose filter is an AND of
	// many 3-byte (a=*) children (87 01 61). Here about 1 MiB, far beyond
	// max_filter_elements; decoding stops at element 10,001.
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
				for (std::size_t i = 0; i < children; ++i) a.octet_string("a", ber::context(7));
			});
			o.constructed(ber::tags::sequence, [](ber::writer &) {});
		});
	});
	REQUIRE(bytes.size() > 1'000'000);
	auto r = ldap::decode(bytes);
	REQUIRE_FALSE(r);
	CHECK(r.error().code == client_errc::decode_error);
	CHECK(r.error().context.find("more than 10000 filter elements") != std::string::npos);
	// A client connection (origin::server) does not look at the filter at all.
	CHECK(code_of(ldap::decode(bytes, { .from = ldap::origin::server })) == client_errc::unsupported_operation);
}

TEST_CASE("add and modify-add values must not be empty", "[message]")
{
	const ldap::message empty_add{ .id = 1,
		.op = ldap::add_request{ .entry = "cn=x", .attributes = { { "cn", { "x" } }, { "sn", {} } } } };
	CHECK(code_of(ldap::encode(empty_add)) == client_errc::encode_error);
	const ldap::message empty_mod_add{ .id = 1,
		.op =
		  ldap::modify_request{ .object = "cn=x", .changes = { { ldap::modify_operation::add, { "mail", {} } } } } };
	CHECK(code_of(ldap::encode(empty_mod_add)) == client_errc::encode_error);
	// delete / replace without values: delete or clear the whole attribute.
	for (auto op : { ldap::modify_operation::delete_, ldap::modify_operation::replace }) {
		const ldap::message ok{ .id = 1,
			.op = ldap::modify_request{ .object = "cn=x", .changes = { { op, { "mail", {} } } } } };
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
	CHECK(code_of(ldap::decode(add_bytes)) == client_errc::decode_error);
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
	CHECK(code_of(ldap::decode(mod_bytes)) == client_errc::decode_error);
}
