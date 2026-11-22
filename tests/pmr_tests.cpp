// std::pmr support: everything decoded or built with a resource is
// allocated from it. Checked with a counting default resource, and with a
// null default resource and a null-upstream arena.
#include "counting_resource.hpp"
#include "jhetz/ldap/dn.hpp"
#include "jhetz/ldap/entry.hpp"
#include "jhetz/ldap/message.hpp"
#include "jhetz/ldap/testing/server_codec.hpp"
#include "sample_messages.hpp"
#include "test_util.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <memory_resource>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace ldap = jhetz::ldap;
using jhetz::ldap::test::counting_resource;
using jhetz::ldap::test::hex;
using jhetz::ldap::test::scoped_default_resource;
using namespace std::string_literals;

namespace {

// 30 attributes of 3 values each, plus two large binary values: the shape of
// a big directory entry.
auto large_entry() -> ldap::message
{
	ldap::search_result_entry e;
	e.object_name = "uid=a-user-with-a-long-name,ou=people,ou=department,dc=example,dc=org";
	for (int a = 0; a < 30; ++a) {
		auto &pa = e.attributes.emplace_back();
		pa.type = "attribute-number-" + std::to_string(a);
		for (int v = 0; v < 3; ++v) {
			pa.values.emplace_back(std::string(20 + static_cast<std::size_t>(a), static_cast<char>('a' + v)));
		}
	}
	std::string binary(1 << 20, '\0');
	for (std::size_t i = 0; i < binary.size(); ++i) {
		binary[i] = static_cast<char>(i * 7);
	}
	e.attributes.emplace_back("jpegPhoto", std::initializer_list<std::string_view>{ binary, binary.substr(1000) });
	return { 42, std::move(e), { ldap::control{ "1.2.840.113556.1.4.319", false, "cookie-cookie-cookie" } } };
}

auto all_samples() -> std::vector<ldap::message>
{
	auto out = ldap::test::sample_messages();
	for (auto m : ldap::test::sample_messages()) {
		m.controls = ldap::test::sample_controls();
		out.push_back(std::move(m));
	}
	out.push_back(large_entry());
	return out;
}

}// namespace

TEST_CASE("decode allocates only from decode_options::memory", "[pmr][message]")
{
	for (const auto &m : all_samples()) {
		INFO("sample id " << m.id << ", op index " << m.op.index());
		const auto bytes = *ldap::encode(m);
		counting_resource supplied;
		counting_resource heap;
		ldap::testing::decode_options options;
		options.memory = &supplied;
		{
			std::optional<ldap::result<ldap::message>> d;
			{
				scoped_default_resource guard(&heap);
				d.emplace(ldap::testing::decode(bytes, options));
			}
			CHECK(heap.allocations() == 0);
			REQUIRE(d->has_value());
			CHECK(**d == m);
			CHECK((*d)->get_allocator().resource() == &supplied);
		}
		CHECK(supplied.outstanding() == 0);// all given back when the message is destroyed
	}
}

TEST_CASE("decode into a monotonic buffer with a null upstream", "[pmr][message]")
{
	// Fails loudly (std::bad_alloc) on any allocation outside the buffer,
	// from the default resource included.
	std::vector<std::byte> storage(8 << 20);
	for (const auto &m : all_samples()) {
		INFO("sample id " << m.id << ", op index " << m.op.index());
		const auto bytes = *ldap::encode(m);
		std::pmr::monotonic_buffer_resource arena(storage.data(), storage.size(), std::pmr::null_memory_resource());
		ldap::testing::decode_options options;
		options.memory = &arena;
		std::optional<ldap::result<ldap::message>> d;
		{
			scoped_default_resource guard(std::pmr::null_memory_resource());
			REQUIRE_NOTHROW(d.emplace(ldap::testing::decode(bytes, options)));
		}
		REQUIRE(d->has_value());
		CHECK(**d == m);
		// A plain copy leaves the arena: it stays valid after the release.
		const ldap::message copy = **d;
		d.reset();
		arena.release();
		CHECK(copy == m);
		CHECK(copy.get_allocator().resource() == std::pmr::get_default_resource());
	}
}

TEST_CASE("errors never live in the caller's arena", "[pmr][message][error]")
{
	std::byte storage[4096];
	std::pmr::monotonic_buffer_resource arena(storage, sizeof storage, std::pmr::null_memory_resource());
	ldap::testing::decode_options options;
	options.memory = &arena;
	const auto bytes = ldap::test::from_hex("3003020101");// no protocolOp
	auto r = ldap::testing::decode(bytes, options);
	REQUIRE_FALSE(r);
	CHECK(r.error().context.get_allocator().resource() == std::pmr::get_default_resource());
	CHECK(r.error().code == ldap::client_errc::decode_error);

	// to_error() of a result in an arena: on the default resource too.
	ldap::ldap_result in_arena(ldap::ldap_result{ 32, "dc=example,dc=org", "no such entry", { "ldap://x/" } }, &arena);
	const auto e = in_arena.to_error("ctx");
	CHECK(e.diagnostic.get_allocator().resource() == std::pmr::get_default_resource());
	CHECK(e.matched_dn->get_allocator().resource() == std::pmr::get_default_resource());
	CHECK(e.referrals.get_allocator().resource() == std::pmr::get_default_resource());
	CHECK(e.referrals[0].get_allocator().resource() == std::pmr::get_default_resource());
}

TEST_CASE("a builder-made filter and its encoding allocate only from the given resource", "[pmr][filter]")
{
	std::byte storage[16384];
	std::pmr::monotonic_buffer_resource arena(storage, sizeof storage, std::pmr::null_memory_resource());
	const std::string user_input = "a user-supplied value, long enough to need an allocation";
	std::optional<ldap::result<std::pmr::vector<std::byte>>> bytes;
	{
		scoped_default_resource guard(std::pmr::null_memory_resource());
		using namespace ldap::filters;
		const attr::allocator_type a(&arena);
		auto f = attr("objectClass", a) == "person"
				 && (attr("uid", a) == user_input || attr("mail", a).starts_with(user_input))
				 && !attr("nsAccountLock", a).present() && attr("cn;lang-en", a).contains(user_input);
		ldap::search_request s(a);
		s.base_object = "ou=people,dc=example,dc=org";
		s.scope = ldap::search_scope::whole_subtree;
		s.filter = std::move(f);
		s.attributes.emplace_back("uid");
		s.attributes.emplace_back("a-long-attribute-name-that-does-not-fit-inline");
		ldap::message m(a);
		m.id = 7;
		m.op = std::move(s);
		m.controls.push_back(*ldap::encode_paged_results({ 500, "" }, true, &arena));
		REQUIRE_NOTHROW(bytes.emplace(ldap::encode(m, &arena)));
		REQUIRE(bytes->has_value());
		CHECK((*bytes)->get_allocator().resource() == &arena);
		CHECK(std::get<ldap::search_request>(m.op).filter.get_allocator().resource() == &arena);
	}
	// The same message built on the heap encodes to the same bytes.
	using namespace ldap::filters;
	ldap::search_request s("ou=people,dc=example,dc=org",
	  ldap::search_scope::whole_subtree,
	  attr("objectClass") == "person" && (attr("uid") == user_input || attr("mail").starts_with(user_input))
		&& !attr("nsAccountLock").present() && attr("cn;lang-en").contains(user_input),
	  { "uid", "a-long-attribute-name-that-does-not-fit-inline" });
	const ldap::message heap{ 7, std::move(s), { *ldap::encode_paged_results({ 500, "" }, true) } };
	CHECK(hex(**bytes) == hex(*ldap::encode(heap)));
}

TEST_CASE("filter::raw and decode_filter allocate from the given resource", "[pmr][filter]")
{
	std::byte storage[8192];
	std::pmr::monotonic_buffer_resource arena(storage, sizeof storage, std::pmr::null_memory_resource());
	scoped_default_resource guard(std::pmr::null_memory_resource());
	// Unwrapped text and extensible matches without dnAttributes too.
	auto f = ldap::filter::raw(
	  "&(cn=a-long-value-that-needs-memory*)(|(x=1)(y:dn:1.2.3:=z)(cn:2.5.13.5:=x)(:1.2.3:=v)(sn:=w))", &arena);
	REQUIRE(f.has_value());
	CHECK(f->get_allocator().resource() == &arena);
	ldap::ber::writer w{ ldap::ber::writer::allocator_type(&arena) };
	REQUIRE(ldap::encode_filter(w, *f));
	ldap::ber::reader r(w.bytes());
	auto back = ldap::testing::decode_filter(r, {}, &arena);
	REQUIRE(back.has_value());
	CHECK(*back == *f);
	CHECK(back->get_allocator().resource() == &arena);
	CHECK(f->to_string(&arena)
		  == "(&(cn=a-long-value-that-needs-memory*)(|(x=1)(y:dn:1.2.3:=z)(cn:2.5.13.5:=x)(:1.2.3:=v)(sn:=w)))");
}

TEST_CASE("message model types are allocator-aware", "[pmr][message]")
{
	std::vector<std::byte> storage(16 << 20);// the large entry is copied 4 times
	const ldap::message other = ldap::test::sample_messages().back();// on the default resource
	for (const auto &m : all_samples()) {
		INFO("sample id " << m.id << ", op index " << m.op.index());
		std::pmr::monotonic_buffer_resource arena(storage.data(), storage.size(), std::pmr::null_memory_resource());
		const ldap::message::allocator_type a(&arena);
		counting_resource heap;
		{
			scoped_default_resource guard(&heap);
			// Allocator-extended copy: everything on the arena.
			const ldap::message copy(m, a);
			CHECK(copy.get_allocator() == a);
			CHECK(copy == m);
			// Allocator-extended move within one resource.
			ldap::message moved(ldap::message(copy, a), a);
			CHECK(moved == m);
			// Assignment keeps the target's resource, whatever the source's
			// alternative and optional members are.
			ldap::message target(a);
			target = m;
			CHECK(target == m);
			CHECK(target.get_allocator() == a);
			target = other;
			CHECK(target == other);
			ldap::message target2(a);
			target2 = std::move(moved);
			CHECK(target2 == m);
		}
		CHECK(heap.allocations() == 0);// nothing of it went to the default resource
	}
}

TEST_CASE("assignment keeps the target's resource for optional and variant members", "[pmr][message]")
{
	counting_resource arena;
	const ldap::message::allocator_type a(&arena);
	counting_resource heap;
	scoped_default_resource guard(&heap);

	// std::variant switching alternatives, std::optional becoming engaged.
	ldap::message target(a);// holds a bind_request
	const ldap::message source{ 1,
		ldap::extended_response{ ldap::ldap_result{ 0 }, "1.2.3.4.5.6.7.8.9.10.11.12.13.14", std::string(100, 'v') },
		{ ldap::control{ "1.2.3.4.5.6.7.8.9.10.11.12.13.14.15", true, std::string(50, 'c') } } };
	const auto heap_before = heap.allocations();
	target = source;
	CHECK(heap.allocations() == heap_before);
	CHECK(target == source);
	const auto &x = std::get<ldap::extended_response>(target.op);
	CHECK(x.response_name->get_allocator().resource() == &arena);
	CHECK(x.response_value->get_allocator().resource() == &arena);
	CHECK(target.controls[0].value->get_allocator().resource() == &arena);

	ldap::bind_request b(a);
	b = ldap::bind_request{
		3, "cn=a-long-name-for-the-bind,dc=example,dc=org", ldap::sasl_auth{ "GSSAPI", std::string(40, 'x') }
	};
	const auto &sasl = std::get<ldap::sasl_auth>(b.authentication);
	CHECK(sasl.mechanism.get_allocator().resource() == &arena);
	CHECK(sasl.credentials->get_allocator().resource() == &arena);

	ldap::intermediate_response i(a);
	i = ldap::intermediate_response{ std::string(40, 'n'), std::string(40, 'v') };
	CHECK(i.get_allocator().resource() == &arena);
	CHECK(i.response_name->get_allocator().resource() == &arena);
	CHECK(i.response_value->get_allocator().resource() == &arena);
	// A plain copy uses the default resource, like any pmr container.
	const auto plain = i;
	CHECK(plain.get_allocator().resource() == &heap);
	CHECK(plain.response_value->get_allocator().resource() == &heap);
	CHECK(plain == i);

	// Containers hand their resource to their elements.
	std::pmr::vector<ldap::message> list(a);
	list.push_back(source);
	CHECK(list[0].get_allocator() == a);
	CHECK(std::get<ldap::extended_response>(list[0].op).response_value->get_allocator().resource() == &arena);
}

TEST_CASE("ber::writer allocates from its resource", "[pmr][ber]")
{
	counting_resource counting;
	ldap::ber::writer w{ ldap::ber::writer::allocator_type(&counting) };
	w.octet_string(std::string(1000, 'x'));
	CHECK(counting.allocations() > 0);
	CHECK(w.bytes().get_allocator().resource() == &counting);
	const auto taken = w.take();
	CHECK(taken.get_allocator().resource() == &counting);
	CHECK(w.get_allocator().resource() == &counting);// still, and empty
	CHECK(w.bytes().empty());
	const ldap::ber::writer copy = w;
	CHECK(copy.get_allocator().resource() == std::pmr::get_default_resource());
}

TEST_CASE("dn, attribute and entry allocate from the given resource", "[pmr][dn][attribute]")
{
	std::byte storage[16384];
	std::pmr::monotonic_buffer_resource arena(storage, sizeof storage, std::pmr::null_memory_resource());
	scoped_default_resource guard(std::pmr::null_memory_resource());

	auto d = ldap::dn::parse("cn=a long common name\\2C with a comma+uid=someone,ou=people,dc=example,dc=org", &arena);
	REQUIRE(d.has_value());
	CHECK(d->get_allocator().resource() == &arena);
	CHECK(d->rdns()[0].avas[1].type.get_allocator().resource() == &arena);
	const auto parent = d->parent();
	CHECK(parent.get_allocator().resource() == &arena);
	const auto child = parent.child(ldap::rdn{ { ldap::ava{ ldap::attribute{ "cn" }, "x" } }, &arena });
	CHECK(child.get_allocator().resource() == &arena);
	CHECK(child.rdns()[0].avas[0].value.get_allocator().resource() == &arena);
	CHECK(d->to_string(&arena).get_allocator().resource() == &arena);
	const ldap::dn literal(ldap::dn::literal("dc=example,dc=org"), &arena);
	CHECK(literal.rdns()[1].get_allocator().resource() == &arena);

	auto attr = ldap::attribute::parse("userCertificate;binary-with-a-long-option", &arena);
	REQUIRE(attr.has_value());
	CHECK(attr->name().get_allocator().resource() == &arena);

	// An entry made from a search entry on the arena lives there too.
	ldap::search_result_entry e(&arena);
	e.object_name = "uid=jdoe,ou=people,dc=example,dc=org";
	e.attributes.emplace_back("cn", std::initializer_list<std::string_view>{ "John Doe the Long" });
	e.attributes.emplace_back("CN", std::initializer_list<std::string_view>{ "Johnny" });
	e.attributes.emplace_back("mail", std::initializer_list<std::string_view>{ "john.doe@example.org" });
	const auto x = ldap::entry::from(std::move(e));
	CHECK(x.get_allocator().resource() == &arena);
	REQUIRE(x.attributes.size() == 2);
	CHECK(x.attributes[0].values.size() == 2);
	CHECK(x.attributes[0].values[1].get_allocator().resource() == &arena);
	CHECK(x.attributes[1].type.get_allocator().resource() == &arena);
}

TEST_CASE("copies of arena objects go to the default resource", "[pmr]")
{
	std::byte storage[8192];
	std::optional<ldap::dn> d_copy;
	std::optional<ldap::filter> f_copy;
	std::optional<ldap::message> m_copy;
	{
		std::pmr::monotonic_buffer_resource arena(storage, sizeof storage, std::pmr::null_memory_resource());
		auto d = ldap::dn::parse("cn=a value that is long enough,dc=example,dc=org", &arena);
		auto f = ldap::filter::raw("(cn=a value that is long enough*)", &arena);
		ldap::testing::decode_options options;
		options.memory = &arena;
		auto m = ldap::testing::decode(*ldap::encode(ldap::test::sample_messages()[12]), options);
		REQUIRE(d);
		REQUIRE(f);
		REQUIRE(m);
		d_copy.emplace(*d);
		f_copy.emplace(*f);
		m_copy.emplace(*m);
	}
	// The arena (and its buffer contents) are gone; the copies are not.
	std::ranges::fill(storage, std::byte{ 0xAA });
	CHECK(d_copy->to_string() == "cn=a value that is long enough,dc=example,dc=org");
	CHECK(f_copy->to_string() == "(cn=a value that is long enough*)");
	CHECK(*m_copy == ldap::test::sample_messages()[12]);
}
