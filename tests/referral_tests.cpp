#include "jhetz/ldap/referral.hpp"

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <string_view>

namespace ldap = jhetz::ldap;
using ldap::client_errc;
using ldap::reference_kind;
using ldap::search_scope;

namespace {

auto url(std::string_view text) -> ldap::url
{
	auto u = ldap::url::parse(text);
	INFO(text);
	REQUIRE(u.has_value());
	return *u;
}

auto original_search() -> ldap::search_params
{
	return {
		.base = ldap::dn{ "ou=people,dc=example,dc=org" },
		.scope = search_scope::single_level,
		.filter = ldap::filters::attr("uid") == "jdoe",
		.attributes = { "cn", "mail" },
		.size_limit = 10,
		.controls = { ldap::manage_dsa_it{} },
		.timeout = std::chrono::seconds(5),
	};
}

}// namespace

TEST_CASE("referral_target: a referral's absent parts are the original search's", "[referral]")
{
	const auto original = original_search();
	// RFC 4511 section 4.1.10: absent DN, scope and filter mean the same as
	// the original request; an empty DN counts as absent.
	for (const auto *text :
	  { "ldap://other.example.org", "ldap://other.example.org/", "ldap://other.example.org/??" }) {
		INFO(text);
		auto t = ldap::referral_target(url(text), original);
		REQUIRE(t.has_value());
		CHECK(t->base == original.base);
		CHECK(t->scope == search_scope::single_level);
		CHECK(t->filter == original.filter);
		CHECK(t->attributes == original.attributes);
		CHECK(t->size_limit == 10);
		CHECK(t->timeout == original.timeout);
		CHECK(t->controls.size() == 1);
	}
}

TEST_CASE("referral_target: a referral's DN, scope and filter replace the original's", "[referral]")
{
	auto t = ldap::referral_target(
	  url("ldap://other.example.org/ou=staff,dc=example,dc=org?mail?sub?(sn=Doe)"), original_search());
	REQUIRE(t.has_value());
	CHECK(t->base == ldap::dn{ "ou=staff,dc=example,dc=org" });
	CHECK(t->scope == search_scope::whole_subtree);
	CHECK(t->filter == ldap::filter::raw("(sn=Doe)").value());
	// The URL's attribute list is not used (section 4.1.10 names only the
	// DN, scope and filter).
	CHECK(t->attributes == original_search().attributes);
}

TEST_CASE("referral_target: UTF-8 in the DN and filter", "[referral]")
{
	auto t = ldap::referral_target(
	  url("ldap://h/ou=%C3%89quipe,dc=example,dc=org??base?(cn=J%C3%BCrgen%20M%C3%BCller)"), original_search());
	REQUIRE(t.has_value());
	CHECK(t->base == ldap::dn{ "ou=Équipe,dc=example,dc=org" });
	CHECK(t->scope == search_scope::base_object);
	CHECK(t->filter == (ldap::filters::attr("cn") == "Jürgen Müller"));
}

TEST_CASE("referral_target: continuation references", "[referral]")
{
	SECTION("without a scope, the original's: singleLevel stays singleLevel (RFC 4511 section 4.5.3)")
	{
		auto t = ldap::referral_target(url("ldap://h/uid=jdoe,ou=people,dc=example,dc=org"),
		  original_search(),
		  reference_kind::continuation_reference);
		REQUIRE(t.has_value());
		CHECK(t->base == ldap::dn{ "uid=jdoe,ou=people,dc=example,dc=org" });
		CHECK(t->scope == search_scope::single_level);
		CHECK(t->filter == original_search().filter);
	}
	SECTION("the server's \"base\" for a singleLevel search is used as given")
	{
		auto t = ldap::referral_target(url("ldap://h/uid=jdoe,ou=people,dc=example,dc=org??base"),
		  original_search(),
		  reference_kind::continuation_reference);
		REQUIRE(t.has_value());
		CHECK(t->scope == search_scope::base_object);
	}
	SECTION("a referral keeps singleLevel")
	{
		auto t = ldap::referral_target(url("ldap://h/uid=jdoe,ou=people,dc=example,dc=org"), original_search());
		REQUIRE(t.has_value());
		CHECK(t->scope == search_scope::single_level);
	}
	SECTION("an explicit scope wins")
	{
		auto t = ldap::referral_target(
		  url("ldap://h/ou=x,dc=example,dc=org??one"), original_search(), reference_kind::continuation_reference);
		REQUIRE(t.has_value());
		CHECK(t->scope == search_scope::single_level);
	}
	SECTION("a subtree search stays subtree")
	{
		auto o = original_search();
		o.scope = search_scope::whole_subtree;
		auto t =
		  ldap::referral_target(url("ldap://h/ou=x,dc=example,dc=org"), o, reference_kind::continuation_reference);
		REQUIRE(t.has_value());
		CHECK(t->scope == search_scope::whole_subtree);
	}
	SECTION("the DN must be present")
	{
		for (const auto *text : { "ldap://h", "ldap://h/", "ldap://h/??sub" }) {
			INFO(text);
			auto t = ldap::referral_target(url(text), original_search(), reference_kind::continuation_reference);
			REQUIRE_FALSE(t.has_value());
			CHECK(t.error().code == client_errc::invalid_url);
		}
	}
}

TEST_CASE("referral_target: extensions (RFC 4516 section 2)", "[referral]")
{
	SECTION("a non-critical extension is ignored")
	{
		auto t = ldap::referral_target(url("ldap://h/dc=example,dc=org????e-bindname=cn=x"), original_search());
		REQUIRE(t.has_value());
		CHECK(t->base == ldap::dn{ "dc=example,dc=org" });
	}
	SECTION("a critical one refuses the URL, for every operation")
	{
		const auto u = url(
		  "ldap://h/dc=example,dc=org???"
		  "?!e-bindname=cn=x");
		auto s = ldap::referral_target(u, original_search());
		REQUIRE_FALSE(s.has_value());
		CHECK(s.error().code == client_errc::invalid_url);
		CHECK(s.error().context == "referral: unsupported critical extension e-bindname");
		CHECK_FALSE(ldap::referral_target(u, ldap::compare_params{}).has_value());
		CHECK_FALSE(ldap::referral_target(u, ldap::add_params{}).has_value());
		CHECK_FALSE(ldap::referral_target(u, ldap::modify_params{}).has_value());
		CHECK_FALSE(ldap::referral_target(u, ldap::del_params{}).has_value());
		CHECK_FALSE(ldap::referral_target(u, ldap::modify_dn_params{}).has_value());
	}
}

TEST_CASE("referral_target: compare and updates take only the DN", "[referral]")
{
	const auto moved = url("ldap://h/uid=jdoe,ou=moved,dc=example,dc=org?cn?sub?(cn=x)");
	const auto bare = url("ldap://h");
	const ldap::dn old_dn{ "uid=jdoe,ou=people,dc=example,dc=org" };
	const ldap::dn new_dn{ "uid=jdoe,ou=moved,dc=example,dc=org" };

	SECTION("compare")
	{
		const ldap::compare_params o{ .entry = old_dn, .attribute = "mail", .value = "jdoe@example.org" };
		auto t = ldap::referral_target(moved, o);
		REQUIRE(t.has_value());
		CHECK(t->entry == new_dn);
		CHECK(t->attribute == "mail");
		CHECK(t->value == "jdoe@example.org");
		CHECK(ldap::referral_target(bare, o)->entry == old_dn);
	}
	SECTION("add")
	{
		const ldap::add_params o{ .entry = old_dn, .attributes = { ldap::partial_attribute{ "cn", { "J" } } } };
		auto t = ldap::referral_target(moved, o);
		REQUIRE(t.has_value());
		CHECK(t->entry == new_dn);
		CHECK(t->attributes == o.attributes);
		CHECK(ldap::referral_target(bare, o)->entry == old_dn);
	}
	SECTION("modify")
	{
		const ldap::modify_params o{ .object = old_dn, .changes = { ldap::mod::replace("mail", { "x" }) } };
		auto t = ldap::referral_target(moved, o);
		REQUIRE(t.has_value());
		CHECK(t->object == new_dn);
		CHECK(t->changes == o.changes);
		CHECK(ldap::referral_target(bare, o)->object == old_dn);
	}
	SECTION("delete")
	{
		const ldap::del_params o{ .entry = old_dn };
		CHECK(ldap::referral_target(moved, o)->entry == new_dn);
		CHECK(ldap::referral_target(bare, o)->entry == old_dn);
	}
	SECTION("modify DN")
	{
		const ldap::modify_dn_params o{
			.entry = old_dn, .new_rdn = ldap::rdn{ "uid=jane" }, .new_superior = ldap::dn{ "ou=x,dc=example,dc=org" }
		};
		auto t = ldap::referral_target(moved, o);
		REQUIRE(t.has_value());
		CHECK(t->entry == new_dn);
		CHECK(t->new_rdn == ldap::rdn{ "uid=jane" });
		CHECK(t->new_superior == o.new_superior);
		CHECK(ldap::referral_target(bare, o)->entry == old_dn);
	}
}
