#include "jhetz/ldap/sync_repository.hpp"

#include <iostream>
#include <optional>
#include <string>

namespace ldap = jhetz::ldap;

struct person
{
	std::string uid;
	std::optional<std::string> mail;
};

template<>
constexpr auto ldap::schema<person> = ldap::describe(ldap::object_class("inetOrgPerson"),
  ldap::field<&person::uid>("uid"),
  ldap::field<&person::mail>("mail"));

auto main(int argc, char *const *argv) -> int
{
	auto conn = ldap::sync::connect(argc > 1 ? argv[1] : "ldap://localhost");
	if (!conn) {
		std::cerr << conn.error().message() << '\n';
		return 1;
	}
	ldap::repository people(*conn, ldap::dn{ "ou=people,dc=example,dc=org" }, ldap::named_by<&person::uid>);
	auto all = people.search_paged(ldap::filters::field<&person::mail>().present(), 100);
	if (!all) {
		std::cerr << all.error().message() << '\n';
		return 1;
	}
	for (const ldap::record<person> &p : all->entries) {
		std::cout << p.value.uid << ": " << *p.value.mail << '\n';
	}
}
