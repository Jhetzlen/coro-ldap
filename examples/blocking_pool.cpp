#include "jhetz/ldap/sync.hpp"

#include <iostream>

namespace ldap = jhetz::ldap;

auto main(int argc, char *const *argv) -> int
{
	auto server = ldap::url::parse(argc > 1 ? argv[1] : "ldap://localhost");
	if (!server) {
		std::cerr << server.error().message() << '\n';
		return 1;
	}
	ldap::sync::client pool(
	  { .servers = { *server }, .setup = ldap::simple_bind_setup(ldap::dn{ "cn=admin,dc=example,dc=org" }, "secret") });
	auto people = pool.search({
	  .base = ldap::dn{ "ou=people,dc=example,dc=org" },
	  .filter = ldap::filters::attr("uid").starts_with("user00"),
	  .attributes = { "cn" },
	});
	if (!people) {
		std::cerr << people.error().message() << '\n';
		return 1;
	}
	for (const ldap::entry &person : *people) {
		std::cout << person.dn << ": " << person.find("cn")->front() << '\n';
	}
}
