#include "jhetz/ldap/sync.hpp"

#include <iostream>

namespace ldap = jhetz::ldap;

int main(int argc, char **argv)
{
	auto url = ldap::url::parse(argc > 1 ? argv[1] : "ldap://localhost");
	if (!url) {
		std::cerr << url.error().message() << '\n';
		return 1;
	}
	ldap::sync::client client;
	if (auto connected = client.connect(*url); !connected) {
		std::cerr << connected.error().message() << '\n';
		return 1;
	}
	if (auto bound = client.simple_bind(ldap::dn{ "cn=admin,dc=example,dc=org" }, "secret"); !bound) {
		std::cerr << bound.error().message() << '\n';
		return 1;
	}
	auto people = client.search({
	  .base = ldap::dn{ "ou=people,dc=example,dc=org" },
	  .filter = ldap::filters::attr("uid").starts_with("user00"),
	  .attributes = { "cn" },
	});
	if (!people) {
		std::cerr << people.error().message() << '\n';
		return 1;
	}
	for (const ldap::entry &person : *people) std::cout << person.dn << ": " << person.find("cn")->front() << '\n';
}
