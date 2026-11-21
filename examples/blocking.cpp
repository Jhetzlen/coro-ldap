#include "jhetz/ldap/sync.hpp"

#include <iostream>

namespace ldap = jhetz::ldap;

auto main(int argc, char *const *argv) -> int
{
	auto conn = ldap::sync::connect(argc > 1 ? argv[1] : "ldap://localhost", { .allow_cleartext_passwords = true });
	if (!conn) {
		std::cerr << conn.error().message() << '\n';
		return 1;
	}
	if (auto bound = conn->simple_bind(ldap::dn{ "cn=admin,dc=example,dc=org" }, "secret"); !bound) {
		std::cerr << bound.error().message() << '\n';
		return 1;
	}
	auto people = conn->search({
	  .base = ldap::dn{ "ou=people,dc=example,dc=org" },
	  .filter = ldap::filters::attr("uid").starts_with("user00"),
	  .attributes = { "cn" },
	});
	if (!people) {
		std::cerr << people.error().message() << '\n';
		return 1;
	}
	if (!people->is_complete()) {
		std::cerr << "the result is partial: result code " << people->result_code << ", " << people->references.size()
				  << " references not followed\n";
	}
	for (const ldap::entry &person : people->entries) {
		std::cout << person.dn << ": " << person.find("cn")->front() << '\n';
	}
}
