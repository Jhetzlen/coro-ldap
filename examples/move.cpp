#include "jhetz/ldap/connection.hpp"

#include <boost/corosio/io_context.hpp>

#include <iostream>
#include <string>

namespace ldap = jhetz::ldap;

auto example(boost::corosio::io_context &ioc, std::string text) -> boost::capy::task<int>
{
	auto c = co_await ldap::connect(ioc, text, { .allow_cleartext_passwords = true });
	if (!c) {
		std::cerr << c.error().message() << '\n';
		co_return 1;
	}
	auto bound = co_await c->simple_bind(ldap::dn{ "cn=admin,dc=example,dc=org" }, "secret");
	if (!bound) {
		std::cerr << bound.error().message() << '\n';
		co_return 1;
	}
	auto moved = co_await c->modify_dn({ .entry = ldap::dn{ "uid=jane,ou=people,dc=example,dc=org" },
	  .new_rdn = ldap::rdn{ "uid=jane" },
	  .new_superior = ldap::dn{ "ou=alumni,dc=example,dc=org" } });
	if (!moved) {
		std::cerr << moved.error().message() << '\n';
		co_return 1;
	}
	std::cout << "moved uid=jane from ou=people to ou=alumni\n";
	co_return 0;
}

auto main(int argc, char *const *argv) -> int { return ldap::run(example, argc > 1 ? argv[1] : "ldap://localhost"); }
