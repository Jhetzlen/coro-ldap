#include "jhetz/ldap/connection.hpp"

#include <boost/corosio/io_context.hpp>

#include <iostream>
#include <string>

namespace ldap = jhetz::ldap;

auto example(boost::corosio::io_context &ioc, std::string text) -> boost::capy::task<int>
{
	auto c = co_await ldap::connect(ioc, text);
	if (!c) {
		std::cerr << c.error().message() << '\n';
		co_return 1;
	}
	auto bound = co_await c->simple_bind(ldap::dn{ "cn=admin,dc=example,dc=org" }, "secret");
	if (!bound) {
		std::cerr << bound.error().message() << '\n';
		co_return 1;
	}
	std::cout << "connected to " << text << " as cn=admin,dc=example,dc=org\n";
	co_return 0;
}

auto main(int argc, char *const *argv) -> int { return ldap::run(example, argc > 1 ? argv[1] : "ldap://localhost"); }
