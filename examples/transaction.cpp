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
	auto t = co_await ldap::transaction::begin(*c);
	if (!t) {
		std::cerr << t.error().message() << '\n';
		co_return 1;
	}
	auto added = co_await t->add({
	  .entry = ldap::dn{ "uid=jane,ou=people,dc=example,dc=org" },
	  .attributes = { { "objectClass", { "inetOrgPerson" } },
		{ "uid", { "jane" } },
		{ "cn", { "Jane Doe" } },
		{ "sn", { "Doe" } } },
	});
	auto modified = co_await t->modify({
	  .object = ldap::dn{ "uid=user001,ou=people,dc=example,dc=org" },
	  .changes = { ldap::mod::replace("manager", { "uid=jane,ou=people,dc=example,dc=org" }) },
	});
	if (!added || !modified) {
		std::cerr << (added ? modified.error() : added.error()).message() << '\n';
		co_return 1;
	}
	auto committed = co_await t->commit();
	if (!committed) {
		std::cerr << committed.error().message() << '\n';
		co_return 1;
	}
	std::cout << "added uid=jane and set the manager of uid=user001 in one transaction\n";
	co_return 0;
}

auto main(int argc, char *const *argv) -> int { return ldap::run(example, argc > 1 ? argv[1] : "ldap://localhost"); }
