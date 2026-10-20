#include "jhetz/ldap/connection.hpp"

#include <boost/capy/ex/run_async.hpp>
#include <boost/corosio/io_context.hpp>

#include <iostream>
#include <string>

namespace ldap = jhetz::ldap;

auto run(boost::corosio::io_context &ioc, std::string text) -> boost::capy::task<int>
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
	auto added = co_await c->add({
	  .entry = ldap::dn{ "uid=jane,ou=people,dc=example,dc=org" },
	  .attributes = { { "objectClass", { "inetOrgPerson" } },
		{ "uid", { "jane" } },
		{ "cn", { "Jane Doe" } },
		{ "sn", { "Doe" } } },
	});
	if (!added) {
		std::cerr << added.error().message() << '\n';
		co_return 1;
	}
	std::cout << "added uid=jane,ou=people,dc=example,dc=org\n";
	co_return 0;
}

auto main(int argc, char *const *argv) -> int
{
	boost::corosio::io_context ioc;
	int rc = 1;
	boost::capy::run_async(ioc.get_executor(), [&](int r) { rc = r; })(
	  run(ioc, argc > 1 ? argv[1] : "ldap://localhost"));
	ioc.run();
	return rc;
}
