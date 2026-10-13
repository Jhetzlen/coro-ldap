#include "jhetz/ldap/connection.hpp"

#include <boost/capy/ex/run_async.hpp>
#include <boost/corosio/io_context.hpp>

#include <iostream>
#include <string>

namespace ldap = jhetz::ldap;

boost::capy::task<int> run(boost::corosio::io_context &ioc, std::string text)
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
	auto reset = co_await c->reset_password(ldap::dn{ "uid=user001,ou=people,dc=example,dc=org" }, "a new pässword");
	if (!reset) {
		std::cerr << reset.error().message() << '\n';
		co_return 1;
	}
	std::cout << "reset the password of uid=user001,ou=people,dc=example,dc=org\n";
	co_return 0;
}

int main(int argc, char **argv)
{
	boost::corosio::io_context ioc;
	int rc = 1;
	boost::capy::run_async(ioc.get_executor(), [&](int r) { rc = r; })(
	  run(ioc, argc > 1 ? argv[1] : "ldap://localhost"));
	ioc.run();
	return rc;
}
