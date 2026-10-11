#include "jhetz/ldap/connection.hpp"

#include <boost/capy/ex/run_async.hpp>
#include <boost/corosio/io_context.hpp>

#include <iostream>
#include <string>

namespace ldap = jhetz::ldap;

boost::capy::task<> run(boost::corosio::io_context &ioc, std::string text)
{
	auto url = ldap::url::parse(text);
	if (!url) {
		std::cerr << url.error().message() << '\n';
		co_return;
	}
	auto c = co_await ldap::connect(ioc, *url);
	if (!c) {
		std::cerr << c.error().message() << '\n';
		co_return;
	}
	auto bound = co_await c->simple_bind(ldap::dn{ "cn=admin,dc=example,dc=org" }, "secret");
	if (!bound) {
		std::cerr << bound.error().message() << '\n';
		co_return;
	}
	auto modified = co_await c->modify({
	  .object = ldap::dn{ "uid=user001,ou=people,dc=example,dc=org" },
	  .changes = { ldap::mod::replace("mail", { "new.address@example.org" }) },
	});
	if (!modified) {
		std::cerr << modified.error().message() << '\n';
		co_return;
	}
	std::cout << "changed the mail of uid=user001,ou=people,dc=example,dc=org\n";
}

int main(int argc, char **argv)
{
	boost::corosio::io_context ioc;
	boost::capy::run_async(ioc.get_executor())(run(ioc, argc > 1 ? argv[1] : "ldap://localhost"));
	ioc.run();
}
