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
	auto people = co_await c->search({
	  .base = ldap::dn{ "ou=people,dc=example,dc=org" },
	  .filter = ldap::filters::attr("uid").starts_with("user00"),
	  .attributes = { "cn" },
	});
	if (!people) {
		std::cerr << people.error().message() << '\n';
		co_return;
	}
	for (const ldap::entry &person : *people) std::cout << person.dn << ": " << person.find("cn")->front() << '\n';
}

int main(int argc, char **argv)
{
	boost::corosio::io_context ioc;
	boost::capy::run_async(ioc.get_executor())(run(ioc, argc > 1 ? argv[1] : "ldap://localhost"));
	ioc.run();
}
