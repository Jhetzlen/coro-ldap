#include "jhetz/ldap/client.hpp"

#include <boost/corosio/io_context.hpp>

#include <iostream>

namespace ldap = jhetz::ldap;

auto example(boost::corosio::io_context &ioc, ldap::url server) -> boost::capy::task<int>
{
	ldap::client pool(ioc,
	  { .servers = { server }, .setup = ldap::simple_bind_setup(ldap::dn{ "cn=admin,dc=example,dc=org" }, "secret") });
	auto people = co_await pool.search({
	  .base = ldap::dn{ "ou=people,dc=example,dc=org" },
	  .filter = ldap::filters::attr("uid").starts_with("user00"),
	  .attributes = { "cn" },
	});
	if (!people) {
		std::cerr << people.error().message() << '\n';
		co_return 1;
	}
	for (const ldap::entry &person : people->entries) {
		std::cout << person.dn << ": " << person.find("cn")->front() << '\n';
	}
	co_return 0;
}

auto main(int argc, char *const *argv) -> int
{
	auto server = ldap::url::parse_server(argc > 1 ? argv[1] : "ldap://localhost");
	if (!server) {
		std::cerr << server.error().message() << '\n';
		return 1;
	}
	boost::corosio::io_context ioc;
	return ldap::run(ioc, example(ioc, *server));
}
