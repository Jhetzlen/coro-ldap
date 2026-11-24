#include "jhetz/ldap/client.hpp"

#include <boost/corosio/io_context.hpp>

#include <iostream>
#include <string>

namespace ldap = jhetz::ldap;

auto example(boost::corosio::io_context &ioc, std::string server) -> boost::capy::task<int>
{
	ldap::client pool(ioc,
	  { .server_urls = { std::move(server) },
		.connection = { .allow_cleartext_passwords = true },
		.setup = ldap::simple_bind_setup(ldap::dn{ "cn=admin,dc=example,dc=org" }, "secret") });
	auto people = co_await pool.search({
	  .base = ldap::dn{ "ou=people,dc=example,dc=org" },
	  .filter = ldap::filters::attr("uid").starts_with("user00"),
	  .attributes = { "cn" },
	});
	if (!people) {
		std::cerr << people.error().message() << '\n';
		co_return 1;
	}
	if (!people->is_complete()) {
		std::cerr << "the result is partial: result code " << people->result_code << ", " << people->references.size()
				  << " references not followed\n";
	}
	for (const ldap::entry &person : people->entries) {
		std::cout << person.dn << ": " << person.find("cn")->front() << '\n';
	}
	co_return 0;
}

auto main(int argc, char *const *argv) -> int
{
	boost::corosio::io_context ioc;
	return ldap::run(ioc, example(ioc, argc > 1 ? argv[1] : "ldap://localhost"));
}
