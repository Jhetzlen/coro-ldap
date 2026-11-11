#include "jhetz/ldap/referral_chase.hpp"

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
	const auto connector = ldap::make_same_policy_connector(ioc, *c, {}, { "example.org" });
	auto people = co_await ldap::chase_search(*c,
	  {
		.base = ldap::dn{ "dc=example,dc=org" },
		.filter = ldap::filters::attr("uid").starts_with("user00"),
	  },
	  connector);
	if (!people) {
		std::cerr << people.error().message() << '\n';
		co_return 1;
	}
	for (const ldap::entry &person : people->entries) {
		std::cout << person.dn << '\n';
	}
	if (!people->is_complete()) {
		std::cerr << "the result is partial\n";
	}
	co_return 0;
}

auto main(int argc, char *const *argv) -> int
{
	boost::corosio::io_context ioc;
	return ldap::run(ioc, example(ioc, argc > 1 ? argv[1] : "ldap://localhost"));
}
