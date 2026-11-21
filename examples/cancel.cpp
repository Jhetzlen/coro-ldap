#include "jhetz/ldap/connection.hpp"

#include <boost/capy/when_any.hpp>
#include <boost/corosio/io_context.hpp>
#include <boost/corosio/signal_set.hpp>

#include <csignal>
#include <iostream>
#include <string>
#include <variant>

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
	boost::corosio::signal_set ctrl_c(ioc, SIGINT);
	auto raced = co_await boost::capy::when_any(
	  ldap::raceable(c->search({ .base = ldap::dn{ "dc=example,dc=org" } })), ctrl_c.wait());
	if (raced.index() != 1) {
		std::cerr << "interrupted: the search was abandoned\n";
		co_return 1;
	}
	auto &everything = std::get<1>(raced);
	if (!everything) {
		std::cerr << everything.error().message() << '\n';
		co_return 1;
	}
	std::cout << everything->entries.size() << " entries under dc=example,dc=org\n";
	co_return 0;
}

auto main(int argc, char *const *argv) -> int
{
	boost::corosio::io_context ioc;
	return ldap::run(ioc, example(ioc, argc > 1 ? argv[1] : "ldap://localhost"));
}
