#include "jhetz/ldap/connection.hpp"
#include "jhetz/ldap/extended_operations.hpp"
#include "jhetz/ldap/sasl_ntlm.hpp"

#include <boost/corosio/io_context.hpp>

#include <cstdlib>
#include <iostream>

namespace ldap = jhetz::ldap;

auto example(boost::corosio::io_context &ioc, char *const *argv, const char *password) -> boost::capy::task<int>
{
	auto c = co_await ldap::connect(ioc, argv[1]);
	if (!c) {
		std::cerr << c.error().message() << '\n';
		co_return 1;
	}
	ldap::sasl_ntlm ntlm(argv[2], password);
	auto bound = co_await c->sasl_bind(ntlm);
	if (!bound) {
		std::cerr << bound.error().message() << '\n';
		co_return 1;
	}
	auto me = co_await ldap::who_am_i(*c);
	if (!me) {
		std::cerr << me.error().message() << '\n';
		co_return 1;
	}
	std::cout << "bound as " << *me << '\n';
	co_return 0;
}

auto main(int argc, char *const *argv) -> int
{
	// NOLINTNEXTLINE(concurrency-mt-unsafe): single-threaded, nothing calls setenv
	const char *password = std::getenv("LDAP_PASSWORD");
	if (argc != 3 || password == nullptr) {
		std::cerr << "usage: LDAP_PASSWORD=... ntlm ldaps://dc1.example.org 'EXAMPLE\\jdoe'\n";
		return 2;
	}
	return ldap::run(example, argv, password);
}
