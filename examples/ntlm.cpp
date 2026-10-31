#include "jhetz/ldap/connection.hpp"
#include "jhetz/ldap/sasl_ntlm.hpp"

#include <boost/capy/ex/run_async.hpp>
#include <boost/corosio/io_context.hpp>

#include <iostream>

namespace ldap = jhetz::ldap;

auto run(boost::corosio::io_context &ioc, char *const *argv) -> boost::capy::task<int>
{
	auto c = co_await ldap::connect(ioc, argv[1]);
	if (!c) {
		std::cerr << c.error().message() << '\n';
		co_return 1;
	}
	ldap::sasl_ntlm ntlm(argv[2], argv[3]);
	auto bound = co_await c->sasl_bind(ntlm);
	if (!bound) {
		std::cerr << bound.error().message() << '\n';
		co_return 1;
	}
	auto me = co_await c->who_am_i();
	if (!me) {
		std::cerr << me.error().message() << '\n';
		co_return 1;
	}
	std::cout << "bound as " << *me << '\n';
	co_return 0;
}

auto main(int argc, char *const *argv) -> int
{
	if (argc != 4) {
		std::cerr << "usage: ntlm ldaps://dc1.example.org 'EXAMPLE\\jdoe' password\n";
		return 2;
	}
	boost::corosio::io_context ioc;
	int rc = 1;
	boost::capy::run_async(ioc.get_executor(), [&](int r) { rc = r; })(run(ioc, argv));
	ioc.run();
	return rc;
}
