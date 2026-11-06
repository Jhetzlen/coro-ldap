#include "jhetz/ldap/connection.hpp"
#include "jhetz/ldap/extended_operations.hpp"
#include "jhetz/ldap/sasl_gssapi.hpp"

#include <boost/capy/ex/run_async.hpp>
#include <boost/corosio/io_context.hpp>

#include <iostream>
#include <string>

namespace ldap = jhetz::ldap;

auto run(boost::corosio::io_context &ioc, std::string text) -> boost::capy::task<int>
{
	auto c = co_await ldap::connect(ioc, text, { .start_tls = true });
	if (!c) {
		std::cerr << c.error().message() << '\n';
		co_return 1;
	}
	ldap::sasl_gssapi kerberos;
	auto bound = co_await c->sasl_bind(kerberos);
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
	boost::corosio::io_context ioc;
	int rc = 1;
	boost::capy::run_async(ioc.get_executor(), [&](int r) { rc = r; })(
	  run(ioc, argc > 1 ? argv[1] : "ldap://localhost"));
	ioc.run();
	return rc;
}
