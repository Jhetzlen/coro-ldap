// Connect, bind, search with a filter and print the entries.
//   jhetz_ldap_example_basics [ldap://localhost]
#include "jhetz/ldap/connection.hpp"

#include <boost/capy/ex/run_async.hpp>
#include <boost/corosio/io_context.hpp>

#include <iostream>
#include <string>

namespace ldap = jhetz::ldap;

// Operations return ldap::result<T> (std::expected): errors are values.
static int fail(const ldap::error &e)
{
	std::cerr << e.message() << '\n';
	return 1;
}

static boost::capy::task<int> run(boost::corosio::io_context &ioc, std::string url)
{
	auto u = ldap::url::parse(url);
	if (!u) co_return fail(u.error());
	auto c = co_await ldap::connect(ioc, *u);
	if (!c) co_return fail(c.error());
	if (auto r = co_await c->simple_bind(ldap::dn{ "cn=admin,dc=example,dc=org" }, "secret"); !r)
		co_return fail(r.error());

	// Filters are built as trees, so values never need escaping by hand.
	using ldap::filters::attr;
	auto entries = co_await c->search({
	  .base = ldap::dn{ "dc=example,dc=org" },
	  .filter = attr("objectClass") == "inetOrgPerson" && attr("uid").starts_with("user00"),
	  .attributes = { "cn", "mail" },
	});
	if (!entries) co_return fail(entries.error());
	for (const ldap::entry &e : *entries) {
		std::cout << e.dn << '\n';
		if (const auto *mail = e.find("mail"))
			for (const auto &m : *mail) std::cout << "  mail: " << m << '\n';
	}
	(void)co_await c->unbind();
	co_return 0;
}

int main(int argc, char **argv)
{
	boost::corosio::io_context ioc;
	int status = 1;
	boost::capy::run_async(ioc.get_executor(), [&](int s) { status = s; })(
	  run(ioc, argc > 1 ? argv[1] : "ldap://localhost"));
	ioc.run();
	return status;
}
