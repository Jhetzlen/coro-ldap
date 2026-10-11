// Read a large result one entry at a time, in pages of 100 (RFC 2696).
//   jhetz_ldap_example_streaming [ldap://localhost]
#include "jhetz/ldap/connection.hpp"

#include <boost/capy/ex/run_async.hpp>
#include <boost/corosio/io_context.hpp>

#include <iostream>
#include <string>

namespace ldap = jhetz::ldap;

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

	// search_stream() is the same without paging. "1.1": DNs only.
	auto s = co_await c->search_paged({ .base = ldap::dn{ "dc=example,dc=org" }, .attributes = { "1.1" } }, 100);
	if (!s) co_return fail(s.error());
	int count = 0;
	while (true) {
		auto e = co_await s->next();// an entry, nullopt at the end, or an error
		if (!e) co_return fail(e.error());
		if (!*e) break;
		std::cout << (*e)->dn << '\n';
		++count;
	}
	std::cout << count << " entries in " << s->pages() << " pages\n";
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
