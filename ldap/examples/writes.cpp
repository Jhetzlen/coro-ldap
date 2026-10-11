// Add an entry, modify it, rename it and delete it.
//   jhetz_ldap_example_writes [ldap://localhost]
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

	const ldap::dn base{ "dc=example,dc=org" };
	const ldap::dn jane = base.child(ldap::rdn{ "uid=jane" });
	auto r = co_await c->add({
	  .entry = jane,
	  .attributes = { { "objectClass", { "inetOrgPerson" } },
		{ "uid", { "jane" } },
		{ "cn", { "Jane Doe" } },
		{ "sn", { "Doe" } } },
	});
	if (!r) co_return fail(r.error());

	// The changes are applied in order, all or nothing.
	r = co_await c->modify({
	  .object = jane,
	  .changes = { ldap::mod::add("mail", { "jane@example.org" }), ldap::mod::replace("cn", { "Jane Q. Doe" }) },
	});
	if (!r) co_return fail(r.error());

	// A new RDN renames; .new_superior would also move the entry.
	r = co_await c->modify_dn({ .entry = jane, .new_rdn = ldap::rdn{ "uid=jdoe" } });
	if (!r) co_return fail(r.error());

	r = co_await c->del({ .entry = base.child(ldap::rdn{ "uid=jdoe" }) });
	if (!r) co_return fail(r.error());
	std::cout << "added, modified, renamed and deleted " << jane.to_string() << '\n';
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
