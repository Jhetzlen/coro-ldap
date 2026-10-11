// A C++ struct mapped to inetOrgPerson: add it, search for it, modify it.
//   jhetz_ldap_example_mapping [ldap://localhost]
#include "jhetz/ldap/mapping.hpp"
#include "jhetz/ldap/connection.hpp"

#include <boost/capy/ex/run_async.hpp>
#include <boost/corosio/io_context.hpp>

#include <iostream>
#include <optional>
#include <string>

namespace ldap = jhetz::ldap;

// T is required, std::optional<T> optional, std::vector<T> multi-valued.
struct person
{
	std::string uid;
	std::string cn;
	std::string sn;
	std::optional<std::string> mail;
};

template<>
constexpr auto ldap::schema<person> = ldap::describe(ldap::object_class("inetOrgPerson"),
  ldap::field<&person::uid>("uid"),
  ldap::field<&person::cn>("cn"),
  ldap::field<&person::sn>("sn"),
  ldap::field<&person::mail>("mail"));

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
	const ldap::dn dn = base.child(ldap::rdn{ "uid=jane" });
	const person jane{ .uid = "jane", .cn = "Jane Doe", .sn = "Doe", .mail = "jane@example.org" };
	if (auto r = co_await c->add(dn, jane); !r) co_return fail(r.error());// objectClass comes from the schema
	if (auto r = co_await c->modify<person>(dn, { ldap::replace<&person::mail>("jane.doe@example.org") }); !r)
		co_return fail(r.error());

	auto people = co_await c->search_as<person>({
	  .base = base,
	  .filter = ldap::filters::field<&person::uid>() == "jane",
	});
	if (!people) co_return fail(people.error());
	for (const person &p : *people) std::cout << p.uid << ": " << p.cn << ", " << p.mail.value_or("-") << '\n';

	if (auto r = co_await c->del({ .entry = dn }); !r) co_return fail(r.error());
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
