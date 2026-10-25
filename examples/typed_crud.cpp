#include "jhetz/ldap/connection.hpp"

#include <boost/capy/ex/run_async.hpp>
#include <boost/corosio/io_context.hpp>

#include <iostream>
#include <optional>
#include <string>

namespace ldap = jhetz::ldap;

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

auto run(boost::corosio::io_context &ioc, std::string text) -> boost::capy::task<int>
{
	auto c = co_await ldap::connect(ioc, text, { .schema_check = ldap::schema_check::on_first_use });
	if (!c) {
		std::cerr << c.error().message() << '\n';
		co_return 1;
	}
	auto bound = co_await c->simple_bind(ldap::dn{ "cn=admin,dc=example,dc=org" }, "secret");
	if (!bound) {
		std::cerr << bound.error().message() << '\n';
		co_return 1;
	}
	auto added = co_await c->add(ldap::dn{ "uid=jdoe,ou=people,dc=example,dc=org" },
	  person{ .uid = "jdoe", .cn = "John Doe", .sn = "Doe", .mail = "jdoe@example.org" });
	if (!added) {
		std::cerr << added.error().message() << '\n';
		co_return 1;
	}
	std::cout << "added uid=jdoe,ou=people,dc=example,dc=org\n";
	auto modified = co_await c->modify<person>(
	  ldap::dn{ "uid=jdoe,ou=people,dc=example,dc=org" }, { ldap::replace<&person::mail>("john.doe@example.org") });
	if (!modified) {
		std::cerr << modified.error().message() << '\n';
		co_return 1;
	}
	std::cout << "changed the mail of uid=jdoe,ou=people,dc=example,dc=org\n";
	auto deleted = co_await c->del({ .entry = ldap::dn{ "uid=jdoe,ou=people,dc=example,dc=org" } });
	if (!deleted) {
		std::cerr << deleted.error().message() << '\n';
		co_return 1;
	}
	std::cout << "deleted uid=jdoe,ou=people,dc=example,dc=org\n";
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
