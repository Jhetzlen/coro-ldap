#include "jhetz/ldap/connection.hpp"
#include "jhetz/ldap/repository.hpp"

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

auto example(boost::corosio::io_context &ioc, std::string text) -> boost::capy::task<int>
{
	auto c = co_await ldap::connect(ioc, text);
	if (!c) {
		std::cerr << c.error().message() << '\n';
		co_return 1;
	}
	auto bound = co_await c->simple_bind(ldap::dn{ "cn=admin,dc=example,dc=org" }, "secret");
	if (!bound) {
		std::cerr << bound.error().message() << '\n';
		co_return 1;
	}
	ldap::repository people(*c,
	  ldap::dn{ "ou=people,dc=example,dc=org" },
	  ldap::named_by<&person::uid>,
	  { .schema_check = ldap::schema_check::on_first_use });
	auto added =
	  co_await people.add(person{ .uid = "jdoe", .cn = "John Doe", .sn = "Doe", .mail = "jdoe@example.org" });
	if (!added) {
		std::cerr << added.error().message() << '\n';
		co_return 1;
	}
	std::cout << "added uid=jdoe\n";
	auto modified = co_await people.modify("jdoe", { ldap::replace<&person::mail>("john.doe@example.org") });
	if (!modified) {
		std::cerr << modified.error().message() << '\n';
		co_return 1;
	}
	auto found = co_await people.get("jdoe");
	if (!found || !*found) {
		std::cerr << "uid=jdoe not found\n";
		co_return 1;
	}
	std::cout << "uid=jdoe's mail is " << (*found)->mail.value_or("") << '\n';
	auto removed = co_await people.remove("jdoe");
	if (!removed) {
		std::cerr << removed.error().message() << '\n';
		co_return 1;
	}
	std::cout << "deleted uid=jdoe\n";
	co_return 0;
}

auto main(int argc, char *const *argv) -> int { return ldap::run(example, argc > 1 ? argv[1] : "ldap://localhost"); }
