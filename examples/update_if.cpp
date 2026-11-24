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
	ldap::repository people(*c, ldap::dn{ "ou=people,dc=example,dc=org" }, ldap::named_by<&person::uid>);
	auto found = co_await people.require("user001");
	if (!found) {
		std::cerr << found.error().message() << '\n';
		co_return 1;
	}
	person changed = *found;
	changed.mail = "first.user@example.org";
	auto updated = co_await people.update_if(*found, changed);
	if (!updated && updated.error().code == ldap::errc::assertion_failed) {
		std::cerr << "uid=user001 changed since it was read: read it again and retry\n";
		co_return 1;
	}
	if (!updated) {
		std::cerr << updated.error().message() << '\n';
		co_return 1;
	}
	std::cout << "set the mail of uid=user001, which nobody had changed meanwhile\n";
	co_return 0;
}

auto main(int argc, char *const *argv) -> int { return ldap::run(example, argc > 1 ? argv[1] : "ldap://localhost"); }
