#include "common.hpp"

auto main() -> int
{
	auto a = ldap::replace<&person::mail>("x@example.org");
	auto b = ldap::add<&person::member_of>(ldap::dn{ "cn=g,dc=example,dc=org" });
	auto c = ldap::replace<&person::member_of>(std::vector<ldap::dn>{});
	auto d = ldap::replace<&person::uid_number>(5);
	auto e = ldap::remove<&person::mail>();
	auto f = ldap::filters::field<&person::uid_number>() >= 5;
	auto g = ldap::to_attributes(person{});
	std::vector<ldap::change<person>> changes{ a, b, c, d, e };
	(void)f;
	(void)g;
	return static_cast<int>(changes.size());
}
