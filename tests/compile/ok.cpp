#include "common.hpp"

#include "jhetz/ldap/operations.hpp"

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
	// The controls each operation's specification allows (the compile tests
	// *_on_* use one where it does not).
	const ldap::add_params add{ .controls = { ldap::post_read{}, ldap::relax_rules{} } };
	const ldap::del_params del{ .controls = { ldap::pre_read{}, ldap::control{ "1.2.3", false } } };
	const ldap::modify_params modify{ .controls = { ldap::pre_read{}, ldap::post_read{}, ldap::assertion{} } };
	const ldap::search_params search{ .controls = { ldap::paged{ .page_size = 10 }, ldap::server_side_sort{} } };
	(void)f;
	(void)g;
	(void)add;
	(void)del;
	(void)modify;
	(void)search;
	return static_cast<int>(changes.size());
}
