#include "jhetz/ldap/ad/dirsync.hpp"
#include "jhetz/ldap/connection.hpp"

#include <boost/corosio/io_context.hpp>

#include <fstream>
#include <iostream>
#include <iterator>
#include <string>

namespace ldap = jhetz::ldap;

auto example(boost::corosio::io_context &ioc, std::string text) -> boost::capy::task<int>
{
	auto c = co_await ldap::connect(ioc, text);
	if (!c) {
		std::cerr << c.error().message() << '\n';
		co_return 1;
	}
	auto bound = co_await c->simple_bind(ldap::dn{ "cn=sync,cn=Users,dc=example,dc=org" }, "secret");
	if (!bound) {
		std::cerr << bound.error().message() << '\n';
		co_return 1;
	}
	std::ifstream saved("dirsync.cookie", std::ios::binary);
	std::string cookie{ std::istreambuf_iterator<char>(saved), {} };
	auto changes = co_await ldap::ad::dirsync(*c,
	  { .base = ldap::dn{ "dc=example,dc=org" } },
	  { .flags = ldap::ad::dirsync_flags::object_security, .cookie = std::move(cookie) });
	if (!changes) {
		std::cerr << changes.error().message() << '\n';
		co_return 1;
	}
	for (const auto &entry : changes->entries) {
		std::cout << (entry.find("isDeleted") != nullptr ? "deleted " : "changed ") << entry.dn << '\n';
	}
	std::ofstream("dirsync.cookie", std::ios::binary) << changes->cookie;
	std::cout << changes->cookie.size() << "-byte cookie saved for the next run\n";
	co_return 0;
}

auto main(int argc, char *const *argv) -> int
{
	return ldap::run(example, argc > 1 ? argv[1] : "ldaps://dc1.example.org");
}
