#include "jhetz/ldap/connection.hpp"

#include <boost/capy/ex/run_async.hpp>
#include <boost/capy/when_all.hpp>
#include <boost/corosio/io_context.hpp>

#include <iostream>
#include <string>
#include <vector>

namespace ldap = jhetz::ldap;
namespace capy = boost::capy;

capy::task<ldap::result<int>> list(boost::corosio::io_context &ioc, ldap::url url, std::string prefix)
{
	auto c = co_await ldap::connect(ioc, url);
	if (!c) co_return std::unexpected(c.error());
	auto pages = co_await c->search_paged(
	  {
		.base = ldap::dn{ "ou=people,dc=example,dc=org" },
		.filter = ldap::filters::attr("uid").starts_with(prefix),
		.attributes = { "cn", "sn" },
		.controls = { ldap::server_side_sort{
		  .keys = { { .attribute = "sn", .ordering_rule = "caseIgnoreOrderingMatch", .reverse = true } } } },
	  },
	  20);
	if (!pages) co_return std::unexpected(pages.error());
	int count = 0;
	for (;;) {
		auto e = co_await pages->next();
		if (!e) co_return std::unexpected(e.error());
		if (!*e) co_return count;
		std::cout << prefix << " page " << pages->pages() << ": " << (*e)->find("sn")->front() << ' ' << (*e)->dn
				  << '\n';
		++count;
	}
}

capy::task<int> run(boost::corosio::io_context &ioc, std::string text)
{
	auto url = ldap::url::parse(text);
	if (!url) {
		std::cerr << url.error().message() << '\n';
		co_return 1;
	}
	std::vector<capy::task<capy::io_result<ldap::result<int>>>> searches;
	for (std::string prefix : { "user0", "user1", "user2" })
		searches.push_back(ldap::raceable(list(ioc, *url, prefix)));
	auto [ec, counts] = co_await capy::when_all(std::move(searches));
	for (auto &n : counts) {
		if (n)
			std::cout << *n << " entries\n";
		else
			std::cerr << n.error().message() << '\n';
	}
	co_return 0;
}

int main(int argc, char **argv)
{
	boost::corosio::io_context ioc;
	int rc = 1;
	boost::capy::run_async(ioc.get_executor(), [&](int r) { rc = r; })(
	  run(ioc, argc > 1 ? argv[1] : "ldap://localhost"));
	ioc.run();
	return rc;
}
