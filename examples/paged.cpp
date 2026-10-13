#include "jhetz/ldap/connection.hpp"

#include <boost/capy/ex/run_async.hpp>
#include <boost/corosio/io_context.hpp>

#include <iostream>
#include <string>

namespace ldap = jhetz::ldap;

boost::capy::task<int> run(boost::corosio::io_context &ioc, std::string text)
{
	auto c = co_await ldap::connect(ioc, text);
	if (!c) {
		std::cerr << c.error().message() << '\n';
		co_return 1;
	}
	auto pages = co_await c->search_paged(
	  {
		.base = ldap::dn{ "ou=people,dc=example,dc=org" },
		.filter = ldap::filters::attr("mail").present(),
		.attributes = { "mail" },
		.controls = { ldap::server_side_sort{
		  .keys = { { .attribute = "mail", .ordering_rule = "caseIgnoreOrderingMatch" } } } },
	  },
	  100);
	if (!pages) {
		std::cerr << pages.error().message() << '\n';
		co_return 1;
	}
	for (;;) {
		auto person = co_await pages->next();
		if (!person) {
			std::cerr << person.error().message() << '\n';
			co_return 1;
		}
		if (!*person) co_return 0;
		std::cout << "page " << pages->pages() << ": " << (*person)->find("mail")->front() << '\n';
	}
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
