#include "jhetz/ldap/connection.hpp"

#include <boost/corosio/io_context.hpp>

#include <iostream>
#include <string>

namespace ldap = jhetz::ldap;

constexpr int page_size = 100;

auto example(boost::corosio::io_context &ioc, std::string text) -> boost::capy::task<int>
{
	auto c = co_await ldap::connect(ioc, text);
	if (!c) {
		std::cerr << c.error().message() << '\n';
		co_return 1;
	}
	auto pages = co_await ldap::search_paged_stream(*c,
	  {
		.base = ldap::dn{ "ou=people,dc=example,dc=org" },
		.filter = ldap::filters::attr("mail").present(),
		.attributes = { "mail" },
		.controls = { ldap::server_side_sort{
		  .keys = { { .attribute = "mail", .ordering_rule = "caseIgnoreOrderingMatch" } } } },
	  },
	  page_size);
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
		if (!*person) {
			co_return 0;
		}
		std::cout << "page " << pages->page_count() << ": " << (*person)->find("mail")->front() << '\n';
	}
}

auto main(int argc, char *const *argv) -> int { return ldap::run(example, argc > 1 ? argv[1] : "ldap://localhost"); }
