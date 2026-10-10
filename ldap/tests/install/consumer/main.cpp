// Uses the installed headers and libraries: the codec always, the
// connection with WITH_NET (a connect that must be refused: no server).
#include "jhetz/ldap/dn.hpp"
#include "jhetz/ldap/filter.hpp"
#include "jhetz/ldap/message.hpp"

#ifdef WITH_NET
#include "jhetz/ldap/connection.hpp"

#include <boost/capy/ex/run_async.hpp>
#include <boost/corosio/io_context.hpp>
#endif

#include <cstdio>

namespace ldap = jhetz::ldap;

int main()
{
	const ldap::dn base{ "ou=people,dc=example,dc=org" };
	const auto f = ldap::filters::attr("uid") == "jdoe";
	const auto bytes =
	  ldap::encode(ldap::message{ 1, ldap::search_request{ base.to_string(), ldap::search_scope::whole_subtree, f } });
	if (!bytes || f.to_string() != "(uid=jdoe)") {
		std::puts("codec: unexpected result");
		return 1;
	}
#ifdef WITH_NET
	boost::corosio::io_context ioc;
	bool failed = false;
	auto u = ldap::url::parse("ldap://127.0.0.1:1");
	boost::capy::run_async(ioc.get_executor(), [&](ldap::result<ldap::connection> c) {
		failed = !c;// nothing listens on port 1
	})(ldap::connect(ioc, *u, { .timeout = std::chrono::seconds(5) }));
	ioc.run();
	if (!failed) {
		std::puts("net: expected the connect to fail");
		return 1;
	}
#endif
	std::puts("ok");
	return 0;
}
