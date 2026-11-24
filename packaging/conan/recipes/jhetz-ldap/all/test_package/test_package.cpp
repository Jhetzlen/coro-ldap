#include "jhetz/ldap/ad/sid.hpp"
#include "jhetz/ldap/dn.hpp"
#include "jhetz/ldap/filter.hpp"
#include "jhetz/ldap/message.hpp"
#include "jhetz/ldap/operations.hpp"

#ifdef WITH_NET
#include "jhetz/ldap/ad/discover.hpp"
#include "jhetz/ldap/connection.hpp"
#include "jhetz/ldap/sasl_scram.hpp"

#ifdef WITH_GSSAPI
#include "jhetz/ldap/sasl_gssapi.hpp"
#endif

#include <boost/capy/ex/run_async.hpp>
#include <boost/corosio/io_context.hpp>
#endif

#include <cstdio>
#include <string_view>
#include <vector>

namespace ldap = jhetz::ldap;

auto main() -> int
{
	const ldap::dn base{ "ou=people,dc=example,dc=org" };
	const auto f = ldap::filters::attr("uid") == "jdoe";
	const auto bytes =
	  ldap::encode(ldap::message{ 1, ldap::search_request{ base.to_string(), ldap::search_scope::whole_subtree, f } });
	if (!bytes || f.to_string() != "(uid=jdoe)"
		|| ldap::ad::sid::parse("S-1-5-32-544").value_or(ldap::ad::sid{}).to_binary().size() != 16) {
		std::puts("codec: unexpected result");
		return 1;
	}
#ifdef WITH_NET
	boost::corosio::io_context ioc;
	bool failed = false;
	auto u = ldap::url::parse("ldap://127.0.0.1:1");
	boost::capy::run_async(ioc.get_executor(), [&](ldap::result<ldap::connection> c) { failed = !c; })(
	  ldap::connect(ioc, *u, { .timeout = std::chrono::seconds(5) }));
	ioc.run();
	if (!failed) {
		std::puts("net: expected the connect to fail");
		return 1;
	}
	auto dcs = ldap::ad::discover_domain_controllers(
	  "example.org", { .resolver = [](std::string_view) -> ldap::result<std::vector<ldap::ad::srv_record>> {
		  return std::vector<ldap::ad::srv_record>{ { .port = 389, .target = "dc1.example.org" } };
	  } });
	if (!dcs || dcs->size() != 1) {
		std::puts("ad: unexpected discovery result");
		return 1;
	}
	// SASLprep maps U+00AD to nothing.
	ldap::sasl_scram_sha256 mech(
	  "I\xC2\xAD"
	  "X",
	  "pencil");
	auto first = mech.start();
	if (!first || !*first || !(*first)->starts_with("n,,n=IX,r=")) {
		std::puts("net: unexpected SCRAM client-first-message");
		return 1;
	}
#endif
#ifdef WITH_GSSAPI
	ldap::sasl_gssapi gss;
	if (gss.name() != "GSSAPI") {
		std::puts("gssapi: unexpected mechanism name");
		return 1;
	}
#endif
	std::puts("jhetz-ldap ok");
	return 0;
}
