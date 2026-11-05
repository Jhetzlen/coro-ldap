// Uses the installed headers and libraries: the codec always (with the
// operations.hpp mod:: builders and the ad/ headers), the connection and
// jhetz::ldap_ad with WITH_NET (a connect that must be refused: no server)
// and SCRAM's SASLprep (links ICU through the package).
#include "jhetz/ldap/ad/filetime.hpp"
#include "jhetz/ldap/ad/root_dse.hpp"
#include "jhetz/ldap/dn.hpp"
#include "jhetz/ldap/filter.hpp"
#include "jhetz/ldap/message.hpp"
#include "jhetz/ldap/operations.hpp"

#ifdef WITH_NET
#include "jhetz/ldap/connection.hpp"
#include "jhetz/ldap/sasl_scram.hpp"

#include <boost/capy/ex/run_async.hpp>
#include <boost/corosio/io_context.hpp>
#endif

#include <cstdio>
#include <initializer_list>
#include <string_view>

namespace ldap = jhetz::ldap;

auto main() -> int
{
	const ldap::dn base{ "ou=people,dc=example,dc=org" };
	const auto f = ldap::filters::attr("uid") == "jdoe";
	const auto bytes =
	  ldap::encode(ldap::message{ 1, ldap::search_request{ base.to_string(), ldap::search_scope::whole_subtree, f } });
	if (!bytes || f.to_string() != "(uid=jdoe)") {
		std::puts("codec: unexpected result");
		return 1;
	}
	const auto change = ldap::mod::replace("mail", { "x" });
	if (change.operation != ldap::modify_operation::replace || change.modification.type != "mail"
		|| change.modification.values.size() != 1) {
		std::puts("codec: unexpected mod::replace result");
		return 1;
	}
	ldap::entry dse;
	dse.attributes.emplace_back(ldap::attribute::unchecked("supportedCapabilities"),
	  std::initializer_list<std::string_view>{ ldap::ad::ds_capability_oid });
	const auto expires = ldap::value_traits<ldap::ad::filetime_clock::time_point>::decode("0");
	if (!ldap::ad::is_active_directory(dse) || !expires || !ldap::ad::is_never(*expires)) {
		std::puts("codec: unexpected ad result");
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
	// "I" U+00AD "X": SASLprep maps the soft hyphen to nothing.
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
	std::puts("ok");
	return 0;
}
