// Uses the installed headers and libraries: the codec, and with WITH_NET
// the connection, jhetz::ldap_ad and SCRAM's SASLprep.
#include "jhetz/ldap/ad/filetime.hpp"
#include "jhetz/ldap/ad/password_value.hpp"
#include "jhetz/ldap/ad/sid.hpp"
#include "jhetz/ldap/dn.hpp"
#include "jhetz/ldap/filter.hpp"
#include "jhetz/ldap/message.hpp"
#include "jhetz/ldap/operations.hpp"

#ifdef WITH_NET
#include "jhetz/ldap/ad/discover.hpp"
#include "jhetz/ldap/ad/password.hpp"
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
#include <system_error>
#include <vector>

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
	const auto expires = ldap::value_traits<ldap::ad::filetime_clock::time_point>::decode("0");
	if (!expires || !ldap::ad::is_never(*expires)
		|| ldap::ad::password_value("ab") != std::string_view("\"\0a\0b\0\"\0", 8)
		|| ldap::ad::sid::parse("S-1-5-32-544").value_or(ldap::ad::sid{}).to_binary().size() != 16) {
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
	// jhetz::ldap_ad: a reset on a connection that is not open.
	ldap::connection none;
	std::error_code refused;
	boost::capy::run_async(ioc.get_executor(), [&](ldap::result<void> r) {
		if (!r) {
			refused = r.error().code;
		}
	})(ldap::ad::reset_password(none, ldap::dn{ "cn=x" }, "pw"));
	ioc.restart();
	ioc.run();
	// The library's error category against the consumer's condition.
	if (refused != ldap::cond::connection_lost) {
		std::puts("ad: expected the reset to fail with cond::connection_lost");
		return 1;
	}
	// jhetz::ldap_ad's discovery (ICU, the resolver library) with a scripted
	// resolver.
	auto dcs = ldap::ad::discover_domain_controllers(
	  "example.org", { .resolver = [](std::string_view) -> ldap::result<std::vector<ldap::ad::srv_record>> {
		  return std::vector<ldap::ad::srv_record>{ { .port = 389, .target = "dc1.example.org" } };
	  } });
	if (!dcs || dcs->size() != 1) {
		std::puts("ad: unexpected discovery result");
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
#ifdef WITH_GSSAPI
	ldap::sasl_gssapi gss;
	if (gss.name() != "GSSAPI") {
		std::puts("gssapi: unexpected mechanism name");
		return 1;
	}
#endif
	std::puts("ok");
	return 0;
}
