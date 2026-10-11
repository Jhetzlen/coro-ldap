// StartTLS, then a simple bind over the encrypted connection.
//   jhetz_ldap_example_security [ldap://localhost [CA_FILE]]
#include "jhetz/ldap/connection.hpp"

#include <boost/capy/ex/run_async.hpp>
#include <boost/corosio/io_context.hpp>

#include <iostream>
#include <string>

namespace ldap = jhetz::ldap;

static int fail(const ldap::error &e)
{
	std::cerr << e.message() << '\n';
	return 1;
}

static boost::capy::task<int> run(boost::corosio::io_context &ioc, std::string url, std::string ca_file)
{
	auto u = ldap::url::parse(url);
	if (!u) co_return fail(u.error());
	// The certificate chain and host name are always verified; without a CA
	// file, against the system trust store. For ldaps:// leave start_tls off.
	ldap::connection_options options{ .start_tls = true };
	options.tls.ca_file = ca_file;
	auto c = co_await ldap::connect(ioc, *u, options);
	if (!c) co_return fail(c.error());
	if (auto r = co_await c->simple_bind(ldap::dn{ "cn=admin,dc=example,dc=org" }, "secret"); !r)
		co_return fail(r.error());

	// SASL EXTERNAL (ldap::sasl_external with c->sasl_bind) would instead use
	// a client certificate (options.tls.cert_file / key_file) or ldapi://.
	auto me = co_await c->who_am_i();
	if (!me) co_return fail(me.error());
	std::cout << (c->is_tls() ? "TLS" : "no TLS") << ", bound as " << *me << '\n';
	(void)co_await c->unbind();
	co_return 0;
}

int main(int argc, char **argv)
{
	boost::corosio::io_context ioc;
	int status = 1;
	boost::capy::run_async(ioc.get_executor(), [&](int s) { status = s; })(
	  run(ioc, argc > 1 ? argv[1] : "ldap://localhost", argc > 2 ? argv[2] : ""));
	ioc.run();
	return status;
}
