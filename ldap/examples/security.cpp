// Security: ldaps://, StartTLS, and SASL EXTERNAL (over ldapi:// or with a
// TLS client certificate).
//
//   jhetz_ldap_example_security
//
// Each part runs when its settings are present, and prints who the server
// thinks we are ("Who am I?", RFC 4532):
//
//   LDAPS_URL         ldaps://localhost      ldaps:// with a simple bind
//   LDAP_URL          ldap://localhost       StartTLS, then a simple bind
//   LDAP_CA_FILE      (system trust store)   CA certificates (PEM)
//   LDAP_TLS_NAME     (the URL's host)       name the certificate must match
//   LDAP_BIND_DN      cn=admin,dc=example,dc=org
//   LDAP_PASSWORD     secret
//   LDAPI_URL         (skipped if unset)     SASL EXTERNAL over a Unix socket,
//                                            e.g. ldapi://%2Fvar%2Frun%2Fslapd%2Fldapi
//   LDAP_CLIENT_CERT, LDAP_CLIENT_KEY        SASL EXTERNAL with a client
//                     (skipped if unset)     certificate, over LDAPS_URL
//
// The server needs TLS set up (a certificate the client can verify) for the
// first two parts; set an empty variable to skip a part. The defaults verify
// everything: the chain up to a trusted CA and the host name. Turning that
// off takes an explicit tls_options::verification =
// certificate_verification::insecure_accept_any, for tests only.
#include "jhetz/ldap/connection.hpp"

#include <boost/capy/ex/run_async.hpp>
#include <boost/corosio/io_context.hpp>

#include <cstdio>
#include <cstdlib>
#include <exception>
#include <format>
#include <string>
#include <utility>

namespace ldap = jhetz::ldap;
namespace capy = boost::capy;
namespace corosio = boost::corosio;

namespace {

template<class... Args> void println(std::FILE *f, std::format_string<Args...> fmt, Args &&...args)
{
	std::string line = std::format(fmt, std::forward<Args>(args)...);
	line += '\n';
	std::fwrite(line.data(), 1, line.size(), f);
}

// An unset variable gives the fallback, an empty one stays empty.
std::string setting(const char *name, const char *fallback)
{
	const char *v = std::getenv(name);
	return v != nullptr ? v : fallback;
}

enum class auth { simple, external };

// Connects to `url_text` (upgrading with StartTLS when asked),
// authenticates, and prints the identity. False on any failure.
capy::task<bool> session(corosio::io_context &ioc,
  const char *label,
  std::string url_text,
  ldap::net::tls_options tls,
  bool start_tls,
  auth how)
{
	auto u = ldap::url::parse(url_text);
	if (!u) {
		println(stderr, "{}: {}", label, u.error().message());
		co_return false;
	}
	ldap::connection_options options;
	options.tls = tls;// used by ldaps:// at connect time
	// connection_options::start_tls = true would upgrade inside connect();
	// here it is done by hand to show the call.
	auto c = co_await ldap::connect(ioc, std::move(*u), options);
	if (!c) {
		// TLS problems (untrusted CA, name mismatch) match cond::tls_failure
		// and say what failed in the context.
		println(stderr, "{}: {}", label, c.error().message());
		co_return false;
	}
	if (start_tls) {
		// Upgrades the plain connection in place, with the same checks as
		// ldaps://. Must be done before binding, with nothing outstanding.
		if (auto r = co_await c->start_tls(std::move(tls)); !r) {
			println(stderr, "{}: StartTLS: {}", label, r.error().message());
			co_return false;
		}
	}

	if (how == auth::simple) {
		auto name = ldap::dn::parse(setting("LDAP_BIND_DN", "cn=admin,dc=example,dc=org"));
		if (!name) {
			println(stderr, "{}: LDAP_BIND_DN: {}", label, name.error().message());
			co_return false;
		}
		if (auto r = co_await c->simple_bind(std::move(*name), setting("LDAP_PASSWORD", "secret")); !r) {
			println(stderr, "{}: bind: {}", label, r.error().message());
			co_return false;
		}
	} else {
		// EXTERNAL: no password; the server takes the identity from the
		// client certificate or from the ldapi:// peer's uid / gid. The
		// mechanism object must outlive the bind.
		ldap::sasl_external mech;
		if (auto r = co_await c->sasl_bind(mech); !r) {
			println(stderr, "{}: SASL EXTERNAL bind: {}", label, r.error().message());
			co_return false;
		}
	}

	auto me = co_await c->who_am_i();
	if (!me) {
		println(stderr, "{}: who_am_i: {}", label, me.error().message());
		co_return false;
	}
	println(stdout, "{}: {} as \"{}\"", label, c->is_tls() ? "TLS" : "no TLS", *me);
	(void)co_await c->unbind();
	co_return true;
}

capy::task<int> run(corosio::io_context &ioc)
{
	ldap::net::tls_options tls;
	tls.ca_file = setting("LDAP_CA_FILE", "");// empty: the system trust store
	tls.server_name = setting("LDAP_TLS_NAME", "");// empty: the URL's host

	int failures = 0;
	if (auto url = setting("LDAPS_URL", "ldaps://localhost"); !url.empty())
		failures += !co_await session(ioc, "ldaps", url, tls, false, auth::simple);
	if (auto url = setting("LDAP_URL", "ldap://localhost"); !url.empty())
		failures += !co_await session(ioc, "StartTLS", url, tls, true, auth::simple);
	if (auto url = setting("LDAPI_URL", ""); !url.empty())
		failures += !co_await session(ioc, "ldapi EXTERNAL", url, tls, false, auth::external);

	const std::string cert = setting("LDAP_CLIENT_CERT", "");
	const std::string url = setting("LDAPS_URL", "ldaps://localhost");
	if (!cert.empty() && !url.empty()) {
		ldap::net::tls_options with_cert = tls;
		with_cert.cert_file = cert;// PEM certificate chain
		with_cert.key_file = setting("LDAP_CLIENT_KEY", "");// its PEM private key
		failures += !co_await session(ioc, "certificate EXTERNAL", url, std::move(with_cert), false, auth::external);
	}
	co_return failures == 0 ? 0 : 1;
}

}// namespace

int main()
{
	corosio::io_context ioc;
	int status = 1;
	capy::run_async(
	  ioc.get_executor(),
	  [&status](int s) { status = s; },
	  [](std::exception_ptr e) {
		  try {
			  std::rethrow_exception(e);
		  } catch (const std::exception &x) {
			  println(stderr, "exception: {}", x.what());
		  }
	  })(run(ioc));
	ioc.run();
	return status;
}
