// Default trust anchors off Windows: OpenSSL's own (SSL_CERT_FILE,
// SSL_CERT_DIR, its compiled-in paths), re-read for every context.
#include "trust_store.hpp"

namespace jhetz::ldap::net::detail {

auto load_system_trust(boost::corosio::tls_context &ctx) -> result<void>
{
	if (const auto ec = ctx.set_default_verify_paths(); ec) {
		return fail(ec, "tls: system trust store");
	}
	return {};
}

}// namespace jhetz::ldap::net::detail
