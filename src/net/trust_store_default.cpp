// Default trust anchors off Windows: OpenSSL's own (SSL_CERT_FILE,
// SSL_CERT_DIR, its compiled-in paths), re-read for every context.
#include "trust_store.hpp"

#include <system_error>

namespace jhetz::ldap::net::detail {

auto load_system_trust(boost::corosio::tls_context &ctx) -> result<void>
{
	if (const auto ec = ctx.set_default_verify_paths(); ec) {
		return fail(ec, "tls: system trust store");
	}
	return {};
}

auto platform_verifies_chain() noexcept -> bool { return false; }

auto verify_system_chain(std::span<const std::vector<unsigned char>> /*chain*/,
  std::optional<std::chrono::milliseconds> /*timeout*/) -> result<void>
{
	return fail(std::make_error_code(std::errc::function_not_supported),
	  "system certificate chain: not available on this platform");
}

}// namespace jhetz::ldap::net::detail
