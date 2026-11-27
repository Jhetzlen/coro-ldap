// Opening a transport for an ldap://, ldaps:// or ldapi:// URL, with Happy
// Eyeballs (RFC 8305) and TLS (docs/API.md, "jhetz/ldap/net/connect.hpp").
#pragma once

#include "jhetz/ldap/error.hpp"
#include "jhetz/ldap/net/transport.hpp"
#include "jhetz/ldap/timeout.hpp"
#include "jhetz/ldap/url.hpp"

#include <boost/capy/task.hpp>
#include <boost/corosio/io_context.hpp>
#include <boost/corosio/tls_context.hpp>

#include <chrono>
#include <filesystem>
#include <memory_resource>
#include <optional>
#include <string>

namespace jhetz::ldap::net {

// How the server certificate is checked; no boolean on purpose.
enum class certificate_verification : unsigned char {
	// Default: a trusted chain and a host name match.
	full,
	// Accept any certificate. For tests and lab setups only.
	insecure_accept_any,
};

// How the host name is matched (with certificate_verification::full).
enum class host_name_matching : unsigned char {
	// Default (RFC 6125, RFC 4513 section 3.1.3): subjectAltName DNS names only,
	// a wildcard only as the whole leftmost label.
	strict,
	// OpenSSL 3's defaults: subject CN fallback, partial wildcards.
	legacy,
};

// TLS settings for ldaps:// and StartTLS; files are checked before any
// network traffic.
struct tls_options
{
	certificate_verification verification = certificate_verification::full;

	// Trust anchors; none set: the system store.
	std::filesystem::path ca_file{};// PEM file with one or more CA certificates
	// Directory hashed with `openssl rehash`.
	std::filesystem::path ca_dir{};
	std::pmr::string ca_pem{};// CA certificates as PEM text

	// Client certificate and key (PEM), both or neither: as files, or as
	// text (e.g. read from a PKCS#12 file or a platform store), not both.
	std::filesystem::path cert_file{};
	std::filesystem::path key_file{};
	// The leaf certificate first; its chain may follow.
	std::pmr::string cert_pem{};
	// Unencrypted, PKCS#8 or traditional PEM; copied with the options and
	// not wiped by the library (the caller owns its lifetime).
	std::pmr::string key_pem{};

	// SNI and the name matched; empty: the URL's host.
	std::pmr::string server_name{};
	host_name_matching host_matching = host_name_matching::strict;

	boost::corosio::tls_version min_version = boost::corosio::tls_version::tls_1_2;
};

struct connect_options
{
	static constexpr std::chrono::milliseconds default_timeout = std::chrono::seconds(30);
	static constexpr std::chrono::milliseconds default_attempt_delay = std::chrono::milliseconds(250);

	// The whole connect; ldap::no_timeout: no limit; zero or negative: fails
	// at once.
	std::chrono::milliseconds timeout{ default_timeout };
	tls_options tls{};
	// Happy Eyeballs Connection Attempt Delay (RFC 8305 section 5).
	std::chrono::milliseconds attempt_delay{ default_attempt_delay };
	bool tcp_no_delay = true;
};

// Connects to the server named by `u`; `ioc` must outlive the transport.
auto connect(boost::corosio::io_context &ioc,
  url u,
  connect_options options = {},
  std::pmr::memory_resource *mr = std::pmr::get_default_resource()) -> boost::capy::task<result<transport>>;

class read_buffer;

// StartTLS's TLS half: upgrades a plain TCP transport in place. `t` and
// `pending` must outlive the task.
auto start_tls(transport &t,
  const read_buffer &pending,
  tls_options options,
  std::optional<std::chrono::milliseconds> timeout = std::nullopt) -> boost::capy::task<result<void>>;

}// namespace jhetz::ldap::net
