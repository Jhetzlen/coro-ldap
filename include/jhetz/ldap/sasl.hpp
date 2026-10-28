// SASL mechanisms for connection::sasl_bind (RFC 4513 section 5.2, RFC 4422).
//
// A mechanism produces the credentials of each BindRequest and reads the
// server's challenges; the connection drives the exchange (one BindRequest
// per step while the server answers saslBindInProgress):
//
//   ldap::sasl_external mech;                       // identity from TLS / ldapi://
//   if (auto r = co_await conn.sasl_bind(mech); !r) ...
//
// SCRAM-SHA-256 is sasl_scram_sha256 (sasl_scram.hpp, in jhetz::ldap_net),
// GSSAPI (Kerberos) sasl_gssapi (sasl_gssapi.hpp, in jhetz::ldap_net when
// built with JHETZ_LDAP_WITH_GSSAPI). Implement sasl_mechanism to add
// another. A mechanism object serves one bind at a time.
//
// start(), step() and complete() run on the connection's I/O thread, so
// they must not block. A mechanism whose steps may block (network I/O,
// like GSSAPI contacting a Kerberos KDC) hands them to sasl_bind as work
// to run on a thread of its own instead (offload_start, offload_step).
#pragma once

#include "jhetz/ldap/channel_binding.hpp"
#include "jhetz/ldap/error.hpp"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <memory_resource>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace jhetz::ldap {

// What connection::sasl_bind tells a mechanism about the server, before
// start() (sasl_mechanism::prepare). Valid only during that call.
struct sasl_bind_context
{
	// The host of the URL connected to (ldap://, ldaps://), as decoded:
	// a name or an IP address (without brackets). Empty for ldapi:// and
	// for transports wrap()ped by the caller.
	std::string_view host{};
	// Whether a step can be offloaded (offload_start, offload_step): false
	// when the io_context is in locking_mode::unsafe, where offloaded work
	// fails (sasl_work), so that a mechanism whose offloading is optional
	// (SCRAM's PBKDF2) runs the step inline instead. True otherwise,
	// unsafe_io included (it cannot be detected). False when prepare() is
	// called with a default sasl_bind_context.
	bool can_offload = false;
	// Whether TLS protects the connection (connection::is_tls()).
	bool tls = false;
	// The connection's TLS channel bindings (channel_binding.hpp), e.g. for
	// SCRAM-SHA-256-PLUS: views valid only during prepare(), like the rest
	// of the context. Empty when !tls; tls-exporter empty once a bind used
	// it (sasl_mechanism::channel_binding_used, which by default says a
	// mechanism given tls-exporter data used it).
	channel_bindings bindings{};
	// The server's certificate (DER, connection::peer_certificate()), a
	// view valid only during prepare(); empty when !tls.
	std::span<const std::byte> peer_certificate{};
};

// A step's credentials computed off the I/O thread (offload_start,
// offload_step): sasl_bind calls it once, on a thread of its own, and waits
// for it. The wait honours the bind's timeout and cancellation, but the
// work itself is not interrupted: once sasl_bind gave up, the work runs on
// while the mechanism may be destroyed or start another bind, so it must
// own (or share) everything it uses, and the mechanism must not touch that
// state again until the work is over. Its result is then discarded. The
// thread wakes the bind through the io_context, so the io_context must use
// Corosio's default locking_mode::safe: under unsafe the step fails with
// std::errc::operation_not_supported before the work runs; unsafe_io (which
// cannot be detected) is unsupported, its wakeup may be lost.
using sasl_work = std::move_only_function<result<std::optional<std::string>>()>;

// The protection a SASL security layer gives the rest of the session (RFC
// 4422 section 3.7): none, integrity (every PDU signed), or
// confidentiality (signed and sealed).
enum class sasl_protection : std::uint8_t {
	none,
	integrity,
	confidentiality,
};

// A SASL security layer (RFC 4422 section 3.7), negotiated by a mechanism
// (sasl_mechanism::take_security_layer) and installed by
// connection::sasl_bind under the LDAP PDUs, both ways, from the first octet
// after the bind's final BindResponse with success (RFC 4513 section
// 5.2.1.4) until the connection closes. The connection does the framing:
// each protected buffer goes on the wire after a four-octet length in
// network byte order; outgoing PDUs are cut into pieces of at most
// max_wrap_input() octets, and an incoming length above max_received()
// closes the connection before the buffer is read (RFC 4422: "the receiver
// SHOULD close the connection, as this might be a sign of an attack").
// The layer only protects and checks buffers; it runs on the connection's
// I/O thread and must not block. One layer serves one connection.
class sasl_security_layer
{
  public:
	virtual ~sasl_security_layer() = default;

	[[nodiscard]] virtual auto protection() const noexcept -> sasl_protection = 0;
	// The most plaintext one wrap() takes: what keeps the protected buffer
	// within the peer's maximum buffer size. At least 1.
	[[nodiscard]] virtual auto max_wrap_input() const noexcept -> std::size_t = 0;
	// The largest protected buffer accepted from the peer (the maximum
	// buffer size this side announced).
	[[nodiscard]] virtual auto max_received() const noexcept -> std::size_t = 0;
	// Appends the protected form of `plaintext` (at most max_wrap_input()
	// octets, possibly none) to `out`, without the length.
	[[nodiscard]] virtual auto wrap(std::span<const std::byte> plaintext, std::pmr::vector<std::byte> &out)
	  -> result<void> = 0;
	// Checks (and decrypts) one protected buffer from the peer and appends
	// its plaintext to `out`. An error closes the connection.
	[[nodiscard]] virtual auto unwrap(std::span<const std::byte> buffer, std::pmr::vector<std::byte> &out)
	  -> result<void> = 0;

  protected:
	sasl_security_layer() = default;
	sasl_security_layer(const sasl_security_layer &) = default;
	sasl_security_layer(sasl_security_layer &&) = default;
	auto operator=(const sasl_security_layer &) -> sasl_security_layer & = default;
	auto operator=(sasl_security_layer &&) -> sasl_security_layer & = default;
};

// sasl_bind prefixes an error's context with "sasl bind <name>", so a
// mechanism's own contexts should not name the mechanism.
class sasl_mechanism
{
  public:
	virtual ~sasl_mechanism() = default;

	// Called by sasl_bind at the start of each bind, before start(), e.g.
	// for GSSAPI's default target (ldap@<host>). Default: ignored.
	virtual void prepare(const sasl_bind_context &context) { (void)context; }

	// The mechanism name sent in the BindRequest, e.g. "EXTERNAL".
	[[nodiscard]] virtual auto name() const noexcept -> std::string_view = 0;
	// Credentials of the first BindRequest (nullopt: none sent). Called at
	// the start of each bind, so it also resets the mechanism.
	[[nodiscard]] virtual auto start() -> result<std::optional<std::string>> = 0;
	// After saslBindInProgress: the server's challenge (serverSaslCreds,
	// nullopt if absent) gives the credentials of the next BindRequest. An
	// error aborts the bind.
	[[nodiscard]] virtual auto step(std::optional<std::string_view> challenge)
	  -> result<std::optional<std::string>> = 0;
	// After success: the server's final serverSaslCreds, if any (e.g. a
	// SCRAM server signature to verify). An error fails the bind. Default:
	// accept anything.
	[[nodiscard]] virtual auto complete(std::optional<std::string_view> server_creds) -> result<void>
	{
		(void)server_creds;
		return {};
	}

	// For a step that may block: the work of start() or step(), to run on
	// another thread (sasl_work). sasl_bind calls these in place of start()
	// and step(), and uses the work's result as theirs; empty work (the
	// default) means start() or step() is called on the I/O thread instead.
	// Non-empty work needs an io_context in locking_mode::safe (sasl_work).
	[[nodiscard]] virtual auto offload_start() -> sasl_work { return {}; }
	[[nodiscard]] virtual auto offload_step(std::optional<std::string_view> challenge) -> sasl_work
	{
		(void)challenge;
		return {};
	}

	// After start() (or offload_start()'s work) succeeded: the channel
	// binding type whose data (sasl_bind_context::bindings) the exchange
	// authenticates, nullopt for none. tls-exporter MUST NOT be used for
	// more than one authentication on a TLS connection (RFC 9266 section
	// 4.1): when this says tls_exporter and the bind was given tls-exporter
	// data, sasl_bind counts the bind as that one use, whatever its
	// outcome, and later binds on the connection get no tls-exporter data
	// (channel_bindings, with default_type falling back to
	// tls-server-end-point or none). Default: tls_exporter, fail-closed: a
	// mechanism that does not say what it used counts as having used it. A
	// mechanism that binds to nothing, or to another type, overrides it
	// (the library's mechanisms report exactly what they used).
	[[nodiscard]] virtual auto channel_binding_used() const noexcept -> std::optional<channel_binding_type>
	{
		return channel_binding_type::tls_exporter;
	}

	// After each step (start(), step() or their offloaded work) succeeded:
	// the security layer the exchange negotiated, if the BindRequest that
	// step's credentials go in is the last one. sasl_bind takes it (calling
	// this once per step) and installs it when the server answers that
	// BindRequest with success (RFC 4513 section 5.2.1.4), before complete()
	// runs: a complete() that fails then closes the connection, as it always
	// does. Any other answer drops it. A layer while one is in effect
	// fails the bind with client_errc::security_layer_in_effect (the
	// exchange is aborted). Default: none (nullptr).
	[[nodiscard]] virtual auto take_security_layer() -> std::unique_ptr<sasl_security_layer> { return nullptr; }

  protected:
	// Copied and moved only as part of a derived mechanism, never sliced
	// through a sasl_mechanism reference.
	sasl_mechanism() = default;
	sasl_mechanism(const sasl_mechanism &) = default;
	sasl_mechanism(sasl_mechanism &&) = default;
	auto operator=(const sasl_mechanism &) -> sasl_mechanism & = default;
	auto operator=(sasl_mechanism &&) -> sasl_mechanism & = default;
};

// EXTERNAL (RFC 4422 appendix A): the server takes the identity from the
// layer below, a TLS client certificate or the peer credentials of an
// ldapi:// socket. `authz_id` asks to act as another identity ("dn:...",
// "u:..."); empty: the authenticated identity itself. One step: a challenge
// from the server is a protocol error.
class sasl_external final : public sasl_mechanism
{
  public:
	explicit sasl_external(std::string authz_id = {}) : authz_id_(std::move(authz_id)) {}

	[[nodiscard]] auto name() const noexcept -> std::string_view override { return "EXTERNAL"; }
	[[nodiscard]] auto start() -> result<std::optional<std::string>> override
	{
		return std::optional<std::string>(authz_id_);
	}
	[[nodiscard]] auto step(std::optional<std::string_view>) -> result<std::optional<std::string>> override
	{
		return fail(client_errc::unexpected_response, "the server sent a challenge to a single-step mechanism");
	}
	// Binds to no channel: the TLS layer below carries the identity.
	[[nodiscard]] auto channel_binding_used() const noexcept -> std::optional<channel_binding_type> override
	{
		return std::nullopt;
	}

  private:
	std::string authz_id_;
};

}// namespace jhetz::ldap
