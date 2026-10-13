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

#include "jhetz/ldap/error.hpp"

#include <functional>
#include <optional>
#include <string>
#include <string_view>

namespace jhetz::ldap {

// What connection::sasl_bind tells a mechanism about the server, before
// start() (sasl_mechanism::prepare). Valid only during that call.
struct sasl_bind_context
{
	// The host of the URL connected to (ldap://, ldaps://), as decoded:
	// a name or an IP address (without brackets). Empty for ldapi:// and
	// for transports wrap()ped by the caller.
	std::string_view host{};
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
	virtual std::string_view name() const noexcept = 0;
	// Credentials of the first BindRequest (nullopt: none sent). Called at
	// the start of each bind, so it also resets the mechanism.
	[[nodiscard]] virtual result<std::optional<std::string>> start() = 0;
	// After saslBindInProgress: the server's challenge (serverSaslCreds,
	// nullopt if absent) gives the credentials of the next BindRequest. An
	// error aborts the bind.
	[[nodiscard]] virtual result<std::optional<std::string>> step(std::optional<std::string_view> challenge) = 0;
	// After success: the server's final serverSaslCreds, if any (e.g. a
	// SCRAM server signature to verify). An error fails the bind. Default:
	// accept anything.
	[[nodiscard]] virtual result<void> complete(std::optional<std::string_view> server_creds)
	{
		(void)server_creds;
		return {};
	}

	// For a step that may block: the work of start() or step(), to run on
	// another thread (sasl_work). sasl_bind calls these in place of start()
	// and step(), and uses the work's result as theirs; empty work (the
	// default) means start() or step() is called on the I/O thread instead.
	// Non-empty work needs an io_context in locking_mode::safe (sasl_work).
	[[nodiscard]] virtual sasl_work offload_start() { return {}; }
	[[nodiscard]] virtual sasl_work offload_step(std::optional<std::string_view> challenge)
	{
		(void)challenge;
		return {};
	}
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

	std::string_view name() const noexcept override { return "EXTERNAL"; }
	[[nodiscard]] result<std::optional<std::string>> start() override { return std::optional<std::string>(authz_id_); }
	[[nodiscard]] result<std::optional<std::string>> step(std::optional<std::string_view>) override
	{
		return fail(client_errc::unexpected_response, "the server sent a challenge to a single-step mechanism");
	}

  private:
	std::string authz_id_;
};

}// namespace jhetz::ldap
