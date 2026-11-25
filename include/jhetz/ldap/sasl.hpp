// SASL mechanisms for connection::sasl_bind (RFC 4513 section 5.2, RFC
// 4422) and the interface to write others (docs/API.md, "SASL").
#pragma once

#include "jhetz/ldap/channel_binding.hpp"
#include "jhetz/ldap/error.hpp"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace jhetz::ldap {

// What sasl_bind tells a mechanism before start(); valid only during
// prepare().
struct sasl_bind_context
{
	// The URL's host, decoded; empty for ldapi:// and wrapped transports.
	std::string_view host{};
	// Whether a step can be offloaded (false under locking_mode::unsafe).
	bool can_offload = false;
	bool tls = false;
	// Empty unless tls; no tls-exporter once a bind used it.
	channel_bindings bindings{};
	// DER; empty unless tls.
	std::span<const std::byte> peer_certificate{};
};

// A step's work run once on a thread of its own; it must own or share
// everything it uses.
using sasl_work = std::move_only_function<result<std::optional<std::string>>()>;

// RFC 4422 section 3.7: none, integrity (signed) or confidentiality
// (signed and sealed).
enum class sasl_protection : std::uint8_t {
	none,
	integrity,
	confidentiality,
};

// A SASL security layer (RFC 4422 section 3.7): wraps and unwraps the
// buffers the connection frames.
class sasl_security_layer
{
  public:
	virtual ~sasl_security_layer() = default;

	[[nodiscard]] virtual auto protection() const noexcept -> sasl_protection = 0;
	// The most plaintext one wrap() takes; at least 1.
	[[nodiscard]] virtual auto max_wrap_input() const noexcept -> std::size_t = 0;
	// The largest protected buffer accepted from the peer.
	[[nodiscard]] virtual auto max_received() const noexcept -> std::size_t = 0;
	// Appends the protected form of `plaintext` to `out`, without the length.
	[[nodiscard]] virtual auto wrap(std::span<const std::byte> plaintext, std::pmr::vector<std::byte> &out)
	  -> result<void> = 0;
	// Checks (and decrypts) one buffer, appending its plaintext to `out`.
	[[nodiscard]] virtual auto unwrap(std::span<const std::byte> buffer, std::pmr::vector<std::byte> &out)
	  -> result<void> = 0;

  protected:
	sasl_security_layer() = default;
	sasl_security_layer(const sasl_security_layer &) = default;
	sasl_security_layer(sasl_security_layer &&) = default;
	auto operator=(const sasl_security_layer &) -> sasl_security_layer & = default;
	auto operator=(sasl_security_layer &&) -> sasl_security_layer & = default;
};

class sasl_mechanism
{
  public:
	virtual ~sasl_mechanism() = default;

	// Called before start() at each bind. Default: ignored.
	virtual void prepare(const sasl_bind_context &context) { (void)context; }

	[[nodiscard]] virtual auto name() const noexcept -> std::string_view = 0;
	// Credentials of the first BindRequest (nullopt: none); resets the
	// mechanism.
	[[nodiscard]] virtual auto start() -> result<std::optional<std::string>> = 0;
	// The server's challenge gives the next BindRequest's credentials.
	[[nodiscard]] virtual auto step(std::optional<std::string_view> challenge)
	  -> result<std::optional<std::string>> = 0;
	// The server's final serverSaslCreds, if any. Default: accept.
	[[nodiscard]] virtual auto complete(std::optional<std::string_view> server_creds) -> result<void>
	{
		(void)server_creds;
		return {};
	}

	// The work of start() or step() for another thread; empty: run inline.
	[[nodiscard]] virtual auto offload_start() -> sasl_work { return {}; }
	[[nodiscard]] virtual auto offload_step(std::optional<std::string_view> challenge) -> sasl_work
	{
		(void)challenge;
		return {};
	}

	// The channel binding type the exchange authenticates. Default:
	// tls_exporter (fail-closed).
	[[nodiscard]] virtual auto channel_binding_used() const noexcept -> std::optional<channel_binding_type>
	{
		return channel_binding_type::tls_exporter;
	}

	// The security layer the exchange negotiated, if this step's BindRequest is
	// the last. Default: none.
	[[nodiscard]] virtual auto take_security_layer() -> std::unique_ptr<sasl_security_layer> { return nullptr; }

  protected:
	// Copied and moved only as part of a derived mechanism.
	sasl_mechanism() = default;
	sasl_mechanism(const sasl_mechanism &) = default;
	sasl_mechanism(sasl_mechanism &&) = default;
	auto operator=(const sasl_mechanism &) -> sasl_mechanism & = default;
	auto operator=(sasl_mechanism &&) -> sasl_mechanism & = default;
};

// EXTERNAL (RFC 4422 appendix A): the identity comes from TLS or ldapi://.
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
	[[nodiscard]] auto channel_binding_used() const noexcept -> std::optional<channel_binding_type> override
	{
		return std::nullopt;
	}

  private:
	std::string authz_id_;
};

}// namespace jhetz::ldap
