// SASL NTLM (NTLMv2, MS-NLMP) for connection::sasl_bind: "GSS-SPNEGO"
// carrying raw NTLMSSP messages, as Active Directory accepts them
// (docs/API.md, "SASL NTLM").
#pragma once

#include "jhetz/ldap/channel_binding.hpp"
#include "jhetz/ldap/error.hpp"
#include "jhetz/ldap/sasl.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>

namespace jhetz::ldap {

namespace detail {
	struct ntlm_test_access;// defined by the tests only
}

enum class ntlm_channel_binding : std::uint8_t {
	// MsvAvChannelBindings over "tls-server-end-point:<hash>".
	tls_server_end_point,
	none,// no MsvAvChannelBindings over TLS
};

struct sasl_ntlm_options
{
	// UserDom; empty: from a "DOMAIN\user" username, else none.
	std::string domain{};
	// Workstation; empty: none.
	std::string workstation{};
	// The SPN in MsvAvTargetName; empty: "ldap/<host>".
	std::string target{};
	bool require_tls = true;
	ntlm_channel_binding channel_binding = ntlm_channel_binding::tls_server_end_point;
	// Only over plain ldap://, where it stands in for require_tls.
	sasl_protection security_layer = sasl_protection::none;
	// The largest protected buffer accepted from the server (at least 16).
	std::uint32_t max_receive_size = 0x0100'0000;// 16 MiB
};

class sasl_ntlm final : public sasl_mechanism
{
  public:
	// `username`: "DOMAIN\user", "user@dns.domain" or "user". The `password`
	// parameter is wiped once copied.
	sasl_ntlm(std::string username, std::string password, sasl_ntlm_options options = {});
	~sasl_ntlm() override;

	// Not copyable, not movable: no stray password copies.
	sasl_ntlm(const sasl_ntlm &) = delete;
	auto operator=(const sasl_ntlm &) -> sasl_ntlm & = delete;

	[[nodiscard]] auto name() const noexcept -> std::string_view override { return "GSS-SPNEGO"; }
	void prepare(const sasl_bind_context &context) override;
	// The NEGOTIATE_MESSAGE.
	[[nodiscard]] auto start() -> result<std::optional<std::string>> override;
	// The CHALLENGE_MESSAGE gives the AUTHENTICATE_MESSAGE.
	[[nodiscard]] auto step(std::optional<std::string_view> challenge) -> result<std::optional<std::string>> override;
	// Succeeds once the AUTHENTICATE_MESSAGE was sent.
	[[nodiscard]] auto complete(std::optional<std::string_view> server_creds) -> result<void> override;
	// With a security layer: the layer, once.
	[[nodiscard]] auto take_security_layer() -> std::unique_ptr<sasl_security_layer> override;
	// tls_server_end_point when the exchange carries channel bindings.
	[[nodiscard]] auto channel_binding_used() const noexcept -> std::optional<channel_binding_type> override
	{
		if (state_ == state::idle || binding_data_.empty()) {
			return std::nullopt;
		}
		return channel_binding_type::tls_server_end_point;
	}

  private:
	friend struct detail::ntlm_test_access;
	static constexpr std::size_t key_size = 16;
	static constexpr std::size_t challenge_size = 8;

	// Tests only: a fixed ClientChallenge. Wipes `password`.
	sasl_ntlm(std::string username,
	  std::string &password,
	  sasl_ntlm_options options,
	  std::optional<std::array<unsigned char, challenge_size>> client_challenge);

	enum class state : std::uint8_t { idle, sent_negotiate, sent_authenticate };

	void wipe() noexcept;

	std::string username_;
	std::string password_;
	sasl_ntlm_options options_;
	std::optional<std::array<unsigned char, challenge_size>> fixed_client_challenge_;
	std::string host_;// from prepare()
	bool tls_ = false;// from prepare()
	// The channel bindings' application data; empty: none.
	std::string binding_data_;
	// Why the TLS connection cannot be bound.
	std::string binding_error_;
	state state_ = state::idle;
	std::string negotiate_;// the NEGOTIATE_MESSAGE sent, for the MIC
	std::string user_;// UTF-16LE
	std::string domain_;// UTF-16LE
	std::string workstation_;// UTF-16LE
	std::string target_;// UTF-16LE; empty: no MsvAvTargetName
	std::array<unsigned char, key_size> response_key_{};// NTOWFv2, wiped once used
	// Tests only: a fixed ExportedSessionKey.
	std::optional<std::array<unsigned char, key_size>> fixed_session_key_;
	// The negotiated layer, until taken.
	std::unique_ptr<sasl_security_layer> layer_;
};

}// namespace jhetz::ldap
