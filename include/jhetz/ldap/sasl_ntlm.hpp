// SASL NTLM (NTLMv2, MS-NLMP) for connection::sasl_bind: "GSS-SPNEGO"
// carrying raw NTLMSSP messages, as Active Directory accepts them
// (docs/API.md, "SASL NTLM").
#pragma once

#include "jhetz/ldap/channel_binding.hpp"
#include "jhetz/ldap/error.hpp"
#include "jhetz/ldap/ntlm_message.hpp"
#include "jhetz/ldap/sasl.hpp"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

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
	// Tests only: a fixed ClientChallenge. Wipes `password`.
	sasl_ntlm(std::string username,
	  std::string &password,
	  sasl_ntlm_options options,
	  std::optional<detail::ntlm_challenge> client_challenge);

	enum class state : std::uint8_t { idle, sent_negotiate, sent_authenticate };

	void wipe() noexcept;

	std::string username_;
	std::string password_;
	sasl_ntlm_options options_;
	std::optional<detail::ntlm_challenge> fixed_client_challenge_;
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
	detail::ntlm_key response_key_{};// NTOWFv2, wiped once used
	// Tests only: a fixed ExportedSessionKey.
	std::optional<detail::ntlm_key> fixed_session_key_;
	// The negotiated layer, until taken.
	std::unique_ptr<sasl_security_layer> layer_;
};

namespace detail {

	// The NTLMv2 computations of MS-NLMP section 3.3.2. Keys are written into
	// the caller's `out`.

	[[nodiscard]] auto ntlm_hmac_md5(std::span<const unsigned char> key, std::string_view data, ntlm_key &out)
	  -> result<void>;

	// NTOWFv2(Passwd, User, UserDom), from UTF-8, into `out`.
	// NOLINTNEXTLINE(bugprone-easily-swappable-parameters): MS-NLMP's NTOWFv2(Passwd, User, UserDom)
	[[nodiscard]] auto ntowfv2(std::string_view password, std::string_view user, std::string_view domain, ntlm_key &out)
	  -> result<void>;

	// ComputeResponse's results (MS-NLMP section 3.3.2).
	struct ntlm_responses
	{
		std::string nt_challenge_response{};
		std::string lm_challenge_response{};
		ntlm_key session_base_key{};
	};

	// ComputeResponse with `response_key` (NTOWFv2), into `out`; with
	// `server_timestamp` the LmChallengeResponse is Z(24).
	[[nodiscard]] auto ntlm_compute_response(const ntlm_key &response_key,
	  const ntlm_challenge &server_challenge,
	  const ntlm_challenge &client_challenge,
	  std::uint64_t time,
	  std::string_view server_name,
	  bool server_timestamp,
	  ntlm_responses &out) -> result<void>;

	// The MsvAvChannelBindings value: MD5 of a gss_channel_bindings_struct
	// holding only `application_data`.
	[[nodiscard]] auto ntlm_channel_bindings_hash(std::string_view application_data) -> result<ntlm_key>;

	// Session security (MS-NLMP section 3.4).

	// ClientSigningKey, ClientSealingKey, ServerSigningKey, ServerSealingKey
	// (MS-NLMP section 3.1.1.1); the caller wipes them.
	struct ntlm_session_keys
	{
		ntlm_key client_signing_key{};
		ntlm_key client_sealing_key{};
		ntlm_key server_signing_key{};
		ntlm_key server_sealing_key{};
	};

	// The keys of `exported_session_key`, into `out`.
	[[nodiscard]] auto ntlm_derive_session_keys(const ntlm_key &exported_session_key, ntlm_session_keys &out)
	  -> result<void>;

	// The most plaintext one protected buffer carries (128 KiB with the
	// signature).
	inline constexpr std::size_t ntlm_max_wrap_input = (std::size_t{ 1 } << 17) - ntlm_signature_size;

	// The client side of an NTLM security layer: wrap() signs (and seals),
	// unwrap() verifies (and unseals).
	class ntlm_security_layer final : public sasl_security_layer
	{
	  public:
		// `keys` are copied; `protection` is integrity or confidentiality.
		ntlm_security_layer(const ntlm_session_keys &keys,
		  sasl_protection protection,
		  std::size_t max_received) noexcept;
		~ntlm_security_layer() override;
		ntlm_security_layer(const ntlm_security_layer &) = delete;
		ntlm_security_layer(ntlm_security_layer &&) = delete;
		auto operator=(const ntlm_security_layer &) -> ntlm_security_layer & = delete;
		auto operator=(ntlm_security_layer &&) -> ntlm_security_layer & = delete;

		[[nodiscard]] auto protection() const noexcept -> sasl_protection override { return protection_; }
		[[nodiscard]] auto max_wrap_input() const noexcept -> std::size_t override { return ntlm_max_wrap_input; }
		[[nodiscard]] auto max_received() const noexcept -> std::size_t override { return max_received_; }
		[[nodiscard]] auto wrap(std::span<const std::byte> plaintext, std::pmr::vector<std::byte> &out)
		  -> result<void> override;
		[[nodiscard]] auto unwrap(std::span<const std::byte> buffer, std::pmr::vector<std::byte> &out)
		  -> result<void> override;

	  private:
		sasl_protection protection_;
		std::size_t max_received_;
		ntlm_key client_signing_key_;
		ntlm_key server_signing_key_;
		ntlm_rc4 client_handle_;
		ntlm_rc4 server_handle_;
		std::uint64_t send_seq_num_ = 0;
		std::uint64_t receive_seq_num_ = 0;
	};

}// namespace detail

}// namespace jhetz::ldap
