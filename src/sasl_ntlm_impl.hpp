// Internal: the NTLMv2 computations and the NTLM security layer behind
// sasl_ntlm, also used by the tests and the fuzz targets.
#pragma once

#include "jhetz/ldap/error.hpp"
#include "jhetz/ldap/sasl.hpp"
#include "jhetz/ldap/sasl_ntlm.hpp"

#include "ntlm_message.hpp"

#include <cstddef>
#include <cstdint>
#include <memory_resource>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace jhetz::ldap {

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
