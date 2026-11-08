// SASL NTLM bind (NTLMv2, MS-NLMP), client side, for connection::sasl_bind:
// a password bind to Active Directory where Kerberos (sasl_gssapi) is not
// available (DESIGN.md section 3, "NTLM"):
//
//   ldap::sasl_ntlm mech("EXAMPLE\\jdoe", password);  // or "jdoe@example.org"
//   if (auto r = co_await conn.sasl_bind(mech); !r) ...
//
// The SASL mechanism is "GSS-SPNEGO" carrying raw NTLMSSP messages (MS-ADTS
// section 3.1.1.3.4.5.2): NEGOTIATE, the server's CHALLENGE, AUTHENTICATE.
// The password never crosses the wire. Part of jhetz::ldap_net (OpenSSL);
// the messages and MD4 are in the codec (ntlm_message.hpp).
//
// - NTLMv2 only: a CHALLENGE_MESSAGE without NTLMSSP_NEGOTIATE_UNICODE,
//   NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY or TargetInfo is refused.
// - NTLM does not authenticate the server: over TLS the certificate check
//   does, and channel binding prevents relaying the bind.
// - TLS is required by default (sasl_ntlm_options::require_tls): start()
//   fails with client_errc::tls_required before anything is sent. Without TLS
//   or a security layer every PDU after the bind is unprotected, a recorded
//   exchange can be attacked offline (the NTProofStr), and AD with LDAP signing
//   required refuses the bind (errc::stronger_auth_required).
// - Security layer (MS-NLMP section 3.4, sasl_ntlm_options::security_layer):
//   none by default (no signing or sealing negotiated). integrity or
//   confidentiality negotiates SIGN, KEY_EXCH, 128 and ALWAYS_SIGN (SEAL
//   too for confidentiality); a CHALLENGE_MESSAGE not granting them all
//   fails with client_errc::security_layer_unavailable before
//   AUTHENTICATE is sent. connection::sasl_bind installs it after the
//   successful BindResponse; PDUs are always sealed (AD requires it), so
//   connection::security_layer() reports confidentiality for both levels.
//   A buffer with a wrong checksum or sequence number, or larger than
//   sasl_ntlm_options::max_receive_size, closes the connection; outgoing
//   buffers are at most 128 KiB. With a layer in effect, start_tls() and a
//   bind negotiating another layer fail (security_layer_in_effect), and AD
//   may refuse further binds. Plain ldap:// only: over TLS start() fails with
//   security_layer_unavailable. A requested layer replaces require_tls. The
//   layer is RC4 and HMAC-MD5, weaker than TLS.
// - Channel binding (MsvAvChannelBindings): over TLS, the MD5 of a
//   gss_channel_bindings_struct with "tls-server-end-point:" and the
//   certificate hash (RFC 5929); without such a hash (e.g. Ed25519) start()
//   fails with client_errc::tls_required. ntlm_channel_binding::none sends
//   none over TLS (for a TLS-terminating proxy). Without TLS: 16 zero
//   octets.
// - The NTProofStr covers the client's TargetInfo, with MsvAvTargetName (the
//   SPN, "ldap/<host>" by default); a MIC protects the three messages.
// - Unicode: user name, domain, password, workstation and target are UTF-8,
//   sent as UTF-16LE (ill-formed UTF-8 refused); the password is not
//   normalized, the user name is uppercased with the simple case mapping.
// - The user: "DOMAIN\user" splits at the first backslash; "user@dns.domain"
//   (a UPN) goes with an empty domain; a bare "user" with
//   sasl_ntlm_options::domain (empty: the server's). An explicit domain keeps
//   the username as given.
// - The password is kept for later binds and wiped with OPENSSL_cleanse on
//   destruction, as are its derived secrets and the layer's keys.
//
// Errors (contexts never contain the password; sasl_bind prefixes
// "sasl bind GSS-SPNEGO"):
// - client_errc::tls_required (cond::access_denied): no TLS with
//   require_tls and no security layer, or no tls-server-end-point hash.
// - client_errc::security_layer_unavailable (cond::access_denied): a layer
//   asked for over TLS, or not granted by the CHALLENGE_MESSAGE.
// - client_errc::encode_error (cond::invalid_input): an empty user name,
//   ill-formed UTF-8, a field too long, max_receive_size below 16 with a
//   layer.
// - client_errc::decode_error (cond::protocol_error): a malformed or missing
//   CHALLENGE_MESSAGE; with a layer, a malformed signature.
// - client_errc::unexpected_response (cond::protocol_error): a challenge
//   without NTLMv2, a challenge after AUTHENTICATE, success before it (the
//   connection is closed); with a layer, a wrong checksum or sequence number.
// - client_errc::internal_error: OpenSSL failed (e.g. MD5 unavailable under
//   FIPS).
// - errc::invalid_credentials (cond::auth_failed): the server refused the
//   credentials.
#pragma once

#include "jhetz/ldap/channel_binding.hpp"
#include "jhetz/ldap/error.hpp"
#include "jhetz/ldap/ntlm_message.hpp"
#include "jhetz/ldap/sasl.hpp"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <memory_resource>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace jhetz::ldap {

namespace detail {
	struct ntlm_test_access;// defined by the tests only
}

// Whether the NTLM exchange is bound to the TLS channel (see the header
// comment).
enum class ntlm_channel_binding : std::uint8_t {
	// Over TLS: MsvAvChannelBindings over "tls-server-end-point:<hash>";
	// start() fails with client_errc::tls_required without the hash.
	tls_server_end_point,
	none,// no MsvAvChannelBindings over TLS (Z(16) without TLS)
};

struct sasl_ntlm_options
{
	// The user's domain (UserDom, e.g. "EXAMPLE"); empty: from a
	// "DOMAIN\user" username, else none.
	std::string domain{};
	// The client's name (Workstation of the AUTHENTICATE_MESSAGE); empty:
	// none.
	std::string workstation{};
	// The service principal name in MsvAvTargetName (e.g.
	// "ldap/dc1.example.org"). Empty: "ldap/<host>", the host of the URL
	// connected to; none for ldapi:// or a wrapped transport.
	std::string target{};
	// Refuse to bind on a connection without TLS (see the header comment).
	bool require_tls = true;
	// Channel binding over TLS; none for a server behind a TLS-terminating
	// proxy.
	ntlm_channel_binding channel_binding = ntlm_channel_binding::tls_server_end_point;
	// The SASL security layer to negotiate (see the header comment): none,
	// integrity (signing) or confidentiality (signing and sealing); only
	// over plain ldap://, where it stands in for require_tls.
	sasl_protection security_layer = sasl_protection::none;
	// With a security layer: the largest protected buffer accepted from the
	// server (at least 16, the signature; else start() fails with
	// client_errc::encode_error). GSS-SPNEGO announces no maximum (no RFC
	// 4752 layer messages), so this is only this side's bound; a larger
	// buffer closes the connection.
	std::uint32_t max_receive_size = 0x0100'0000;// 16 MiB
};

class sasl_ntlm final : public sasl_mechanism
{
  public:
	// `username`: "DOMAIN\user", "user@dns.domain" or "user" (see the
	// header comment). The inputs are checked by start(), so the
	// constructor cannot fail. The `password` parameter is wiped once moved
	// from (a short password's bytes would stay in its buffer). A string
	// the caller moves into it is the caller's to wipe: moving out of a
	// short string leaves its bytes behind.
	sasl_ntlm(std::string username, std::string password, sasl_ntlm_options options = {});
	~sasl_ntlm() override;

	// Holds a password: not copyable, not movable (no stray copies to wipe).
	sasl_ntlm(const sasl_ntlm &) = delete;
	auto operator=(const sasl_ntlm &) -> sasl_ntlm & = delete;

	[[nodiscard]] auto name() const noexcept -> std::string_view override { return "GSS-SPNEGO"; }
	// Keeps the host (the default target), whether TLS protects the
	// connection, and the channel binding data.
	void prepare(const sasl_bind_context &context) override;
	// The NEGOTIATE_MESSAGE, after the checks (TLS, channel binding, the
	// inputs).
	[[nodiscard]] auto start() -> result<std::optional<std::string>> override;
	// The CHALLENGE_MESSAGE gives the AUTHENTICATE_MESSAGE.
	[[nodiscard]] auto step(std::optional<std::string_view> challenge) -> result<std::optional<std::string>> override;
	// Succeeds once the AUTHENTICATE_MESSAGE was sent; the server's final
	// credentials, if any, are not checked (NTLM has nothing to verify).
	[[nodiscard]] auto complete(std::optional<std::string_view> server_creds) -> result<void> override;
	// After the step that sent the AUTHENTICATE_MESSAGE, with a security
	// layer: the layer (detail::ntlm_security_layer), once.
	[[nodiscard]] auto take_security_layer() -> std::unique_ptr<sasl_security_layer> override;
	// tls_server_end_point when the exchange carries channel bindings,
	// else nullopt (never tls-exporter).
	[[nodiscard]] auto channel_binding_used() const noexcept -> std::optional<channel_binding_type> override
	{
		if (state_ == state::idle || binding_data_.empty()) {
			return std::nullopt;
		}
		return channel_binding_type::tls_server_end_point;
	}

  private:
	friend struct detail::ntlm_test_access;
	// `client_challenge`: tests only (detail::ntlm_test_access), a fixed
	// ClientChallenge instead of a random one.
	sasl_ntlm(std::string username,
	  std::string password,
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
	// The channel bindings' application data ("tls-server-end-point:"
	// and the hash); empty: none (Z(16) without TLS, no pair over TLS).
	std::string binding_data_;
	// Why the TLS connection cannot be bound (start() fails with it).
	std::string binding_error_;
	state state_ = state::idle;
	// From start() to the AUTHENTICATE_MESSAGE: what it is built from.
	std::string negotiate_;// the NEGOTIATE_MESSAGE sent, for the MIC
	std::string user_;// UTF-16LE
	std::string domain_;// UTF-16LE
	std::string workstation_;// UTF-16LE
	std::string target_;// UTF-16LE; empty: no MsvAvTargetName
	detail::ntlm_key response_key_{};// NTOWFv2, wiped once used
	// Tests only (detail::ntlm_test_access): a fixed ExportedSessionKey
	// instead of a random one.
	std::optional<detail::ntlm_key> fixed_session_key_;
	// The layer the AUTHENTICATE_MESSAGE negotiated, until taken.
	std::unique_ptr<sasl_security_layer> layer_;
};

namespace detail {

	// The NTLMv2 computations of MS-NLMP section 3.3.2, exposed for the
	// tests (the section 4.2.4 test vectors). client_errc::internal_error
	// when OpenSSL fails. Each writes its keys into the caller's `out`
	// rather than returning them, as md4 does: a key returned in a result
	// is a copy of a local, left behind unwiped in the callee's frame.

	// HMAC_MD5(key, data), into `out`.
	[[nodiscard]] auto ntlm_hmac_md5(std::span<const unsigned char> key, std::string_view data, ntlm_key &out)
	  -> result<void>;

	// NTOWFv2(Passwd, User, UserDom) = HMAC_MD5(MD4(UNICODE(Passwd)),
	// UNICODE(ConcatenationOf(Uppercase(User), UserDom))), from UTF-8, into
	// `out`. The password's UTF-16 and the NT hash are wiped before it
	// returns. client_errc::encode_error for ill-formed UTF-8.
	// NOLINTNEXTLINE(bugprone-easily-swappable-parameters): MS-NLMP's NTOWFv2(Passwd, User, UserDom)
	[[nodiscard]] auto ntowfv2(std::string_view password, std::string_view user, std::string_view domain, ntlm_key &out)
	  -> result<void>;

	// What ComputeResponse gives (MS-NLMP section 3.3.2):
	// NtChallengeResponse (NTProofStr, then the temp structure),
	// LmChallengeResponse and SessionBaseKey.
	struct ntlm_responses
	{
		std::string nt_challenge_response{};
		std::string lm_challenge_response{};
		ntlm_key session_base_key{};
	};

	// ComputeResponse with ResponseKeyNT = ResponseKeyLM = `response_key`
	// (NTOWFv2), `time` (a FILETIME) and `server_name` (the AV_PAIR list
	// the client sends, encode_ntlm_av_pairs), into `out` (the
	// SessionBaseKey is the caller's to wipe, also on failure).
	// `server_timestamp`: `time` is the server's MsvAvTimestamp, and then
	// the LmChallengeResponse is Z(24) (MS-NLMP section 3.1.5.1.2), the LMv2
	// response otherwise.
	[[nodiscard]] auto ntlm_compute_response(const ntlm_key &response_key,
	  const ntlm_challenge &server_challenge,
	  const ntlm_challenge &client_challenge,
	  std::uint64_t time,
	  std::string_view server_name,
	  bool server_timestamp,
	  ntlm_responses &out) -> result<void>;

	// The MsvAvChannelBindings value: MD5 of a gss_channel_bindings_struct
	// with no addresses (initiator and acceptor address types and lengths
	// 0) and `application_data`, every integer four octets little-endian,
	// as Windows hashes its SEC_CHANNEL_BINDINGS.
	[[nodiscard]] auto ntlm_channel_bindings_hash(std::string_view application_data) -> result<ntlm_key>;

	// Session security (MS-NLMP section 3.4), with extended session
	// security, key exchange and 128-bit keys, as sasl_ntlm negotiates it.

	// The four keys of MS-NLMP section 3.1.1.1 (ClientSigningKey,
	// ClientSealingKey, ServerSigningKey, ServerSealingKey): SIGNKEY and
	// SEALKEY (sections 3.4.5.2 and 3.4.5.3) of the ExportedSessionKey,
	// MD5(ConcatenationOf(key, "session key to client-to-server signing key
	// magic constant" and its NUL)) and so on. Secrets: the caller's to wipe.
	struct ntlm_session_keys
	{
		ntlm_key client_signing_key{};
		ntlm_key client_sealing_key{};
		ntlm_key server_signing_key{};
		ntlm_key server_sealing_key{};
	};

	// The keys of `exported_session_key`, into `out` (wiped by the caller,
	// also on failure).
	[[nodiscard]] auto ntlm_derive_session_keys(const ntlm_key &exported_session_key, ntlm_session_keys &out)
	  -> result<void>;

	// The most plaintext one protected buffer carries: 128 KiB in all with
	// the signature, as Samba's gensec_max_input_size.
	inline constexpr std::size_t ntlm_max_wrap_input = (std::size_t{ 1 } << 17) - ntlm_signature_size;

	// The client's side of an NTLM security layer: wrap() signs (and with
	// confidentiality seals) with the client-to-server keys and its own RC4
	// handle and sequence number, unwrap() checks (and unseals) with the
	// server-to-client ones. A buffer that does not verify fails with
	// client_errc::unexpected_response (decode_error when it is malformed),
	// and so does one after 2^32 buffers in a direction (the sequence
	// number would wrap). The keys are wiped when it goes, the RC4 states
	// by ntlm_rc4.
	class ntlm_security_layer final : public sasl_security_layer
	{
	  public:
		// `keys`: copied (the caller wipes its own). `protection`:
		// integrity or confidentiality.
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
