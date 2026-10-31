// SASL NTLM bind (NTLMv2, MS-NLMP), client side, for connection::sasl_bind:
// a user's password bind to Active Directory where Kerberos (sasl_gssapi)
// is not available, as Samba's libads, python-ldap3 and Rust's ldap3 do:
//
//   ldap::sasl_ntlm mech("EXAMPLE\\jdoe", password);  // or "jdoe@example.org"
//   if (auto r = co_await conn.sasl_bind(mech); !r) ...
//
// The SASL mechanism is "GSS-SPNEGO" carrying raw NTLMSSP messages, not
// wrapped in SPNEGO tokens, which Active Directory accepts (MS-ADTS
// section 3.1.1.3.4.5.2): two BindRequests, NEGOTIATE_MESSAGE then
// AUTHENTICATE_MESSAGE, the server's CHALLENGE_MESSAGE in between (MS-NLMP
// section 3.1). The password never crosses the wire.
//
// Part of jhetz::ldap_net (HMAC-MD5, MD5 and the random client challenge
// come from OpenSSL); the messages and MD4 are in the codec
// (ntlm_message.hpp).
//
// What it does, and what it does not:
// - NTLMv2 only (MS-NLMP section 3.3.2): a CHALLENGE_MESSAGE without
//   NTLMSSP_NEGOTIATE_UNICODE, without
//   NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY or without TargetInfo (a
//   server that would take LM or NTLMv1 responses) is refused before any
//   response is computed.
// - NTLM does not authenticate the server: nothing in the exchange proves
//   that the server knows the user's password hash, so a bind's success
//   says nothing about whom the client is talking to. Over TLS the
//   certificate check does that; the channel binding below keeps a man in
//   the middle from relaying the bind.
// - Security layer (MS-NLMP section 3.4, sasl_ntlm_options::
//   security_layer): none by default, and then the client negotiates
//   neither signing nor sealing (no NTLMSSP_NEGOTIATE_SIGN, SEAL,
//   ALWAYS_SIGN nor KEY_EXCH), so the session after the bind is protected
//   only by TLS, if any. With sasl_protection::integrity the NEGOTIATE_MESSAGE
//   adds NTLMSSP_NEGOTIATE_SIGN and NTLMSSP_NEGOTIATE_KEY_EXCH (with 128-bit
//   keys, NTLMSSP_NEGOTIATE_128, always asked for) and
//   NTLMSSP_NEGOTIATE_ALWAYS_SIGN (MS-NLMP section 2.2.2.5: it MUST be set
//   in the NEGOTIATE_MESSAGE; SIGN overrides it), with confidentiality
//   NTLMSSP_NEGOTIATE_SEAL too; a CHALLENGE_MESSAGE that does not grant
//   them all fails the bind with client_errc::security_layer_unavailable
//   (cond::access_denied) before the AUTHENTICATE_MESSAGE is sent. The
//   client then picks a random ExportedSessionKey, sends it RC4-encrypted
//   with the SessionBaseKey (EncryptedRandomSessionKey, section 3.1.5.1.2;
//   for NTLMv2 the KeyExchangeKey is the SessionBaseKey, section 3.4.5.1),
//   keys the MIC with it, and derives the four keys of section 3.4.5.2 and
//   3.4.5.3 (client-to-server and server-to-client signing and sealing).
//   connection::sasl_bind installs the layer right after the successful
//   BindResponse (RFC 4513 section 5.2.1.4): every later PDU, both ways,
//   goes in a protected buffer after a four-octet length (RFC 4422 section
//   3.7, as MS-ADTS section 5.1.2.1 says Active Directory does), the buffer
//   being the 16-octet NTLMSSP_MESSAGE_SIGNATURE (section 2.2.2.9.2:
//   Version 1, the first eight octets of HMAC_MD5(SigningKey,
//   ConcatenationOf(SeqNum, Message)) RC4-encrypted, SeqNum), then the
//   message, RC4-sealed with confidentiality (section 3.4.3: the message
//   sealed first, then the checksum, with the same RC4 handle), as Samba
//   and Windows lay it out. Each direction has its own RC4 handle, kept
//   across buffers, and its own sequence number from 0; a buffer whose
//   checksum or sequence number is not the expected one (tampered with,
//   replayed, reordered or dropped) closes the connection, as does one
//   larger than sasl_ntlm_options::max_receive_size. Outgoing PDUs go in
//   buffers of at most 128 KiB (Samba's default). connection::
//   security_layer() reports the layer; with one in effect start_tls() and
//   a bind negotiating another fail (client_errc::security_layer_in_effect).
//   Active Directory may refuse any further bind on that connection
//   (MS-ADTS section 5.1.1.1.2: unwillingToPerform without the
//   LDAP_CAP_ACTIVE_DIRECTORY_LDAP_INTEG_OID capability). Only over plain
//   ldap://: Active Directory refuses a SASL layer over TLS (MS-ADTS
//   section 5.1.1.1.2), so with TLS start() fails with
//   client_errc::security_layer_unavailable before anything is sent. A
//   requested layer stands in for TLS: require_tls is not consulted then
//   (integrity alone leaves the PDUs readable to an eavesdropper, but not
//   changeable). The layer's secrets (the ExportedSessionKey, the four keys,
//   the RC4 states) are wiped as the bind's are, the RC4 states and keys
//   when the connection drops the layer. RC4 and HMAC-MD5 are what MS-NLMP
//   defines: the layer is no match for TLS against a determined attacker,
//   but it is what Active Directory's "LDAP server signing requirements"
//   policy accepts on plain ldap://.
// - TLS is required by default (sasl_ntlm_options::require_tls): start()
//   fails with client_errc::tls_required (cond::access_denied) on a
//   connection without TLS, before anything is sent. Over plain ldap://
//   (require_tls false, no security layer) the exchange stays safe from
//   eavesdroppers as far as NTLMv2 goes (an attacker who records it can
//   still try passwords offline against the NTProofStr), but every PDU
//   after the bind is in clear and unsigned, and an active attacker can
//   take over the bound connection. Active Directory with the "Domain
//   controller: LDAP server signing requirements" policy set to require
//   signing refuses such an unsigned bind on plain ldap://
//   (errc::stronger_auth_required, diagnostic 00002028): use ldaps://,
//   StartTLS, or a security layer there.
// - Channel binding (MS-NLMP section 3.1.5.1.2, MsvAvChannelBindings):
//   over TLS the AUTHENTICATE_MESSAGE carries the MD5 hash of a
//   gss_channel_bindings_struct (RFC 2744 section 3.11, no addresses) whose
//   application data is "tls-server-end-point:" and the hash of the
//   server's certificate (RFC 5929 section 4.1; prefixed_channel_binding,
//   channel_binding.hpp), as Windows does; Active Directory with "Domain
//   controller: LDAP server channel binding token requirements" set to
//   "Always" requires it. Over TLS without that hash (a certificate
//   without one, e.g. Ed25519 or Ed448, or no server certificate) start()
//   fails with client_errc::tls_required rather than bind without it.
//   ntlm_channel_binding::none opts out (a server behind a TLS-terminating
//   proxy). Without TLS the value is 16 zero octets (Z(16)).
// - The NTProofStr covers the client's TargetInfo: the server's AV_PAIRs,
//   MsvAvFlags with the MIC bit, MsvAvChannelBindings and MsvAvTargetName
//   (the service principal name, "ldap/<host>" by default). The MIC
//   (HMAC-MD5 of the three messages, keyed with the ExportedSessionKey:
//   with no key exchange, i.e. no security layer, the SessionBaseKey) keeps
//   the messages from being changed in transit. The timestamp is the
//   server's MsvAvTimestamp (then the LmChallengeResponse is Z(24), as
//   MS-NLMP section 3.1.5.1.2 says), the current time when it sent none.
// - Unicode: the username, domain, password, workstation and target are
//   UTF-8, sent as UTF-16LE (ill-formed UTF-8 is refused). NTOWFv2 hashes
//   the password's UTF-16 as it is (no normalization: Windows hashes what
//   was typed) and uppercases the user name with the simple case mapping
//   (ntlm_uppercase_unicode), as Windows does; the domain is not
//   uppercased (MS-NLMP section 3.3.2).
// - The user: "DOMAIN\user" is split at its first backslash into the
//   domain and the user name; "user@dns.domain" (a UPN) is sent as the
//   user name with an empty domain, which Active Directory accepts; a bare
//   "user" goes with sasl_ntlm_options::domain (empty: the server's
//   domain). An explicit sasl_ntlm_options::domain keeps the username as
//   given.
// - The password is kept (to allow later binds with the same object) and
//   wiped with OPENSSL_cleanse when the object is destroyed, as are its
//   UTF-16 form, the NT hash, NTOWFv2 and the SessionBaseKey once used:
//   each is built in place in its wiped buffer, or copied into one and
//   its source cleansed at once (step()'s copy of NTOWFv2 and the
//   exported session key), never returned or moved by value (which would
//   leave an unwiped copy behind). OpenSSL's HMAC
//   working state, registers and spill slots are beyond the library's
//   reach.
//
// Errors (contexts never contain the password, nor name the mechanism:
// sasl_bind prefixes "sasl bind GSS-SPNEGO"):
// - client_errc::tls_required (cond::access_denied): no TLS with
//   require_tls (and no security layer), or no tls-server-end-point hash
//   with channel binding.
// - client_errc::security_layer_unavailable (cond::access_denied): a
//   security layer asked for over TLS, or one the CHALLENGE_MESSAGE does
//   not grant.
// - client_errc::encode_error (cond::invalid_input): an empty user name,
//   ill-formed UTF-8, a target or an AUTHENTICATE_MESSAGE field too long,
//   max_receive_size below 16 with a security layer.
// - client_errc::decode_error (cond::protocol_error): a malformed
//   CHALLENGE_MESSAGE (bounds-checked: every offset and length, the
//   AV_PAIR list), or none.
// - client_errc::unexpected_response (cond::protocol_error): a challenge
//   that does not offer NTLMv2, a challenge after the AUTHENTICATE_MESSAGE,
//   or a server that reports success before it (then connection::sasl_bind
//   closes the connection).
// - client_errc::internal_error: OpenSSL (RAND_bytes, MD5, HMAC-MD5)
//   failed, e.g. MD5 unavailable in a FIPS-only configuration.
// Once a layer is in effect, a protected buffer that does not verify
// closes the connection; the read fails with client_errc::decode_error
// (a malformed signature) or client_errc::unexpected_response (a checksum
// or sequence number that is not the expected one).
// A server that refuses the credentials answers invalidCredentials
// (errc::invalid_credentials, cond::auth_failed).
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
	none,// Z(16), even over TLS
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
	// and the hash); empty: Z(16).
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
