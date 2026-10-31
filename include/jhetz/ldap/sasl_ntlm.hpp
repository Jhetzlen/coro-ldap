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
// - No security layer: the client negotiates neither signing nor sealing
//   (no NTLMSSP_NEGOTIATE_SIGN, SEAL, ALWAYS_SIGN nor KEY_EXCH), so the
//   session after the bind is protected only by TLS, if any.
// - TLS is required by default (sasl_ntlm_options::require_tls): start()
//   fails with client_errc::tls_required (cond::access_denied) on a
//   connection without TLS, before anything is sent. Over plain ldap://
//   (require_tls false) the exchange stays safe from eavesdroppers as far
//   as NTLMv2 goes (an attacker who records it can still try passwords
//   offline against the NTProofStr), but every PDU after the bind is in
//   clear and unsigned, and an active attacker can take over the bound
//   connection. Active Directory with the "Domain controller: LDAP server
//   signing requirements" policy set to require signing refuses such an
//   unsigned bind on plain ldap:// (errc::stronger_auth_required,
//   diagnostic 00002028): use ldaps:// or StartTLS there.
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
//   (HMAC-MD5 of the three messages, keyed with the SessionBaseKey: with
//   no key exchange the exported session key is the SessionBaseKey) keeps
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
//   require_tls, or no tls-server-end-point hash with channel binding.
// - client_errc::encode_error (cond::invalid_input): an empty user name,
//   ill-formed UTF-8, a target or an AUTHENTICATE_MESSAGE field too long.
// - client_errc::decode_error (cond::protocol_error): a malformed
//   CHALLENGE_MESSAGE (bounds-checked: every offset and length, the
//   AV_PAIR list), or none.
// - client_errc::unexpected_response (cond::protocol_error): a challenge
//   that does not offer NTLMv2, a challenge after the AUTHENTICATE_MESSAGE,
//   or a server that reports success before it (then connection::sasl_bind
//   closes the connection).
// - client_errc::internal_error: OpenSSL (RAND_bytes, MD5, HMAC-MD5)
//   failed, e.g. MD5 unavailable in a FIPS-only configuration.
// A server that refuses the credentials answers invalidCredentials
// (errc::invalid_credentials, cond::auth_failed).
#pragma once

#include "jhetz/ldap/channel_binding.hpp"
#include "jhetz/ldap/error.hpp"
#include "jhetz/ldap/ntlm_message.hpp"
#include "jhetz/ldap/sasl.hpp"

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>

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

}// namespace detail

}// namespace jhetz::ldap
