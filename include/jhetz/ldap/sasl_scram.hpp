// SASL SCRAM-SHA-256 (RFC 5802, RFC 7677), client side, for
// connection::sasl_bind (DESIGN.md section 3, "SCRAM-SHA-256"):
//
//   ldap::sasl_scram_sha256 mech("jdoe", password);
//   if (auto r = co_await conn.sasl_bind(mech); !r) ...
//
// A password mechanism with mutual authentication: the password never
// crosses the wire, and the bind fails unless the server's "v=" signature
// proves it knows the stored keys. SCRAM does not protect the rest of the
// session: use TLS. Part of jhetz::ldap_net (OpenSSL, ICU).
//
// Channel binding (RFC 5802 sections 6 and 7, RFC 5056, RFC 9266),
// sasl_scram_options::channel_binding:
// - none (default): mechanism SCRAM-SHA-256, GS2 header "n,," ("n,a=<authzid>,"
//   with an authorization identity).
// - plus: mechanism SCRAM-SHA-256-PLUS, GS2 header "p=<type>,,", c= binds the
//   authentication to the TLS connection. sasl_scram_options::binding_type
//   picks the type; default channel_bindings::default_type (tls-exporter on
//   TLS 1.3; on TLS 1.2 tls-server-end-point, or tls-exporter with the
//   extended master secret when the certificate has no
//   tls-server-end-point). For OpenLDAP's slapd set binding_form to
//   scram_channel_binding_form::openldap ("p=ldap,,", tls-server-end-point
//   hashed as OpenLDAP does). Without TLS or binding data of the type,
//   start() fails with client_errc::tls_required. tls-exporter serves one
//   authentication per TLS connection (RFC 9266 section 4.1): once a bind
//   used it (from a successful start() on), later binds there get no
//   tls-exporter data, so the default falls back to tls-server-end-point,
//   else start() fails with tls_required.
// - not_offered: the server did not advertise SCRAM-SHA-256-PLUS. Mechanism
//   SCRAM-SHA-256 with "y,," on a TLS connection with binding data ("n,,"
//   otherwise), so a -PLUS server refuses the bind if a man in the middle
//   stripped -PLUS (RFC 5802 section 6).
// scram_channel_binding_for() maps the root DSE's supportedSASLMechanisms to
// plus or not_offered; reading it without TLS is fine.
//
// - Usernames and passwords are UTF-8, prepared with SASLprep (RFC 4013, ICU):
//   the password as a stored string, the username as a query (RFC 5802
//   sections 2.2 and 5.1); invalid UTF-8 and prohibited text are refused.
//   cyrus-sasl (slapd) does not SASLprep stored passwords, so a password
//   SASLprep changes does not match there.
// - The authorization identity must be valid UTF-8 without control
//   characters (C0, DEL, C1); it is not SASLprep'ed.
// - '=' and ',' in the username and authorization identity are escaped as
//   "=3D" and "=2C".
// - The server's iteration count must be in [min_iterations,
//   options.max_iterations] (4096 .. 1'000'000 by default, about 0.45 s of
//   PBKDF2 at the top).
// - PBKDF2 runs on a thread of its own (offload_step(), sasl.hpp) above
//   options.offload_above_iterations (16'384 by default) when the io_context
//   accepts posts from other threads (locking_mode::safe or unsafe_io), else
//   inside step(). The bind's timeout and cancellation apply to the wait; a
//   step given up on runs to its end and its result is dropped.
// - The SaltedPassword is cached per (salt, iteration count) and wiped with
//   OPENSSL_cleanse when replaced or on destruction.
// - The server nonce must extend the client nonce.
// - The password is kept for later binds and wiped on destruction; SASLprep
//   buffers when start() returns; the prepared password and derived keys
//   once the proof is built. ICU's internal buffers and the caller's copies
//   are not wiped.
//
// Errors (contexts never contain the password; sasl_bind prefixes
// "sasl bind SCRAM-SHA-256"):
// - client_errc::tls_required (cond::access_denied): plus without TLS or
//   without binding data of the chosen type.
// - client_errc::encode_error (cond::invalid_input): binding_form openldap
//   with binding_type tls_exporter; an empty username or password (also after
//   SASLprep), invalid UTF-8, a prohibited or unassigned character, a bidi
//   violation; max_iterations outside [min_iterations, 2^31-1].
// - client_errc::decode_error (cond::protocol_error): a malformed server
//   message.
// - client_errc::unexpected_response (cond::protocol_error): a message out of
//   order, a nonce not extending ours, an iteration count out of bounds, an
//   unknown mandatory extension ("m="), a server error ("e=", quoted
//   sanitized, at most 64 bytes), a wrong server signature, or success
//   without a valid signature. The last three mean the server is not
//   authenticated; if it already reported success, sasl_bind closes the
//   connection.
// - client_errc::internal_error (no condition): OpenSSL or ICU failed.
// - errc::invalid_credentials (cond::auth_failed): the server refused the
//   proof.
#pragma once

#include "jhetz/ldap/channel_binding.hpp"
#include "jhetz/ldap/sasl.hpp"

#include <array>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>

namespace jhetz::ldap {

namespace detail {
	struct scram_test_access;// defined by the tests only
}

// The client's channel binding choice (gs2-cbind-flag, RFC 5802 section 7;
// see the header comment).
enum class scram_channel_binding : std::uint8_t {
	none,// "n": SCRAM-SHA-256, no channel binding support claimed
	not_offered,// "y" over TLS ("n" otherwise): SCRAM-SHA-256, the server did not advertise -PLUS
	plus,// "p=<type>": SCRAM-SHA-256-PLUS
};

// The form of the channel binding with scram_channel_binding::plus.
enum class scram_channel_binding_form : std::uint8_t {
	// RFC 5802 section 7: "p=<type name>", c= over the GS2 header and the
	// binding data. The type is sasl_scram_options::binding_type, or the
	// connection's default.
	rfc5802,
	// OpenLDAP's (libldap and slapd's "sasl-cbinding", through 2.6 at
	// least), which does not follow RFC 5802 section 7: "p=ldap", and c=
	// over the GS2 header and "<type name>:" then the data (the generic
	// form of RFC 5056 section 2.1, which GSS-API uses). The type is
	// tls-server-end-point (OpenLDAP has no tls-exporter; binding_type
	// tls_exporter is refused) and its hash is OpenLDAP's: the hash named
	// by the certificate's signature algorithm, SHA-256 for RSASSA-PSS,
	// Ed25519 and Ed448 too (where RFC 5929 takes the PSS hash, or has
	// none).
	openldap,
};

// plus if `server_mechanisms` (e.g. the root DSE's supportedSASLMechanisms
// values) holds SCRAM-SHA-256-PLUS, else not_offered. The comparison is
// case-sensitive: SASL mechanism names are upper case (RFC 4422 section
// 3.1).
template<class Range>
[[nodiscard]] auto scram_channel_binding_for(const Range &server_mechanisms) -> scram_channel_binding
{
	for (const auto &m : server_mechanisms) {
		if (std::string_view(m) == "SCRAM-SHA-256-PLUS") {
			return scram_channel_binding::plus;
		}
	}
	return scram_channel_binding::not_offered;
}

// Tuning of sasl_scram_sha256 (see the header comment).
struct sasl_scram_options
{
	// An identity to act as ("dn:...", "u:..."); empty: the authenticated
	// identity itself.
	std::string authz_id{};
	// Channel binding, and with it the mechanism name (SCRAM-SHA-256 or
	// SCRAM-SHA-256-PLUS). none keeps the plain SCRAM-SHA-256 exchange.
	scram_channel_binding channel_binding = scram_channel_binding::none;
	// With scram_channel_binding::plus, the channel binding type; nullopt:
	// the connection's default (channel_bindings::default_type), or
	// tls-server-end-point in the openldap form.
	std::optional<channel_binding_type> binding_type{};
	// With scram_channel_binding::plus, the form: RFC 5802's (the default),
	// or openldap for a slapd with "sasl-cbinding tls-endpoint", which
	// refuses the RFC form ("Unsupported channel bindings type").
	// openldap with binding_type tls_exporter fails start() with
	// client_errc::encode_error when channel_binding is plus (otherwise
	// the form is not used).
	scram_channel_binding_form binding_form = scram_channel_binding_form::rfc5802;
	// The largest iteration count accepted from the server: PBKDF2's cost,
	// which the server chooses. In [sasl_scram_sha256::min_iterations,
	// 2^31-1]. Servers use 4096 to a few hundred thousand.
	static constexpr std::uint32_t default_max_iterations = 1'000'000;
	std::uint32_t max_iterations = default_max_iterations;
	// PBKDF2 with more iterations than this runs on a thread of its own
	// (when sasl_bind can offload it); up to it, on the I/O thread. 0:
	// always offloaded; max_iterations or more: never.
	std::uint32_t offload_above_iterations = 16'384;
};

class sasl_scram_sha256 final : public sasl_mechanism
{
  public:
	// RFC 7677 section 4: the iteration count "SHOULD be at least 4096".
	static constexpr std::uint32_t min_iterations = 4096;

	// `username`: the SASL authentication identity (for slapd, mapped to a DN
	// with authz-regexp). `authz_id`: an identity to act as ("dn:...",
	// "u:..."), empty: the authenticated identity itself. The inputs are
	// checked by start(), so the constructors cannot fail.
	// The `password` parameter is wiped once moved from (a short
	// password's bytes would stay in its buffer). A string the caller moves
	// into it is the caller's to wipe: moving out of a short string leaves
	// its bytes behind.
	sasl_scram_sha256(std::string username, std::string password, std::string authz_id = {});
	sasl_scram_sha256(std::string username, std::string password, sasl_scram_options options);
	~sasl_scram_sha256() override;

	// Holds a password: not copyable, not movable (no stray copies to wipe).
	sasl_scram_sha256(const sasl_scram_sha256 &) = delete;
	auto operator=(const sasl_scram_sha256 &) -> sasl_scram_sha256 & = delete;

	// "SCRAM-SHA-256", or "SCRAM-SHA-256-PLUS" with
	// scram_channel_binding::plus.
	[[nodiscard]] auto name() const noexcept -> std::string_view override
	{
		return options_.channel_binding == scram_channel_binding::plus ? "SCRAM-SHA-256-PLUS" : "SCRAM-SHA-256";
	}
	// Notes whether sasl_bind can run a step on another thread
	// (sasl_bind_context::can_offload), whether TLS protects the connection
	// and its channel binding data (copied: start() uses it).
	void prepare(const sasl_bind_context &context) override;
	// client-first-message: GS2 header, n=<username>, r=<client nonce>.
	// The channel binding data is the last prepare()'s (none without one).
	[[nodiscard]] auto start() -> result<std::optional<std::string>> override;
	// After the client-first-message: the server-first-message gives the
	// client-final-message (c=, r=, p=<proof>), PBKDF2 included. After the
	// client-final-message (a server that sends its server-final-message as
	// a challenge rather than with the success result): verifies it and
	// answers with an empty response.
	[[nodiscard]] auto step(std::optional<std::string_view> challenge) -> result<std::optional<std::string>> override;
	// The work of step() on the server-first-message when its PBKDF2 is to
	// run on a thread of its own (above options.offload_above_iterations,
	// not cached, after a prepare() that allowed it); empty otherwise, step()
	// then does it (a malformed message included: step() reports it).
	[[nodiscard]] auto offload_step(std::optional<std::string_view> challenge) -> sasl_work override;
	// Verifies the server-final-message ("v=") unless step() already did.
	[[nodiscard]] auto complete(std::optional<std::string_view> server_creds) -> result<void> override;
	// With scram_channel_binding::plus, after a start() that succeeded: the
	// type bound to ("p=<type>"); nullopt otherwise.
	[[nodiscard]] auto channel_binding_used() const noexcept -> std::optional<channel_binding_type> override
	{
		if (options_.channel_binding != scram_channel_binding::plus || state_ == state::idle) {
			return std::nullopt;
		}
		return binding_type_;
	}

  private:
	friend struct detail::scram_test_access;
	// `fixed_nonce`: tests only (detail::scram_test_access), a fixed client
	// nonce (e.g. the RFC 7677 test vector's) instead of a fresh random one.
	sasl_scram_sha256(std::string username,
	  std::string password,
	  sasl_scram_options options,
	  std::optional<std::string> fixed_nonce);

	enum class state : std::uint8_t { idle, sent_first, sent_final, verified };
	struct server_first;// the parsed server-first-message
	struct derivation;// PBKDF2 and the keys, shared with an offloaded step

	auto parse_server_first(std::string_view message) -> result<server_first>;
	auto client_final(std::string_view message) -> result<std::optional<std::string>>;
	void collect() noexcept;
	auto verify(std::string_view server_final) -> result<void>;
	void wipe() noexcept;
	void wipe_cache() noexcept;

	std::string username_;
	std::string password_;
	std::string prepared_password_;// SASLprep'ed, from start() until PBKDF2
	sasl_scram_options options_;
	std::optional<std::string> fixed_nonce_;
	bool can_offload_ = false;// from prepare()
	bool tls_ = false;// from prepare(): TLS protects the connection
	// From prepare(): the channel binding type and data used with
	// scram_channel_binding::plus or not_offered (nullopt: none available).
	std::optional<channel_binding_type> binding_type_;
	std::string binding_data_;
	state state_ = state::idle;
	std::string gs2_header_;
	// cbind-input (RFC 5802 section 7): the GS2 header, then the channel
	// binding data with "p="; c= carries its base64.
	std::string cbind_input_;
	std::string client_nonce_;
	std::string client_first_bare_;
	std::array<unsigned char, 32> server_signature_{};
	bool have_signature_ = false;// server_signature_ was computed for this exchange
	// The step offloaded for this exchange, until its result is collected.
	std::shared_ptr<derivation> pending_;
	// The SaltedPassword of the last PBKDF2, for (cache_salt_, cache_iterations_).
	std::array<unsigned char, 32> cache_salted_{};
	std::string cache_salt_;
	std::uint32_t cache_iterations_ = 0;// 0: nothing cached
};

}// namespace jhetz::ldap
