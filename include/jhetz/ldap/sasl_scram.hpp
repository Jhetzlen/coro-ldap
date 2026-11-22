// SASL SCRAM-SHA-256 and SCRAM-SHA-256-PLUS (RFC 5802, RFC 7677) for
// connection::sasl_bind (docs/API.md, "SASL").
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

// gs2-cbind-flag (RFC 5802 section 7).
enum class scram_channel_binding : std::uint8_t {
	none,// "n": no channel binding support claimed
	not_offered,// "y" over TLS ("n" otherwise): the server did not advertise -PLUS
	plus,// "p=<type>": SCRAM-SHA-256-PLUS
};

enum class scram_channel_binding_form : std::uint8_t {
	// RFC 5802 section 7: "p=<type name>".
	rfc5802,
	// OpenLDAP's: "p=ldap", c= over "<type name>:" and the data, with
	// tls-server-end-point hashed as OpenLDAP does.
	openldap,
};

// plus if `server_mechanisms` holds SCRAM-SHA-256-PLUS (case-sensitive),
// else not_offered.
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

struct sasl_scram_options
{
	// "dn:..." or "u:..."; empty: the authenticated identity.
	std::string authz_id{};
	scram_channel_binding channel_binding = scram_channel_binding::not_offered;
	// nullopt: the connection's default type (tls-server-end-point in the
	// openldap form).
	std::optional<channel_binding_type> binding_type{};
	// openldap with binding_type tls_exporter fails with encode_error.
	scram_channel_binding_form binding_form = scram_channel_binding_form::rfc5802;
	// The largest iteration count accepted from the server.
	static constexpr std::uint32_t default_max_iterations = 1'000'000;
	std::uint32_t max_iterations = default_max_iterations;
	// PBKDF2 with more iterations runs on a thread of its own; 0: always.
	std::uint32_t offload_above_iterations = 16'384;
};

class sasl_scram_sha256 final : public sasl_mechanism
{
  public:
	// RFC 7677 section 4.
	static constexpr std::uint32_t min_iterations = 4096;

	// The `password` parameter is wiped once copied; the inputs are checked by
	// start().
	sasl_scram_sha256(std::string username, std::string password, std::string authz_id = {});
	sasl_scram_sha256(std::string username, std::string password, sasl_scram_options options);
	~sasl_scram_sha256() override;

	// Not copyable, not movable: no stray password copies.
	sasl_scram_sha256(const sasl_scram_sha256 &) = delete;
	auto operator=(const sasl_scram_sha256 &) -> sasl_scram_sha256 & = delete;

	[[nodiscard]] auto name() const noexcept -> std::string_view override
	{
		return options_.channel_binding == scram_channel_binding::plus ? "SCRAM-SHA-256-PLUS" : "SCRAM-SHA-256";
	}
	// Keeps whether a step can be offloaded, TLS, and the binding data.
	void prepare(const sasl_bind_context &context) override;
	// client-first-message: GS2 header, n=<username>, r=<client nonce>.
	[[nodiscard]] auto start() -> result<std::optional<std::string>> override;
	// The server-first-message gives the client-final-message; a
	// server-final-message sent as a challenge is verified.
	[[nodiscard]] auto step(std::optional<std::string_view> challenge) -> result<std::optional<std::string>> override;
	// step()'s PBKDF2 for another thread when above offload_above_iterations
	// and not cached; empty otherwise.
	[[nodiscard]] auto offload_step(std::optional<std::string_view> challenge) -> sasl_work override;
	// Verifies "v=" unless step() already did.
	[[nodiscard]] auto complete(std::optional<std::string_view> server_creds) -> result<void> override;
	// With plus, after a successful start(): the type bound to.
	[[nodiscard]] auto channel_binding_used() const noexcept -> std::optional<channel_binding_type> override
	{
		if (options_.channel_binding != scram_channel_binding::plus || state_ == state::idle) {
			return std::nullopt;
		}
		return binding_type_;
	}

  private:
	friend struct detail::scram_test_access;
	// Tests only: a fixed client nonce. Wipes `password`.
	sasl_scram_sha256(std::string username,
	  std::string &password,
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
	std::string prepared_password_;// from start() until PBKDF2
	sasl_scram_options options_;
	std::optional<std::string> fixed_nonce_;
	bool can_offload_ = false;// from prepare()
	bool tls_ = false;// from prepare()
	// From prepare(); nullopt: none available.
	std::optional<channel_binding_type> binding_type_;
	std::string binding_data_;
	state state_ = state::idle;
	std::string gs2_header_;
	// cbind-input (RFC 5802 section 7).
	std::string cbind_input_;
	std::string client_nonce_;
	std::string client_first_bare_;
	std::array<unsigned char, 32> server_signature_{};
	bool have_signature_ = false;
	// The offloaded step, until its result is collected.
	std::shared_ptr<derivation> pending_;
	// The SaltedPassword for (cache_salt_, cache_iterations_).
	std::array<unsigned char, 32> cache_salted_{};
	std::string cache_salt_;
	std::uint32_t cache_iterations_ = 0;// 0: nothing cached
};

}// namespace jhetz::ldap
