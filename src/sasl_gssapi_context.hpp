// Internal: the client security context behind sasl_gssapi, implemented over
// GSS-API (sasl_gssapi_gss.cpp) or SSPI (sasl_gssapi_sspi.cpp).
#pragma once

#include "jhetz/ldap/error.hpp"
#include "jhetz/ldap/sasl_gssapi.hpp"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <memory_resource>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace jhetz::ldap::detail {

struct gssapi_request
{
	// "service@host".
	std::string_view target;
	// Empty: the default credentials.
	std::string_view principal;
	// Empty: none (credentials held for `principal`).
	std::string_view password;
	// The channel bindings' application data; empty: none.
	std::string_view bindings;
	// Integrity and confidentiality asked for.
	bool layer = false;
};

class gssapi_context
{
  public:
	gssapi_context();
	~gssapi_context();
	gssapi_context(gssapi_context &&) noexcept;
	auto operator=(gssapi_context &&) noexcept -> gssapi_context &;
	gssapi_context(const gssapi_context &) = delete;
	auto operator=(const gssapi_context &) -> gssapi_context & = delete;

	// Names and credentials for `request`, kept for the following init calls.
	[[nodiscard]] auto acquire(const gssapi_request &request) -> result<void>;
	// One context establishment call with the server's token (none at
	// first): the output token, possibly empty. Fails if the context is
	// established without mutual authentication.
	[[nodiscard]] auto init(std::optional<std::string_view> token) -> result<std::string>;
	[[nodiscard]] auto established() const noexcept -> bool;
	// The established context's protection.
	[[nodiscard]] auto flags() const noexcept -> gssapi_context_flags;
	// Appends the wrap token of `plaintext` to `out`.
	[[nodiscard]] auto wrap(std::span<const std::byte> plaintext,
	  bool confidentiality,
	  std::pmr::vector<std::byte> &out) -> result<void>;
	// Appends the plaintext of `token` to `out`; `confidential` says whether
	// it was encrypted. A replayed or out-of-sequence token fails.
	[[nodiscard]] auto unwrap(std::span<const std::byte> token, std::pmr::vector<std::byte> &out, bool &confidential)
	  -> result<void>;
	// The most plaintext whose wrap token fits in `max_size` octets.
	[[nodiscard]] auto wrap_size_limit(bool confidentiality, std::uint32_t max_size) const -> result<std::size_t>;
	// Releases everything: an empty context again.
	void reset() noexcept;

  private:
	struct handles;
	std::unique_ptr<handles> h_;
};

// Well-formed UTF-8 without control characters (Cc).
[[nodiscard]] auto gssapi_check_text(std::string_view s, std::string_view what) -> result<void>;

// UTF-8 to UTF-16; encode_error naming `what` for ill-formed UTF-8.
[[nodiscard]] auto utf8_to_utf16(std::string_view s, std::string_view what) -> result<std::u16string>;

// The SEC_WINNT_AUTH_IDENTITY_W fields, UTF-16: "user@domain", "DOMAIN\user"
// or "user".
struct sspi_identity
{
	std::u16string user;
	std::u16string domain;
	std::u16string password;
	sspi_identity() = default;
	sspi_identity(const sspi_identity &) = delete;
	auto operator=(const sspi_identity &) -> sspi_identity & = delete;
	sspi_identity(sspi_identity &&) noexcept = default;
	auto operator=(sspi_identity &&) noexcept -> sspi_identity & = default;
	~sspi_identity();
};
[[nodiscard]] auto make_sspi_identity(std::string_view principal, std::string_view password) -> result<sspi_identity>;

// The SSPI target name of a "service@host" target: "service/host".
[[nodiscard]] auto sspi_target_name(std::string_view target) -> result<std::u16string>;

// The gssapi_failure of an SSPI call's status (SSPI backend only).
[[nodiscard]] auto sspi_failure(std::string_view call, std::int32_t status) -> std::unexpected<error>;

}// namespace jhetz::ldap::detail
