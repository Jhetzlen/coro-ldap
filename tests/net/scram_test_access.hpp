// Tests only: builds a sasl_scram_sha256 with a fixed client nonce (e.g. the
// RFC 7677 test vector's) instead of a fresh random one. Shared by every
// test file that needs it, so the friend struct has a single definition.
#pragma once

#include "jhetz/ldap/sasl_scram.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <utility>

namespace jhetz::ldap::detail {

struct scram_test_access
{
	static auto with_nonce(std::string username, std::string password, std::string authz_id, std::string nonce)
	  -> sasl_scram_sha256
	{
		return with_nonce(std::move(username),
		  std::move(password),
		  sasl_scram_options{ .authz_id = std::move(authz_id) },
		  std::move(nonce));
	}

	static auto with_nonce(std::string username, std::string password, sasl_scram_options options, std::string nonce)
	  -> sasl_scram_sha256
	{
		return {
			std::move(username), std::move(password), std::move(options), std::optional<std::string>(std::move(nonce))
		};
	}

	// The iteration count whose SaltedPassword is cached (0: none).
	static auto cached_iterations(const sasl_scram_sha256 &m) -> std::uint32_t { return m.cache_iterations_; }

	// The SASLprep'ed password the mechanism holds (empty when it holds none).
	static auto prepared_password(const sasl_scram_sha256 &m) -> const std::string & { return m.prepared_password_; }
};

}// namespace jhetz::ldap::detail
