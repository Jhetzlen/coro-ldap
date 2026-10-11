// Tests only: builds a sasl_scram_sha256 with a fixed client nonce (e.g. the
// RFC 7677 test vector's) instead of a fresh random one. Shared by every
// test file that needs it, so the friend struct has a single definition.
#pragma once

#include "jhetz/ldap/sasl_scram.hpp"

#include <optional>
#include <string>
#include <utility>

namespace jhetz::ldap::detail {

struct scram_test_access
{
	static sasl_scram_sha256
	  with_nonce(std::string username, std::string password, std::string authz_id, std::string nonce)
	{
		return sasl_scram_sha256(
		  std::move(username), std::move(password), std::move(authz_id), std::optional<std::string>(std::move(nonce)));
	}
};

}// namespace jhetz::ldap::detail
