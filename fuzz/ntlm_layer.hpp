// The keys of every NTLM security layer the layer fuzzer and its replay
// build.
#pragma once

#include "jhetz/ldap/error.hpp"
#include "jhetz/ldap/sasl_ntlm.hpp"

#include <cstddef>
#include <expected>
#include <utility>

namespace jhetz::ldap::fuzz {

// The ExportedSessionKey (that of the golden security layer test).
inline constexpr detail::ntlm_key ntlm_layer_session_key{ 0x00,
	0x11,
	0x22,
	0x33,
	0x44,
	0x55,
	0x66,
	0x77,
	0x88,
	0x99,
	0xAA,
	0xBB,
	0xCC,
	0xDD,
	0xEE,
	0xFF };

// The largest buffer one layer accepts (max_received()).
inline constexpr std::size_t ntlm_layer_max_received = std::size_t{ 1 } << 20;

struct ntlm_layer_keys
{
	detail::ntlm_session_keys client;
	detail::ntlm_session_keys server;// the client's, both directions swapped
};

// The keys of ntlm_layer_session_key (the derivation is OpenSSL's MD5).
inline auto ntlm_layer_derive_keys() -> result<ntlm_layer_keys>
{
	ntlm_layer_keys keys;
	if (auto r = detail::ntlm_derive_session_keys(ntlm_layer_session_key, keys.client); !r) {
		return std::unexpected(std::move(r.error()));
	}
	keys.server = { .client_signing_key = keys.client.server_signing_key,
		.client_sealing_key = keys.client.server_sealing_key,
		.server_signing_key = keys.client.client_signing_key,
		.server_sealing_key = keys.client.client_sealing_key };
	return keys;
}

}// namespace jhetz::ldap::fuzz
