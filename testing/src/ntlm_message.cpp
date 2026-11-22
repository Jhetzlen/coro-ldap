// The server side of the MS-NLMP messages: CHALLENGE_MESSAGE out,
// AUTHENTICATE_MESSAGE in.
#include "jhetz/ldap/testing/server_codec.hpp"

#include "ntlm_wire.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <tuple>

namespace jhetz::ldap::testing {

namespace {

	using namespace ldap::detail;
	using namespace ldap::detail::ntlm_wire;

}// namespace

auto encode_ntlm_challenge(const ntlm_challenge_message &message) -> std::string
{
	const bool with_info =
	  !message.target_info.empty() || (message.negotiate_flags & ntlmssp_negotiate_target_info) != 0;
	const std::string info = with_info ? encode_ntlm_av_pairs(message.target_info) : std::string{};
	std::string out(ntlmssp_signature);
	put32(out, ntlm_challenge_message_type);
	put_fields(out, message.target_name.size(), challenge_version_size);
	put32(out, message.negotiate_flags);
	out.append(reinterpret_cast<const char *>(message.server_challenge.data()), message.server_challenge.size());
	out.append(ntlm_challenge_size, '\0');// Reserved
	put_fields(out, info.size(), challenge_version_size + message.target_name.size());
	if (message.version) {
		put_version(out, *message.version);
	} else {
		out.append(version_size, '\0');
	}
	out += message.target_name;
	out += info;
	return out;
}

auto parse_ntlm_authenticate(std::string_view message) -> result<ntlm_authenticate_message>
{
	constexpr std::string_view kind = "AUTHENTICATE_MESSAGE";
	if (auto h = check_header(message, kind, ntlm_authenticate_header_size, ntlm_authenticate_message_type); !h) {
		return std::unexpected(std::move(h.error()));
	}
	ntlm_authenticate_message out;
	const std::array<std::tuple<std::string *, std::size_t, std::string_view>, 6> fields{ {
	  { &out.lm_challenge_response, auth_lm_fields, "LmChallengeResponse" },
	  { &out.nt_challenge_response, auth_nt_fields, "NtChallengeResponse" },
	  { &out.domain_name, auth_domain_fields, "DomainName" },
	  { &out.user_name, auth_user_fields, "UserName" },
	  { &out.workstation, auth_workstation_fields, "Workstation" },
	  { &out.encrypted_random_session_key, auth_session_key_fields, "EncryptedRandomSessionKey" },
	} };
	for (const auto &[value, at, name] : fields) {
		auto f = payload_field(message, kind, at, name);
		if (!f) {
			return std::unexpected(std::move(f.error()));
		}
		*value = std::string(*f);
	}
	out.negotiate_flags = get32(message, auth_flags);
	out.version = get_version(message, auth_version);
	std::ranges::copy(message.substr(ntlm_authenticate_mic_offset, ntlm_key_size), out.mic.begin());
	return out;
}

}// namespace jhetz::ldap::testing
