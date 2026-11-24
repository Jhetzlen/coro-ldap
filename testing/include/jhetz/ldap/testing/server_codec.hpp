// The server side of the codec, for the mock servers, tests, fuzzers and
// benchmarks: request decoding and the response controls a server writes.
// Not part of the installed library.
#pragma once

#include "jhetz/ldap/ad/controls.hpp"
#include "jhetz/ldap/ber.hpp"
#include "jhetz/ldap/content_sync.hpp"
#include "jhetz/ldap/controls.hpp"
#include "jhetz/ldap/error.hpp"
#include "jhetz/ldap/filter.hpp"
#include "jhetz/ldap/message.hpp"
#include "jhetz/ldap/ntlm_message.hpp"

#include <cstddef>
#include <memory_resource>
#include <optional>
#include <span>
#include <string>
#include <string_view>

namespace jhetz::ldap::testing {

// ---------------------------------------------------------------- messages

// Which side sent the message being decoded.
enum class origin {
	any,// requests and responses
	server,// responses only
	client,// requests only
};

struct decode_options
{
	// Operations the peer may not send fail with unsupported_operation.
	origin from = origin::any;
	std::size_t max_depth = ber::reader::default_max_depth;
	filter_limits filter{};
	// Strings one message may decode to; more fail with message_too_large.
	std::size_t max_elements = default_max_elements;
	// Everything the decoded message owns; errors use the default resource.
	std::pmr::memory_resource *memory = std::pmr::get_default_resource();
};

// ldap::decode with the request operations: exactly one LDAPMessage, from
// the side `options.from` names.
[[nodiscard]] auto decode(std::span<const std::byte> one_complete_message, const decode_options &options = {})
  -> result<message>;

// Reads one BER Filter from `r` into a tree on `mr`; `r` is unchanged on
// failure.
[[nodiscard]] auto decode_filter(ber::reader &r,
  const filter_limits &limits = {},
  std::pmr::memory_resource *mr = std::pmr::get_default_resource()) -> result<filter>;

// ---------------------------------------------------------------- response controls

[[nodiscard]] auto encode_sort_result(const sort_result &value,
  bool criticality = false,
  std::pmr::memory_resource *mr = std::pmr::get_default_resource()) -> result<control>;

[[nodiscard]] auto encode_vlv_response(const vlv_response &value,
  bool criticality = false,
  std::pmr::memory_resource *mr = std::pmr::get_default_resource()) -> result<control>;

// `oid` is pre_read_oid or post_read_oid.
[[nodiscard]] auto encode_read_entry(std::string_view oid,
  const search_result_entry &entry,
  bool criticality = false,
  std::pmr::memory_resource *mr = std::pmr::get_default_resource()) -> result<control>;

[[nodiscard]] auto encode_sync_state(const sync_state &value,
  bool criticality = false,
  std::pmr::memory_resource *mr = std::pmr::get_default_resource()) -> result<control>;

[[nodiscard]] auto encode_sync_done(const sync_done &value,
  bool criticality = false,
  std::pmr::memory_resource *mr = std::pmr::get_default_resource()) -> result<control>;

[[nodiscard]] auto encode_sync_info(const sync_info &value,
  std::pmr::memory_resource *mr = std::pmr::get_default_resource()) -> result<intermediate_response>;

// ---------------------------------------------------------------- request controls

[[nodiscard]] auto decode_matched_values(const control &c,
  std::pmr::memory_resource *mr = std::pmr::get_default_resource()) -> result<matched_values>;

[[nodiscard]] auto decode_virtual_list_view(const control &c) -> result<virtual_list_view>;

[[nodiscard]] auto decode_transaction_specification(const control &c) -> result<transaction_specification>;

[[nodiscard]] auto decode_sync_request(const control &c) -> result<sync_request>;

// ---------------------------------------------------------------- transactions (RFC 5805)

[[nodiscard]] auto decode_end_transaction_request(std::string_view value) -> result<end_transaction_request>;

// nullopt when both fields are absent.
[[nodiscard]] auto encode_end_transaction_response(const end_transaction_response &value,
  std::pmr::memory_resource *mr = std::pmr::get_default_resource()) -> result<std::optional<std::pmr::string>>;

// ---------------------------------------------------------------- DirSync

namespace ad {

	[[nodiscard]] auto decode_dirsync_request(const control &c) -> result<ldap::ad::dirsync_request>;

	[[nodiscard]] auto encode_dirsync_response(const ldap::ad::dirsync_response &value,
	  bool criticality = false,
	  std::pmr::memory_resource *mr = std::pmr::get_default_resource()) -> control;

}// namespace ad

// ---------------------------------------------------------------- NTLM (MS-NLMP)

[[nodiscard]] auto encode_ntlm_challenge(const detail::ntlm_challenge_message &message) -> std::string;

[[nodiscard]] auto parse_ntlm_authenticate(std::string_view message) -> result<detail::ntlm_authenticate_message>;

}// namespace jhetz::ldap::testing
