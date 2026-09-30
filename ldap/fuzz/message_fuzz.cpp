// libFuzzer target for the LDAPMessage codec (also driven by
// message_fuzz_replay).
//
// For any input it must not crash, and if the input decodes as a message:
// - it encodes (the decoder only accepts what the encoder can write);
// - the encoding decodes to an equal message and re-encodes to the same bytes;
// - the framer measures the encoding as exactly one complete message;
// - a paged results control that decodes re-encodes to an equal value;
// - search entries convert to ldap::entry, results to ldap::error;
// - decode_options::from accepts exactly the responses (origin::server) or the
//   requests (origin::client), failing otherwise with unsupported_operation.
// Also, with the input as (possibly non-canonical) filter text of a search
// request m: if encode(m) succeeds, encode(decode(encode(m))) == encode(m).
#include "jhetz/ldap/entry.hpp"
#include "jhetz/ldap/message.hpp"

#define FUZZ_TARGET "message_fuzz"
#include "check.hpp"

#include <cstdint>
#include <span>
#include <string>
#include <type_traits>
#include <variant>

namespace {

namespace ldap = jhetz::ldap;

template<class T>
concept has_result = requires(const T &t) { t.result.to_error(); };

void exercise(const ldap::message &m)
{
	for (const auto &c : m.controls) {
		if (c.type != ldap::paged_results_oid) continue;
		if (auto p = ldap::decode_paged_results(c)) {
			const auto again = ldap::encode_paged_results(*p, c.criticality);
			LDAP_FUZZ_CHECK(again.has_value());
			LDAP_FUZZ_CHECK(ldap::decode_paged_results(*again) == *p);
		} else {
			LDAP_FUZZ_CHECK(p.error().code == ldap::client_errc::decode_error
							|| p.error().code == ldap::client_errc::unexpected_tag
							|| p.error().code == ldap::client_errc::nesting_too_deep
							|| p.error().code == ldap::client_errc::integer_overflow
							|| p.error().code == ldap::client_errc::unsupported_tag);
		}
	}
	std::visit(
	  [](const auto &op) {
		  using T = std::decay_t<decltype(op)>;
		  if constexpr (std::is_same_v<T, ldap::search_result_entry>) {
			  const auto e = ldap::entry::from(op);
			  LDAP_FUZZ_CHECK(e.dn == op.object_name);
			  for (const auto &a : op.attributes) LDAP_FUZZ_CHECK(e.find(a.type) != nullptr);
		  } else if constexpr (has_result<T>) {
			  const auto err = op.result.to_error("fuzz");
			  LDAP_FUZZ_CHECK(err.code.value() == op.result.result_code);
			  LDAP_FUZZ_CHECK(!err.message().empty());
		  }
	  },
	  m.op);
}

template<class T>
constexpr bool is_request_v = std::is_same_v<T, ldap::bind_request> || std::is_same_v<T, ldap::unbind_request>
							  || std::is_same_v<T, ldap::search_request> || std::is_same_v<T, ldap::modify_request>
							  || std::is_same_v<T, ldap::add_request> || std::is_same_v<T, ldap::del_request>
							  || std::is_same_v<T, ldap::modify_dn_request> || std::is_same_v<T, ldap::compare_request>
							  || std::is_same_v<T, ldap::abandon_request> || std::is_same_v<T, ldap::extended_request>;

void check_origins(std::span<const std::byte> input, const ldap::message &m)
{
	const bool request = std::visit([](const auto &op) { return is_request_v<std::decay_t<decltype(op)>>; }, m.op);
	auto from_server = ldap::decode(input, { .from = ldap::origin::server });
	auto from_client = ldap::decode(input, { .from = ldap::origin::client });
	LDAP_FUZZ_CHECK(from_server.has_value() == !request);
	LDAP_FUZZ_CHECK(from_client.has_value() == request);
	const auto &rejected = request ? from_server : from_client;
	LDAP_FUZZ_CHECK(rejected.error().code == ldap::client_errc::unsupported_operation);
	LDAP_FUZZ_CHECK(*(request ? from_client : from_server) == m);
}

// encode(decode(encode(m))) == encode(m) for arbitrary filter text.
void check_filter_text(std::span<const std::uint8_t> data)
{
	const std::string text(reinterpret_cast<const char *>(data.data()), data.size());
	const ldap::message m{ .id = 1, .op = ldap::search_request{ .filter = ldap::filter::raw(text) } };
	auto encoded = ldap::encode(m);
	if (!encoded) {
		LDAP_FUZZ_CHECK(encoded.error().code == ldap::client_errc::invalid_filter);
		return;
	}
	auto decoded = ldap::decode(*encoded);
	LDAP_FUZZ_CHECK(decoded.has_value());
	auto again = ldap::encode(*decoded);
	LDAP_FUZZ_CHECK(again.has_value() && *again == *encoded);
}

}// namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *data, std::size_t size)
{
	const auto input = std::as_bytes(std::span(data, size));
	check_filter_text(std::span(data, size));
	auto m = ldap::decode(input);
	if (!m) {
		LDAP_FUZZ_CHECK(static_cast<bool>(m.error().code));
		return 0;
	}

	auto encoded = ldap::encode(*m);
	LDAP_FUZZ_CHECK(encoded.has_value());
	auto again = ldap::decode(*encoded);
	LDAP_FUZZ_CHECK(again.has_value());
	LDAP_FUZZ_CHECK(*again == *m);
	auto reencoded = ldap::encode(*again);
	LDAP_FUZZ_CHECK(reencoded.has_value() && *reencoded == *encoded);

	auto framed = jhetz::ldap::ber::complete_message_size(*encoded);
	LDAP_FUZZ_CHECK(framed && *framed && **framed == encoded->size());

	check_origins(input, *m);
	exercise(*m);
	return 0;
}
