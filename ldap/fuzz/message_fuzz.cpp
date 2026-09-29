// libFuzzer target for the LDAPMessage codec (also driven by
// message_fuzz_replay).
//
// For any input it must not crash, and if the input decodes as a message:
// - it encodes (the decoder only accepts what the encoder can write);
// - the encoding decodes to an equal message and re-encodes to the same bytes;
// - the framer measures the encoding as exactly one complete message;
// - a paged results control that decodes re-encodes to an equal value;
// - search entries convert to ldap::entry, results to ldap::error.
#include "jhetz/ldap/entry.hpp"
#include "jhetz/ldap/message.hpp"

#define FUZZ_TARGET "message_fuzz"
#include "check.hpp"

#include <cstdint>
#include <span>
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
			LDAP_FUZZ_CHECK(ldap::decode_paged_results(again) == *p);
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

}// namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *data, std::size_t size)
{
	const auto input = std::as_bytes(std::span(data, size));
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

	exercise(*m);
	return 0;
}
