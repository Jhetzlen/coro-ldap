// libFuzzer target for the NTLM security layer: unwrap of the input, wrap
// and unwrap round trips both ways, and a flipped bit refused.
#include "jhetz/ldap/sasl_ntlm.hpp"

#include "check.hpp"
#include "ntlm_layer.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <memory_resource>
#include <numeric>
#include <span>

constexpr jhetz::ldap::fuzz::checker check{ "ntlm_layer_fuzz" };

namespace ldap = jhetz::ldap;
namespace detail = jhetz::ldap::detail;
namespace fuzz = jhetz::ldap::fuzz;

namespace {

constexpr std::size_t max_received = fuzz::ntlm_layer_max_received;

// Picks the flipped bit from the input.
constexpr std::size_t hash_multiplier = 31;

// What `out` holds before each call: kept by wrap() and unwrap().
constexpr std::array<std::byte, 3> prefix{ std::byte{ 0xA5 }, std::byte{ 0x5A }, std::byte{ 0xC3 } };

auto with_prefix() -> std::pmr::vector<std::byte> { return { prefix.begin(), prefix.end() }; }

auto has_prefix(const std::pmr::vector<std::byte> &out) -> bool
{
	return out.size() >= prefix.size() && std::ranges::equal(std::span(out).first(prefix.size()), prefix);
}

auto appended(const std::pmr::vector<std::byte> &out) -> std::span<const std::byte>
{
	return std::span(out).subspan(prefix.size());
}

auto refused(const ldap::error &e) -> bool
{
	return e.code == ldap::client_errc::decode_error || e.code == ldap::client_errc::unexpected_response;
}

// `from` wraps a message, `to` unwraps it back.
struct direction
{
	detail::ntlm_security_layer *from;
	detail::ntlm_security_layer *to;
};

void round_trip(direction d, std::span<const std::byte> message)
{
	auto wrapped = with_prefix();
	check(d.from->wrap(message, wrapped).has_value(), "wrap succeeds");
	check(has_prefix(wrapped), "wrap keeps out");
	check(wrapped.size() == prefix.size() + detail::ntlm_signature_size + message.size(), "wrapped size");
	auto unwrapped = with_prefix();
	check(d.to->unwrap(appended(wrapped), unwrapped).has_value(), "unwrap of a wrapped buffer succeeds");
	check(has_prefix(unwrapped), "unwrap keeps out");
	check(std::ranges::equal(appended(unwrapped), message), "round trip gives the message back");
}

void check_protection(const fuzz::ntlm_layer_keys &keys,
  ldap::sasl_protection protection,
  std::span<const std::byte> input)
{
	{
		detail::ntlm_security_layer client(keys.client, protection, max_received);
		auto out = with_prefix();
		if (auto r = client.unwrap(input, out); !r) {
			check(refused(r.error()), "unwrap fails with decode_error or unexpected_response");
			check(std::ranges::equal(out, prefix), "a failed unwrap leaves out unchanged");
		} else {
			check(has_prefix(out), "unwrap keeps out");
			detail::ntlm_security_layer server(keys.server, protection, max_received);
			std::pmr::vector<std::byte> rewrapped;
			check(server.wrap(appended(out), rewrapped).has_value(), "rewrap succeeds");
			check(std::ranges::equal(rewrapped, input), "an accepted buffer is the server's");
		}
	}
	{
		detail::ntlm_security_layer client(keys.client, protection, max_received);
		detail::ntlm_security_layer server(keys.server, protection, max_received);
		for (int i = 0; i < 2; ++i) {
			round_trip({ .from = &client, .to = &server }, input);
			round_trip({ .from = &server, .to = &client }, input);
		}
	}
	{
		detail::ntlm_security_layer client(keys.client, protection, max_received);
		detail::ntlm_security_layer server(keys.server, protection, max_received);
		std::pmr::vector<std::byte> wrapped;
		check(client.wrap(input, wrapped).has_value(), "wrap succeeds");
		const std::size_t sum =
		  std::accumulate(input.begin(), input.end(), input.size(), [](std::size_t acc, std::byte b) {
			  return (acc * hash_multiplier) + std::to_integer<std::size_t>(b);
		  });
		constexpr std::size_t bits = 8;
		wrapped[sum % wrapped.size()] ^= std::byte{ static_cast<unsigned char>(1u << ((sum / wrapped.size()) % bits)) };
		auto out = with_prefix();
		auto r = server.unwrap(wrapped, out);
		check(!r, "a flipped bit is refused");
		check(refused(r.error()), "a flipped bit fails with decode_error or unexpected_response");
		check(std::ranges::equal(out, prefix), "a refused buffer leaves out unchanged");
	}
}

}// namespace

extern "C" auto LLVMFuzzerTestOneInput(const std::uint8_t *data, std::size_t size) -> int
{
	static const fuzz::ntlm_layer_keys keys = [] {
		auto k = fuzz::ntlm_layer_derive_keys();
		check(k.has_value(), "the session keys derive");
		return *k;
	}();
	const auto input = std::as_bytes(std::span(data, size));
	for (const auto protection : { ldap::sasl_protection::integrity, ldap::sasl_protection::confidentiality }) {
		check_protection(keys, protection, input);
	}
	return 0;
}
