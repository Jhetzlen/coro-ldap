#include "trust_store.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <string>
#include <string_view>

namespace jhetz::ldap::net::detail {

auto revocation_retrieval_budget(std::optional<std::chrono::milliseconds> timeout) noexcept -> std::chrono::milliseconds
{
	return std::clamp(
	  timeout.value_or(max_revocation_retrieval), std::chrono::milliseconds(1), max_revocation_retrieval);
}

auto strong_sign_for_level(int security_level) -> std::optional<strong_sign_lists>
{
	// OpenSSL's minbits_table (crypto/x509/x509_vfy.c), by level 1 to 5,
	// and the RSA sizes it rates at those bits.
	static constexpr std::array<int, 5> min_security_bits{ 80, 112, 128, 192, 256 };
	static constexpr std::array<int, 5> min_rsa_bits{ 1024, 2048, 3072, 7680, 15360 };
	static constexpr std::array<int, 3> sha2_digest_bits{ 256, 384, 512 };
	static constexpr std::array<std::wstring_view, 2> sign_algorithms{ L"RSA", L"ECDSA" };
	if (security_level <= 0) {
		return std::nullopt;
	}
	const auto level = static_cast<std::size_t>(std::min(security_level, static_cast<int>(min_security_bits.size())));
	const int bits = min_security_bits.at(level - 1);
	strong_sign_lists out;
	for (const int digest : sha2_digest_bits) {
		if (digest < 2 * bits) {
			continue;
		}
		for (const auto algorithm : sign_algorithms) {
			if (!out.sign_hash_algids.empty()) {
				out.sign_hash_algids += L';';
			}
			out.sign_hash_algids += algorithm;
			out.sign_hash_algids += L"/SHA" + std::to_wstring(digest);
		}
	}
	out.min_key_bits = L"RSA/" + std::to_wstring(min_rsa_bits.at(level - 1)) + L";ECDSA/" + std::to_wstring(2 * bits);
	return out;
}

}// namespace jhetz::ldap::net::detail
