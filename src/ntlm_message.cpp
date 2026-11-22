// The MS-NLMP messages and MD4 (RFC 1320). See ntlm_message.hpp.
#include "jhetz/ldap/ntlm_message.hpp"

#include "format_util.hpp"
#include "icu_util.hpp"
#include "ntlm_wire.hpp"

#include <unicode/uchar.h>

#include <algorithm>
#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>
#include <vector>

namespace jhetz::ldap::detail {

namespace {

	using namespace ntlm_wire;

	auto parse_av_pairs(std::string_view field) -> result<std::vector<ntlm_av_pair>>
	{
		constexpr std::string_view kind = "CHALLENGE_MESSAGE";
		std::vector<ntlm_av_pair> pairs;
		bool have_flags = false;
		bool have_timestamp = false;
		std::size_t at = 0;
		while (true) {
			if (field.size() - at < av_header_size) {
				return malformed(kind, "TargetInfo ends without MsvAvEOL");
			}
			const auto id = get16(field, at);
			const std::size_t length = get16(field, at + 2);
			at += av_header_size;
			if (length > field.size() - at) {
				return malformed(
				  kind, detail::format("AV_PAIR {}: AvLen {} runs past the end of TargetInfo", id, length));
			}
			const auto av_id = static_cast<ntlm_av_id>(id);
			if (av_id == ntlm_av_id::msv_av_eol) {
				if (length != 0) {
					return malformed(kind, detail::format("MsvAvEOL with AvLen {}, not 0", length));
				}
				return pairs;
			}
			if (av_id == ntlm_av_id::msv_av_flags) {
				if (length != av_flags_size || have_flags) {
					return malformed(kind, have_flags ? "MsvAvFlags twice" : "MsvAvFlags not of 4 octets");
				}
				have_flags = true;
			}
			if (av_id == ntlm_av_id::msv_av_timestamp) {
				if (length != av_timestamp_size || have_timestamp) {
					return malformed(kind, have_timestamp ? "MsvAvTimestamp twice" : "MsvAvTimestamp not of 8 octets");
				}
				have_timestamp = true;
			}
			pairs.push_back({ .av_id = av_id, .value = std::string(field.substr(at, length)) });
			at += length;
		}
	}

	void append_utf16le(std::string &out, std::uint32_t c)
	{
		constexpr std::uint32_t bmp_end = 0x1'0000;
		constexpr std::uint32_t lead_base = 0xD800;
		constexpr std::uint32_t trail_base = 0xDC00;
		constexpr unsigned surrogate_bits = 10;
		constexpr std::uint32_t surrogate_mask = 0x3FF;
		if (c < bmp_end) {
			put16(out, c);
			return;
		}
		const std::uint32_t v = c - bmp_end;
		put16(out, lead_base + (v >> surrogate_bits));
		put16(out, trail_base + (v & surrogate_mask));
	}

	// Into `out`, reserved once for the longest result so it never
	// reallocates.
	template<class Map> auto to_utf16le(std::string_view utf8, Map map, std::string &out) -> result<void>
	{
		out.clear();
		out.reserve(utf8.size() * 2);
		for (std::size_t i = 0; i < utf8.size();) {
			const auto [c, n] = utf8_next(utf8, i);
			if (c < 0) {
				return fail(client_errc::encode_error, "not valid UTF-8");
			}
			append_utf16le(out, static_cast<std::uint32_t>(map(c)));
			i += n;
		}
		return {};
	}

	template<class Map> auto to_utf16le(std::string_view utf8, Map map) -> result<std::string>
	{
		std::string out;
		if (auto r = to_utf16le(utf8, map, out); !r) {
			return std::unexpected(std::move(r.error()));
		}
		return out;
	}

	// ---------------------------------------------------------------- MD4 (RFC 1320)

	// Zeroes `n` octets at `p` through a volatile pointer.
	void wipe_bytes(void *p, std::size_t n) noexcept
	{
		for (volatile unsigned char &b : std::span(static_cast<volatile unsigned char *>(p), n)) {
			b = 0;
		}
	}

	template<typename T, std::size_t N> void wipe_array(std::array<T, N> &a) noexcept
	{
		wipe_bytes(a.data(), sizeof a);
	}

	// The chaining state, wiped when it goes out of scope: for NTOWFv2 it
	// ends as the NT hash, and each block() reads the password's UTF-16.
	struct md4_state
	{
		// RFC 1320 section 3.3, words A, B, C, D.
		static constexpr std::array<std::uint32_t, 4> initial_abcd{ 0x6745'2301u,
			0xEFCD'AB89u,
			0x98BA'DCFEu,
			0x1032'5476u };
		std::array<std::uint32_t, 4> abcd = initial_abcd;

		md4_state() = default;
		md4_state(const md4_state &) = delete;
		auto operator=(const md4_state &) -> md4_state & = delete;
		~md4_state() { wipe_array(abcd); }

		static constexpr std::size_t block_size = 64;
		static constexpr std::uint32_t round2_constant = 0x5A82'7999u;
		static constexpr std::uint32_t round3_constant = 0x6ED9'EBA1u;

		static constexpr auto f(std::uint32_t x, std::uint32_t y, std::uint32_t z) -> std::uint32_t
		{
			return (x & y) | (~x & z);
		}
		static constexpr auto g(std::uint32_t x, std::uint32_t y, std::uint32_t z) -> std::uint32_t
		{
			return (x & y) | (x & z) | (y & z);
		}
		static constexpr auto h(std::uint32_t x, std::uint32_t y, std::uint32_t z) -> std::uint32_t
		{
			return x ^ y ^ z;
		}

		// RFC 1320 section 3.4, one 16-word block.
		void block(std::span<const unsigned char, block_size> b) noexcept
		{
			std::array<std::uint32_t, 16> x{};
			for (std::size_t i = 0; i < x.size(); ++i) {
				const std::size_t at = 4 * i;
				x[i] = std::uint32_t{ b[at] } | std::uint32_t{ b[at + 1] } << byte_bits
					   | std::uint32_t{ b[at + 2] } << (2 * byte_bits) | std::uint32_t{ b[at + 3] } << (3 * byte_bits);
			}
			auto [a, bb, c, d] = abcd;
			// Round 1: [abcd k s] a = (a + F(b,c,d) + X[k]) <<< s.
			constexpr std::array<int, 4> s1{ 3, 7, 11, 19 };
			for (std::size_t i = 0; i < 16; ++i) {
				const std::uint32_t t = std::rotl(a + f(bb, c, d) + x[i], s1[i % 4]);
				a = d;
				d = c;
				c = bb;
				bb = t;
			}
			// Round 2: [abcd k s] a = (a + G(b,c,d) + X[k] + 5A827999) <<< s,
			// k in the order 0 4 8 12, 1 5 9 13, ...
			constexpr std::array<int, 4> s2{ 3, 5, 9, 13 };
			for (std::size_t i = 0; i < 16; ++i) {
				const std::size_t k = ((i % 4) * 4) + (i / 4);
				const std::uint32_t t = std::rotl(a + g(bb, c, d) + x[k] + round2_constant, s2[i % 4]);
				a = d;
				d = c;
				c = bb;
				bb = t;
			}
			// Round 3: [abcd k s] a = (a + H(b,c,d) + X[k] + 6ED9EBA1) <<< s,
			// k in the order 0 8 4 12, 2 10 6 14, 1 9 5 13, 3 11 7 15.
			constexpr std::array<int, 4> s3{ 3, 9, 11, 15 };
			constexpr std::array<std::size_t, 16> k3{ 0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15 };
			for (std::size_t i = 0; i < 16; ++i) {
				const std::uint32_t t = std::rotl(a + h(bb, c, d) + x[k3[i]] + round3_constant, s3[i % 4]);
				a = d;
				d = c;
				c = bb;
				bb = t;
			}
			abcd[0] += a;
			abcd[1] += bb;
			abcd[2] += c;
			abcd[3] += d;
			// The message words; a, bb, c, d and t live in registers (or
			// spill slots the compiler picks), which C++ cannot reach.
			wipe_array(x);
		}
	};

}// namespace

auto encode_ntlm_negotiate(std::uint32_t negotiate_flags, const ntlm_version &version) -> std::string
{
	std::string out(ntlmssp_signature);
	put32(out, ntlm_negotiate_message_type);
	put32(out, negotiate_flags);
	put_fields(out, 0, negotiate_size);// DomainNameFields
	put_fields(out, 0, negotiate_size);// WorkstationFields
	put_version(out, version);
	return out;
}

auto parse_ntlm_challenge(std::string_view message) -> result<ntlm_challenge_message>
{
	constexpr std::string_view kind = "CHALLENGE_MESSAGE";
	if (auto h = check_header(message, kind, challenge_fixed_size, ntlm_challenge_message_type); !h) {
		return std::unexpected(std::move(h.error()));
	}
	ntlm_challenge_message out;
	out.negotiate_flags = get32(message, challenge_flags);
	std::ranges::copy(message.substr(challenge_server_challenge, ntlm_challenge_size), out.server_challenge.begin());
	if ((out.negotiate_flags & ntlmssp_negotiate_version) != 0) {
		if (message.size() < challenge_version_size) {
			return malformed(kind,
			  detail::format("{} octets, shorter than its {}-octet fixed part with a Version",
				message.size(),
				challenge_version_size));
		}
		out.version = get_version(message, challenge_version);
	}
	auto target_name = payload_field(message, kind, challenge_target_name_fields, "TargetName");
	if (!target_name) {
		return std::unexpected(std::move(target_name.error()));
	}
	out.target_name = std::string(*target_name);
	auto target_info = payload_field(message, kind, challenge_target_info_fields, "TargetInfo");
	if (!target_info) {
		return std::unexpected(std::move(target_info.error()));
	}
	if (!target_info->empty()) {
		auto pairs = parse_av_pairs(*target_info);
		if (!pairs) {
			return std::unexpected(std::move(pairs.error()));
		}
		out.target_info = std::move(*pairs);
	}
	return out;
}

auto encode_ntlm_av_pairs(std::span<const ntlm_av_pair> pairs) -> std::string
{
	std::string out;
	for (const auto &p : pairs) {
		put16(out, static_cast<std::uint32_t>(p.av_id));
		put16(out, static_cast<std::uint32_t>(p.value.size()));
		out += p.value;
	}
	put16(out, static_cast<std::uint32_t>(ntlm_av_id::msv_av_eol));
	put16(out, 0);
	return out;
}

auto ntlm_timestamp(std::span<const ntlm_av_pair> pairs) -> std::optional<std::uint64_t>
{
	for (const auto &p : pairs) {
		if (p.av_id == ntlm_av_id::msv_av_timestamp && p.value.size() == av_timestamp_size) {
			return get_le(p.value, 0, av_timestamp_size);
		}
	}
	return std::nullopt;
}

auto ntlm_client_target_info(std::span<const ntlm_av_pair> server,
  bool mic,
  const std::optional<ntlm_key> &channel_bindings,
  std::string_view target_name) -> std::vector<ntlm_av_pair>
{
	std::vector<ntlm_av_pair> out;
	bool have_flags = false;
	for (const auto &p : server) {
		if (p.av_id == ntlm_av_id::msv_av_channel_bindings || p.av_id == ntlm_av_id::msv_av_target_name) {
			continue;
		}
		out.push_back(p);
		if (p.av_id == ntlm_av_id::msv_av_flags && p.value.size() == av_flags_size) {
			have_flags = true;
			if (mic) {
				std::string flags;
				put32(flags, static_cast<std::uint32_t>(get_le(p.value, 0, av_flags_size)) | msv_av_flags_mic);
				out.back().value = std::move(flags);
			}
		}
	}
	if (!have_flags && mic) {
		std::string flags;
		put32(flags, msv_av_flags_mic);
		out.push_back({ .av_id = ntlm_av_id::msv_av_flags, .value = std::move(flags) });
	}
	if (channel_bindings) {
		out.push_back({ .av_id = ntlm_av_id::msv_av_channel_bindings,
		  .value = std::string(reinterpret_cast<const char *>(channel_bindings->data()), channel_bindings->size()) });
	}
	if (!target_name.empty()) {
		out.push_back({ .av_id = ntlm_av_id::msv_av_target_name, .value = std::string(target_name) });
	}
	return out;
}

auto encode_ntlm_authenticate(const ntlm_authenticate_message &message) -> result<std::string>
{
	// The payload, in this order (section 2.2.1.3's Payload).
	const std::array<std::pair<const std::string *, std::size_t>, 6> fields{ {
	  { &message.domain_name, auth_domain_fields },
	  { &message.user_name, auth_user_fields },
	  { &message.workstation, auth_workstation_fields },
	  { &message.lm_challenge_response, auth_lm_fields },
	  { &message.nt_challenge_response, auth_nt_fields },
	  { &message.encrypted_random_session_key, auth_session_key_fields },
	} };
	std::string out(ntlm_authenticate_header_size, '\0');
	std::ranges::copy(ntlmssp_signature, out.begin());
	std::string fixed;
	put32(fixed, ntlm_authenticate_message_type);
	std::ranges::copy(fixed, out.begin() + static_cast<std::ptrdiff_t>(message_type_offset));
	for (const auto &[value, at] : fields) {
		if (value->size() > max_field_length) {
			return fail(client_errc::encode_error,
			  detail::format("AUTHENTICATE_MESSAGE: a field of {} octets (at most 65535)", value->size()));
		}
		std::string f;
		put_fields(f, value->size(), out.size());
		std::ranges::copy(f, out.begin() + static_cast<std::ptrdiff_t>(at));
		out += *value;
	}
	std::string tail;
	put32(tail, message.negotiate_flags);
	put_version(tail, message.version);
	tail.append(reinterpret_cast<const char *>(message.mic.data()), message.mic.size());
	std::ranges::copy(tail, out.begin() + static_cast<std::ptrdiff_t>(auth_flags));
	return out;
}

auto ntlm_unicode(std::string_view utf8) -> result<std::string>
{
	return to_utf16le(utf8, [](UChar32 c) { return c; });
}

auto ntlm_unicode(std::string_view utf8, std::string &out) -> result<void>
{
	return to_utf16le(utf8, [](UChar32 c) { return c; }, out);
}

auto ntlm_uppercase_unicode(std::string_view utf8) -> result<std::string>
{
	constexpr UChar32 bmp_end = 0x1'0000;
	return to_utf16le(utf8, [](UChar32 c) {
		if (c >= bmp_end) {
			return c;// a surrogate pair: Windows maps each UTF-16 unit on its own
		}
		const UChar32 upper = u_toupper(c);
		return upper < bmp_end ? upper : c;
	});
}

void md4(std::span<const std::byte> data, ntlm_key &out) noexcept
{
	md4_state st;
	const auto *bytes = reinterpret_cast<const unsigned char *>(data.data());
	const std::size_t n = data.size();
	std::size_t at = 0;
	for (; n - at >= md4_state::block_size; at += md4_state::block_size) {
		st.block(std::span<const unsigned char, md4_state::block_size>(bytes + at, md4_state::block_size));
	}
	// RFC 1320 sections 3.1 and 3.2: a 1 bit, zeros to 56 mod 64 octets,
	// then the length in bits, 64 bits little-endian.
	constexpr std::size_t length_at = 56;
	std::array<unsigned char, 2 * md4_state::block_size> tail{};
	const std::size_t rest = n - at;
	std::copy_n(bytes + at, rest, tail.begin());
	constexpr unsigned char one_bit = 0x80;
	tail[rest] = one_bit;
	const std::size_t total = rest < length_at ? md4_state::block_size : 2 * md4_state::block_size;
	const std::uint64_t bits = static_cast<std::uint64_t>(n) * byte_bits;
	for (std::size_t i = 0; i < sizeof bits; ++i) {
		tail[total - sizeof bits + i] = static_cast<unsigned char>((bits >> (byte_bits * i)) & byte_mask);
	}
	for (std::size_t b = 0; b < total; b += md4_state::block_size) {
		st.block(std::span<const unsigned char, md4_state::block_size>(tail.data() + b, md4_state::block_size));
	}
	wipe_array(tail);
	for (std::size_t i = 0; i < st.abcd.size(); ++i) {
		for (std::size_t k = 0; k < 4; ++k) {
			out[(4 * i) + k] = static_cast<unsigned char>((st.abcd[i] >> (byte_bits * k)) & byte_mask);
		}
	}
}

// ---------------------------------------------------------------- RC4 (MS-NLMP section 6)

ntlm_rc4::ntlm_rc4(std::span<const unsigned char> key) noexcept
{
	for (std::size_t k = 0; k < s_.size(); ++k) {
		s_[k] = static_cast<unsigned char>(k);
	}
	// The key-scheduling algorithm: j = j + S[i] + key[i mod keylength].
	unsigned char j = 0;
	for (std::size_t k = 0; k < s_.size(); ++k) {
		j = static_cast<unsigned char>(j + s_[k] + (key.empty() ? 0 : key[k % key.size()]));
		std::swap(s_[k], s_[j]);
	}
}

ntlm_rc4::~ntlm_rc4()
{
	wipe_array(s_);
	wipe_bytes(&i_, sizeof i_);
	wipe_bytes(&j_, sizeof j_);
}

void ntlm_rc4::apply(std::span<unsigned char> data) noexcept
{
	for (unsigned char &b : data) {
		i_ = static_cast<unsigned char>(i_ + 1);
		j_ = static_cast<unsigned char>(j_ + s_[i_]);
		std::swap(s_[i_], s_[j_]);
		b ^= s_[static_cast<unsigned char>(s_[i_] + s_[j_])];
	}
}

void ntlm_rc4::apply(std::span<std::byte> data) noexcept
{
	apply(std::span(reinterpret_cast<unsigned char *>(data.data()), data.size()));
}

// ---------------------------------------------------------------- NTLMSSP_MESSAGE_SIGNATURE

void encode_ntlm_signature(const ntlm_message_signature &signature,
  std::span<std::byte, ntlm_signature_size> out) noexcept
{
	const auto put = [&](std::size_t at, std::uint32_t v) {
		for (std::size_t i = 0; i < 4; ++i) {
			out[at + i] = static_cast<std::byte>((v >> (byte_bits * i)) & byte_mask);
		}
	};
	put(0, signature.version);
	for (std::size_t i = 0; i < ntlm_checksum_size; ++i) {
		out[4 + i] = static_cast<std::byte>(signature.checksum[i]);
	}
	put(ntlm_signature_seq_num_offset, signature.seq_num);
}

auto parse_ntlm_protected_buffer(std::span<const std::byte> buffer) -> result<ntlm_protected_buffer>
{
	constexpr std::string_view kind = "NTLM protected buffer";
	if (buffer.size() < ntlm_signature_size) {
		return malformed(kind, detail::format("{} octets, shorter than its 16-octet signature", buffer.size()));
	}
	const std::string_view s(reinterpret_cast<const char *>(buffer.data()), ntlm_signature_size);
	ntlm_protected_buffer out{
		.signature = { .version = get32(s, 0), .checksum = {}, .seq_num = get32(s, ntlm_signature_seq_num_offset) },
		.message = buffer.subspan(ntlm_signature_size)
	};
	if (out.signature.version != ntlm_signature_version) {
		return malformed(kind, detail::format("signature Version {}, not 1", out.signature.version));
	}
	for (std::size_t i = 0; i < ntlm_checksum_size; ++i) {
		out.signature.checksum[i] = static_cast<unsigned char>(s[4 + i]);
	}
	return out;
}

}// namespace jhetz::ldap::detail
