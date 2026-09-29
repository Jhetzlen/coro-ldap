#include "jhetz/ldap/ber.hpp"
#include "test_util.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>

namespace ber = jhetz::ldap::ber;
using jhetz::ldap::client_errc;
using jhetz::ldap::test::bytes;

namespace {

// "need more", "size N" or the error code, for readable comparisons.
std::string frame(std::span<const std::byte> buf, std::size_t max_size = ber::default_max_message_size)
{
	auto r = ber::complete_message_size(buf, max_size);
	if (!r) return std::string(r.error().code.category().name()) + ":" + std::to_string(r.error().code.value());
	if (!*r) return "need more";
	return "size " + std::to_string(**r);
}

const std::string too_large = "ldap.client:" + std::to_string(static_cast<int>(client_errc::message_too_large));
const std::string decode_error = "ldap.client:" + std::to_string(static_cast<int>(client_errc::decode_error));
const std::string unsupported_tag = "ldap.client:" + std::to_string(static_cast<int>(client_errc::unsupported_tag));

const auto bind_request = bytes({ 0x30, 0x0C, 0x02, 0x01, 0x01, 0x60, 0x07, 0x02, 0x01, 0x03, 0x04, 0x00, 0x80, 0x00 });

}// namespace

TEST_CASE("complete_message_size waits for a complete header", "[ber][framer]")
{
	CHECK(frame({}) == "need more");
	CHECK(frame(bytes({ 0x30 })) == "need more");
	CHECK(frame(bytes({ 0x30, 0x83, 0x01, 0x00 })) == "need more");// one length octet missing
}

TEST_CASE("complete_message_size waits for complete content", "[ber][framer]")
{
	for (std::size_t n = 0; n < bind_request.size(); ++n) {
		INFO("prefix of " << n << " bytes");
		CHECK(frame(std::span(bind_request).first(n)) == "need more");
	}
}

TEST_CASE("complete_message_size reports the size of the first element", "[ber][framer]")
{
	CHECK(frame(bind_request) == "size 14");

	auto two = bind_request;
	two.insert(two.end(), bind_request.begin(), bind_request.end());
	two.push_back(std::byte{ 0x30 });
	CHECK(frame(two) == "size 14");

	// Long-form header: 30 82 01 00 + 256 content bytes.
	std::vector<std::byte> big = bytes({ 0x30, 0x82, 0x01, 0x00 });
	big.resize(4 + 255);
	CHECK(frame(big) == "need more");
	big.resize(4 + 256);
	CHECK(frame(big) == "size 260");
}

TEST_CASE("complete_message_size rejects oversized messages from the header alone", "[ber][framer]")
{
	// Declares 16 MiB + 1 of content; only the 6 header bytes are present.
	CHECK(frame(bytes({ 0x30, 0x84, 0x01, 0x00, 0x00, 0x01 })) == too_large);
	// Exactly 16 MiB in total (5 header + 16 MiB - 5 content) is allowed: still waiting.
	CHECK(frame(bytes({ 0x30, 0x83, 0xFF, 0xFF, 0xFB })) == "need more");
	CHECK(frame(bytes({ 0x30, 0x83, 0xFF, 0xFF, 0xFC })) == too_large);
	// Largest encodable length, 4 GiB - 1.
	CHECK(frame(bytes({ 0x30, 0x84, 0xFF, 0xFF, 0xFF, 0xFF })) == too_large);

	// max_size bounds header + content.
	CHECK(frame(bytes({ 0x30, 0x03 }), 5) == "need more");
	CHECK(frame(bytes({ 0x30, 0x03 }), 4) == too_large);
	CHECK(frame(bind_request, 14) == "size 14");
	CHECK(frame(bind_request, 13) == too_large);
}

TEST_CASE("complete_message_size rejects malformed headers", "[ber][framer]")
{
	CHECK(frame(bytes({ 0x30, 0x80 })) == decode_error);// indefinite length
	CHECK(frame(bytes({ 0x30, 0x85 })) == decode_error);// 5 length octets
	CHECK(frame(bytes({ 0x30, 0xFF })) == decode_error);// reserved
	CHECK(frame(bytes({ 0x3F })) == unsupported_tag);// high-tag-number form
}
