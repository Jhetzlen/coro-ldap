// libFuzzer target for RFC 4515 filters (also driven by filter_fuzz_replay).
//
// For any input it must not crash, and:
// - as filter text: if it parses, the BER decodes back to text, that text
//   parses to identical BER and decodes to the same text again; if it does
//   not parse, the error is invalid_filter and nothing was written;
// - as a value: every builder accepts it, the result always parses, and
//   `attr("cn") == v` decodes to an equality whose value is exactly v;
// - as BER: if a filter decodes, its text re-encodes to BER that decodes to
//   the same text;
// - as a raw operand of &&, || and !: the combination only parses if the raw
//   text parses on its own (malformed text cannot become valid by combining),
//   and then the operand keeps its meaning (its BER appears in the result).
#include "jhetz/ldap/filter.hpp"

#define FUZZ_TARGET "filter_fuzz"
#include "check.hpp"

#include <algorithm>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>

namespace {

namespace ber = jhetz::ldap::ber;
namespace ldap = jhetz::ldap;

bool same(const std::vector<std::byte> &a, const std::vector<std::byte> &b) { return a == b; }

// Parses `text`, requires success, returns the BER.
std::vector<std::byte> must_encode(std::string_view text)
{
	ber::writer w;
	auto r = ldap::encode_filter(w, text);
	LDAP_FUZZ_CHECK(r.has_value());
	return w.take();
}

std::string must_decode(const std::vector<std::byte> &bytes)
{
	ber::reader r(bytes);
	auto t = ldap::decode_filter(r);
	LDAP_FUZZ_CHECK(t.has_value());
	LDAP_FUZZ_CHECK(r.empty());
	return *t;
}

void check_text(std::string_view text)
{
	ber::writer w;
	auto r = ldap::encode_filter(w, text);
	if (!r) {
		LDAP_FUZZ_CHECK(r.error().code == ldap::client_errc::invalid_filter);
		LDAP_FUZZ_CHECK(w.bytes().empty());
		return;
	}
	const auto first = w.take();
	const auto canonical = must_decode(first);
	const auto second = must_encode(canonical);
	LDAP_FUZZ_CHECK(same(first, second));
	LDAP_FUZZ_CHECK(must_decode(second) == canonical);
}

void check_value(std::string_view v)
{
	using namespace ldap::filters;
	const auto eq = attr("cn") == v;
	const auto bytes = must_encode(eq.text);
	{
		ber::reader r(bytes);
		auto ava = r.enter(ber::context(3));
		LDAP_FUZZ_CHECK(ava.has_value());
		LDAP_FUZZ_CHECK(ava->read_string() == "cn");
		LDAP_FUZZ_CHECK(ava->read_string() == v);
		LDAP_FUZZ_CHECK(ava->empty() && r.empty());
	}
	LDAP_FUZZ_CHECK(must_decode(bytes) == eq.text);

	const ldap::filter all[] = { attr("cn") >= v,
		attr("cn;x-1") <= v,
		attr("2.5.4.3").approx(v),
		attr("cn").starts_with(v),
		attr("cn").ends_with(v),
		attr("cn").contains(v),
		!(eq && attr("sn").present()) || eq };
	for (const auto &f : all) {
		const auto b = must_encode(f.text);
		LDAP_FUZZ_CHECK(same(must_encode(must_decode(b)), b));
	}
}

void check_ber(std::span<const std::byte> input)
{
	ber::reader r(input);
	auto t = ldap::decode_filter(r);
	if (!t) {
		LDAP_FUZZ_CHECK(r.offset() == 0);
		return;
	}
	const auto b = must_encode(*t);
	LDAP_FUZZ_CHECK(must_decode(b) == *t);
}

bool parses(std::string_view text)
{
	ber::writer w;
	return ldap::encode_filter(w, text).has_value();
}

void check_combinators(std::string_view text)
{
	using namespace ldap::filters;
	const auto raw = ldap::filter::raw(std::string(text));
	const auto other = attr("zz") == "1";
	const bool alone = parses(text);
	for (const auto &f : { raw && other, other || raw, !raw }) {
		if (!parses(f.text)) continue;
		LDAP_FUZZ_CHECK(alone);
	}
	// (!raw) is NOT around exactly the operand's BER. It may exceed the depth
	// or element limit by one when the operand is at the limit.
	if (!alone || !parses((!raw).text)) return;
	const auto operand = must_encode(text);
	const auto negated = must_encode((!raw).text);
	ber::reader r(negated);
	auto inner = r.enter(ber::context(2));
	LDAP_FUZZ_CHECK(inner.has_value());
	LDAP_FUZZ_CHECK(inner->remaining() == operand.size());
	LDAP_FUZZ_CHECK(
	  std::equal(operand.begin(), operand.end(), negated.end() - static_cast<std::ptrdiff_t>(operand.size())));
}

}// namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *data, std::size_t size)
{
	const std::string_view text(reinterpret_cast<const char *>(data), size);
	check_text(text);
	check_value(text);
	check_ber(std::as_bytes(std::span(data, size)));
	check_combinators(text);
	return 0;
}
