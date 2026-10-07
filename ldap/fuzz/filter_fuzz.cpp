// libFuzzer target for search filters (also driven by filter_fuzz_replay).
//
// For any input it must not crash, and:
// - as filter text: if filter::raw parses it, its BER decodes to an equal
//   tree that encodes to the same BER, and its canonical text (to_string)
//   parses to an equal tree again and is a fixed point; if it does not
//   parse, the error is invalid_filter;
// - as a value: every builder accepts it and its tree holds it unescaped;
//   `attr("cn") == v` encodes to an equality whose value is exactly v; the
//   text of every builder filter parses back to the same tree (so the
//   escaping is right); builder trees round-trip through BER;
// - as BER: if a filter decodes, it re-encodes to BER that decodes to an
//   equal tree, and its text parses to an equal tree;
// - a parsed filter keeps its meaning when combined: (!f) holds exactly f's
//   BER and prints as "(!" + text + ")".
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

std::pmr::vector<std::byte> must_encode(const ldap::filter &f)
{
	ber::writer w;
	auto r = ldap::encode_filter(w, f);
	LDAP_FUZZ_CHECK(r.has_value());
	return w.take();
}

ldap::filter must_decode(std::span<const std::byte> bytes)
{
	ber::reader r(bytes);
	auto f = ldap::decode_filter(r);
	LDAP_FUZZ_CHECK(f.has_value());
	LDAP_FUZZ_CHECK(r.empty());
	return std::move(*f);
}

ldap::filter must_parse(std::string_view text)
{
	auto f = ldap::filter::raw(text);
	LDAP_FUZZ_CHECK(f.has_value());
	return std::move(*f);
}

// Tree -> BER -> tree -> BER, and tree -> text -> tree.
void check_round_trips(const ldap::filter &f)
{
	const auto bytes = must_encode(f);
	const auto back = must_decode(bytes);
	LDAP_FUZZ_CHECK(back == f);
	LDAP_FUZZ_CHECK(must_encode(back) == bytes);
	const auto text = f.to_string();
	const auto reparsed = must_parse(text);
	LDAP_FUZZ_CHECK(reparsed == f);
	LDAP_FUZZ_CHECK(reparsed.to_string() == text);
	LDAP_FUZZ_CHECK(reparsed.depth() == f.depth() && reparsed.elements() == f.elements());
}

void check_text(std::string_view text)
{
	auto f = ldap::filter::raw(text);
	if (!f) {
		LDAP_FUZZ_CHECK(f.error().code == ldap::client_errc::invalid_filter);
		return;
	}
	check_round_trips(*f);

	// Combining keeps a parsed operand's meaning (when (!f) is still within
	// the limits: f may be at the depth or element limit already).
	const auto neg = !*f;
	if (neg.depth() > ldap::max_filter_depth || neg.elements() > ldap::max_filter_elements) return;
	LDAP_FUZZ_CHECK(std::string(neg.to_string()) == "(!" + std::string(f->to_string()) + ")");
	const auto operand = must_encode(*f);
	const auto negated = must_encode(neg);
	ber::reader r(negated);
	auto inner = r.enter(ber::context(2));
	LDAP_FUZZ_CHECK(inner.has_value());
	LDAP_FUZZ_CHECK(inner->remaining() == operand.size());
	LDAP_FUZZ_CHECK(
	  std::equal(operand.begin(), operand.end(), negated.end() - static_cast<std::ptrdiff_t>(operand.size())));
}

void check_value(std::string_view v)
{
	using namespace ldap::filters;
	const auto eq = attr("cn") == v;
	LDAP_FUZZ_CHECK(eq.root().value() == v);
	const auto bytes = must_encode(eq);
	{
		ber::reader r(bytes);
		auto ava = r.enter(ber::context(3));
		LDAP_FUZZ_CHECK(ava.has_value());
		LDAP_FUZZ_CHECK(ava->read_string() == "cn");
		LDAP_FUZZ_CHECK(ava->read_string() == v);
		LDAP_FUZZ_CHECK(ava->empty() && r.empty());
	}
	check_round_trips(eq);

	const ldap::filter all[] = { attr("cn") >= v,
		attr("cn;x-1") <= v,
		attr("2.5.4.3").approx(v),
		attr("cn").starts_with(v),
		attr("cn").ends_with(v),
		attr("cn").contains(v),
		!(eq && attr("sn").present()) || eq };
	for (const auto &f : all) check_round_trips(f);
	if (!v.empty()) {
		LDAP_FUZZ_CHECK(all[3].root().initial() == v);
		LDAP_FUZZ_CHECK(all[4].root().final() == v);
		LDAP_FUZZ_CHECK(*all[5].root().any().begin() == v);
	}
}

void check_ber(std::span<const std::byte> input)
{
	ber::reader r(input);
	auto f = ldap::decode_filter(r);
	if (!f) {
		LDAP_FUZZ_CHECK(r.offset() == 0);
		return;
	}
	check_round_trips(*f);
}

}// namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *data, std::size_t size)
{
	const std::string_view text(reinterpret_cast<const char *>(data), size);
	check_text(text);
	check_value(text);
	check_ber(std::as_bytes(std::span(data, size)));
	return 0;
}
