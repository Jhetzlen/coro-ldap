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
//   escaping is right), and is "(cn=" + escape_filter_value(v) + ")";
//   unescape_filter_value reverses escape_filter_value; builder trees
//   round-trip through BER;
// - as an escaped value without '*': unescape_filter_value accepts it
//   exactly when filter::raw accepts "(cn=" + it + ")", with the same value;
// - as BER: if a filter decodes, it re-encodes to BER that decodes to an
//   equal tree, and its text parses to an equal tree;
// - a parsed filter keeps its meaning when combined: (!f) holds exactly f's
//   BER and prints as "(!" + text + ")".
#include "jhetz/ldap/filter.hpp"

#include "check.hpp"

#include <algorithm>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>

constexpr jhetz::ldap::fuzz::checker check{ "filter_fuzz" };

namespace {

namespace ber = jhetz::ldap::ber;
namespace ldap = jhetz::ldap;

std::pmr::vector<std::byte> must_encode(const ldap::filter &f)
{
	ber::writer w;
	auto r = ldap::encode_filter(w, f);
	check(r.has_value(), "r.has_value()");
	return w.take();
}

ldap::filter must_decode(std::span<const std::byte> bytes)
{
	ber::reader r(bytes);
	auto f = ldap::decode_filter(r);
	check(f.has_value(), "f.has_value()");
	check(r.empty(), "r.empty()");
	return std::move(*f);
}

ldap::filter must_parse(std::string_view text)
{
	auto f = ldap::filter::raw(text);
	check(f.has_value(), "f.has_value()");
	return std::move(*f);
}

// Tree -> BER -> tree -> BER, and tree -> text -> tree.
void check_round_trips(const ldap::filter &f)
{
	const auto bytes = must_encode(f);
	const auto back = must_decode(bytes);
	check(back == f, "back == f");
	check(must_encode(back) == bytes, "must_encode(back) == bytes");
	const auto text = f.to_string();
	const auto reparsed = must_parse(text);
	check(reparsed == f, "reparsed == f");
	check(reparsed.to_string() == text, "reparsed.to_string() == text");
	check(reparsed.depth() == f.depth() && reparsed.elements() == f.elements(),
	  "reparsed.depth() == f.depth() && reparsed.elements() == f.elements()");
}

void check_text(std::string_view text)
{
	auto f = ldap::filter::raw(text);
	if (!f) {
		check(
		  f.error().code == ldap::client_errc::invalid_filter, "f.error().code == ldap::client_errc::invalid_filter");
		return;
	}
	check_round_trips(*f);

	// Combining keeps a parsed operand's meaning (when (!f) is still within
	// the limits: f may be at the depth or element limit already).
	const auto neg = !*f;
	if (neg.depth() > ldap::max_filter_depth || neg.elements() > ldap::max_filter_elements) return;
	check(std::string(neg.to_string()) == "(!" + std::string(f->to_string()) + ")",
	  "std::string(neg.to_string()) == \"(!\" + std::string(f->to_string()) + \")\"");
	const auto operand = must_encode(*f);
	const auto negated = must_encode(neg);
	ber::reader r(negated);
	auto inner = r.enter(ber::context(2));
	check(inner.has_value(), "inner.has_value()");
	check(inner->remaining() == operand.size(), "inner->remaining() == operand.size()");
	check(std::ranges::ends_with(negated, operand), "std::ranges::ends_with(negated, operand)");
}

void check_value(std::string_view v)
{
	using namespace ldap::filters;
	const auto eq = attr("cn") == v;
	check(eq.root().value() == v, "eq.root().value() == v");
	const auto bytes = must_encode(eq);
	{
		ber::reader r(bytes);
		auto ava = r.enter(ber::context(3));
		check(ava.has_value(), "ava.has_value()");
		check(ava->read_string() == "cn", "ava->read_string() == \"cn\"");
		check(ava->read_string() == v, "ava->read_string() == v");
		check(ava->empty() && r.empty(), "ava->empty() && r.empty()");
	}
	check_round_trips(eq);
	const auto escaped = std::string(ldap::escape_filter_value(v));
	check(std::string(eq.to_string()) == "(cn=" + escaped + ")", "eq.to_string() == \"(cn=\" + escaped + \")\"");
	const auto unescaped = ldap::unescape_filter_value(escaped);
	check(unescaped.has_value() && *unescaped == v, "unescaped.has_value() && *unescaped == v");

	const ldap::filter all[] = { attr("cn") >= v,
		attr("cn;x-1") <= v,
		attr("2.5.4.3").approx(v),
		attr("cn").starts_with(v),
		attr("cn").ends_with(v),
		attr("cn").contains(v),
		!(eq && attr("sn").present()) || eq };
	for (const auto &f : all) check_round_trips(f);
	if (!v.empty()) {
		check(all[3].root().initial() == v, "all[3].root().initial() == v");
		check(all[4].root().final() == v, "all[4].root().final() == v");
		check(*all[5].root().any().begin() == v, "*all[5].root().any().begin() == v");
	}
}

void check_unescape(std::string_view text)
{
	if (text.find('*') != std::string_view::npos) return;// a substring filter in raw
	const auto u = ldap::unescape_filter_value(text);
	const auto f = ldap::filter::raw("(cn=" + std::string(text) + ")");
	check(u.has_value() == f.has_value(), "u.has_value() == f.has_value()");
	if (!u) {
		check(
		  u.error().code == ldap::client_errc::invalid_filter, "u.error().code == ldap::client_errc::invalid_filter");
		return;
	}
	check(f->root().value() == *u, "f->root().value() == *u");
}

void check_ber(std::span<const std::byte> input)
{
	ber::reader r(input);
	auto f = ldap::decode_filter(r);
	if (!f) {
		check(r.offset() == 0, "r.offset() == 0");
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
	check_unescape(text);
	check_ber(std::as_bytes(std::span(data, size)));
	return 0;
}
