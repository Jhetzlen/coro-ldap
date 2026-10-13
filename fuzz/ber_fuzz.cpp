// libFuzzer target for the BER codec (also driven by ber_fuzz_replay).
//
// For any input it must not crash, and these properties must hold:
// - framer and reader agree on the size of the first element;
// - every element can be walked (constructed elements via `enter`, which is
//   depth bounded), and the reader never consumes more than it has;
// - OCTET STRING contents are also walked as encapsulated BER;
// - decoded INTEGER / ENUMERATED / BOOLEAN / OCTET STRING / NULL values
//   re-encode to something that decodes to the same value, and to the same
//   content octets when the input was already minimal.
#include "jhetz/ldap/ber.hpp"

#include "check.hpp"

#include <cstdint>
#include <span>
#include <vector>

constexpr jhetz::ldap::fuzz::checker check{ "ber_fuzz" };

namespace {

namespace ber = jhetz::ldap::ber;
using jhetz::ldap::client_errc;

bool same_bytes(std::span<const std::byte> a, std::span<const std::byte> b)
{
	if (a.size() != b.size()) return false;
	for (std::size_t i = 0; i < a.size(); ++i)
		if (a[i] != b[i]) return false;
	return true;
}

// Content octets of the single element in `encoded`.
std::span<const std::byte> content_of(std::span<const std::byte> encoded)
{
	ber::reader r(encoded);
	auto e = r.read();
	check(e.has_value(), "e.has_value()");
	check(r.empty(), "r.empty()");
	return e->content;
}

bool minimal_integer(std::span<const std::byte> c)
{
	if (c.size() < 2) return true;
	const auto b0 = std::to_integer<unsigned>(c[0]);
	const bool high1 = (std::to_integer<unsigned>(c[1]) & 0x80u) != 0;
	return !((b0 == 0x00u && !high1) || (b0 == 0xFFu && high1));
}

void walk(ber::reader r);

// Every typed read is attempted with the element's own tag on a copy of the
// reader; successes must round-trip through the writer.
void check_typed_reads(const ber::reader &r, ber::tag t, std::span<const std::byte> content)
{
	const ber::tag prim{ t.cls, false, t.number };
	{
		auto copy = r;
		if (auto v = copy.read_integer(t)) {
			check(!t.constructed, "!t.constructed");
			ber::writer w;
			w.integer(*v, prim);
			ber::reader back(w.bytes());
			auto again = back.read_integer(prim);
			check(again && *again == *v, "again && *again == *v");
			const auto re = content_of(w.bytes());
			if (minimal_integer(content))
				check(same_bytes(re, content), "same_bytes(re, content)");
			else
				check(re.size() < content.size(), "re.size() < content.size()");
		} else {
			check(copy.offset() == r.offset(), "copy.offset() == r.offset()");
			if (!t.constructed && !content.empty() && content.size() <= 8)
				check.failed("integer rejected", std::source_location::current());
		}
	}
	{
		auto copy = r;
		if (auto v = copy.read_enumerated(t)) {
			auto copy2 = r;
			auto i = copy2.read_integer(t);
			check(i && *i == *v, "i && *i == *v");
		}
	}
	{
		auto copy = r;
		if (auto v = copy.read_boolean(t)) {
			check(content.size() == 1, "content.size() == 1");
			ber::writer w;
			w.boolean(*v, prim);
			ber::reader back(w.bytes());
			auto again = back.read_boolean(prim);
			check(again && *again == *v, "again && *again == *v");
			const auto b = std::to_integer<unsigned>(content[0]);
			if (b == 0x00u || b == 0xFFu)
				check(same_bytes(content_of(w.bytes()), content), "same_bytes(content_of(w.bytes()), content)");
		} else {
			check(copy.offset() == r.offset(), "copy.offset() == r.offset()");
		}
	}
	{
		auto copy = r;
		if (auto v = copy.read_octet_string(t)) {
			check(same_bytes(*v, content), "same_bytes(*v, content)");
			ber::writer w;
			w.octet_string(*v, prim);
			ber::reader back(w.bytes());
			auto again = back.read_octet_string(prim);
			check(again && same_bytes(*again, *v), "again && same_bytes(*again, *v)");
			auto copy2 = r;
			auto s = copy2.read_string(t);
			check(s && s->size() == v->size(), "s && s->size() == v->size()");

			// Treat the content as encapsulated BER (control values etc.).
			// Recursion stays bounded: the sub-reader is one level deeper.
			auto copy3 = r;
			if (auto sub = copy3.enter_encapsulated(t)) {
				check(sub->depth() == r.depth() + 1, "sub->depth() == r.depth() + 1");
				check(sub->offset() == r.offset() + (r.remaining() - copy3.remaining()) - content.size(),
				  "sub->offset() == r.offset() + (r.remaining() - copy3.remaining()) - content.size()");
				check(sub->remaining() == content.size(), "sub->remaining() == content.size()");
				walk(*sub);
			} else {
				check(sub.error().code == client_errc::nesting_too_deep,
				  "sub.error().code == client_errc::nesting_too_deep");
				check(r.depth() >= r.max_depth(), "r.depth() >= r.max_depth()");
			}
		}
	}
	{
		auto copy = r;
		if (copy.read_null(t)) {
			check(content.empty(), "content.empty()");
			ber::writer w;
			w.null(prim);
			ber::reader back(w.bytes());
			check(back.read_null(prim).has_value(), "back.read_null(prim).has_value()");
		}
	}
}

// Recursion depth is bounded by the reader's max depth: `enter` refuses to
// go deeper, and only a successful `enter` recurses.
void walk(ber::reader r)
{
	while (!r.empty()) {
		const std::size_t before = r.remaining();
		auto t = r.peek_tag();
		if (!t) {
			check(t.error().code == client_errc::unsupported_tag, "t.error().code == client_errc::unsupported_tag");
			check(!r.read().has_value(), "!r.read().has_value()");
			return;
		}

		auto probe = r;
		auto e = probe.read();
		if (!e) {
			check(r.remaining() == before, "r.remaining() == before");
			return;
		}
		check(e->t == *t, "e->t == *t");
		check(e->size() <= before, "e->size() <= before");
		check(probe.remaining() == before - e->size(), "probe.remaining() == before - e->size()");

		if (t->constructed) {
			auto copy = r;
			auto sub = copy.enter(*t);
			if (sub) {
				check(sub->depth() == r.depth() + 1, "sub->depth() == r.depth() + 1");
				check(sub->remaining() == e->content.size(), "sub->remaining() == e->content.size()");
				check(copy.remaining() == probe.remaining(), "copy.remaining() == probe.remaining()");
				walk(*sub);
			} else {
				check(sub.error().code == client_errc::nesting_too_deep,
				  "sub.error().code == client_errc::nesting_too_deep");
				check(r.depth() >= r.max_depth(), "r.depth() >= r.max_depth()");
			}
		} else {
			check_typed_reads(r, *t, e->content);
		}
		r = probe;
	}
	check(r.expect_end().has_value(), "r.expect_end().has_value()");
}

}// namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *data, std::size_t size)
{
	const auto input = std::as_bytes(std::span(data, size));

	// Framer vs reader on the first element.
	constexpr std::size_t max_size = 1024;
	auto framed = ber::complete_message_size(input, max_size);
	ber::reader first(input);
	auto e = first.read();
	if (framed && *framed) {
		check(**framed <= input.size(), "**framed <= input.size()");
		check(**framed <= max_size, "**framed <= max_size");
		check(e && e->size() == **framed, "e && e->size() == **framed");
	} else if (framed) {
		check(!e.has_value(), "!e.has_value()");// needs more bytes: reader must fail too
	} else if (e) {
		// Framer refused a readable element: only because it is too large.
		check(framed.error().code == client_errc::message_too_large,
		  "framed.error().code == client_errc::message_too_large");
		check(e->size() > max_size, "e->size() > max_size");
	}

	// declared_message_size knows the size from the header alone: it fails
	// exactly when the framer fails, and agrees with it once complete.
	auto declared = ber::declared_message_size(input, max_size);
	check(declared.has_value() == framed.has_value(), "declared.has_value() == framed.has_value()");
	if (!declared) {
		check(declared.error() == framed.error(), "declared.error() == framed.error()");
	} else if (*framed) {
		check(*declared == *framed, "*declared == *framed");
	} else if (*declared) {
		check(**declared > input.size(), "**declared > input.size()");// header complete, content missing
		check(**declared <= max_size, "**declared <= max_size");
	}

	// Walk everything, with the default and with a tiny depth limit.
	walk(ber::reader(input));
	walk(ber::reader(input, 2));
	return 0;
}
