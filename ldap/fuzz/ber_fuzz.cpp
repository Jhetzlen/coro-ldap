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

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <span>
#include <vector>

namespace {

namespace ber = jhetz::ldap::ber;
using jhetz::ldap::client_errc;

[[noreturn]] void property_failed(const char *what, int line)
{
	std::fprintf(stderr, "ber_fuzz: property violated: %s (line %d)\n", what, line);
	std::abort();
}

#define FUZZ_CHECK(cond)                               \
	do {                                               \
		if (!(cond)) property_failed(#cond, __LINE__); \
	} while (false)

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
	FUZZ_CHECK(e.has_value());
	FUZZ_CHECK(r.empty());
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
			FUZZ_CHECK(!t.constructed);
			ber::writer w;
			w.integer(*v, prim);
			ber::reader back(w.bytes());
			auto again = back.read_integer(prim);
			FUZZ_CHECK(again && *again == *v);
			const auto re = content_of(w.bytes());
			if (minimal_integer(content))
				FUZZ_CHECK(same_bytes(re, content));
			else
				FUZZ_CHECK(re.size() < content.size());
		} else {
			FUZZ_CHECK(copy.offset() == r.offset());
			if (!t.constructed && !content.empty() && content.size() <= 8)
				property_failed("integer rejected", __LINE__);
		}
	}
	{
		auto copy = r;
		if (auto v = copy.read_enumerated(t)) {
			auto copy2 = r;
			auto i = copy2.read_integer(t);
			FUZZ_CHECK(i && *i == *v);
		}
	}
	{
		auto copy = r;
		if (auto v = copy.read_boolean(t)) {
			FUZZ_CHECK(content.size() == 1);
			ber::writer w;
			w.boolean(*v, prim);
			ber::reader back(w.bytes());
			auto again = back.read_boolean(prim);
			FUZZ_CHECK(again && *again == *v);
			const auto b = std::to_integer<unsigned>(content[0]);
			if (b == 0x00u || b == 0xFFu) FUZZ_CHECK(same_bytes(content_of(w.bytes()), content));
		} else {
			FUZZ_CHECK(copy.offset() == r.offset());
		}
	}
	{
		auto copy = r;
		if (auto v = copy.read_octet_string(t)) {
			FUZZ_CHECK(same_bytes(*v, content));
			ber::writer w;
			w.octet_string(*v, prim);
			ber::reader back(w.bytes());
			auto again = back.read_octet_string(prim);
			FUZZ_CHECK(again && same_bytes(*again, *v));
			auto copy2 = r;
			auto s = copy2.read_string(t);
			FUZZ_CHECK(s && s->size() == v->size());

			// Treat the content as encapsulated BER (control values etc.).
			// Recursion stays bounded: the sub-reader is one level deeper.
			auto copy3 = r;
			if (auto sub = copy3.enter_encapsulated(t)) {
				FUZZ_CHECK(sub->depth() == r.depth() + 1);
				FUZZ_CHECK(sub->offset() == r.offset() + (r.remaining() - copy3.remaining()) - content.size());
				FUZZ_CHECK(sub->remaining() == content.size());
				walk(*sub);
			} else {
				FUZZ_CHECK(sub.error().code == client_errc::nesting_too_deep);
				FUZZ_CHECK(r.depth() >= r.max_depth());
			}
		}
	}
	{
		auto copy = r;
		if (copy.read_null(t)) {
			FUZZ_CHECK(content.empty());
			ber::writer w;
			w.null(prim);
			ber::reader back(w.bytes());
			FUZZ_CHECK(back.read_null(prim).has_value());
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
			FUZZ_CHECK(t.error().code == client_errc::unsupported_tag);
			FUZZ_CHECK(!r.read().has_value());
			return;
		}

		auto probe = r;
		auto e = probe.read();
		if (!e) {
			FUZZ_CHECK(r.remaining() == before);
			return;
		}
		FUZZ_CHECK(e->t == *t);
		FUZZ_CHECK(e->size() <= before);
		FUZZ_CHECK(probe.remaining() == before - e->size());

		if (t->constructed) {
			auto copy = r;
			auto sub = copy.enter(*t);
			if (sub) {
				FUZZ_CHECK(sub->depth() == r.depth() + 1);
				FUZZ_CHECK(sub->remaining() == e->content.size());
				FUZZ_CHECK(copy.remaining() == probe.remaining());
				walk(*sub);
			} else {
				FUZZ_CHECK(sub.error().code == client_errc::nesting_too_deep);
				FUZZ_CHECK(r.depth() >= r.max_depth());
			}
		} else {
			check_typed_reads(r, *t, e->content);
		}
		r = probe;
	}
	FUZZ_CHECK(r.expect_end().has_value());
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
		FUZZ_CHECK(**framed <= input.size());
		FUZZ_CHECK(**framed <= max_size);
		FUZZ_CHECK(e && e->size() == **framed);
	} else if (framed) {
		FUZZ_CHECK(!e.has_value());// needs more bytes: reader must fail too
	} else if (e) {
		// Framer refused a readable element: only because it is too large.
		FUZZ_CHECK(framed.error().code == client_errc::message_too_large);
		FUZZ_CHECK(e->size() > max_size);
	}

	// declared_message_size knows the size from the header alone: it fails
	// exactly when the framer fails, and agrees with it once complete.
	auto declared = ber::declared_message_size(input, max_size);
	FUZZ_CHECK(declared.has_value() == framed.has_value());
	if (!declared) {
		FUZZ_CHECK(declared.error() == framed.error());
	} else if (*framed) {
		FUZZ_CHECK(*declared == *framed);
	} else if (*declared) {
		FUZZ_CHECK(**declared > input.size());// header complete, content missing
		FUZZ_CHECK(**declared <= max_size);
	}

	// Walk everything, with the default and with a tiny depth limit.
	walk(ber::reader(input));
	walk(ber::reader(input, 2));
	return 0;
}
