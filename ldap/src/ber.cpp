#include "jhetz/ldap/ber.hpp"

#include <array>
#include <bit>
#include <iterator>
#include <string>
#include <utility>

namespace jhetz::ldap::ber {
namespace {

	// Longest long-form length accepted by the decoder: 4 octets (lengths up to
	// 4 GiB - 1), far beyond any sane LDAP message and within size_t on every
	// supported platform.
	constexpr std::size_t max_length_octets = 4;

	unsigned octet(std::byte b) noexcept { return std::to_integer<unsigned>(b); }

	// Caller has checked that the number is not 31 (high-tag-number form).
	tag tag_from_identifier(unsigned id) noexcept
	{
		return tag{ static_cast<tag_class>(id >> 6), (id & 0x20u) != 0, static_cast<std::uint8_t>(id & 0x1Fu) };
	}

	std::string at(std::size_t offset) { return " at offset " + std::to_string(offset); }

	struct raw_header
	{
		tag t;
		std::size_t header_size;// identifier + length octets
		std::uint64_t content_size;
	};

	// Parses the identifier and length octets at the start of `buf`.
	// nullopt: `buf` ends inside the header. `base` is the absolute offset of
	// buf[0], used only for error messages. Never reads past buf.size().
	result<std::optional<raw_header>> parse_header_at(std::span<const std::byte> buf, std::size_t base)
	{
		if (buf.empty()) return std::nullopt;

		const unsigned id = octet(buf[0]);
		if ((id & 0x1Fu) == 0x1Fu) return fail(client_errc::unsupported_tag, "ber: high-tag-number form" + at(base));
		const tag t = tag_from_identifier(id);

		if (buf.size() < 2) return std::nullopt;
		const unsigned first = octet(buf[1]);
		if (first < 0x80u) return raw_header{ t, 2, first };
		if (first == 0x80u) return fail(client_errc::decode_error, "ber: indefinite length" + at(base + 1));

		const std::size_t count = first & 0x7Fu;
		if (count > max_length_octets)
			return fail(client_errc::decode_error,
			  "ber: length uses " + std::to_string(count) + " octets (at most " + std::to_string(max_length_octets)
				+ " supported)" + at(base + 1));
		if (buf.size() < 2 + count) return std::nullopt;

		// Non-minimal long forms (leading zero octets, or values < 128) are
		// accepted: harmless, and some encoders produce them.
		std::uint64_t length = 0;
		for (std::size_t i = 0; i < count; ++i) length = (length << 8) | octet(buf[2 + i]);
		return raw_header{ t, 2 + count, length };
	}

	// Long-form definite lengths (length >= 0x80): the initial octet is
	// 0x80 | count, followed by `count` minimal big-endian length octets.
	// Precondition: length >= 0x80 (short-form lengths have no length octets).
	unsigned length_octet_count(std::size_t length) noexcept
	{
		return static_cast<unsigned>(std::bit_width(length) + 7) / 8;
	}

	// Writes the `count` low octets of `length` through `out`, most significant first.
	template<class Out> void put_length_octets(Out out, std::size_t length, unsigned count)
	{
		for (unsigned shift = 8 * count; shift != 0;) {
			shift -= 8;
			*out++ = static_cast<std::byte>((length >> shift) & 0xFFu);
		}
	}

	std::string describe(tag expected, tag actual)
	{
		return "expected " + to_string(expected) + ", got " + to_string(actual);
	}

	// Class and number must match; the form is imposed by the operation.
	bool matches(tag actual, tag expected, bool constructed) noexcept
	{
		return actual.cls == expected.cls && actual.number == expected.number && actual.constructed == constructed;
	}

}// namespace

std::string to_string(tag t)
{
	static constexpr std::array<const char *, 4> names{ "UNIVERSAL", "APPLICATION", "CONTEXT", "PRIVATE" };
	std::string out = "[";
	out += names[std::to_underlying(t.cls) & 3u];
	out += ' ';
	out += std::to_string(t.number);
	if (t.constructed) out += " constructed";
	out += ']';
	return out;
}

// ---------------------------------------------------------------- encoder

void encode_length(std::pmr::vector<std::byte> &out, std::size_t length)
{
	if (length < 0x80) {
		out.push_back(static_cast<std::byte>(length));
		return;
	}
	const unsigned count = length_octet_count(length);
	out.push_back(static_cast<std::byte>(0x80u | count));
	put_length_octets(std::back_inserter(out), length, count);
}

void writer::put_identifier(tag t, bool constructed)
{
	// identifier_octet throws std::invalid_argument for numbers above 30.
	buf_.push_back(identifier_octet(tag{ t.cls, constructed, t.number }));
}

void writer::put_length(std::size_t length) { encode_length(buf_, length); }

void writer::primitive(tag t, std::span<const std::byte> content)
{
	put_identifier(t, false);
	put_length(content.size());
	buf_.insert(buf_.end(), content.begin(), content.end());
}

void writer::boolean(bool value, tag t)
{
	const std::byte content{ static_cast<std::byte>(value ? 0xFF : 0x00) };
	primitive(t, std::span(&content, 1));
}

void writer::integer(std::int64_t value, tag t)
{
	// Big-endian two's complement, then drop redundant leading octets: a 00
	// followed by a byte with the top bit clear, or FF followed by one with
	// the top bit set.
	const auto u = static_cast<std::uint64_t>(value);
	std::array<std::byte, 8> octets{};
	for (std::size_t i = 0; i < 8; ++i) octets[i] = static_cast<std::byte>((u >> (8 * (7 - i))) & 0xFFu);
	std::size_t start = 0;
	while (start < 7) {
		const unsigned b = octet(octets[start]);
		const bool next_high = (octet(octets[start + 1]) & 0x80u) != 0;
		if ((b == 0x00u && !next_high) || (b == 0xFFu && next_high))
			++start;
		else
			break;
	}
	primitive(t, std::span(octets).subspan(start));
}

void writer::enumerated(std::int64_t value, tag t) { integer(value, t); }

void writer::octet_string(std::span<const std::byte> value, tag t) { primitive(t, value); }

void writer::octet_string(std::string_view value, tag t) { primitive(t, std::as_bytes(std::span(value))); }

void writer::null(tag t) { primitive(t, {}); }

std::size_t writer::begin_constructed(tag t)
{
	const std::size_t mark = buf_.size();
	put_identifier(t, true);
	buf_.push_back(std::byte{ 0 });// length placeholder, fixed in end_constructed
	return mark;
}

void writer::check_mark(std::size_t mark, std::size_t resets) const
{
	if (resets != resets_ || buf_.size() < mark + 2)
		throw std::logic_error("ber::writer: clear() or take() called inside constructed()");
}

void writer::end_constructed(std::size_t mark, std::size_t resets)
{
	check_mark(mark, resets);
	const std::size_t content_start = mark + 2;
	const std::size_t length = buf_.size() - content_start;
	if (length < 0x80) {
		buf_[mark + 1] = static_cast<std::byte>(length);
		return;
	}
	// Long form: the extra length octets are inserted in front of the
	// content, which moves it. Nested long-form elements therefore move their
	// content once per level (quadratic in the nesting depth in the worst
	// case); fine for LDAP message sizes and depths.
	const unsigned count = length_octet_count(length);
	// Make room first (may throw; std::vector gives the strong guarantee for
	// trivially copyable elements), then fill it and patch the placeholder,
	// which cannot throw.
	const auto room = buf_.insert(buf_.begin() + static_cast<std::ptrdiff_t>(content_start), count, std::byte{ 0 });
	put_length_octets(room, length, count);
	buf_[mark + 1] = static_cast<std::byte>(0x80u | count);
}

void writer::rollback(std::size_t mark, std::size_t resets)
{
	check_mark(mark, resets);
	buf_.resize(mark);
}

// ---------------------------------------------------------------- decoder

// The common case (low tag number, definite length, content present), without
// building a result; everything else, every error included, goes through
// parse_header_at.
bool reader::fast_header(header &out) const noexcept
{
	const auto rest = data_.subspan(pos_);
	if (rest.size() < 2) return false;
	const unsigned id = octet(rest[0]);
	if ((id & 0x1Fu) == 0x1Fu) return false;
	const unsigned first = octet(rest[1]);
	std::size_t header_size = 2;
	std::size_t length = first;
	if (first >= 0x80u) {
		const std::size_t count = first & 0x7Fu;
		if (count == 0 || count > max_length_octets || rest.size() < 2 + count) return false;
		length = 0;
		for (std::size_t i = 0; i < count; ++i) length = (length << 8) | octet(rest[2 + i]);
		header_size += count;
	}
	if (length > rest.size() - header_size) return false;
	out = header{ tag_from_identifier(id), header_size, length };
	return true;
}

result<reader::header> reader::parse_header() const
{
	if (header h; fast_header(h)) return h;
	const auto rest = data_.subspan(pos_);
	if (rest.empty()) return fail(client_errc::decode_error, "ber: unexpected end of input" + at(offset()));
	auto h = parse_header_at(rest, offset());
	if (!h) return std::unexpected(std::move(h.error()));
	if (!*h) return fail(client_errc::decode_error, "ber: truncated header" + at(offset()));
	const raw_header &raw = **h;
	const std::size_t available = rest.size() - raw.header_size;
	if (raw.content_size > available)
		return fail(client_errc::decode_error,
		  "ber: length " + std::to_string(raw.content_size) + " exceeds the " + std::to_string(available)
			+ " remaining bytes" + at(offset()));
	return header{ raw.t, raw.header_size, static_cast<std::size_t>(raw.content_size) };
}

result<tag> reader::peek_tag() const
{
	// Only the identifier octet is inspected; length problems surface on read.
	if (empty()) return fail(client_errc::decode_error, "ber: unexpected end of input" + at(offset()));
	const unsigned id = octet(data_[pos_]);
	if ((id & 0x1Fu) == 0x1Fu) return fail(client_errc::unsupported_tag, "ber: high-tag-number form" + at(offset()));
	return tag_from_identifier(id);
}

result<element> reader::read()
{
	auto h = parse_header();
	if (!h) return std::unexpected(std::move(h.error()));
	element e{ h->t, data_.subspan(pos_ + h->header_size, h->content_size), offset(), h->header_size };
	pos_ += e.size();
	return e;
}

result<element> reader::read(tag expected)
{
	auto h = parse_header();
	if (!h) return std::unexpected(std::move(h.error()));
	// Class and number only; the element keeps its real constructed bit.
	if (h->t.cls != expected.cls || h->t.number != expected.number)
		return fail(client_errc::unexpected_tag, "ber: " + describe(expected, h->t) + at(offset()));
	return read();
}

result<element> reader::read_primitive(tag expected, const char *what)
{
	auto h = parse_header();
	if (!h) return std::unexpected(std::move(h.error()));
	if (!matches(h->t, expected, false))
		return fail(client_errc::unexpected_tag,
		  std::string("ber: reading ") + what + ": " + describe(tag{ expected.cls, false, expected.number }, h->t)
			+ at(offset()));
	// Not committed yet: the caller validates the content first.
	return element{ h->t, data_.subspan(pos_ + h->header_size, h->content_size), offset(), h->header_size };
}

result<bool> reader::read_boolean(tag t)
{
	auto e = read_primitive(t, "BOOLEAN");
	if (!e) return std::unexpected(std::move(e.error()));
	if (e->content.size() != 1)
		return fail(client_errc::decode_error,
		  "ber: BOOLEAN with " + std::to_string(e->content.size()) + " content octets" + at(e->offset));
	pos_ += e->size();
	return e->content[0] != std::byte{ 0 };
}

result<std::int64_t> reader::read_int(tag t, const char *what)
{
	auto e = read_primitive(t, what);
	if (!e) return std::unexpected(std::move(e.error()));
	const auto c = e->content;
	if (c.empty()) return fail(client_errc::decode_error, std::string("ber: empty ") + what + at(e->offset));
	if (c.size() > 8)
		return fail(client_errc::integer_overflow,
		  std::string("ber: ") + what + " with " + std::to_string(c.size()) + " content octets" + at(e->offset));
	// Sign-extend from the first octet; unsigned arithmetic avoids UB, and the
	// final conversion to int64 is modular (well defined since C++20).
	std::uint64_t v = (octet(c[0]) & 0x80u) != 0 ? ~std::uint64_t{ 0 } : 0;
	for (std::byte b : c) v = (v << 8) | octet(b);
	pos_ += e->size();
	return static_cast<std::int64_t>(v);
}

result<std::int64_t> reader::read_integer(tag t) { return read_int(t, "INTEGER"); }

result<std::int64_t> reader::read_enumerated(tag t) { return read_int(t, "ENUMERATED"); }

result<std::span<const std::byte>> reader::read_octet_string(tag t)
{
	auto e = read_primitive(t, "OCTET STRING");
	if (!e) return std::unexpected(std::move(e.error()));
	pos_ += e->size();
	return e->content;
}

result<std::pmr::string> reader::read_string(tag t, std::pmr::memory_resource *mr)
{
	auto s = read_octet_string(t);
	if (!s) return std::unexpected(std::move(s.error()));
	// The length was checked against the bytes present, so this allocation is
	// bounded by the input size.
	return std::pmr::string(reinterpret_cast<const char *>(s->data()), s->size(), mr);
}

result<void> reader::read_null(tag t)
{
	auto e = read_primitive(t, "NULL");
	if (!e) return std::unexpected(std::move(e.error()));
	if (!e->content.empty())
		return fail(client_errc::decode_error,
		  "ber: NULL with " + std::to_string(e->content.size()) + " content octets" + at(e->offset));
	pos_ += e->size();
	return {};
}

result<reader> reader::enter_impl(tag t, bool constructed, const char *what)
{
	auto h = parse_header();
	if (!h) return std::unexpected(std::move(h.error()));
	if (!matches(h->t, t, constructed))
		return fail(client_errc::unexpected_tag,
		  std::string("ber: entering ") + what + ": " + describe(tag{ t.cls, constructed, t.number }, h->t)
			+ at(offset()));
	if (depth_ >= max_depth_)
		return fail(
		  client_errc::nesting_too_deep, "ber: more than " + std::to_string(max_depth_) + " levels" + at(offset()));
	const std::size_t content_offset = offset() + h->header_size;
	reader sub(data_.subspan(pos_ + h->header_size, h->content_size), content_offset, depth_ + 1, max_depth_);
	pos_ += h->header_size + h->content_size;
	return sub;
}

result<reader> reader::enter(tag t) { return enter_impl(t, true, "constructed element"); }

result<reader> reader::enter_encapsulated(tag t) { return enter_impl(t, false, "encapsulated element"); }

result<void> reader::expect_end() const
{
	if (!empty())
		return fail(client_errc::decode_error,
		  "ber: " + std::to_string(remaining()) + " unexpected trailing bytes" + at(offset()));
	return {};
}

// ---------------------------------------------------------------- framer

result<std::optional<std::size_t>> declared_message_size(std::span<const std::byte> buf, std::size_t max_size)
{
	auto h = parse_header_at(buf, 0);
	if (!h) return std::unexpected(std::move(h.error()));
	if (!*h) return std::optional<std::size_t>{};
	// header_size <= 6 and content_size < 2^32, so the sum cannot overflow.
	const std::uint64_t total = (*h)->header_size + (*h)->content_size;
	if (total > static_cast<std::uint64_t>(max_size))
		return fail(client_errc::message_too_large,
		  "ber: declared message size " + std::to_string(total) + " exceeds the maximum of " + std::to_string(max_size)
			+ " bytes");
	return std::optional<std::size_t>{ static_cast<std::size_t>(total) };
}

result<std::optional<std::size_t>> complete_message_size(std::span<const std::byte> buf, std::size_t max_size)
{
	auto total = declared_message_size(buf, max_size);
	if (!total) return total;
	if (!*total || buf.size() < **total) return std::optional<std::size_t>{};
	return total;
}

}// namespace jhetz::ldap::ber
