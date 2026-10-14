// Restricted BER codec used by LDAP (RFC 4511 section 5.1).
//
// Only what LDAP needs: definite lengths, low tag numbers (0..30), and the
// universal types BOOLEAN, INTEGER, OCTET STRING, NULL, ENUMERATED, SEQUENCE
// and SET. The decoder is written for untrusted input: it never reads out of
// bounds, never recurses (callers recurse through `enter`, which is depth
// bounded), and never allocates based on a length it has not checked against
// the bytes actually present.
//
// `reader` and `element` are non-owning views into a caller-owned buffer and
// are internal building blocks (DESIGN.md section 8): nothing built on them
// may hand such a view to the user.
#pragma once

#include "jhetz/ldap/error.hpp"

#include <cstddef>
#include <cstdint>
#include <memory_resource>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace jhetz::ldap::detail {

// The bytes as text, without copying (char may alias any object). For BER
// payloads that hold strings: LDAPString, OCTET STRING values, encoded
// control values.
[[nodiscard]] inline std::string_view as_text(std::span<const std::byte> b) noexcept
{
	return { reinterpret_cast<const char *>(b.data()), b.size() };
}

}// namespace jhetz::ldap::detail

namespace jhetz::ldap::ber {

enum class tag_class : std::uint8_t { universal = 0, application = 1, context = 2, private_ = 3 };

// Highest tag number the low-tag-number form can carry. 31 means "high tag
// number form follows", which LDAP never needs and this codec rejects.
inline constexpr std::uint8_t max_tag_number = 30;

struct tag
{
	tag_class cls = tag_class::universal;
	bool constructed = false;
	std::uint8_t number = 0;

	friend constexpr bool operator==(tag, tag) = default;
};

// Builds a tag, checking the number. Throws std::invalid_argument for numbers
// above 30 (a programming error; in a constant expression it fails to compile).
[[nodiscard]] constexpr tag make_tag(tag_class cls, std::uint8_t number, bool constructed = false)
{
	if (number > max_tag_number) {
		throw std::invalid_argument("ber: tag number above 30 needs the high-tag-number form");
	}
	return tag{ cls, constructed, number };
}

[[nodiscard]] constexpr tag universal(std::uint8_t number, bool constructed = false)
{
	return make_tag(tag_class::universal, number, constructed);
}
[[nodiscard]] constexpr tag application(std::uint8_t number, bool constructed = false)
{
	return make_tag(tag_class::application, number, constructed);
}
[[nodiscard]] constexpr tag context(std::uint8_t number, bool constructed = false)
{
	return make_tag(tag_class::context, number, constructed);
}
[[nodiscard]] constexpr tag private_tag(std::uint8_t number, bool constructed = false)
{
	return make_tag(tag_class::private_, number, constructed);
}

namespace tags {
	inline constexpr tag boolean = universal(1);
	inline constexpr tag integer = universal(2);
	inline constexpr tag octet_string = universal(4);
	inline constexpr tag null = universal(5);
	inline constexpr tag enumerated = universal(10);
	inline constexpr tag sequence = universal(16, true);
	inline constexpr tag set = universal(17, true);
}// namespace tags

// The single identifier octet for `t`. Throws std::invalid_argument for tag
// numbers above 30 (a compile error in constant expressions), which would
// otherwise be silently turned into the high-tag-number marker 0x1F.
[[nodiscard]] constexpr std::byte identifier_octet(tag t)
{
	if (t.number > max_tag_number) {
		throw std::invalid_argument("ber: tag number above 30 needs the high-tag-number form");
	}
	return static_cast<std::byte>(
	  (unsigned{ std::to_underlying(t.cls) } << 6) | (t.constructed ? 0x20u : 0x00u) | (t.number & 0x1Fu));
}

// Human readable form, e.g. "[UNIVERSAL 16 constructed]", for error context.
[[nodiscard]] std::string to_string(tag t);

// ---------------------------------------------------------------- encoder

// Appends BER elements to an internal buffer.
//
// The primitive/constructed bit of the emitted identifier is decided by the
// method, not by the `constructed` flag of the tag passed in: `constructed()`
// always sets it, every other method always clears it. This lets callers write
// `w.constructed(ber::context(0), ...)` without repeating the flag.
//
// Tags with a number above 30 cannot be encoded and throw
// std::invalid_argument (only reachable by aggregate-initialising a `tag`).
//
// Memory: the buffer is a std::pmr::vector on the resource given to the
// constructor (default: the default resource), so it can live in an arena or
// be reused: clear() keeps its capacity. Like any pmr container, a copy uses
// the default resource and assignment keeps the target's resource.
class writer
{
  public:
	using allocator_type = std::pmr::polymorphic_allocator<>;

	writer() = default;
	explicit writer(const allocator_type &alloc) : buf_(alloc) {}
	writer(const writer &) = default;
	writer(writer &&) noexcept = default;
	writer(const writer &other, const allocator_type &alloc) : buf_(other.buf_, alloc) {}
	writer(writer &&other, const allocator_type &alloc) : buf_(std::move(other.buf_), alloc) {}
	// Assigning replaces the buffer, so it counts as a reset (see constructed()).
	writer &operator=(const writer &other)
	{
		buf_ = other.buf_;
		++resets_;
		return *this;
	}
	writer &operator=(writer &&other)
	{
		buf_ = std::move(other.buf_);
		other.buf_.clear();
		++other.resets_;
		++resets_;
		return *this;
	}
	~writer() = default;

	allocator_type get_allocator() const noexcept { return buf_.get_allocator(); }

	void boolean(bool value, tag t = tags::boolean);
	void integer(std::int64_t value, tag t = tags::integer);
	void enumerated(std::int64_t value, tag t = tags::enumerated);
	void octet_string(std::span<const std::byte> value, tag t = tags::octet_string);
	void octet_string(std::string_view value, tag t = tags::octet_string);
	void null(tag t = tags::null);
	void primitive(tag t, std::span<const std::byte> content);

	// Writes the identifier, runs `body(*this)` to append the contents, then
	// fills in the minimal definite length. If `body` or the length fix-up
	// throws, the partial element is removed. `body` must only append: calling
	// clear() or take() on this writer inside it throws std::logic_error.
	template<class F> void constructed(tag t, F &&body)
	{
		const std::size_t resets = resets_;
		const std::size_t mark = begin_constructed(t);
		try {
			std::forward<F>(body)(*this);
			end_constructed(mark, resets);
		} catch (...) {
			rollback(mark, resets);// throws std::logic_error if the buffer was reset
			throw;
		}
	}

	// Capacity for at least `n` bytes in all (like std::vector::reserve).
	void reserve(std::size_t n) { buf_.reserve(n); }

	const std::pmr::vector<std::byte> &bytes() const noexcept { return buf_; }
	// Moves the encoded bytes out (on the writer's resource) and leaves the
	// writer empty, still on the same resource.
	[[nodiscard]] std::pmr::vector<std::byte> take() noexcept
	{
		++resets_;
		std::pmr::vector<std::byte> out(std::move(buf_));
		buf_.clear();// valid but unspecified after the move: make it empty
		return out;
	}
	void clear() noexcept
	{
		++resets_;
		buf_.clear();
	}

  private:
	void put_identifier(tag t, bool constructed);
	void put_length(std::size_t length);
	std::size_t begin_constructed(tag t);
	void end_constructed(std::size_t mark, std::size_t resets);
	void rollback(std::size_t mark, std::size_t resets);
	void check_mark(std::size_t mark, std::size_t resets) const;

	std::pmr::vector<std::byte> buf_{};
	std::size_t resets_ = 0;// bumped by clear()/take(), to detect misuse inside constructed()
};

// Appends the minimal definite length encoding of `length` to `out`.
void encode_length(std::pmr::vector<std::byte> &out, std::size_t length);

// ---------------------------------------------------------------- decoder

struct element
{
	tag t{};
	std::span<const std::byte> content{};// view into the reader's buffer
	std::size_t offset = 0;// absolute offset of the identifier octet
	std::size_t header_size = 0;// identifier + length octets

	std::size_t size() const noexcept { return header_size + content.size(); }
};

// Sequential decoder over a caller-owned buffer.
//
// Decoding choices (leniency toward servers, strictness where it matters for
// safety):
// - Lengths: definite form only. Indefinite length (0x80) is rejected; long
//   form with more than 4 length octets is rejected; non-minimal length
//   encodings (e.g. 81 05) are accepted.
// - BOOLEAN: content must be exactly 1 octet; any non-zero value is true
//   (BER), not only 0xFF (DER).
// - INTEGER / ENUMERATED: empty content is rejected; more than 8 content
//   octets fail with integer_overflow, even if a redundant leading 00/FF
//   would make the value fit; non-minimal encodings of up to 8 octets
//   (e.g. 00 7F) are accepted.
// - NULL: content must be empty.
// - Typed reads compare class and number with the expected tag and require
//   the primitive form (constructed form for `enter`), regardless of the
//   expected tag's `constructed` flag.
//
// Every operation either succeeds and advances, or fails and leaves the reader
// unchanged. Error contexts include the absolute byte offset of the problem.
//
// A reader (and every span or sub-reader it returns) only borrows the buffer:
// it must not outlive it. `reader r(make_vector());` dangles immediately.
// To decode BER nested in a value, use `enter_encapsulated` rather than a
// fresh reader over element::content, so depth and offsets carry over.
class reader
{
  public:
	static constexpr std::size_t default_max_depth = 32;

	explicit reader(std::span<const std::byte> data, std::size_t max_depth = default_max_depth) noexcept
	  : data_(data), max_depth_(max_depth)
	{}

	[[nodiscard]] bool empty() const noexcept { return pos_ == data_.size(); }
	std::size_t remaining() const noexcept { return data_.size() - pos_; }
	// Absolute offset of the next byte, counted from the start of the
	// outermost reader's buffer.
	std::size_t offset() const noexcept { return base_ + pos_; }
	// Number of `enter` calls between the outermost reader and this one.
	std::size_t depth() const noexcept { return depth_; }
	std::size_t max_depth() const noexcept { return max_depth_; }

	[[nodiscard]] result<tag> peek_tag() const;
	// Reads the next element of any tag.
	[[nodiscard]] result<element> read();
	// Reads the next element; fails with unexpected_tag unless its class and
	// number match `expected`. Like the typed reads, the constructed bit of
	// `expected` is ignored; the returned element carries the real one.
	[[nodiscard]] result<element> read(tag expected);

	[[nodiscard]] result<bool> read_boolean(tag t = tags::boolean);
	[[nodiscard]] result<std::int64_t> read_integer(tag t = tags::integer);
	[[nodiscard]] result<std::int64_t> read_enumerated(tag t = tags::enumerated);
	[[nodiscard]] result<std::span<const std::byte>> read_octet_string(tag t = tags::octet_string);
	// Same as read_octet_string, copied into a string allocated from `mr`
	// (the only allocation any reader operation makes, apart from errors).
	[[nodiscard]] result<std::pmr::string> read_string(tag t = tags::octet_string,
	  std::pmr::memory_resource *mr = std::pmr::get_default_resource());
	[[nodiscard]] result<void> read_null(tag t = tags::null);

	// Reads a constructed element with class/number of `t` and returns a
	// reader over its contents, one level deeper. Fails with
	// nesting_too_deep when that would exceed max_depth().
	[[nodiscard]] result<reader> enter(tag t = tags::sequence);

	// Reads a primitive element with class/number of `t` (by default an
	// OCTET STRING) whose content is itself BER, e.g. a control value or
	// the paged-results cookie, and returns a reader over that content one
	// level deeper, with the same depth limit as `enter` and absolute offsets.
	[[nodiscard]] result<reader> enter_encapsulated(tag t = tags::octet_string);

	// Fails with decode_error if any bytes are left (trailing garbage).
	[[nodiscard]] result<void> expect_end() const;

  private:
	struct header
	{
		tag t;
		std::size_t header_size;
		std::size_t content_size;
	};

	reader(std::span<const std::byte> data, std::size_t base, std::size_t depth, std::size_t max_depth) noexcept
	  : data_(data), base_(base), depth_(depth), max_depth_(max_depth)
	{}

	bool fast_header(header &out) const noexcept;
	result<header> parse_header() const;
	result<element> read_primitive(tag expected, const char *what);
	result<reader> enter_impl(tag t, bool constructed, const char *what);
	result<std::int64_t> read_int(tag expected, const char *what);

	std::span<const std::byte> data_;
	std::size_t pos_ = 0;
	std::size_t base_ = 0;
	std::size_t depth_ = 0;
	std::size_t max_depth_ = default_max_depth;
};

// ---------------------------------------------------------------- framer

inline constexpr std::size_t default_max_message_size = std::size_t{ 16 } * 1024 * 1024;

// Size of the first complete element at the start of `buf`.
// - nullopt: more bytes are needed (header or content incomplete);
// - value:   total size (header + content) of the first element; bytes after
//            it are ignored;
// - error:   malformed header (unsupported_tag, decode_error), or a declared
//            total size above `max_size` (message_too_large). Both are decided
//            from the header alone, before any content has arrived.
// Only the header is inspected; the content is not validated.
[[nodiscard]] result<std::optional<std::size_t>> complete_message_size(std::span<const std::byte> buf,
  std::size_t max_size = default_max_message_size);

// Total size (header + content) that the first element at the start of `buf`
// declares, known as soon as its header is complete, whether or not the
// content has arrived: nullopt while the header is incomplete; the same
// errors as complete_message_size. Lets a reader size its buffer for the
// whole element after reading only the header.
[[nodiscard]] result<std::optional<std::size_t>> declared_message_size(std::span<const std::byte> buf,
  std::size_t max_size = default_max_message_size);

}// namespace jhetz::ldap::ber
