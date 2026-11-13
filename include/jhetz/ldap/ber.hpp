// Restricted BER codec used by LDAP (RFC 4511 section 5.1), safe on
// untrusted input (docs/API.md, "jhetz/ldap/ber.hpp").
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

// The bytes as text, without copying.
[[nodiscard]] inline auto as_text(std::span<const std::byte> b) noexcept -> std::string_view
{
	return { reinterpret_cast<const char *>(b.data()), b.size() };
}

}// namespace jhetz::ldap::detail

namespace jhetz::ldap::ber {

enum class tag_class : std::uint8_t { universal = 0, application = 1, context = 2, private_ = 3 };

// Highest low-form tag number; 31 (high form) is rejected.
inline constexpr std::uint8_t max_tag_number = 30;

// The identifier octet's fields (X.690 section 8.1.2).
inline constexpr unsigned identifier_class_shift = 6;
inline constexpr unsigned identifier_constructed_bit = 0x20u;
inline constexpr unsigned identifier_number_mask = 0x1Fu;

struct tag
{
	tag_class cls = tag_class::universal;
	bool constructed = false;
	std::uint8_t number = 0;

	friend constexpr auto operator==(tag, tag) -> bool = default;
};

// Throws std::invalid_argument for numbers above 30.
[[nodiscard]] constexpr auto make_tag(tag_class cls, std::uint8_t number, bool constructed = false) -> tag
{
	if (number > max_tag_number) {
		throw std::invalid_argument("ber: tag number above 30 needs the high-tag-number form");
	}
	return tag{ .cls = cls, .constructed = constructed, .number = number };
}

[[nodiscard]] constexpr auto universal(std::uint8_t number, bool constructed = false) -> tag
{
	return make_tag(tag_class::universal, number, constructed);
}
[[nodiscard]] constexpr auto application(std::uint8_t number, bool constructed = false) -> tag
{
	return make_tag(tag_class::application, number, constructed);
}
[[nodiscard]] constexpr auto context(std::uint8_t number, bool constructed = false) -> tag
{
	return make_tag(tag_class::context, number, constructed);
}
[[nodiscard]] constexpr auto private_tag(std::uint8_t number, bool constructed = false) -> tag
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

// Throws std::invalid_argument for tag numbers above 30.
[[nodiscard]] constexpr auto identifier_octet(tag t) -> std::byte
{
	if (t.number > max_tag_number) {
		throw std::invalid_argument("ber: tag number above 30 needs the high-tag-number form");
	}
	return static_cast<std::byte>((unsigned{ std::to_underlying(t.cls) } << identifier_class_shift)
								  | (t.constructed ? identifier_constructed_bit : 0x00u)
								  | (t.number & identifier_number_mask));
}

// "[UNIVERSAL 16 constructed]", for error contexts.
[[nodiscard]] auto to_string(tag t) -> std::string;

// ---------------------------------------------------------------- encoder

// Appends BER elements to a pmr buffer; the method decides the constructed
// bit.
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
	// Counts as a reset.
	auto operator=(const writer &other) -> writer &
	{
		if (this == &other) {// not a reset
			return *this;
		}
		buf_ = other.buf_;
		++resets_;
		return *this;
	}
	auto operator=(writer &&other) -> writer &
	{
		buf_ = std::move(other.buf_);
		other.buf_.clear();
		++other.resets_;
		++resets_;
		return *this;
	}
	~writer() = default;

	[[nodiscard]] auto get_allocator() const noexcept -> allocator_type { return buf_.get_allocator(); }

	void boolean(bool value, tag t = tags::boolean);
	void integer(std::int64_t value, tag t = tags::integer);
	void enumerated(std::int64_t value, tag t = tags::enumerated);
	void octet_string(std::span<const std::byte> value, tag t = tags::octet_string);
	void octet_string(std::string_view value, tag t = tags::octet_string);
	void null(tag t = tags::null);
	void primitive(tag t, std::span<const std::byte> content);

	// Writes the identifier, appends `body(*this)`, then the minimal length.
	// The partial element is removed if `body` throws.
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

	void reserve(std::size_t n) { buf_.reserve(n); }

	[[nodiscard]] auto bytes() const noexcept -> const std::pmr::vector<std::byte> & { return buf_; }
	// Moves the bytes out and leaves the writer empty, on the same resource.
	[[nodiscard]] auto take() noexcept -> std::pmr::vector<std::byte>
	{
		++resets_;
		std::pmr::vector<std::byte> out(std::move(buf_));
		buf_.clear();// valid but unspecified after the move
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
	auto begin_constructed(tag t) -> std::size_t;
	void end_constructed(std::size_t mark, std::size_t resets);
	void rollback(std::size_t mark, std::size_t resets);
	void check_mark(std::size_t mark, std::size_t resets) const;

	std::pmr::vector<std::byte> buf_{};
	std::size_t resets_ = 0;// bumped by clear()/take()
};

// Appends the minimal definite length encoding of `length` to `out`.
void encode_length(std::pmr::vector<std::byte> &out, std::size_t length);

// ---------------------------------------------------------------- decoder

struct element
{
	tag t{};
	std::span<const std::byte> content{};// view into the reader's buffer
	std::size_t offset = 0;// of the identifier octet
	std::size_t header_size = 0;// identifier + length octets

	[[nodiscard]] auto size() const noexcept -> std::size_t { return header_size + content.size(); }
};

// Sequential decoder over a caller-owned buffer, which it must not outlive.
// Each operation succeeds and advances, or fails and leaves it unchanged.
class reader
{
  public:
	static constexpr std::size_t default_max_depth = 32;

	explicit reader(std::span<const std::byte> data, std::size_t max_depth = default_max_depth) noexcept
	  : data_(data), max_depth_(max_depth)
	{}

	[[nodiscard]] auto empty() const noexcept -> bool { return pos_ == data_.size(); }
	[[nodiscard]] auto remaining() const noexcept -> std::size_t { return data_.size() - pos_; }
	// Absolute offset of the next byte.
	[[nodiscard]] auto offset() const noexcept -> std::size_t { return base_ + pos_; }
	[[nodiscard]] auto depth() const noexcept -> std::size_t { return depth_; }
	[[nodiscard]] auto max_depth() const noexcept -> std::size_t { return max_depth_; }

	[[nodiscard]] auto peek_tag() const -> result<tag>;
	[[nodiscard]] auto read() -> result<element>;
	// unexpected_tag unless class and number match `expected`.
	[[nodiscard]] auto read(tag expected) -> result<element>;

	[[nodiscard]] auto read_boolean(tag t = tags::boolean) -> result<bool>;
	[[nodiscard]] auto read_integer(tag t = tags::integer) -> result<std::int64_t>;
	[[nodiscard]] auto read_enumerated(tag t = tags::enumerated) -> result<std::int64_t>;
	[[nodiscard]] auto read_octet_string(tag t = tags::octet_string) -> result<std::span<const std::byte>>;
	// read_octet_string copied into a string on `mr`.
	[[nodiscard]] auto read_string(tag t = tags::octet_string,
	  std::pmr::memory_resource *mr = std::pmr::get_default_resource()) -> result<std::pmr::string>;
	[[nodiscard]] auto read_null(tag t = tags::null) -> result<void>;

	// A reader over a constructed element's contents, one level deeper.
	[[nodiscard]] auto enter(tag t = tags::sequence) -> result<reader>;

	// A reader over a primitive element whose content is itself BER.
	[[nodiscard]] auto enter_encapsulated(tag t = tags::octet_string) -> result<reader>;

	// decode_error if any bytes are left.
	[[nodiscard]] auto expect_end() const -> result<void>;

  private:
	struct header
	{
		tag t;
		std::size_t header_size{};
		std::size_t content_size{};
	};

	// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
	reader(std::span<const std::byte> data, std::size_t base, std::size_t depth, std::size_t max_depth) noexcept
	  : data_(data), base_(base), depth_(depth), max_depth_(max_depth)
	{}

	auto fast_header(header &out) const noexcept -> bool;
	auto parse_header() const -> result<header>;
	auto read_primitive(tag expected, const char *what) -> result<element>;
	auto enter_impl(tag t, bool constructed, const char *what) -> result<reader>;
	auto read_int(tag expected, const char *what) -> result<std::int64_t>;

	std::span<const std::byte> data_;
	std::size_t pos_ = 0;
	std::size_t base_ = 0;
	std::size_t depth_ = 0;
	std::size_t max_depth_ = default_max_depth;
};

// ---------------------------------------------------------------- framer

inline constexpr std::size_t default_max_message_size = std::size_t{ 16 } * 1024 * 1024;

// Size of the first complete element at the start of `buf`; nullopt while
// incomplete; an error, from the header alone, for a malformed header or a
// size above `max_size`.
[[nodiscard]] auto complete_message_size(std::span<const std::byte> buf,
  std::size_t max_size = default_max_message_size) -> result<std::optional<std::size_t>>;

// The total size the first element declares, once its header is complete.
[[nodiscard]] auto declared_message_size(std::span<const std::byte> buf,
  std::size_t max_size = default_max_message_size) -> result<std::optional<std::size_t>>;

}// namespace jhetz::ldap::ber
