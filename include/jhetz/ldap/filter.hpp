// Search filters (DESIGN.md section 2): a typed tree, built by ldap::filters
// or parsed from RFC 4515 text, encoded to and decoded from BER.
#pragma once

#include "jhetz/ldap/attribute.hpp"
#include "jhetz/ldap/ber.hpp"
#include "jhetz/ldap/error.hpp"

#include <cstddef>
#include <cstdint>
#include <iterator>
#include <memory_resource>
#include <optional>
#include <ranges>
#include <string>
#include <string_view>
#include <vector>

namespace jhetz::ldap {

// Maximum nesting of filter elements: `(cn=x)` has depth 1, `(&(cn=x))` 2.
inline constexpr std::size_t max_filter_depth = 24;

// Maximum number of filter elements, each substring part counted.
inline constexpr std::size_t max_filter_elements = 10'000;

// Limits applied by filter::raw and encode_filter.
struct filter_limits
{
	std::size_t max_depth = max_filter_depth;
	std::size_t max_elements = max_filter_elements;
};

class filter;

namespace detail {
	struct filter_access;
}

namespace filters {
	class attr;
}

// A search filter (RFC 4511 section 4.5.1.7) as a tree of unescaped values,
// its nodes in one vector and its strings in one string. Empty when
// default-constructed.
class filter
{
  public:
	using allocator_type = std::pmr::polymorphic_allocator<>;

	enum class kind : std::uint8_t {
		and_,// (&...); (&) is absolute true (RFC 4526)
		or_,// (|...); (|) is absolute false
		not_,// (!f)
		equality,// (a=v)
		substrings,// (a=initial*any*...*final)
		greater_or_equal,// (a>=v)
		less_or_equal,// (a<=v)
		present,// (a=*)
		approx,// (a~=v)
		extensible_match,// (a:dn:rule:=v)
	};

	class view;
	class child_iterator;
	class child_range;
	class substring_iterator;
	class substring_range;

	filter() = default;
	explicit filter(const allocator_type &alloc) : nodes_(alloc), text_(alloc) {}
	filter(const filter &) = default;// default resource, like any pmr copy
	filter(filter &&other) noexcept;
	filter(const filter &other, const allocator_type &alloc);
	filter(filter &&other, const allocator_type &alloc);
	auto operator=(const filter &) -> filter & = default;
	auto operator=(filter &&other) -> filter &;
	~filter() = default;

	[[nodiscard]] auto get_allocator() const noexcept -> allocator_type { return nodes_.get_allocator(); }

	// Parses RFC 4515 text into a tree on `mr`; invalid_filter with the
	// position. Text without an outer '(' is read as if wrapped in one.
	[[nodiscard]] static auto raw(std::string_view text,
	  std::pmr::memory_resource *mr = std::pmr::get_default_resource()) -> result<filter>;
	[[nodiscard]] static auto raw(std::string_view text,
	  const filter_limits &limits,
	  std::pmr::memory_resource *mr = std::pmr::get_default_resource()) -> result<filter>;

	[[nodiscard]] auto empty() const noexcept -> bool { return nodes_.empty(); }
	// Precondition: !empty().
	[[nodiscard]] auto root() const noexcept -> view;
	// Both 0 when empty. Constant time.
	[[nodiscard]] auto depth() const noexcept -> std::size_t { return empty() ? 0 : depth_; }
	[[nodiscard]] auto elements() const noexcept -> std::size_t { return empty() ? 0 : elements_; }

	// Canonical RFC 4515 text, for logs; raw(to_string()) == *this.
	[[nodiscard]] auto to_string(std::pmr::memory_resource *mr = std::pmr::get_default_resource()) const
	  -> std::pmr::string;

	friend auto operator==(const filter &a, const filter &b) noexcept -> bool;

  private:
	friend struct detail::filter_access;

	static constexpr std::uint32_t npos = 0xFFFF'FFFFu;

	// Node kinds of substring parts (never a filter::kind).
	static constexpr std::uint8_t part_initial = 32;
	static constexpr std::uint8_t part_any = 33;
	static constexpr std::uint8_t part_final = 34;

	struct node
	{
		std::uint8_t k = 0;// filter::kind, or a part_* constant
		bool dn_attributes = false;// extensible match
		std::uint32_t attr_off = 0;// attribute description (extensible: type, may be empty)
		std::uint32_t attr_len = 0;
		std::uint32_t value_off = 0;// assertion value / substring part
		std::uint32_t value_len = 0;
		std::uint32_t rule_off = 0;// extensible: matching rule, may be empty
		std::uint32_t rule_len = 0;
		std::uint32_t parent = npos;
		std::uint32_t first = npos;
		std::uint32_t last = npos;
		std::uint32_t next = npos;
	};

	[[nodiscard]] auto str(std::uint32_t off, std::uint32_t len) const noexcept -> std::string_view
	{
		return std::string_view(text_).substr(off, len);
	}
	void clear() noexcept;

	std::pmr::vector<node> nodes_{};
	std::pmr::string text_{};
	std::uint32_t root_ = 0;
	std::size_t depth_ = 0;
	std::size_t elements_ = 0;
};

// A node of a filter; valid while the filter is alive and unchanged.
class filter::view
{
  public:
	[[nodiscard]] auto kind() const noexcept -> filter::kind { return static_cast<filter::kind>(n().k); }
	// Empty for and / or / not.
	[[nodiscard]] auto attribute() const noexcept -> std::string_view { return f_->str(n().attr_off, n().attr_len); }
	// Unescaped.
	[[nodiscard]] auto value() const noexcept -> std::string_view { return f_->str(n().value_off, n().value_len); }
	[[nodiscard]] auto matching_rule() const noexcept -> std::string_view
	{
		return f_->str(n().rule_off, n().rule_len);
	}
	[[nodiscard]] auto dn_attributes() const noexcept -> bool { return n().dn_attributes; }
	[[nodiscard]] auto children() const noexcept -> child_range;
	// Never empty strings; nullopt / empty for other kinds.
	[[nodiscard]] auto initial() const noexcept -> std::optional<std::string_view>;
	[[nodiscard]] auto any() const noexcept -> substring_range;
	[[nodiscard]] auto final() const noexcept -> std::optional<std::string_view>;

  private:
	friend class filter;
	friend class filter::child_iterator;
	view(const filter *f, std::uint32_t i) noexcept : f_(f), i_(i) {}
	[[nodiscard]] auto n() const noexcept -> const node & { return f_->nodes_[i_]; }

	const filter *f_;
	std::uint32_t i_;
};

class filter::child_iterator
{
  public:
	using value_type = filter::view;
	using difference_type = std::ptrdiff_t;
	using iterator_category = std::forward_iterator_tag;

	child_iterator() = default;
	auto operator*() const noexcept -> filter::view { return { f_, i_ }; }
	auto operator++() noexcept -> child_iterator &
	{
		i_ = f_->nodes_[i_].next;
		return *this;
	}
	auto operator++(int) noexcept -> child_iterator
	{
		auto old = *this;
		++*this;
		return old;
	}
	friend auto operator==(const child_iterator &a, const child_iterator &b) noexcept -> bool { return a.i_ == b.i_; }

  private:
	friend class filter::view;
	child_iterator(const filter *f, std::uint32_t i) noexcept : f_(f), i_(i) {}
	const filter *f_ = nullptr;
	std::uint32_t i_ = filter::npos;
};

// A borrowed view: its iterators point into the filter.
class filter::child_range : public std::ranges::view_interface<filter::child_range>
{
  public:
	[[nodiscard]] auto begin() const noexcept -> child_iterator { return first_; }
	// NOLINTNEXTLINE(readability-convert-member-functions-to-static): range protocol end()
	[[nodiscard]] auto end() const noexcept -> child_iterator { return {}; }
	// NOLINTNEXTLINE(bugprone-derived-method-shadowing-base-method): same result, kept [[nodiscard]] noexcept
	[[nodiscard]] auto empty() const noexcept -> bool { return first_ == child_iterator{}; }

  private:
	friend class filter::view;
	explicit child_range(child_iterator first) noexcept : first_(first) {}
	child_iterator first_;
};

class filter::substring_iterator
{
  public:
	using value_type = std::string_view;
	using difference_type = std::ptrdiff_t;
	using iterator_category = std::forward_iterator_tag;

	substring_iterator() = default;
	auto operator*() const noexcept -> std::string_view
	{
		const auto &p = f_->nodes_[i_];
		return f_->str(p.value_off, p.value_len);
	}
	auto operator++() noexcept -> substring_iterator &
	{
		i_ = f_->nodes_[i_].next;
		if (i_ != filter::npos && f_->nodes_[i_].k != part_any) {
			i_ = filter::npos;
		}
		return *this;
	}
	auto operator++(int) noexcept -> substring_iterator
	{
		auto old = *this;
		++*this;
		return old;
	}
	friend auto operator==(const substring_iterator &a, const substring_iterator &b) noexcept -> bool
	{
		return a.i_ == b.i_;
	}

  private:
	friend class filter::view;
	substring_iterator(const filter *f, std::uint32_t i) noexcept : f_(f), i_(i) {}
	const filter *f_ = nullptr;
	std::uint32_t i_ = filter::npos;
};

// A borrowed view, like child_range.
class filter::substring_range : public std::ranges::view_interface<filter::substring_range>
{
  public:
	[[nodiscard]] auto begin() const noexcept -> substring_iterator { return first_; }
	// NOLINTNEXTLINE(readability-convert-member-functions-to-static): range protocol end()
	[[nodiscard]] auto end() const noexcept -> substring_iterator { return {}; }
	// NOLINTNEXTLINE(bugprone-derived-method-shadowing-base-method): same result, kept [[nodiscard]] noexcept
	[[nodiscard]] auto empty() const noexcept -> bool { return first_ == substring_iterator{}; }

  private:
	friend class filter::view;
	explicit substring_range(substring_iterator first) noexcept : first_(first) {}
	substring_iterator first_;
};

inline auto filter::root() const noexcept -> filter::view { return { this, root_ }; }

// RFC 4515 section 3 escaping; valid UTF-8 is kept as is.
[[nodiscard]] auto escape_filter_value(std::string_view value,
  std::pmr::memory_resource *mr = std::pmr::get_default_resource()) -> std::pmr::string;

// The inverse of escape_filter_value; invalid_filter on what filter::raw
// rejects in a value.
[[nodiscard]] auto unescape_filter_value(std::string_view text,
  std::pmr::memory_resource *mr = std::pmr::get_default_resource()) -> result<std::pmr::string>;

// (&fg), (|fg), (!f); a nested AND (OR) operand is merged. An empty operand
// gives an empty result.
[[nodiscard]] auto operator&&(const filter &f, const filter &g) -> filter;
[[nodiscard]] auto operator&&(filter &&f, const filter &g) -> filter;
[[nodiscard]] auto operator&&(const filter &f, filter &&g) -> filter;
[[nodiscard]] auto operator&&(filter &&f, filter &&g) -> filter;
[[nodiscard]] auto operator||(const filter &f, const filter &g) -> filter;
[[nodiscard]] auto operator||(filter &&f, const filter &g) -> filter;
[[nodiscard]] auto operator||(const filter &f, filter &&g) -> filter;
[[nodiscard]] auto operator||(filter &&f, filter &&g) -> filter;
[[nodiscard]] auto operator!(const filter &f) -> filter;
[[nodiscard]] auto operator!(filter &&f) -> filter;

namespace filters {

	// `attr(a) == v` and friends: one-node filters holding `v` unescaped.
	class attr
	{
	  public:
		using allocator_type = std::pmr::polymorphic_allocator<>;

		// NOLINTNEXTLINE(cppcoreguidelines-explicit-constructor,misc-explicit-constructor)
		attr(attribute::literal name, const allocator_type &alloc = {}) : name_(name.text, alloc) {}
		explicit attr(const attribute &name, const allocator_type &alloc = {});

		[[nodiscard]] auto operator==(std::string_view value) const -> filter;
		[[nodiscard]] auto operator>=(std::string_view value) const -> filter;
		[[nodiscard]] auto operator<=(std::string_view value) const -> filter;
		[[nodiscard]] auto approx(std::string_view value) const -> filter;
		[[nodiscard]] auto present() const -> filter;
		// (a=v*), (a=*v), (a=*v*); an empty value gives present().
		[[nodiscard]] auto starts_with(std::string_view value) const -> filter;
		[[nodiscard]] auto ends_with(std::string_view value) const -> filter;
		[[nodiscard]] auto contains(std::string_view value) const -> filter;
		// Extensible match (RFC 4515): `(a:rule:=v)`, `(a:dn:rule:=v)`.
		[[nodiscard]] auto matches(std::string_view rule, std::string_view value, bool dn_attributes = false) const
		  -> filter;

	  private:
		std::pmr::string name_;
	};

	// Extensible match without an attribute: `(:rule:=v)`, `(:dn:rule:=v)`.
	[[nodiscard]] auto rule_matches(std::string_view rule,
	  std::string_view value,
	  bool dn_attributes = false,
	  const filter::allocator_type &alloc = {}) -> filter;

	// The combinators, also reachable from here.
	using ldap::operator&&;
	using ldap::operator||;
	using ldap::operator!;

}// namespace filters

// Appends the BER Filter of `f` to `w`; invalid_filter, nothing written, if
// `f` is empty or beyond `limits`.
[[nodiscard]] auto encode_filter(ber::writer &w, const filter &f, const filter_limits &limits = {}) -> result<void>;

}// namespace jhetz::ldap

template<> inline constexpr bool std::ranges::enable_borrowed_range<jhetz::ldap::filter::child_range> = true;
template<> inline constexpr bool std::ranges::enable_borrowed_range<jhetz::ldap::filter::substring_range> = true;
