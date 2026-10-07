// Search filters (DESIGN.md section 2): a typed tree, made by the builders in
// ldap::filters or parsed once from RFC 4515 text by filter::raw, written to
// BER directly from the tree, decoded from BER back into a tree, and printed
// as canonical RFC 4515 text for logs.
#pragma once

#include "jhetz/ldap/attribute.hpp"
#include "jhetz/ldap/ber.hpp"
#include "jhetz/ldap/error.hpp"

#include <cstddef>
#include <cstdint>
#include <iterator>
#include <memory_resource>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace jhetz::ldap {

// Maximum nesting of filter elements, counting every `(...)` on the path from
// the outermost filter to a leaf: `(cn=x)` has depth 1, `(&(cn=x))` depth 2.
// filter::raw and decode_filter reject deeper filters as they read them
// (invalid_filter, resp. nesting_too_deep); a deeper filter made by the
// builders fails with invalid_filter when it is encoded. The value keeps a
// search request with the deepest allowed filter within ber::reader's default
// depth limit (32): LDAPMessage and SearchRequest take 2 levels, a substrings
// leaf 1 extra.
inline constexpr std::size_t max_filter_depth = 24;

// Maximum number of filter elements (every `(...)`, leaves included, plus
// every part of a substring assertion: `(a=*x*y*)` is 3) in one filter, with
// the same checks as max_filter_depth. A hostile peer could otherwise send a multi-megabyte
// `(&(a=*)(a=*)...)` whose 3-byte BER children each become a tree node.
// 10,000 leaves room for large real filters (group membership ORs).
inline constexpr std::size_t max_filter_elements = 10'000;

// Limits applied by filter::raw, encode_filter and decode_filter. Raising
// `max_depth` above 24 can produce search requests deeper than ber::reader's
// default depth limit; parsing, encoding and decoding recurse once per level.
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

// A search filter (RFC 4511 section 4.5.1.7) as a tree whose leaves hold
// unescaped values: and / or / not, equality, substrings (initial, any...,
// final), >=, <=, present, approx and extensible match.
//
// Made three ways, each giving a tree the encoder can write without parsing:
// - the builders in ldap::filters (`attr("uid") == v && !attr("x").present()`);
// - filter::raw(text), the only parser of RFC 4515 text, run once when called;
// - decode_filter (BER, e.g. a mock server reading a search request).
// There is no other way to build nodes, so every non-empty filter is well
// formed: its attribute descriptions are valid (RFC 4512), no substring part
// is empty, and it has an RFC 4515 form. Only the depth and element limits can
// be exceeded, by builders; encoding then fails with invalid_filter.
//
// A default-constructed filter is empty: it has no tree, encoding it fails
// with invalid_filter, and combining it with && / || / ! gives an empty filter
// again (so an empty filter never silently turns into a condition).
//
// Equality compares the trees: same shape, kinds, attribute descriptions
// (exact spelling), values and flags. How a filter was made does not matter:
// `filter::raw("(&(a=1)(b=2))") == (attr("a") == "1" && attr("b") == "2")`.
//
// Representation: all nodes of a filter live in one std::pmr::vector
// (44 bytes each, linked by 32-bit indices: parent, first / last child, next
// sibling) and all their strings in one std::pmr::string, so a filter makes
// two allocations however large it is, copies with two memcpy-like copies,
// and its destructor never recurses. Combining reuses the storage of an
// rvalue operand (the larger one when both are) and copies an lvalue one, so
// a chain in one expression (`a && b && c ...`, nested either way) and a loop
// `f = std::move(f) || x` are linear, while `f = f || x` copies f every time
// (quadratic over a loop). Traversals (==, to_string) follow the
// parent links instead of recursing, so any depth is safe; encoding recurses,
// but only after checking the depth limit.
//
// Nodes are linked by 32-bit offsets, so the strings of one filter are
// limited to 4 GiB in all; exceeding that throws std::length_error, like
// exceeding a container's max_size() (a filter that large cannot be sent).
//
// Memory (DESIGN.md section 8): allocator-aware. The nodes and strings use
// the resource given to raw(), decode_filter(), filters::attr or the
// constructor; a filter combined from others uses the left operand's
// resource. As for any pmr container, a plain copy uses the default resource,
// the allocator-extended copy the one given, and assignment keeps the target's
// resource. A filter allocated from an arena must not outlive the arena.
class filter
{
  public:
	using allocator_type = std::pmr::polymorphic_allocator<>;

	enum class kind : std::uint8_t {
		and_,// (&...): any number of children, (&) is absolute true (RFC 4526)
		or_,// (|...): any number of children, (|) is absolute false
		not_,// (!f): exactly one child
		equality,// (a=v)
		substrings,// (a=initial*any*...*final): at least one non-empty part
		greater_or_equal,// (a>=v)
		less_or_equal,// (a<=v)
		present,// (a=*)
		approx,// (a~=v)
		extensible_match,// (a:dn:rule:=v): attribute and/or rule, dnAttributes
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
	// Assignment keeps this filter's resource.
	filter &operator=(const filter &) = default;
	filter &operator=(filter &&other);
	~filter() = default;

	allocator_type get_allocator() const noexcept { return nodes_.get_allocator(); }

	// Parses RFC 4515 text into a tree allocated from `mr`. Fails with
	// invalid_filter (position in the context); never throws on bad input.
	//
	// Supported: and/or/not, RFC 4526 absolute true/false `(&)` and `(|)`,
	// equality, substrings (empty `any` parts such as `a**b` are skipped), >=,
	// <=, ~=, presence, extensible match (`attr[:dn][:rule]:=v`,
	// `[:dn]:rule:=v`), attribute options (`cn;lang-en`), numeric OIDs, `\xx`
	// escapes. Leniency: text that does not start with '(' is read as if it
	// were wrapped in parentheses, as ldapsearch does (`uid=jdoe` is
	// `(uid=jdoe)`). No other leniency: no whitespace between elements, and
	// `(`, `)`, `*` (outside substrings), `\` and NUL must be escaped in values.
	// Filters beyond `limits` (depth or number of elements) fail too.
	static result<filter> raw(std::string_view text, std::pmr::memory_resource *mr = std::pmr::get_default_resource());
	static result<filter> raw(std::string_view text,
	  const filter_limits &limits,
	  std::pmr::memory_resource *mr = std::pmr::get_default_resource());

	bool empty() const noexcept { return nodes_.empty(); }
	// The top node. Precondition: !empty().
	view root() const noexcept;
	// Longest path from the root to a leaf, counting both (`(cn=x)` is 1), and
	// number of elements; both 0 when empty. Constant time.
	std::size_t depth() const noexcept { return empty() ? 0 : depth_; }
	std::size_t elements() const noexcept { return empty() ? 0 : elements_; }

	// Canonical RFC 4515 text, for logs: values escaped with
	// escape_filter_value (lower-case hex), `:dn` in lower case, empty
	// substring parts dropped, attribute descriptions and rules as stored.
	// raw(to_string()) == *this for every filter within the limits. Empty
	// filter: "".
	std::pmr::string to_string(std::pmr::memory_resource *mr = std::pmr::get_default_resource()) const;

	friend bool operator==(const filter &a, const filter &b) noexcept;

  private:
	friend struct detail::filter_access;

	static constexpr std::uint32_t npos = 0xFFFF'FFFFu;

	// Substring parts are child nodes of their substrings node, with these
	// kinds (never visible as a filter::kind).
	enum part_kind : std::uint8_t { part_initial = 32, part_any, part_final };

	struct node
	{
		std::uint8_t k = 0;// filter::kind, or a part_kind
		bool dn_attributes = false;// extensible match
		std::uint32_t attr_off = 0;// attribute description (extensible: type, may be empty)
		std::uint32_t attr_len = 0;
		std::uint32_t value_off = 0;// assertion value / substring part
		std::uint32_t value_len = 0;
		std::uint32_t rule_off = 0;// extensible: matching rule, may be empty
		std::uint32_t rule_len = 0;
		std::uint32_t parent = npos;
		std::uint32_t first = npos;// first child
		std::uint32_t last = npos;// last child
		std::uint32_t next = npos;// next sibling
	};

	std::string_view str(std::uint32_t off, std::uint32_t len) const noexcept
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

// A node of a filter, for inspecting the tree (e.g. evaluating it in a mock
// server). Refers into the filter: valid while it is alive and unchanged.
class filter::view
{
  public:
	filter::kind kind() const noexcept { return static_cast<filter::kind>(n().k); }
	// Attribute description of a leaf; the (possibly empty) type of an
	// extensible match; empty for and / or / not.
	std::string_view attribute() const noexcept { return f_->str(n().attr_off, n().attr_len); }
	// Assertion value of equality, >=, <=, ~= and extensible match (unescaped).
	std::string_view value() const noexcept { return f_->str(n().value_off, n().value_len); }
	// Extensible match: matching rule (may be empty) and dnAttributes.
	std::string_view matching_rule() const noexcept { return f_->str(n().rule_off, n().rule_len); }
	bool dn_attributes() const noexcept { return n().dn_attributes; }
	// Children of and / or (any number) and not (one); empty for other kinds.
	child_range children() const noexcept;
	// Parts of a substrings assertion (never empty strings); nullopt / empty
	// for other kinds.
	std::optional<std::string_view> initial() const noexcept;
	substring_range any() const noexcept;
	std::optional<std::string_view> final() const noexcept;

  private:
	friend class filter;
	friend class filter::child_iterator;
	view(const filter *f, std::uint32_t i) noexcept : f_(f), i_(i) {}
	const node &n() const noexcept { return f_->nodes_[i_]; }

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
	filter::view operator*() const noexcept { return filter::view(f_, i_); }
	child_iterator &operator++() noexcept
	{
		i_ = f_->nodes_[i_].next;
		return *this;
	}
	child_iterator operator++(int) noexcept
	{
		auto old = *this;
		++*this;
		return old;
	}
	friend bool operator==(const child_iterator &a, const child_iterator &b) noexcept { return a.i_ == b.i_; }

  private:
	friend class filter::view;
	child_iterator(const filter *f, std::uint32_t i) noexcept : f_(f), i_(i) {}
	const filter *f_ = nullptr;
	std::uint32_t i_ = filter::npos;
};

class filter::child_range
{
  public:
	child_iterator begin() const noexcept { return first_; }
	child_iterator end() const noexcept { return {}; }
	bool empty() const noexcept { return first_ == child_iterator{}; }

  private:
	friend class filter::view;
	explicit child_range(child_iterator first) noexcept : first_(first) {}
	child_iterator first_;
};

// Iterates over the `any` parts of a substrings node.
class filter::substring_iterator
{
  public:
	using value_type = std::string_view;
	using difference_type = std::ptrdiff_t;
	using iterator_category = std::forward_iterator_tag;

	substring_iterator() = default;
	std::string_view operator*() const noexcept
	{
		const auto &p = f_->nodes_[i_];
		return f_->str(p.value_off, p.value_len);
	}
	substring_iterator &operator++() noexcept
	{
		i_ = f_->nodes_[i_].next;
		if (i_ != filter::npos && f_->nodes_[i_].k != part_any) i_ = filter::npos;
		return *this;
	}
	substring_iterator operator++(int) noexcept
	{
		auto old = *this;
		++*this;
		return old;
	}
	friend bool operator==(const substring_iterator &a, const substring_iterator &b) noexcept { return a.i_ == b.i_; }

  private:
	friend class filter::view;
	substring_iterator(const filter *f, std::uint32_t i) noexcept : f_(f), i_(i) {}
	const filter *f_ = nullptr;
	std::uint32_t i_ = filter::npos;
};

class filter::substring_range
{
  public:
	substring_iterator begin() const noexcept { return first_; }
	substring_iterator end() const noexcept { return {}; }
	bool empty() const noexcept { return first_ == substring_iterator{}; }

  private:
	friend class filter::view;
	explicit substring_range(substring_iterator first) noexcept : first_(first) {}
	substring_iterator first_;
};

inline filter::view filter::root() const noexcept { return view(this, root_); }

// RFC 4515 section 3 escaping: `*` `(` `)` `\` and NUL become \2a \28 \29 \5c
// \00; every other byte is kept as is, including bytes that are not UTF-8.
std::pmr::string escape_filter_value(std::string_view value,
  std::pmr::memory_resource *mr = std::pmr::get_default_resource());

// (&fg), (|fg), (!f). An operand that is itself an AND (resp. OR) is merged,
// so `a && b && c` gives (&abc), not (&(&ab)c), in whichever order the chain
// is built; (!f) is always a new node. Combining only adds nodes: an
// operand's own tree, parsed or built, is never re-read, so it keeps its
// meaning (merging (&...) into an AND does not change it). The result is
// allocated from the left operand's resource; an rvalue operand's storage is
// reused when possible. An empty operand gives an empty result.
filter operator&&(const filter &f, const filter &g);
filter operator&&(filter &&f, const filter &g);
filter operator&&(const filter &f, filter &&g);
filter operator&&(filter &&f, filter &&g);
filter operator||(const filter &f, const filter &g);
filter operator||(filter &&f, const filter &g);
filter operator||(const filter &f, filter &&g);
filter operator||(filter &&f, filter &&g);
filter operator!(const filter &f);
filter operator!(filter &&f);

namespace filters {

	// `attr(a) == v` and friends (DESIGN.md section 2 table). Each builds a
	// one-node filter holding `v` unescaped, allocated from the resource
	// given to attr (default: the default resource). A literal name is
	// checked at compile time; an ldap::attribute is checked when attr() is
	// built and throws std::invalid_argument if it is not a valid attribute
	// description (only possible with attribute::unchecked), so an attribute
	// name can never make a filter that has no RFC 4515 form.
	class attr
	{
	  public:
		using allocator_type = std::pmr::polymorphic_allocator<>;

		attr(attribute::literal name, const allocator_type &alloc = {}) : name_(name.text, alloc) {}
		explicit attr(const attribute &name, const allocator_type &alloc = {});

		filter operator==(std::string_view value) const;// (a=v)
		filter operator>=(std::string_view value) const;// (a>=v)
		filter operator<=(std::string_view value) const;// (a<=v)
		filter approx(std::string_view value) const;// (a~=v)
		filter present() const;// (a=*)
		// (a=v*), (a=*v), (a=*v*). With an empty value these mean "has any
		// value" and give present(), since (a=**) is not a valid filter.
		filter starts_with(std::string_view value) const;
		filter ends_with(std::string_view value) const;
		filter contains(std::string_view value) const;
		// Extensible match (RFC 4515): `(a:rule:=v)`, `(a:dn:rule:=v)` with
		// dn_attributes, `(a:=v)` / `(a:dn:=v)` with an empty rule. The rule
		// is a matching rule name or OID ("caseExactMatch", "2.5.13.5");
		// anything else throws std::invalid_argument, as does the rule "dn"
		// without dn_attributes (RFC 4515 has no form for it).
		filter matches(std::string_view rule, std::string_view value, bool dn_attributes = false) const;

	  private:
		std::pmr::string name_;
	};

	// Extensible match without an attribute: `(:rule:=v)`, `(:dn:rule:=v)`.
	// The rule is required; same checks as attr::matches.
	filter rule_matches(std::string_view rule,
	  std::string_view value,
	  bool dn_attributes = false,
	  const filter::allocator_type &alloc = {});

	// The combinators live in namespace ldap (found by argument-dependent
	// lookup for any filter, parsed or built); also reachable from here.
	using ldap::operator&&;
	using ldap::operator||;
	using ldap::operator!;

}// namespace filters

// Appends the BER Filter (RFC 4511 section 4.5.1.7) of `f` to `w`. Fails with
// invalid_filter, before writing anything, if `f` is empty or deeper or larger
// than `limits` (only possible for filters made by the builders).
result<void> encode_filter(ber::writer &w, const filter &f, const filter_limits &limits = {});

// Reads one BER Filter from `r` into a tree allocated from `mr`. Filters that
// cannot be written as RFC 4515 text are rejected with decode_error (invalid
// attribute descriptions, empty substrings, initial or final out of place,
// extensible match without type and rule, or with a rule named "dn" but no
// dnAttributes), as are filters deeper than limits.max_depth
// (nesting_too_deep) and filters with more than limits.max_elements elements
// (decode_error). So every decoded filter encodes, and encodes to the same
// tree. Unknown trailing elements are skipped and an explicit dnAttributes
// FALSE is accepted (re-encoding omits both). On failure `r` is unchanged.
result<filter> decode_filter(ber::reader &r,
  const filter_limits &limits = {},
  std::pmr::memory_resource *mr = std::pmr::get_default_resource());

}// namespace jhetz::ldap
