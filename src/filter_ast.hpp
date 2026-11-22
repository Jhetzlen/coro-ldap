// Internal: the filter tree's private parts, and the two halves of
// encode_filter, so a search request can check its filter before anything is
// written, then write it.
#pragma once

#include "jhetz/ldap/ber.hpp"
#include "jhetz/ldap/error.hpp"
#include "jhetz/ldap/filter.hpp"

#include <cstddef>
#include <cstdint>
#include <limits>
#include <stdexcept>
#include <string_view>
#include <utility>

namespace jhetz::ldap::detail {

// Everything that builds or walks the private tree of a filter.
struct filter_access
{
	using node = filter::node;
	using kind = filter::kind;
	static constexpr std::uint32_t npos = filter::npos;

	static constexpr std::uint8_t part_initial = filter::part_initial;
	static constexpr std::uint8_t part_any = filter::part_any;
	static constexpr std::uint8_t part_final = filter::part_final;

	static constexpr auto k(kind x) noexcept -> std::uint8_t { return std::to_underlying(x); }

	// and / or / not: the nodes whose children are elements.
	static auto composite(const node &n) noexcept -> bool { return n.k <= k(kind::not_); }

	static auto size(const filter &f) noexcept -> std::size_t { return f.nodes_.size(); }

	// Appends `s` to the string pool and returns its offset.
	static auto add_text(filter &f, std::string_view s) -> std::uint32_t
	{
		// Offsets are 32-bit to keep nodes small. A filter with 4 GiB of
		// values cannot be sent anyway; treat it like exceeding max_size().
		if (s.size() > std::numeric_limits<std::uint32_t>::max() - f.text_.size()) {
			throw std::length_error("ldap::filter: more than 4 GiB of values");
		}
		const auto off = static_cast<std::uint32_t>(f.text_.size());
		f.text_.append(s);
		return off;
	}

	static auto add_node(filter &f, std::uint8_t node_kind) -> std::uint32_t
	{
		if (f.nodes_.size() >= npos) {
			throw std::length_error("ldap::filter: too many nodes");
		}
		f.nodes_.push_back(node{});
		f.nodes_.back().k = node_kind;
		return static_cast<std::uint32_t>(f.nodes_.size() - 1);
	}

	static void set_attr(filter &f, std::uint32_t i, std::string_view s)
	{
		const auto off = add_text(f, s);
		f.nodes_[i].attr_off = off;
		f.nodes_[i].attr_len = static_cast<std::uint32_t>(s.size());
	}

	static void set_value(filter &f, std::uint32_t i, std::string_view s)
	{
		const auto off = add_text(f, s);
		f.nodes_[i].value_off = off;
		f.nodes_[i].value_len = static_cast<std::uint32_t>(s.size());
	}

	static void set_rule(filter &f, std::uint32_t i, std::string_view s)
	{
		const auto off = add_text(f, s);
		f.nodes_[i].rule_off = off;
		f.nodes_[i].rule_len = static_cast<std::uint32_t>(s.size());
	}

	// Appends one byte to the pool (the parser unescapes byte by byte).
	static void add_char(filter &f, char c)
	{
		if (f.text_.size() >= std::numeric_limits<std::uint32_t>::max()) {
			throw std::length_error("ldap::filter: more than 4 GiB of values");
		}
		f.text_ += c;
	}

	// Value of node i from a range already in the pool: (offset, length),
	// as read_part returns it.
	static void set_value_range(filter &f, std::uint32_t i, std::pair<std::uint32_t, std::uint32_t> range) noexcept
	{
		f.nodes_[i].value_off = range.first;
		f.nodes_[i].value_len = range.second;
	}

	static void set_dn_attributes(filter &f, std::uint32_t i, bool on) noexcept { f.nodes_[i].dn_attributes = on; }

	// Makes `child` the last child of `parent`.
	static void link_last(filter &f, std::uint32_t parent, std::uint32_t child) noexcept
	{
		node &c = f.nodes_[child];
		node &p = f.nodes_[parent];
		c.parent = parent;
		c.next = npos;
		if (p.last == npos) {
			p.first = child;
		} else {
			f.nodes_[p.last].next = child;
		}
		p.last = child;
	}

	// Inserts `child` after `prev` (npos: as first child) under `parent`.
	static void link_after(filter &f, std::uint32_t parent, std::uint32_t prev, std::uint32_t child) noexcept
	{
		node &c = f.nodes_[child];
		node &p = f.nodes_[parent];
		c.parent = parent;
		if (prev == npos) {
			c.next = p.first;
			p.first = child;
		} else {
			c.next = f.nodes_[prev].next;
			f.nodes_[prev].next = child;
		}
		if (c.next == npos) {
			p.last = child;
		}
	}

	// A new root of kind `op` (and / or / not) above the current one.
	static void wrap(filter &f, kind op)
	{
		const std::uint32_t n = add_node(f, k(op));
		link_last(f, n, f.root_);
		f.root_ = n;
		++f.depth_;
		++f.elements_;
	}

	// A single-element filter: `node_kind` with an attribute and a value.
	// Attribute, then value: the order of the filter text (attr=value).
	// NOLINTBEGIN(bugprone-easily-swappable-parameters)
	static auto
	  leaf(const filter::allocator_type &alloc, kind node_kind, std::string_view attr, std::string_view value = {})
		-> filter
	// NOLINTEND(bugprone-easily-swappable-parameters)
	{
		filter f(alloc);
		f.root_ = add_node(f, k(node_kind));
		set_attr(f, f.root_, attr);
		if (!value.empty()) {
			set_value(f, f.root_, value);
		}
		f.depth_ = 1;
		f.elements_ = 1;
		return f;
	}

	static void add_part(filter &f, std::uint32_t parent, std::uint8_t part, std::string_view value)
	{
		const std::uint32_t p = add_node(f, part);
		set_value(f, p, value);
		link_last(f, parent, p);
	}

	// Visits the subtree at `top` in preorder without recursion; substring
	// parts are not visited.
	template<class Enter, class Leave> static void walk(const filter &f, std::uint32_t top, Enter enter, Leave leave)
	{
		std::uint32_t i = top;
		while (true) {
			enter(i);
			const node &n = f.nodes_[i];
			if (composite(n) && n.first != npos) {
				i = n.first;
				continue;
			}
			while (true) {
				leave(i);
				if (i == top) {
					return;
				}
				const node &c = f.nodes_[i];
				if (c.next != npos) {
					i = c.next;
					break;
				}
				i = c.parent;
			}
		}
	}

	// Copies the subtree of `src` at `top` into `dst` (not linked; returns its
	// index). `base`: where src's string pool starts in dst's.
	// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
	static auto copy_subtree(filter &dst, const filter &src, std::uint32_t top, std::uint32_t base) -> std::uint32_t
	{
		std::uint32_t result = npos;
		std::uint32_t parent = npos;// dst parent of the next node entered
		auto copy_node = [&](const node &n) {
			const std::uint32_t m = add_node(dst, n.k);
			node &c = dst.nodes_[m];
			c.dn_attributes = n.dn_attributes;
			c.attr_off = n.attr_off + base;
			c.attr_len = n.attr_len;
			c.value_off = n.value_off + base;
			c.value_len = n.value_len;
			c.rule_off = n.rule_off + base;
			c.rule_len = n.rule_len;
			return m;
		};
		walk(
		  src,
		  top,
		  [&](std::uint32_t i) {
			  const node &n = src.nodes_[i];
			  const std::uint32_t m = copy_node(n);
			  if (i == top) {
				  result = m;
			  } else {
				  link_last(dst, parent, m);
			  }
			  if (n.k == k(kind::substrings)) {
				  for (std::uint32_t p = n.first; p != npos; p = src.nodes_[p].next) {
					  link_last(dst, m, copy_node(src.nodes_[p]));
				  }
			  } else if (composite(n) && n.first != npos) {
				  parent = m;
			  }
		  },
		  [&](std::uint32_t i) {
			  const node &n = src.nodes_[i];
			  if (composite(n) && n.first != npos) {
				  parent = dst.nodes_[parent].parent;
			  }
		  });
		return result;
	}

	// f `op` g, reusing f. An AND (resp. OR) root of either operand is
	// merged into the result.
	static auto combine(filter f, const filter &g, kind op) -> filter
	{
		if (f.empty() || g.empty()) {
			return filter(f.get_allocator());
		}
		if (f.nodes_[f.root_].k != k(op)) {
			wrap(f, op);
		}
		const std::uint32_t root = f.root_;
		const std::uint32_t base = add_text(f, g.text_);
		const node &groot = g.nodes_[g.root_];
		if (groot.k == k(op)) {
			for (std::uint32_t c = groot.first; c != npos; c = g.nodes_[c].next) {
				link_last(f, root, copy_subtree(f, g, c, base));
			}
			f.depth_ = std::max(f.depth_, g.depth_);
			f.elements_ += g.elements_ - 1;
		} else {
			link_last(f, root, copy_subtree(f, g, g.root_, base));
			f.depth_ = std::max(f.depth_, g.depth_ + 1);
			f.elements_ += g.elements_;
		}
		return f;
	}

	// f `op` g, reusing g: f's nodes go in front of g's.
	static auto combine_front(const filter &f, filter g, kind op) -> filter
	{
		if (f.empty() || g.empty()) {
			return filter(g.get_allocator());
		}
		if (g.nodes_[g.root_].k != k(op)) {
			wrap(g, op);
		}
		const std::uint32_t root = g.root_;
		const std::uint32_t base = add_text(g, f.text_);
		const node &froot = f.nodes_[f.root_];
		if (froot.k == k(op)) {
			std::uint32_t prev = npos;
			for (std::uint32_t c = froot.first; c != npos; c = f.nodes_[c].next) {
				const std::uint32_t m = copy_subtree(g, f, c, base);
				link_after(g, root, prev, m);
				prev = m;
			}
			g.depth_ = std::max(g.depth_, f.depth_);
			g.elements_ += f.elements_ - 1;
		} else {
			link_after(g, root, npos, copy_subtree(g, f, f.root_, base));
			g.depth_ = std::max(g.depth_, f.depth_ + 1);
			g.elements_ += f.elements_;
		}
		return g;
	}

	// f `op` g with an rvalue g: reused when it is on f's resource.
	static auto combine_right(const filter &f, filter &&g, kind op) -> filter
	{
		if (f.get_allocator() == g.get_allocator()) {
			return combine_front(f, std::move(g), op);
		}
		return combine(filter(f, f.get_allocator()), g, op);
	}

	// Both rvalues: the larger one is reused (so chains nested either way
	// stay linear), g only when it is on f's resource.
	static auto combine_both(filter &&f, filter &&g, kind op) -> filter
	{
		if (g.nodes_.size() > f.nodes_.size() && f.get_allocator() == g.get_allocator()) {
			return combine_front(f, std::move(g), op);
		}
		return combine(std::move(f), g, op);
	}

	// (a=initial*any*...*final); empty parts are omitted, all empty gives
	// present.
	// NOLINTBEGIN(bugprone-easily-swappable-parameters)
	static auto substrings(const filter::allocator_type &alloc,
	  std::string_view attr,
	  std::string_view initial,
	  std::string_view any,
	  std::string_view final_) -> filter
	// NOLINTEND(bugprone-easily-swappable-parameters)
	{
		if (initial.empty() && any.empty() && final_.empty()) {
			return leaf(alloc, kind::present, attr);
		}
		filter f = leaf(alloc, kind::substrings, attr);
		if (!initial.empty()) {
			add_part(f, f.root_, filter::part_initial, initial);
		}
		if (!any.empty()) {
			add_part(f, f.root_, filter::part_any, any);
		}
		if (!final_.empty()) {
			add_part(f, f.root_, filter::part_final, final_);
		}
		f.elements_ += std::size_t{ !initial.empty() } + std::size_t{ !any.empty() } + std::size_t{ !final_.empty() };
		return f;
	}

	static auto negate(filter f) -> filter
	{
		if (!f.empty()) {
			wrap(f, kind::not_);
		}
		return f;
	}

	// Both callers pass the parser's like-named depth_ and elements_.
	// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
	static void set_limits(filter &f, std::size_t depth, std::size_t elements) noexcept
	{
		f.depth_ = depth;
		f.elements_ = elements;
	}
	static void set_root(filter &f, std::uint32_t root) noexcept { f.root_ = root; }
	static auto at(const filter &f, std::uint32_t i) noexcept -> const node & { return f.nodes_[i]; }
	static auto attr_of(const filter &f, const node &n) noexcept -> std::string_view
	{
		return f.str(n.attr_off, n.attr_len);
	}
	static auto value_of(const filter &f, const node &n) noexcept -> std::string_view
	{
		return f.str(n.value_off, n.value_len);
	}
	static auto rule_of(const filter &f, const node &n) noexcept -> std::string_view
	{
		return f.str(n.rule_off, n.rule_len);
	}
	static auto root(const filter &f) noexcept -> std::uint32_t { return f.root_; }
};

// The Filter CHOICE's context tag numbers (RFC 4511 section 4.5.1).
namespace filter_choice {
	inline constexpr std::uint8_t and_ = 0;
	inline constexpr std::uint8_t or_ = 1;
	inline constexpr std::uint8_t not_ = 2;
	inline constexpr std::uint8_t equality_match = 3;
	inline constexpr std::uint8_t substrings = 4;
	inline constexpr std::uint8_t greater_or_equal = 5;
	inline constexpr std::uint8_t less_or_equal = 6;
	inline constexpr std::uint8_t present = 7;
	inline constexpr std::uint8_t approx_match = 8;
	inline constexpr std::uint8_t extensible_match = 9;
}// namespace filter_choice

// invalid_filter if `f` is empty or beyond `limits`.
auto check_filter(const filter &f, const filter_limits &limits) -> result<void>;

// Tree -> BER. Precondition: check_filter succeeded (it bounds the recursion).
void write_filter(ber::writer &w, const filter &f);

}// namespace jhetz::ldap::detail
