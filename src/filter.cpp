#include "jhetz/ldap/filter.hpp"

#include "control_util.hpp"
#include "filter_ast.hpp"
#include "format_util.hpp"

#include <algorithm>
#include <expected>
#include <limits>
#include <span>
#include <stdexcept>
#include <string_view>
#include <utility>

namespace jhetz::ldap {

// ---------------------------------------------------------------- tree primitives

namespace detail {

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
		template<class Enter, class Leave>
		static void walk(const filter &f, std::uint32_t top, Enter enter, Leave leave)
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
			f.elements_ +=
			  std::size_t{ !initial.empty() } + std::size_t{ !any.empty() } + std::size_t{ !final_.empty() };
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

}// namespace detail

using access = detail::filter_access;

// ---------------------------------------------------------------- filter members

filter::filter(filter &&other) noexcept
  : nodes_(std::move(other.nodes_)), text_(std::move(other.text_)), root_(other.root_), depth_(other.depth_),
	elements_(other.elements_)
{
	other.clear();
}

filter::filter(const filter &other, const allocator_type &alloc)
  : nodes_(other.nodes_, alloc), text_(other.text_, alloc), root_(other.root_), depth_(other.depth_),
	elements_(other.elements_)
{}

filter::filter(filter &&other, const allocator_type &alloc)
  : nodes_(std::move(other.nodes_), alloc), text_(std::move(other.text_), alloc), root_(other.root_),
	depth_(other.depth_), elements_(other.elements_)
{
	other.clear();
}

auto filter::operator=(filter &&other) -> filter &
{
	if (this != &other) {
		nodes_ = std::move(other.nodes_);
		text_ = std::move(other.text_);
		root_ = other.root_;
		depth_ = other.depth_;
		elements_ = other.elements_;
		other.clear();
	}
	return *this;
}

void filter::clear() noexcept
{
	nodes_.clear();
	text_.clear();
	root_ = 0;
	depth_ = 0;
	elements_ = 0;
}

auto filter::view::children() const noexcept -> filter::child_range
{
	const node &x = n();
	if (!access::composite(x)) {
		return child_range(child_iterator{});
	}
	return child_range(child_iterator(f_, x.first));
}

auto filter::view::initial() const noexcept -> std::optional<std::string_view>
{
	const node &x = n();
	if (x.k != access::k(kind::substrings) || x.first == npos) {
		return std::nullopt;
	}
	const node &p = f_->nodes_[x.first];
	if (p.k != part_initial) {
		return std::nullopt;
	}
	return f_->str(p.value_off, p.value_len);
}

auto filter::view::any() const noexcept -> filter::substring_range
{
	const node &x = n();
	if (x.k != access::k(kind::substrings)) {
		return substring_range(substring_iterator{});
	}
	std::uint32_t i = x.first;
	if (i != npos && f_->nodes_[i].k == part_initial) {
		i = f_->nodes_[i].next;
	}
	if (i != npos && f_->nodes_[i].k != part_any) {
		i = npos;
	}
	return substring_range(substring_iterator(f_, i));
}

auto filter::view::final() const noexcept -> std::optional<std::string_view>
{
	const node &x = n();
	if (x.k != access::k(kind::substrings) || x.last == npos) {
		return std::nullopt;
	}
	const node &p = f_->nodes_[x.last];
	if (p.k != part_final) {
		return std::nullopt;
	}
	return f_->str(p.value_off, p.value_len);
}

auto operator==(const filter &a, const filter &b) noexcept -> bool
{
	using node = filter::node;
	if (a.empty() || b.empty()) {
		return a.empty() == b.empty();
	}
	const auto same_node = [&](const node &x, const node &y) {
		return x.k == y.k && x.dn_attributes == y.dn_attributes && access::attr_of(a, x) == access::attr_of(b, y)
			   && access::value_of(a, x) == access::value_of(b, y) && access::rule_of(a, x) == access::rule_of(b, y);
	};
	// Both trees in preorder, in lockstep, without recursion.
	std::uint32_t i = a.root_;
	std::uint32_t j = b.root_;
	while (true) {
		const node &x = a.nodes_[i];
		const node &y = b.nodes_[j];
		if (!same_node(x, y)) {
			return false;
		}
		if (x.k == access::k(filter::kind::substrings)) {
			std::uint32_t p = x.first;
			std::uint32_t q = y.first;
			for (; p != filter::npos && q != filter::npos; p = a.nodes_[p].next, q = b.nodes_[q].next) {
				if (!same_node(a.nodes_[p], b.nodes_[q])) {
					return false;
				}
			}
			if (p != q) {
				return false;// one has more parts
			}
		}
		const bool down_x = access::composite(x) && x.first != filter::npos;
		const bool down_y = access::composite(y) && y.first != filter::npos;
		if (down_x != down_y) {
			return false;
		}
		if (down_x) {
			i = x.first;
			j = y.first;
			continue;
		}
		while (true) {
			// Same shape so far, so both reach their roots together.
			if (i == a.root_) {
				return true;
			}
			const node &cx = a.nodes_[i];
			const node &cy = b.nodes_[j];
			if ((cx.next == filter::npos) != (cy.next == filter::npos)) {
				return false;
			}
			if (cx.next != filter::npos) {
				i = cx.next;
				j = cy.next;
				break;
			}
			i = cx.parent;
			j = cy.parent;
		}
	}
}

// ---------------------------------------------------------------- text

namespace {

	// RFC 4515 section 3 escaping, and every octet not part of valid UTF-8.
	void append_escaped(std::pmr::string &out, std::string_view value)
	{
		const auto escape = [&](unsigned char u) {
			out += '\\';
			detail::append_hex_octet(out, u);
		};
		for (std::size_t i = 0; i < value.size(); ++i) {
			const char c = value[i];
			const auto u = static_cast<unsigned char>(c);
			if (u >= 0x80u) {
				const std::size_t len = detail::utf8_sequence_length(value, i);
				if (len == 0) {
					escape(u);
				} else {
					out += value.substr(i, len);
					i += len - 1;
				}
				continue;
			}
			switch (c) {
			case '*':
			case '(':
			case ')':
			case '\\':
			case '\0':
				escape(u);
				break;
			default:
				out += c;
			}
		}
	}

}// namespace

auto escape_filter_value(std::string_view value, std::pmr::memory_resource *mr) -> std::pmr::string
{
	std::pmr::string out(mr);
	out.reserve(value.size());
	append_escaped(out, value);
	return out;
}

auto filter::to_string(std::pmr::memory_resource *mr) const -> std::pmr::string
{
	std::pmr::string out(mr);
	if (empty()) {
		return out;
	}
	out.reserve(text_.size() + (4 * elements_));
	access::walk(
	  *this,
	  root_,
	  [&](std::uint32_t i) {
		  const node &n = nodes_[i];
		  const std::string_view attr = str(n.attr_off, n.attr_len);
		  const std::string_view value = str(n.value_off, n.value_len);
		  out += '(';
		  switch (static_cast<kind>(n.k)) {
		  case kind::and_:
			  out += '&';
			  break;
		  case kind::or_:
			  out += '|';
			  break;
		  case kind::not_:
			  out += '!';
			  break;
		  case kind::equality:
			  out += attr;
			  out += '=';
			  append_escaped(out, value);
			  break;
		  case kind::greater_or_equal:
			  out += attr;
			  out += ">=";
			  append_escaped(out, value);
			  break;
		  case kind::less_or_equal:
			  out += attr;
			  out += "<=";
			  append_escaped(out, value);
			  break;
		  case kind::approx:
			  out += attr;
			  out += "~=";
			  append_escaped(out, value);
			  break;
		  case kind::present:
			  out += attr;
			  out += "=*";
			  break;
		  case kind::substrings:
			  out += attr;
			  out += '=';
			  for (std::uint32_t p = n.first; p != npos; p = nodes_[p].next) {
				  const node &part = nodes_[p];
				  if (part.k != part_initial) {
					  out += '*';
				  }
				  append_escaped(out, str(part.value_off, part.value_len));
			  }
			  if (n.last == npos || nodes_[n.last].k != part_final) {
				  out += '*';
			  }
			  break;
		  case kind::extensible_match:
			  out += attr;
			  if (n.dn_attributes) {
				  out += ":dn";
			  }
			  if (n.rule_len != 0) {
				  out += ':';
				  out += str(n.rule_off, n.rule_len);
			  }
			  out += ":=";
			  append_escaped(out, value);
			  break;
		  }
	  },
	  [&](std::uint32_t) { out += ')'; });
	return out;
}

// ---------------------------------------------------------------- builders

namespace filters {

	using kind = filter::kind;

	attr::attr(const attribute &name, const allocator_type &alloc) : name_(name.name(), alloc)
	{
		if (!detail::is_attribute_description(name_)) {
			throw std::invalid_argument("ldap::filters::attr: invalid attribute description");
		}
	}

	auto attr::operator==(std::string_view value) const -> filter
	{
		return access::leaf(name_.get_allocator(), kind::equality, name_, value);
	}
	auto attr::operator>=(std::string_view value) const -> filter
	{
		return access::leaf(name_.get_allocator(), kind::greater_or_equal, name_, value);
	}
	auto attr::operator<=(std::string_view value) const -> filter
	{
		return access::leaf(name_.get_allocator(), kind::less_or_equal, name_, value);
	}
	auto attr::approx(std::string_view value) const -> filter
	{
		return access::leaf(name_.get_allocator(), kind::approx, name_, value);
	}
	auto attr::present() const -> filter { return access::leaf(name_.get_allocator(), kind::present, name_); }

	auto attr::starts_with(std::string_view value) const -> filter
	{
		return access::substrings(name_.get_allocator(), name_, value, {}, {});
	}
	auto attr::ends_with(std::string_view value) const -> filter
	{
		return access::substrings(name_.get_allocator(), name_, {}, {}, value);
	}
	auto attr::contains(std::string_view value) const -> filter
	{
		return access::substrings(name_.get_allocator(), name_, {}, value, {});
	}

	namespace {
		// RFC 4515 extensible match text order (attr:rule:=value), as its two
		// callers attr::matches and rule_matches.
		// NOLINTBEGIN(bugprone-easily-swappable-parameters)
		auto extensible(const filter::allocator_type &alloc,
		  std::string_view attr,
		  std::string_view rule,
		  std::string_view value,
		  bool dn_attributes) -> filter
		// NOLINTEND(bugprone-easily-swappable-parameters)
		{
			if (!rule.empty() && !detail::is_oid(rule)) {
				throw std::invalid_argument(detail::format("ldap::filters: invalid matching rule \"{}\"", rule));
			}
			if (!dn_attributes && detail::iequals(rule, "dn")) {
				throw std::invalid_argument("ldap::filters: a matching rule named \"dn\" needs dn_attributes");
			}
			filter f = access::leaf(alloc, kind::extensible_match, attr, value);
			if (!rule.empty()) {
				access::set_rule(f, access::root(f), rule);
			}
			access::set_dn_attributes(f, access::root(f), dn_attributes);
			return f;
		}
	}// namespace

	auto attr::matches(std::string_view rule, std::string_view value, bool dn_attributes) const -> filter
	{
		return extensible(name_.get_allocator(), name_, rule, value, dn_attributes);
	}

	auto rule_matches(std::string_view rule,
	  std::string_view value,
	  bool dn_attributes,
	  const filter::allocator_type &alloc) -> filter
	{
		if (rule.empty()) {
			throw std::invalid_argument("ldap::filters::rule_matches: the matching rule is required");
		}
		return extensible(alloc, {}, rule, value, dn_attributes);
	}

}// namespace filters

auto operator&&(const filter &f, const filter &g) -> filter
{
	return access::combine(filter(f, f.get_allocator()), g, filter::kind::and_);
}
auto operator&&(filter &&f, const filter &g) -> filter
{
	if (&f == &g) {
		return static_cast<const filter &>(f) && g;// same object: copy, don't steal
	}
	return access::combine(std::move(f), g, filter::kind::and_);
}
auto operator&&(const filter &f, filter &&g) -> filter
{
	if (&f == &g) {
		return f && static_cast<const filter &>(g);
	}
	return access::combine_right(f, std::move(g), filter::kind::and_);
}
auto operator&&(filter &&f, filter &&g) -> filter
{
	if (&f == &g) {
		return static_cast<const filter &>(f) && static_cast<const filter &>(g);
	}
	return access::combine_both(std::move(f), std::move(g), filter::kind::and_);
}
auto operator||(const filter &f, const filter &g) -> filter
{
	return access::combine(filter(f, f.get_allocator()), g, filter::kind::or_);
}
auto operator||(filter &&f, const filter &g) -> filter
{
	if (&f == &g) {
		return static_cast<const filter &>(f) || g;// same object: copy, don't steal
	}
	return access::combine(std::move(f), g, filter::kind::or_);
}
auto operator||(const filter &f, filter &&g) -> filter
{
	if (&f == &g) {
		return f || static_cast<const filter &>(g);
	}
	return access::combine_right(f, std::move(g), filter::kind::or_);
}
auto operator||(filter &&f, filter &&g) -> filter
{
	if (&f == &g) {
		return static_cast<const filter &>(f) || static_cast<const filter &>(g);
	}
	return access::combine_both(std::move(f), std::move(g), filter::kind::or_);
}
auto operator!(const filter &f) -> filter { return access::negate(filter(f, f.get_allocator())); }
auto operator!(filter &&f) -> filter { return access::negate(std::move(f)); }


// ---------------------------------------------------------------- text -> tree

namespace {

	using detail::hex_value;
	using detail::is_hex;
	using detail::utf8_sequence_length;
	using kind = filter::kind;
	constexpr std::uint32_t npos = access::npos;
	constexpr std::uint8_t filter_part_initial = access::part_initial;
	constexpr std::uint8_t filter_part_any = access::part_any;
	constexpr std::uint8_t filter_part_final = access::part_final;

	// One unit of an RFC 4515 assertion value at s[i], appended with `emit`;
	// the characters read, or the error.
	template<class Emit>
	auto read_value_unit(std::string_view s, std::size_t i, const Emit &emit)
	  -> std::expected<std::size_t, std::string_view>
	{
		const char c = s[i];
		if (c == '(' || c == '\0') {
			return std::unexpected("unescaped '(' or NUL in value");
		}
		if (c == '*') {
			return std::unexpected("unescaped '*' in value");
		}
		if (c == '\\') {
			if (i + 2 >= s.size() || !is_hex(s[i + 1]) || !is_hex(s[i + 2])) {
				return std::unexpected("invalid escape (expected \\ and two hex digits)");
			}
			emit(static_cast<char>((hex_value(s[i + 1]) << 4) | hex_value(s[i + 2])));
			return 3;
		}
		if (static_cast<unsigned char>(c) < 0x80u) {
			emit(c);
			return 1;
		}
		// RFC 4515 section 3: unescaped octets are UTF-8.
		const std::size_t n = utf8_sequence_length(s, i);
		if (n == 0) {
			return std::unexpected("invalid UTF-8 in value");
		}
		for (std::size_t k = 0; k < n; ++k) {
			emit(s[i + k]);
		}
		return n;
	}

	auto is_attr_char(char c) -> bool { return detail::is_keychar(c) || c == '.' || c == ';'; }
	auto is_oid_char(char c) -> bool { return detail::is_keychar(c) || c == '.'; }

	class filter_parser
	{
	  public:
		// `shift`: 1 when the text was wrapped in parentheses.
		filter_parser(std::string_view s, std::size_t shift, const filter_limits &limits, filter &out)
		  : s_(s), shift_(shift), limits_(limits), out_(&out)
		{}

		auto parse() -> result<void>
		{
			auto root = parse_filter(1, npos);
			if (!root) {
				return std::unexpected(std::move(root.error()));
			}
			if (i_ != s_.size()) {
				return error("unexpected characters after the filter");
			}
			access::set_root(*out_, *root);
			access::set_limits(*out_, depth_, elements_);
			return {};
		}

	  private:
		[[nodiscard]] auto error(std::string_view what, std::size_t at) const -> std::unexpected<ldap::error>
		{
			const std::size_t pos = at >= shift_ ? at - shift_ : 0;
			return fail(client_errc::invalid_filter, detail::format("filter: {} at position {}", what, pos));
		}
		[[nodiscard]] auto error(std::string_view what) const -> std::unexpected<ldap::error>
		{
			return error(what, i_);
		}
		[[nodiscard]] auto too_many_elements() const -> std::unexpected<ldap::error>
		{
			return error(detail::format("too many elements (more than {})", limits_.max_elements));
		}

		[[nodiscard]] auto at_end() const -> bool { return i_ >= s_.size(); }
		[[nodiscard]] auto peek() const -> char { return s_[i_]; }

		auto expect(char c) -> result<void>
		{
			if (at_end() || peek() != c) {
				if (c == ')') {
					return error("expected ')'");
				}
				return error("expected '('");
			}
			++i_;
			return {};
		}

		auto add(kind k, std::uint32_t parent) -> std::uint32_t
		{
			const std::uint32_t n = access::add_node(*out_, access::k(k));
			if (parent != npos) {
				access::link_last(*out_, parent, n);
			}
			return n;
		}

		// Bounded recursion: depth never exceeds limits_.max_depth.
		auto parse_filter(std::size_t depth, std::uint32_t parent) -> result<std::uint32_t>
		{
			if (depth > limits_.max_depth) {
				return error(detail::format("nested too deeply (more than {} levels)", limits_.max_depth));
			}
			if (++elements_ > limits_.max_elements) {
				return too_many_elements();
			}
			depth_ = std::max(depth_, depth);
			if (auto e = expect('('); !e) {
				return std::unexpected(std::move(e.error()));
			}
			if (at_end()) {
				return error("unexpected end of filter");
			}
			std::uint32_t node = npos;
			const char c = peek();
			if (c == '&' || c == '|') {
				node = add(c == '&' ? kind::and_ : kind::or_, parent);
				++i_;
				while (!at_end() && peek() == '(') {
					auto child = parse_filter(depth + 1, node);
					if (!child) {
						return child;
					}
				}
			} else if (c == '!') {
				node = add(kind::not_, parent);
				++i_;
				auto child = parse_filter(depth + 1, node);
				if (!child) {
					return child;
				}
			} else {
				auto item = parse_item(parent);
				if (!item) {
					return item;
				}
				node = *item;
			}
			if (auto e = expect(')'); !e) {
				return std::unexpected(std::move(e.error()));
			}
			return node;
		}

		// Unescapes value bytes up to ')' (or, with `stars`, an unescaped '*');
		// returns (offset, length) in out_'s pool.
		auto read_part(bool stars) -> result<std::pair<std::uint32_t, std::uint32_t>>
		{
			const std::uint32_t off = access::add_text(*out_, {});
			std::uint32_t len = 0;
			while (true) {
				if (at_end()) {
					return error("unexpected end of filter");
				}
				const char c = peek();
				if (c == ')' || (c == '*' && stars)) {
					break;
				}
				const auto n = read_value_unit(s_, i_, [&](char byte) {
					access::add_char(*out_, byte);
					++len;
				});
				if (!n) {
					return error(n.error());
				}
				i_ += *n;
			}
			return std::pair{ off, len };
		}

		auto parse_item(std::uint32_t parent) -> result<std::uint32_t>
		{
			const std::size_t attr_start = i_;
			while (!at_end() && is_attr_char(peek())) {
				++i_;
			}
			const std::string_view attr = s_.substr(attr_start, i_ - attr_start);
			if (at_end()) {
				return error("unexpected end of filter");
			}
			if (peek() == ':') {
				return parse_extensible(attr, attr_start, parent);
			}
			if (!detail::is_attribute_description(attr)) {
				return error("invalid attribute description", attr_start);
			}

			const char c = peek();
			if (c == '~' || c == '>' || c == '<') {
				if (i_ + 1 >= s_.size() || s_[i_ + 1] != '=') {
					return error("expected '='", i_ + 1);
				}
				const kind k = [c] {
					if (c == '~') {
						return kind::approx;
					}
					if (c == '>') {
						return kind::greater_or_equal;
					}
					return kind::less_or_equal;
				}();
				i_ += 2;
				const std::uint32_t node = add(k, parent);
				access::set_attr(*out_, node, attr);
				if (auto e = set_value(node); !e) {
					return std::unexpected(std::move(e.error()));
				}
				return node;
			}
			if (c != '=') {
				return error("expected a filter type ('=', '~=', '>=', '<=' or ':=')");
			}
			++i_;
			const std::size_t value_start = i_;
			// Unescaped '*' up to the closing ')' decide the kind.
			const auto stars = std::ranges::count(s_.substr(i_, s_.find(')', i_) - i_), '*');
			if (stars == 0) {
				const std::uint32_t node = add(kind::equality, parent);
				access::set_attr(*out_, node, attr);
				if (auto e = set_value(node); !e) {
					return std::unexpected(std::move(e.error()));
				}
				return node;
			}
			if (stars == 1 && s_.substr(i_, 2) == "*)") {
				++i_;
				const std::uint32_t node = add(kind::present, parent);
				access::set_attr(*out_, node, attr);
				return node;
			}
			return parse_substrings(attr, value_start, parent);
		}

		// A substrings item from `value_start` (after '='), whose value has
		// unescaped '*' and is not just "*".
		auto parse_substrings(std::string_view attr, std::size_t value_start, std::uint32_t parent)
		  -> result<std::uint32_t>
		{
			const std::uint32_t node = add(kind::substrings, parent);
			access::set_attr(*out_, node, attr);
			bool first = true;
			bool any_part = false;
			while (true) {
				auto part = read_part(true);
				if (!part) {
					return std::unexpected(std::move(part.error()));
				}
				const bool last = peek() == ')';
				if (part->second != 0) {
					if (++elements_ > limits_.max_elements) {
						return too_many_elements();
					}
					const std::uint8_t k = [first, last] {
						if (first) {
							return filter_part_initial;
						}
						if (last) {
							return filter_part_final;
						}
						return filter_part_any;
					}();
					const std::uint32_t p = access::add_node(*out_, k);
					access::set_value_range(*out_, p, *part);
					access::link_last(*out_, node, p);
					any_part = true;
				}
				if (last) {
					break;
				}
				++i_;// '*'
				first = false;
			}
			if (!any_part) {
				return error("substring filter without any substring", value_start);
			}
			return node;
		}

		auto set_value(std::uint32_t node) -> result<void>
		{
			auto v = read_part(false);
			if (!v) {
				return std::unexpected(std::move(v.error()));
			}
			access::set_value_range(*out_, node, *v);
			return {};
		}

		// attr [":dn"] [":" rule] ":=" value, or [":dn"] ":" rule ":=" value
		auto parse_extensible(std::string_view attr, std::size_t attr_start, std::uint32_t parent)
		  -> result<std::uint32_t>
		{
			if (!attr.empty() && !detail::is_attribute_description(attr)) {
				return error("invalid attribute description", attr_start);
			}
			bool dn_attributes = false;
			std::string_view rule;
			while (true) {
				if (at_end() || peek() != ':') {
					return error("expected ':='");
				}
				++i_;
				if (!at_end() && peek() == '=') {
					++i_;
					break;
				}
				const std::size_t tok_start = i_;
				while (!at_end() && is_oid_char(peek())) {
					++i_;
				}
				const std::string_view tok = s_.substr(tok_start, i_ - tok_start);
				if (tok.empty()) {
					return error("expected 'dn', a matching rule or '='");
				}
				if (!dn_attributes && rule.empty() && detail::iequals(tok, "dn")) {
					dn_attributes = true;
				} else if (rule.empty()) {
					if (!detail::is_oid(tok)) {
						return error("invalid matching rule", tok_start);
					}
					rule = tok;
				} else {
					return error("expected ':='", tok_start);
				}
			}
			if (attr.empty() && rule.empty()) {
				return error("extensible match needs an attribute or a matching rule", attr_start);
			}
			const std::uint32_t node = add(kind::extensible_match, parent);
			access::set_attr(*out_, node, attr);
			access::set_rule(*out_, node, rule);
			access::set_dn_attributes(*out_, node, dn_attributes);
			if (auto e = set_value(node); !e) {
				return std::unexpected(std::move(e.error()));
			}
			return node;
		}

		std::string_view s_;
		std::size_t shift_;
		filter_limits limits_;
		filter *out_;// non-null
		std::size_t i_ = 0;
		std::size_t elements_ = 0;
		std::size_t depth_ = 0;
	};

}// namespace

auto filter::raw(std::string_view text, std::pmr::memory_resource *mr) -> result<filter> { return raw(text, {}, mr); }

auto filter::raw(std::string_view text, const filter_limits &limits, std::pmr::memory_resource *mr) -> result<filter>
{
	filter out{ allocator_type(mr) };
	if (!text.empty() && text.front() == '(') {
		if (auto r = filter_parser(text, 0, limits, out).parse(); !r) {
			return std::unexpected(std::move(r.error()));
		}
		return out;
	}
	std::pmr::string wrapped(mr);
	wrapped.reserve(text.size() + 2);
	wrapped += '(';
	wrapped += text;
	wrapped += ')';
	if (auto r = filter_parser(wrapped, 1, limits, out).parse(); !r) {
		return std::unexpected(std::move(r.error()));
	}
	return out;
}

auto unescape_filter_value(std::string_view text, std::pmr::memory_resource *mr) -> result<std::pmr::string>
{
	std::pmr::string out(mr);
	out.reserve(text.size());
	const auto error = [&](std::string_view what, std::size_t at) {
		return fail(client_errc::invalid_filter, detail::format("filter value: {} at position {}", what, at));
	};
	for (std::size_t i = 0; i < text.size();) {
		if (text[i] == ')') {
			return error("unescaped ')' in value", i);
		}
		const auto n = read_value_unit(text, i, [&](char byte) { out += byte; });
		if (!n) {
			return error(n.error(), i);
		}
		i += *n;
	}
	return out;
}

// ---------------------------------------------------------------- tree -> BER

namespace {

	// The Filter CHOICE's context tag numbers (RFC 4511 section 4.5.1).
	namespace filter_choice {
		constexpr std::uint8_t and_ = 0;
		constexpr std::uint8_t or_ = 1;
		constexpr std::uint8_t not_ = 2;
		constexpr std::uint8_t equality_match = 3;
		constexpr std::uint8_t substrings = 4;
		constexpr std::uint8_t greater_or_equal = 5;
		constexpr std::uint8_t less_or_equal = 6;
		constexpr std::uint8_t present = 7;
		constexpr std::uint8_t approx_match = 8;
		constexpr std::uint8_t extensible_match = 9;
	}// namespace filter_choice

}// namespace

namespace detail {

	auto check_filter(const filter &f, const filter_limits &limits) -> result<void>
	{
		if (f.empty()) {
			return fail(client_errc::invalid_filter, "filter: empty");
		}
		if (f.depth() > limits.max_depth) {
			return fail(client_errc::invalid_filter,
			  detail::format("filter: nested too deeply ({} levels, at most {})", f.depth(), limits.max_depth));
		}
		if (f.elements() > limits.max_elements) {
			return fail(client_errc::invalid_filter,
			  detail::format("filter: too many elements ({}, at most {})", f.elements(), limits.max_elements));
		}
		return {};
	}

	namespace {

		// Recursion depth is the filter's depth, checked by check_filter.
		void write_node(ber::writer &w, const filter &f, std::uint32_t i)
		{
			const auto &n = access::at(f, i);
			const std::string_view attr = access::attr_of(f, n);
			const auto ava = [&](std::uint8_t number) {
				w.constructed(ber::context(number), [&](ber::writer &c) {
					c.octet_string(attr);
					c.octet_string(access::value_of(f, n));
				});
			};
			switch (static_cast<filter::kind>(n.k)) {
			case filter::kind::and_:
			case filter::kind::or_:
				w.constructed(
				  ber::context(n.k == access::k(filter::kind::and_) ? filter_choice::and_ : filter_choice::or_),
				  [&](ber::writer &c) {
					  for (std::uint32_t child = n.first; child != npos; child = access::at(f, child).next) {
						  write_node(c, f, child);
					  }
				  });
				return;
			case filter::kind::not_:
				w.constructed(ber::context(filter_choice::not_), [&](ber::writer &c) { write_node(c, f, n.first); });
				return;
			case filter::kind::equality:
				ava(filter_choice::equality_match);
				return;
			case filter::kind::substrings:
				w.constructed(ber::context(filter_choice::substrings), [&](ber::writer &c) {
					c.octet_string(attr);
					c.constructed(ber::tags::sequence, [&](ber::writer &s) {
						for (std::uint32_t p = n.first; p != npos; p = access::at(f, p).next) {
							const auto &part = access::at(f, p);
							const auto number = [&part] -> std::uint8_t {
								if (part.k == filter_part_initial) {
									return 0;
								}
								if (part.k == filter_part_any) {
									return 1;
								}
								return 2;
							}();
							s.octet_string(access::value_of(f, part), ber::context(number));
						}
					});
				});
				return;
			case filter::kind::greater_or_equal:
				ava(filter_choice::greater_or_equal);
				return;
			case filter::kind::less_or_equal:
				ava(filter_choice::less_or_equal);
				return;
			case filter::kind::present:
				w.octet_string(attr, ber::context(filter_choice::present));
				return;
			case filter::kind::approx:
				ava(filter_choice::approx_match);
				return;
			case filter::kind::extensible_match:
				w.constructed(ber::context(filter_choice::extensible_match), [&](ber::writer &c) {
					const std::string_view rule = access::rule_of(f, n);
					if (!rule.empty()) {
						c.octet_string(rule, ber::context(1));
					}
					if (!attr.empty()) {
						c.octet_string(attr, ber::context(2));
					}
					c.octet_string(access::value_of(f, n), ber::context(3));
					if (n.dn_attributes) {
						c.boolean(true, ber::context(4));// DEFAULT FALSE: omitted when false
					}
				});
				return;
			}
		}

	}// namespace

	void write_filter(ber::writer &w, const filter &f) { write_node(w, f, access::root(f)); }

}// namespace detail

auto encode_filter(ber::writer &w, const filter &f, const filter_limits &limits) -> result<void>
{
	if (auto r = detail::check_filter(f, limits); !r) {
		return r;
	}
	detail::write_filter(w, f);
	return {};
}

// ---------------------------------------------------------------- BER -> tree

namespace {

	using detail::next_is;
	using detail::skip_rest;

	auto bad(std::string_view what, std::size_t offset) -> std::unexpected<error>
	{
		return fail(client_errc::decode_error, detail::format("filter: {} at offset {}", what, offset));
	}

	class filter_decoder
	{
	  public:
		filter_decoder(const filter_limits &limits, filter &out) : limits_(limits), out_(&out) {}

		auto decode(ber::reader &r) -> result<void>
		{
			auto root = node(r, 1, npos);
			if (!root) {
				return std::unexpected(std::move(root.error()));
			}
			access::set_root(*out_, *root);
			access::set_limits(*out_, depth_, elements_);
			return {};
		}

	  private:
		auto add(kind k, std::uint32_t parent) -> std::uint32_t
		{
			const std::uint32_t n = access::add_node(*out_, access::k(k));
			if (parent != npos) {
				access::link_last(*out_, parent, n);
			}
			return n;
		}

		static auto read_attr(ber::reader &r, ber::tag t = ber::tags::octet_string) -> result<std::string_view>
		{
			const std::size_t at = r.offset();
			auto s = r.read_octet_string(t);
			if (!s) {
				return std::unexpected(std::move(s.error()));
			}
			const auto text = detail::as_text(*s);
			if (!detail::is_attribute_description(text)) {
				return bad("invalid attribute description", at);
			}
			return text;
		}

		auto ava(ber::reader &r, ber::tag t, kind k, std::uint32_t parent) -> result<std::uint32_t>
		{
			auto sub = r.enter(t);
			if (!sub) {
				return std::unexpected(std::move(sub.error()));
			}
			auto a = read_attr(*sub);
			if (!a) {
				return std::unexpected(std::move(a.error()));
			}
			auto v = sub->read_octet_string();
			if (!v) {
				return std::unexpected(std::move(v.error()));
			}
			if (auto e = skip_rest(*sub); !e) {
				return std::unexpected(std::move(e.error()));
			}
			const std::uint32_t n = add(k, parent);
			access::set_attr(*out_, n, *a);
			access::set_value(*out_, n, detail::as_text(*v));
			return n;
		}

		auto substrings(ber::reader &r, ber::tag t, std::uint32_t parent) -> result<std::uint32_t>
		{
			const std::size_t at = r.offset();
			auto sub = r.enter(t);
			if (!sub) {
				return std::unexpected(std::move(sub.error()));
			}
			auto a = read_attr(*sub);
			if (!a) {
				return std::unexpected(std::move(a.error()));
			}
			auto seq = sub->enter();
			if (!seq) {
				return std::unexpected(std::move(seq.error()));
			}
			const std::uint32_t n = add(kind::substrings, parent);
			access::set_attr(*out_, n, *a);
			bool first = true;
			bool final_seen = false;
			while (!seq->empty()) {
				const std::size_t item_at = seq->offset();
				auto st = seq->peek_tag();
				if (!st) {
					return std::unexpected(std::move(st.error()));
				}
				if (st->cls != ber::tag_class::context || st->number > 2) {
					return bad("unknown substring choice", item_at);
				}
				if (final_seen) {
					return bad("substring after 'final'", item_at);
				}
				auto s = seq->read_octet_string(*st);
				if (!s) {
					return std::unexpected(std::move(s.error()));
				}
				if (s->empty()) {
					return bad("empty substring", item_at);
				}
				std::uint8_t k = filter_part_any;
				if (st->number == 0) {
					if (!first) {
						return bad("'initial' is not the first substring", item_at);
					}
					k = filter_part_initial;
				} else if (st->number == 2) {
					k = filter_part_final;
					final_seen = true;
				}
				if (++elements_ > limits_.max_elements) {
					return bad(detail::format("more than {} filter elements", limits_.max_elements), item_at);
				}
				const std::uint32_t p = access::add_node(*out_, k);
				access::set_value(*out_, p, detail::as_text(*s));
				access::link_last(*out_, n, p);
				first = false;
			}
			if (first) {
				return bad("substring filter without substrings", at);
			}
			if (auto e = skip_rest(*sub); !e) {
				return std::unexpected(std::move(e.error()));
			}
			return n;
		}

		auto extensible(ber::reader &r, ber::tag t, std::uint32_t parent) -> result<std::uint32_t>
		{
			const std::size_t at = r.offset();
			auto sub = r.enter(t);
			if (!sub) {
				return std::unexpected(std::move(sub.error()));
			}
			std::string_view rule;
			std::string_view type;
			bool dn_attributes = false;
			if (next_is(*sub, ber::context(1))) {
				const std::size_t rule_at = sub->offset();
				auto s = sub->read_octet_string(ber::context(1));
				if (!s) {
					return std::unexpected(std::move(s.error()));
				}
				rule = detail::as_text(*s);
				if (!detail::is_oid(rule)) {
					return bad("invalid matching rule", rule_at);
				}
			}
			if (next_is(*sub, ber::context(2))) {
				auto s = read_attr(*sub, ber::context(2));
				if (!s) {
					return std::unexpected(std::move(s.error()));
				}
				type = *s;
			}
			auto v = sub->read_octet_string(ber::context(3));
			if (!v) {
				return std::unexpected(std::move(v.error()));
			}
			if (next_is(*sub, ber::context(4))) {
				auto b = sub->read_boolean(ber::context(4));
				if (!b) {
					return std::unexpected(std::move(b.error()));
				}
				dn_attributes = *b;
			}
			if (auto e = skip_rest(*sub); !e) {
				return std::unexpected(std::move(e.error()));
			}
			if (rule.empty() && type.empty()) {
				return bad("extensible match without type or matching rule", at);
			}
			// "(a:dn:=v)" means dnAttributes, so a rule named "dn" is only
			// expressible together with dnAttributes ("(a:dn:dn:=v)").
			if (!dn_attributes && detail::iequals(rule, "dn")) {
				return bad("matching rule 'dn' without dnAttributes has no RFC 4515 form", at);
			}
			const std::uint32_t n = add(kind::extensible_match, parent);
			access::set_attr(*out_, n, type);
			access::set_rule(*out_, n, rule);
			access::set_value(*out_, n, detail::as_text(*v));
			access::set_dn_attributes(*out_, n, dn_attributes);
			return n;
		}

		// Bounded recursion: depth never exceeds limits_.max_depth. The
		// element count is checked before anything is allocated for the element.
		auto node(ber::reader &r, std::size_t depth, std::uint32_t parent) -> result<std::uint32_t>
		{
			const std::size_t at = r.offset();
			if (depth > limits_.max_depth) {
				return fail(client_errc::nesting_too_deep,
				  detail::format("filter: more than {} levels at offset {}", limits_.max_depth, at));
			}
			if (++elements_ > limits_.max_elements) {
				return bad(detail::format("more than {} filter elements", limits_.max_elements), at);
			}
			depth_ = std::max(depth_, depth);
			auto t = r.peek_tag();
			if (!t) {
				return std::unexpected(std::move(t.error()));
			}
			if (t->cls != ber::tag_class::context) {
				return fail(client_errc::unexpected_tag,
				  detail::format("filter: unknown filter choice {} at offset {}", ber::to_string(*t), at));
			}
			switch (t->number) {
			case filter_choice::and_:
			case filter_choice::or_:
			case filter_choice::not_: {
				auto sub = r.enter(*t);
				if (!sub) {
					return std::unexpected(std::move(sub.error()));
				}
				const kind k = [number = t->number] {
					if (number == filter_choice::and_) {
						return kind::and_;
					}
					if (number == filter_choice::or_) {
						return kind::or_;
					}
					return kind::not_;
				}();
				const std::uint32_t n = add(k, parent);
				if (k == kind::not_) {
					auto child = node(*sub, depth + 1, n);
					if (!child) {
						return child;
					}
					if (auto e = sub->expect_end(); !e) {
						return std::unexpected(std::move(e.error()));
					}
				} else {
					while (!sub->empty()) {
						auto child = node(*sub, depth + 1, n);
						if (!child) {
							return child;
						}
					}
				}
				return n;
			}
			case filter_choice::equality_match:
				return ava(r, *t, kind::equality, parent);
			case filter_choice::substrings:
				return substrings(r, *t, parent);
			case filter_choice::greater_or_equal:
				return ava(r, *t, kind::greater_or_equal, parent);
			case filter_choice::less_or_equal:
				return ava(r, *t, kind::less_or_equal, parent);
			case filter_choice::present: {
				auto a = read_attr(r, *t);
				if (!a) {
					return std::unexpected(std::move(a.error()));
				}
				const std::uint32_t n = add(kind::present, parent);
				access::set_attr(*out_, n, *a);
				return n;
			}
			case filter_choice::approx_match:
				return ava(r, *t, kind::approx, parent);
			case filter_choice::extensible_match:
				return extensible(r, *t, parent);
			default:
				return fail(client_errc::unexpected_tag,
				  detail::format("filter: unknown filter choice {} at offset {}", ber::to_string(*t), at));
			}
		}

		filter_limits limits_;
		filter *out_;// non-null
		std::size_t elements_ = 0;
		std::size_t depth_ = 0;
	};

}// namespace

auto decode_filter(ber::reader &r, const filter_limits &limits, std::pmr::memory_resource *mr) -> result<filter>
{
	ber::reader copy = r;
	filter out{ filter::allocator_type(mr) };
	if (auto e = filter_decoder(limits, out).decode(copy); !e) {
		return std::unexpected(std::move(e.error()));
	}
	r = copy;
	return out;
}

}// namespace jhetz::ldap
