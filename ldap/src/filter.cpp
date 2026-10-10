#include "jhetz/ldap/filter.hpp"

#include "filter_ast.hpp"

#include <algorithm>
#include <limits>
#include <span>
#include <stdexcept>
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

		static constexpr std::uint8_t k(kind x) noexcept { return static_cast<std::uint8_t>(x); }

		// and / or / not: the nodes whose children are elements.
		static bool composite(const node &n) noexcept { return n.k <= k(kind::not_); }

		static std::size_t size(const filter &f) noexcept { return f.nodes_.size(); }

		// Appends `s` to the string pool and returns its offset.
		static std::uint32_t add_text(filter &f, std::string_view s)
		{
			// Offsets are 32-bit to keep nodes small. A filter with 4 GiB of
			// values cannot be sent anyway; treat it like exceeding max_size().
			if (s.size() > std::numeric_limits<std::uint32_t>::max() - f.text_.size())
				throw std::length_error("ldap::filter: more than 4 GiB of values");
			const auto off = static_cast<std::uint32_t>(f.text_.size());
			f.text_.append(s);
			return off;
		}

		static std::uint32_t add_node(filter &f, std::uint8_t node_kind)
		{
			if (f.nodes_.size() >= npos) throw std::length_error("ldap::filter: too many nodes");
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
			if (f.text_.size() >= std::numeric_limits<std::uint32_t>::max())
				throw std::length_error("ldap::filter: more than 4 GiB of values");
			f.text_ += c;
		}

		// Value of node i from a range already in the pool.
		static void set_value_range(filter &f, std::uint32_t i, std::uint32_t off, std::uint32_t len) noexcept
		{
			f.nodes_[i].value_off = off;
			f.nodes_[i].value_len = len;
		}

		static void set_dn_attributes(filter &f, std::uint32_t i, bool on) noexcept { f.nodes_[i].dn_attributes = on; }

		// Makes `child` the last child of `parent`.
		static void link_last(filter &f, std::uint32_t parent, std::uint32_t child) noexcept
		{
			node &c = f.nodes_[child];
			node &p = f.nodes_[parent];
			c.parent = parent;
			c.next = npos;
			if (p.last == npos)
				p.first = child;
			else
				f.nodes_[p.last].next = child;
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
			if (c.next == npos) p.last = child;
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
		static filter
		  leaf(const filter::allocator_type &alloc, kind node_kind, std::string_view attr, std::string_view value = {})
		{
			filter f(alloc);
			f.root_ = add_node(f, k(node_kind));
			set_attr(f, f.root_, attr);
			if (!value.empty()) set_value(f, f.root_, value);
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

		// Visits the elements of the subtree at `top` in preorder without
		// recursion: enter(i) before the children of i, leave(i) after them.
		// Substring parts are not visited (they belong to their node).
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
					if (i == top) return;
					const node &c = f.nodes_[i];
					if (c.next != npos) {
						i = c.next;
						break;
					}
					i = c.parent;
				}
			}
		}

		// Copies the subtree of `src` at `top` into `dst` (not linked; returns
		// its index). `base`: where src's string pool starts in dst's.
		static std::uint32_t copy_subtree(filter &dst, const filter &src, std::uint32_t top, std::uint32_t base)
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
				  if (i == top)
					  result = m;
				  else
					  link_last(dst, parent, m);
				  if (n.k == k(kind::substrings))
					  for (std::uint32_t p = n.first; p != npos; p = src.nodes_[p].next)
						  link_last(dst, m, copy_node(src.nodes_[p]));
				  else if (composite(n) && n.first != npos)
					  parent = m;
			  },
			  [&](std::uint32_t i) {
				  const node &n = src.nodes_[i];
				  if (composite(n) && n.first != npos) parent = dst.nodes_[parent].parent;
			  });
			return result;
		}

		// f `op` g, reusing f. An AND (resp. OR) root of either operand is
		// merged into the result.
		static filter combine(filter f, const filter &g, kind op)
		{
			if (f.empty() || g.empty()) return filter(f.get_allocator());
			if (f.nodes_[f.root_].k != k(op)) wrap(f, op);
			const std::uint32_t root = f.root_;
			const std::uint32_t base = add_text(f, g.text_);
			const node &groot = g.nodes_[g.root_];
			if (groot.k == k(op)) {
				for (std::uint32_t c = groot.first; c != npos; c = g.nodes_[c].next)
					link_last(f, root, copy_subtree(f, g, c, base));
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
		static filter combine_front(const filter &f, filter g, kind op)
		{
			if (f.empty() || g.empty()) return filter(g.get_allocator());
			if (g.nodes_[g.root_].k != k(op)) wrap(g, op);
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
		static filter combine_right(const filter &f, filter &&g, kind op)
		{
			if (f.get_allocator() == g.get_allocator()) return combine_front(f, std::move(g), op);
			return combine(filter(f, f.get_allocator()), g, op);
		}

		// Both rvalues: the larger one is reused (so chains nested either way
		// stay linear), g only when it is on f's resource.
		static filter combine_both(filter &&f, filter &&g, kind op)
		{
			if (g.nodes_.size() > f.nodes_.size() && f.get_allocator() == g.get_allocator())
				return combine_front(f, std::move(g), op);
			return combine(std::move(f), g, op);
		}

		// (a=initial*any*...*final); empty parts are omitted, all empty gives
		// present (callers pass at least one non-empty part otherwise).
		static filter substrings(const filter::allocator_type &alloc,
		  std::string_view attr,
		  std::string_view initial,
		  std::string_view any,
		  std::string_view final_)
		{
			if (initial.empty() && any.empty() && final_.empty()) return leaf(alloc, kind::present, attr);
			filter f = leaf(alloc, kind::substrings, attr);
			if (!initial.empty()) add_part(f, f.root_, filter::part_initial, initial);
			if (!any.empty()) add_part(f, f.root_, filter::part_any, any);
			if (!final_.empty()) add_part(f, f.root_, filter::part_final, final_);
			f.elements_ +=
			  std::size_t{ !initial.empty() } + std::size_t{ !any.empty() } + std::size_t{ !final_.empty() };
			return f;
		}

		static filter negate(filter f)
		{
			if (!f.empty()) wrap(f, kind::not_);
			return f;
		}

		static void set_limits(filter &f, std::size_t depth, std::size_t elements) noexcept
		{
			f.depth_ = depth;
			f.elements_ = elements;
		}
		static void set_root(filter &f, std::uint32_t root) noexcept { f.root_ = root; }
		static const node &at(const filter &f, std::uint32_t i) noexcept { return f.nodes_[i]; }
		static std::string_view attr_of(const filter &f, const node &n) noexcept
		{
			return f.str(n.attr_off, n.attr_len);
		}
		static std::string_view value_of(const filter &f, const node &n) noexcept
		{
			return f.str(n.value_off, n.value_len);
		}
		static std::string_view rule_of(const filter &f, const node &n) noexcept
		{
			return f.str(n.rule_off, n.rule_len);
		}
		static std::uint32_t root(const filter &f) noexcept { return f.root_; }
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

filter &filter::operator=(filter &&other)
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

filter::child_range filter::view::children() const noexcept
{
	const node &x = n();
	if (!access::composite(x)) return child_range(child_iterator{});
	return child_range(child_iterator(f_, x.first));
}

std::optional<std::string_view> filter::view::initial() const noexcept
{
	const node &x = n();
	if (x.k != access::k(kind::substrings) || x.first == npos) return std::nullopt;
	const node &p = f_->nodes_[x.first];
	if (p.k != part_initial) return std::nullopt;
	return f_->str(p.value_off, p.value_len);
}

filter::substring_range filter::view::any() const noexcept
{
	const node &x = n();
	if (x.k != access::k(kind::substrings)) return substring_range(substring_iterator{});
	std::uint32_t i = x.first;
	if (i != npos && f_->nodes_[i].k == part_initial) i = f_->nodes_[i].next;
	if (i != npos && f_->nodes_[i].k != part_any) i = npos;
	return substring_range(substring_iterator(f_, i));
}

std::optional<std::string_view> filter::view::final() const noexcept
{
	const node &x = n();
	if (x.k != access::k(kind::substrings) || x.last == npos) return std::nullopt;
	const node &p = f_->nodes_[x.last];
	if (p.k != part_final) return std::nullopt;
	return f_->str(p.value_off, p.value_len);
}

bool operator==(const filter &a, const filter &b) noexcept
{
	using node = filter::node;
	if (a.empty() || b.empty()) return a.empty() == b.empty();
	auto same_node = [&](const node &x, const node &y) {
		return x.k == y.k && x.dn_attributes == y.dn_attributes && access::attr_of(a, x) == access::attr_of(b, y)
			   && access::value_of(a, x) == access::value_of(b, y) && access::rule_of(a, x) == access::rule_of(b, y);
	};
	// Both trees in preorder, in lockstep, without recursion.
	std::uint32_t i = a.root_;
	std::uint32_t j = b.root_;
	while (true) {
		const node &x = a.nodes_[i];
		const node &y = b.nodes_[j];
		if (!same_node(x, y)) return false;
		if (x.k == access::k(filter::kind::substrings)) {
			std::uint32_t p = x.first;
			std::uint32_t q = y.first;
			for (; p != filter::npos && q != filter::npos; p = a.nodes_[p].next, q = b.nodes_[q].next)
				if (!same_node(a.nodes_[p], b.nodes_[q])) return false;
			if (p != q) return false;// one has more parts
		}
		const bool down_x = access::composite(x) && x.first != filter::npos;
		const bool down_y = access::composite(y) && y.first != filter::npos;
		if (down_x != down_y) return false;
		if (down_x) {
			i = x.first;
			j = y.first;
			continue;
		}
		while (true) {
			// Same shape so far, so both reach their roots together.
			if (i == a.root_) return true;
			const node &cx = a.nodes_[i];
			const node &cy = b.nodes_[j];
			if ((cx.next == filter::npos) != (cy.next == filter::npos)) return false;
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

	// RFC 4515 section 3: `*`, `(`, `)`, `\` and NUL are escaped as \XX, and
	// so is every octet that is not part of valid UTF-8 (the string form is
	// UTF-8).
	void append_escaped(std::pmr::string &out, std::string_view value)
	{
		static constexpr char digits[] = "0123456789abcdef";
		auto escape = [&](unsigned char u) {
			out += '\\';
			out += digits[u >> 4];
			out += digits[u & 0xFu];
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

std::pmr::string escape_filter_value(std::string_view value, std::pmr::memory_resource *mr)
{
	std::pmr::string out(mr);
	out.reserve(value.size());
	append_escaped(out, value);
	return out;
}

std::pmr::string filter::to_string(std::pmr::memory_resource *mr) const
{
	std::pmr::string out(mr);
	if (empty()) return out;
	out.reserve(text_.size() + 4 * elements_);
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
				  if (part.k != part_initial) out += '*';
				  append_escaped(out, str(part.value_off, part.value_len));
			  }
			  if (n.last == npos || nodes_[n.last].k != part_final) out += '*';
			  break;
		  case kind::extensible_match:
			  out += attr;
			  if (n.dn_attributes) out += ":dn";
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
		if (!detail::is_attribute_description(name_))
			throw std::invalid_argument("ldap::filters::attr: invalid attribute description");
	}

	filter attr::operator==(std::string_view value) const
	{
		return access::leaf(name_.get_allocator(), kind::equality, name_, value);
	}
	filter attr::operator>=(std::string_view value) const
	{
		return access::leaf(name_.get_allocator(), kind::greater_or_equal, name_, value);
	}
	filter attr::operator<=(std::string_view value) const
	{
		return access::leaf(name_.get_allocator(), kind::less_or_equal, name_, value);
	}
	filter attr::approx(std::string_view value) const
	{
		return access::leaf(name_.get_allocator(), kind::approx, name_, value);
	}
	filter attr::present() const { return access::leaf(name_.get_allocator(), kind::present, name_); }

	filter attr::starts_with(std::string_view value) const
	{
		return access::substrings(name_.get_allocator(), name_, value, {}, {});
	}
	filter attr::ends_with(std::string_view value) const
	{
		return access::substrings(name_.get_allocator(), name_, {}, {}, value);
	}
	filter attr::contains(std::string_view value) const
	{
		return access::substrings(name_.get_allocator(), name_, {}, value, {});
	}

	namespace {
		filter extensible(const filter::allocator_type &alloc,
		  std::string_view attr,
		  std::string_view rule,
		  std::string_view value,
		  bool dn_attributes)
		{
			if (!rule.empty() && !detail::is_oid(rule))
				throw std::invalid_argument("ldap::filters: invalid matching rule \"" + std::string(rule) + "\"");
			if (!dn_attributes && detail::iequals(rule, "dn"))
				throw std::invalid_argument("ldap::filters: a matching rule named \"dn\" needs dn_attributes");
			filter f = access::leaf(alloc, kind::extensible_match, attr, value);
			if (!rule.empty()) access::set_rule(f, access::root(f), rule);
			access::set_dn_attributes(f, access::root(f), dn_attributes);
			return f;
		}
	}// namespace

	filter attr::matches(std::string_view rule, std::string_view value, bool dn_attributes) const
	{
		return extensible(name_.get_allocator(), name_, rule, value, dn_attributes);
	}

	filter rule_matches(std::string_view rule,
	  std::string_view value,
	  bool dn_attributes,
	  const filter::allocator_type &alloc)
	{
		if (rule.empty()) throw std::invalid_argument("ldap::filters::rule_matches: the matching rule is required");
		return extensible(alloc, {}, rule, value, dn_attributes);
	}

}// namespace filters

filter operator&&(const filter &f, const filter &g)
{
	return access::combine(filter(f, f.get_allocator()), g, filter::kind::and_);
}
filter operator&&(filter &&f, const filter &g)
{
	if (&f == &g) return static_cast<const filter &>(f) && g;// same object: copy, don't steal
	return access::combine(std::move(f), g, filter::kind::and_);
}
filter operator&&(const filter &f, filter &&g)
{
	if (&f == &g) return f && static_cast<const filter &>(g);
	return access::combine_right(f, std::move(g), filter::kind::and_);
}
filter operator&&(filter &&f, filter &&g)
{
	if (&f == &g) return static_cast<const filter &>(f) && static_cast<const filter &>(g);
	return access::combine_both(std::move(f), std::move(g), filter::kind::and_);
}
filter operator||(const filter &f, const filter &g)
{
	return access::combine(filter(f, f.get_allocator()), g, filter::kind::or_);
}
filter operator||(filter &&f, const filter &g)
{
	if (&f == &g) return static_cast<const filter &>(f) || g;// same object: copy, don't steal
	return access::combine(std::move(f), g, filter::kind::or_);
}
filter operator||(const filter &f, filter &&g)
{
	if (&f == &g) return f || static_cast<const filter &>(g);
	return access::combine_right(f, std::move(g), filter::kind::or_);
}
filter operator||(filter &&f, filter &&g)
{
	if (&f == &g) return static_cast<const filter &>(f) || static_cast<const filter &>(g);
	return access::combine_both(std::move(f), std::move(g), filter::kind::or_);
}
filter operator!(const filter &f) { return access::negate(filter(f, f.get_allocator())); }
filter operator!(filter &&f) { return access::negate(std::move(f)); }


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

	bool is_attr_char(char c) { return detail::is_keychar(c) || c == '.' || c == ';'; }
	bool is_oid_char(char c) { return detail::is_keychar(c) || c == '.'; }

	class filter_parser
	{
	  public:
		// `shift`: 1 when the text was wrapped in parentheses, so positions
		// in errors refer to the caller's text.
		filter_parser(std::string_view s, std::size_t shift, const filter_limits &limits, filter &out)
		  : s_(s), shift_(shift), limits_(limits), out_(out)
		{}

		result<void> parse()
		{
			auto root = parse_filter(1, npos);
			if (!root) return std::unexpected(std::move(root.error()));
			if (i_ != s_.size()) return error("unexpected characters after the filter");
			access::set_root(out_, *root);
			access::set_limits(out_, depth_, elements_);
			return {};
		}

	  private:
		std::unexpected<ldap::error> error(const char *what, std::size_t at) const
		{
			const std::size_t pos = at >= shift_ ? at - shift_ : 0;
			return fail(
			  client_errc::invalid_filter, std::string("filter: ") + what + " at position " + std::to_string(pos));
		}
		std::unexpected<ldap::error> error(const char *what) const { return error(what, i_); }

		bool at_end() const { return i_ >= s_.size(); }
		char peek() const { return s_[i_]; }

		result<void> expect(char c)
		{
			if (at_end() || peek() != c) {
				if (c == ')') return error("expected ')'");
				return error("expected '('");
			}
			++i_;
			return {};
		}

		std::uint32_t add(kind k, std::uint32_t parent)
		{
			const std::uint32_t n = access::add_node(out_, access::k(k));
			if (parent != npos) access::link_last(out_, parent, n);
			return n;
		}

		// Bounded recursion: depth never exceeds limits_.max_depth.
		result<std::uint32_t> parse_filter(std::size_t depth, std::uint32_t parent)
		{
			if (depth > limits_.max_depth) return error("filter nested too deeply");
			if (++elements_ > limits_.max_elements) return error("filter has too many elements");
			depth_ = std::max(depth_, depth);
			if (auto e = expect('('); !e) return std::unexpected(std::move(e.error()));
			if (at_end()) return error("unexpected end of filter");
			std::uint32_t node = npos;
			const char c = peek();
			if (c == '&' || c == '|') {
				node = add(c == '&' ? kind::and_ : kind::or_, parent);
				++i_;
				while (!at_end() && peek() == '(') {
					auto child = parse_filter(depth + 1, node);
					if (!child) return child;
				}
			} else if (c == '!') {
				node = add(kind::not_, parent);
				++i_;
				auto child = parse_filter(depth + 1, node);
				if (!child) return child;
			} else {
				auto item = parse_item(parent);
				if (!item) return item;
				node = *item;
			}
			if (auto e = expect(')'); !e) return std::unexpected(std::move(e.error()));
			return node;
		}

		// Unescapes value bytes up to the closing ')' (or, with `stars`, an
		// unescaped '*'), which is not consumed, into a string of out_.
		// Returns (offset, length).
		result<std::pair<std::uint32_t, std::uint32_t>> read_part(bool stars)
		{
			const std::uint32_t off = access::add_text(out_, {});
			std::uint32_t len = 0;
			while (true) {
				if (at_end()) return error("unexpected end of filter");
				const char c = peek();
				if (c == ')') break;
				if (c == '(' || c == '\0') return error("unescaped '(' or NUL in value");
				if (c == '*') {
					if (!stars) return error("unescaped '*' in value");
					break;
				}
				char byte = c;
				if (c == '\\') {
					if (i_ + 2 >= s_.size() || !is_hex(s_[i_ + 1]) || !is_hex(s_[i_ + 2]))
						return error("invalid escape (expected \\ and two hex digits)");
					byte = static_cast<char>((hex_value(s_[i_ + 1]) << 4) | hex_value(s_[i_ + 2]));
					i_ += 3;
				} else if (static_cast<unsigned char>(c) >= 0x80u) {
					// RFC 4515 section 3: unescaped octets are UTF-8.
					const std::size_t n = utf8_sequence_length(s_, i_);
					if (n == 0) return error("invalid UTF-8 in value");
					for (std::size_t k = 0; k < n; ++k) access::add_char(out_, s_[i_ + k]);
					i_ += n;
					len += static_cast<std::uint32_t>(n);
					continue;
				} else {
					++i_;
				}
				access::add_char(out_, byte);
				++len;
			}
			return std::pair{ off, len };
		}

		result<std::uint32_t> parse_item(std::uint32_t parent)
		{
			const std::size_t attr_start = i_;
			while (!at_end() && is_attr_char(peek())) ++i_;
			const std::string_view attr = s_.substr(attr_start, i_ - attr_start);
			if (at_end()) return error("unexpected end of filter");
			if (peek() == ':') return parse_extensible(attr, attr_start, parent);
			if (!detail::is_attribute_description(attr)) return error("invalid attribute description", attr_start);

			const char c = peek();
			if (c == '~' || c == '>' || c == '<') {
				if (i_ + 1 >= s_.size() || s_[i_ + 1] != '=') return error("expected '='", i_ + 1);
				const kind k = c == '~' ? kind::approx : c == '>' ? kind::greater_or_equal : kind::less_or_equal;
				i_ += 2;
				const std::uint32_t node = add(k, parent);
				access::set_attr(out_, node, attr);
				if (auto e = set_value(node); !e) return std::unexpected(std::move(e.error()));
				return node;
			}
			if (c != '=') return error("expected a filter type ('=', '~=', '>=', '<=' or ':=')");
			++i_;
			const std::size_t value_start = i_;
			// Unescaped '*' up to the closing ')' decide the kind. Escapes are
			// `\` and two hex digits, so they never hide a '*' or ')'; text
			// with a bad escape fails below, whatever the count.
			std::size_t stars = 0;
			for (std::size_t j = i_; j < s_.size() && s_[j] != ')'; ++j)
				if (s_[j] == '*') ++stars;
			if (stars == 0) {
				const std::uint32_t node = add(kind::equality, parent);
				access::set_attr(out_, node, attr);
				if (auto e = set_value(node); !e) return std::unexpected(std::move(e.error()));
				return node;
			}
			if (stars == 1 && s_.substr(i_, 2) == "*)") {
				++i_;
				const std::uint32_t node = add(kind::present, parent);
				access::set_attr(out_, node, attr);
				return node;
			}
			const std::uint32_t node = add(kind::substrings, parent);
			access::set_attr(out_, node, attr);
			bool first = true;
			bool any_part = false;
			while (true) {
				auto part = read_part(true);
				if (!part) return std::unexpected(std::move(part.error()));
				const bool last = peek() == ')';
				if (part->second != 0) {
					if (++elements_ > limits_.max_elements) return error("filter has too many elements");
					const std::uint8_t k = first ? filter_part_initial : last ? filter_part_final : filter_part_any;
					const std::uint32_t p = access::add_node(out_, k);
					access::set_value_range(out_, p, part->first, part->second);
					access::link_last(out_, node, p);
					any_part = true;
				}
				if (last) break;
				++i_;// '*'
				first = false;
			}
			if (!any_part) return error("substring filter without any substring", value_start);
			return node;
		}

		result<void> set_value(std::uint32_t node)
		{
			auto v = read_part(false);
			if (!v) return std::unexpected(std::move(v.error()));
			access::set_value_range(out_, node, v->first, v->second);
			return {};
		}

		// attr [":dn"] [":" rule] ":=" value, or [":dn"] ":" rule ":=" value
		result<std::uint32_t> parse_extensible(std::string_view attr, std::size_t attr_start, std::uint32_t parent)
		{
			if (!attr.empty() && !detail::is_attribute_description(attr))
				return error("invalid attribute description", attr_start);
			bool dn_attributes = false;
			std::string_view rule;
			while (true) {
				if (at_end() || peek() != ':') return error("expected ':='");
				++i_;
				if (!at_end() && peek() == '=') {
					++i_;
					break;
				}
				const std::size_t tok_start = i_;
				while (!at_end() && is_oid_char(peek())) ++i_;
				const std::string_view tok = s_.substr(tok_start, i_ - tok_start);
				if (tok.empty()) return error("expected 'dn', a matching rule or '='");
				if (!dn_attributes && rule.empty() && detail::iequals(tok, "dn")) {
					dn_attributes = true;
				} else if (rule.empty()) {
					if (!detail::is_oid(tok)) return error("invalid matching rule", tok_start);
					rule = tok;
				} else {
					return error("expected ':='", tok_start);
				}
			}
			if (attr.empty() && rule.empty())
				return error("extensible match needs an attribute or a matching rule", attr_start);
			const std::uint32_t node = add(kind::extensible_match, parent);
			access::set_attr(out_, node, attr);
			access::set_rule(out_, node, rule);
			access::set_dn_attributes(out_, node, dn_attributes);
			if (auto e = set_value(node); !e) return std::unexpected(std::move(e.error()));
			return node;
		}

		std::string_view s_;
		std::size_t shift_;
		filter_limits limits_;
		filter &out_;
		std::size_t i_ = 0;
		std::size_t elements_ = 0;
		std::size_t depth_ = 0;
	};

}// namespace

result<filter> filter::raw(std::string_view text, std::pmr::memory_resource *mr) { return raw(text, {}, mr); }

result<filter> filter::raw(std::string_view text, const filter_limits &limits, std::pmr::memory_resource *mr)
{
	filter out{ allocator_type(mr) };
	if (!text.empty() && text.front() == '(') {
		if (auto r = filter_parser(text, 0, limits, out).parse(); !r) return std::unexpected(std::move(r.error()));
		return out;
	}
	std::pmr::string wrapped(mr);
	wrapped.reserve(text.size() + 2);
	wrapped += '(';
	wrapped += text;
	wrapped += ')';
	if (auto r = filter_parser(wrapped, 1, limits, out).parse(); !r) return std::unexpected(std::move(r.error()));
	return out;
}

// ---------------------------------------------------------------- tree -> BER

namespace detail {

	result<void> check_filter(const filter &f, const filter_limits &limits)
	{
		if (f.empty()) return fail(client_errc::invalid_filter, "filter: empty filter");
		if (f.depth() > limits.max_depth)
			return fail(client_errc::invalid_filter,
			  "filter: nested too deeply (" + std::to_string(f.depth()) + " levels, at most "
				+ std::to_string(limits.max_depth) + ")");
		if (f.elements() > limits.max_elements)
			return fail(client_errc::invalid_filter,
			  "filter: too many elements (" + std::to_string(f.elements()) + ", at most "
				+ std::to_string(limits.max_elements) + ")");
		return {};
	}

	namespace {

		// Recursion depth is the filter's depth, checked by check_filter.
		void write_node(ber::writer &w, const filter &f, std::uint32_t i)
		{
			const auto &n = access::at(f, i);
			const std::string_view attr = access::attr_of(f, n);
			auto ava = [&](std::uint8_t number) {
				w.constructed(ber::context(number), [&](ber::writer &c) {
					c.octet_string(attr);
					c.octet_string(access::value_of(f, n));
				});
			};
			switch (static_cast<filter::kind>(n.k)) {
			case filter::kind::and_:
			case filter::kind::or_:
				w.constructed(ber::context(n.k == access::k(filter::kind::and_) ? 0 : 1), [&](ber::writer &c) {
					for (std::uint32_t child = n.first; child != npos; child = access::at(f, child).next)
						write_node(c, f, child);
				});
				return;
			case filter::kind::not_:
				w.constructed(ber::context(2), [&](ber::writer &c) { write_node(c, f, n.first); });
				return;
			case filter::kind::equality:
				ava(3);
				return;
			case filter::kind::substrings:
				w.constructed(ber::context(4), [&](ber::writer &c) {
					c.octet_string(attr);
					c.constructed(ber::tags::sequence, [&](ber::writer &s) {
						for (std::uint32_t p = n.first; p != npos; p = access::at(f, p).next) {
							const auto &part = access::at(f, p);
							const std::uint8_t number = part.k == filter_part_initial ? 0
														: part.k == filter_part_any	  ? 1
																					  : 2;
							s.octet_string(access::value_of(f, part), ber::context(number));
						}
					});
				});
				return;
			case filter::kind::greater_or_equal:
				ava(5);
				return;
			case filter::kind::less_or_equal:
				ava(6);
				return;
			case filter::kind::present:
				w.octet_string(attr, ber::context(7));
				return;
			case filter::kind::approx:
				ava(8);
				return;
			case filter::kind::extensible_match:
				w.constructed(ber::context(9), [&](ber::writer &c) {
					const std::string_view rule = access::rule_of(f, n);
					if (!rule.empty()) c.octet_string(rule, ber::context(1));
					if (!attr.empty()) c.octet_string(attr, ber::context(2));
					c.octet_string(access::value_of(f, n), ber::context(3));
					if (n.dn_attributes) c.boolean(true, ber::context(4));// DEFAULT FALSE: omitted when false
				});
				return;
			}
		}

	}// namespace

	void write_filter(ber::writer &w, const filter &f) { write_node(w, f, access::root(f)); }

}// namespace detail

result<void> encode_filter(ber::writer &w, const filter &f, const filter_limits &limits)
{
	if (auto r = detail::check_filter(f, limits); !r) return r;
	detail::write_filter(w, f);
	return {};
}

// ---------------------------------------------------------------- BER -> tree

namespace {

	std::unexpected<error> bad(const std::string &what, std::size_t offset)
	{
		return fail(client_errc::decode_error, "filter: " + what + " at offset " + std::to_string(offset));
	}

	std::string_view as_text(std::span<const std::byte> b)
	{
		return std::string_view(reinterpret_cast<const char *>(b.data()), b.size());
	}

	// RFC 4511 section 4: unknown trailing SEQUENCE elements are ignored (but
	// must be well-formed).
	result<void> skip_rest(ber::reader &r)
	{
		while (!r.empty()) {
			auto e = r.read();
			if (!e) return std::unexpected(std::move(e.error()));
		}
		return {};
	}

	class filter_decoder
	{
	  public:
		filter_decoder(const filter_limits &limits, filter &out) : limits_(limits), out_(out) {}

		result<void> decode(ber::reader &r)
		{
			auto root = node(r, 1, npos);
			if (!root) return std::unexpected(std::move(root.error()));
			access::set_root(out_, *root);
			access::set_limits(out_, depth_, elements_);
			return {};
		}

	  private:
		std::uint32_t add(kind k, std::uint32_t parent)
		{
			const std::uint32_t n = access::add_node(out_, access::k(k));
			if (parent != npos) access::link_last(out_, parent, n);
			return n;
		}

		result<std::string_view> read_attr(ber::reader &r, ber::tag t = ber::tags::octet_string)
		{
			const std::size_t at = r.offset();
			auto s = r.read_octet_string(t);
			if (!s) return std::unexpected(std::move(s.error()));
			const auto text = as_text(*s);
			if (!detail::is_attribute_description(text)) return bad("invalid attribute description", at);
			return text;
		}

		result<std::uint32_t> ava(ber::reader &r, ber::tag t, kind k, std::uint32_t parent)
		{
			auto sub = r.enter(t);
			if (!sub) return std::unexpected(std::move(sub.error()));
			auto a = read_attr(*sub);
			if (!a) return std::unexpected(std::move(a.error()));
			auto v = sub->read_octet_string();
			if (!v) return std::unexpected(std::move(v.error()));
			if (auto e = skip_rest(*sub); !e) return std::unexpected(std::move(e.error()));
			const std::uint32_t n = add(k, parent);
			access::set_attr(out_, n, *a);
			access::set_value(out_, n, as_text(*v));
			return n;
		}

		result<std::uint32_t> substrings(ber::reader &r, ber::tag t, std::uint32_t parent)
		{
			const std::size_t at = r.offset();
			auto sub = r.enter(t);
			if (!sub) return std::unexpected(std::move(sub.error()));
			auto a = read_attr(*sub);
			if (!a) return std::unexpected(std::move(a.error()));
			auto seq = sub->enter();
			if (!seq) return std::unexpected(std::move(seq.error()));
			const std::uint32_t n = add(kind::substrings, parent);
			access::set_attr(out_, n, *a);
			bool first = true;
			bool final_seen = false;
			while (!seq->empty()) {
				const std::size_t item_at = seq->offset();
				auto st = seq->peek_tag();
				if (!st) return std::unexpected(std::move(st.error()));
				if (st->cls != ber::tag_class::context || st->number > 2)
					return bad("unknown substring choice", item_at);
				if (final_seen) return bad("substring after 'final'", item_at);
				auto s = seq->read_octet_string(*st);
				if (!s) return std::unexpected(std::move(s.error()));
				if (s->empty()) return bad("empty substring", item_at);
				std::uint8_t k = filter_part_any;
				if (st->number == 0) {
					if (!first) return bad("'initial' is not the first substring", item_at);
					k = filter_part_initial;
				} else if (st->number == 2) {
					k = filter_part_final;
					final_seen = true;
				}
				if (++elements_ > limits_.max_elements)
					return bad("more than " + std::to_string(limits_.max_elements) + " filter elements", item_at);
				const std::uint32_t p = access::add_node(out_, k);
				access::set_value(out_, p, as_text(*s));
				access::link_last(out_, n, p);
				first = false;
			}
			if (first) return bad("substring filter without substrings", at);
			if (auto e = skip_rest(*sub); !e) return std::unexpected(std::move(e.error()));
			return n;
		}

		result<std::uint32_t> extensible(ber::reader &r, ber::tag t, std::uint32_t parent)
		{
			const std::size_t at = r.offset();
			auto sub = r.enter(t);
			if (!sub) return std::unexpected(std::move(sub.error()));
			auto next_is = [&](std::uint8_t number) {
				// Checked first: peek_tag() on an empty reader would build an
				// error (on the default resource) only to drop it.
				if (sub->empty()) return false;
				auto pt = sub->peek_tag();
				return pt && pt->cls == ber::tag_class::context && pt->number == number;
			};
			std::string_view rule;
			std::string_view type;
			bool dn_attributes = false;
			if (next_is(1)) {
				const std::size_t rule_at = sub->offset();
				auto s = sub->read_octet_string(ber::context(1));
				if (!s) return std::unexpected(std::move(s.error()));
				rule = as_text(*s);
				if (!detail::is_oid(rule)) return bad("invalid matching rule", rule_at);
			}
			if (next_is(2)) {
				auto s = read_attr(*sub, ber::context(2));
				if (!s) return std::unexpected(std::move(s.error()));
				type = *s;
			}
			auto v = sub->read_octet_string(ber::context(3));
			if (!v) return std::unexpected(std::move(v.error()));
			if (next_is(4)) {
				auto b = sub->read_boolean(ber::context(4));
				if (!b) return std::unexpected(std::move(b.error()));
				dn_attributes = *b;
			}
			if (auto e = skip_rest(*sub); !e) return std::unexpected(std::move(e.error()));
			if (rule.empty() && type.empty()) return bad("extensible match without type or matching rule", at);
			// "(a:dn:=v)" means dnAttributes, so a rule named "dn" is only
			// expressible together with dnAttributes ("(a:dn:dn:=v)").
			if (!dn_attributes && detail::iequals(rule, "dn"))
				return bad("matching rule 'dn' without dnAttributes has no RFC 4515 form", at);
			const std::uint32_t n = add(kind::extensible_match, parent);
			access::set_attr(out_, n, type);
			access::set_rule(out_, n, rule);
			access::set_value(out_, n, as_text(*v));
			access::set_dn_attributes(out_, n, dn_attributes);
			return n;
		}

		// Bounded recursion: depth never exceeds limits_.max_depth. The
		// element count is checked before anything is allocated for the element.
		result<std::uint32_t> node(ber::reader &r, std::size_t depth, std::uint32_t parent)
		{
			const std::size_t at = r.offset();
			if (depth > limits_.max_depth)
				return fail(client_errc::nesting_too_deep,
				  "filter: nested deeper than " + std::to_string(limits_.max_depth) + " levels at offset "
					+ std::to_string(at));
			if (++elements_ > limits_.max_elements)
				return bad("more than " + std::to_string(limits_.max_elements) + " filter elements", at);
			depth_ = std::max(depth_, depth);
			auto t = r.peek_tag();
			if (!t) return std::unexpected(std::move(t.error()));
			if (t->cls != ber::tag_class::context)
				return fail(client_errc::unexpected_tag,
				  "filter: unknown filter choice " + ber::to_string(*t) + " at offset " + std::to_string(at));
			switch (t->number) {
			case 0:
			case 1:
			case 2: {
				auto sub = r.enter(*t);
				if (!sub) return std::unexpected(std::move(sub.error()));
				const kind k = t->number == 0 ? kind::and_ : t->number == 1 ? kind::or_ : kind::not_;
				const std::uint32_t n = add(k, parent);
				if (k == kind::not_) {
					auto child = node(*sub, depth + 1, n);
					if (!child) return child;
					if (auto e = sub->expect_end(); !e) return std::unexpected(std::move(e.error()));
				} else {
					while (!sub->empty()) {
						auto child = node(*sub, depth + 1, n);
						if (!child) return child;
					}
				}
				return n;
			}
			case 3:
				return ava(r, *t, kind::equality, parent);
			case 4:
				return substrings(r, *t, parent);
			case 5:
				return ava(r, *t, kind::greater_or_equal, parent);
			case 6:
				return ava(r, *t, kind::less_or_equal, parent);
			case 7: {
				auto a = read_attr(r, *t);
				if (!a) return std::unexpected(std::move(a.error()));
				const std::uint32_t n = add(kind::present, parent);
				access::set_attr(out_, n, *a);
				return n;
			}
			case 8:
				return ava(r, *t, kind::approx, parent);
			case 9:
				return extensible(r, *t, parent);
			default:
				return fail(client_errc::unexpected_tag,
				  "filter: unknown filter choice " + ber::to_string(*t) + " at offset " + std::to_string(at));
			}
		}

		filter_limits limits_;
		filter &out_;
		std::size_t elements_ = 0;
		std::size_t depth_ = 0;
	};

}// namespace

result<filter> decode_filter(ber::reader &r, const filter_limits &limits, std::pmr::memory_resource *mr)
{
	ber::reader copy = r;
	filter out{ filter::allocator_type(mr) };
	if (auto e = filter_decoder(limits, out).decode(copy); !e) return std::unexpected(std::move(e.error()));
	r = copy;
	return out;
}

}// namespace jhetz::ldap
