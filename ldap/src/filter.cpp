#include "jhetz/ldap/filter.hpp"

#include "filter_ast.hpp"

#include <stdexcept>

namespace jhetz::ldap {

// ---------------------------------------------------------------- escaping and builders

std::string escape_filter_value(std::string_view value)
{
	static constexpr char digits[] = "0123456789abcdef";
	std::string out;
	out.reserve(value.size());
	for (char c : value) {
		switch (c) {
		case '*':
		case '(':
		case ')':
		case '\\':
		case '\0': {
			const auto u = static_cast<unsigned char>(c);
			out += '\\';
			out += digits[u >> 4];
			out += digits[u & 0xFu];
			break;
		}
		default:
			out += c;
		}
	}
	return out;
}

namespace filters {
	namespace {

		// True if `text` is one parenthesized group "(<op>...)": the '(' at
		// index 0 is closed by the last character. `\xx` escapes are skipped,
		// so escaped parentheses in values do not count.
		bool is_group(std::string_view text, char op)
		{
			if (text.size() < 3 || text[0] != '(' || text[1] != op || text.back() != ')') return false;
			std::size_t depth = 0;
			for (std::size_t i = 0; i < text.size(); ++i) {
				const char c = text[i];
				if (c == '\\') {
					i += 2;
				} else if (c == '(') {
					++depth;
				} else if (c == ')') {
					if (depth == 0) return false;
					if (--depth == 0) return i + 1 == text.size();
				}
			}
			return false;
		}

		void append_operand(std::string &out, const filter &f, char op)
		{
			if (is_group(f.text, op))
				out.append(f.text, 2, f.text.size() - 3);
			else
				out += f.text;
		}

		filter combine(const filter &f, const filter &g, char op)
		{
			std::string out = "(";
			out += op;
			append_operand(out, f, op);
			append_operand(out, g, op);
			out += ')';
			return filter{ std::move(out) };
		}

	}// namespace

	attr::attr(const attribute &name) : name_(name.name())
	{
		if (!detail::is_attribute_description(name_))
			throw std::invalid_argument("ldap::filters::attr: invalid attribute description");
	}

	filter attr::simple(std::string_view op, std::string_view value) const
	{
		std::string out = "(";
		out += name_;
		out += op;
		out += escape_filter_value(value);
		out += ')';
		return filter{ std::move(out) };
	}

	filter attr::operator==(std::string_view value) const { return simple("=", value); }
	filter attr::operator>=(std::string_view value) const { return simple(">=", value); }
	filter attr::operator<=(std::string_view value) const { return simple("<=", value); }
	filter attr::approx(std::string_view value) const { return simple("~=", value); }
	filter attr::present() const { return filter{ "(" + name_ + "=*)" }; }

	filter attr::starts_with(std::string_view value) const
	{
		if (value.empty()) return present();
		return filter{ "(" + name_ + "=" + escape_filter_value(value) + "*)" };
	}

	filter attr::ends_with(std::string_view value) const
	{
		if (value.empty()) return present();
		return filter{ "(" + name_ + "=*" + escape_filter_value(value) + ")" };
	}

	filter attr::contains(std::string_view value) const
	{
		if (value.empty()) return present();
		return filter{ "(" + name_ + "=*" + escape_filter_value(value) + "*)" };
	}

	filter operator&&(const filter &f, const filter &g) { return combine(f, g, '&'); }
	filter operator||(const filter &f, const filter &g) { return combine(f, g, '|'); }
	filter operator!(const filter &f) { return filter{ "(!" + f.text + ")" }; }

}// namespace filters

// ---------------------------------------------------------------- text -> tree

namespace detail {
	namespace {

		bool is_attr_char(char c) { return is_keychar(c) || c == '.' || c == ';'; }
		bool is_oid_char(char c) { return is_keychar(c) || c == '.'; }

		class filter_parser
		{
		  public:
			// `shift`: 1 when the text was wrapped in parentheses, so positions
			// in errors refer to the caller's text.
			filter_parser(std::string_view s, std::size_t shift) : s_(s), shift_(shift) {}

			result<filter_node> parse()
			{
				auto node = parse_filter(1);
				if (!node) return node;
				if (i_ != s_.size()) return error("unexpected characters after the filter");
				return node;
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

			// Bounded recursion: depth never exceeds max_filter_depth.
			result<filter_node> parse_filter(std::size_t depth)
			{
				if (depth > max_filter_depth) return error("filter nested too deeply");
				if (auto e = expect('('); !e) return std::unexpected(std::move(e.error()));
				if (at_end()) return error("unexpected end of filter");
				filter_node node;
				const char c = peek();
				if (c == '&' || c == '|') {
					node.kind = c == '&' ? filter_kind::and_ : filter_kind::or_;
					++i_;
					while (!at_end() && peek() == '(') {
						auto child = parse_filter(depth + 1);
						if (!child) return child;
						node.children.push_back(std::move(*child));
					}
				} else if (c == '!') {
					node.kind = filter_kind::not_;
					++i_;
					auto child = parse_filter(depth + 1);
					if (!child) return child;
					node.children.push_back(std::move(*child));
				} else {
					auto item = parse_item();
					if (!item) return item;
					node = std::move(*item);
				}
				if (auto e = expect(')'); !e) return std::unexpected(std::move(e.error()));
				return node;
			}

			// Value up to the closing ')', which is not consumed. With
			// `split_stars`, unescaped '*' separates the returned parts.
			result<std::vector<std::string>> parse_value(bool split_stars)
			{
				std::vector<std::string> parts(1);
				while (true) {
					if (at_end()) return error("unexpected end of filter");
					const char c = peek();
					if (c == ')') break;
					if (c == '(' || c == '\0') return error("unescaped '(' or NUL in value");
					if (c == '*') {
						if (!split_stars) return error("unescaped '*' in value");
						parts.emplace_back();
						++i_;
					} else if (c == '\\') {
						if (i_ + 2 >= s_.size() || !is_hex(s_[i_ + 1]) || !is_hex(s_[i_ + 2]))
							return error("invalid escape (expected \\ and two hex digits)");
						parts.back() += static_cast<char>((hex_value(s_[i_ + 1]) << 4) | hex_value(s_[i_ + 2]));
						i_ += 3;
					} else {
						parts.back() += c;
						++i_;
					}
				}
				return parts;
			}

			result<filter_node> parse_item()
			{
				const std::size_t attr_start = i_;
				while (!at_end() && is_attr_char(peek())) ++i_;
				filter_node node;
				node.attr = std::string(s_.substr(attr_start, i_ - attr_start));
				if (at_end()) return error("unexpected end of filter");
				if (peek() == ':') return parse_extensible(std::move(node), attr_start);
				if (!is_attribute_description(node.attr)) return error("invalid attribute description", attr_start);

				const char c = peek();
				if (c == '~' || c == '>' || c == '<') {
					if (i_ + 1 >= s_.size() || s_[i_ + 1] != '=') return error("expected '='", i_ + 1);
					node.kind = c == '~'   ? filter_kind::approx
								: c == '>' ? filter_kind::greater_or_equal
										   : filter_kind::less_or_equal;
					i_ += 2;
					auto v = parse_value(false);
					if (!v) return std::unexpected(std::move(v.error()));
					node.value = std::move(v->front());
					return node;
				}
				if (c != '=') return error("expected a filter type ('=', '~=', '>=', '<=' or ':=')");
				++i_;
				const std::size_t value_start = i_;
				auto v = parse_value(true);
				if (!v) return std::unexpected(std::move(v.error()));
				auto &parts = *v;
				if (parts.size() == 1) {
					node.kind = filter_kind::equality;
					node.value = std::move(parts.front());
					return node;
				}
				if (parts.size() == 2 && parts[0].empty() && parts[1].empty()) {
					node.kind = filter_kind::present;
					return node;
				}
				node.kind = filter_kind::substrings;
				if (!parts.front().empty()) node.initial = std::move(parts.front());
				if (!parts.back().empty()) node.final_ = std::move(parts.back());
				for (std::size_t k = 1; k + 1 < parts.size(); ++k)
					if (!parts[k].empty()) node.any.push_back(std::move(parts[k]));
				if (!node.initial && !node.final_ && node.any.empty())
					return error("substring filter without any substring", value_start);
				return node;
			}

			// attr [":dn"] [":" rule] ":=" value, or [":dn"] ":" rule ":=" value
			result<filter_node> parse_extensible(filter_node node, std::size_t attr_start)
			{
				node.kind = filter_kind::extensible;
				if (!node.attr.empty() && !is_attribute_description(node.attr))
					return error("invalid attribute description", attr_start);
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
					if (!node.dn_attributes && node.rule.empty() && iequals(tok, "dn")) {
						node.dn_attributes = true;
					} else if (node.rule.empty()) {
						if (!is_oid(tok)) return error("invalid matching rule", tok_start);
						node.rule = std::string(tok);
					} else {
						return error("expected ':='", tok_start);
					}
				}
				if (node.attr.empty() && node.rule.empty())
					return error("extensible match needs an attribute or a matching rule", attr_start);
				auto v = parse_value(false);
				if (!v) return std::unexpected(std::move(v.error()));
				node.value = std::move(v->front());
				return node;
			}

			std::string_view s_;
			std::size_t shift_;
			std::size_t i_ = 0;
		};

	}// namespace

	result<filter_node> parse_filter(std::string_view text)
	{
		if (!text.empty() && text.front() == '(') return filter_parser(text, 0).parse();
		const std::string wrapped = "(" + std::string(text) + ")";
		return filter_parser(wrapped, 1).parse();
	}

	// ---------------------------------------------------------------- tree -> BER

	void write_filter(ber::writer &w, const filter_node &n)
	{
		auto ava = [&](std::uint8_t number) {
			w.constructed(ber::context(number), [&](ber::writer &c) {
				c.octet_string(n.attr);
				c.octet_string(n.value);
			});
		};
		switch (n.kind) {
		case filter_kind::and_:
		case filter_kind::or_:
			w.constructed(ber::context(n.kind == filter_kind::and_ ? 0 : 1), [&](ber::writer &c) {
				for (const auto &child : n.children) write_filter(c, child);
			});
			return;
		case filter_kind::not_:
			w.constructed(ber::context(2), [&](ber::writer &c) { write_filter(c, n.children.front()); });
			return;
		case filter_kind::equality:
			ava(3);
			return;
		case filter_kind::substrings:
			w.constructed(ber::context(4), [&](ber::writer &c) {
				c.octet_string(n.attr);
				c.constructed(ber::tags::sequence, [&](ber::writer &s) {
					if (n.initial) s.octet_string(*n.initial, ber::context(0));
					for (const auto &a : n.any) s.octet_string(a, ber::context(1));
					if (n.final_) s.octet_string(*n.final_, ber::context(2));
				});
			});
			return;
		case filter_kind::greater_or_equal:
			ava(5);
			return;
		case filter_kind::less_or_equal:
			ava(6);
			return;
		case filter_kind::present:
			w.octet_string(n.attr, ber::context(7));
			return;
		case filter_kind::approx:
			ava(8);
			return;
		case filter_kind::extensible:
			w.constructed(ber::context(9), [&](ber::writer &c) {
				if (!n.rule.empty()) c.octet_string(n.rule, ber::context(1));
				if (!n.attr.empty()) c.octet_string(n.attr, ber::context(2));
				c.octet_string(n.value, ber::context(3));
				if (n.dn_attributes) c.boolean(true, ber::context(4));// DEFAULT FALSE: omitted when false
			});
			return;
		}
	}

}// namespace detail

result<void> encode_filter(ber::writer &w, std::string_view text)
{
	auto node = detail::parse_filter(text);
	if (!node) return std::unexpected(std::move(node.error()));
	detail::write_filter(w, *node);
	return {};
}

// ---------------------------------------------------------------- BER -> text

namespace {

	using detail::filter_kind;
	using detail::filter_node;

	std::unexpected<error> bad(const char *what, std::size_t offset)
	{
		return fail(client_errc::decode_error, std::string("filter: ") + what + " at offset " + std::to_string(offset));
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

	result<std::string> read_attr(ber::reader &r)
	{
		const std::size_t at = r.offset();
		auto s = r.read_string();
		if (!s) return s;
		if (!detail::is_attribute_description(*s)) return bad("invalid attribute description", at);
		return s;
	}

	result<filter_node> decode_node(ber::reader &r, std::size_t depth);

	result<filter_node> decode_ava(ber::reader &r, ber::tag t, filter_kind kind)
	{
		auto sub = r.enter(t);
		if (!sub) return std::unexpected(std::move(sub.error()));
		filter_node n;
		n.kind = kind;
		auto a = read_attr(*sub);
		if (!a) return std::unexpected(std::move(a.error()));
		auto v = sub->read_string();
		if (!v) return std::unexpected(std::move(v.error()));
		if (auto e = skip_rest(*sub); !e) return std::unexpected(std::move(e.error()));
		n.attr = std::move(*a);
		n.value = std::move(*v);
		return n;
	}

	result<filter_node> decode_substrings(ber::reader &r, ber::tag t)
	{
		const std::size_t at = r.offset();
		auto sub = r.enter(t);
		if (!sub) return std::unexpected(std::move(sub.error()));
		filter_node n;
		n.kind = filter_kind::substrings;
		auto a = read_attr(*sub);
		if (!a) return std::unexpected(std::move(a.error()));
		n.attr = std::move(*a);
		auto seq = sub->enter();
		if (!seq) return std::unexpected(std::move(seq.error()));
		bool first = true;
		while (!seq->empty()) {
			const std::size_t item_at = seq->offset();
			auto st = seq->peek_tag();
			if (!st) return std::unexpected(std::move(st.error()));
			if (st->cls != ber::tag_class::context || st->number > 2) return bad("unknown substring choice", item_at);
			if (n.final_) return bad("substring after 'final'", item_at);
			auto s = seq->read_string(*st);
			if (!s) return std::unexpected(std::move(s.error()));
			if (s->empty()) return bad("empty substring", item_at);
			if (st->number == 0) {
				if (!first) return bad("'initial' is not the first substring", item_at);
				n.initial = std::move(*s);
			} else if (st->number == 1) {
				n.any.push_back(std::move(*s));
			} else {
				n.final_ = std::move(*s);
			}
			first = false;
		}
		if (first) return bad("substring filter without substrings", at);
		if (auto e = skip_rest(*sub); !e) return std::unexpected(std::move(e.error()));
		return n;
	}

	result<filter_node> decode_extensible(ber::reader &r, ber::tag t)
	{
		const std::size_t at = r.offset();
		auto sub = r.enter(t);
		if (!sub) return std::unexpected(std::move(sub.error()));
		filter_node n;
		n.kind = filter_kind::extensible;
		auto next_is = [&](std::uint8_t number) {
			auto pt = sub->peek_tag();
			return pt && pt->cls == ber::tag_class::context && pt->number == number;
		};
		if (next_is(1)) {
			const std::size_t rule_at = sub->offset();
			auto rule = sub->read_string(ber::context(1));
			if (!rule) return std::unexpected(std::move(rule.error()));
			if (!detail::is_oid(*rule)) return bad("invalid matching rule", rule_at);
			n.rule = std::move(*rule);
		}
		if (next_is(2)) {
			const std::size_t type_at = sub->offset();
			auto type = sub->read_string(ber::context(2));
			if (!type) return std::unexpected(std::move(type.error()));
			if (!detail::is_attribute_description(*type)) return bad("invalid attribute description", type_at);
			n.attr = std::move(*type);
		}
		auto v = sub->read_string(ber::context(3));
		if (!v) return std::unexpected(std::move(v.error()));
		n.value = std::move(*v);
		if (next_is(4)) {
			auto b = sub->read_boolean(ber::context(4));
			if (!b) return std::unexpected(std::move(b.error()));
			n.dn_attributes = *b;
		}
		if (auto e = skip_rest(*sub); !e) return std::unexpected(std::move(e.error()));
		if (n.rule.empty() && n.attr.empty()) return bad("extensible match without type or matching rule", at);
		// "(a:dn:=v)" means dnAttributes, so a rule named "dn" is only
		// expressible together with dnAttributes ("(a:dn:dn:=v)").
		if (!n.dn_attributes && detail::iequals(n.rule, "dn"))
			return bad("matching rule 'dn' without dnAttributes has no RFC 4515 form", at);
		return n;
	}

	// Bounded recursion: depth never exceeds max_filter_depth.
	result<filter_node> decode_node(ber::reader &r, std::size_t depth)
	{
		const std::size_t at = r.offset();
		if (depth > max_filter_depth)
			return fail(client_errc::nesting_too_deep,
			  "filter: nested deeper than " + std::to_string(max_filter_depth) + " levels at offset "
				+ std::to_string(at));
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
			filter_node n;
			n.kind = t->number == 0 ? filter_kind::and_ : t->number == 1 ? filter_kind::or_ : filter_kind::not_;
			if (n.kind == filter_kind::not_) {
				auto child = decode_node(*sub, depth + 1);
				if (!child) return child;
				n.children.push_back(std::move(*child));
				if (auto e = sub->expect_end(); !e) return std::unexpected(std::move(e.error()));
			} else {
				while (!sub->empty()) {
					auto child = decode_node(*sub, depth + 1);
					if (!child) return child;
					n.children.push_back(std::move(*child));
				}
			}
			return n;
		}
		case 3:
			return decode_ava(r, *t, filter_kind::equality);
		case 4:
			return decode_substrings(r, *t);
		case 5:
			return decode_ava(r, *t, filter_kind::greater_or_equal);
		case 6:
			return decode_ava(r, *t, filter_kind::less_or_equal);
		case 7: {
			filter_node n;
			n.kind = filter_kind::present;
			auto a = r.read_string(*t);
			if (!a) return std::unexpected(std::move(a.error()));
			if (!detail::is_attribute_description(*a)) return bad("invalid attribute description", at);
			n.attr = std::move(*a);
			return n;
		}
		case 8:
			return decode_ava(r, *t, filter_kind::approx);
		case 9:
			return decode_extensible(r, *t);
		default:
			return fail(client_errc::unexpected_tag,
			  "filter: unknown filter choice " + ber::to_string(*t) + " at offset " + std::to_string(at));
		}
	}

	void print(std::string &out, const filter_node &n)
	{
		out += '(';
		switch (n.kind) {
		case filter_kind::and_:
		case filter_kind::or_:
		case filter_kind::not_:
			out += n.kind == filter_kind::and_ ? '&' : n.kind == filter_kind::or_ ? '|' : '!';
			for (const auto &c : n.children) print(out, c);
			break;
		case filter_kind::equality:
			out += n.attr + "=" + escape_filter_value(n.value);
			break;
		case filter_kind::greater_or_equal:
			out += n.attr + ">=" + escape_filter_value(n.value);
			break;
		case filter_kind::less_or_equal:
			out += n.attr + "<=" + escape_filter_value(n.value);
			break;
		case filter_kind::approx:
			out += n.attr + "~=" + escape_filter_value(n.value);
			break;
		case filter_kind::present:
			out += n.attr + "=*";
			break;
		case filter_kind::substrings:
			out += n.attr + "=";
			if (n.initial) out += escape_filter_value(*n.initial);
			out += '*';
			for (const auto &a : n.any) {
				out += escape_filter_value(a);
				out += '*';
			}
			if (n.final_) out += escape_filter_value(*n.final_);
			break;
		case filter_kind::extensible:
			out += n.attr;
			if (n.dn_attributes) out += ":dn";
			if (!n.rule.empty()) out += ":" + n.rule;
			out += ":=" + escape_filter_value(n.value);
			break;
		}
		out += ')';
	}

}// namespace

result<std::string> decode_filter(ber::reader &r)
{
	ber::reader copy = r;
	auto node = decode_node(copy, 1);
	if (!node) return std::unexpected(std::move(node.error()));
	std::string out;
	print(out, *node);
	r = copy;
	return out;
}

}// namespace jhetz::ldap
