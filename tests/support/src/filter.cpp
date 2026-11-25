// BER Filter -> tree (RFC 4511 section 4.5.1), as a server reads it.
#include "jhetz/ldap/testing/server_codec.hpp"

#include "control_util.hpp"
#include "filter_ast.hpp"
#include "format_util.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <string_view>
#include <utility>

namespace jhetz::ldap::testing {

namespace {

	using access = detail::filter_access;
	using kind = filter::kind;
	using detail::next_is;
	using detail::skip_rest;
	namespace filter_choice = detail::filter_choice;
	constexpr std::uint32_t npos = access::npos;
	constexpr std::uint8_t filter_part_initial = access::part_initial;
	constexpr std::uint8_t filter_part_any = access::part_any;
	constexpr std::uint8_t filter_part_final = access::part_final;

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
}// namespace jhetz::ldap::testing
