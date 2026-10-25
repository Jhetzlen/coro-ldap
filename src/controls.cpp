#include "jhetz/ldap/controls.hpp"

#include "format_util.hpp"

#include "jhetz/ldap/ber.hpp"

#include <algorithm>
#include <cstddef>
#include <span>
#include <string>
#include <utility>

namespace jhetz::ldap {

namespace {

	// Control types a peer sent are shown in errors cut to this many bytes.
	constexpr std::size_t max_shown_type = 64;

	auto value_control(std::string_view oid, bool critical, const ber::writer &w, const control::allocator_type &alloc)
	  -> control
	{
		return { oid, critical, detail::as_text(w.bytes()), alloc };
	}

	// SortKeyList ::= SEQUENCE OF SEQUENCE { attributeType AttributeDescription,
	//   orderingRule [0] MatchingRuleId OPTIONAL, reverseOrder [1] BOOLEAN DEFAULT FALSE }
	auto encode_sort(const server_side_sort &v, std::pmr::memory_resource *mr) -> result<control>
	{
		if (v.keys.empty()) {
			return fail(client_errc::encode_error, "server side sort: no sort keys");
		}
		for (std::size_t i = 0; i < v.keys.size(); ++i) {
			if (v.keys[i].attribute.empty()) {
				return fail(
				  client_errc::encode_error, detail::format("server side sort: key {} has no attribute", i + 1));
			}
		}
		ber::writer w{ ber::writer::allocator_type(mr) };
		w.constructed(ber::tags::sequence, [&](ber::writer &list) {
			for (const auto &k : v.keys) {
				list.constructed(ber::tags::sequence, [&](ber::writer &key) {
					key.octet_string(k.attribute);
					if (!k.ordering_rule.empty()) {
						key.octet_string(k.ordering_rule, ber::context(0));
					}
					if (k.reverse) {
						key.boolean(true, ber::context(1));
					}
				});
			}
		});
		return value_control(sort_request_oid, v.critical, w, control::allocator_type(mr));
	}

	// AttributeSelection ::= SEQUENCE OF selector LDAPString (RFC 4527 section 3.1).
	auto encode_selection(std::string_view oid,
	  const std::vector<std::string> &attributes,
	  bool critical,
	  std::pmr::memory_resource *mr) -> result<control>
	{
		ber::writer w{ ber::writer::allocator_type(mr) };
		w.constructed(ber::tags::sequence, [&](ber::writer &list) {
			for (const auto &a : attributes) {
				list.octet_string(a);
			}
		});
		return value_control(oid, critical, w, control::allocator_type(mr));
	}

	// The first control of type `oid`, decoded by `decode` (which returns
	// a result<T>); nullopt if there is none.
	template<class T, class Decode>
	auto find_decoded(const std::pmr::vector<control> &controls, std::string_view oid, Decode decode)
	  -> result<std::optional<T>>
	{
		const auto it = std::ranges::find(controls, oid, &control::type);
		if (it == controls.end()) {
			return std::optional<T>{};
		}
		return decode(*it).transform([](T &&v) { return std::optional<T>(std::move(v)); });
	}

	auto find_read_entry(const std::pmr::vector<control> &controls, std::string_view oid, std::pmr::memory_resource *mr)
	  -> result<std::optional<entry>>
	{
		return find_decoded<entry>(controls, oid, [mr](const control &c) {
			decode_options options;
			options.memory = mr;
			return decode_read_entry(c, options).transform([](search_result_entry &&e) {
				return entry::from(std::move(e));
			});
		});
	}

	// The value bytes of a request control read back (for mock servers),
	// once its type is `oid` and it has a value; decode_error naming the
	// control otherwise.
	auto control_value(const control &c, std::string_view oid, std::string_view what)
	  -> result<std::span<const std::byte>>
	{
		if (c.type != oid) {
			std::string text = detail::format("{}: control type is ", what);
			detail::append_sanitized(text, c.type, max_shown_type);
			detail::format_to(text, ", not {}", oid);
			return fail(client_errc::decode_error, text);
		}
		if (!c.value) {
			return fail(client_errc::decode_error, detail::format("{}: control has no value", what));
		}
		return std::as_bytes(std::span(*c.value));
	}

	// Errors from inside a control value name the control: their offsets
	// are relative to the value.
	template<class T> auto in_control(result<T> r, std::string_view what) -> result<T>
	{
		return std::move(r).transform_error([what](error e) {
			e.context.insert(0, e.context.empty() ? std::string(what) : detail::format("{}: ", what));
			return e;
		});
	}

	// ---------------------------------------------------------------- matched values (RFC 3876)

	constexpr std::string_view matched_values_name = "matched values";

	// Whether `f` is a SimpleFilterItem (RFC 3876 section 2): one leaf, and
	// an extensible match without dnAttributes. `code` is the error's
	// (invalid_filter when encoding or parsing, decode_error when decoding),
	// whose context ("item 2 is (&...), ...") callers prefix; `index` is
	// 0-based.
	auto check_simple_item(const filter &f, std::size_t index, client_errc code) -> result<void>
	{
		const std::size_t n = index + 1;
		if (f.empty()) {
			return fail(code, detail::format("item {} is empty", n));
		}
		std::string_view shape;
		switch (f.root().kind()) {
		case filter::kind::and_:
			shape = "(&...)";
			break;
		case filter::kind::or_:
			shape = "(|...)";
			break;
		case filter::kind::not_:
			shape = "(!...)";
			break;
		case filter::kind::extensible_match:
			if (f.root().dn_attributes()) {
				shape = "an extensible match with dnAttributes";
			}
			break;
		default:
			break;
		}
		if (shape.empty()) {
			return {};
		}
		return fail(code, detail::format("item {} is {}, not a simple filter item (RFC 3876 section 2)", n, shape));
	}

	// ValuesReturnFilter ::= SEQUENCE OF SimpleFilterItem; each item is
	// written as a Filter, whose CHOICE tags and MatchingRuleAssertion
	// (without dnAttributes) are SimpleFilterItem's.
	auto encode_matched_values(const matched_values &v, std::pmr::memory_resource *mr) -> result<control>
	{
		if (v.values_return_filter.empty()) {
			return fail(client_errc::encode_error, detail::format("{}: no filter items", matched_values_name));
		}
		for (std::size_t i = 0; i < v.values_return_filter.size(); ++i) {
			if (auto ok = in_control(
				  check_simple_item(v.values_return_filter[i], i, client_errc::invalid_filter), matched_values_name);
			  !ok) {
				return std::unexpected(std::move(ok.error()));
			}
		}
		ber::writer w{ ber::writer::allocator_type(mr) };
		result<void> written;
		std::size_t failed_at = 0;
		w.constructed(ber::tags::sequence, [&](ber::writer &list) {
			for (std::size_t i = 0; i < v.values_return_filter.size() && written; ++i) {
				written = encode_filter(list, v.values_return_filter[i]);
				failed_at = i + 1;
			}
		});
		if (!written) {
			error e = std::move(written.error());
			e.context.insert(0, detail::format("{}: item {}: ", matched_values_name, failed_at));
			return std::unexpected(std::move(e));
		}
		return value_control(matched_values_oid, v.critical, w, control::allocator_type(mr));
	}

	auto read_matched_values(std::span<const std::byte> value, std::pmr::memory_resource *mr) -> result<matched_values>
	{
		ber::reader r(value);
		auto s = r.enter();
		if (!s) {
			return std::unexpected(std::move(s.error()));
		}
		if (auto done = r.expect_end(); !done) {
			return std::unexpected(std::move(done.error()));
		}
		matched_values out;
		std::size_t elements = 0;
		while (!s->empty()) {
			// The items share one element budget, as one filter would.
			const filter_limits limits{ .max_depth = max_filter_depth, .max_elements = max_filter_elements - elements };
			const std::size_t at = s->offset();
			auto f = decode_filter(*s, limits, mr);
			if (!f) {
				return std::unexpected(std::move(f.error()));
			}
			if (auto ok = check_simple_item(*f, out.values_return_filter.size(), client_errc::decode_error); !ok) {
				ok.error().context += detail::format(" at offset {}", at);
				return std::unexpected(std::move(ok.error()));
			}
			elements += f->elements();
			out.values_return_filter.push_back(std::move(*f));
			if (elements >= max_filter_elements && !s->empty()) {
				return fail(client_errc::decode_error,
				  detail::format("more than {} filter elements at offset {}", max_filter_elements, s->offset()));
			}
		}
		if (out.values_return_filter.empty()) {
			return fail(client_errc::decode_error, "no filter items");
		}
		return out;
	}

}// namespace

auto to_control(const control &c, std::pmr::memory_resource *mr) -> result<control>
{
	return control(c, control::allocator_type(mr));
}

auto to_control(const paged &c, std::pmr::memory_resource *mr) -> result<control>
{
	return encode_paged_results(paged_results(c.page_size, c.cookie, control::allocator_type(mr)), c.critical, mr);
}

auto to_control(const manage_dsa_it &c, std::pmr::memory_resource *mr) -> result<control>
{
	return control(manage_dsa_it_oid, c.critical, std::nullopt, control::allocator_type(mr));
}

auto to_control(const relax_rules &c, std::pmr::memory_resource *mr) -> result<control>
{
	return control(relax_rules_oid, c.critical, std::nullopt, control::allocator_type(mr));
}

auto to_control(const proxied_authorization &c, std::pmr::memory_resource *mr) -> result<control>
{
	// controlValue is the authzId itself, not BER; always critical (RFC 4370
	// section 3).
	return control(proxied_authorization_oid, true, c.authz_id, control::allocator_type(mr));
}

auto to_control(const server_side_sort &c, std::pmr::memory_resource *mr) -> result<control>
{
	return encode_sort(c, mr);
}

auto to_control(const assertion &c, std::pmr::memory_resource *mr) -> result<control>
{
	// controlValue is the Filter itself (RFC 4528 section 3).
	ber::writer w{ ber::writer::allocator_type(mr) };
	return encode_filter(w, c.filter)
	  .transform_error([](error e) {
		  e.context.insert(0, e.context.empty() ? "assertion" : "assertion: ");
		  return e;
	  })
	  .transform([&] { return value_control(assertion_oid, c.critical, w, control::allocator_type(mr)); });
}

auto to_control(const pre_read &c, std::pmr::memory_resource *mr) -> result<control>
{
	return encode_selection(pre_read_oid, c.attributes, c.critical, mr);
}

auto to_control(const post_read &c, std::pmr::memory_resource *mr) -> result<control>
{
	return encode_selection(post_read_oid, c.attributes, c.critical, mr);
}

auto to_control(const sync_request &c, std::pmr::memory_resource *mr) -> result<control>
{
	return encode_sync_request(c, mr);
}

auto to_control(const matched_values &c, std::pmr::memory_resource *mr) -> result<control>
{
	return encode_matched_values(c, mr);
}

auto parse_values_return_filter(std::string_view text, std::pmr::memory_resource *mr) -> result<std::vector<filter>>
{
	const auto item = [&](std::string_view t, std::size_t index) -> result<filter> {
		auto f = filter::raw(t, mr);
		if (!f) {
			f.error().context.insert(0, detail::format("{}: item {}: ", matched_values_name, index + 1));
			return f;
		}
		if (auto ok = in_control(check_simple_item(*f, index, client_errc::invalid_filter), matched_values_name); !ok) {
			return std::unexpected(std::move(ok.error()));
		}
		return f;
	};
	std::vector<filter> out;
	// One item without the outer parentheses.
	if (!text.starts_with("((")) {
		auto f = item(text, 0);
		if (!f) {
			return std::unexpected(std::move(f.error()));
		}
		out.push_back(std::move(*f));
		return out;
	}
	if (!text.ends_with(')')) {
		return fail(client_errc::invalid_filter,
		  detail::format("{}: no closing parenthesis at position {}", matched_values_name, text.size()));
	}
	// Unescaped parentheses only delimit (RFC 4515 escapes them in values),
	// so the items are found by counting them.
	const std::string_view inner = text.substr(1, text.size() - 2);
	std::size_t pos = 0;
	while (pos < inner.size()) {
		if (inner[pos] != '(') {
			return fail(client_errc::invalid_filter,
			  detail::format("{}: expected '(' at position {}", matched_values_name, pos + 1));
		}
		std::size_t depth = 0;
		std::size_t end = pos;
		for (; end < inner.size(); ++end) {
			if (inner[end] == '(') {
				++depth;
			} else if (inner[end] == ')' && --depth == 0) {
				break;
			}
		}
		if (end == inner.size()) {
			return fail(client_errc::invalid_filter,
			  detail::format("{}: unbalanced parentheses at position {}", matched_values_name, pos + 1));
		}
		auto f = item(inner.substr(pos, end - pos + 1), out.size());
		if (!f) {
			return std::unexpected(std::move(f.error()));
		}
		out.push_back(std::move(*f));
		pos = end + 1;
	}
	if (out.empty()) {
		return fail(client_errc::invalid_filter, detail::format("{}: no filter items", matched_values_name));
	}
	return out;
}

auto decode_matched_values(const control &c, std::pmr::memory_resource *mr) -> result<matched_values>
{
	auto value = control_value(c, matched_values_oid, matched_values_name);
	if (!value) {
		return std::unexpected(std::move(value.error()));
	}
	auto out = in_control(read_matched_values(*value, mr), matched_values_name);
	if (out) {
		out->critical = c.criticality;
	}
	return out;
}

namespace detail {

	auto inapplicable_control(const control_rule &rule, operation_kind op) -> error
	{
		const std::string_view article = op == operation_kind::extended ? "an " : "";
		return make_error(client_errc::encode_error,
		  detail::format("{} is not valid on {}{} ({})", rule.name, article, operation_name(op), rule.source));
	}

}// namespace detail

auto find_paged(const std::pmr::vector<control> &controls, std::pmr::memory_resource *mr)
  -> result<std::optional<paged_results>>
{
	return find_decoded<paged_results>(
	  controls, paged_results_oid, [mr](const control &c) { return decode_paged_results(c, mr); });
}

auto find_sort_result(const std::pmr::vector<control> &controls, std::pmr::memory_resource *mr)
  -> result<std::optional<sort_result>>
{
	return find_decoded<sort_result>(
	  controls, sort_response_oid, [mr](const control &c) { return decode_sort_result(c, mr); });
}

auto find_pre_read(const std::pmr::vector<control> &controls, std::pmr::memory_resource *mr)
  -> result<std::optional<entry>>
{
	return find_read_entry(controls, pre_read_oid, mr);
}

auto find_post_read(const std::pmr::vector<control> &controls, std::pmr::memory_resource *mr)
  -> result<std::optional<entry>>
{
	return find_read_entry(controls, post_read_oid, mr);
}

}// namespace jhetz::ldap
