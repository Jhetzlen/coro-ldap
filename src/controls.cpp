#include "jhetz/ldap/controls.hpp"

#include "control_util.hpp"
#include "format_util.hpp"

#include "jhetz/ldap/ber.hpp"

#include <algorithm>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <span>
#include <string>
#include <utility>

namespace jhetz::ldap {

using detail::check_simple_item;
using detail::find_decoded;
using detail::in_control;
using detail::matched_values_name;
using detail::value_control;

namespace {

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

	// ---------------------------------------------------------------- matched values (RFC 3876)

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

	// Adds `by` to the " at position N" that ends a filter parse error.
	void shift_position(std::pmr::string &context, std::size_t by)
	{
		constexpr std::string_view marker = " at position ";
		const auto at = context.rfind(marker);
		if (by == 0 || at == std::pmr::string::npos) {
			return;
		}
		const std::string_view digits = std::string_view(context).substr(at + marker.size());
		std::size_t n = 0;
		const auto [end, ec] = std::from_chars(digits.data(), digits.data() + digits.size(), n);
		if (ec != std::errc{} || end != digits.data() + digits.size()) {
			return;
		}
		context.resize(at + marker.size());
		context += std::to_string(n + by);
	}

	// ---------------------------------------------------------------- virtual list view

	constexpr std::string_view vlv_name = "virtual list view";
	constexpr std::int64_t max_int = std::numeric_limits<std::int32_t>::max();

	// VirtualListViewRequest ::= SEQUENCE { beforeCount INTEGER (0..maxInt),
	//   afterCount INTEGER (0..maxInt), target CHOICE { byOffset [0] SEQUENCE {
	//   offset INTEGER (1 .. maxInt), contentCount INTEGER (0 .. maxInt) },
	//   greaterThanOrEqual [1] AssertionValue }, contextID OCTET STRING OPTIONAL }
	auto encode_vlv(const virtual_list_view &v, std::pmr::memory_resource *mr) -> result<control>
	{
		const auto negative = [](std::string_view field, std::int32_t value) {
			return fail(client_errc::encode_error, detail::format("{}: {} {} is negative", vlv_name, field, value));
		};
		if (v.before_count < 0) {
			return negative("beforeCount", v.before_count);
		}
		if (v.after_count < 0) {
			return negative("afterCount", v.after_count);
		}
		if (const auto *o = std::get_if<vlv_by_offset>(&v.target)) {
			if (o->offset < 1) {
				return fail(client_errc::encode_error,
				  detail::format("{}: offset {} outside 1..{}", vlv_name, o->offset, max_int));
			}
			if (o->content_count < 0) {
				return negative("contentCount", o->content_count);
			}
		}
		ber::writer w{ ber::writer::allocator_type(mr) };
		w.constructed(ber::tags::sequence, [&](ber::writer &s) {
			s.integer(v.before_count);
			s.integer(v.after_count);
			if (const auto *o = std::get_if<vlv_by_offset>(&v.target)) {
				s.constructed(ber::context(0, true), [&](ber::writer &by) {
					by.integer(o->offset);
					by.integer(o->content_count);
				});
			} else {
				s.octet_string(std::get<vlv_greater_than_or_equal>(v.target).value, ber::context(1));
			}
			if (v.context_id) {
				s.octet_string(*v.context_id);
			}
		});
		return value_control(vlv_request_oid, v.critical, w, control::allocator_type(mr));
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
	// `at`: where the item starts in `text`, so positions in the filter's
	// errors refer to the whole text.
	// NOLINTNEXTLINE(bugprone-easily-swappable-parameters): local, two callers
	const auto item = [&](std::string_view t, std::size_t index, std::size_t at) -> result<filter> {
		auto f = filter::raw(t, mr);
		if (!f) {
			shift_position(f.error().context, at);
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
		auto f = item(text, 0, 0);
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
		auto f = item(inner.substr(pos, end - pos + 1), out.size(), pos + 1);
		if (!f) {
			return std::unexpected(std::move(f.error()));
		}
		out.push_back(std::move(*f));
		pos = end + 1;
	}
	return out;
}

auto to_control(const virtual_list_view &c, std::pmr::memory_resource *mr) -> result<control>
{
	return encode_vlv(c, mr);
}

auto to_control(const transaction_specification &c, std::pmr::memory_resource *mr) -> result<control>
{
	return control(transaction_specification_oid, true, c.identifier, control::allocator_type(mr));
}

namespace detail {

	auto check_simple_item(const filter &f, std::size_t index, client_errc code) -> result<void>
	{
		const std::size_t n = index + 1;
		if (f.empty()) {
			if (auto why = f.build_error()) {
				why->context.insert(0, detail::format("item {}: ", n));
				return std::unexpected(std::move(*why));
			}
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

	auto check_transaction_proxy(const std::pmr::vector<control> &wire) -> result<void>
	{
		if (!std::ranges::contains(wire, proxied_authorization_oid, &control::type)) {
			return {};
		}
		return fail(client_errc::encode_error,
		  "proxied_authorization is not valid on an update in a transaction: put it on the Start Transaction "
		  "request (RFC 5805 section 4.4)");
	}

	auto check_vlv_sort(const std::pmr::vector<control> &wire) -> result<void>
	{
		if (std::ranges::contains(wire, sort_request_oid, &control::type)) {
			return {};
		}
		return fail(client_errc::encode_error,
		  "virtual_list_view needs a server_side_sort control on the same search "
		  "(draft-ietf-ldapext-ldapv3-vlv-09 section 6.1)");
	}

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

auto find_vlv_response(const std::pmr::vector<control> &controls, std::pmr::memory_resource *mr)
  -> result<std::optional<vlv_response>>
{
	return find_decoded<vlv_response>(
	  controls, vlv_response_oid, [mr](const control &c) { return decode_vlv_response(c, mr); });
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
