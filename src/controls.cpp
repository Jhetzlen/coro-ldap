#include "jhetz/ldap/controls.hpp"

#include "format_util.hpp"

#include "jhetz/ldap/ber.hpp"

#include <algorithm>
#include <cstddef>
#include <string>
#include <utility>

namespace jhetz::ldap {

namespace {

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

namespace detail {

	auto inapplicable_control(const control_rule &rule, operation_kind op) -> error
	{
		return make_error(client_errc::encode_error,
		  detail::format("{} is not valid on {} ({})", rule.name, operation_name(op), rule.source));
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
