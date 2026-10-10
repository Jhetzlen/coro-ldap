#include "jhetz/ldap/controls.hpp"

#include "jhetz/ldap/ber.hpp"

#include <cstddef>
#include <string>
#include <type_traits>
#include <utility>

namespace jhetz::ldap {

namespace {

	control
	  value_control(std::string_view oid, bool critical, const ber::writer &w, const control::allocator_type &alloc)
	{
		const auto &bytes = w.bytes();
		return control(
		  oid, critical, std::string_view(reinterpret_cast<const char *>(bytes.data()), bytes.size()), alloc);
	}

	// SortKeyList ::= SEQUENCE OF SEQUENCE { attributeType AttributeDescription,
	//   orderingRule [0] MatchingRuleId OPTIONAL, reverseOrder [1] BOOLEAN DEFAULT FALSE }
	result<control> encode_sort(const server_side_sort &v, std::pmr::memory_resource *mr)
	{
		if (v.keys.empty()) return fail(client_errc::encode_error, "server side sort: no sort keys");
		for (std::size_t i = 0; i < v.keys.size(); ++i)
			if (v.keys[i].attribute.empty())
				return fail(
				  client_errc::encode_error, "server side sort: key " + std::to_string(i + 1) + " has no attribute");
		ber::writer w{ ber::writer::allocator_type(mr) };
		w.constructed(ber::tags::sequence, [&](ber::writer &list) {
			for (const auto &k : v.keys)
				list.constructed(ber::tags::sequence, [&](ber::writer &key) {
					key.octet_string(k.attribute);
					if (!k.ordering_rule.empty()) key.octet_string(k.ordering_rule, ber::context(0));
					if (k.reverse) key.boolean(true, ber::context(1));
				});
		});
		return value_control(sort_request_oid, v.critical, w, control::allocator_type(mr));
	}

	// AttributeSelection ::= SEQUENCE OF selector LDAPString (RFC 4527 section 3.1).
	result<control> encode_selection(std::string_view oid,
	  const std::vector<std::string> &attributes,
	  bool critical,
	  std::pmr::memory_resource *mr)
	{
		ber::writer w{ ber::writer::allocator_type(mr) };
		w.constructed(ber::tags::sequence, [&](ber::writer &list) {
			for (const auto &a : attributes) list.octet_string(a);
		});
		return value_control(oid, critical, w, control::allocator_type(mr));
	}

	result<std::optional<entry>>
	  find_read_entry(const std::pmr::vector<control> &controls, std::string_view oid, std::pmr::memory_resource *mr)
	{
		for (const auto &c : controls) {
			if (c.type != oid) continue;
			decode_options options;
			options.memory = mr;
			auto e = decode_read_entry(c, options);
			if (!e) return std::unexpected(std::move(e.error()));
			return std::optional<entry>(entry::from(std::move(*e)));
		}
		return std::optional<entry>{};
	}

}// namespace

result<control> to_control(const request_control &c, std::pmr::memory_resource *mr)
{
	return std::visit(
	  [mr](const auto &v) -> result<control> {
		  using T = std::decay_t<decltype(v)>;
		  const control::allocator_type alloc(mr);
		  if constexpr (std::is_same_v<T, control>) {
			  return control(v, alloc);
		  } else if constexpr (std::is_same_v<T, paged>) {
			  return encode_paged_results(paged_results(v.page_size, v.cookie, alloc), v.critical, mr);
		  } else if constexpr (std::is_same_v<T, manage_dsa_it>) {
			  return control(manage_dsa_it_oid, v.critical, std::nullopt, alloc);
		  } else if constexpr (std::is_same_v<T, server_side_sort>) {
			  return encode_sort(v, mr);
		  } else if constexpr (std::is_same_v<T, assertion>) {
			  // controlValue is the Filter itself (RFC 4528 section 3).
			  ber::writer w{ ber::writer::allocator_type(mr) };
			  auto ok = encode_filter(w, v.filter);
			  if (!ok) {
				  auto e = std::move(ok.error());
				  e.context.insert(0, e.context.empty() ? "assertion" : "assertion: ");
				  return std::unexpected(std::move(e));
			  }
			  return value_control(assertion_oid, v.critical, w, alloc);
		  } else if constexpr (std::is_same_v<T, pre_read>) {
			  return encode_selection(pre_read_oid, v.attributes, v.critical, mr);
		  } else if constexpr (std::is_same_v<T, post_read>) {
			  return encode_selection(post_read_oid, v.attributes, v.critical, mr);
		  } else {
			  static_assert(std::is_same_v<T, proxied_authorization>);
			  // controlValue is the authzId itself, not BER (RFC 4370 section 3).
			  return control(proxied_authorization_oid, true, v.authz_id, alloc);
		  }
	  },
	  c);
}

result<void> append_controls(const request_controls &controls, std::pmr::vector<control> &out)
{
	for (const auto &c : controls) {
		auto wire = to_control(c, out.get_allocator().resource());
		if (!wire) return std::unexpected(std::move(wire.error()));
		out.push_back(std::move(*wire));
	}
	return {};
}

result<std::optional<paged_results>> find_paged(const std::pmr::vector<control> &controls,
  std::pmr::memory_resource *mr)
{
	for (const auto &c : controls) {
		if (c.type != paged_results_oid) continue;
		auto p = decode_paged_results(c, mr);
		if (!p) return std::unexpected(std::move(p.error()));
		return std::optional<paged_results>(std::move(*p));
	}
	return std::optional<paged_results>{};
}

result<std::optional<sort_result>> find_sort_result(const std::pmr::vector<control> &controls,
  std::pmr::memory_resource *mr)
{
	for (const auto &c : controls) {
		if (c.type != sort_response_oid) continue;
		auto r = decode_sort_result(c, mr);
		if (!r) return std::unexpected(std::move(r.error()));
		return std::optional<sort_result>(std::move(*r));
	}
	return std::optional<sort_result>{};
}

result<std::optional<entry>> find_pre_read(const std::pmr::vector<control> &controls, std::pmr::memory_resource *mr)
{
	return find_read_entry(controls, pre_read_oid, mr);
}

result<std::optional<entry>> find_post_read(const std::pmr::vector<control> &controls, std::pmr::memory_resource *mr)
{
	return find_read_entry(controls, post_read_oid, mr);
}

}// namespace jhetz::ldap
