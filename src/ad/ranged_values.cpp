#include "jhetz/ldap/ad/ranged_values.hpp"

#include "jhetz/ldap/ad/range.hpp"
#include "jhetz/ldap/attribute.hpp"
#include "jhetz/ldap/directory.hpp"
#include "jhetz/ldap/operations.hpp"

#include <boost/capy/task.hpp>

#include <algorithm>
#include <cstdint>
#include <iterator>
#include <limits>
#include <optional>
#include <string>
#include <system_error>
#include <utility>

namespace capy = boost::capy;

namespace jhetz::ldap::ad {

namespace {

	struct request
	{
		dn object;
		std::string attribute;
		range_options options;
		std::pmr::memory_resource *mr;
		std::string context;
	};

	auto prepare(dn object, std::string attribute, range_options options, std::pmr::memory_resource *mr)
	  -> result<request>
	{
		std::string context = detail::op_context("read all values of " + attribute, object);
		if (attribute.empty()) {
			return fail(std::make_error_code(std::errc::invalid_argument), context + ": no attribute");
		}
		if (auto r = parse_range(attribute); !r || *r) {
			return fail(std::make_error_code(std::errc::invalid_argument),
			  context + ": the attribute has a range option of its own");
		}
		return request{ .object = std::move(object),
			.attribute = std::move(attribute),
			.options = options,
			.mr = mr,
			.context = std::move(context) };
	}

	// The attribute description to ask for, from value `low` on.
	auto selector(const request &r, std::uint32_t low) -> std::string
	{
		if (r.options.step == 0) {
			return low == 0 ? r.attribute : with_range(r.attribute, { .low = low });
		}
		constexpr auto top = std::uint64_t{ std::numeric_limits<std::uint32_t>::max() };
		const auto high = std::min(top, std::uint64_t{ low } + r.options.step - 1);
		return with_range(r.attribute, { .low = low, .high = static_cast<std::uint32_t>(high) });
	}

	// Moves the values of `r.attribute` in `e` (plain or ranged from `low`)
	// to `out`. The next window's low bound, or nullopt once complete.
	auto take(entry &e, const request &r, std::uint32_t low, string_list &out) -> result<std::optional<std::uint32_t>>
	{
		const auto append = [&](std::pmr::vector<std::pmr::string> &values) {
			out.insert(out.end(), std::make_move_iterator(values.begin()), std::make_move_iterator(values.end()));
		};
		for (auto &a : e.attributes) {
			const std::string_view name = a.type.name();
			if (detail::iequals(name, r.attribute)) {
				if (low != 0) {
					return fail(client_errc::unexpected_response,
					  r.context + ": the attribute without a range after the values up to " + std::to_string(low - 1));
				}
				append(a.values);
				return std::optional<std::uint32_t>{};
			}
			auto ranged = parse_range(name);
			if (!ranged) {
				return std::unexpected(detail::with_context(std::move(ranged.error()), r.context));
			}
			if (!*ranged || !detail::iequals((*ranged)->type, r.attribute)) {
				continue;
			}
			const value_range got = (*ranged)->range;
			if (got.low != low) {
				return fail(client_errc::unexpected_response,
				  r.context + ": asked for the values from " + std::to_string(low) + ", got " + std::string(name));
			}
			append(a.values);
			if (!got.high || *got.high == std::numeric_limits<std::uint32_t>::max()) {
				return std::optional<std::uint32_t>{};
			}
			return std::optional<std::uint32_t>(*got.high + 1);
		}
		return std::optional<std::uint32_t>{};
	}

	auto read(connection &c, const request &r) -> capy::task<result<string_list>>
	{
		string_list out(r.mr);
		std::optional<std::uint32_t> low = 0;
		while (low) {
			search_params query{ .base = r.object, .scope = search_scope::base_object };
			query.attributes.emplace_back(selector(r, *low));
			auto found = co_await c.search(std::move(query), r.mr);
			if (!found) {
				co_return std::unexpected(detail::with_context(std::move(found.error()), r.context));
			}
			if (!found->is_success()) {
				co_return std::unexpected(detail::search_error(*found, r.context));
			}
			if (found->entries.empty()) {
				co_return fail(client_errc::unexpected_response, r.context + ": no entry returned");
			}
			auto next = take(found->entries.front(), r, *low, out);
			if (!next) {
				co_return std::unexpected(std::move(next.error()));
			}
			low = *next;
		}
		co_return out;
	}

	auto run(connection &c, result<request> r) -> capy::task<result<string_list>>
	{
		if (!r) {
			co_return std::unexpected(std::move(r.error()));
		}
		co_return co_await read(c, *r);
	}

	// `first` and `retry` are acquire() tasks of the same client: `retry`
	// runs only after cond::connection_lost on the first lease.
	auto run(capy::task<result<lease>> first, capy::task<result<lease>> retry, result<request> r)
	  -> capy::task<result<string_list>>
	{
		if (!r) {
			co_return std::unexpected(std::move(r.error()));
		}
		{
			auto l = co_await std::move(first);
			if (!l) {
				co_return std::unexpected(std::move(l.error()));
			}
			auto values = co_await read(l->get(), *r);
			if (values || values.error().code != cond::connection_lost) {
				co_return values;
			}
		}
		auto l = co_await std::move(retry);
		if (!l) {
			co_return std::unexpected(std::move(l.error()));
		}
		co_return co_await read(l->get(), *r);
	}

}// namespace

auto read_all_values(connection &c,
  dn object,
  std::string attribute,
  range_options options,
  std::pmr::memory_resource *mr) -> capy::task<result<string_list>>
{
	return run(c, prepare(std::move(object), std::move(attribute), options, mr));
}

auto read_all_values(client &pool,
  dn object,
  std::string attribute,
  range_options options,
  std::pmr::memory_resource *mr) -> capy::task<result<string_list>>
{
	return run(pool.acquire(), pool.acquire(), prepare(std::move(object), std::move(attribute), options, mr));
}

}// namespace jhetz::ldap::ad
