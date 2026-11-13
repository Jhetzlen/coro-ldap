#include "jhetz/ldap/ad/ranged_values.hpp"

#include "jhetz/ldap/ad/range.hpp"
#include "jhetz/ldap/attribute.hpp"
#include "jhetz/ldap/directory.hpp"
#include "jhetz/ldap/operations.hpp"

#include <boost/capy/task.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <iterator>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

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

	// The attribute description to ask for, `type` from value `low` on;
	// `plain` asks for the first window without a range.
	auto selector(const request &r, std::string_view type, std::uint32_t low, bool plain) -> std::string
	{
		if (r.options.step == 0 || (plain && low == 0)) {
			return low == 0 ? std::string(type) : with_range(type, { .low = low });
		}
		constexpr auto top = std::uint64_t{ std::numeric_limits<std::uint32_t>::max() };
		const auto high = std::min(top, std::uint64_t{ low } + r.options.step - 1);
		return with_range(type, { .low = low, .high = static_cast<std::uint32_t>(high) });
	}

	struct answer
	{
		attribute_values *values = nullptr;
		std::optional<ranged_description> ranged{};
	};

	struct returned
	{
		attribute_values *values = nullptr;
		std::optional<ranged_description> ranged{};

		[[nodiscard]] auto base() const -> std::string_view
		{
			return ranged ? std::string_view(ranged->type) : std::string_view(values->type.name());
		}
	};

	// The attribute of `e` answering a request for `type`: the group named
	// `type` (descriptions without the range option), else the only group;
	// values nullptr when the entry has none.
	auto find_answer(entry &e, std::string_view type, const request &r) -> result<answer>
	{
		std::vector<returned> all;
		all.reserve(e.attributes.size());
		for (auto &a : e.attributes) {
			auto ranged = parse_range(a.type.name());
			if (!ranged) {
				return std::unexpected(detail::with_context(std::move(ranged.error()), r.context));
			}
			all.push_back({ .values = &a, .ranged = std::move(*ranged) });
		}
		if (all.empty()) {
			return answer{};
		}
		const auto named = [&](std::string_view base) {
			return [base](const returned &x) { return detail::iequals(x.base(), base); };
		};
		std::string_view group = type;
		if (std::ranges::none_of(all, named(type))) {
			group = all.front().base();
			if (!std::ranges::all_of(all, named(group))) {
				return fail(client_errc::unexpected_response,
				  r.context + ": none of the attributes returned is " + std::string(type));
			}
		}
		returned *ranged = nullptr;
		const returned *plain = nullptr;
		std::size_t ranged_count = 0;
		std::size_t plain_count = 0;
		for (auto &x : all) {
			if (!named(group)(x)) {
				continue;
			}
			if (x.ranged) {
				ranged = &x;
				++ranged_count;
			} else {
				plain = &x;
				++plain_count;
			}
		}
		if (ranged_count == 1 && (plain_count == 0 || (plain_count == 1 && plain->values->values.empty()))) {
			return answer{ .values = ranged->values, .ranged = std::move(ranged->ranged) };
		}
		if (ranged_count == 0 && plain_count == 1) {
			return answer{ .values = plain->values };
		}
		return fail(
		  client_errc::unexpected_response, r.context + ": several attributes returned answer " + std::string(type));
	}

	// Moves the values of `type` (plain or ranged from `low`) to `out` and sets
	// `type` to the server's name; the next window's low bound, or nullopt.
	auto take(entry &e, const request &r, std::string &type, std::uint32_t low, string_list &out)
	  -> result<std::optional<std::uint32_t>>
	{
		auto found = find_answer(e, type, r);
		if (!found) {
			return std::unexpected(std::move(found.error()));
		}
		if (found->values == nullptr) {
			return std::optional<std::uint32_t>{};
		}
		auto &values = found->values->values;
		const auto append = [&] {
			out.insert(out.end(), std::make_move_iterator(values.begin()), std::make_move_iterator(values.end()));
		};
		if (!found->ranged) {
			if (low != 0) {
				return fail(client_errc::unexpected_response,
				  r.context + ": the attribute without a range after the values up to " + std::to_string(low - 1));
			}
			append();
			return std::optional<std::uint32_t>{};
		}
		const value_range got = found->ranged->range;
		if (got.low != low) {
			return fail(client_errc::unexpected_response,
			  r.context + ": asked for the values from " + std::to_string(low) + ", got "
				+ std::string(found->values->type.name()));
		}
		append();
		type = std::move(found->ranged->type);
		if (!got.high || *got.high == std::numeric_limits<std::uint32_t>::max()) {
			return std::optional<std::uint32_t>{};
		}
		return std::optional<std::uint32_t>(*got.high + 1);
	}

	auto read(connection &c, const request &r) -> capy::task<result<string_list>>
	{
		string_list out(r.mr);
		std::string type = r.attribute;
		std::optional<std::uint32_t> low = 0;
		bool plain = false;
		while (low) {
			search_params query{ .base = r.object, .scope = search_scope::base_object };
			query.attributes.emplace_back(selector(r, type, *low, plain));
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
			auto next = take(found->entries.front(), r, type, *low, out);
			if (!next) {
				co_return std::unexpected(std::move(next.error()));
			}
			if (r.options.step != 0 && *low == 0 && !*next && out.empty() && !plain) {
				plain = true;
				continue;
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
