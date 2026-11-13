// ldap::repository and ldap::load_schema for the blocking facades, run with
// sync::run.
#pragma once

#include "jhetz/ldap/directory.hpp"
#include "jhetz/ldap/repository.hpp"
#include "jhetz/ldap/sync.hpp"

#include <cstdint>
#include <memory_resource>
#include <optional>
#include <string_view>
#include <utility>
#include <vector>

namespace jhetz::ldap::sync {

template<directory D> [[nodiscard]] auto load_schema(D &d) -> result<server_schema>
{
	auto r = sync::run(d, [](auto &a) { return ldap::load_schema(a); });
	if (!r && (r.error().code == client_errc::would_deadlock || r.error().code == client_errc::not_connected)
		&& !std::string_view(r.error().context).starts_with(ldap::detail::load_schema_context)) {
		return std::unexpected(ldap::detail::with_context(std::move(r.error()), ldap::detail::load_schema_context));
	}
	return r;
}

// ldap::repository, blocking. The source must outlive the repository.
template<auto Naming, directory D> class repository
{
	using core = ldap::detail::repository_core<Naming>;
	using codec = ldap::detail::repository_codec<Naming>;

  public:
	using value_type = core::value_type;
	using key_type = core::key_type;
	using source_type = D;

	repository(D &source, dn base, named_by_t<Naming> /*naming*/, repository_options options = {})
	  : source_(&source), core_(std::move(base), options)
	{}

	[[nodiscard]] auto source() const noexcept -> D & { return *source_; }
	[[nodiscard]] auto base() const noexcept -> const dn & { return core_.base(); }
	[[nodiscard]] auto dn_of(const key_type &key) const -> result<dn> { return core_.dn_of(key); }

	[[nodiscard]] auto get(const key_type &key) -> result<std::optional<value_type>>
	{
		return sync::run(*source_, [&](auto &a) { return core_.get(a, key); });
	}
	[[nodiscard]] auto get_at(const dn &entry) -> result<std::optional<value_type>>
	{
		return sync::run(*source_, [&](auto &a) { return core_.get_at(a, entry); });
	}

	[[nodiscard]] auto add(const value_type &value, const add_controls &controls = {}) -> result<response>
	{
		return sync::run(*source_, [&](auto &a) { return core_.add(a, value, controls); });
	}

	[[nodiscard]] auto modify(const key_type &key,
	  std::vector<change<value_type>> changes,
	  modify_controls controls = {}) -> result<response>
	{
		return sync::run(
		  *source_, [&](auto &a) { return core_.modify(a, key, std::move(changes), std::move(controls)); });
	}
	[[nodiscard]] auto modify_at(dn entry, std::vector<change<value_type>> changes, modify_controls controls = {})
	  -> result<response>
	{
		return sync::run(*source_,
		  [&](auto &a) { return core_.modify_at(a, std::move(entry), std::move(changes), std::move(controls)); });
	}

	[[nodiscard]] auto update(const record<value_type> &original,
	  const value_type &changed,
	  modify_controls controls = {}) -> result<std::optional<response>>
	{
		return sync::run(*source_,
		  [&](auto &a) { return core_.update_at(a, original.dn, original.value, changed, std::move(controls)); });
	}
	[[nodiscard]] auto update(const value_type &original, const value_type &changed, modify_controls controls = {})
	  -> result<std::optional<response>>
	{
		return sync::run(*source_, [&](auto &a) { return core_.update(a, original, changed, std::move(controls)); });
	}

	[[nodiscard]] auto update_if(const record<value_type> &original,
	  const value_type &changed,
	  modify_controls controls = {}) -> result<std::optional<response>>
	{
		return update_if_at(original, changed, ldap::detail::every_mapped_value{}, std::move(controls));
	}
	[[nodiscard]] auto update_if(const value_type &original, const value_type &changed, modify_controls controls = {})
	  -> result<std::optional<response>>
	{
		return update_if_key(original, changed, ldap::detail::every_mapped_value{}, std::move(controls));
	}
	template<auto Version>
	[[nodiscard]] auto update_if(const record<value_type> &original,
	  const value_type &changed,
	  versioned_by_t<Version> version,
	  modify_controls controls = {}) -> result<std::optional<response>>
	{
		return update_if_at(original, changed, version, std::move(controls));
	}
	template<auto Version>
	[[nodiscard]] auto update_if(const value_type &original,
	  const value_type &changed,
	  versioned_by_t<Version> version,
	  modify_controls controls = {}) -> result<std::optional<response>>
	{
		return update_if_key(original, changed, version, std::move(controls));
	}

	[[nodiscard]] auto remove(const key_type &key, const del_controls &controls = {}) -> result<response>
	{
		return sync::run(*source_, [&](auto &a) { return core_.remove(a, key, controls); });
	}
	[[nodiscard]] auto remove_at(const dn &entry, const del_controls &controls = {}) -> result<response>
	{
		return sync::run(*source_, [&](auto &a) { return core_.remove_at(a, entry, controls); });
	}

	[[nodiscard]] auto rename(const key_type &from, const key_type &to, const modify_dn_controls &controls = {})
	  -> result<response>
	{
		return sync::run(*source_, [&](auto &a) { return core_.rename(a, from, to, controls); });
	}
	[[nodiscard]] auto move(const key_type &key, const dn &new_base, const modify_dn_controls &controls = {})
	  -> result<response>
	{
		return sync::run(*source_, [&](auto &a) { return core_.move(a, key, new_base, controls); });
	}
	template<directory Other>
	[[nodiscard]] auto move(const key_type &key,
	  const repository<Naming, Other> &other,
	  const modify_dn_controls &controls = {}) -> result<response>
	{
		return move(key, other.base(), controls);
	}

	[[nodiscard]] auto search(filter f = filters::attr("objectClass").present(),
	  search_scope scope = search_scope::single_level) -> result<typed_search_result<record<value_type>>>
	{
		return sync::run(*source_, [&](auto &a) { return core_.search(a, std::move(f), scope); });
	}
	// search() in pages, every page collected.
	[[nodiscard]] auto search_paged(std::int32_t page_size,
	  filter f = filters::attr("objectClass").present(),
	  search_scope scope = search_scope::single_level) -> result<typed_search_result<record<value_type>>>
	{
		return sync::run(*source_, [&](auto &a) { return collect_records(core_, a, page_size, std::move(f), scope); });
	}

  private:
	template<class Guard>
	auto
	  update_if_at(const record<value_type> &original, const value_type &changed, Guard guard, modify_controls controls)
		-> result<std::optional<response>>
	{
		return sync::run(*source_, [&](auto &a) {
			return core_.update_if_at(a, original.dn, original.value, changed, guard, std::move(controls));
		});
	}
	template<class Guard>
	auto update_if_key(const value_type &original, const value_type &changed, Guard guard, modify_controls controls)
	  -> result<std::optional<response>>
	{
		return sync::run(
		  *source_, [&](auto &a) { return core_.update_if(a, original, changed, guard, std::move(controls)); });
	}

	template<class A>
	static auto collect_records(core &c, A &a, std::int32_t page_size, filter f, search_scope scope)
	  -> boost::capy::task<result<typed_search_result<record<value_type>>>>
	{
		auto request = co_await c.search_request(a, std::move(f), scope);
		if (!request) {
			co_return std::unexpected(std::move(request.error()));
		}
		auto found = co_await detail::collect_paged(
		  a, std::move(*request), page_size, search_paged_default_max_pages, std::pmr::get_default_resource());
		co_return codec::search_result_of(std::move(found), c.base());
	}

	D *source_;
	core core_;
};

}// namespace jhetz::ldap::sync
