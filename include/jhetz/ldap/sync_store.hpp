// ldap::store (store.hpp) and ldap::load_schema (directory.hpp) for the
// blocking facade: the same operations, on a sync::connection, a
// sync::client or a sync lease, blocking the calling thread. Each runs the
// async operation with sync::run (sync.hpp).
//
//   ldap::sync::store people(pool, ldap::dn{"ou=people,dc=example,dc=org"}, ldap::named_by<&person::uid>);
//   ldap::result<std::optional<person>> p = people.get("jdoe");
#pragma once

#include "jhetz/ldap/directory.hpp"
#include "jhetz/ldap/store.hpp"
#include "jhetz/ldap/sync.hpp"

#include <cstdint>
#include <memory_resource>
#include <optional>
#include <string_view>
#include <utility>
#include <vector>

namespace jhetz::ldap::sync {

// As ldap::load_schema: on a sync::client, ldap::load_schema(client &)
// (both searches on one shared lease). The facade's own errors
// (not_connected, would_deadlock) have the context "load schema" too.
template<directory D> [[nodiscard]] auto load_schema(D &d) -> result<server_schema>
{
	auto r = sync::run(d, [](auto &a) { return ldap::load_schema(a); });
	if (!r && (r.error().code == client_errc::would_deadlock || r.error().code == client_errc::not_connected)
		&& !std::string_view(r.error().context).starts_with(ldap::detail::load_schema_context)) {
		return std::unexpected(ldap::detail::with_context(std::move(r.error()), ldap::detail::load_schema_context));
	}
	return r;
}

// As ldap::store, blocking: each operation runs the async store's on the
// I/O thread. The source must outlive the store. One store may be used
// from several threads at once.
template<auto Naming, directory D> class store
{
	using core = ldap::detail::store_core<Naming>;
	using codec = ldap::detail::store_codec<Naming>;

  public:
	using value_type = core::value_type;
	using key_type = core::key_type;
	using source_type = D;

	store(D &source, dn base, named_by_t<Naming> /*naming*/, store_options options = {})
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
	  const store<Naming, Other> &other,
	  const modify_dn_controls &controls = {}) -> result<response>
	{
		return move(key, other.base(), controls);
	}

	[[nodiscard]] auto search(filter f = filters::attr("objectClass").present(),
	  search_scope scope = search_scope::single_level) -> result<typed_search_result<record<value_type>>>
	{
		return sync::run(*source_, [&](auto &a) { return core_.search(a, std::move(f), scope); });
	}
	// As search(), in pages of `page_size` entries, every page collected
	// (sync::search_paged): the records of every page, the last page's
	// result. No stream: the blocking facade has none (sync.hpp).
	[[nodiscard]] auto search_paged(std::int32_t page_size,
	  filter f = filters::attr("objectClass").present(),
	  search_scope scope = search_scope::single_level) -> result<typed_search_result<record<value_type>>>
	{
		return sync::run(*source_, [&](auto &a) { return collect_records(core_, a, page_size, std::move(f), scope); });
	}

  private:
	template<class A>
	static auto collect_records(core &c, A &a, std::int32_t page_size, filter f, search_scope scope)
	  -> boost::capy::task<result<typed_search_result<record<value_type>>>>
	{
		auto request = co_await c.search_request(a, std::move(f), scope);
		if (!request) {
			co_return std::unexpected(std::move(request.error()));
		}
		auto found =
		  co_await detail::collect_paged(a, std::move(*request), page_size, std::pmr::get_default_resource());
		co_return codec::search_result_of(std::move(found), c.base());
	}

	D *source_;
	core core_;
};

}// namespace jhetz::ldap::sync
