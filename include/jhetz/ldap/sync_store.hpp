// ldap::store (store.hpp) and ldap::load_schema (directory.hpp) for the
// blocking facade: the same operations, on a sync::connection, a
// sync::client or a sync lease, blocking the calling thread.
//
//   ldap::sync::store people(pool, ldap::dn{"ou=people,dc=example,dc=org"}, ldap::named_by<&person::uid>);
//   ldap::result<std::optional<person>> p = people.get("jdoe");
#pragma once

#include "jhetz/ldap/store.hpp"
#include "jhetz/ldap/sync.hpp"

#include <concepts>
#include <optional>
#include <utility>
#include <vector>

namespace jhetz::ldap::sync {

// ldap::directory, blocking: sync::connection, sync::client, sync::lease
// and sync::exclusive_lease satisfy it.
template<class D>
concept directory = requires(D &d, search_params s, add_params a, modify_params m, del_params r, modify_dn_params n) {
	{ d.search(std::move(s)) } -> std::same_as<result<search_result>>;
	{ d.add(std::move(a)) } -> std::same_as<result<response>>;
	{ d.modify(std::move(m)) } -> std::same_as<result<response>>;
	{ d.del(std::move(r)) } -> std::same_as<result<response>>;
	{ d.modify_dn(std::move(n)) } -> std::same_as<result<response>>;
};

// As ldap::load_schema.
template<directory D> [[nodiscard]] auto load_schema(D &d) -> result<server_schema>
{
	auto sub = ldap::detail::subschema_request(d.search(root_dse({ "subschemaSubentry" })));
	if (!sub) {
		return std::unexpected(std::move(sub.error()));
	}
	return ldap::detail::subschema_of(d.search(std::move(sub->request)), sub->where);
}

// As ldap::load_schema on an ldap::client: both searches on one shared
// lease, run once more on a new lease after cond::connection_lost.
[[nodiscard]] auto load_schema(client &c) -> result<server_schema>;

// As ldap::store, blocking. The source must outlive the store. One store
// may be used from several threads at once.
template<auto Naming, directory D> class store
{
	using codec = ldap::detail::store_codec<Naming>;

  public:
	using value_type = codec::value_type;
	using key_type = codec::key_type;
	using source_type = D;

	store(D &source, dn base, named_by_t<Naming> /*naming*/, store_options options = {})
	  : source_(&source), base_(std::move(base)), options_(options)
	{}

	[[nodiscard]] auto source() const noexcept -> D & { return *source_; }
	[[nodiscard]] auto base() const noexcept -> const dn & { return base_; }
	[[nodiscard]] auto dn_of(const key_type &key) const -> result<dn> { return codec::dn_of(base_, key); }

	[[nodiscard]] auto get(const key_type &key) -> result<std::optional<value_type>>
	{
		auto entry = dn_of(key);
		if (!entry) {
			return std::unexpected(ldap::detail::with_context(std::move(entry.error()), "search"));
		}
		return get_at(std::move(*entry));
	}
	[[nodiscard]] auto get_at(const dn &entry) -> result<std::optional<value_type>>
	{
		if (auto c = check_schema(); !c) {
			return std::unexpected(std::move(c.error()));
		}
		return codec::get_result(source_->search(codec::get_request(entry)), entry);
	}

	[[nodiscard]] auto add(const value_type &value, const add_controls &controls = {}) -> result<response>
	{
		auto request = codec::add_request(base_, value, controls);
		if (!request) {
			return std::unexpected(std::move(request.error()));
		}
		if (auto c = check_schema(); !c) {
			return std::unexpected(std::move(c.error()));
		}
		return source_->add(std::move(*request));
	}

	[[nodiscard]] auto modify(const key_type &key,
	  std::vector<change<value_type>> changes,
	  modify_controls controls = {}) -> result<response>
	{
		auto entry = dn_of(key);
		if (!entry) {
			return std::unexpected(ldap::detail::with_context(std::move(entry.error()), "modify"));
		}
		return modify_at(std::move(*entry), std::move(changes), std::move(controls));
	}
	[[nodiscard]] auto modify_at(dn entry, std::vector<change<value_type>> changes, modify_controls controls = {})
	  -> result<response>
	{
		auto request = codec::modify_request(std::move(entry), std::move(changes), std::move(controls));
		if (!request) {
			return std::unexpected(std::move(request.error()));
		}
		if (auto c = check_schema(); !c) {
			return std::unexpected(std::move(c.error()));
		}
		return source_->modify(std::move(*request));
	}

	[[nodiscard]] auto remove(const key_type &key, const del_controls &controls = {}) -> result<response>
	{
		auto entry = dn_of(key);
		if (!entry) {
			return std::unexpected(ldap::detail::with_context(std::move(entry.error()), "delete"));
		}
		return remove_at(*entry, controls);
	}
	[[nodiscard]] auto remove_at(const dn &entry, const del_controls &controls = {}) -> result<response>
	{
		if (auto c = check_schema(); !c) {
			return std::unexpected(std::move(c.error()));
		}
		return source_->del({ .entry = entry, .controls = controls });
	}

	[[nodiscard]] auto search(filter f = filters::attr("objectClass").present(),
	  search_scope scope = search_scope::single_level) -> result<typed_search_result<record<value_type>>>
	{
		auto request = codec::search_request(base_, std::move(f), scope);
		if (!request) {
			return std::unexpected(std::move(request.error()));
		}
		if (auto c = check_schema(); !c) {
			return std::unexpected(std::move(c.error()));
		}
		return codec::search_result_of(source_->search(std::move(*request)), base_);
	}

  private:
	auto check_schema() -> result<void>
	{
		if (options_.schema_check == ldap::schema_check::off) {
			return {};
		}
		const ldap::detail::source_protection now = ldap::detail::protection_of(*source_);
		if (auto known = checked_.find(now)) {
			return std::move(*known);
		}
		auto s = sync::load_schema(*source_);
		if (!s) {
			return std::unexpected(std::move(s.error()));
		}
		auto outcome = codec::check(*s);
		checked_.record(outcome, now);
		return outcome;
	}

	D *source_;
	dn base_;
	store_options options_;
	ldap::detail::schema_check_cache checked_{};
};

}// namespace jhetz::ldap::sync
