// Typed CRUD over a directory (DESIGN.md section 4): the entries of one
// mapped struct (mapping.hpp) under a base DN, each named by one member.
//
//   ldap::store people(conn, ldap::dn{"ou=people,dc=example,dc=org"}, ldap::named_by<&person::uid>);
//   co_await people.add(person{.uid = "jdoe", ...});         // uid=jdoe,ou=people,dc=example,dc=org
//   auto p = co_await people.get("jdoe");                    // result<std::optional<person>>
//   co_await people.modify("jdoe", {ldap::replace<&person::mail>("j@example.org")});
//   auto all = co_await people.search(ldap::filters::field<&person::mail>().present());
//   co_await people.remove("jdoe");
//
// The source is any ldap::directory (directory.hpp): an ldap::connection,
// an ldap::client, or a shared lease's connection (*lease). The store only
// calls its public operations, one request per call (two more, once, for
// the schema check), and keeps no entries.
#pragma once

#include "jhetz/ldap/controls.hpp"
#include "jhetz/ldap/directory.hpp"
#include "jhetz/ldap/dn.hpp"
#include "jhetz/ldap/error.hpp"
#include "jhetz/ldap/filter.hpp"
#include "jhetz/ldap/mapping.hpp"
#include "jhetz/ldap/operations.hpp"
#include "jhetz/ldap/sasl.hpp"
#include "jhetz/ldap/schema.hpp"

#include <boost/capy/task.hpp>

#include <concepts>
#include <optional>
#include <string>
#include <type_traits>
#include <typeinfo>
#include <utility>
#include <vector>

namespace jhetz::ldap {

// The member whose value names a store's entries: ldap::named_by<&person::uid>.
template<auto Naming> struct named_by_t
{
	explicit constexpr named_by_t() = default;
};
template<auto Naming> inline constexpr named_by_t<Naming> named_by{};

// When a store checks its struct against the server's schema (DESIGN.md
// section 6).
enum class schema_check {
	off,
	// The first operation loads the schema (load_schema) and checks the
	// struct against it (validate<T>); a mismatch fails that operation and
	// every later one with schema_mismatch (the report in the context),
	// before anything is sent. A schema that does not load fails the
	// operation and is tried again by the next one. On a source that
	// reports is_tls() and security_layer() (a connection), a check made
	// before StartTLS or a SASL security layer is made again (RFC 4513
	// sections 3.1.5 and 5.2.1.6: what was read unprotected is read again).
	// On a client, the schema is read on one pooled connection (both
	// searches on one shared lease, see load_schema(client &)) and the
	// outcome holds for every operation of the store, whichever server it
	// runs on: every server of the pool must serve the same schema. For a
	// check per connection, use a lease's connection (*lease) as the
	// source.
	on_first_use,
};

struct store_options
{
	ldap::schema_check schema_check = ldap::schema_check::off;
};

// An entry a store's search found: its DN, as the server sent it, and its
// value.
template<class T> struct record
{
	ldap::dn dn{};
	T value{};

	friend auto operator==(const record &, const record &) -> bool = default;
};

namespace detail {

	// The requests and results of a store, without the I/O: shared by
	// ldap::store and sync::store.
	template<auto Naming> struct store_codec
	{
		using value_type = member_pointer<decltype(Naming)>::owner;
		using field_type = std::remove_cvref_t<decltype(field_of<Naming>())>;
		using key_type = field_type::member;

		static_assert(field_type::kind == cardinality::required,
		  "ldap::named_by: the naming member must be single-valued and required (not std::optional or std::vector)");
		static_assert(!field_of<Naming>().read_only, "ldap::named_by: the naming member must not be read_only");

		[[nodiscard]] static auto name() -> const char * { return field_of<Naming>().name; }

		[[nodiscard]] static auto dn_of(const dn &base, const key_type &key) -> result<dn>
		{
			auto value = encode_value(key);
			if (!value) {
				return std::unexpected(with_context(std::move(value.error()), std::string("attribute ") + name()));
			}
			return base.child(rdn{ ava{ attribute::unchecked(name()), *value } });
		}

		[[nodiscard]] static auto get_request(const dn &entry) -> search_params
		{
			return { .base = entry,
				.scope = search_scope::base_object,
				.filter = narrow_filter<value_type>(filters::attr("objectClass").present()),
				.attributes = attribute_names<value_type>() };
		}

		// No entry, or no entry of T's object classes: nullopt. A limit code
		// with no entry is an error.
		[[nodiscard]] static auto get_result(result<search_result> found, const dn &entry)
		  -> result<std::optional<value_type>>
		{
			if (!found) {
				if (found.error().code == errc::no_such_object) {
					return std::optional<value_type>{};
				}
				return std::unexpected(std::move(found.error()));
			}
			if (found->entries.empty()) {
				if (!found->is_success()) {
					return std::unexpected(search_error(*found, op_context("search", entry)));
				}
				return std::optional<value_type>{};
			}
			auto v = decode<value_type>(found->entries.front());
			if (!v) {
				return std::unexpected(with_context(std::move(v.error()), op_context("search", entry)));
			}
			return std::optional<value_type>(std::move(*v));
		}

		[[nodiscard]] static auto add_request(const dn &base, const value_type &value, const add_controls &controls)
		  -> result<add_params>
		{
			auto entry = dn_of(base, value.*Naming);
			if (!entry) {
				return std::unexpected(with_context(std::move(entry.error()), "add"));
			}
			auto attributes = to_attributes(value);
			if (!attributes) {
				return std::unexpected(with_context(std::move(attributes.error()), op_context("add", *entry)));
			}
			return add_params{ .entry = std::move(*entry), .attributes = std::move(*attributes), .controls = controls };
		}

		[[nodiscard]] static auto modify_request(dn entry,
		  std::vector<change<value_type>> changes,
		  modify_controls controls) -> result<modify_params>
		{
			modify_params p{ .object = std::move(entry), .controls = std::move(controls) };
			p.changes.reserve(changes.size());
			for (auto &c : changes) {
				if (!c.wire) {
					return std::unexpected(with_context(std::move(c.wire.error()), op_context("modify", p.object)));
				}
				p.changes.push_back(std::move(*c.wire));
			}
			return p;
		}

		// An empty filter (a typed filter whose value did not encode) fails
		// with invalid_filter.
		[[nodiscard]] static auto search_request(const dn &base, filter f, search_scope scope) -> result<search_params>
		{
			if (f.empty()) {
				return std::unexpected(
				  with_context(make_error(client_errc::invalid_filter, "filter: empty"), op_context("search", base)));
			}
			return search_params{ .base = base,
				.scope = scope,
				.filter = narrow_filter<value_type>(std::move(f)),
				.attributes = attribute_names<value_type>() };
		}

		// The entries decoded, on the limit codes too; the first entry that
		// does not decode, or whose DN does not parse, fails the call.
		[[nodiscard]] static auto search_result_of(result<search_result> found, const dn &base)
		  -> result<typed_search_result<record<value_type>>>
		{
			if (!found) {
				return std::unexpected(std::move(found.error()));
			}
			typed_search_result<record<value_type>> out{ .references = std::move(found->references),
				.result_code = found->result_code,
				.matched_dn = std::move(found->matched_dn),
				.diagnostic_message = std::move(found->diagnostic_message),
				.controls = std::move(found->controls) };
			out.entries.reserve(found->entries.size());
			for (const auto &e : found->entries) {
				auto name = dn::parse(e.dn);
				if (!name) {
					return std::unexpected(with_context(std::move(name.error()), op_context("search", base)));
				}
				auto v = decode<value_type>(e);
				if (!v) {
					return std::unexpected(with_context(std::move(v.error()), op_context("search", base)));
				}
				out.entries.push_back({ .dn = std::move(*name), .value = std::move(*v) });
			}
			return out;
		}

		[[nodiscard]] static auto check(const server_schema &s) -> result<void>
		{
			const schema_report report = validate<value_type>(s);
			if (!report.ok()) {
				return std::unexpected(schema_mismatch(typeid(value_type).name(), report));
			}
			return {};
		}
	};

	// The protection of a store's source, when it reports one.
	struct source_protection
	{
		bool tls = false;
		sasl_protection layer = sasl_protection::none;

		friend auto operator==(const source_protection &, const source_protection &) -> bool = default;
	};
	template<class D> [[nodiscard]] auto protection_of(const D &d) -> source_protection
	{
		if constexpr (requires {
						  { d.is_tls() } -> std::convertible_to<bool>;
						  { d.security_layer() } -> std::convertible_to<sasl_protection>;
					  }) {
			return { .tls = d.is_tls(), .layer = d.security_layer() };
		} else {
			return {};
		}
	}

}// namespace detail

// The entries of `T` (the struct owning `Naming`) under `base`, each named
// <naming attribute>=<value>,<base>. Every operation is a task that refers
// to *this and to the source: both must outlive it. Not thread-safe: use it
// on the source's executor.
template<auto Naming, directory D> class store
{
	using codec = detail::store_codec<Naming>;

  public:
	using value_type = codec::value_type;
	using key_type = codec::key_type;
	using source_type = D;

	store(D &source, dn base, named_by_t<Naming> /*naming*/, store_options options = {})
	  : source_(&source), base_(std::move(base)), options_(options)
	{}

	[[nodiscard]] auto source() const noexcept -> D & { return *source_; }
	[[nodiscard]] auto base() const noexcept -> const dn & { return base_; }

	// <naming attribute>=<key>,<base>. Fails with the key's encode error.
	[[nodiscard]] auto dn_of(const key_type &key) const -> result<dn> { return codec::dn_of(base_, key); }

	// The entry named `key` (or at `entry`), read with a base-object search
	// for T's attributes and object classes. nullopt when there is none
	// (noSuchObject, or an entry that is not of T's object classes); a
	// limit code with no entry is an error.
	auto get(key_type key) -> boost::capy::task<result<std::optional<value_type>>>
	{
		auto entry = dn_of(key);
		if (!entry) {
			co_return std::unexpected(detail::with_context(std::move(entry.error()), "search"));
		}
		co_return co_await get_at(std::move(*entry));
	}
	auto get_at(dn entry) -> boost::capy::task<result<std::optional<value_type>>>
	{
		if (auto c = co_await check_schema(); !c) {
			co_return std::unexpected(std::move(c.error()));
		}
		auto found = co_await source_->search(codec::get_request(entry));
		co_return codec::get_result(std::move(found), entry);
	}

	// Adds `value` at dn_of(value's naming member), with to_attributes(value).
	auto add(value_type value, add_controls controls = {}) -> boost::capy::task<result<response>>
	{
		auto request = codec::add_request(base_, value, controls);
		if (!request) {
			co_return std::unexpected(std::move(request.error()));
		}
		if (auto c = co_await check_schema(); !c) {
			co_return std::unexpected(std::move(c.error()));
		}
		co_return co_await source_->add(std::move(*request));
	}

	// Applies `changes` (ldap::replace / add / remove<&T::member>) to the
	// entry named `key` (or at `entry`).
	auto modify(key_type key, std::vector<change<value_type>> changes, modify_controls controls = {})
	  -> boost::capy::task<result<response>>
	{
		auto entry = dn_of(key);
		if (!entry) {
			co_return std::unexpected(detail::with_context(std::move(entry.error()), "modify"));
		}
		co_return co_await modify_at(std::move(*entry), std::move(changes), std::move(controls));
	}
	auto modify_at(dn entry, std::vector<change<value_type>> changes, modify_controls controls = {})
	  -> boost::capy::task<result<response>>
	{
		auto request = codec::modify_request(std::move(entry), std::move(changes), std::move(controls));
		if (!request) {
			co_return std::unexpected(std::move(request.error()));
		}
		if (auto c = co_await check_schema(); !c) {
			co_return std::unexpected(std::move(c.error()));
		}
		co_return co_await source_->modify(std::move(*request));
	}

	// Deletes the entry named `key` (or at `entry`).
	auto remove(key_type key, del_controls controls = {}) -> boost::capy::task<result<response>>
	{
		auto entry = dn_of(key);
		if (!entry) {
			co_return std::unexpected(detail::with_context(std::move(entry.error()), "delete"));
		}
		co_return co_await remove_at(std::move(*entry), std::move(controls));
	}
	auto remove_at(dn entry, del_controls controls = {}) -> boost::capy::task<result<response>>
	{
		if (auto c = co_await check_schema(); !c) {
			co_return std::unexpected(std::move(c.error()));
		}
		co_return co_await source_->del({ .entry = std::move(entry), .controls = std::move(controls) });
	}

	// The entries of T's object classes matching `f` under the base
	// (single_level: its children), with their DNs; entries named otherwise
	// are returned too. A value on the limit codes, as search() (the
	// entries received). An empty filter fails with invalid_filter before
	// anything is sent.
	auto search(filter f = filters::attr("objectClass").present(), search_scope scope = search_scope::single_level)
	  -> boost::capy::task<result<typed_search_result<record<value_type>>>>
	{
		auto request = codec::search_request(base_, std::move(f), scope);
		if (!request) {
			co_return std::unexpected(std::move(request.error()));
		}
		if (auto c = co_await check_schema(); !c) {
			co_return std::unexpected(std::move(c.error()));
		}
		auto found = co_await source_->search(std::move(*request));
		co_return codec::search_result_of(std::move(found), base_);
	}

  private:
	auto check_schema() -> boost::capy::task<result<void>>
	{
		if (options_.schema_check == ldap::schema_check::off) {
			co_return result<void>{};
		}
		const detail::source_protection now = detail::protection_of(*source_);
		if (!checked_ || checked_under_ != now) {
			auto s = co_await load_schema(*source_);
			if (!s) {
				co_return std::unexpected(std::move(s.error()));
			}
			checked_ = codec::check(*s);
			checked_under_ = now;
		}
		co_return *checked_;
	}

	D *source_;
	dn base_;
	store_options options_;
	std::optional<result<void>> checked_{};
	detail::source_protection checked_under_{};
};

}// namespace jhetz::ldap
