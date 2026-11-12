// Typed CRUD over a directory (DESIGN.md section 4): the entries of one
// mapped struct (mapping.hpp) under a base DN, each named by one member.
//
//   ldap::store people(conn, ldap::dn{"ou=people,dc=example,dc=org"}, ldap::named_by<&person::uid>);
//   co_await people.add(person{.uid = "jdoe", ...});         // uid=jdoe,ou=people,dc=example,dc=org
//   auto p = co_await people.get("jdoe");                    // result<std::optional<person>>
//   co_await people.modify("jdoe", {ldap::replace<&person::mail>("j@example.org")});
//   person q = **p; q.mail = "john@example.org";
//   co_await people.update(**p, q);                          // the changed members only
//   co_await people.update_if(**p, q);                       // ... if the entry still has p's values
//   co_await people.rename("jdoe", "john");                  // uid=john,ou=people,dc=example,dc=org
//   auto all = co_await people.search(ldap::filters::field<&person::mail>().present());
//   auto pages = co_await people.search_paged(100);         // result<record_stream<person, paged_search>>
//   co_await people.remove("jdoe");
//
// The source is any ldap::directory (directory.hpp): an ldap::connection,
// an ldap::client, or a shared lease's connection (*lease). The store only
// calls its public operations, one request per call (one per page for
// search_paged; two more, once, for the schema check), and keeps no
// entries.
#pragma once

#include "jhetz/ldap/controls.hpp"
#include "jhetz/ldap/directory.hpp"
#include "jhetz/ldap/dn.hpp"
#include "jhetz/ldap/error.hpp"
#include "jhetz/ldap/filter.hpp"
#include "jhetz/ldap/mapping.hpp"
#include "jhetz/ldap/operations.hpp"
#include "jhetz/ldap/paged_search.hpp"
#include "jhetz/ldap/sasl.hpp"
#include "jhetz/ldap/schema.hpp"
#include "jhetz/ldap/search_stream.hpp"

#include <boost/capy/task.hpp>

#include <algorithm>
#include <concepts>
#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <type_traits>
#include <typeinfo>
#include <utility>
#include <variant>
#include <vector>

namespace jhetz::ldap {

// The member whose value names a store's entries: ldap::named_by<&person::uid>.
template<auto Naming> struct named_by_t
{
	explicit constexpr named_by_t() = default;
};
template<auto Naming> inline constexpr named_by_t<Naming> named_by{};

// The single-valued member store::update_if asserts instead of every mapped
// value: ldap::versioned_by<&person::entry_csn>.
template<auto Version> struct versioned_by_t
{
	explicit constexpr versioned_by_t() = default;
};
template<auto Version> inline constexpr versioned_by_t<Version> versioned_by{};

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

	// `e` decoded as T. Fails with schema_mismatch when `e` holds an
	// attribute T maps under no name (an alias, OID or supertype mapping that
	// the server answers under another name, RFC 4511 4.5.2).
	template<class T> [[nodiscard]] auto decode_requested(const entry &e) -> result<T>
	{
		static constexpr auto names = attribute_name_array<T>();
		if (auto unrequested = unrequested_attribute_error(e, names)) {
			return std::unexpected(std::move(*unrequested));
		}
		return decode<T>(e);
	}

	// `e` decoded as T, with its DN parsed; errors have the context of a
	// search of `base`.
	template<class T> [[nodiscard]] auto record_of(const entry &e, const dn &base) -> result<record<T>>
	{
		auto name = dn::parse(e.dn);
		if (!name) {
			return std::unexpected(with_context(std::move(name.error()), op_context("search", base)));
		}
		auto v = decode_requested<T>(e);
		if (!v) {
			return std::unexpected(with_context(std::move(v.error()), op_context("search", base)));
		}
		return record<T>{ .dn = std::move(*name), .value = std::move(*v) };
	}

	// store::update_if asserting every mapped value.
	struct every_mapped_value
	{
	};

	// Whether `controls` already has an Assertion control, typed or raw.
	[[nodiscard]] inline auto has_assertion(const modify_controls &controls) -> bool
	{
		return std::ranges::any_of(controls, [](const auto &c) {
			const auto *raw = std::get_if<control>(&c);
			return std::holds_alternative<assertion>(c) || (raw != nullptr && raw->type == assertion_oid);
		});
	}

	// The requests and results of a store, without the I/O (store_core).
	template<auto Naming> struct store_codec
	{
		using value_type = member_pointer<decltype(Naming)>::owner;
		using field_type = std::remove_cvref_t<decltype(field_of<Naming>())>;
		using key_type = field_type::member;

		static_assert(field_type::kind == cardinality::required,
		  "ldap::named_by: the naming member must be single-valued and required (not std::optional or std::vector)");
		static_assert(!field_of<Naming>().read_only, "ldap::named_by: the naming member must not be read_only");

		[[nodiscard]] static auto name() -> const char * { return field_of<Naming>().name; }

		// <naming attribute>=<key>. Fails with the key's encode error.
		[[nodiscard]] static auto rdn_of(const key_type &key) -> result<rdn>
		{
			auto value = encode_value(key);
			if (!value) {
				return std::unexpected(with_context(std::move(value.error()), std::string("attribute ") + name()));
			}
			return rdn{ ava{ attribute::unchecked(name()), *value } };
		}

		[[nodiscard]] static auto dn_of(const dn &base, const key_type &key) -> result<dn>
		{
			auto name = rdn_of(key);
			if (!name) {
				return std::unexpected(std::move(name.error()));
			}
			return base.child(std::move(*name));
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
			auto v = decode_requested<value_type>(found->entries.front());
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

		// The modify turning `original` into `changed` at `entry` (diff),
		// nullopt when nothing differs. A naming member that differs fails
		// with naming_value_changed.
		[[nodiscard]] static auto
		  update_request(dn entry, const value_type &original, const value_type &changed, modify_controls controls)
			-> result<std::optional<modify_params>>
		{
			auto from = encode_value(original.*Naming);
			auto to = encode_value(changed.*Naming);
			if (!from || !to) {
				return std::unexpected(with_context(
				  std::move(!from ? from.error() : to.error()), op_context("modify", entry) + ": attribute " + name()));
			}
			if (*from != *to) {
				return std::unexpected(
				  with_context(make_error(client_errc::naming_value_changed, std::string(name()) + ": use rename()"),
					op_context("modify", entry)));
			}
			auto changes = diff(original, changed);
			if (!changes) {
				return std::unexpected(with_context(std::move(changes.error()), op_context("modify", entry)));
			}
			if (changes->empty()) {
				return std::optional<modify_params>{};
			}
			auto request = modify_request(std::move(entry), std::move(*changes), std::move(controls));
			if (!request) {
				return std::unexpected(std::move(request.error()));
			}
			return std::optional<modify_params>(std::move(*request));
		}

		[[nodiscard]] static auto guard_filter(const value_type &original, every_mapped_value /*guard*/)
		  -> result<filter>
		{
			return unchanged_filter(original);
		}
		template<auto Version>
		[[nodiscard]] static auto guard_filter(const value_type &original, versioned_by_t<Version> /*guard*/)
		  -> result<filter>
		{
			static_assert(std::same_as<owner_of<Version>, value_type>,
			  "ldap::versioned_by: the version member must be a member of the store's struct");
			return unchanged_filter<Version>(original);
		}

		// update_request with an Assertion control on `original` (guard_filter).
		// An Assertion control already in `controls` fails with encode_error.
		template<class Guard>
		[[nodiscard]] static auto update_if_request(dn entry,
		  const value_type &original,
		  const value_type &changed,
		  Guard guard,
		  modify_controls controls) -> result<std::optional<modify_params>>
		{
			auto request = update_request(std::move(entry), original, changed, std::move(controls));
			if (!request || !*request) {
				return request;
			}
			modify_params &p = **request;
			if (has_assertion(p.controls)) {
				return std::unexpected(
				  with_context(make_error(client_errc::encode_error, "assertion: update_if sends its own"),
					op_context("modify", p.object)));
			}
			auto f = guard_filter(original, guard);
			if (!f) {
				return std::unexpected(with_context(std::move(f.error()), op_context("modify", p.object)));
			}
			p.controls.emplace_back(assertion{ .filter = std::move(*f) });
			return request;
		}

		// The modify DN renaming the entry named `from` to `to` under `base`:
		// the new RDN <naming attribute>=<to>, the old one's value removed.
		// NOLINTBEGIN(bugprone-easily-swappable-parameters): from, then to, as modify DN
		[[nodiscard]] static auto
		  rename_request(const dn &base, const key_type &from, const key_type &to, const modify_dn_controls &controls)
			-> result<modify_dn_params>
		{
			auto entry = dn_of(base, from);
			if (!entry) {
				return std::unexpected(with_context(std::move(entry.error()), "modify DN"));
			}
			auto name = rdn_of(to);
			if (!name) {
				return std::unexpected(with_context(std::move(name.error()), op_context("modify DN", *entry)));
			}
			return modify_dn_params{
				.entry = std::move(*entry), .new_rdn = std::move(*name), .delete_old_rdn = true, .controls = controls
			};
		}
		// NOLINTEND(bugprone-easily-swappable-parameters)

		// The modify DN moving the entry named `key` under `base` to
		// `new_base`, its RDN kept.
		[[nodiscard]] static auto
		  move_request(const dn &base, const key_type &key, const dn &new_base, const modify_dn_controls &controls)
			-> result<modify_dn_params>
		{
			auto name = rdn_of(key);
			if (!name) {
				return std::unexpected(with_context(std::move(name.error()), "modify DN"));
			}
			return modify_dn_params{ .entry = base.child(*name),
				.new_rdn = std::move(*name),
				.delete_old_rdn = true,
				.new_superior = new_base,
				.controls = controls };
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
				auto r = record_of<value_type>(e, base);
				if (!r) {
					return std::unexpected(std::move(r.error()));
				}
				out.entries.push_back(std::move(*r));
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

	// A store's schema-check outcome and the protection it was made under,
	// behind a lock: one store may be used from several threads.
	class schema_check_cache
	{
	  public:
		schema_check_cache() = default;
		schema_check_cache(const schema_check_cache &other) : schema_check_cache(other, std::scoped_lock(other.mutex_))
		{}
		schema_check_cache(schema_check_cache &&other) : schema_check_cache(other, std::scoped_lock(other.mutex_)) {}
		auto operator=(const schema_check_cache &other) -> schema_check_cache &
		{
			if (this != &other) {
				const std::scoped_lock lock(mutex_, other.mutex_);
				outcome_ = other.outcome_;
				under_ = other.under_;
			}
			return *this;
		}
		auto operator=(schema_check_cache &&other) -> schema_check_cache &
		{
			if (this != &other) {
				const std::scoped_lock lock(mutex_, other.mutex_);
				outcome_ = std::move(other.outcome_);
				under_ = other.under_;
			}
			return *this;
		}
		~schema_check_cache() = default;

		// The outcome recorded under `now`, if any.
		[[nodiscard]] auto find(source_protection now) const -> std::optional<result<void>>
		{
			const std::scoped_lock lock(mutex_);
			if (!outcome_ || under_ != now) {
				return std::nullopt;
			}
			return outcome_;
		}
		void record(const result<void> &outcome, source_protection now)
		{
			const std::scoped_lock lock(mutex_);
			outcome_ = outcome;
			under_ = now;
		}

	  private:
		schema_check_cache(const schema_check_cache &other, const std::scoped_lock<std::mutex> & /*held*/)
		  : outcome_(other.outcome_), under_(other.under_)
		{}

		mutable std::mutex mutex_;
		std::optional<result<void>> outcome_{};
		source_protection under_{};
	};

}// namespace detail

// The entries of a store's streamed or paged search (store::search_stream,
// store::search_paged), each decoded as a record<T>: `Stream` is
// ldap::search_stream or ldap::paged_search, whose rules apply (move-only,
// one next() at a time, not destroyed or moved while next() is suspended,
// destroyed before its end it abandons the search). As store::search(), an
// entry that does not decode, or whose DN does not parse, is an error: it
// ends the stream, and next() returns that error again from then on
// (destroying the stream abandons the search).
template<class T, class Stream> class record_stream
{
  public:
	record_stream() = default;
	record_stream(Stream entries, dn base) : entries_(std::move(entries)), base_(std::move(base)) {}

	// The next record, nullopt at the end, or an error: the search's (as
	// Stream::next()) or the entry's decode error, with the context
	// "search <base>".
	auto next() -> boost::capy::task<result<std::optional<record<T>>>>
	{
		if (failed_) {
			co_return std::unexpected(*failed_);
		}
		auto e = co_await entries_.next();
		if (!e) {
			co_return std::unexpected(std::move(e.error()));
		}
		if (!*e) {
			co_return std::optional<record<T>>{};
		}
		auto r = detail::record_of<T>(**e, base_);
		if (!r) {
			failed_ = r.error();
			co_return std::unexpected(std::move(r.error()));
		}
		co_return std::optional<record<T>>(std::move(*r));
	}

	// True once the search ended, or an entry did not decode.
	[[nodiscard]] auto done() const noexcept -> bool { return failed_.has_value() || entries_.done(); }
	// The underlying stream: its references(), controls(), pages().
	[[nodiscard]] auto stream() noexcept -> Stream & { return entries_; }
	[[nodiscard]] auto stream() const noexcept -> const Stream & { return entries_; }

  private:
	Stream entries_{};
	dn base_{};
	std::optional<error> failed_{};
};

namespace detail {

	// A store's base, options and schema-check outcome, and its operations
	// over a source given to each call: ldap::store runs them on its
	// source, sync::store on its facade's ldap::connection or ldap::client,
	// on the I/O thread. The tasks refer to *this and to the source.
	template<auto Naming> class store_core
	{
		using codec = store_codec<Naming>;

	  public:
		using value_type = codec::value_type;
		using key_type = codec::key_type;

		store_core(dn base, store_options options) : base_(std::move(base)), options_(options) {}

		[[nodiscard]] auto base() const noexcept -> const dn & { return base_; }
		[[nodiscard]] auto dn_of(const key_type &key) const -> result<dn> { return codec::dn_of(base_, key); }

		template<directory S> auto get(S &s, key_type key) -> boost::capy::task<result<std::optional<value_type>>>
		{
			auto entry = dn_of(key);
			if (!entry) {
				co_return std::unexpected(with_context(std::move(entry.error()), "search"));
			}
			co_return co_await get_at(s, std::move(*entry));
		}
		template<directory S> auto get_at(S &s, dn entry) -> boost::capy::task<result<std::optional<value_type>>>
		{
			if (auto c = co_await check_schema(s); !c) {
				co_return std::unexpected(std::move(c.error()));
			}
			auto found = co_await s.search(codec::get_request(entry));
			co_return codec::get_result(std::move(found), entry);
		}

		template<directory S>
		auto add(S &s, value_type value, add_controls controls) -> boost::capy::task<result<response>>
		{
			auto request = codec::add_request(base_, value, controls);
			if (!request) {
				co_return std::unexpected(std::move(request.error()));
			}
			if (auto c = co_await check_schema(s); !c) {
				co_return std::unexpected(std::move(c.error()));
			}
			co_return co_await s.add(std::move(*request));
		}

		template<directory S>
		auto modify(S &s, key_type key, std::vector<change<value_type>> changes, modify_controls controls)
		  -> boost::capy::task<result<response>>
		{
			auto entry = dn_of(key);
			if (!entry) {
				co_return std::unexpected(with_context(std::move(entry.error()), "modify"));
			}
			co_return co_await modify_at(s, std::move(*entry), std::move(changes), std::move(controls));
		}
		template<directory S>
		auto modify_at(S &s, dn entry, std::vector<change<value_type>> changes, modify_controls controls)
		  -> boost::capy::task<result<response>>
		{
			auto request = codec::modify_request(std::move(entry), std::move(changes), std::move(controls));
			if (!request) {
				co_return std::unexpected(std::move(request.error()));
			}
			if (auto c = co_await check_schema(s); !c) {
				co_return std::unexpected(std::move(c.error()));
			}
			co_return co_await s.modify(std::move(*request));
		}

		template<directory S>
		auto update(S &s, value_type original, value_type changed, modify_controls controls)
		  -> boost::capy::task<result<std::optional<response>>>
		{
			auto entry = dn_of(original.*Naming);
			if (!entry) {
				co_return std::unexpected(with_context(std::move(entry.error()), "modify"));
			}
			co_return co_await update_at(
			  s, std::move(*entry), std::move(original), std::move(changed), std::move(controls));
		}
		template<directory S>
		auto update_at(S &s, dn entry, value_type original, value_type changed, modify_controls controls)
		  -> boost::capy::task<result<std::optional<response>>>
		{
			co_return co_await send_update(
			  s, codec::update_request(std::move(entry), original, changed, std::move(controls)));
		}

		template<directory S, class Guard>
		auto update_if(S &s, value_type original, value_type changed, Guard guard, modify_controls controls)
		  -> boost::capy::task<result<std::optional<response>>>
		{
			auto entry = dn_of(original.*Naming);
			if (!entry) {
				co_return std::unexpected(with_context(std::move(entry.error()), "modify"));
			}
			co_return co_await update_if_at(
			  s, std::move(*entry), std::move(original), std::move(changed), guard, std::move(controls));
		}
		template<directory S, class Guard>
		auto
		  update_if_at(S &s, dn entry, value_type original, value_type changed, Guard guard, modify_controls controls)
			-> boost::capy::task<result<std::optional<response>>>
		{
			co_return co_await send_update(
			  s, codec::update_if_request(std::move(entry), original, changed, guard, std::move(controls)));
		}

		template<directory S>
		auto remove(S &s, key_type key, del_controls controls) -> boost::capy::task<result<response>>
		{
			auto entry = dn_of(key);
			if (!entry) {
				co_return std::unexpected(with_context(std::move(entry.error()), "delete"));
			}
			co_return co_await remove_at(s, std::move(*entry), std::move(controls));
		}
		template<directory S>
		auto remove_at(S &s, dn entry, del_controls controls) -> boost::capy::task<result<response>>
		{
			if (auto c = co_await check_schema(s); !c) {
				co_return std::unexpected(std::move(c.error()));
			}
			co_return co_await s.del({ .entry = std::move(entry), .controls = std::move(controls) });
		}

		template<directory S>
		auto rename(S &s, key_type from, key_type to, modify_dn_controls controls)
		  -> boost::capy::task<result<response>>
		{
			auto request = codec::rename_request(base_, from, to, controls);
			if (!request) {
				co_return std::unexpected(std::move(request.error()));
			}
			if (auto c = co_await check_schema(s); !c) {
				co_return std::unexpected(std::move(c.error()));
			}
			co_return co_await s.modify_dn(std::move(*request));
		}
		template<directory S>
		auto move(S &s, key_type key, dn new_base, modify_dn_controls controls) -> boost::capy::task<result<response>>
		{
			auto request = codec::move_request(base_, key, new_base, controls);
			if (!request) {
				co_return std::unexpected(std::move(request.error()));
			}
			if (auto c = co_await check_schema(s); !c) {
				co_return std::unexpected(std::move(c.error()));
			}
			co_return co_await s.modify_dn(std::move(*request));
		}

		template<directory S>
		auto search(S &s, filter f, search_scope scope)
		  -> boost::capy::task<result<typed_search_result<record<value_type>>>>
		{
			auto request = co_await search_request(s, std::move(f), scope);
			if (!request) {
				co_return std::unexpected(std::move(request.error()));
			}
			auto found = co_await s.search(std::move(*request));
			co_return codec::search_result_of(std::move(found), base_);
		}
		template<directory S>
		auto search_stream(S &s, filter f, search_scope scope)
		  -> boost::capy::task<result<record_stream<value_type, ldap::search_stream>>>
		{
			auto request = co_await search_request(s, std::move(f), scope);
			if (!request) {
				co_return std::unexpected(std::move(request.error()));
			}
			auto stream = co_await s.search_stream(std::move(*request));
			if (!stream) {
				co_return std::unexpected(std::move(stream.error()));
			}
			co_return record_stream<value_type, ldap::search_stream>(std::move(*stream), base_);
		}
		template<directory S>
		auto search_paged(S &s, std::int32_t page_size, filter f, search_scope scope)
		  -> boost::capy::task<result<record_stream<value_type, ldap::paged_search>>>
		{
			auto request = co_await search_request(s, std::move(f), scope);
			if (!request) {
				co_return std::unexpected(std::move(request.error()));
			}
			auto pages = co_await ldap::search_paged(s, std::move(*request), page_size);
			if (!pages) {
				co_return std::unexpected(std::move(pages.error()));
			}
			co_return record_stream<value_type, ldap::paged_search>(std::move(*pages), base_);
		}

		// The search of T's entries matching `f` under the base, once the
		// schema check passed: what search() sends.
		template<directory S>
		auto search_request(S &s, filter f, search_scope scope) -> boost::capy::task<result<search_params>>
		{
			auto request = codec::search_request(base_, std::move(f), scope);
			if (!request) {
				co_return std::unexpected(std::move(request.error()));
			}
			if (auto c = co_await check_schema(s); !c) {
				co_return std::unexpected(std::move(c.error()));
			}
			co_return std::move(*request);
		}

	  private:
		// Sends `request` once the schema check passed; nullopt sends nothing.
		template<directory S>
		auto send_update(S &s, result<std::optional<modify_params>> request)
		  -> boost::capy::task<result<std::optional<response>>>
		{
			if (!request) {
				co_return std::unexpected(std::move(request.error()));
			}
			if (!*request) {
				co_return std::optional<response>{};
			}
			if (auto c = co_await check_schema(s); !c) {
				co_return std::unexpected(std::move(c.error()));
			}
			auto done = co_await s.modify(std::move(**request));
			if (!done) {
				co_return std::unexpected(std::move(done.error()));
			}
			co_return std::optional<response>(std::move(*done));
		}

		template<directory S> auto check_schema(S &s) -> boost::capy::task<result<void>>
		{
			if (options_.schema_check == ldap::schema_check::off) {
				co_return result<void>{};
			}
			const source_protection now = protection_of(s);
			if (auto known = checked_.find(now)) {
				co_return std::move(*known);
			}
			auto schema = co_await load_schema(s);
			if (!schema) {
				co_return std::unexpected(std::move(schema.error()));
			}
			auto outcome = codec::check(*schema);
			checked_.record(outcome, now);
			co_return outcome;
		}

		dn base_;
		store_options options_;
		schema_check_cache checked_{};
	};

}// namespace detail

// The entries of `T` (the struct owning `Naming`) under `base`, each named
// <naming attribute>=<value>,<base>. Every operation is a task that refers
// to *this and to the source: both must outlive it. One store may be used
// from several threads at once, as its source (a connection, a client).
template<auto Naming, directory D> class store
{
	using core = detail::store_core<Naming>;

  public:
	using value_type = core::value_type;
	using key_type = core::key_type;
	using source_type = D;

	store(D &source, dn base, named_by_t<Naming> /*naming*/, store_options options = {})
	  : source_(&source), core_(std::move(base), options)
	{}

	[[nodiscard]] auto source() const noexcept -> D & { return *source_; }
	[[nodiscard]] auto base() const noexcept -> const dn & { return core_.base(); }

	// <naming attribute>=<key>,<base>. Fails with the key's encode error.
	[[nodiscard]] auto dn_of(const key_type &key) const -> result<dn> { return core_.dn_of(key); }

	// The entry named `key` (or at `entry`), read with a base-object search
	// for T's attributes and object classes. nullopt when there is none
	// (noSuchObject, or an entry that is not of T's object classes); a
	// limit code with no entry is an error.
	auto get(key_type key) -> boost::capy::task<result<std::optional<value_type>>>
	{
		return core_.get(*source_, std::move(key));
	}
	auto get_at(dn entry) -> boost::capy::task<result<std::optional<value_type>>>
	{
		return core_.get_at(*source_, std::move(entry));
	}

	// Adds `value` at dn_of(value's naming member), with to_attributes(value).
	auto add(value_type value, add_controls controls = {}) -> boost::capy::task<result<response>>
	{
		return core_.add(*source_, std::move(value), std::move(controls));
	}

	// Applies `changes` (ldap::replace / add / remove<&T::member>) to the
	// entry named `key` (or at `entry`).
	auto modify(key_type key, std::vector<change<value_type>> changes, modify_controls controls = {})
	  -> boost::capy::task<result<response>>
	{
		return core_.modify(*source_, std::move(key), std::move(changes), std::move(controls));
	}
	auto modify_at(dn entry, std::vector<change<value_type>> changes, modify_controls controls = {})
	  -> boost::capy::task<result<response>>
	{
		return core_.modify_at(*source_, std::move(entry), std::move(changes), std::move(controls));
	}

	// One modify turning `original` into `changed` (ldap::diff: only the
	// members T maps, read_only ones skipped; a member empty in `original`
	// written with replace, since empty in the struct is not absent on the
	// server: an attribute the reader may not see, RFC 4511 4.5.1.8), sent to
	// original.dn, or for a value, to dn_of(its naming member). nullopt, and
	// nothing sent (no schema check either), when no member differs. A changed naming member
	// fails with naming_value_changed before anything is sent: use rename().
	auto update(const record<value_type> &original, value_type changed, modify_controls controls = {})
	  -> boost::capy::task<result<std::optional<response>>>
	{
		return core_.update_at(*source_, original.dn, original.value, std::move(changed), std::move(controls));
	}
	auto update(const value_type &original, value_type changed, modify_controls controls = {})
	  -> boost::capy::task<result<std::optional<response>>>
	{
		return core_.update(*source_, original, std::move(changed), std::move(controls));
	}

	// update(), the modify carrying an Assertion control (RFC 4528) on
	// `original`: the server applies it only if the entry still matches,
	// else it fails with errc::assertion_failed (122). The filter is
	// ldap::unchanged_filter(original), true while every value of `original`
	// is still there (subtypes and tagged values included; added values are
	// not seen, so a value written meanwhile to a member empty in `original`
	// is overwritten), or with ldap::versioned_by<&T::m>, the exact check,
	// (m=<original's value>), which fails with missing_attribute before
	// anything is sent if `original` has none. Critical. nullopt, and nothing
	// sent, when no member differs. An Assertion control in `controls` fails
	// with encode_error before anything is sent, and so does, with
	// invalid_filter, a default filter past max_filter_elements (one element
	// per value): use ldap::versioned_by for such a struct.
	auto update_if(const record<value_type> &original, value_type changed, modify_controls controls = {})
	  -> boost::capy::task<result<std::optional<response>>>
	{
		return core_.update_if_at(
		  *source_, original.dn, original.value, std::move(changed), detail::every_mapped_value{}, std::move(controls));
	}
	auto update_if(const value_type &original, value_type changed, modify_controls controls = {})
	  -> boost::capy::task<result<std::optional<response>>>
	{
		return core_.update_if(
		  *source_, original, std::move(changed), detail::every_mapped_value{}, std::move(controls));
	}
	template<auto Version>
	auto update_if(const record<value_type> &original,
	  value_type changed,
	  versioned_by_t<Version> version,
	  modify_controls controls = {}) -> boost::capy::task<result<std::optional<response>>>
	{
		return core_.update_if_at(
		  *source_, original.dn, original.value, std::move(changed), version, std::move(controls));
	}
	template<auto Version>
	auto update_if(const value_type &original,
	  value_type changed,
	  versioned_by_t<Version> version,
	  modify_controls controls = {}) -> boost::capy::task<result<std::optional<response>>>
	{
		return core_.update_if(*source_, original, std::move(changed), version, std::move(controls));
	}

	// Deletes the entry named `key` (or at `entry`).
	auto remove(key_type key, del_controls controls = {}) -> boost::capy::task<result<response>>
	{
		return core_.remove(*source_, std::move(key), std::move(controls));
	}
	auto remove_at(dn entry, del_controls controls = {}) -> boost::capy::task<result<response>>
	{
		return core_.remove_at(*source_, std::move(entry), std::move(controls));
	}

	// Renames the entry named `from` to `to` (modify DN, RFC 4511 section
	// 4.9): the new RDN is <naming attribute>=<to> and the old RDN's value
	// is removed (deleteoldrdn TRUE), so the naming member reads `to`
	// afterwards. A key that does not encode fails before anything is sent.
	auto rename(key_type from, key_type to, modify_dn_controls controls = {}) -> boost::capy::task<result<response>>
	{
		return core_.rename(*source_, std::move(from), std::move(to), std::move(controls));
	}

	// Moves the entry named `key` under `new_base` (modify DN with
	// newSuperior), keeping its RDN: it is then named `key` in a store of
	// `new_base`.
	auto move(key_type key, dn new_base, modify_dn_controls controls = {}) -> boost::capy::task<result<response>>
	{
		return core_.move(*source_, std::move(key), std::move(new_base), std::move(controls));
	}
	// As above, under `other`'s base (a store of the same struct and naming
	// member, on any source); the request runs on this store's source.
	template<directory Other>
	auto move(key_type key, const store<Naming, Other> &other, modify_dn_controls controls = {})
	  -> boost::capy::task<result<response>>
	{
		return move(std::move(key), other.base(), std::move(controls));
	}

	// The entries of T's object classes matching `f` under the base
	// (single_level: its children), with their DNs; entries named otherwise
	// are returned too. A value on the limit codes, as search() (the
	// entries received). An empty filter fails with invalid_filter before
	// anything is sent.
	auto search(filter f = filters::attr("objectClass").present(), search_scope scope = search_scope::single_level)
	  -> boost::capy::task<result<typed_search_result<record<value_type>>>>
	{
		return core_.search(*source_, std::move(f), scope);
	}

	// search() read one entry at a time: the source's search_stream(), each
	// entry decoded by next() (see record_stream). On a client, the stream
	// holds a shared lease until destroyed (client::search_stream()).
	auto search_stream(filter f = filters::attr("objectClass").present(),
	  search_scope scope = search_scope::single_level)
	  -> boost::capy::task<result<record_stream<value_type, ldap::search_stream>>>
	{
		return core_.search_stream(*source_, std::move(f), scope);
	}

	// search() in pages of `page_size` entries: ldap::search_paged on the
	// source (paged_search.hpp; on a client, one shared lease for every
	// page), each entry decoded by next() (see record_stream).
	auto search_paged(std::int32_t page_size,
	  filter f = filters::attr("objectClass").present(),
	  search_scope scope = search_scope::single_level)
	  -> boost::capy::task<result<record_stream<value_type, ldap::paged_search>>>
	{
		return core_.search_paged(*source_, page_size, std::move(f), scope);
	}

  private:
	D *source_;
	core core_;
};

}// namespace jhetz::ldap
