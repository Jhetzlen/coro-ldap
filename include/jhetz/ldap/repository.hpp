// Typed CRUD over a directory: the entries of one mapped struct under a
// base DN, each named by one member (docs/API.md, DESIGN.md section 4).
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

// The member whose value names a repository's entries.
template<auto Naming> struct named_by_t
{
	explicit constexpr named_by_t() = default;
};
template<auto Naming> inline constexpr named_by_t<Naming> named_by{};

// The single-valued member repository::update_if asserts instead of every
// mapped value.
template<auto Version> struct versioned_by_t
{
	explicit constexpr versioned_by_t() = default;
};
template<auto Version> inline constexpr versioned_by_t<Version> versioned_by{};

// When a repository checks its struct against the server's schema.
enum class schema_check {
	off,
	// The first operation loads the schema and validates the struct; a
	// mismatch fails every operation with schema_mismatch. Rechecked after
	// StartTLS or a SASL security layer.
	on_first_use,
};

struct repository_options
{
	ldap::schema_check schema_check = ldap::schema_check::off;
};

// An entry a repository's search found: its DN, as sent, and its value.
template<class T> struct record
{
	ldap::dn dn{};
	T value{};

	friend auto operator==(const record &, const record &) -> bool = default;
};

namespace detail {

	// `e` decoded as T; schema_mismatch when `e` holds an attribute T maps
	// under no name.
	template<class T> [[nodiscard]] auto decode_requested(const entry &e) -> result<T>
	{
		static constexpr auto names = attribute_name_array<T>();
		if (auto unrequested = unrequested_attribute_error(e, names)) {
			return std::unexpected(std::move(*unrequested));
		}
		return decode<T>(e);
	}

	// `e` decoded as T, with its DN parsed; errors name a search of `base`.
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

	struct every_mapped_value
	{
	};

	[[nodiscard]] inline auto has_assertion(const modify_controls &controls) -> bool
	{
		return std::ranges::any_of(controls, [](const auto &c) {
			const auto *raw = std::get_if<control>(&c);
			return std::holds_alternative<assertion>(c) || (raw != nullptr && raw->type == assertion_oid);
		});
	}

	// Whether T fits the schema, and whether update_if's default guard can
	// succeed on it.
	struct schema_outcome
	{
		result<void> fits{};
		result<void> guardable{};
	};

	// The requests and results of a repository, without the I/O.
	template<auto Naming> struct repository_codec
	{
		using value_type = member_pointer<decltype(Naming)>::owner;
		using field_type = std::remove_cvref_t<decltype(field_of<Naming>())>;
		using key_type = field_type::member;

		static_assert(field_type::kind == cardinality::required,
		  "ldap::named_by: the naming member must be single-valued and required (not std::optional or std::vector)");
		static_assert(!field_of<Naming>().read_only, "ldap::named_by: the naming member must not be read_only");

		[[nodiscard]] static auto name() -> const char * { return field_of<Naming>().name; }

		// <naming attribute>=<key>.
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

		// nullopt for no entry, or none of T's object classes; a limit code with
		// no entry is an error.
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

		// The modify turning `original` into `changed`, nullopt when nothing
		// differs; naming_value_changed when the naming member differs.
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
			  "ldap::versioned_by: the version member must be a member of the repository's struct");
			return unchanged_filter<Version>(original);
		}

		// update_request with an Assertion control on `original`.
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

		// Renames `from` to `to` under `base`, removing the old RDN's value.
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

		// Moves `key` from `base` to `new_base`, keeping its RDN.
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

		// The entries decoded; the first that does not decode fails the call.
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
				.controls = std::move(found->controls),
				.referrals = std::move(found->referrals),
				.unlisted = found->unlisted };
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


		// validate<T>'s outcome as schema_mismatch, and no_equality_rule for
		// update_if's default guard.
		[[nodiscard]] static auto check(const server_schema &s) -> schema_outcome
		{
			const schema_report report = validate<value_type>(s);
			if (!report.ok()) {
				return { .fits = std::unexpected(schema_mismatch(typeid(value_type).name(), report)), .guardable = {} };
			}
			for (const auto &i : report.issues) {
				if (i.what == schema_issue::kind::no_equality_rule) {
					return { .fits = {},
						.guardable = std::unexpected(make_error(client_errc::no_equality_rule,
						  "attribute " + i.name
							+ ": no equality rule, an assertion on it is always Undefined (use ldap::versioned_by)")) };
				}
			}
			return {};
		}
	};

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

	// A schema-check outcome and the protection it was made under, behind a
	// lock.
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

		[[nodiscard]] auto find(source_protection now) const -> std::optional<schema_outcome>
		{
			const std::scoped_lock lock(mutex_);
			if (!outcome_ || under_ != now) {
				return std::nullopt;
			}
			return outcome_;
		}
		void record(const schema_outcome &outcome, source_protection now)
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
		std::optional<schema_outcome> outcome_{};
		source_protection under_{};
	};

}// namespace detail

// The entries of a streamed or paged search, each decoded as a record<T>.
// An entry that does not decode ends the stream with that error.
template<class T, class Stream> class record_stream
{
  public:
	record_stream() = default;
	record_stream(Stream entries, dn base) : entries_(std::move(entries)), base_(std::move(base)) {}

	// The next record, nullopt at the end, or an error.
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

	// A repository's state and its operations over a source given to each call.
	template<auto Naming> class repository_core
	{
		using codec = repository_codec<Naming>;

	  public:
		using value_type = codec::value_type;
		using key_type = codec::key_type;

		repository_core(dn base, repository_options options) : base_(std::move(base)), options_(options) {}

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
			co_return co_await send_checked(
			  s, codec::add_request(base_, value, controls), [](S &d, add_params p) { return d.add(std::move(p)); });
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
			co_return co_await send_checked(s,
			  codec::modify_request(std::move(entry), std::move(changes), std::move(controls)),
			  [](S &d, modify_params p) { return d.modify(std::move(p)); });
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
			co_return co_await send_update(s,
			  codec::update_if_request(std::move(entry), original, changed, guard, std::move(controls)),
			  std::same_as<Guard, every_mapped_value>);
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
			co_return co_await send_checked(s,
			  result<del_params>(del_params{ .entry = std::move(entry), .controls = std::move(controls) }),
			  [](S &d, del_params p) { return d.del(std::move(p)); });
		}

		template<directory S>
		auto rename(S &s, key_type from, key_type to, modify_dn_controls controls)
		  -> boost::capy::task<result<response>>
		{
			co_return co_await send_checked(s, codec::rename_request(base_, from, to, controls), modify_dn_of<S>);
		}
		template<directory S>
		auto move(S &s, key_type key, dn new_base, modify_dn_controls controls) -> boost::capy::task<result<response>>
		{
			co_return co_await send_checked(s, codec::move_request(base_, key, new_base, controls), modify_dn_of<S>);
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

		// What search() sends, once the schema check passed.
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
		template<directory S> static auto modify_dn_of(S &d, modify_dn_params p) -> boost::capy::task<result<response>>
		{
			return d.modify_dn(std::move(p));
		}

		// Sends `request` with `send(s, request)` once the schema check passed.
		template<directory S, class Params, class Send>
		auto send_checked(S &s, result<Params> request, Send send) -> boost::capy::task<result<response>>
		{
			if (!request) {
				co_return std::unexpected(std::move(request.error()));
			}
			if (auto c = co_await check_schema(s); !c) {
				co_return std::unexpected(std::move(c.error()));
			}
			co_return co_await send(s, std::move(*request));
		}

		// Sends `request` once the schema check passed; nullopt sends nothing.
		template<directory S>
		auto send_update(S &s, result<std::optional<modify_params>> request, bool default_guard = false)
		  -> boost::capy::task<result<std::optional<response>>>
		{
			if (!request) {
				co_return std::unexpected(std::move(request.error()));
			}
			if (!*request) {
				co_return std::optional<response>{};
			}
			auto c = co_await check_schema(s);
			if (!c) {
				co_return std::unexpected(std::move(c.error()));
			}
			if (default_guard && !c->guardable) {
				co_return std::unexpected(
				  with_context(std::move(c->guardable.error()), op_context("modify", (*request)->object)));
			}
			auto done = co_await s.modify(std::move(**request));
			if (!done) {
				co_return std::unexpected(std::move(done.error()));
			}
			co_return std::optional<response>(std::move(*done));
		}

		// The schema check's outcome, or its schema_mismatch or load error.
		template<directory S> auto check_schema(S &s) -> boost::capy::task<result<schema_outcome>>
		{
			if (options_.schema_check == ldap::schema_check::off) {
				co_return schema_outcome{};
			}
			const source_protection now = protection_of(s);
			auto known = checked_.find(now);
			if (!known) {
				auto schema = co_await load_schema(s);
				if (!schema) {
					co_return std::unexpected(std::move(schema.error()));
				}
				known = codec::check(*schema);
				checked_.record(*known, now);
			}
			if (!known->fits) {
				co_return std::unexpected(std::move(known->fits.error()));
			}
			co_return std::move(*known);
		}

		dn base_;
		repository_options options_;
		schema_check_cache checked_{};
	};

}// namespace detail

// The entries of the struct owning `Naming` under `base`. The tasks refer
// to *this and to the source: both must outlive them.
template<auto Naming, directory D> class repository
{
	using core = detail::repository_core<Naming>;

  public:
	using value_type = core::value_type;
	using key_type = core::key_type;
	using source_type = D;

	repository(D &source, dn base, named_by_t<Naming> /*naming*/, repository_options options = {})
	  : source_(&source), core_(std::move(base), options)
	{}

	[[nodiscard]] auto source() const noexcept -> D & { return *source_; }
	[[nodiscard]] auto base() const noexcept -> const dn & { return core_.base(); }

	// <naming attribute>=<key>,<base>.
	[[nodiscard]] auto dn_of(const key_type &key) const -> result<dn> { return core_.dn_of(key); }

	// nullopt when there is no entry (or none of T's object classes).
	auto get(key_type key) -> boost::capy::task<result<std::optional<value_type>>>
	{
		return core_.get(*source_, std::move(key));
	}
	auto get_at(dn entry) -> boost::capy::task<result<std::optional<value_type>>>
	{
		return core_.get_at(*source_, std::move(entry));
	}

	// Adds `value` at dn_of(its naming member).
	auto add(value_type value, add_controls controls = {}) -> boost::capy::task<result<response>>
	{
		return core_.add(*source_, std::move(value), std::move(controls));
	}

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

	// One modify turning `original` into `changed`; nullopt, nothing sent,
	// when no member differs.
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

	// update() with an Assertion control (RFC 4528) on `original`; fails with
	// errc::assertion_failed if the entry changed.
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

	auto remove(key_type key, del_controls controls = {}) -> boost::capy::task<result<response>>
	{
		return core_.remove(*source_, std::move(key), std::move(controls));
	}
	auto remove_at(dn entry, del_controls controls = {}) -> boost::capy::task<result<response>>
	{
		return core_.remove_at(*source_, std::move(entry), std::move(controls));
	}

	// Renames `from` to `to` (deleteoldrdn TRUE).
	auto rename(key_type from, key_type to, modify_dn_controls controls = {}) -> boost::capy::task<result<response>>
	{
		return core_.rename(*source_, std::move(from), std::move(to), std::move(controls));
	}

	// Moves the entry under `new_base`, keeping its RDN.
	auto move(key_type key, dn new_base, modify_dn_controls controls = {}) -> boost::capy::task<result<response>>
	{
		return core_.move(*source_, std::move(key), std::move(new_base), std::move(controls));
	}
	// Moves the entry under `other`'s base; runs on this repository's source.
	template<directory Other>
	auto move(key_type key, const repository<Naming, Other> &other, modify_dn_controls controls = {})
	  -> boost::capy::task<result<response>>
	{
		return move(std::move(key), other.base(), std::move(controls));
	}

	// The entries of T's object classes matching `f` under the base.
	auto search(filter f = filters::attr("objectClass").present(), search_scope scope = search_scope::whole_subtree)
	  -> boost::capy::task<result<typed_search_result<record<value_type>>>>
	{
		return core_.search(*source_, std::move(f), scope);
	}

	auto search_stream(filter f = filters::attr("objectClass").present(),
	  search_scope scope = search_scope::whole_subtree)
	  -> boost::capy::task<result<record_stream<value_type, ldap::search_stream>>>
	{
		return core_.search_stream(*source_, std::move(f), scope);
	}

	auto search_paged(std::int32_t page_size,
	  filter f = filters::attr("objectClass").present(),
	  search_scope scope = search_scope::whole_subtree)
	  -> boost::capy::task<result<record_stream<value_type, ldap::paged_search>>>
	{
		return core_.search_paged(*source_, page_size, std::move(f), scope);
	}

  private:
	D *source_;
	core core_;
};

}// namespace jhetz::ldap
