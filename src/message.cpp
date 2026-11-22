#include "jhetz/ldap/message.hpp"

#include "control_util.hpp"
#include "filter_ast.hpp"
#include "format_util.hpp"
#include "message_codec.hpp"
#include "pmr_util.hpp"

#include <algorithm>
#include <limits>
#include <string>
#include <utility>

namespace jhetz::ldap {

// ---------------------------------------------------------------- constructors and assignment

using detail::assign_optional;
using detail::assign_variant;
using detail::control_value;
using detail::enter_value;
using detail::in_control;
using detail::next_is;
using detail::optional_string;
using detail::optional_with;
using detail::skip_rest;
using detail::variant_with;

namespace {

	auto strings(std::initializer_list<std::string_view> list, const string_list::allocator_type &alloc) -> string_list
	{
		// Each element built straight on `alloc`.
		return { list.begin(), list.end(), alloc };
	}

}// namespace

// Public API, RFC 4511 field order.
// NOLINTBEGIN(bugprone-easily-swappable-parameters)
ldap_result::ldap_result(std::int32_t result_code_,
  std::string_view matched_dn_,
  std::string_view diagnostic_message_,
  std::initializer_list<std::string_view> referral_,
  const allocator_type &alloc)
  // NOLINTEND(bugprone-easily-swappable-parameters)
  : result_code(result_code_), matched_dn(matched_dn_, alloc), diagnostic_message(diagnostic_message_, alloc),
	referral(strings(referral_, alloc))
{}

ldap_result::ldap_result(const ldap_result &other, const allocator_type &alloc)
  : result_code(other.result_code), matched_dn(other.matched_dn, alloc),
	diagnostic_message(other.diagnostic_message, alloc), referral(other.referral, alloc)
{}

ldap_result::ldap_result(ldap_result &&other, const allocator_type &alloc)
  : result_code(other.result_code), matched_dn(std::move(other.matched_dn), alloc),
	diagnostic_message(std::move(other.diagnostic_message), alloc), referral(std::move(other.referral), alloc)
{}

auto ldap_result::to_error(std::string_view context) const -> error
{
	// On the default resource (see error.hpp).
	error e;
	e.code = std::error_code(result_code, result_category());
	e.diagnostic.assign(diagnostic_message);
	if (!matched_dn.empty()) {
		e.matched_dn.emplace(matched_dn);
	}
	e.referrals.assign(referral.begin(), referral.end());
	e.context.assign(context);
	return e;
}

control::control(std::string_view type_,
  bool criticality_,
  std::optional<std::string_view> value_,
  const allocator_type &alloc)
  : type(type_, alloc), criticality(criticality_), value(optional_string(value_, alloc))
{}

control::control(const control &other, const allocator_type &alloc)
  : type(other.type, alloc), criticality(other.criticality), value(optional_with(other.value, alloc))
{}

control::control(control &&other, const allocator_type &alloc)
  : type(std::move(other.type), alloc), criticality(other.criticality),
	value(optional_with(std::move(other.value), alloc))
{}

auto control::operator=(const control &other) -> control &
{
	if (this == &other) {
		return *this;
	}
	type = other.type;
	criticality = other.criticality;
	assign_optional(value, other.value, get_allocator());
	return *this;
}

auto control::operator=(control &&other) -> control &
{
	type = std::move(other.type);
	criticality = other.criticality;
	assign_optional(value, std::move(other.value), get_allocator());
	return *this;
}

partial_attribute::partial_attribute(std::string_view type_,
  std::initializer_list<std::string_view> values_,
  const allocator_type &alloc)
  : type(type_, alloc), values(strings(values_, alloc))
{}

sasl_auth::sasl_auth(std::string_view mechanism_,
  std::optional<std::string_view> credentials_,
  const allocator_type &alloc)
  : mechanism(mechanism_, alloc), credentials(optional_string(credentials_, alloc))
{}

sasl_auth::sasl_auth(const sasl_auth &other, const allocator_type &alloc)
  : mechanism(other.mechanism, alloc), credentials(optional_with(other.credentials, alloc))
{}

sasl_auth::sasl_auth(sasl_auth &&other, const allocator_type &alloc)
  : mechanism(std::move(other.mechanism), alloc), credentials(optional_with(std::move(other.credentials), alloc))
{}

auto sasl_auth::operator=(const sasl_auth &other) -> sasl_auth &
{
	if (this == &other) {
		return *this;
	}
	mechanism = other.mechanism;
	assign_optional(credentials, other.credentials, get_allocator());
	return *this;
}

auto sasl_auth::operator=(sasl_auth &&other) -> sasl_auth &
{
	mechanism = std::move(other.mechanism);
	assign_optional(credentials, std::move(other.credentials), get_allocator());
	return *this;
}

bind_request::bind_request(std::int32_t version_,
  std::string_view name_,
  auth_type authentication_,
  const allocator_type &alloc)
  : version(version_), name(name_, alloc), authentication(variant_with(std::move(authentication_), alloc))
{}

bind_request::bind_request(const bind_request &other, const allocator_type &alloc)
  : version(other.version), name(other.name, alloc), authentication(variant_with(other.authentication, alloc))
{}

bind_request::bind_request(bind_request &&other, const allocator_type &alloc)
  : version(other.version), name(std::move(other.name), alloc),
	authentication(variant_with(std::move(other.authentication), alloc))
{}

auto bind_request::operator=(const bind_request &other) -> bind_request &
{
	if (this == &other) {
		return *this;
	}
	version = other.version;
	name = other.name;
	assign_variant(authentication, other.authentication, get_allocator());
	return *this;
}

auto bind_request::operator=(bind_request &&other) -> bind_request &
{
	version = other.version;
	name = std::move(other.name);
	assign_variant(authentication, std::move(other.authentication), get_allocator());
	return *this;
}

bind_response::bind_response(const ldap_result &result_,
  std::optional<std::string_view> server_sasl_creds_,
  const allocator_type &alloc)
  : result(result_, alloc), server_sasl_creds(optional_string(server_sasl_creds_, alloc))
{}

bind_response::bind_response(const bind_response &other, const allocator_type &alloc)
  : result(other.result, alloc), server_sasl_creds(optional_with(other.server_sasl_creds, alloc))
{}

bind_response::bind_response(bind_response &&other, const allocator_type &alloc)
  : result(std::move(other.result), alloc), server_sasl_creds(optional_with(std::move(other.server_sasl_creds), alloc))
{}

auto bind_response::operator=(const bind_response &other) -> bind_response &
{
	if (this == &other) {
		return *this;
	}
	result = other.result;
	assign_optional(server_sasl_creds, other.server_sasl_creds, get_allocator());
	return *this;
}

auto bind_response::operator=(bind_response &&other) -> bind_response &
{
	result = std::move(other.result);
	assign_optional(server_sasl_creds, std::move(other.server_sasl_creds), get_allocator());
	return *this;
}

search_request::search_request(const allocator_type &alloc)
  : base_object(alloc), filter(filters::attr("objectClass", alloc).present()), attributes(alloc)
{}

search_request::search_request(std::string_view base_object_,
  search_scope scope_,
  ldap::filter filter_,
  std::initializer_list<std::string_view> attributes_,
  const allocator_type &alloc)
  : base_object(base_object_, alloc), scope(scope_), filter(std::move(filter_), alloc),
	attributes(strings(attributes_, alloc))
{}

search_request::search_request(const search_request &other, const allocator_type &alloc)
  : base_object(other.base_object, alloc), scope(other.scope), deref(other.deref), size_limit(other.size_limit),
	time_limit(other.time_limit), types_only(other.types_only), filter(other.filter, alloc),
	attributes(other.attributes, alloc)
{}

search_request::search_request(search_request &&other, const allocator_type &alloc)
  : base_object(std::move(other.base_object), alloc), scope(other.scope), deref(other.deref),
	size_limit(other.size_limit), time_limit(other.time_limit), types_only(other.types_only),
	filter(std::move(other.filter), alloc), attributes(std::move(other.attributes), alloc)
{}

// Public API, RFC 4511 field order.
// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
modify_dn_request::modify_dn_request(std::string_view entry_,
  std::string_view new_rdn_,
  bool delete_old_rdn_,
  std::optional<std::string_view> new_superior_,
  const allocator_type &alloc)
  : entry(entry_, alloc), new_rdn(new_rdn_, alloc), delete_old_rdn(delete_old_rdn_),
	new_superior(optional_string(new_superior_, alloc))
{}

modify_dn_request::modify_dn_request(const modify_dn_request &other, const allocator_type &alloc)
  : entry(other.entry, alloc), new_rdn(other.new_rdn, alloc), delete_old_rdn(other.delete_old_rdn),
	new_superior(optional_with(other.new_superior, alloc))
{}

modify_dn_request::modify_dn_request(modify_dn_request &&other, const allocator_type &alloc)
  : entry(std::move(other.entry), alloc), new_rdn(std::move(other.new_rdn), alloc),
	delete_old_rdn(other.delete_old_rdn), new_superior(optional_with(std::move(other.new_superior), alloc))
{}

auto modify_dn_request::operator=(const modify_dn_request &other) -> modify_dn_request &
{
	if (this == &other) {
		return *this;
	}
	entry = other.entry;
	new_rdn = other.new_rdn;
	delete_old_rdn = other.delete_old_rdn;
	assign_optional(new_superior, other.new_superior, get_allocator());
	return *this;
}

auto modify_dn_request::operator=(modify_dn_request &&other) -> modify_dn_request &
{
	entry = std::move(other.entry);
	new_rdn = std::move(other.new_rdn);
	delete_old_rdn = other.delete_old_rdn;
	assign_optional(new_superior, std::move(other.new_superior), get_allocator());
	return *this;
}

extended_request::extended_request(std::string_view request_name_,
  std::optional<std::string_view> request_value_,
  const allocator_type &alloc)
  : request_name(request_name_, alloc), request_value(optional_string(request_value_, alloc))
{}

extended_request::extended_request(const extended_request &other, const allocator_type &alloc)
  : request_name(other.request_name, alloc), request_value(optional_with(other.request_value, alloc))
{}

extended_request::extended_request(extended_request &&other, const allocator_type &alloc)
  : request_name(std::move(other.request_name), alloc),
	request_value(optional_with(std::move(other.request_value), alloc))
{}

auto extended_request::operator=(const extended_request &other) -> extended_request &
{
	if (this == &other) {
		return *this;
	}
	request_name = other.request_name;
	assign_optional(request_value, other.request_value, get_allocator());
	return *this;
}

auto extended_request::operator=(extended_request &&other) -> extended_request &
{
	request_name = std::move(other.request_name);
	assign_optional(request_value, std::move(other.request_value), get_allocator());
	return *this;
}

// Public API, RFC 4511 field order.
// NOLINTBEGIN(bugprone-easily-swappable-parameters)
extended_response::extended_response(const ldap_result &result_,
  std::optional<std::string_view> response_name_,
  std::optional<std::string_view> response_value_,
  const allocator_type &alloc)
  // NOLINTEND(bugprone-easily-swappable-parameters)
  : result(result_, alloc), response_name(optional_string(response_name_, alloc)),
	response_value(optional_string(response_value_, alloc))
{}

extended_response::extended_response(const extended_response &other, const allocator_type &alloc)
  : result(other.result, alloc), response_name(optional_with(other.response_name, alloc)),
	response_value(optional_with(other.response_value, alloc))
{}

extended_response::extended_response(extended_response &&other, const allocator_type &alloc)
  : result(std::move(other.result), alloc), response_name(optional_with(std::move(other.response_name), alloc)),
	response_value(optional_with(std::move(other.response_value), alloc))
{}

auto extended_response::operator=(const extended_response &other) -> extended_response &
{
	if (this == &other) {
		return *this;
	}
	result = other.result;
	assign_optional(response_name, other.response_name, get_allocator());
	assign_optional(response_value, other.response_value, get_allocator());
	return *this;
}

auto extended_response::operator=(extended_response &&other) -> extended_response &
{
	result = std::move(other.result);
	assign_optional(response_name, std::move(other.response_name), get_allocator());
	assign_optional(response_value, std::move(other.response_value), get_allocator());
	return *this;
}

// Public API, RFC 4511 field order.
// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
intermediate_response::intermediate_response(std::optional<std::string_view> response_name_,
  std::optional<std::string_view> response_value_,
  const allocator_type &alloc)
  : response_name(optional_string(response_name_, alloc)), response_value(optional_string(response_value_, alloc)),
	alloc_(alloc)
{}

// A plain copy uses the default resource, like the pmr containers.
intermediate_response::intermediate_response(const intermediate_response &other)
  : intermediate_response(other, allocator_type{})
{}

intermediate_response::intermediate_response(const intermediate_response &other, const allocator_type &alloc)
  : response_name(optional_with(other.response_name, alloc)),
	response_value(optional_with(other.response_value, alloc)), alloc_(alloc)
{}

intermediate_response::intermediate_response(intermediate_response &&other, const allocator_type &alloc)
  : response_name(optional_with(std::move(other.response_name), alloc)),
	response_value(optional_with(std::move(other.response_value), alloc)), alloc_(alloc)
{}

auto intermediate_response::operator=(const intermediate_response &other) -> intermediate_response &
{
	if (this == &other) {
		return *this;
	}
	assign_optional(response_name, other.response_name, alloc_);
	assign_optional(response_value, other.response_value, alloc_);
	return *this;
}

auto intermediate_response::operator=(intermediate_response &&other) -> intermediate_response &
{
	assign_optional(response_name, std::move(other.response_name), alloc_);
	assign_optional(response_value, std::move(other.response_value), alloc_);
	return *this;
}

message::message(const allocator_type &alloc) : op(std::in_place_type<bind_request>, alloc), controls(alloc) {}

message::message(std::int32_t id_,
  protocol_op op_,
  std::initializer_list<control> controls_,
  const allocator_type &alloc)
  : id(id_), op(variant_with(std::move(op_), alloc)), controls(controls_, alloc)
{}

message::message(const message &other, const allocator_type &alloc)
  : id(other.id), op(variant_with(other.op, alloc)), controls(other.controls, alloc)
{}

message::message(message &&other, const allocator_type &alloc)
  : id(other.id), op(variant_with(std::move(other.op), alloc)), controls(std::move(other.controls), alloc)
{}

auto message::operator=(const message &other) -> message &
{
	if (this == &other) {
		return *this;
	}
	id = other.id;
	assign_variant(op, other.op, get_allocator());
	controls = other.controls;
	return *this;
}

auto message::operator=(message &&other) -> message &
{
	id = other.id;
	assign_variant(op, std::move(other.op), get_allocator());
	controls = std::move(other.controls);
	return *this;
}

namespace {

	namespace op_tag = detail::op_tag;
	namespace field_tag = detail::field_tag;
	using detail::max_bind_version;

	// ---------------------------------------------------------------- encoder

	auto out_of_range(const char *what) -> std::unexpected<error>
	{
		return fail(client_errc::encode_error, detail::format("message: {} out of range", what));
	}

	// The operations a client sends (RFC 4511 section 4.2 protocolOp requests).
	template<class T>
	constexpr bool is_request_v =
	  std::is_same_v<T, bind_request> || std::is_same_v<T, unbind_request> || std::is_same_v<T, search_request>
	  || std::is_same_v<T, modify_request> || std::is_same_v<T, add_request> || std::is_same_v<T, del_request>
	  || std::is_same_v<T, modify_dn_request> || std::is_same_v<T, compare_request>
	  || std::is_same_v<T, abandon_request> || std::is_same_v<T, extended_request>;

	// By protocol_op::index(): safe on a valueless op.
	auto is_request_op(const protocol_op &op) noexcept -> bool
	{
		const std::size_t index = op.index();// variant_npos when valueless
		return [index]<std::size_t... I>(std::index_sequence<I...>) -> bool {
			return ((index == I && is_request_v<std::variant_alternative_t<I, protocol_op>>) || ...);
		}(std::make_index_sequence<std::variant_size_v<protocol_op>>{});
	}

	// Checks everything encoding could reject, before the writer is touched.
	auto precheck(const message &m) -> result<void>
	{
		if (m.id < 0) {
			return out_of_range("message id");
		}
		// RFC 4511 section 4.1.1: id 0 is reserved for unsolicited notifications.
		if (m.id == 0 && is_request_op(m.op)) {
			return fail(client_errc::encode_error, "message: a request with message id 0");
		}
		if (const auto *s = std::get_if<search_request>(&m.op)) {
			const auto scope = std::to_underlying(s->scope);
			const auto deref = std::to_underlying(s->deref);
			if (scope < 0 || scope > 3) {
				return out_of_range("search scope");
			}
			if (deref < 0 || deref > 3) {
				return out_of_range("derefAliases");
			}
			if (s->size_limit < 0) {
				return out_of_range("size limit");
			}
			if (s->time_limit < 0) {
				return out_of_range("time limit");
			}
			return detail::check_filter(s->filter, {});
		}
		if (const auto *b = std::get_if<bind_request>(&m.op)) {
			if (b->version < 1 || b->version > max_bind_version) {
				return out_of_range("bind version");
			}
		} else if (const auto *a = std::get_if<abandon_request>(&m.op)) {
			if (a->message_id < 0) {
				return out_of_range("abandoned message id");
			}
		} else if (const auto *mod = std::get_if<modify_request>(&m.op)) {
			for (const auto &c : mod->changes) {
				const auto op = std::to_underlying(c.operation);
				if (op < 0 || op > 3) {
					return out_of_range("modify operation");
				}
				if (c.operation == modify_operation::add && c.modification.values.empty()) {
					return fail(client_errc::encode_error, "message: modify add change without values");
				}
			}
		} else if (const auto *add = std::get_if<add_request>(&m.op)) {
			for (const auto &attr : add->attributes) {
				if (attr.values.empty()) {
					return fail(client_errc::encode_error, "message: add request attribute without values");
				}
			}
		} else if (const auto *ref = std::get_if<search_result_reference>(&m.op); ref != nullptr && ref->uris.empty()) {
			return fail(client_errc::encode_error, "message: search result reference without a URI");
		}
		return {};
	}

	void write_result(ber::writer &w, const ldap_result &r)
	{
		w.enumerated(r.result_code);
		w.octet_string(r.matched_dn);
		w.octet_string(r.diagnostic_message);
		if (!r.referral.empty()) {
			w.constructed(ber::context(3), [&](ber::writer &ref) {
				for (const auto &uri : r.referral) {
					ref.octet_string(uri);
				}
			});
		}
	}

	void write_attribute(ber::writer &w, const partial_attribute &a)
	{
		w.constructed(ber::tags::sequence, [&](ber::writer &pa) {
			pa.octet_string(a.type);
			pa.constructed(ber::tags::set, [&](ber::writer &vals) {
				for (const auto &v : a.values) {
					vals.octet_string(v);
				}
			});
		});
	}

	void write_attributes(ber::writer &w, const std::pmr::vector<partial_attribute> &attrs)
	{
		w.constructed(ber::tags::sequence, [&](ber::writer &list) {
			for (const auto &a : attrs) {
				write_attribute(list, a);
			}
		});
	}

	struct op_writer
	{
		ber::writer *w;// non-null

		template<class F> void seq(std::uint8_t number, F &&body) const
		{
			w->constructed(ber::application(number), std::forward<F>(body));
		}

		template<std::uint8_t Tag> void operator()(const result_response<Tag> &r) const
		{
			seq(Tag, [&](ber::writer &o) { write_result(o, r.result); });
		}

		void operator()(const bind_request &b) const
		{
			seq(op_tag::bind_request, [&](ber::writer &o) {
				o.integer(b.version);
				o.octet_string(b.name);
				if (const auto *simple = std::get_if<simple_auth>(&b.authentication)) {
					o.octet_string(simple->password, ber::context(0));
				} else {
					const auto &sasl = std::get<sasl_auth>(b.authentication);
					o.constructed(ber::context(3), [&](ber::writer &s) {
						s.octet_string(sasl.mechanism);
						if (sasl.credentials) {
							s.octet_string(*sasl.credentials);
						}
					});
				}
			});
		}
		void operator()(const bind_response &b) const
		{
			seq(op_tag::bind_response, [&](ber::writer &o) {
				write_result(o, b.result);
				if (b.server_sasl_creds) {
					o.octet_string(*b.server_sasl_creds, ber::context(field_tag::server_sasl_creds));
				}
			});
		}
		void operator()(const unbind_request &) const { w->null(ber::application(op_tag::unbind_request)); }
		void operator()(const search_request &s) const
		{
			seq(op_tag::search_request, [&](ber::writer &o) {
				o.octet_string(s.base_object);
				o.enumerated(std::to_underlying(s.scope));
				o.enumerated(std::to_underlying(s.deref));
				o.integer(s.size_limit);
				o.integer(s.time_limit);
				o.boolean(s.types_only);
				detail::write_filter(o, s.filter);// checked by precheck
				o.constructed(ber::tags::sequence, [&](ber::writer &attrs) {
					for (const auto &a : s.attributes) {
						attrs.octet_string(a);
					}
				});
			});
		}
		void operator()(const search_result_entry &e) const
		{
			seq(op_tag::search_result_entry, [&](ber::writer &o) {
				o.octet_string(e.object_name);
				write_attributes(o, e.attributes);
			});
		}
		void operator()(const search_result_reference &r) const
		{
			seq(op_tag::search_result_reference, [&](ber::writer &o) {
				for (const auto &uri : r.uris) {
					o.octet_string(uri);
				}
			});
		}
		void operator()(const modify_request &m) const
		{
			seq(op_tag::modify_request, [&](ber::writer &o) {
				o.octet_string(m.object);
				o.constructed(ber::tags::sequence, [&](ber::writer &changes) {
					for (const auto &c : m.changes) {
						changes.constructed(ber::tags::sequence, [&](ber::writer &change) {
							change.enumerated(std::to_underlying(c.operation));
							write_attribute(change, c.modification);
						});
					}
				});
			});
		}
		void operator()(const add_request &a) const
		{
			seq(op_tag::add_request, [&](ber::writer &o) {
				o.octet_string(a.entry);
				write_attributes(o, a.attributes);
			});
		}
		void operator()(const del_request &d) const { w->octet_string(d.entry, ber::application(op_tag::del_request)); }
		void operator()(const modify_dn_request &m) const
		{
			seq(op_tag::modify_dn_request, [&](ber::writer &o) {
				o.octet_string(m.entry);
				o.octet_string(m.new_rdn);
				o.boolean(m.delete_old_rdn);
				if (m.new_superior) {
					o.octet_string(*m.new_superior, ber::context(0));
				}
			});
		}
		void operator()(const compare_request &c) const
		{
			seq(op_tag::compare_request, [&](ber::writer &o) {
				o.octet_string(c.entry);
				o.constructed(ber::tags::sequence, [&](ber::writer &ava) {
					ava.octet_string(c.ava.attribute_desc);
					ava.octet_string(c.ava.assertion_value);
				});
			});
		}
		void operator()(const abandon_request &a) const
		{
			w->integer(a.message_id, ber::application(op_tag::abandon_request));
		}
		void operator()(const extended_request &e) const
		{
			seq(op_tag::extended_request, [&](ber::writer &o) {
				o.octet_string(e.request_name, ber::context(0));
				if (e.request_value) {
					o.octet_string(*e.request_value, ber::context(1));
				}
			});
		}
		void operator()(const extended_response &e) const
		{
			seq(op_tag::extended_response, [&](ber::writer &o) {
				write_result(o, e.result);
				if (e.response_name) {
					o.octet_string(*e.response_name, ber::context(field_tag::response_name));
				}
				if (e.response_value) {
					o.octet_string(*e.response_value, ber::context(field_tag::response_value));
				}
			});
		}
		void operator()(const intermediate_response &i) const
		{
			seq(op_tag::intermediate_response, [&](ber::writer &o) {
				if (i.response_name) {
					o.octet_string(*i.response_name, ber::context(0));
				}
				if (i.response_value) {
					o.octet_string(*i.response_value, ber::context(1));
				}
			});
		}
	};

}// namespace

namespace detail {

	void write_control_list(ber::writer &list, const std::pmr::vector<control> &controls)
	{
		for (const auto &c : controls) {
			list.constructed(ber::tags::sequence, [&](ber::writer &cw) {
				cw.octet_string(c.type);
				if (c.criticality) {
					cw.boolean(true);
				}
				if (c.value) {
					cw.octet_string(*c.value);
				}
			});
		}
	}

	void write_search_result_entry(ber::writer &w, const search_result_entry &e) { op_writer{ &w }(e); }

}// namespace detail

auto encode(ber::writer &w, const message &m) -> result<void>
{
	if (auto done = precheck(m); !done) {
		return std::unexpected(std::move(done.error()));
	}
	w.constructed(ber::tags::sequence, [&](ber::writer &msg) {
		msg.integer(m.id);
		std::visit(op_writer{ &msg }, m.op);
		if (!m.controls.empty()) {
			msg.constructed(ber::context(0), [&](ber::writer &list) { detail::write_control_list(list, m.controls); });
		}
	});
	return {};
}

auto encode(const message &m, std::pmr::memory_resource *mr) -> result<std::pmr::vector<std::byte>>
{
	ber::writer w{ ber::writer::allocator_type(mr) };
	// Most requests fit; saves the first few doublings of the buffer.
	w.reserve(256);
	if (auto done = encode(w, m); !done) {
		return std::unexpected(std::move(done.error()));
	}
	return w.take();
}

auto decode(std::span<const std::byte> one_complete_message, const decode_options &options) -> result<message>
{
	return detail::message_decoder(options).run(one_complete_message);
}

auto peek_message_header(std::span<const std::byte> one_complete_message) -> result<message_header>
{
	ber::reader top(one_complete_message);
	auto r = top.enter();
	if (!r) {
		return std::unexpected(std::move(r.error()));
	}
	auto id = detail::read_ranged(*r, ber::tags::integer, 0, max_int, "message id");
	if (!id) {
		return std::unexpected(std::move(id.error()));
	}
	if (r->empty()) {
		return fail(client_errc::decode_error, "LDAPMessage without a protocolOp");
	}
	auto op = r->peek_tag();
	if (!op) {
		return std::unexpected(std::move(op.error()));
	}
	return message_header{ .id = *id, .op = *op };
}

// ---------------------------------------------------------------- paged results

auto encode_paged_results(const paged_results &value, bool criticality, std::pmr::memory_resource *mr)
  -> result<control>
{
	if (value.size < 0) {
		return fail(client_errc::encode_error, "paged results: negative size");
	}
	ber::writer w{ ber::writer::allocator_type(mr) };
	w.constructed(ber::tags::sequence, [&](ber::writer &s) {
		s.integer(value.size);
		s.octet_string(value.cookie);
	});
	return control(paged_results_oid, criticality, detail::as_text(w.bytes()), control::allocator_type(mr));
}

namespace {

	// realSearchControlValue ::= SEQUENCE { size INTEGER (0..maxInt), cookie OCTET STRING }
	auto read_paged_results(std::span<const std::byte> value, std::pmr::memory_resource *mr) -> result<paged_results>
	{
		ber::reader r(value);
		auto s = enter_value(r);
		if (!s) {
			return std::unexpected(std::move(s.error()));
		}
		auto size = detail::read_ranged(*s, ber::tags::integer, 0, max_int, "size");
		if (!size) {
			return std::unexpected(std::move(size.error()));
		}
		auto cookie = s->read_string(ber::tags::octet_string, mr);
		if (!cookie) {
			return std::unexpected(std::move(cookie.error()));
		}
		if (auto done = skip_rest(*s); !done) {
			return std::unexpected(std::move(done.error()));
		}
		paged_results out{ paged_results::allocator_type(mr) };
		out.size = *size;
		out.cookie = std::move(*cookie);
		return out;
	}

}// namespace

auto decode_paged_results(const control &c, std::pmr::memory_resource *mr) -> result<paged_results>
{
	auto value = control_value(c, paged_results_oid, "paged results");
	if (!value) {
		return std::unexpected(std::move(value.error()));
	}
	return in_control(read_paged_results(*value, mr), "paged results");
}

// ---------------------------------------------------------------- server side sorting

namespace {

	// SortResult ::= SEQUENCE { sortResult ENUMERATED, attributeType [0] AttributeDescription OPTIONAL }
	auto read_sort_result(std::span<const std::byte> value, std::pmr::memory_resource *mr) -> result<sort_result>
	{
		ber::reader r(value);
		auto s = enter_value(r);
		if (!s) {
			return std::unexpected(std::move(s.error()));
		}
		auto code = detail::read_ranged(*s,
		  ber::tags::enumerated,
		  std::numeric_limits<std::int32_t>::min(),
		  std::numeric_limits<std::int32_t>::max(),
		  "sortResult",
		  true);
		if (!code) {
			return std::unexpected(std::move(code.error()));
		}
		sort_result out{ sort_result::allocator_type(mr) };
		out.result_code = *code;
		if (next_is(*s, ber::context(0))) {
			auto type = s->read_string(ber::context(0), mr);
			if (!type) {
				return std::unexpected(std::move(type.error()));
			}
			out.attribute_type = std::move(*type);
		}
		if (auto done = skip_rest(*s); !done) {
			return std::unexpected(std::move(done.error()));
		}
		return out;
	}

}// namespace

auto decode_sort_result(const control &c, std::pmr::memory_resource *mr) -> result<sort_result>
{
	auto value = control_value(c, sort_response_oid, "sort result");
	if (!value) {
		return std::unexpected(std::move(value.error()));
	}
	return in_control(read_sort_result(*value, mr), "sort result");
}

// ---------------------------------------------------------------- virtual list view

// Public API, VirtualListViewResponse field order (draft-ietf-ldapext-ldapv3-vlv-09 section 6.2).
// NOLINTBEGIN(bugprone-easily-swappable-parameters)
vlv_response::vlv_response(std::int32_t target_position_,
  std::int32_t content_count_,
  std::int32_t result_code_,
  std::optional<std::string_view> context_id_,
  const allocator_type &alloc)
  // NOLINTEND(bugprone-easily-swappable-parameters)
  : target_position(target_position_), content_count(content_count_), result_code(result_code_),
	context_id(detail::optional_string(context_id_, alloc)), alloc_(alloc)
{}

// A plain copy uses the default resource, like the pmr containers.
vlv_response::vlv_response(const vlv_response &other) : vlv_response(other, allocator_type{}) {}

vlv_response::vlv_response(const vlv_response &other, const allocator_type &alloc)
  : target_position(other.target_position), content_count(other.content_count), result_code(other.result_code),
	context_id(detail::optional_with(other.context_id, alloc)), alloc_(alloc)
{}

vlv_response::vlv_response(vlv_response &&other, const allocator_type &alloc)
  : target_position(other.target_position), content_count(other.content_count), result_code(other.result_code),
	context_id(detail::optional_with(std::move(other.context_id), alloc)), alloc_(alloc)
{}

auto vlv_response::operator=(const vlv_response &other) -> vlv_response &
{
	if (this == &other) {
		return *this;
	}
	target_position = other.target_position;
	content_count = other.content_count;
	result_code = other.result_code;
	detail::assign_optional(context_id, other.context_id, alloc_);
	return *this;
}

auto vlv_response::operator=(vlv_response &&other) -> vlv_response &
{
	if (this == &other) {
		return *this;
	}
	target_position = other.target_position;
	content_count = other.content_count;
	result_code = other.result_code;
	detail::assign_optional(context_id, std::move(other.context_id), alloc_);
	return *this;
}

namespace {

	// VirtualListViewResponse ::= SEQUENCE { targetPosition INTEGER (0 .. maxInt),
	//   contentCount INTEGER (0 .. maxInt), virtualListViewResult ENUMERATED,
	//   contextID OCTET STRING OPTIONAL }
	auto read_vlv_response(std::span<const std::byte> value, std::pmr::memory_resource *mr) -> result<vlv_response>
	{
		ber::reader r(value);
		auto s = enter_value(r);
		if (!s) {
			return std::unexpected(std::move(s.error()));
		}
		auto position = detail::read_ranged(*s, ber::tags::integer, 0, max_int, "targetPosition");
		if (!position) {
			return std::unexpected(std::move(position.error()));
		}
		auto count = detail::read_ranged(*s, ber::tags::integer, 0, max_int, "contentCount");
		if (!count) {
			return std::unexpected(std::move(count.error()));
		}
		auto code = detail::read_ranged(*s,
		  ber::tags::enumerated,
		  std::numeric_limits<std::int32_t>::min(),
		  std::numeric_limits<std::int32_t>::max(),
		  "virtualListViewResult",
		  true);
		if (!code) {
			return std::unexpected(std::move(code.error()));
		}
		vlv_response out{ vlv_response::allocator_type(mr) };
		out.target_position = *position;
		out.content_count = *count;
		out.result_code = *code;
		if (next_is(*s, ber::tags::octet_string)) {
			auto id = s->read_string(ber::tags::octet_string, mr);
			if (!id) {
				return std::unexpected(std::move(id.error()));
			}
			out.context_id.emplace(std::move(*id));
		}
		if (auto done = skip_rest(*s); !done) {
			return std::unexpected(std::move(done.error()));
		}
		return out;
	}

}// namespace

auto decode_vlv_response(const control &c, std::pmr::memory_resource *mr) -> result<vlv_response>
{
	auto value = control_value(c, vlv_response_oid, "vlv response");
	if (!value) {
		return std::unexpected(std::move(value.error()));
	}
	return in_control(read_vlv_response(*value, mr), "vlv response");
}

// ---------------------------------------------------------------- pre-read / post-read

auto decode_read_entry(const control &c, const decode_options &options) -> result<search_result_entry>
{
	if (c.type != pre_read_oid && c.type != post_read_oid) {
		return fail(client_errc::decode_error,
		  detail::sanitized_context("read entry: control type is ", c.type, ", not pre-read or post-read"));
	}
	const std::string_view name = c.type == pre_read_oid ? "pre-read" : "post-read";
	auto value = control_value(c, c.type, name);
	if (!value) {
		return std::unexpected(std::move(value.error()));
	}
	return in_control(detail::message_decoder(options).run_entry(*value), name);
}

// ---------------------------------------------------------------- transactions (RFC 5805)

auto encode_end_transaction_request(const end_transaction_request &value, std::pmr::memory_resource *mr)
  -> std::pmr::string
{
	ber::writer w{ ber::writer::allocator_type(mr) };
	w.constructed(ber::tags::sequence, [&](ber::writer &s) {
		if (!value.commit) {
			s.boolean(false);
		}
		s.octet_string(value.identifier);
	});
	return std::pmr::string(detail::as_text(w.bytes()), std::pmr::polymorphic_allocator<>(mr));
}

auto decode_end_transaction_response(std::string_view value, const decode_options &options)
  -> result<end_transaction_response>
{
	return in_control(
	  detail::message_decoder(options).run_end_transaction(std::as_bytes(std::span(value))), "txnEndRes");
}

}// namespace jhetz::ldap