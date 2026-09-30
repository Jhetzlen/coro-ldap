#include "jhetz/ldap/message.hpp"

#include "filter_ast.hpp"

#include <limits>
#include <utility>

// Early return on failure: `LDAP_TRY(x, expr);` declares `x` from a result.
#define LDAP_TRY(var, expr)                                                       \
	auto var##_result_ = (expr);                                                  \
	if (!var##_result_) return std::unexpected(std::move(var##_result_.error())); \
	auto var = std::move(*var##_result_)

#define LDAP_TRY_VOID(expr)                                                       \
	do {                                                                          \
		auto try_result_ = (expr);                                                \
		if (!try_result_) return std::unexpected(std::move(try_result_.error())); \
	} while (false)

namespace jhetz::ldap {

error ldap_result::to_error(std::string context) const
{
	error e;
	e.code = std::error_code(result_code, result_category());
	e.diagnostic = diagnostic_message;
	if (!matched_dn.empty()) e.matched_dn = matched_dn;
	e.referrals = referral;
	e.context = std::move(context);
	return e;
}

namespace {

	// Application tag numbers of the protocolOp CHOICE (RFC 4511 section 4.2).
	namespace op_tag {
		constexpr std::uint8_t bind_request = 0;
		constexpr std::uint8_t bind_response = 1;
		constexpr std::uint8_t unbind_request = 2;
		constexpr std::uint8_t search_request = 3;
		constexpr std::uint8_t search_result_entry = 4;
		constexpr std::uint8_t search_result_done = 5;
		constexpr std::uint8_t modify_request = 6;
		constexpr std::uint8_t modify_response = 7;
		constexpr std::uint8_t add_request = 8;
		constexpr std::uint8_t add_response = 9;
		constexpr std::uint8_t del_request = 10;
		constexpr std::uint8_t del_response = 11;
		constexpr std::uint8_t modify_dn_request = 12;
		constexpr std::uint8_t modify_dn_response = 13;
		constexpr std::uint8_t compare_request = 14;
		constexpr std::uint8_t compare_response = 15;
		constexpr std::uint8_t abandon_request = 16;
		constexpr std::uint8_t search_result_reference = 19;
		constexpr std::uint8_t extended_request = 23;
		constexpr std::uint8_t extended_response = 24;
		constexpr std::uint8_t intermediate_response = 25;
	}// namespace op_tag

	std::string at(std::size_t offset) { return " at offset " + std::to_string(offset); }

	std::unexpected<error> bad(const std::string &what, std::size_t offset)
	{
		return fail(client_errc::decode_error, "message: " + what + at(offset));
	}

	// ---------------------------------------------------------------- encoder

	std::unexpected<error> out_of_range(const char *what)
	{
		return fail(client_errc::encode_error, std::string("message: ") + what + " out of range");
	}

	// Checks everything encoding could reject and compiles the filter of a
	// search request, so the writer is only touched once nothing can fail.
	result<std::optional<detail::filter_node>> precheck(const message &m)
	{
		if (m.id < 0) return out_of_range("message id");
		std::optional<detail::filter_node> filter;
		if (const auto *s = std::get_if<search_request>(&m.op)) {
			const auto scope = static_cast<std::int32_t>(s->scope);
			const auto deref = static_cast<std::int32_t>(s->deref);
			if (scope < 0 || scope > 3) return out_of_range("search scope");
			if (deref < 0 || deref > 3) return out_of_range("derefAliases");
			if (s->size_limit < 0) return out_of_range("size limit");
			if (s->time_limit < 0) return out_of_range("time limit");
			auto f = detail::parse_filter(s->filter.text);
			if (!f) return std::unexpected(std::move(f.error()));
			filter = std::move(*f);
		} else if (const auto *b = std::get_if<bind_request>(&m.op)) {
			if (b->version < 1 || b->version > 127) return out_of_range("bind version");
		} else if (const auto *a = std::get_if<abandon_request>(&m.op)) {
			if (a->message_id < 0) return out_of_range("abandoned message id");
		} else if (const auto *mod = std::get_if<modify_request>(&m.op)) {
			for (const auto &c : mod->changes) {
				const auto op = static_cast<std::int32_t>(c.operation);
				if (op < 0 || op > 3) return out_of_range("modify operation");
				if (c.operation == modify_operation::add && c.modification.values.empty())
					return fail(client_errc::encode_error, "message: modify add change without values");
			}
		} else if (const auto *add = std::get_if<add_request>(&m.op)) {
			for (const auto &attr : add->attributes)
				if (attr.values.empty())
					return fail(client_errc::encode_error, "message: add request attribute without values");
		}
		return filter;
	}

	void write_result(ber::writer &w, const ldap_result &r)
	{
		w.enumerated(r.result_code);
		w.octet_string(r.matched_dn);
		w.octet_string(r.diagnostic_message);
		if (!r.referral.empty())
			w.constructed(ber::context(3), [&](ber::writer &ref) {
				for (const auto &uri : r.referral) ref.octet_string(uri);
			});
	}

	void write_attribute(ber::writer &w, const partial_attribute &a)
	{
		w.constructed(ber::tags::sequence, [&](ber::writer &pa) {
			pa.octet_string(a.type);
			pa.constructed(ber::tags::set, [&](ber::writer &vals) {
				for (const auto &v : a.values) vals.octet_string(v);
			});
		});
	}

	void write_attributes(ber::writer &w, const std::vector<partial_attribute> &attrs)
	{
		w.constructed(ber::tags::sequence, [&](ber::writer &list) {
			for (const auto &a : attrs) write_attribute(list, a);
		});
	}

	struct op_writer
	{
		ber::writer &w;
		const std::optional<detail::filter_node> &filter;

		template<class F> void seq(std::uint8_t number, F &&body) { w.constructed(ber::application(number), body); }

		void result_only(std::uint8_t number, const ldap_result &r)
		{
			seq(number, [&](ber::writer &o) { write_result(o, r); });
		}

		void operator()(const bind_request &b)
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
						if (sasl.credentials) s.octet_string(*sasl.credentials);
					});
				}
			});
		}
		void operator()(const bind_response &b)
		{
			seq(op_tag::bind_response, [&](ber::writer &o) {
				write_result(o, b.result);
				if (b.server_sasl_creds) o.octet_string(*b.server_sasl_creds, ber::context(7));
			});
		}
		void operator()(const unbind_request &) { w.null(ber::application(op_tag::unbind_request)); }
		void operator()(const search_request &s)
		{
			seq(op_tag::search_request, [&](ber::writer &o) {
				o.octet_string(s.base_object);
				o.enumerated(static_cast<std::int32_t>(s.scope));
				o.enumerated(static_cast<std::int32_t>(s.deref));
				o.integer(s.size_limit);
				o.integer(s.time_limit);
				o.boolean(s.types_only);
				detail::write_filter(o, *filter);
				o.constructed(ber::tags::sequence, [&](ber::writer &attrs) {
					for (const auto &a : s.attributes) attrs.octet_string(a);
				});
			});
		}
		void operator()(const search_result_entry &e)
		{
			seq(op_tag::search_result_entry, [&](ber::writer &o) {
				o.octet_string(e.object_name);
				write_attributes(o, e.attributes);
			});
		}
		void operator()(const search_result_done &r) { result_only(op_tag::search_result_done, r.result); }
		void operator()(const search_result_reference &r)
		{
			seq(op_tag::search_result_reference, [&](ber::writer &o) {
				for (const auto &uri : r.uris) o.octet_string(uri);
			});
		}
		void operator()(const modify_request &m)
		{
			seq(op_tag::modify_request, [&](ber::writer &o) {
				o.octet_string(m.object);
				o.constructed(ber::tags::sequence, [&](ber::writer &changes) {
					for (const auto &c : m.changes)
						changes.constructed(ber::tags::sequence, [&](ber::writer &change) {
							change.enumerated(static_cast<std::int32_t>(c.operation));
							write_attribute(change, c.modification);
						});
				});
			});
		}
		void operator()(const modify_response &r) { result_only(op_tag::modify_response, r.result); }
		void operator()(const add_request &a)
		{
			seq(op_tag::add_request, [&](ber::writer &o) {
				o.octet_string(a.entry);
				write_attributes(o, a.attributes);
			});
		}
		void operator()(const add_response &r) { result_only(op_tag::add_response, r.result); }
		void operator()(const del_request &d) { w.octet_string(d.entry, ber::application(op_tag::del_request)); }
		void operator()(const del_response &r) { result_only(op_tag::del_response, r.result); }
		void operator()(const modify_dn_request &m)
		{
			seq(op_tag::modify_dn_request, [&](ber::writer &o) {
				o.octet_string(m.entry);
				o.octet_string(m.new_rdn);
				o.boolean(m.delete_old_rdn);
				if (m.new_superior) o.octet_string(*m.new_superior, ber::context(0));
			});
		}
		void operator()(const modify_dn_response &r) { result_only(op_tag::modify_dn_response, r.result); }
		void operator()(const compare_request &c)
		{
			seq(op_tag::compare_request, [&](ber::writer &o) {
				o.octet_string(c.entry);
				o.constructed(ber::tags::sequence, [&](ber::writer &ava) {
					ava.octet_string(c.ava.attribute_desc);
					ava.octet_string(c.ava.assertion_value);
				});
			});
		}
		void operator()(const compare_response &r) { result_only(op_tag::compare_response, r.result); }
		void operator()(const abandon_request &a)
		{
			w.integer(a.message_id, ber::application(op_tag::abandon_request));
		}
		void operator()(const extended_request &e)
		{
			seq(op_tag::extended_request, [&](ber::writer &o) {
				o.octet_string(e.request_name, ber::context(0));
				if (e.request_value) o.octet_string(*e.request_value, ber::context(1));
			});
		}
		void operator()(const extended_response &e)
		{
			seq(op_tag::extended_response, [&](ber::writer &o) {
				write_result(o, e.result);
				if (e.response_name) o.octet_string(*e.response_name, ber::context(10));
				if (e.response_value) o.octet_string(*e.response_value, ber::context(11));
			});
		}
		void operator()(const intermediate_response &i)
		{
			seq(op_tag::intermediate_response, [&](ber::writer &o) {
				if (i.response_name) o.octet_string(*i.response_name, ber::context(0));
				if (i.response_value) o.octet_string(*i.response_value, ber::context(1));
			});
		}
	};

	// ---------------------------------------------------------------- decoder

	// RFC 4511 section 4: unrecognized elements at the end of a SEQUENCE are
	// ignored. They must still be well-formed (read() checks the header and
	// that the length fits).
	result<void> skip_rest(ber::reader &r)
	{
		while (!r.empty()) {
			auto e = r.read();
			if (!e) return std::unexpected(std::move(e.error()));
		}
		return {};
	}

	// Class and number of the next element, without committing.
	bool next_is(const ber::reader &r, ber::tag t)
	{
		if (r.empty()) return false;
		auto p = r.peek_tag();
		return p && p->cls == t.cls && p->number == t.number;
	}

	result<std::int32_t> read_ranged(ber::reader &r,
	  ber::tag t,
	  std::int64_t lo,
	  std::int64_t hi,
	  const char *what,
	  bool enumerated = false)
	{
		const std::size_t offset = r.offset();
		auto copy = r;
		LDAP_TRY(v, enumerated ? copy.read_enumerated(t) : copy.read_integer(t));
		if (v < lo || v > hi)
			return bad(std::string(what) + " " + std::to_string(v) + " outside " + std::to_string(lo) + ".."
						 + std::to_string(hi),
			  offset);
		r = copy;
		return static_cast<std::int32_t>(v);
	}

	result<std::optional<std::string>> read_optional_string(ber::reader &r, ber::tag t)
	{
		if (!next_is(r, t)) return std::optional<std::string>{};
		LDAP_TRY(s, r.read_string(t));
		return std::optional<std::string>{ std::move(s) };
	}

	// COMPONENTS OF LDAPResult: the fields are inline in the op's SEQUENCE.
	result<ldap_result> read_result(ber::reader &r)
	{
		ldap_result out;
		LDAP_TRY(code,
		  read_ranged(r,
			ber::tags::enumerated,
			std::numeric_limits<std::int32_t>::min(),
			std::numeric_limits<std::int32_t>::max(),
			"resultCode",
			true));
		LDAP_TRY(matched, r.read_string());
		LDAP_TRY(diag, r.read_string());
		out.result_code = code;
		out.matched_dn = std::move(matched);
		out.diagnostic_message = std::move(diag);
		if (next_is(r, ber::context(3))) {
			LDAP_TRY(ref, r.enter(ber::context(3)));
			while (!ref.empty()) {
				LDAP_TRY(uri, ref.read_string());
				out.referral.push_back(std::move(uri));
			}
		}
		return out;
	}

	template<class T> result<protocol_op> result_only_op(ber::reader &r, ber::tag t)
	{
		LDAP_TRY(o, r.enter(t));
		LDAP_TRY(res, read_result(o));
		LDAP_TRY_VOID(skip_rest(o));
		return protocol_op{ T{ std::move(res) } };
	}

	result<partial_attribute> read_attribute(ber::reader &r)
	{
		LDAP_TRY(pa, r.enter());
		LDAP_TRY(type, pa.read_string());
		LDAP_TRY(vals, pa.enter(ber::tags::set));
		partial_attribute out;
		out.type = std::move(type);
		while (!vals.empty()) {
			LDAP_TRY(v, vals.read_string());
			out.values.push_back(std::move(v));
		}
		LDAP_TRY_VOID(skip_rest(pa));
		return out;
	}

	result<std::vector<partial_attribute>> read_attributes(ber::reader &r)
	{
		LDAP_TRY(list, r.enter());
		std::vector<partial_attribute> out;
		while (!list.empty()) {
			LDAP_TRY(a, read_attribute(list));
			out.push_back(std::move(a));
		}
		return out;
	}

	result<protocol_op> read_bind_request(ber::reader &r, ber::tag t)
	{
		LDAP_TRY(o, r.enter(t));
		bind_request b;
		LDAP_TRY(version, read_ranged(o, ber::tags::integer, 1, 127, "bind version"));
		LDAP_TRY(name, o.read_string());
		b.version = version;
		b.name = std::move(name);
		const std::size_t auth_at = o.offset();
		if (next_is(o, ber::context(0))) {
			LDAP_TRY(password, o.read_string(ber::context(0)));
			b.authentication = simple_auth{ std::move(password) };
		} else if (next_is(o, ber::context(3))) {
			LDAP_TRY(s, o.enter(ber::context(3)));
			LDAP_TRY(mechanism, s.read_string());
			LDAP_TRY(credentials, read_optional_string(s, ber::tags::octet_string));
			LDAP_TRY_VOID(skip_rest(s));
			b.authentication = sasl_auth{ std::move(mechanism), std::move(credentials) };
		} else {
			if (o.empty()) return bad("bind request without authentication", auth_at);
			return fail(
			  client_errc::unsupported_operation, "message: unsupported bind authentication choice" + at(auth_at));
		}
		LDAP_TRY_VOID(skip_rest(o));
		return protocol_op{ std::move(b) };
	}

	result<protocol_op> read_bind_response(ber::reader &r, ber::tag t)
	{
		LDAP_TRY(o, r.enter(t));
		bind_response b;
		LDAP_TRY(res, read_result(o));
		LDAP_TRY(creds, read_optional_string(o, ber::context(7)));
		LDAP_TRY_VOID(skip_rest(o));
		b.result = std::move(res);
		b.server_sasl_creds = std::move(creds);
		return protocol_op{ std::move(b) };
	}

	result<protocol_op> read_search_request(ber::reader &r, ber::tag t, const filter_limits &limits)
	{
		LDAP_TRY(o, r.enter(t));
		search_request s;
		LDAP_TRY(base, o.read_string());
		LDAP_TRY(scope, read_ranged(o, ber::tags::enumerated, 0, 3, "search scope", true));
		LDAP_TRY(deref, read_ranged(o, ber::tags::enumerated, 0, 3, "derefAliases", true));
		LDAP_TRY(size_limit, read_ranged(o, ber::tags::integer, 0, max_int, "size limit"));
		LDAP_TRY(time_limit, read_ranged(o, ber::tags::integer, 0, max_int, "time limit"));
		LDAP_TRY(types_only, o.read_boolean());
		LDAP_TRY(filter_text, decode_filter(o, limits));
		LDAP_TRY(attrs, o.enter());
		while (!attrs.empty()) {
			LDAP_TRY(a, attrs.read_string());
			s.attributes.push_back(std::move(a));
		}
		LDAP_TRY_VOID(skip_rest(o));
		s.base_object = std::move(base);
		s.scope = static_cast<search_scope>(scope);
		s.deref = static_cast<deref_aliases>(deref);
		s.size_limit = size_limit;
		s.time_limit = time_limit;
		s.types_only = types_only;
		s.filter = filter::raw(std::move(filter_text));
		return protocol_op{ std::move(s) };
	}

	result<protocol_op> read_search_result_entry(ber::reader &r, ber::tag t)
	{
		LDAP_TRY(o, r.enter(t));
		LDAP_TRY(name, o.read_string());
		LDAP_TRY(attrs, read_attributes(o));
		LDAP_TRY_VOID(skip_rest(o));
		return protocol_op{ search_result_entry{ std::move(name), std::move(attrs) } };
	}

	result<protocol_op> read_search_result_reference(ber::reader &r, ber::tag t)
	{
		LDAP_TRY(o, r.enter(t));
		search_result_reference ref;
		while (!o.empty()) {
			LDAP_TRY(uri, o.read_string());
			ref.uris.push_back(std::move(uri));
		}
		return protocol_op{ std::move(ref) };
	}

	result<protocol_op> read_modify_request(ber::reader &r, ber::tag t)
	{
		LDAP_TRY(o, r.enter(t));
		modify_request m;
		LDAP_TRY(object, o.read_string());
		m.object = std::move(object);
		LDAP_TRY(changes, o.enter());
		while (!changes.empty()) {
			LDAP_TRY(change, changes.enter());
			LDAP_TRY(op, read_ranged(change, ber::tags::enumerated, 0, 3, "modify operation", true));
			const std::size_t attr_at = change.offset();
			LDAP_TRY(attr, read_attribute(change));
			if (op == static_cast<std::int32_t>(modify_operation::add) && attr.values.empty())
				return bad("modify add change without values", attr_at);
			LDAP_TRY_VOID(skip_rest(change));
			m.changes.push_back(modify_change{ static_cast<modify_operation>(op), std::move(attr) });
		}
		LDAP_TRY_VOID(skip_rest(o));
		return protocol_op{ std::move(m) };
	}

	result<protocol_op> read_add_request(ber::reader &r, ber::tag t)
	{
		LDAP_TRY(o, r.enter(t));
		LDAP_TRY(entry, o.read_string());
		const std::size_t attrs_at = o.offset();
		LDAP_TRY(attrs, read_attributes(o));
		for (const auto &a : attrs)
			if (a.values.empty()) return bad("add request attribute '" + a.type + "' without values", attrs_at);
		LDAP_TRY_VOID(skip_rest(o));
		return protocol_op{ add_request{ std::move(entry), std::move(attrs) } };
	}

	result<protocol_op> read_modify_dn_request(ber::reader &r, ber::tag t)
	{
		LDAP_TRY(o, r.enter(t));
		modify_dn_request m;
		LDAP_TRY(entry, o.read_string());
		LDAP_TRY(new_rdn, o.read_string());
		LDAP_TRY(delete_old, o.read_boolean());
		LDAP_TRY(superior, read_optional_string(o, ber::context(0)));
		LDAP_TRY_VOID(skip_rest(o));
		m.entry = std::move(entry);
		m.new_rdn = std::move(new_rdn);
		m.delete_old_rdn = delete_old;
		m.new_superior = std::move(superior);
		return protocol_op{ std::move(m) };
	}

	result<protocol_op> read_compare_request(ber::reader &r, ber::tag t)
	{
		LDAP_TRY(o, r.enter(t));
		compare_request c;
		LDAP_TRY(entry, o.read_string());
		LDAP_TRY(ava, o.enter());
		LDAP_TRY(desc, ava.read_string());
		LDAP_TRY(value, ava.read_string());
		LDAP_TRY_VOID(skip_rest(ava));
		LDAP_TRY_VOID(skip_rest(o));
		c.entry = std::move(entry);
		c.ava = attribute_value_assertion{ std::move(desc), std::move(value) };
		return protocol_op{ std::move(c) };
	}

	result<protocol_op> read_extended_request(ber::reader &r, ber::tag t)
	{
		LDAP_TRY(o, r.enter(t));
		LDAP_TRY(name, o.read_string(ber::context(0)));
		LDAP_TRY(value, read_optional_string(o, ber::context(1)));
		LDAP_TRY_VOID(skip_rest(o));
		return protocol_op{ extended_request{ std::move(name), std::move(value) } };
	}

	result<protocol_op> read_extended_response(ber::reader &r, ber::tag t)
	{
		LDAP_TRY(o, r.enter(t));
		LDAP_TRY(res, read_result(o));
		LDAP_TRY(name, read_optional_string(o, ber::context(10)));
		LDAP_TRY(value, read_optional_string(o, ber::context(11)));
		LDAP_TRY_VOID(skip_rest(o));
		return protocol_op{ extended_response{ std::move(res), std::move(name), std::move(value) } };
	}

	result<protocol_op> read_intermediate_response(ber::reader &r, ber::tag t)
	{
		LDAP_TRY(o, r.enter(t));
		LDAP_TRY(name, read_optional_string(o, ber::context(0)));
		LDAP_TRY(value, read_optional_string(o, ber::context(1)));
		LDAP_TRY_VOID(skip_rest(o));
		return protocol_op{ intermediate_response{ std::move(name), std::move(value) } };
	}

	// Operations a client sends (RFC 4511 section 4.2 protocolOp requests).
	bool is_request(std::uint8_t number)
	{
		switch (number) {
		case op_tag::bind_request:
		case op_tag::unbind_request:
		case op_tag::search_request:
		case op_tag::modify_request:
		case op_tag::add_request:
		case op_tag::del_request:
		case op_tag::modify_dn_request:
		case op_tag::compare_request:
		case op_tag::abandon_request:
		case op_tag::extended_request:
			return true;
		default:
			return false;
		}
	}

	result<protocol_op> read_op(ber::reader &r, const decode_options &options)
	{
		const std::size_t offset = r.offset();
		LDAP_TRY(t, r.peek_tag());
		auto unsupported = [&] {
			return fail(
			  client_errc::unsupported_operation, "message: unknown protocolOp " + ber::to_string(t) + at(offset));
		};
		if (t.cls != ber::tag_class::application) return unsupported();
		// Checked before decoding, so a peer cannot make us parse (for
		// example) a huge search request filter it may not send at all.
		if (options.from == origin::server && is_request(t.number))
			return fail(client_errc::unsupported_operation,
			  "message: request operation " + ber::to_string(t) + " from a server" + at(offset));
		if (options.from == origin::client && !is_request(t.number))
			return fail(client_errc::unsupported_operation,
			  "message: response operation " + ber::to_string(t) + " from a client" + at(offset));
		switch (t.number) {
		case op_tag::bind_request:
			return read_bind_request(r, t);
		case op_tag::bind_response:
			return read_bind_response(r, t);
		case op_tag::unbind_request: {
			LDAP_TRY_VOID(r.read_null(t));
			return protocol_op{ unbind_request{} };
		}
		case op_tag::search_request:
			return read_search_request(r, t, options.filter);
		case op_tag::search_result_entry:
			return read_search_result_entry(r, t);
		case op_tag::search_result_done:
			return result_only_op<search_result_done>(r, t);
		case op_tag::search_result_reference:
			return read_search_result_reference(r, t);
		case op_tag::modify_request:
			return read_modify_request(r, t);
		case op_tag::modify_response:
			return result_only_op<modify_response>(r, t);
		case op_tag::add_request:
			return read_add_request(r, t);
		case op_tag::add_response:
			return result_only_op<add_response>(r, t);
		case op_tag::del_request: {
			LDAP_TRY(entry, r.read_string(t));
			return protocol_op{ del_request{ std::move(entry) } };
		}
		case op_tag::del_response:
			return result_only_op<del_response>(r, t);
		case op_tag::modify_dn_request:
			return read_modify_dn_request(r, t);
		case op_tag::modify_dn_response:
			return result_only_op<modify_dn_response>(r, t);
		case op_tag::compare_request:
			return read_compare_request(r, t);
		case op_tag::compare_response:
			return result_only_op<compare_response>(r, t);
		case op_tag::abandon_request: {
			LDAP_TRY(id, read_ranged(r, t, 0, max_int, "abandoned message id"));
			return protocol_op{ abandon_request{ id } };
		}
		case op_tag::extended_request:
			return read_extended_request(r, t);
		case op_tag::extended_response:
			return read_extended_response(r, t);
		case op_tag::intermediate_response:
			return read_intermediate_response(r, t);
		default:
			return unsupported();
		}
	}

	result<control> read_control(ber::reader &r)
	{
		LDAP_TRY(c, r.enter());
		control out;
		LDAP_TRY(type, c.read_string());
		out.type = std::move(type);
		if (next_is(c, ber::tags::boolean)) {
			LDAP_TRY(critical, c.read_boolean());
			out.criticality = critical;
		}
		LDAP_TRY(value, read_optional_string(c, ber::tags::octet_string));
		out.value = std::move(value);
		LDAP_TRY_VOID(skip_rest(c));
		return out;
	}

}// namespace

result<void> encode(ber::writer &w, const message &m)
{
	LDAP_TRY(filter, precheck(m));
	w.constructed(ber::tags::sequence, [&](ber::writer &msg) {
		msg.integer(m.id);
		std::visit(op_writer{ msg, filter }, m.op);
		if (!m.controls.empty())
			msg.constructed(ber::context(0), [&](ber::writer &list) {
				for (const auto &c : m.controls)
					list.constructed(ber::tags::sequence, [&](ber::writer &cw) {
						cw.octet_string(c.type);
						if (c.criticality) cw.boolean(true);
						if (c.value) cw.octet_string(*c.value);
					});
			});
	});
	return {};
}

result<std::vector<std::byte>> encode(const message &m)
{
	ber::writer w;
	LDAP_TRY_VOID(encode(w, m));
	return w.take();
}

result<message> decode(std::span<const std::byte> one_complete_message, const decode_options &options)
{
	ber::reader top(one_complete_message, options.max_depth);
	LDAP_TRY(r, top.enter());
	LDAP_TRY_VOID(top.expect_end());
	message m;
	LDAP_TRY(id, read_ranged(r, ber::tags::integer, 0, max_int, "message id"));
	m.id = id;
	LDAP_TRY(op, read_op(r, options));
	m.op = std::move(op);
	if (next_is(r, ber::context(0))) {
		LDAP_TRY(list, r.enter(ber::context(0)));
		while (!list.empty()) {
			LDAP_TRY(c, read_control(list));
			m.controls.push_back(std::move(c));
		}
	}
	LDAP_TRY_VOID(skip_rest(r));
	return m;
}

// ---------------------------------------------------------------- paged results

result<control> encode_paged_results(const paged_results &value, bool criticality)
{
	if (value.size < 0) return fail(client_errc::encode_error, "paged results: negative size");
	ber::writer w;
	w.constructed(ber::tags::sequence, [&](ber::writer &s) {
		s.integer(value.size);
		s.octet_string(value.cookie);
	});
	const auto &bytes = w.bytes();
	return control{ std::string(paged_results_oid),
		criticality,
		std::string(reinterpret_cast<const char *>(bytes.data()), bytes.size()) };
}

result<paged_results> decode_paged_results(const control &c)
{
	if (c.type != paged_results_oid)
		return fail(client_errc::decode_error,
		  "paged results: control type is " + c.type + ", not " + std::string(paged_results_oid));
	if (!c.value) return fail(client_errc::decode_error, "paged results: control has no value");
	// The control value was already taken out of its OCTET STRING by
	// decode(), so it is decoded with its own reader (offsets relative to the
	// value).
	ber::reader r(std::as_bytes(std::span(*c.value)));
	LDAP_TRY(s, r.enter());
	LDAP_TRY_VOID(r.expect_end());
	LDAP_TRY(size, read_ranged(s, ber::tags::integer, 0, max_int, "paged results size"));
	LDAP_TRY(cookie, s.read_string());
	LDAP_TRY_VOID(skip_rest(s));
	return paged_results{ size, std::move(cookie) };
}

}// namespace jhetz::ldap

#undef LDAP_TRY
#undef LDAP_TRY_VOID
