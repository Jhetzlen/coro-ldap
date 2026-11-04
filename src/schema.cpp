#include "jhetz/ldap/schema.hpp"

#include "format_util.hpp"

#include <algorithm>
#include <array>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <unordered_set>
#include <utility>
#include <vector>

namespace jhetz::ldap {
namespace {

	auto is_space(char c) -> bool { return c == ' ' || c == '\t' || c == '\n' || c == '\r'; }

	// RFC 4512 section 4.1 definitions: "(", ")", "$", 'quoted strings'
	// (with \27 and \5C escapes) and bare words (keywords, OIDs,
	// descriptors, "noidlen" like 1.2.3{64}). "$" ends a word: an oidlist
	// is oid *( WSP DOLLAR WSP oid ) with WSP = 0*SPACE (section 1.4), so
	// "(sn$cn)" is two oids.
	struct token
	{
		enum class kind { open, close, dollar, quoted, word, end } k;
		std::string text;
	};

	class lexer
	{
	  public:
		explicit lexer(std::string_view s) : s_(s) {}

		auto next() -> result<token>
		{
			while (pos_ < s_.size() && is_space(s_[pos_])) {
				++pos_;
			}
			if (pos_ == s_.size()) {
				return token{ .k = token::kind::end, .text = {} };
			}
			const char c = s_[pos_];
			if (c == '(') {
				return ++pos_, token{ .k = token::kind::open, .text = {} };
			}
			if (c == ')') {
				return ++pos_, token{ .k = token::kind::close, .text = {} };
			}
			if (c == '$') {
				return ++pos_, token{ .k = token::kind::dollar, .text = {} };
			}
			if (c == '\'') {
				++pos_;
				std::string out;
				while (pos_ < s_.size() && s_[pos_] != '\'') {
					if (s_[pos_] == '\\' && s_.size() - pos_ >= 3) {
						const std::string_view hex = s_.substr(pos_ + 1, 2);
						if (hex == "27") {
							out += '\'';
						} else if (hex == "5c" || hex == "5C") {
							out += '\\';
						} else {
							return fail(client_errc::decode_error, "schema: bad escape in a quoted string");
						}
						pos_ += 3;
					} else {
						out += s_[pos_++];
					}
				}
				if (pos_ == s_.size()) {
					return fail(client_errc::decode_error, "schema: unterminated quoted string");
				}
				++pos_;
				return token{ .k = token::kind::quoted, .text = std::move(out) };
			}
			const std::size_t start = pos_;
			while (pos_ < s_.size() && !is_space(s_[pos_]) && s_[pos_] != '(' && s_[pos_] != ')' && s_[pos_] != '$'
				   && s_[pos_] != '\'') {
				++pos_;
			}
			return token{ .k = token::kind::word, .text = std::string(s_.substr(start, pos_ - start)) };
		}

		// Consumes a "$" that comes next (after spaces), if one does.
		auto skip_dollar() -> bool
		{
			std::size_t p = pos_;
			while (p < s_.size() && is_space(s_[p])) {
				++p;
			}
			if (p == s_.size() || s_[p] != '$') {
				return false;
			}
			pos_ = p + 1;
			return true;
		}

	  private:
		std::string_view s_;
		std::size_t pos_ = 0;
	};

	// A keyword: RFC 4512 keystring (ALPHA *( ALPHA / DIGIT / "-" )) or an
	// extension's xstring ("X-" 1*( ALPHA / "-" / "_" ), as eDirectory's
	// X-NDS_SYNTAX). Anything else (a "{256}" spaced from SYNTAX's OID, a
	// stray "$" (a token of its own) or OID) fails the definition: taken as a keyword, it would
	// swallow the next one (SINGLE-VALUE, say) as its value.
	auto is_keyword(std::string_view k) -> bool
	{
		if (k.empty() || !detail::is_alpha(k[0])) {
			return false;
		}
		return std::ranges::all_of(k, [](char c) { return detail::is_keychar(c) || c == '_'; });
	}

	// Keywords without an argument.
	auto is_flag(std::string_view k) -> bool
	{
		static constexpr std::array flags{
			"OBSOLETE", "SINGLE-VALUE", "COLLECTIVE", "NO-USER-MODIFICATION", "ABSTRACT", "STRUCTURAL", "AUXILIARY"
		};
		return std::ranges::any_of(flags, [k](const char *f) { return detail::iequals(k, f); });
	}

	// A definition as an OID and keyword -> values (a list argument gives
	// several values; '$' separators are dropped).
	struct definition
	{
		std::string oid;
		std::vector<std::pair<std::string, std::vector<std::string>>> fields;

		[[nodiscard]] auto get(std::string_view keyword) const -> const std::vector<std::string> *
		{
			for (const auto &[k, v] : fields) {
				if (detail::iequals(k, keyword)) {
					return &v;
				}
			}
			return nullptr;
		}
		[[nodiscard]] auto has(std::string_view keyword) const -> bool { return get(keyword) != nullptr; }
	};

	auto schema_error(const char *why) -> std::unexpected<error>
	{
		return fail(client_errc::decode_error, detail::format("schema: {}", why));
	}

	// The keywords whose argument is an oidlist (RFC 4512 4.1.1 SUP, MUST
	// and MAY of an object class), for which an unparenthesised "a$b" is
	// read as the list "( a $ b )".
	auto is_oidlist_keyword(std::string_view k) -> bool
	{
		return detail::iequals(k, "SUP") || detail::iequals(k, "MUST") || detail::iequals(k, "MAY");
	}

	// Which definition parse_definition reads: an object class's SUP is
	// an oidlist (oids), an attribute type's one oid.
	enum class definition_kind { attribute_type, object_class };

	// A keyword's argument: one word or quoted string, or a parenthesised
	// list of them ('$' separators dropped), appended to `values`. With
	// `oidlist`, a word followed by "$" starts an unparenthesised list,
	// "cn$sn" or "cn $ sn" (RFC 4512 4.1 parenthesises a list of several
	// oids; this is a convenience for servers that do not), each "$"
	// followed by a word or quoted string.
	auto read_values(lexer &lx, std::vector<std::string> &values, bool oidlist) -> result<void>
	{
		constexpr std::size_t max_values = 4096;
		auto v = lx.next();
		if (!v) {
			return std::unexpected(std::move(v.error()));
		}
		if (v->k == token::kind::word || v->k == token::kind::quoted) {
			values.push_back(std::move(v->text));
			while (oidlist && lx.skip_dollar()) {
				auto e = lx.next();
				if (!e) {
					return std::unexpected(std::move(e.error()));
				}
				if (e->k != token::kind::word && e->k != token::kind::quoted) {
					return schema_error("'$' without an oid after it");
				}
				if (values.size() == max_values) {
					return schema_error("list too long");
				}
				values.push_back(std::move(e->text));
			}
			return {};
		}
		if (v->k != token::kind::open) {
			return schema_error("missing value");
		}
		while (true) {
			auto e = lx.next();
			if (!e) {
				return std::unexpected(std::move(e.error()));
			}
			if (e->k == token::kind::close) {
				return {};
			}
			if (e->k == token::kind::end || e->k == token::kind::open) {
				return schema_error("unterminated list");
			}
			if (e->k == token::kind::dollar) {
				continue;
			}
			if (values.size() == max_values) {
				return schema_error("list too long");
			}
			values.push_back(std::move(e->text));
		}
	}

	auto parse_definition(std::string_view text, definition_kind kind) -> result<definition>
	{
		// RFC 4512 section 4.1: a definition is ASCII but for its qdstrings
		// (NAME, DESC), which are UTF-8 (QUTF8, section 1.4); the \27 and
		// \5C escapes are ASCII, so the whole text must be UTF-8. A
		// definition that is not fails like any other syntax error.
		if (const std::size_t bad = detail::invalid_utf8_offset(text); bad != std::string_view::npos) {
			return fail(client_errc::decode_error,
			  detail::format("schema: not valid UTF-8 (ill-formed sequence at offset {})", bad));
		}
		lexer lx(text);
		auto t = lx.next();
		if (!t) {
			return std::unexpected(std::move(t.error()));
		}
		if (t->k != token::kind::open) {
			return schema_error("a definition starts with '('");
		}
		t = lx.next();
		if (!t) {
			return std::unexpected(std::move(t.error()));
		}
		if (t->k != token::kind::word && t->k != token::kind::quoted) {
			return schema_error("missing OID");
		}
		definition d;
		d.oid = std::move(t->text);
		if (!detail::is_oid(d.oid)) {
			return schema_error("invalid OID");
		}
		constexpr std::size_t max_fields = 256;
		while (true) {
			auto k = lx.next();
			if (!k) {
				return std::unexpected(std::move(k.error()));
			}
			if (k->k == token::kind::close) {
				break;
			}
			if (k->k == token::kind::end) {
				return schema_error("missing ')'");
			}
			if (k->k != token::kind::word || !is_keyword(k->text)) {
				return schema_error("expected a keyword");
			}
			if (d.fields.size() == max_fields) {
				return schema_error("too many fields");
			}
			std::vector<std::string> values;
			if (!is_flag(k->text)) {
				const bool oidlist = kind == definition_kind::object_class && is_oidlist_keyword(k->text);
				if (auto r = read_values(lx, values, oidlist); !r) {
					return std::unexpected(std::move(r.error()));
				}
			}
			d.fields.emplace_back(std::move(k->text), std::move(values));
		}
		auto rest = lx.next();
		if (!rest) {
			return std::unexpected(std::move(rest.error()));
		}
		if (rest->k != token::kind::end) {
			return schema_error("text after the closing ')'");
		}
		return d;
	}

	// noidlen without its length: "1.2.3{64}" -> "1.2.3". The length must
	// be "{" 1*DIGIT "}" right after the OID and end the text; otherwise
	// nullopt (the definition is then skipped).
	auto strip_length(std::string_view s) -> std::optional<std::string>
	{
		const std::size_t open = s.find('{');
		if (open == std::string_view::npos) {
			return std::string(s);
		}
		const std::string_view len = s.substr(open + 1);
		if (len.size() < 2 || len.back() != '}') {
			return std::nullopt;
		}
		if (!std::ranges::all_of(len.substr(0, len.size() - 1), detail::is_digit)) {
			return std::nullopt;
		}
		return std::string(s.substr(0, open));
	}

	// Keeps the values that `valid` accepts; others could never be looked
	// up, so they are dropped.
	template<class Pred> auto kept(const std::vector<std::string> *values, Pred valid) -> std::vector<std::string>
	{
		std::vector<std::string> out;
		if (values != nullptr) {
			for (const auto &n : *values) {
				if (valid(n)) {
					out.push_back(n);
				}
			}
		}
		return out;
	}

	// The NAMEs that are valid descriptors (RFC 4512 section 1.4).
	auto valid_names(const std::vector<std::string> *names) -> std::vector<std::string>
	{
		return kept(names, [](const std::string &n) { return detail::is_descr(n); });
	}

	// The oids (descr / numericoid, RFC 4512 section 1.4) of a SUP, MUST or
	// MAY list.
	auto valid_oids(const std::vector<std::string> *oids) -> std::vector<std::string>
	{
		return kept(oids, [](const std::string &n) { return detail::is_oid(n); });
	}

	// "cn;lang-en" -> "cn".
	auto without_options(std::string_view s) -> std::string_view { return s.substr(0, s.find(';')); }

}// namespace

namespace {

	// The attribute type of a definition that parsed; fails only for its
	// SYNTAX (server_schema::parse remembers those definitions' names).
	auto to_attribute_type(definition &&d) -> result<attribute_type>
	{
		attribute_type a;
		a.oid = std::move(d.oid);
		a.names = valid_names(d.get("NAME"));
		if (const auto *s = d.get("SUP"); s && !s->empty()) {
			a.sup = s->front();
		}
		if (const auto *s = d.get("EQUALITY"); s && !s->empty()) {
			a.equality = s->front();
		}
		// RFC 4512 section 4.1.2: SYNTAX noidlen, a numericoid with an
		// optional {len} right after it ("{" 1*DIGIT "}", no space; a spaced
		// "{len}" already failed as a keyword). Anything else could never
		// match a syntax the mapping knows, and would be the server's raw
		// text in a report.
		if (const auto *s = d.get("SYNTAX"); s && !s->empty()) {
			a.syntax = strip_length(s->front());
			if (!a.syntax || !detail::is_numericoid(*a.syntax)) {
				return fail(client_errc::decode_error, "schema: SYNTAX is not a numeric OID");
			}
		}
		a.single_value = d.has("SINGLE-VALUE");
		a.no_user_modification = d.has("NO-USER-MODIFICATION");
		return a;
	}

}// namespace

auto parse_attribute_type(std::string_view text) -> result<attribute_type>
{
	return parse_definition(text, definition_kind::attribute_type).and_then(to_attribute_type);
}

auto parse_object_class(std::string_view text) -> result<object_class_type>
{
	return parse_definition(text, definition_kind::object_class).transform([](definition &&d) {
		object_class_type c;
		c.oid = std::move(d.oid);
		c.names = valid_names(d.get("NAME"));
		c.sup = valid_oids(d.get("SUP"));
		// RFC 4512 4.1.1: one kind, STRUCTURAL by default; the first wins
		// if a server writes several.
		for (const auto &[k, v] : d.fields) {
			if (detail::iequals(k, "ABSTRACT")) {
				c.kind = object_class_kind::abstract;
				break;
			}
			if (detail::iequals(k, "STRUCTURAL")) {
				c.kind = object_class_kind::structural;
				break;
			}
			if (detail::iequals(k, "AUXILIARY")) {
				c.kind = object_class_kind::auxiliary;
				break;
			}
		}
		c.must = valid_oids(d.get("MUST"));
		c.may = valid_oids(d.get("MAY"));
		return c;
	});
}

// Public API, subschema attribute order (RFC 4512 4.2); kept by decision (coro-ldap-bsm.30).
// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
auto server_schema::parse(std::span<const std::pmr::string> attribute_types,
  std::span<const std::pmr::string> object_classes) -> server_schema
{
	server_schema s;
	for (const auto &text : attribute_types) {
		auto d = parse_definition(text, definition_kind::attribute_type);
		if (!d) {
			++s.skipped_;
			continue;
		}
		// Kept before the definition is moved: its names, if the SYNTAX
		// fails (they are valid descriptors or an OID, never raw text).
		std::vector<std::string> names = valid_names(d->get("NAME"));
		names.push_back(d->oid);
		auto a = to_attribute_type(std::move(*d));
		if (!a) {
			++s.skipped_;
			for (auto &n : names) {
				s.bad_syntax_.insert(std::move(n));
			}
			continue;
		}
		const std::size_t i = s.attributes_.size();
		s.attribute_index_.emplace(a->oid, i);
		for (const auto &n : a->names) {
			s.attribute_index_.emplace(n, i);
		}
		s.attributes_.push_back(std::move(*a));
	}
	for (const auto &text : object_classes) {
		auto c = parse_object_class(text);
		if (!c) {
			++s.skipped_;
			continue;
		}
		const std::size_t i = s.classes_.size();
		s.class_index_.emplace(c->oid, i);
		for (const auto &n : c->names) {
			s.class_index_.emplace(n, i);
		}
		s.classes_.push_back(std::move(*c));
	}
	return s;
}

auto server_schema::find_attribute(std::string_view name) const noexcept -> const attribute_type *
{
	const auto it = attribute_index_.find(without_options(name));
	return it == attribute_index_.end() ? nullptr : &attributes_[it->second];
}

auto server_schema::find_object_class(std::string_view name) const noexcept -> const object_class_type *
{
	const auto it = class_index_.find(name);
	return it == class_index_.end() ? nullptr : &classes_[it->second];
}

auto server_schema::skipped_for_syntax(std::string_view name) const noexcept -> bool
{
	return bad_syntax_.contains(without_options(name));
}

namespace {

	// Longest SUP chain followed; a longer one is taken for a cycle.
	constexpr int max_sup_depth = 32;

	// The first definition on a's SUP chain (a itself first) that has
	// `field`; nullptr if none does, a SUP is not found, or the chain is
	// longer than max_sup_depth (a cycle).
	auto inherited(const server_schema &s,
	  const attribute_type &a,
	  std::optional<std::string> attribute_type::*field) noexcept -> const std::string *
	{
		const attribute_type *cur = &a;
		for (int depth = 0; depth < max_sup_depth && cur != nullptr; ++depth) {
			if (const auto &v = cur->*field) {
				return &*v;
			}
			if (!cur->sup) {
				return nullptr;
			}
			cur = s.find_attribute(*cur->sup);
		}
		return nullptr;
	}

}// namespace

auto server_schema::syntax_of(const attribute_type &a) const noexcept -> const std::string *
{
	return inherited(*this, a, &attribute_type::syntax);
}

auto server_schema::equality_of(const attribute_type &a) const noexcept -> const std::string *
{
	return inherited(*this, a, &attribute_type::equality);
}

// ---------------------------------------------------------------- report

auto schema_report::ok() const noexcept -> bool { return std::ranges::none_of(issues, &schema_issue::is_error); }

auto schema_report::to_string() const -> std::string
{
	std::string out;
	for (const auto &i : issues) {
		if (!out.empty()) {
			out += '\n';
		}
		detail::format_to(out,
		  "{}{}{}: {}",
		  i.is_error() ? "error: " : "warning: ",
		  i.what == schema_issue::kind::unknown_object_class || i.what == schema_issue::kind::unknown_superclass
			? "object class "
			: "attribute ",
		  i.name,
		  i.detail);
	}
	return out;
}

namespace {

	// Why syntax_of(a) is nullptr: a SUP that names no definition (or one
	// skipped for its SYNTAX), a chain too long (a cycle), or a chain that
	// ends without any SYNTAX (RFC 4512 4.1.2 requires a SYNTAX or a SUP;
	// slapd refuses such a definition, AD always gives SYNTAX). The syntax
	// cannot be checked then, which is an error, not a silent pass.
	auto broken_sup_chain(const server_schema &s, const attribute_type &a) -> std::string
	{
		const attribute_type *cur = &a;
		for (int depth = 0; depth < max_sup_depth; ++depth) {
			if (!cur->sup) {
				return cur == &a ? "syntax unknown: the server declares no SYNTAX and no SUP for it"
								 : "syntax unknown: the server declares no SYNTAX for it or its supertypes";
			}
			const attribute_type *next = s.find_attribute(*cur->sup);
			if (next == nullptr) {
				std::string text = "syntax unknown: SUP ";
				detail::append_sanitized(text, *cur->sup, 64);
				text += s.skipped_for_syntax(*cur->sup)
						  ? " is defined on the server, but skipped: its SYNTAX is not a numeric OID"
						  : " is not defined on the server";
				return text;
			}
			cur = next;
		}
		return detail::format("syntax unknown: the SUP chain is longer than {} (a cycle?)", max_sup_depth);
	}

}// namespace

namespace {

	auto class_name(const object_class_type &c) -> std::string_view
	{
		return c.names.empty() ? std::string_view(c.oid) : std::string_view(c.names.front());
	}

	// Names folded as lookups fold them (ASCII case only).
	using ci_set = std::unordered_set<std::string_view, detail::ci_hash, detail::ci_equal>;

	// A class whose MUSTs apply, and the declared class it was reached
	// from (empty for a declared class).
	struct reached_class
	{
		const object_class_type *c;
		std::string_view from;
	};

	// The declared classes (those the server defines), then their
	// superclasses breadth first, each once (a SUP cycle ends). A SUP the
	// server does not define is reported once, as unknown_superclass.
	auto with_superclasses(const server_schema &s, std::span<const char *const> classes, schema_report &out)
	  -> std::vector<reached_class>
	{
		// Hashed: a server's schema may chain thousands of classes.
		std::vector<reached_class> all;
		std::unordered_set<const object_class_type *> seen;
		for (const char *name : classes) {
			if (const object_class_type *c = s.find_object_class(name); c != nullptr && seen.insert(c).second) {
				all.push_back({ .c = c, .from = {} });
			}
		}
		ci_set unknown;
		for (std::size_t i = 0; i < all.size(); ++i) {
			const reached_class r = all[i];
			const std::string_view declared = r.from.empty() ? class_name(*r.c) : r.from;
			for (const auto &sup : r.c->sup) {
				if (const object_class_type *c = s.find_object_class(sup); c != nullptr) {
					if (seen.insert(c).second) {
						all.push_back({ .c = c, .from = declared });
					}
					continue;
				}
				if (!unknown.insert(sup).second) {
					continue;
				}
				out.issues.push_back({ .what = schema_issue::kind::unknown_superclass,
				  .name = sup,
				  .detail = detail::format(
					"a superclass of {} not defined on the server: the MUST attributes it would add are not checked",
					declared) });
			}
		}
		return all;
	}

	// How the members map a MUST attribute (a: its definition, or nullptr).
	struct must_mapping
	{
		bool mapped = false;
		bool required = false;
		std::string_view why;// for mapped but not required
	};

	auto mapping_of(const server_schema &s,
	  const attribute_type *a,
	  std::string_view must,
	  std::span<const detail::field_use> fields) -> must_mapping
	{
		must_mapping out;
		for (const detail::field_use &f : fields) {
			const attribute_type *fa = s.find_attribute(f.name);
			const bool same = a != nullptr && fa != nullptr ? fa == a : detail::iequals(without_options(f.name), must);
			if (!same) {
				continue;
			}
			out.mapped = true;
			if (f.read_only) {
				out.why = "read_only: add(dn, T) never sends it";
			} else if (f.kind == cardinality::optional) {
				out.why = "a std::optional: add(dn, T) sends nothing when it is empty";
			} else if (f.kind == cardinality::multiple) {
				out.why = "a std::vector: add(dn, T) sends nothing when it is empty";
			} else {
				out.required = true;
				return out;
			}
		}
		return out;
	}

	void report_must(const reached_class &r, std::string_view must, const must_mapping &m, schema_report &out)
	{
		if (m.required) {
			return;
		}
		std::string text = detail::format("required (MUST) by object class {}", class_name(*r.c));
		if (!r.from.empty()) {
			detail::format_to(text, " (a superclass of {})", r.from);
		}
		if (m.mapped) {
			detail::format_to(text, ", but its member is {}", m.why);
		} else {
			text += ", but no member maps it: add(dn, T) fails unless the entry's RDN or the server supplies it";
		}
		out.issues.push_back({ .what = m.mapped ? schema_issue::kind::must_attribute_not_required
												: schema_issue::kind::must_attribute_not_mapped,
		  .name = std::string(must),
		  .detail = std::move(text) });
	}

}// namespace

namespace detail {

	void check_object_class(const server_schema &s, std::string_view name, schema_report &out)
	{
		if (s.find_object_class(name) == nullptr) {
			out.issues.push_back({ .what = schema_issue::kind::unknown_object_class,
			  .name = std::string(name),
			  .detail = "not defined on the server" });
		}
	}

	void check_field(const server_schema &s,
	  std::string_view name,
	  cardinality kind,
	  bool read_only,
	  std::span<const char *const> syntaxes,
	  std::span<const char *const> rejected,
	  schema_report &out)
	{
		const attribute_type *a = s.find_attribute(name);
		if (a == nullptr) {
			out.issues.push_back({ .what = schema_issue::kind::unknown_attribute,
			  .name = std::string(name),
			  .detail = s.skipped_for_syntax(name)
						  ? "defined on the server, but skipped: its SYNTAX is not a numeric OID"
						  : "not defined on the server" });
			return;
		}
		if (kind != cardinality::multiple && !a->single_value) {
			out.issues.push_back({ .what = schema_issue::kind::single_member_multi_valued,
			  .name = std::string(name),
			  .detail =
				"single-valued member, but the attribute is multi-valued (decoding fails if an entry has several "
				"values)" });
		}
		if (!read_only && a->no_user_modification) {
			out.issues.push_back({ .what = schema_issue::kind::writable_but_no_user_modification,
			  .name = std::string(name),
			  .detail = "the attribute is NO-USER-MODIFICATION: mark the member ldap::read_only" });
		}
		if (!syntaxes.empty()) {
			const std::string *syn = s.syntax_of(*a);
			if (syn == nullptr) {
				out.issues.push_back({ .what = schema_issue::kind::syntax_mismatch,
				  .name = std::string(name),
				  .detail = broken_sup_chain(s, *a) });
			} else if (std::ranges::none_of(syntaxes, [&](const char *x) { return *syn == x; })) {
				// A numeric OID (parse_attribute_type), but of any length.
				std::string text = "syntax ";
				detail::append_sanitized(text, *syn, 64);
				text += " is not one the member's type reads (";
				for (std::size_t i = 0; i < syntaxes.size(); ++i) {
					detail::format_to(text, "{}{}", i != 0 ? ", " : "", syntaxes[i]);
				}
				text += ')';
				out.issues.push_back({ .what = schema_issue::kind::syntax_mismatch,
				  .name = std::string(name),
				  .detail = std::move(text) });
			}
		} else if (!rejected.empty()) {
			// Any syntax but these. A syntax that cannot be determined is not
			// reported: the member's type reads almost any.
			const std::string *syn = s.syntax_of(*a);
			const auto is = [&](const char *x) { return syn != nullptr && *syn == x; };
			if (std::ranges::any_of(rejected, is)) {
				std::string text = "syntax ";
				detail::append_sanitized(text, *syn, 64);
				text += " is one the member's type refuses";
				if (std::ranges::any_of(detail::binary_syntaxes, is)) {
					text += ": its values are binary, map the member to ldap::binary";
				}
				out.issues.push_back({ .what = schema_issue::kind::syntax_mismatch,
				  .name = std::string(name),
				  .detail = std::move(text) });
			}
		}
	}

	void check_must(const server_schema &s,
	  std::span<const char *const> classes,
	  std::span<const field_use> fields,
	  schema_report &out)
	{
		const std::vector<reached_class> all = with_superclasses(s, classes, out);
		// objectClass (RFC 4512 3.3, OID 2.5.4.0) by any of its names: add
		// sends the declared classes.
		const attribute_type *object_class = s.find_attribute("objectClass");
		const auto is_object_class = [&](std::string_view m, const attribute_type *a) {
			if (a != nullptr) {
				return a == object_class || a->oid == "2.5.4.0";
			}
			return detail::iequals(m, "objectClass") || m == "2.5.4.0";
		};
		// Each attribute once: by its definition, or by its name if the
		// server does not define it.
		std::unordered_set<const attribute_type *> done_types;
		ci_set done_names;
		for (const reached_class &r : all) {
			for (const auto &m : r.c->must) {
				const attribute_type *a = s.find_attribute(m);
				if (is_object_class(m, a)) {
					continue;
				}
				if (a != nullptr) {
					if (a->no_user_modification || !done_types.insert(a).second) {
						continue;// the server's to provide (RFC 4511 4.7), or done
					}
				} else if (!done_names.insert(m).second) {
					continue;
				}
				report_must(r, m, mapping_of(s, a, m, fields), out);
			}
		}
	}

}// namespace detail

}// namespace jhetz::ldap
