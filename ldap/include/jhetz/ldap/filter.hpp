// Search filters (DESIGN.md section 2): RFC 4515 text, escaping builders, and
// the text <-> BER conversion used by the search request codec.
#pragma once

#include "jhetz/ldap/attribute.hpp"
#include "jhetz/ldap/ber.hpp"
#include "jhetz/ldap/error.hpp"

#include <cstddef>
#include <string>
#include <string_view>
#include <utility>

namespace jhetz::ldap {

// Maximum nesting of filter elements, counting every `(...)` on the path from
// the outermost filter to a leaf: `(cn=x)` has depth 1, `(&(cn=x))` depth 2.
// Deeper filters fail with invalid_filter when encoded and with
// nesting_too_deep when decoded. The value keeps a search request with the
// deepest allowed filter within ber::reader's default depth limit (32):
// LDAPMessage and SearchRequest take 2 levels, a substrings leaf 1 extra.
inline constexpr std::size_t max_filter_depth = 24;

// A filter is its RFC 4515 text. Build it with the ldap::filters operators
// (values are escaped, so user input cannot change the filter structure) or
// pass text through unchanged with filter::raw. Text is only parsed when a
// request is encoded; a malformed filter then fails with invalid_filter.
struct filter
{
	std::string text{};

	static filter raw(std::string text) { return filter{ std::move(text) }; }

	friend bool operator==(const filter &, const filter &) = default;
};

// RFC 4515 section 3 escaping: `*` `(` `)` `\` and NUL become \2a \28 \29 \5c
// \00; every other byte is kept as is.
std::string escape_filter_value(std::string_view value);

namespace filters {

	// `attr(a) == v` and friends (DESIGN.md section 2 table). A literal name is
	// checked at compile time; an ldap::attribute is checked when attr() is
	// built and throws std::invalid_argument if it is not a valid attribute
	// description (only possible with attribute::unchecked), so an attribute
	// name can never inject filter syntax either.
	class attr
	{
	  public:
		attr(attribute::literal name) : name_(name.text) {}
		explicit attr(const attribute &name);

		filter operator==(std::string_view value) const;// (a=v)
		filter operator>=(std::string_view value) const;// (a>=v)
		filter operator<=(std::string_view value) const;// (a<=v)
		filter approx(std::string_view value) const;// (a~=v)
		filter present() const;// (a=*)
		// (a=v*), (a=*v), (a=*v*). With an empty value these mean "has any
		// value" and produce (a=*), since (a=**) is not a valid filter.
		filter starts_with(std::string_view value) const;
		filter ends_with(std::string_view value) const;
		filter contains(std::string_view value) const;

	  private:
		filter simple(std::string_view op, std::string_view value) const;

		std::string name_;
	};

	// (&fg), (|fg), (!f). Operands that already are an AND (resp. OR) are
	// merged, so `a && b && c` gives (&abc), not (&(&ab)c).
	filter operator&&(const filter &f, const filter &g);
	filter operator||(const filter &f, const filter &g);
	filter operator!(const filter &f);

}// namespace filters

// Parses RFC 4515 text and appends the BER Filter (RFC 4511 section 4.5.1.7)
// to `w`. On failure `w` is unchanged and the error is invalid_filter with the
// position in the context.
//
// Supported: and/or/not, RFC 4526 absolute true/false `(&)` and `(|)`,
// equality, substrings (empty `any` parts such as `a**b` are skipped), >=, <=,
// ~=, presence, extensible match (`attr[:dn][:rule]:=v`, `[:dn]:rule:=v`),
// attribute options (`cn;lang-en`), numeric OIDs, `\xx` escapes.
// Leniency: text that does not start with '(' is wrapped in parentheses, as
// ldapsearch does (`uid=jdoe` is `(uid=jdoe)`). No other leniency: no
// whitespace between elements, and `(`, `)`, `*` (outside substrings), `\`
// and NUL must be escaped in values.
result<void> encode_filter(ber::writer &w, std::string_view text);

// Reads one BER Filter from `r` and returns its canonical RFC 4515 text:
// values escaped with escape_filter_value (hex digits lower case), `:dn`
// spelled in lower case, everything else as sent. The text parses back to the
// same BER. Filters that cannot be written as RFC 4515 text are rejected with
// decode_error (invalid attribute descriptions, empty substrings, initial or
// final out of place, extensible match without type and rule), as are
// filters deeper than max_filter_depth (nesting_too_deep). On failure `r` is
// unchanged.
result<std::string> decode_filter(ber::reader &r);

}// namespace jhetz::ldap
