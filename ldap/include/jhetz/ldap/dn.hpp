// Distinguished names (RFC 4514 string form), DESIGN.md section 1.
//
// Scope: syntax only. Attribute types compare case-insensitively and values
// compare byte for byte after unescaping; matching-rule normalization
// (caseIgnoreMatch on values, whitespace folding, schema-aware aliases such as
// `cn` vs `2.5.4.3`, Unicode normalization) is out of scope, so
// `cn=John` != `cn=john` here even though most servers treat them as equal.
//
// Parsing is RFC 4514 with the leniency of RFC 2253 section 4 / OpenLDAP:
// spaces around `,`, `+` and `=` are ignored, and unescaped trailing spaces of
// a value are dropped. Everything else follows RFC 4514: the text is UTF-8,
// `"`, `;`, `<`, `>` and NUL must be escaped, `\` is followed by a special
// character or two hex digits (any octet, so values need not be UTF-8), `#`
// starts a hex-encoded (BER) value, types are descriptors or numeric OIDs
// without options. to_string() escapes octets that are not part of valid
// UTF-8, so its output is UTF-8 too.
//
// Memory: ava, rdn and dn are allocator-aware (std::pmr). Everything a dn owns
// is allocated from the resource given to parse(), the literal constructor or
// the allocator-extended constructors; parent() and child() use the dn's own
// resource. A plain copy uses the default resource, assignment keeps the
// target's resource.
#pragma once

#include "jhetz/ldap/attribute.hpp"
#include "jhetz/ldap/error.hpp"

#include <cstddef>
#include <initializer_list>
#include <memory_resource>
#include <string>
#include <string_view>
#include <vector>

namespace jhetz::ldap {

namespace detail {

	// Characters that may follow `\` as themselves (RFC 4514 `special` + ESC).
	constexpr bool is_dn_escapable(char c) noexcept
	{
		switch (c) {
		case '\\':
		case '"':
		case '+':
		case ',':
		case ';':
		case '<':
		case '>':
		case ' ':
		case '#':
		case '=':
			return true;
		default:
			return false;
		}
	}

	struct dn_token
	{
		std::string_view type;
		std::string_view raw_value;// escaped text, or hex digits after '#'
		bool hex = false;// `#hexstring` form
		bool new_rdn = true;// false: joined to the previous AVA with '+'
	};

	// Scans RFC 4514 text and calls `on_ava(dn_token)` for every AVA in
	// order. Returns npos on success, otherwise the offset of the error.
	// constexpr, so the same code validates literals at compile time.
	template<class F> constexpr std::size_t scan_dn(std::string_view s, F &&on_ava)
	{
		constexpr std::size_t ok = std::string_view::npos;
		if (s.empty()) return ok;
		const std::size_t n = s.size();
		std::size_t i = 0;
		bool new_rdn = true;
		auto skip_spaces = [&] {
			while (i < n && s[i] == ' ') ++i;
		};
		while (true) {
			skip_spaces();
			const std::size_t type_start = i;
			while (i < n && (is_keychar(s[i]) || s[i] == '.')) ++i;
			const std::string_view type = s.substr(type_start, i - type_start);
			if (!is_oid(type)) return type_start;
			skip_spaces();
			if (i == n || s[i] != '=') return i;
			++i;
			skip_spaces();

			dn_token tok{ type, {}, false, new_rdn };
			if (i < n && s[i] == '#') {
				++i;
				const std::size_t start = i;
				while (i < n && is_hex(s[i])) ++i;
				if (i == start || (i - start) % 2 != 0) return i;
				tok.raw_value = s.substr(start, i - start);
				tok.hex = true;
				skip_spaces();
			} else {
				const std::size_t start = i;
				std::size_t end = i;// end of the value without unescaped trailing spaces
				while (i < n) {
					const char c = s[i];
					if (c == '\\') {
						if (i + 1 < n && is_dn_escapable(s[i + 1])) {
							i += 2;
						} else if (i + 2 < n && is_hex(s[i + 1]) && is_hex(s[i + 2])) {
							i += 3;
						} else {
							return i;
						}
						end = i;
					} else if (c == ',' || c == '+') {
						break;
					} else if (c == '"' || c == ';' || c == '<' || c == '>' || c == '\0') {
						return i;
					} else if (c == ' ') {
						++i;
					} else if (static_cast<unsigned char>(c) >= 0x80u) {
						const std::size_t len = utf8_sequence_length(s, i);// RFC 4514: UTF-8 only
						if (len == 0) return i;
						i += len;
						end = i;
					} else {
						++i;
						end = i;
					}
				}
				tok.raw_value = s.substr(start, end - start);
			}
			on_ava(tok);
			if (i == n) return ok;
			if (s[i] == ',')
				new_rdn = true;
			else if (s[i] == '+')
				new_rdn = false;
			else
				return i;
			++i;
		}
	}

	constexpr bool is_dn(std::string_view s) noexcept
	{
		return scan_dn(s, [](const dn_token &) {}) == std::string_view::npos;
	}

}// namespace detail

// One attribute type and value of an RDN. `value` holds the unescaped bytes;
// for the `#hexstring` form (`hex_form == true`) it holds the decoded BER
// bytes, and to_string() writes them back as `#...`.
struct ava
{
	using allocator_type = std::pmr::polymorphic_allocator<>;

	attribute type{};
	std::pmr::string value{};
	bool hex_form = false;

	ava() = default;
	explicit ava(const allocator_type &alloc) : type(alloc), value(alloc) {}
	ava(const attribute &type_, std::string_view value_, bool hex_form_ = false, const allocator_type &alloc = {})
	  : type(type_, alloc), value(value_, alloc), hex_form(hex_form_)
	{}
	ava(const ava &) = default;
	ava(ava &&) noexcept = default;
	ava(const ava &other, const allocator_type &alloc)
	  : type(other.type, alloc), value(other.value, alloc), hex_form(other.hex_form)
	{}
	ava(ava &&other, const allocator_type &alloc)
	  : type(std::move(other.type), alloc), value(std::move(other.value), alloc), hex_form(other.hex_form)
	{}
	ava &operator=(const ava &) = default;
	ava &operator=(ava &&) = default;
	~ava() = default;

	allocator_type get_allocator() const noexcept { return value.get_allocator(); }

	// Type case-insensitively, value and form exactly.
	friend bool operator==(const ava &, const ava &) = default;
};

// Relative distinguished name: one or more AVAs joined with '+'. Equality
// ignores the order of the AVAs (RFC 4512: an RDN is a set).
struct rdn
{
	using allocator_type = std::pmr::polymorphic_allocator<>;

	std::pmr::vector<ava> avas{};

	rdn() = default;
	explicit rdn(const allocator_type &alloc) : avas(alloc) {}
	rdn(std::initializer_list<ava> avas_, const allocator_type &alloc = {}) : avas(avas_, alloc) {}
	rdn(const rdn &) = default;
	rdn(rdn &&) noexcept = default;
	rdn(const rdn &other, const allocator_type &alloc) : avas(other.avas, alloc) {}
	rdn(rdn &&other, const allocator_type &alloc) : avas(std::move(other.avas), alloc) {}
	rdn &operator=(const rdn &) = default;
	rdn &operator=(rdn &&) = default;
	~rdn() = default;

	allocator_type get_allocator() const noexcept { return avas.get_allocator(); }

	friend bool operator==(const rdn &a, const rdn &b);
};

class dn
{
  public:
	using allocator_type = std::pmr::polymorphic_allocator<>;

	// Compile-time checked literal: `ldap::dn base{"ou=people,dc=example,dc=org"};`
	// (consteval: invalid text fails to compile; runtime text uses parse()).
	struct literal
	{
		consteval literal(const char *s) : text(s)
		{
			if (!detail::is_dn(s)) throw "ldap::dn: invalid distinguished name";
		}
		const char *text;
	};

	dn() = default;// the empty DN (root DSE)
	explicit dn(const allocator_type &alloc) : rdns_(alloc) {}
	dn(literal l, const allocator_type &alloc = {});
	dn(const dn &) = default;
	dn(dn &&) noexcept = default;
	dn(const dn &other, const allocator_type &alloc) : rdns_(other.rdns_, alloc) {}
	dn(dn &&other, const allocator_type &alloc) : rdns_(std::move(other.rdns_), alloc) {}
	dn &operator=(const dn &) = default;
	dn &operator=(dn &&) = default;
	~dn() = default;

	allocator_type get_allocator() const noexcept { return rdns_.get_allocator(); }

	static result<dn> parse(std::string_view text, std::pmr::memory_resource *mr = std::pmr::get_default_resource());

	// RFC 4514 string form. Types keep their spelling; values are escaped as
	// needed (`, + " \ < > ;`, leading space or '#', trailing space as `\c`;
	// NUL and other control characters as `\xx`). parse(to_string()) == *this.
	std::pmr::string to_string(std::pmr::memory_resource *mr = std::pmr::get_default_resource()) const;

	// Most specific RDN first, as in the string form.
	const std::pmr::vector<rdn> &rdns() const noexcept { return rdns_; }
	bool empty() const noexcept { return rdns_.empty(); }
	// Without the first RDN; the parent of the empty DN is the empty DN.
	dn parent() const;
	// `r` prepended to this DN. Throws std::invalid_argument (programming
	// error) if `r` has no AVA, a type that is not a descriptor or numeric
	// OID, or an empty `#` value.
	dn child(rdn r) const;

	friend bool operator==(const dn &, const dn &) = default;

  private:
	std::pmr::vector<rdn> rdns_{};
};

}// namespace jhetz::ldap
