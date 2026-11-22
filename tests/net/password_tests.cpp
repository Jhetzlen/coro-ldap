// change_password / reset_password (RFC 3062) against the scripted server.
#include "jhetz/ldap/connection.hpp"
#include "jhetz/ldap/extended_operations.hpp"
#include "mock_ldap.hpp"
#include "net_test_support.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstddef>
#include <cstdint>
#include <memory_resource>
#include <string>
#include <string_view>
#include <system_error>

namespace ldap = jhetz::ldap;
using namespace jhetz::ldap::test;
using namespace std::literals;
using ldap::client_errc;

namespace {

const ldap::dn jdoe{ "uid=jdoe,ou=people,dc=example,dc=org" };
const std::string jdoe_context = "uid=jdoe,ou=people,dc=example,dc=org";
constexpr std::string_view old_pw = "Old-S3cret";
constexpr std::string_view new_pw = "New-S3cret";

auto extended_ok(std::int32_t id) -> ldap::message
{
	return ldap::message{ id, ldap::extended_response{ ldap::ldap_result{ 0 } } };
}

// SEQUENCE { [0] jdoe, [1] old_pw, [2] new_pw } and SEQUENCE { [0] jdoe, [2] new_pw }.
const std::string change_value =
  "\x30\x3e\x80\x24uid=jdoe,ou=people,dc=example,dc=org\x81\x0aOld-S3cret\x82\x0aNew-S3cret"s;
const std::string reset_value = "\x30\x32\x80\x24uid=jdoe,ou=people,dc=example,dc=org\x82\x0aNew-S3cret"s;

auto password_modify_request(std::int32_t id, const std::string &value) -> ldap::message
{
	return ldap::message{ id, ldap::extended_request{ ldap::password_modify_oid, value } };
}

// No password in the error, in any of its parts.
void check_no_password(const ldap::error &e)
{
	const std::string text(e.message());
	CHECK_FALSE(text.contains(old_pw));
	CHECK_FALSE(text.contains(new_pw));
}

// Records whether a block it frees still holds `needle`.
class secret_scanner final : public std::pmr::memory_resource
{
  public:
	explicit secret_scanner(std::string_view needle) : needle_(needle) {}
	[[nodiscard]] auto leaked() const noexcept -> bool { return leaked_; }

  private:
	auto do_allocate(std::size_t n, std::size_t align) -> void * override
	{
		return std::pmr::new_delete_resource()->allocate(n, align);
	}
	void do_deallocate(void *p, std::size_t n, std::size_t align) override
	{
		if (std::string_view(static_cast<const char *>(p), n).contains(needle_)) {
			leaked_ = true;
		}
		std::pmr::new_delete_resource()->deallocate(p, n, align);
	}
	[[nodiscard]] auto do_is_equal(const std::pmr::memory_resource &other) const noexcept -> bool override
	{
		return this == &other;
	}

	std::string_view needle_;
	bool leaked_ = false;
};

}// namespace

TEST_CASE("change_password: RFC 3062 password modify, no root DSE read", "[net][password]")
{
	mock_ldap m;
	m.serve({ answer({ extended_ok(1) }), answer({ extended_ok(2) }) });
	CHECK(m.run(ldap::change_password(m.conn, jdoe, std::string(old_pw), std::string(new_pw))).has_value());
	CHECK(m.run(ldap::reset_password(m.conn, jdoe, std::string(new_pw))).has_value());
	m.check_server();

	REQUIRE(m.log.received.size() == 2);
	CHECK(m.log.received[0] == password_modify_request(1, change_value));
	CHECK(m.log.received[1] == password_modify_request(2, reset_value));
}

TEST_CASE("change_password: the bound user's own, no userIdentity", "[net][password]")
{
	mock_ldap m;
	m.serve({ answer({ extended_ok(1) }) });
	CHECK(m.run(ldap::change_password(m.conn, {}, "o", "n")).has_value());
	m.check_server();
	REQUIRE(m.log.received.size() == 1);
	CHECK(m.log.received[0] == password_modify_request(1, "\x30\x06\x81\x01o\x82\x01n"s));
}

TEST_CASE("change_password: refused before sending", "[net][password]")
{
	mock_ldap m;
	m.serve({});
	const auto invalid = std::make_error_code(std::errc::invalid_argument);
	auto no_new = m.run(ldap::change_password(m.conn, jdoe, std::string(old_pw), ""));
	REQUIRE_FALSE(no_new.has_value());
	CHECK(no_new.error().code == invalid);
	CHECK(std::string(no_new.error().context) == "change password " + jdoe_context + ": empty new password");
	auto no_old = m.run(ldap::change_password(m.conn, jdoe, "", std::string(new_pw)));
	REQUIRE_FALSE(no_old.has_value());
	CHECK(no_old.error().code == invalid);
	CHECK(std::string(no_old.error().context)
		  == "change password " + jdoe_context + ": empty old password (reset_password() sets one without it)");
	auto reset = m.run(ldap::reset_password(m.conn, jdoe, ""));
	REQUIRE_FALSE(reset.has_value());
	CHECK(reset.error().code == invalid);
	CHECK(m.conn.is_open());
	m.check_server();
	CHECK(m.log.received.empty());

	ldap::connection none;
	auto closed = m.run(ldap::change_password(none, jdoe, std::string(old_pw), std::string(new_pw)));
	REQUIRE_FALSE(closed.has_value());
	CHECK(closed.error().code == client_errc::not_connected);
}

TEST_CASE("change_password: not sent in clear over TCP unless allowed", "[net][password]")
{
	tcp_mock_ldap m({}, socket_buffers::system, false);
	m.serve({ step{} });
	const ldap::dn user{ "uid=jdoe,ou=people,dc=example,dc=org" };
	auto changed = m.run(ldap::change_password(m.conn, user, "old", "new"));
	REQUIRE_FALSE(changed.has_value());
	CHECK(changed.error().code == ldap::client_errc::tls_required);
	auto reset = m.run(ldap::reset_password(m.conn, user, "new"));
	REQUIRE_FALSE(reset.has_value());
	CHECK(reset.error().code == ldap::client_errc::tls_required);
	CHECK(m.run(m.conn.unbind()).has_value());
	m.check_server();
	CHECK(m.log.received.size() == 1);
}

TEST_CASE("change_password: a server error", "[net][password]")
{
	mock_ldap m;
	m.serve({ answer({ ldap::message{ 1, ldap::extended_response{ ldap::ldap_result{ 49, "", "wrong" } } } }) });
	auto r = m.run(ldap::change_password(m.conn, jdoe, std::string(old_pw), std::string(new_pw)));
	REQUIRE_FALSE(r.has_value());
	CHECK(r.error().code == ldap::errc::invalid_credentials);
	CHECK(std::string(r.error().context) == "change password " + jdoe_context + ": password modify (RFC 3062)");
	check_no_password(r.error());
	m.check_server();
}

TEST_CASE("passwords: the connection wipes its copies before freeing them", "[net][password]")
{
	// Longer than a short string's buffer, so it lives on the resource.
	constexpr std::string_view secret = "Wiped-Before-Free-S3cret";
	secret_scanner scanner(secret);
	{
		mock_ldap m({}, &scanner);
		m.serve({ answer({ ldap::message{ 1, ldap::bind_response{ ldap::ldap_result{ 0 } } } }),
		  answer({ extended_ok(2) }),
		  answer({ extended_ok(3) }),
		  answer({ ldap::message{ 4, ldap::modify_response{ ldap::ldap_result{ 0 } } } }) });
		CHECK(m.run(m.conn.simple_bind(jdoe, std::string(secret))).has_value());
		CHECK(m.run(ldap::change_password(m.conn, jdoe, std::string(secret), std::string(new_pw))).has_value());
		CHECK(m.run(ldap::reset_password(m.conn, jdoe, std::string(secret))).has_value());
		CHECK(m.run(m.conn.modify({ .object = jdoe, .changes = { ldap::mod::replace("userPassword", { secret }) } }))
			.has_value());
		m.check_server();
		REQUIRE(m.log.received.size() == 4);
	}
	CHECK_FALSE(scanner.leaked());
}

TEST_CASE("passwords: other requests are not wiped", "[net][password]")
{
	constexpr std::string_view value = "Kept-As-Given-Description";
	secret_scanner scanner(value);
	{
		mock_ldap m({}, &scanner);
		m.serve({ answer({ ldap::message{ 1, ldap::modify_response{ ldap::ldap_result{ 0 } } } }) });
		CHECK(m.run(m.conn.modify({ .object = jdoe, .changes = { ldap::mod::replace("description", { value }) } }))
			.has_value());
		m.check_server();
	}
	CHECK(scanner.leaked());
}
