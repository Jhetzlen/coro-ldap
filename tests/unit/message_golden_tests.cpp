// Golden LDAPMessage encodings produced by ldap3 2.9.1 with pyasn1 0.6.4
// (the script is at the end of this file); each test encodes and decodes.
#include "jhetz/ldap/message.hpp"
#include "jhetz/ldap/testing/server_codec.hpp"
#include "test_util.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <string_view>

namespace ldap = jhetz::ldap;
using jhetz::ldap::test::from_hex;
using jhetz::ldap::test::hex;
using namespace std::string_literals;

namespace {

constexpr std::string_view simple_bind =
  "302c0201016027020103041a636e3d61646d696e2c64633d6578616d706c652c64633d6f72678006736563726574";

constexpr std::string_view sasl_bind_external = "301602010260110201030400a30a040845585445524e414c";

constexpr std::string_view sasl_bind_plain = "301f020103601a0201030400a3130405504c41494e040a00757365720070617373";

constexpr std::string_view search_complex =
  "308201330201046382012c041b6f753d70656f706c652c64633d6578616d706c652c64633d6f72670a01020a01030202"
  "01f402010a010100a081dea315040b6f626a656374436c6173730406706572736f6ea129a4170402636e301180024a6f"
  "8102686e8102536d8203697468a20ea30c0403756964040561646d696ea51104097569644e756d626572040431303030"
  "a61104097569644e756d626572040432303030a80b0402736e0405736d79746887046d61696ca9178108322e352e3133"
  "2e358202636e83044a6f686e8401ffa915810e6361736545786163744d617463688303782a79a315040b646573637269"
  "7074696f6e0406612862295c63a40b0402636e30058203656e64a40d0402636e300780057374617274301c0402636e04"
  "046d61696c04106a70656750686f746f3b62696e617279";

constexpr std::string_view modify_all_ops =
  "30819e02010566819804247569643d6a646f652c6f753d70656f706c652c64633d6578616d706c652c64633d6f726730"
  "70302b0a0100302604046d61696c311e040d61406578616d706c652e6f7267040d62406578616d706c652e6f72673018"
  "0a01013013040f74656c6570686f6e654e756d626572310030100a0102300b0402736e31050403446f6530150a010330"
  "1004097569644e756d6265723103040131";

constexpr std::string_view add =
  "306a020106686504237569643d6e65772c6f753d70656f706c652c64633d6578616d706c652c64633d6f7267303e301c"
  "040b6f626a656374436c617373310d0403746f700406706572736f6e30100402636e310a04084e65772055736572300c"
  "0402736e3106040455736572";

constexpr std::string_view delete_ =
  "30280201074a237569643d6f6c642c6f753d70656f706c652c64633d6578616d706c652c64633d6f7267";

constexpr std::string_view modify_dn =
  "30580201086c5304247569643d6a646f652c6f753d70656f706c652c64633d6578616d706c652c64633d6f7267040c75"
  "69643d6a6f686e2e646f650101ff801a6f753d73746166662c64633d6578616d706c652c64633d6f7267";

constexpr std::string_view compare =
  "30430201096e3e04247569643d6a646f652c6f753d70656f706c652c64633d6578616d706c652c64633d6f7267301604"
  "0c7573657250617373776f72640406736563726574";

constexpr std::string_view abandon = "300602010a500104";

constexpr std::string_view start_tls = "301d02010b77188016312e332e362e312e342e312e313436362e3230303337";

constexpr std::string_view search_paged =
  "305e02010c6331041164633d6578616d706c652c64633d6f72670a01020a0100020100020100010100870b6f626a6563"
  "74436c6173733000a02630240416312e322e3834302e3131333535362e312e342e3331390101ff040730050201640400";

constexpr std::string_view search_paged_cookie =
  "306302010d6336041164633d6578616d706c652c64633d6f72670a01010a01000201000201000101ff870b6f626a6563"
  "74436c61737330050403312e31a02630240416312e322e3834302e3131333535362e312e342e333139040a3008020132"
  "0403010203";

constexpr std::string_view unbind = "300502010e4200";

constexpr std::string_view bind_response_sasl = "301902010161140a010e04000400870b6368616c6c656e676500ff";

constexpr std::string_view search_entry =
  "30818b02010464818504247569643d6a646f652c6f753d70656f706c652c64633d6578616d706c652c64633d6f726730"
  "5d30180402636e311204084a6f686e20446f6504064a6f686e6e79302b040b6f626a656374436c617373311c0403746f"
  "700406706572736f6e040d696e65744f7267506572736f6e301404096a70656750686f746f31070405ffd8000180";

constexpr std::string_view search_done_referral =
  "307b02010465760a010a041164633d6578616d706c652c64633d6f7267040c676f20656c73657768657265a35004266c"
  "6461703a2f2f612e6578616d706c652e6f72672f64633d6578616d706c652c64633d6f726704266c6461703a2f2f622e"
  "6578616d706c652e6f72672f64633d6578616d706c652c64633d6f7267";

constexpr std::string_view search_reference =
  "3037020104733204306c6461703a2f2f632e6578616d706c652e6f72672f6f753d782c64633d6578616d706c652c6463"
  "3d6f72673f3f737562";

constexpr std::string_view extended_response =
  "302e02010f78290a0100040004008a17312e332e362e312e342e312e343230332e312e31312e338b0730058003753a78";

constexpr std::string_view notice_of_disconnection =
  "303802010078330a013404000414736572766572207368757474696e6720646f776e8a16312e332e362e312e342e312e"
  "313436362e3230303336";

constexpr std::string_view intermediate_response =
  "3023020110791e8018312e332e362e312e342e312e343230332e312e392e312e3481020102";

void check_golden(std::string_view golden, const ldap::message &m)
{
	const auto expected = from_hex(golden);
	auto encoded = ldap::encode(m);
	REQUIRE(encoded.has_value());
	CHECK(hex(*encoded) == hex(expected));
	auto decoded = ldap::testing::decode(expected);
	REQUIRE(decoded.has_value());
	CHECK(*decoded == m);
}

constexpr std::string_view people = "ou=people,dc=example,dc=org";
constexpr std::string_view jdoe = "uid=jdoe,ou=people,dc=example,dc=org";

auto raw(std::string_view text) -> ldap::filter { return ldap::filter::parse(text).value(); }

}// namespace

TEST_CASE("golden: simple bind", "[message][golden]")
{
	check_golden(
	  simple_bind, { 1, ldap::bind_request{ 3, "cn=admin,dc=example,dc=org", ldap::simple_auth{ "secret" } } });
}

TEST_CASE("golden: SASL bind", "[message][golden]")
{
	check_golden(sasl_bind_external, { 2, ldap::bind_request{ 3, "", ldap::sasl_auth{ "EXTERNAL", {} } } });
	check_golden(sasl_bind_plain, { 3, ldap::bind_request{ 3, "", ldap::sasl_auth{ "PLAIN", "\0user\0pass"s } } });
}

TEST_CASE("golden: search request with a complex filter", "[message][golden]")
{
	const std::string_view filter =
	  "(&(objectClass=person)(|(cn=Jo*hn*Sm*ith)(!(uid=admin)))(uidNumber>=1000)"
	  "(uidNumber<=2000)(sn~=smyth)(mail=*)(cn:dn:2.5.13.5:=John)(:caseExactMatch:=x\\2ay)"
	  "(description=a\\28b\\29\\5cc)(cn=*end)(cn=start*))";
	ldap::search_request req{
		people, ldap::search_scope::whole_subtree, raw(filter), { "cn", "mail", "jpegPhoto;binary" }
	};
	req.deref = ldap::deref_aliases::always;
	req.size_limit = 500;
	req.time_limit = 10;
	const ldap::message m{ 4, std::move(req) };
	check_golden(search_complex, m);
	CHECK(std::get<ldap::search_request>(m.op).filter.to_string() == filter);

	// The builders produce the same tree (and so the same bytes) for every
	// part they can express: all but multi-part substrings.
	using namespace ldap::filters;
	const auto built = attr("objectClass") == "person" && (raw("(cn=Jo*hn*Sm*ith)") || !(attr("uid") == "admin"))
					   && attr("uidNumber") >= "1000" && attr("uidNumber") <= "2000" && attr("sn").approx("smyth")
					   && attr("mail").present() && attr("cn").matches("2.5.13.5", "John", true)
					   && rule_matches("caseExactMatch", "x*y") && attr("description") == "a(b)\\c"
					   && attr("cn").ends_with("end") && attr("cn").starts_with("start");
	CHECK(built == std::get<ldap::search_request>(m.op).filter);
	auto built_message = m;
	std::get<ldap::search_request>(built_message.op).filter = built;
	check_golden(search_complex, built_message);
}

TEST_CASE("golden: modify request with every operation", "[message][golden]")
{
	check_golden(modify_all_ops,
	  { 5,
		ldap::modify_request{ jdoe,
		  {
			{ ldap::modify_operation::add, { "mail", { "a@example.org", "b@example.org" } } },
			{ ldap::modify_operation::delete_, { "telephoneNumber", {} } },
			{ ldap::modify_operation::replace, { "sn", { "Doe" } } },
			{ ldap::modify_operation::increment, { "uidNumber", { "1" } } },
		  } } });
}

TEST_CASE("golden: add, delete, modify DN, compare, abandon", "[message][golden]")
{
	check_golden(add,
	  { 6,
		ldap::add_request{ "uid=new,ou=people,dc=example,dc=org",
		  { { "objectClass", { "top", "person" } }, { "cn", { "New User" } }, { "sn", { "User" } } } } });
	check_golden(delete_, { 7, ldap::del_request{ "uid=old,ou=people,dc=example,dc=org" } });
	check_golden(modify_dn, { 8, ldap::modify_dn_request{ jdoe, "uid=john.doe", true, "ou=staff,dc=example,dc=org" } });
	check_golden(compare, { 9, ldap::compare_request{ jdoe, { "userPassword", "secret" } } });
	check_golden(abandon, { 10, ldap::abandon_request{ 4 } });
	check_golden(unbind, { 14, ldap::unbind_request{} });
}

TEST_CASE("golden: StartTLS extended request", "[message][golden]")
{
	check_golden(start_tls, { 11, ldap::extended_request{ ldap::start_tls_oid, {} } });
}

TEST_CASE("golden: search with paged results control", "[message][golden]")
{
	// (objectClass=*) three ways: parsed, built, and search_request's default.
	using ldap::filters::attr;
	for (const auto &filter :
	  { raw("(objectClass=*)"), attr("objectClass").present(), ldap::search_request{}.filter }) {
		check_golden(search_paged,
		  { 12,
			ldap::search_request{ "dc=example,dc=org", ldap::search_scope::whole_subtree, filter },
			{ ldap::encode_paged_results({ 100, "" }, true).value() } });
		// Non-critical: the DEFAULT FALSE criticality is omitted.
		ldap::search_request types_only{ "dc=example,dc=org", ldap::search_scope::single_level, filter, { "1.1" } };
		types_only.types_only = true;
		check_golden(search_paged_cookie,
		  { 13, std::move(types_only), { ldap::encode_paged_results({ 50, "\x01\x02\x03" }, false).value() } });
	}
}

TEST_CASE("golden: bind response with server SASL credentials", "[message][golden]")
{
	check_golden(bind_response_sasl, { 1, ldap::bind_response{ ldap::ldap_result{ 14 }, "challenge\0\xff"s } });
}

TEST_CASE("golden: search result entry with multi-valued and binary attributes", "[message][golden]")
{
	check_golden(search_entry,
	  { 4,
		ldap::search_result_entry{ jdoe,
		  { { "cn", { "John Doe", "Johnny" } },
			{ "objectClass", { "top", "person", "inetOrgPerson" } },
			{ "jpegPhoto", { "\xff\xd8\0\x01\x80"s } } } } });
}

TEST_CASE("golden: search done with referral, search reference", "[message][golden]")
{
	check_golden(search_done_referral,
	  { 4,
		ldap::search_result_done{ { 10,
		  "dc=example,dc=org",
		  "go elsewhere",
		  { "ldap://a.example.org/dc=example,dc=org", "ldap://b.example.org/dc=example,dc=org" } } } });
	check_golden(
	  search_reference, { 4, ldap::search_result_reference{ { "ldap://c.example.org/ou=x,dc=example,dc=org??sub" } } });
}

TEST_CASE("golden: extended and intermediate responses", "[message][golden]")
{
	check_golden(
	  extended_response, { 15, ldap::extended_response{ {}, "1.3.6.1.4.1.4203.1.11.3", "\x30\x05\x80\x03u:x" } });
	check_golden(intermediate_response, { 16, ldap::intermediate_response{ "1.3.6.1.4.1.4203.1.9.1.4", "\x01\x02" } });
}

TEST_CASE("golden: unsolicited notice of disconnection", "[message][golden]")
{
	const ldap::message notice{ 0,
		ldap::extended_response{ { 52, "", "server shutting down" }, ldap::notice_of_disconnection_oid } };
	check_golden(notice_of_disconnection, notice);

	auto m = ldap::testing::decode(from_hex(notice_of_disconnection));
	REQUIRE(m);
	CHECK(m->id == 0);
	const auto &x = std::get<ldap::extended_response>(m->op);
	CHECK(x.response_name == ldap::notice_of_disconnection_oid);
	CHECK_FALSE(x.response_value.has_value());
	CHECK(x.result.to_error().code == ldap::errc::unavailable);
}

/* Generating script (ldap3 2.9.1, pyasn1 0.6.4):

# Produces reference LDAPMessage encodings with ldap3 2.9.1 / pyasn1 (independent
# implementation) for tests/unit/message_golden_tests.cpp.
from ldap3 import SIMPLE, SASL
from ldap3.operation.bind import bind_operation
from ldap3.operation.search import search_operation
from ldap3.operation.modify import modify_operation
from ldap3.operation.add import add_operation
from ldap3.operation.delete import delete_operation
from ldap3.operation.modifyDn import modify_dn_operation
from ldap3.operation.compare import compare_operation
from ldap3.operation.abandon import abandon_operation
from ldap3.operation.extended import extended_operation
from ldap3.operation.unbind import unbind_operation
from ldap3.protocol.rfc2696 import paged_search_control
from ldap3.protocol.convert import build_controls_list
from ldap3.protocol.rfc4511 import (LDAPMessage, MessageID, ProtocolOp, BindResponse, SearchResultEntry,
	SearchResultDone, SearchResultReference, ExtendedResponse, IntermediateResponse, PartialAttributeList,
	PartialAttribute, Vals, Referral, ResultCode, LDAPDN, LDAPString, AttributeDescription, AttributeValue, URI,
	ServerSaslCreds, ResponseName, ResponseValue, IntermediateResponseName, IntermediateResponseValue, LDAPOID,
)
from ldap3.utils.asn1 import encode


def msg(mid, name, op, controls=None):
	m = LDAPMessage()
	m['messageID'] = MessageID(mid)
	m['protocolOp'] = ProtocolOp().setComponentByName(name, op)
	c = build_controls_list(controls)
	if c is not None:
		m['controls'] = c
	return encode(m).hex()


out = {}
out['simple_bind'] = msg(1, 'bindRequest', bind_operation(3, SIMPLE, 'cn=admin,dc=example,dc=org', 'secret'))
out['sasl_bind_external'] = msg(2, 'bindRequest', bind_operation(3, SASL, '', None, 'EXTERNAL', None))
out['sasl_bind_plain'] = msg(3, 'bindRequest', bind_operation(3, SASL, '', None, 'PLAIN', b'\x00user\x00pass'))
complex_filter = ('(&(objectClass=person)(|(cn=Jo*hn*Sm*ith)(!(uid=admin)))(uidNumber>=1000)(uidNumber<=2000)'
				  '(sn~=smyth)(mail=*)(cn:dn:2.5.13.5:=John)(:caseExactMatch:=x\\2ay)(description=a\\28b\\29\\5cc)'
				  '(cn=*end)(cn=start*))')
out['search_complex'] = msg(4, 'searchRequest',
	search_operation('ou=people,dc=example,dc=org', complex_filter, 2, 3, ['cn', 'mail', 'jpegPhoto;binary'],
					 500, 10, False, False, False))
out['modify_all_ops'] = msg(5, 'modifyRequest', modify_operation('uid=jdoe,ou=people,dc=example,dc=org', {
	'mail': [(0, ['a@example.org', 'b@example.org'])],
	'telephoneNumber': [(1, [])],
	'sn': [(2, ['Doe'])],
	'uidNumber': [(3, ['1'])],
}, False))
out['add'] = msg(6, 'addRequest', add_operation('uid=new,ou=people,dc=example,dc=org', {
	'objectClass': ['top', 'person'], 'cn': ['New User'], 'sn': ['User']}, False))
out['delete'] = msg(7, 'delRequest', delete_operation('uid=old,ou=people,dc=example,dc=org'))
out['modify_dn'] = msg(8, 'modDNRequest', modify_dn_operation('uid=jdoe,ou=people,dc=example,dc=org', 'uid=john.doe',
															 True, 'ou=staff,dc=example,dc=org'))
out['compare'] = msg(9, 'compareRequest', compare_operation('uid=jdoe,ou=people,dc=example,dc=org', 'userPassword',
														   'secret', False))
out['abandon'] = msg(10, 'abandonRequest', abandon_operation(4))
out['start_tls'] = msg(11, 'extendedReq', extended_operation('1.3.6.1.4.1.1466.20037'))
out['search_paged'] = msg(12, 'searchRequest',
	search_operation('dc=example,dc=org', '(objectClass=*)', 2, 0, [], 0, 0, False, False, False),
	[paged_search_control(True, 100, None)])
out['search_paged_cookie'] = msg(13, 'searchRequest',
	search_operation('dc=example,dc=org', '(objectClass=*)', 1, 0, ['1.1'], 0, 0, True, False, False),
	[paged_search_control(False, 50, b'\x01\x02\x03')])
out['unbind'] = msg(14, 'unbindRequest', unbind_operation())

# Responses, built from the pyasn1 RFC 4511 classes.
r = BindResponse()
r['resultCode'] = ResultCode('saslBindInProgress')
r['matchedDN'] = ''
r['diagnosticMessage'] = ''
r['serverSaslCreds'] = ServerSaslCreds(b'challenge\x00\xff')
out['bind_response_sasl'] = msg(1, 'bindResponse', r)

e = SearchResultEntry()
e['object'] = LDAPDN('uid=jdoe,ou=people,dc=example,dc=org')
pal = PartialAttributeList()
for i, (t, vs) in enumerate([('cn', [b'John Doe', b'Johnny']), ('objectClass', [b'top', b'person', b'inetOrgPerson']),
							 ('jpegPhoto', [bytes([0xff, 0xd8, 0x00, 0x01, 0x80])])]):
	pa = PartialAttribute()
	pa['type'] = AttributeDescription(t)
	vals = Vals()
	for j, v in enumerate(vs):
		vals.setComponentByPosition(j, AttributeValue(v))
	pa['vals'] = vals
	pal.setComponentByPosition(i, pa)
e['attributes'] = pal
out['search_entry'] = msg(4, 'searchResEntry', e)

d = SearchResultDone()
d['resultCode'] = ResultCode('referral')
d['matchedDN'] = 'dc=example,dc=org'
d['diagnosticMessage'] = 'go elsewhere'
ref = Referral()
ref.setComponentByPosition(0, URI('ldap://a.example.org/dc=example,dc=org'))
ref.setComponentByPosition(1, URI('ldap://b.example.org/dc=example,dc=org'))
d['referral'] = ref
out['search_done_referral'] = msg(4, 'searchResDone', d)

sr = SearchResultReference()
sr.setComponentByPosition(0, URI('ldap://c.example.org/ou=x,dc=example,dc=org??sub'))
out['search_reference'] = msg(4, 'searchResRef', sr)

x = ExtendedResponse()
x['resultCode'] = ResultCode('success')
x['matchedDN'] = ''
x['diagnosticMessage'] = ''
x['responseName'] = ResponseName('1.3.6.1.4.1.4203.1.11.3')
x['responseValue'] = ResponseValue(b'\x30\x05\x80\x03u:x')
out['extended_response'] = msg(15, 'extendedResp', x)

n = ExtendedResponse()
n['resultCode'] = ResultCode('unavailable')
n['matchedDN'] = ''
n['diagnosticMessage'] = 'server shutting down'
n['responseName'] = ResponseName('1.3.6.1.4.1.1466.20036')
out['notice_of_disconnection'] = msg(0, 'extendedResp', n)

im = IntermediateResponse()
im['responseName'] = IntermediateResponseName('1.3.6.1.4.1.4203.1.9.1.4')
im['responseValue'] = IntermediateResponseValue(b'\x01\x02')
out['intermediate_response'] = msg(16, 'intermediateResponse', im)

for k, v in out.items():
	print(k, v)
*/
