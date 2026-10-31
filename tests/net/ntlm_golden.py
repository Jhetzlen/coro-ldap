#!/usr/bin/env python3
"""Prints the golden NTLMv2 messages of sasl_ntlm_tests.cpp's "a golden
AUTHENTICATE_MESSAGE from an independent implementation".

Written from MS-NLMP alone, stdlib only (hashlib, hmac, struct), none of the
library's code: the NEGOTIATE_MESSAGE, a domain controller's
CHALLENGE_MESSAGE and the AUTHENTICATE_MESSAGE with its MIC, for fixed
inputs, as C++ string literals of hex. Run it with `python3 -I
tests/net/ntlm_golden.py` and paste its output into the test.

MS-NLMP leaves some choices to the client; for those the script copies the
library's (the test comment lists them), so the vector does not anchor them:
the NEGOTIATE flags and its zero Version, the AUTHENTICATE NegotiateFlags
((client & server) | VERSION), the "DOMAIN\\user" split at the first
backslash, the client's AV_PAIR order (the server's pairs, then MsvAvFlags,
MsvAvChannelBindings, MsvAvTargetName, MsvAvEOL) and the payload order.
"""
import hashlib
import hmac
import struct

MASK32 = 0xFFFFFFFF


def rotl(x, s):
    x &= MASK32
    return ((x << s) | (x >> (32 - s))) & MASK32


def md4_f(x, y, z):
    return (x & y) | (~x & z)


def md4_g(x, y, z):
    return (x & y) | (x & z) | (y & z)


def md4_h(x, y, z):
    return x ^ y ^ z


def md4(data: bytes) -> bytes:
    """RFC 1320 (hashlib's MD4 needs OpenSSL's legacy provider)."""
    msg = data + b"\x80" + b"\0" * ((55 - len(data)) % 64) + struct.pack("<Q", len(data) * 8)
    assert len(msg) % 64 == 0
    a, b, c, d = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476
    round3_order = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15]
    for off in range(0, len(msg), 64):
        x = struct.unpack("<16I", msg[off:off + 64])
        aa, bb, cc, dd = a, b, c, d
        for i in range(16):
            t = rotl(a + md4_f(b, c, d) + x[i], [3, 7, 11, 19][i % 4])
            a, b, c, d = d, t, b, c
        for i in range(16):
            k = (i % 4) * 4 + i // 4
            t = rotl(a + md4_g(b, c, d) + x[k] + 0x5A827999, [3, 5, 9, 13][i % 4])
            a, b, c, d = d, t, b, c
        for i in range(16):
            t = rotl(a + md4_h(b, c, d) + x[round3_order[i]] + 0x6ED9EBA1, [3, 9, 11, 15][i % 4])
            a, b, c, d = d, t, b, c
        a, b, c, d = (a + aa) & MASK32, (b + bb) & MASK32, (c + cc) & MASK32, (d + dd) & MASK32
    return struct.pack("<4I", a, b, c, d)


# RFC 1320 appendix A.5.
assert md4(b"").hex() == "31d6cfe0d16ae931b73c59d7e0c089c0"
assert md4(b"abc").hex() == "a448017aaf21d8525fc10ae87aa6729d"
assert md4(b"1234567890" * 8).hex() == "e33b4ddc9c38f2199c3e7b164fcc0536"


def u16(s: str) -> bytes:
    """UNICODE(s): UTF-16LE."""
    return s.encode("utf-16-le")


def upper_simple(s: str) -> str:
    """Uppercase(User) as Windows' RtlUpcaseUnicodeString: one UTF-16 unit
    to one, so each code point of the BMP by its simple (one-to-one)
    uppercase mapping, the others unchanged.

    Python has no simple case mapping: str.upper() is the full mapping
    (SpecialCasing, "SS" for U+00DF). Where the full uppercase is one code
    point it is the simple mapping; where it is several, the simple mapping
    is the titlecase when that is one code point (the Greek letters with
    ypogegrammeni: U+1F80 to U+1F88), otherwise none (U+00DF stays).
    Checked against ICU's u_toupper over the whole BMP; only letters whose
    mapping is newer than Python's Unicode version can differ.
    """
    out = []
    for ch in s:
        mapped = ch
        if ord(ch) < 0x10000:
            for candidate in (ch.upper(), ch.title()):
                if len(candidate) == 1:
                    if ord(candidate) < 0x10000:
                        mapped = candidate
                    break
        out.append(mapped)
    return "".join(out)


assert upper_simple("straße jörg ᾀ ı 𐐨") == "STRAßE JÖRG ᾈ I 𐐨"


def hmac_md5(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.md5).digest()


def ntowfv2(password: str, user: str, domain: str) -> bytes:
    """MS-NLMP 3.3.2: HMAC_MD5(MD4(UNICODE(Passwd)),
    UNICODE(ConcatenationOf(Uppercase(User), UserDom)))."""
    return hmac_md5(md4(u16(password)), u16(upper_simple(user) + domain))


# MS-NLMP 4.2.4.1.1.
assert ntowfv2("Password", "User", "Domain").hex() == "0c868a403bfd7a93a3001ef22ef02e3f"

# NegotiateFlags (MS-NLMP 2.2.2.5).
UNICODE, REQUEST_TARGET, NTLM = 0x1, 0x4, 0x200
ALWAYS_SIGN, TARGET_TYPE_DOMAIN, ESS = 0x8000, 0x10000, 0x80000
TARGET_INFO, VERSION, F128, F56 = 0x800000, 0x2000000, 0x20000000, 0x80000000

# AvId (MS-NLMP 2.2.2.1).
EOL, NB_COMPUTER, NB_DOMAIN, FLAGS, TIMESTAMP, TARGET_NAME, CHANNEL_BINDINGS = 0, 1, 2, 6, 7, 9, 10
MSV_AV_FLAGS_MIC = 0x2


def version(major, minor, build):
    """VERSION (2.2.2.10), NTLMSSP_REVISION_W2K3."""
    return struct.pack("<BBH3xB", major, minor, build, 0x0F)


def av(av_id, value):
    return struct.pack("<HH", av_id, len(value)) + value


def fields(length, offset):
    """Len, MaxLen, BufferOffset."""
    return struct.pack("<HHI", length, length, offset)


# ---- Inputs.
username = "CORP\\jörg"  # "DOMAIN\user", split at the first backslash
password = "pässwort€"
domain, user = username.split("\\", 1)
workstation = "WS01"
spn = "ldap/dc1.example.org"
client_challenge = b"\xaa" * 8
server_challenge = bytes.fromhex("0123456789abcdef")
server_time = 0x01DB2B3C4D5E6F70
cert_hash = bytes(range(32))

# ---- NEGOTIATE_MESSAGE (2.2.1.1): no domain nor workstation, a zero Version.
client_flags = UNICODE | REQUEST_TARGET | NTLM | ESS | TARGET_INFO | VERSION | F128
negotiate = b"NTLMSSP\0" + struct.pack("<II", 1, client_flags) + fields(0, 40) + fields(0, 40) + version(0, 0, 0)

# ---- CHALLENGE_MESSAGE (2.2.1.2) of a domain controller.
dc_flags = UNICODE | REQUEST_TARGET | NTLM | ALWAYS_SIGN | TARGET_TYPE_DOMAIN | ESS | TARGET_INFO | VERSION | F128 | F56
target_name = u16("EXAMPLE")
server_pairs = (av(NB_DOMAIN, u16("Domain")) + av(NB_COMPUTER, u16("Server"))
                + av(TIMESTAMP, struct.pack("<Q", server_time)))
server_info = server_pairs + av(EOL, b"")
challenge = (b"NTLMSSP\0" + struct.pack("<I", 2) + fields(len(target_name), 56) + struct.pack("<I", dc_flags)
             + server_challenge + b"\0" * 8 + fields(len(server_info), 56 + len(target_name)) + version(10, 0, 20348)
             + target_name + server_info)

# ---- MsvAvChannelBindings (3.1.5.1.2): MD5 of an RFC 2744
# gss_channel_bindings_struct with no addresses over RFC 5929's
# tls-server-end-point.
app_data = b"tls-server-end-point:" + cert_hash
bindings = hashlib.md5(b"\0" * 16 + struct.pack("<I", len(app_data)) + app_data).digest()

# ---- The client's AV_PAIRs (3.1.5.1.2), in the library's order: the
# server's, MsvAvFlags with the MIC bit, MsvAvChannelBindings,
# MsvAvTargetName, MsvAvEOL.
client_info = (server_pairs + av(FLAGS, struct.pack("<I", MSV_AV_FLAGS_MIC)) + av(CHANNEL_BINDINGS, bindings)
               + av(TARGET_NAME, u16(spn)) + av(EOL, b""))

# ---- NTLMv2 (3.3.2), Time = the server's MsvAvTimestamp.
key = ntowfv2(password, user, domain)
temp = (b"\x01\x01" + b"\0" * 6 + struct.pack("<Q", server_time) + client_challenge + b"\0" * 4 + client_info
        + b"\0" * 4)
nt_proof = hmac_md5(key, server_challenge + temp)
nt_response = nt_proof + temp
lm_response = b"\0" * 24  # MsvAvTimestamp present: Z(24)
session_base_key = hmac_md5(key, nt_proof)
exported_session_key = session_base_key  # no NTLMSSP_NEGOTIATE_KEY_EXCH

# ---- AUTHENTICATE_MESSAGE (2.2.1.3): the 88-octet fixed part (with Version
# and MIC), then the payload in the library's order: DomainName, UserName,
# Workstation, LmChallengeResponse, NtChallengeResponse,
# EncryptedRandomSessionKey.
auth_flags = (client_flags & dc_flags) | VERSION
payload = [u16(domain), u16(user), u16(workstation), lm_response, nt_response, b""]
offsets = []
at = 88
for p in payload:
    offsets.append(at)
    at += len(p)
dom, usr, ws, lm, nt, rsk = [fields(len(p), o) for p, o in zip(payload, offsets)]


def authenticate(mic):
    return (b"NTLMSSP\0" + struct.pack("<I", 3) + lm + nt + dom + usr + ws + rsk + struct.pack("<I", auth_flags)
            + version(0, 0, 0) + mic + b"".join(payload))


# MIC = HMAC_MD5(ExportedSessionKey, ConcatenationOf(NEGOTIATE_MESSAGE,
# CHALLENGE_MESSAGE, AUTHENTICATE_MESSAGE with a zero MIC)) (3.1.5.1.2).
mic = hmac_md5(exported_session_key, negotiate + challenge + authenticate(b"\0" * 16))
auth = authenticate(mic)
assert auth[72:88] == mic


def cxx(name, data):
    h = data.hex()
    lines = [h[i:i + 96] for i in range(0, len(h), 96)]
    print(f"// {name}: {len(data)} octets")
    print("  " + "\n  ".join(f'"{line}"' for line in lines))


cxx("NEGOTIATE", negotiate)
cxx("CHALLENGE", challenge)
cxx("AUTHENTICATE", auth)
print("// MIC", mic.hex(), "NTProofStr", nt_proof.hex(), "bindings", bindings.hex())
