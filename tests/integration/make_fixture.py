#!/usr/bin/env python3
"""Writes the integration tests' LDIF fixture to stdout (docs/DEVELOPMENT.md)."""
import base64

out = []
def entry(dn, *lines):
    out.append("dn: " + dn)
    out.extend(lines)
    out.append("")

entry("dc=example,dc=org", "objectClass: dcObject", "objectClass: organization", "dc: example", "o: Example")
entry("ou=people,dc=example,dc=org", "objectClass: organizationalUnit", "ou: people")
entry("ou=groups,dc=example,dc=org", "objectClass: organizationalUnit", "ou: groups")
entry("ou=alumni,dc=example,dc=org", "objectClass: organizationalUnit", "ou: alumni")
for i in range(250):
    uid = "user%03d" % i
    entry("uid=%s,ou=people,dc=example,dc=org" % uid,
          "objectClass: inetOrgPerson", "objectClass: posixAccount",
          "uid: " + uid, "cn: User %03d" % i, "sn: %03d" % i,
          "mail: %s@example.org" % uid,
          "uidNumber: %d" % (10000 + i), "gidNumber: 100",
          "homeDirectory: /home/" + uid,
          "userPassword: pw-" + uid)
# The password is in SASLprep form.
def b64(text):
    return base64.b64encode(text.encode()).decode()
entry_dn = "uid=j\u00f6rg,ou=people,dc=example,dc=org"
out.extend(["dn:: " + b64(entry_dn), "objectClass: inetOrgPerson", "uid:: " + b64("j\u00f6rg"),
            "cn:: " + b64("J\u00f6rg \u00c5ngstr\u00f6m"), "sn:: " + b64("\u00c5ngstr\u00f6m"),
            "userPassword:: " + b64("p\u00e4ssw\u00f6rd \u65e5\u672c \u20ac"), ""])
photo = bytes(i % 251 for i in range(10000))
entry("uid=photo,ou=people,dc=example,dc=org",
      "objectClass: inetOrgPerson", "uid: photo", "cn: Photo", "sn: Photo",
      "jpegPhoto:: " + base64.b64encode(photo).decode())
entry("cn=staff,ou=groups,dc=example,dc=org", "objectClass: groupOfNames", "cn: staff",
      *["member: uid=user%03d,ou=people,dc=example,dc=org" % i for i in range(10)])
entry("cn=big,ou=groups,dc=example,dc=org", "objectClass: groupOfNames", "cn: big",
      *["member: uid=member%04d,ou=elsewhere,dc=example,dc=org" % i for i in range(2000)])
print("\n".join(out))
