# jhetz::ldap

C++23 LDAP client library, in progress. Design: [`docs/ldap/DESIGN.md`](../docs/ldap/DESIGN.md).

## What exists

- `jhetz/ldap/error.hpp`: `ldap::error`, `ldap::result<T>` (`std::expected`),
  `ldap::errc` (RFC 4511 result codes, category `ldap.result`) and
  `ldap::client_errc` (category `ldap.client`).
- `jhetz/ldap/ber.hpp`: the restricted BER codec LDAP uses (RFC 4511 section 5.1):
  `ber::writer`, `ber::reader` (non-owning, depth-bounded, safe on untrusted
  input) and the framer `ber::complete_message_size`.
- `jhetz/ldap/message.hpp`: RFC 4511 `LDAPMessage` as a wire model
  (`ldap::message`, `protocol_op` = every request and response, `control`,
  `ldap_result` with `to_error()`), `encode()` / `decode()`, and the paged
  results control (RFC 2696). Wire strings stay `std::string`; see the header
  for the decoding rules (RFC 4511 section 4 extensibility, range checks).
- `jhetz/ldap/filter.hpp`: `ldap::filter` (RFC 4515 text), escaping builders in
  `ldap::filters` (`attr("uid") == v && !attr("x").present()`), the RFC 4515
  parser to BER (`encode_filter`) and BER back to canonical text
  (`decode_filter`). Filters nest at most `max_filter_depth` (24) levels.
- `jhetz/ldap/dn.hpp`: `ldap::dn` (RFC 4514 parse / `to_string`, multi-valued
  RDNs, `parent()`, `child()`, compile-time checked literals). Syntax only: no
  matching-rule normalization of values.
- `jhetz/ldap/attribute.hpp`: `ldap::attribute`, an attribute description with
  case-insensitive equality, ordering and `std::hash`.
- `jhetz/ldap/entry.hpp`: `ldap::entry`, the untyped search result entry
  (DN text + attributes, case-insensitive `find`).

LDAP resultCode 0 (success) has no `errc` value: success is the absence of
an error; `ldap_result::is_success()` checks for it.

No networking yet. The `ldap::cond` error conditions from DESIGN.md
section 5 are deferred.

## Build and test

Standalone CMake project (CMake 3.25+, GCC 13+ or Clang 19+). Catch2 v3 is
fetched from GitHub.

```sh
cmake -S ldap -B build/ldap -G Ninja -DCMAKE_BUILD_TYPE=Debug -DJHETZ_LDAP_SANITIZE=ON
cmake --build build/ldap
ctest --test-dir build/ldap --output-on-failure
```

| Option | Default | |
|---|---|---|
| `JHETZ_LDAP_BUILD_TESTS` | `ON` | unit tests and the `*_fuzz_replay` tests |
| `JHETZ_LDAP_BUILD_FUZZERS` | `OFF` | libFuzzer targets (Clang only) |
| `JHETZ_LDAP_SANITIZE` | `OFF` | ASan + UBSan on every target |
| `JHETZ_LDAP_WERROR` | `OFF` | warnings are errors in our code (CI turns it on) |

## Fuzz

| Target | Input | Properties |
|---|---|---|
| `ber_fuzz` | bytes | framer and reader agree; every element walks; values re-encode consistently |
| `message_fuzz` | bytes | a message that decodes encodes, decodes to an equal message and re-encodes to the same bytes |
| `filter_fuzz` | text / bytes | filter text -> BER -> text -> identical BER; every builder output parses and `attr("cn") == v` carries `v` exactly; decodable BER filters round-trip |
| `dn_fuzz` | text | `parse(to_string(d)) == d`; the literal validator agrees with `parse` |

```sh
cmake -S ldap -B build/ldap-fuzz -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo \
      -DCMAKE_CXX_COMPILER=clang++ -DJHETZ_LDAP_BUILD_FUZZERS=ON -DJHETZ_LDAP_BUILD_TESTS=OFF
cmake --build build/ldap-fuzz
mkdir -p corpus && cp ldap/fuzz/corpus/message_fuzz/* corpus/
UBSAN_OPTIONS=halt_on_error=1 build/ldap-fuzz/fuzzers/message_fuzz -max_total_time=60 corpus
```

`fuzz/corpus/<target>/` holds the seed inputs (the same ones
`<target>_replay` mutates). Regenerate them after changing the seeds with
`<target>_replay --write-seeds ldap/fuzz/corpus/<target>`.

Sanitized and fuzz builds use `-fno-sanitize-recover=all`, so any UBSan
finding aborts and fails the test or fuzz run.

With Clang 18 and libstdc++ 13 the build adds
`-D__cpp_concepts=202002L -Wno-builtin-macro-redefined`, otherwise
`<expected>` is unavailable.

Without libFuzzer, the `<target>_replay` tests (part of `ctest`) run the same
entry points on deterministic generated and mutated inputs (about 300,000 for
`ber_fuzz`, 200,000 for `message_fuzz`, 150,000 for `dn_fuzz` and 45,000 for
the slower `filter_fuzz`).

## Golden vectors

`tests/message_golden_tests.cpp` compares the codec with encodings produced
by an independent implementation (ldap3 2.9.1 / pyasn1 0.6.4); the generating
script is in the file.
