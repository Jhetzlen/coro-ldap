# jhetz::ldap

C++23 LDAP client library, in progress. Design: [`docs/ldap/DESIGN.md`](../docs/ldap/DESIGN.md).

## What exists

- `jhetz/ldap/error.hpp`: `ldap::error`, `ldap::result<T>` (`std::expected`),
  `ldap::errc` (RFC 4511 result codes, category `ldap.result`) and
  `ldap::client_errc` (category `ldap.client`).
- `jhetz/ldap/ber.hpp`: the restricted BER codec LDAP uses (RFC 4511 section 5.1):
  `ber::writer`, `ber::reader` (non-owning, depth-bounded, safe on untrusted
  input) and the framer `ber::complete_message_size`.

No networking and no LDAP message types yet.

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
| `JHETZ_LDAP_BUILD_TESTS` | `ON` | unit tests and `ber_fuzz_replay` |
| `JHETZ_LDAP_BUILD_FUZZERS` | `OFF` | libFuzzer targets (Clang only) |
| `JHETZ_LDAP_SANITIZE` | `OFF` | ASan + UBSan on every target |
| `JHETZ_LDAP_WERROR` | `OFF` | warnings are errors in our code (CI turns it on) |

## Fuzz

`fuzz/ber_fuzz.cpp` runs the framer and walks every element with the reader,
checking that decoded values re-encode consistently.

```sh
cmake -S ldap -B build/ldap-fuzz -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo \
      -DCMAKE_CXX_COMPILER=clang++ -DJHETZ_LDAP_BUILD_FUZZERS=ON -DJHETZ_LDAP_BUILD_TESTS=OFF
cmake --build build/ldap-fuzz
mkdir -p corpus && build/ldap-fuzz/fuzzers/ber_fuzz -max_total_time=60 corpus
```

With Clang 18 and libstdc++ 13 the build adds
`-D__cpp_concepts=202002L -Wno-builtin-macro-redefined`, otherwise
`<expected>` is unavailable.

Without libFuzzer, the `ber_fuzz_replay` test (part of `ctest`) runs the same
entry point on about 300,000 deterministic generated and mutated inputs.
