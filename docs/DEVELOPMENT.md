# Development

Building, testing, fuzzing and benchmarking jhetz::ldap. The basics are in the
[README](../README.md).

## Build and test

Linux is the tested platform. Windows (MSVC, clang-cl, MinGW-w64) is
ported in the code but has not been built or tested by us yet: see
[Windows](#windows). macOS is not supported (configure rejects Apple Clang,
even for the codec-only target). Standalone CMake project (CMake 3.25+, GCC 16+ or Clang 23+;
Clang needs libstdc++ 16+ too, so install g++-16 next to it; configure
stops with an error on anything older; libc++ is neither supported nor
checked, so use libstdc++). Catch2 v3, and for `jhetz::ldap_net` Corosio
and Capy, are fetched from GitHub. Both libraries need the ICU 60+ development
files (`libicu-dev`; Arch: `icu`), and `jhetz::ldap_net` OpenSSL's too
(`libssl-dev`; Arch: `openssl`).

```sh
cmake -B build/main -G Ninja -DCMAKE_BUILD_TYPE=Debug -DJHETZ_LDAP_SANITIZE=ON
cmake --build build/main
ctest --test-dir build/main --output-on-failure
ctest --test-dir build/main -R '^net\.'     # just the transport / connect / connection tests
```

To build against local checkouts instead of downloading, pass
`-DFETCHCONTENT_SOURCE_DIR_CAPY=/path/to/capy -DFETCHCONTENT_SOURCE_DIR_COROSIO=/path/to/corosio`.

The `net.*` tests need no LDAP server and no fixed ports: they run TCP, TLS
and Unix socket servers in-process on loopback, with a throwaway CA and
certificates generated at run time through the OpenSSL API.

Every public header compiles on its own: the build compiles one generated
file per header in `include/jhetz/ldap/` (targets `jhetz_ldap_header_check`
for the codec's headers, against `jhetz::ldap` alone, so a codec header that
needs Corosio or Capy fails, and `jhetz_ldap_net_header_check` for the
others; the list of `jhetz::ldap_net` headers is in `tests/CMakeLists.txt`).

| Option | Default | |
|---|---|---|
| `JHETZ_LDAP_BUILD_TESTS` | `ON` | unit tests and the `*_fuzz_replay` tests |
| `JHETZ_LDAP_BUILD_NET` | `ON` (`OFF` with fuzzers) | `jhetz::ldap_net` and its tests; fetches Corosio + Capy, needs OpenSSL |
| `JHETZ_LDAP_WITH_GSSAPI` | `OFF` | SASL GSSAPI (Kerberos) in `jhetz::ldap_net`, its tests and example; needs the GSS-API library (pkg-config `krb5-gssapi`). The installed package then has the component `gssapi` |
| `JHETZ_LDAP_BUILD_FUZZERS` | `OFF` | libFuzzer targets (Clang only) |
| `JHETZ_LDAP_SANITIZE` | `OFF` | ASan + UBSan on every target |
| `JHETZ_LDAP_WERROR` | `ON` (`OFF` as a subproject, and on MSVC / clang-cl) | warnings are errors in our own targets (never in Corosio, Capy or Catch2); off when added with `add_subdirectory` or FetchContent, so a newer compiler's new warnings do not break consumers. Off on MSVC and clang-cl until the first clean Windows build (`/W4` still shows the warnings; `-DJHETZ_LDAP_WERROR=ON` adds `/WX`; coro-ldap-2we) |
| `JHETZ_LDAP_BUILD_BENCH` | `OFF` | `jhetz_ldap_decode_bench` (see below; not run by ctest or CI) |
| `JHETZ_LDAP_COVERAGE` | `OFF` | Clang source-based coverage on our own targets (see [Coverage](#coverage)) |
| `JHETZ_LDAP_CLANG_TIDY` | `OFF` | run clang-tidy (`.clang-tidy`) on our own targets while building them (see [clang-tidy](#clang-tidy)) |

## Windows

Status: the code has been ported to Windows (Winsock through Corosio, the
CryptoAPI trust store, wide file paths, MSVC-safe code and CMake), but no
Windows build has run here: there is no Windows toolchain in the
development setup, so the port is checked only by syntax checks against the
mingw-w64 headers. Expect a first build to turn up warnings and small
errors; reports are welcome.

Compilers: MSVC 19.40 (Visual Studio 2022 17.10) or newer, clang-cl on such
a toolset (configure checks `MSVC_VERSION` for both), or MinGW-w64 with GCC
16+. Clang's GNU driver aimed at `x86_64-pc-windows-msvc` (`clang++
--target=...`, not clang-cl) gets no check of the MSVC STL's version: CMake
does not set `MSVC` for it and the libstdc++ probe passes vacuously, so an
old Visual Studio STL shows up only as compile errors.

### Build with vcpkg

From a "x64 Native Tools Command Prompt for VS 2022", with vcpkg cloned and
bootstrapped in `%VCPKG_ROOT%`:

```bat
%VCPKG_ROOT%\vcpkg install icu openssl --triplet x64-windows
cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Debug ^
  -DCMAKE_TOOLCHAIN_FILE=%VCPKG_ROOT%\scripts\buildsystems\vcpkg.cmake ^
  -DVCPKG_TARGET_TRIPLET=x64-windows
cmake --build build
ctest --test-dir build --output-on-failure
```

Catch2, Corosio and Capy are fetched as on Linux. The tests are listed when
ctest runs them (`DISCOVERY_MODE PRE_TEST`), so the ICU and OpenSSL DLLs
must be found at test time only: vcpkg's toolchain copies them next to the
executables, or put `%VCPKG_ROOT%\installed\x64-windows\debug\bin` (`bin`
for Release) on `PATH`. Use the dynamic triplet: with a static ICU
(`x64-windows-static`) consumers must compile with
`U_STATIC_IMPLEMENTATION`, which the build does not set yet (pass
`-DCMAKE_CXX_FLAGS=/DU_STATIC_IMPLEMENTATION` to try it; untested).

What the build does on Windows, for our own targets only: `/W4 /utf-8
/bigobj` on MSVC and clang-cl (`-Wa,-mbig-obj` on MinGW),
`_CRT_SECURE_NO_WARNINGS`, `NOMINMAX` and `WIN32_LEAN_AND_MEAN`, and
`jhetz_ldap_net` links `crypt32`. Warnings are not errors on MSVC and
clang-cl by default (`/WX` is off until the first clean build;
`-DJHETZ_LDAP_WERROR=ON` turns it on; coro-ldap-2we tracks the switch).
Corosio's and Capy's targets get none of these flags, so no `/bigobj`
either: if MSVC stops on C1128 (too many sections) in one of their files,
add `/bigobj` to `CMAKE_CXX_FLAGS`. The `compile.*` tests (the mapping's
compile-time diagnostics) are not registered with MSVC or clang-cl.

### Behaviour that differs on Windows

- Default trust store: with no `ca_file`, `ca_dir` or `ca_pem`, the anchors
  come from the CryptoAPI `ROOT` system store, enumerated again for every
  connection (OpenSSL reads no Windows store). A root is skipped when its
  extended key usage property excludes serverAuth, its disallowed usage
  property lists serverAuth, it has a `CERT_DISALLOWED_FILETIME_PROP_ID`,
  or it is also in the `Disallowed` store; the `CA` (intermediate) store
  never provides anchors. A store that cannot be enumerated to the end
  fails the connect rather than give a partial set.
- NotBefore: the root program can stop trusting what a root issues after a
  date (`CERT_NOT_BEFORE_FILETIME_PROP_ID`, for the uses
  `CERT_NOT_BEFORE_ENHKEY_USAGE_PROP_ID` lists, or all). OpenSSL cannot
  trust a root only for certificates issued before a date, so when the date
  applies to serverAuth the root is not used at all (fail closed). Pass it
  in `ca_file` to trust it anyway.
- AuthRoot gap: Windows downloads most Microsoft-trusted roots on demand
  (AuthRoot auto-update) while CryptoAPI builds a chain. A root no
  CryptoAPI client has needed yet is not in `ROOT`, so a server chaining to
  it fails to verify here although Windows' own clients accept it. Install
  the root or pass `ca_file` meanwhile. Verifying the chain with CryptoAPI
  itself (`CertGetCertificateChain` with the SSL policy, as wldap32 does)
  would close the gap and add Windows' revocation checks: coro-ldap-1q5.
- ldapi:// uses Windows' AF_UNIX, which needs Windows 10 1803 or later.
  Abstract socket names (a leading NUL, `ldapi://%00name`) are Linux only:
  elsewhere the URL is rejected as `invalid_url`. Winsock reads `sun_path`
  in the ANSI code page, so a socket path outside it (non-ASCII on most
  systems) may not reach the right file.
- `tls_options::ca_dir` is read lazily by OpenSSL through char paths: keep
  its path ASCII on Windows. The other TLS files go through
  `std::filesystem::path` and take any name.
- `ad::filetime_clock` works for any `system_clock` period (MSVC's is
  100 ns); `from_sys` is defined up to `time_point::max()` minus the
  1601-to-1970 offset, as documented in `ad.hpp`.

### Linux only

- SASL GSSAPI: configure stops on `JHETZ_LDAP_WITH_GSSAPI` (SSPI is not
  implemented).
- The integration tests (`run_slapd.sh`, `run_kdc.sh`), coverage
  (`run_coverage.sh`, Clang only and rejected for clang-cl) and the
  fuzzers (configure stops on `JHETZ_LDAP_BUILD_FUZZERS`). The
  `*_fuzz_replay` tests do run on Windows.
- `JHETZ_LDAP_SANITIZE` is ASan only on MSVC and clang-cl (no UBSan) and is
  refused with MinGW (no ASan runtime).
- A few `net.*` tests need Linux interfaces (the `getaddrinfo` interposer,
  `getifaddrs` for a link-local address) and skip elsewhere.

### Open questions for the first Windows build

- `/W4` warnings: none has been seen yet. Fix them, then default
  `JHETZ_LDAP_WERROR` back on (coro-ldap-2we).
- C1128 in Corosio's or Capy's sources without `/bigobj` (above).
- AF_UNIX: which error a connect to a missing socket path gives (the ldapi
  test accepts any "no such file" or "connection refused" condition), and
  whether Corosio's `local_endpoint` and Windows agree on paths near
  `max_path_length`.
- Refused connects: Winsock retries the SYN after an RST (about a second,
  `TcpMaxConnectRetransmissions`) before failing with `WSAECONNREFUSED`,
  where Linux fails at once. The tests that connect to `refused_port`
  (`tests/net/net_test_support.hpp`) with a short timeout (e.g. the
  client's `acquire_timeout` of 100 ms) may then see a timeout instead of
  the refusal; unverified.
- Abstract addresses: Windows' AF_UNIX has been said to accept them;
  connect() refuses them off Linux until that is checked.
- Time zones: `std::chrono::locate_zone` on MSVC uses ICU's tzdb, whose
  abbreviations may differ from IANA's (`ad_tests` checks the offset, not
  "CET").
- Static ICU (`U_STATIC_IMPLEMENTATION`, above) and a static OpenSSL's
  extra system libraries.
- The Winsock test sockets (`tests/net/platform.hpp`): overlapped, so that
  `SO_RCVTIMEO` bounds a blocking `recv`; the CLI test's `cmd.exe` quoting
  (`shell_quote` refuses `"` and `%`).

## Installing

Either add it to the build (`add_subdirectory` or FetchContent) and
link `jhetz::ldap` / `jhetz::ldap_net`, or install it and use the CMake
package:

```cmake
find_package(jhetz_ldap 0.1 REQUIRED COMPONENTS net)   # or without `net`
target_link_libraries(app PRIVATE jhetz::ldap_net)     # jhetz::ldap: codec only
```

`cmake --install` installs the headers, the libraries and the `jhetz_ldap`
package (`JHETZ_LDAP_INSTALL`, on when this is the top-level project).
`jhetz::ldap_net` is part of the package only when Capy and Corosio were
found as installed packages (on `CMAKE_PREFIX_PATH`; configure prefers them
to fetching): a fetched Corosio does not export its targets. Without it the
package is the codec only, without the networking headers; fetched
dependencies are never installed with it. The package finds ICU
(`find_dependency(ICU 60 COMPONENTS uc data)`), which the static libraries
need at link time, codec-only too. Corosio at the
pinned commit needs help to install against an installed Capy;
`tests/install/check_install.sh WORK_DIR` does the whole sequence (Capy,
Corosio, jhetz_ldap, then a consumer in `tests/install/consumer/`, also
codec-only) and is the reference for doing it by hand.

## Examples

Bare programs in `examples/`, one action each (option
`JHETZ_LDAP_BUILD_EXAMPLES`, targets `jhetz_ldap_example_<name>`). They
expect a local OpenLDAP serving `dc=example,dc=org` with
`cn=admin,dc=example,dc=org` / `secret`; the first argument overrides the
URL (`ldap://localhost`).

| Example | Does |
|---|---|
| `connect.cpp` | connect and simple bind |
| `search.cpp` | search `ou=people` with a filter, print each DN and `cn` |
| `pool.cpp` | the same search through an `ldap::client` pool (`client::search`: a shared lease, retried once on another connection) |
| `modify.cpp` | replace a user's `mail` |
| `add.cpp` | add the user `uid=jane` |
| `move.cpp` | move `uid=jane` from `ou=people` to `ou=alumni` (`connection::move`; `rename` changes the RDN instead) |
| `delete.cpp` | delete the user `uid=jane` from `ou=alumni` (run `add`, `move`, then `delete`) |
| `password.cpp` | reset a user's password (RFC 3062 or Active Directory, from the root DSE) |
| `starttls.cpp` | connect with StartTLS, then bind |
| `cancel.cpp` | search the whole tree; Ctrl-C gives up on it (`capy::when_any` with `ldap::raceable`) |
| `paged.cpp` | page through `ou=people` 100 entries at a time, sorted by `mail` (RFC 2696 paging, RFC 2891 server-side sort) |
| `blocking.cpp` | the same search with the blocking `ldap::sync::connection` |
| `blocking_pool.cpp` | the same search through the blocking pool `ldap::sync::client` |
| `referrals.cpp` | search `dc=example,dc=org` and follow its referrals to hosts under `example.org` (`chase_search` with `make_same_policy_connector`) |
| `gssapi.cpp` | StartTLS, then a Kerberos bind with the default ticket (`sasl_gssapi`; built with `JHETZ_LDAP_WITH_GSSAPI`) |

`examples/ldapsearch.cpp` (see [API.md](API.md)) is a fuller command-line tool. To try an
example against the throwaway slapd of the integration tests:

```sh
tests/integration/run_slapd.sh sh -c \
  'build/main/jhetz_ldap_example_search $JHETZ_LDAP_IT_LDAP'
```


## Integration tests

`tests/integration/` runs the client against a real OpenLDAP `slapd`
(ldap://, ldaps://, StartTLS, ldapi://; simple and SASL EXTERNAL binds over
ldapi:// and with a TLS client certificate; SASL SCRAM-SHA-256 binds,
also with a non-ASCII username and password, skipped unless cyrus-sasl's scram plugin is installed, e.g. Debian's
libsasl2-modules; plain, streaming, paged and
typed searches with the server's schema; every write operation; the
assertion, pre-read, post-read and (with the sssvlv overlay) server side
sort controls;
cancellation; a fault-injecting proxy that truncates, oversizes or cuts
the server's answer). `run_slapd.sh` starts a throwaway slapd with a test
PKI and the fixture from `make_fixture.py`, runs a command and stops it:

```sh
tests/integration/run_slapd.sh ctest --test-dir build/main -L integration --output-on-failure
```

It needs `slapd` and `openssl`; the defaults suit Debian / Ubuntu's slapd
package, others are set with `SLAPD`, `SLAPD_SCHEMA_DIR` and
`SLAPD_MODULE_PATH`. The sssvlv overlay is loaded when it is in the module
path; without it the server side sort test is skipped. Without slapd the
`integration` test is skipped, so plain `ctest` stays hermetic. CI runs it
in the `integration` job.

SASL GSSAPI (built with `JHETZ_LDAP_WITH_GSSAPI`) has its own test,
`integration.gssapi` (labels `integration` and `kerberos`), run with a
throwaway MIT Kerberos KDC around slapd: `run_kdc.sh` creates the realm
`EXAMPLE.ORG`, the service principal `ldap/localhost` (slapd's keytab)
and tickets for `user007` and `jörg`, with its configuration in a
temporary directory, and `run_slapd.sh` then configures slapd for GSSAPI:

```sh
tests/integration/run_kdc.sh tests/integration/run_slapd.sh \
  ctest --test-dir build/main -L integration --output-on-failure
```

It needs MIT krb5's KDC tools (`krb5kdc`, `kdb5_util`, `kadmin.local`,
`kinit`) and cyrus-sasl's gssapi plugin for slapd (Debian
`libsasl2-modules-gssapi-mit`, Arch `cyrus-sasl-gssapi`). Without the KDC
tools `run_kdc.sh` runs the command without Kerberos, and without the
plugin slapd does not offer GSSAPI: either way the test is skipped. The
KDC listens on 127.0.0.1, port `JHETZ_LDAP_IT_KDC_PORT` (3750). Not in
CI.

A plugin outside cyrus-sasl's directory is found through `SASL_PATH`, a
colon-separated list of directories replacing the default one, so list
that one too. To use the plugin without installing it (Arch), extract the
package into a scratch directory, as for a local slapd:

```sh
mkdir -p /tmp/sasl-gssapi
curl -L https://archlinux.org/packages/extra/x86_64/cyrus-sasl-gssapi/download/ \
  | bsdtar -xf - -C /tmp/sasl-gssapi
SASL_PATH=/tmp/sasl-gssapi/usr/lib/sasl2:/usr/lib/sasl2 \
  SLAPD=<ol>/usr/bin/slapd SLAPD_SCHEMA_DIR=<ol>/etc/openldap/schema \
  SLAPD_MODULE_PATH=<ol>/usr/lib/openldap \
  tests/integration/run_kdc.sh tests/integration/run_slapd.sh \
  ctest --test-dir build/gssapi -L integration --output-on-failure
```

(`<ol>`: the Arch `openldap` package extracted the same way; `build/gssapi`
configured with `-DJHETZ_LDAP_WITH_GSSAPI=ON`.)

## Coverage

`tests/coverage/run_coverage.sh` configures and builds `BUILD_DIR` (default
`build/coverage`) with clang++ and `-DJHETZ_LDAP_COVERAGE=ON` (only our
libraries, tests and examples are instrumented; no sanitizers), runs the
whole ctest suite, and with `SLAPD` set (as for `run_slapd.sh`) the
integration tests too, then reports on `src` and `include`:

```sh
SLAPD=/usr/sbin/slapd tests/coverage/run_coverage.sh [--run-only] [BUILD_DIR]
```

- `BUILD_DIR/llvm-cov/summary.txt`: the `llvm-cov report` table (also printed)
- `BUILD_DIR/llvm-cov/html/index.html`: line, region and branch counts per file
- `BUILD_DIR/llvm-cov/summary.json`: `llvm-cov export -summary-only`

`--run-only` stops after the tests and leaves the raw profiles in
`BUILD_DIR/llvm-cov/profraw`. A failing test still gets a report, and the
script exits with the first failing test step's status (a failing report
step exits with its own). An existing `BUILD_DIR`
configured without the option is refused rather than reconfigured. It needs
`llvm-profdata` and `llvm-cov` matching the compiler (the `llvm` package; or
set `LLVM_PROFDATA`, `LLVM_COV` and `CXX`), on Linux.

A template that nothing instantiates generates no code, so it is missing
from the report rather than shown as 0% (uncalled inline functions do show
up, with zero counts).

## clang-tidy

The checks are in `.clang-tidy` (each disabled check has its reason there);
`tests/.clang-tidy` and `fuzz/.clang-tidy` inherit it and turn off test-only
noise. The header filter keeps the reports to our own headers (never Corosio,
Capy, Catch2), and the dependencies are SYSTEM includes. Static-analyzer
reports are placed in the main file (`report-in-main-source-file`, set through
`ExtraArgs`), so one whose path ends in a dependency header lands on our call
site, where a NOLINT can silence it. Use Clang for the build directory, with GSSAPI on so
`sasl_gssapi.cpp` is covered; `compile_commands.json` is written by default.
`build/tidy` is that directory:

```sh
cmake -B build/tidy -G Ninja -DCMAKE_CXX_COMPILER=clang++ -DCMAKE_BUILD_TYPE=Debug \
  -DJHETZ_LDAP_WITH_GSSAPI=ON -DJHETZ_LDAP_BUILD_BENCH=ON
cmake --build build/tidy -j8      # once, for the generated files and the dependencies
run-clang-tidy -p build/tidy -j6 -quiet -source-filter '.*/coro-ldap/(src|tests|examples|fuzz|bench)/.*'
```

The fuzz targets are checked through their `*_fuzz_replay` builds. A full
run takes about five minutes. Alternatively, `-DJHETZ_LDAP_CLANG_TIDY=ON`
sets `CXX_CLANG_TIDY` on our own targets (through `jhetz_ldap_warnings`), so
every compile of our sources also runs clang-tidy:

```sh
cmake -B build/tidy-werror -G Ninja -DCMAKE_CXX_COMPILER=clang++ -DCMAKE_BUILD_TYPE=Debug \
  -DJHETZ_LDAP_CLANG_TIDY=ON -DJHETZ_LDAP_WITH_GSSAPI=ON
cmake --build build/tidy-werror -j6
```

The tree is clean: `.clang-tidy` sets `WarningsAsErrors: '*'` (inherited by
`tests/.clang-tidy`, `fuzz/.clang-tidy` and `bench/.clang-tidy`), so every
finding is an error,
run-clang-tidy exits non-zero on one and a `-DJHETZ_LDAP_CLANG_TIDY=ON`
build fails on it. The default build (option `OFF`) does not run
clang-tidy. A finding that is a false positive gets
`// NOLINT(check-name): reason` (or `NOLINTNEXTLINE`) rather than a
disabled check.

## Fuzz

| Target | Input | Properties |
|---|---|---|
| `ber_fuzz` | bytes | framer and reader agree; every element walks; values re-encode consistently |
| `message_fuzz` | bytes | a message that decodes encodes, decodes to an equal message (exactly) and re-encodes to the same bytes; paged results, sort result, pre-/post-read and RFC 4533 sync request / state / done controls, and Sync Info Messages, that decode re-encode to equal values; decoding into a `monotonic_buffer_resource` (with `null_memory_resource()` as the default resource meanwhile) gives an equal message, and a copy taken before the arena is released stays valid (ASan); filter text in a search request round-trips exactly |
| `filter_fuzz` | text / bytes | `filter::raw` text -> BER -> equal tree -> same BER, and `to_string` -> `raw` -> equal tree (a fixed point); every builder's text parses back to its tree (escaping) and `attr("cn") == v` carries `v` exactly; decodable BER filters round-trip; `!f` holds exactly `f`'s BER |
| `dn_fuzz` | text | `parse(to_string(d)) == d`; the literal validator agrees with `parse` |
| `url_fuzz` | text | `parse(to_string(u)) == u` and `to_string` is canonical; printed URLs contain only RFC 3986 characters |
| `matching_fuzz` | text (two values, split at an offset in the first byte) | `prepare_string` fails only with `string_prep_failed` and is idempotent (one SPACE more for a value starting with a combining mark); a value matches itself exactly when it prepares; equality rules are symmetric and caseExactMatch TRUE implies caseIgnoreMatch TRUE; orderings are never TRUE both ways; a parsed DN never fails to match itself; the OID, uniqueMember, generalizedTime, uuid, bitString and caseIgnoreList rules are symmetric and never FALSE on a value against itself |

```sh
cmake -B build/fuzz -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo \
      -DCMAKE_CXX_COMPILER=clang++ -DJHETZ_LDAP_BUILD_FUZZERS=ON -DJHETZ_LDAP_BUILD_TESTS=OFF
cmake --build build/fuzz
mkdir -p corpus && cp fuzz/corpus/message_fuzz/* corpus/
UBSAN_OPTIONS=halt_on_error=1 build/fuzz/fuzzers/message_fuzz -max_total_time=60 corpus
# url_fuzz has a dictionary: add -dict=fuzz/url.dict
```

`fuzz/corpus/<target>/` holds the seed inputs (the same ones
`<target>_replay` mutates). Regenerate them after changing the seeds with
`<target>_replay --write-seeds fuzz/corpus/<target>`.

Sanitized and fuzz builds use `-fno-sanitize-recover=all`, so any UBSan
finding aborts and fails the test or fuzz run.

A fuzz build leaves `JHETZ_LDAP_BUILD_NET` off by default: the fuzzers only
cover the codec and URLs.

Without libFuzzer, the `<target>_replay` tests (part of `ctest`) run the same
entry points on deterministic generated and mutated inputs (about 300,000 for
`ber_fuzz`, 200,000 for `message_fuzz` and `url_fuzz`, 150,000 for `dn_fuzz`
and 45,000 for the slower `filter_fuzz`).

## Benchmark

`bench/decode_bench.cpp` (option `JHETZ_LDAP_BUILD_BENCH`) decodes a stream
of 1,000 SearchResultEntry PDUs, 30 attributes x 3 values (10-60 bytes) each,
plus a 64 KiB `jpegPhoto` and a 4 KiB `userCertificate` in every 20th entry
(7.1 MiB, 90,100 values), with the default resource and with one
`monotonic_buffer_resource` `release()`d after each message, with and
without a 256 KiB initial buffer. Heap allocations are counted with a
counting default resource in a separate pass.

```sh
cmake -B build/bench -G Ninja -DCMAKE_BUILD_TYPE=Release \
      -DJHETZ_LDAP_BUILD_BENCH=ON -DJHETZ_LDAP_BUILD_TESTS=OFF -DJHETZ_LDAP_BUILD_NET=OFF
cmake --build build/bench && build/bench/jhetz_ldap_decode_bench
```

GCC 16.2, Release (`-O3`), a 12-thread desktop, best / median of 15 runs
(three invocations; the heap row varies by about 10% between them, the
arena rows by under 1%):

| Mode | Best | Median | Heap allocations | per entry | Heap MiB |
|---|---:|---:|---:|---:|---:|
| default resource (heap) | 10.0 ms | 10.0 ms | 111,662 | 111.7 | 11.8 |
| monotonic arena, 256 KiB buffer, `release()` | 7.6 ms | 7.6 ms | 0 | 0 | 0 |
| monotonic arena, no buffer, `release()` | 8.0 ms | 8.0 ms | 5,100 | 5.1 | 17.4 |

A reused arena with a buffer that holds a typical response removes every
heap allocation and saves about 24% of the decode time here; without a
buffer, `release()` hands the chunks back and each message fetches them
again (about 5 per entry, larger ones for the photos). Decoding reserves the
attribute and value vectors exactly (counting the elements first), which
took the heap mode from 177 to 112 allocations per entry and the arena
without buffer from 24.6 to 17.4 MiB, at the price of reading the element
headers twice. Since BER headers are parsed without building a `result` in
the common case (#19), that second read costs nothing measurable, and
decoding got faster in every mode: on the same machine and in the same
session, before and after that change, heap 11.5 to 10.0 ms (-13%), arena
with buffer 9.3 to 7.6 ms (-18%), arena without buffer 9.6 to 8.0 ms
(-17%). Counting decoded strings against `decode_options::max_elements`
costs about 0.3 ms of that.

## Golden vectors

`tests/message_golden_tests.cpp` compares the codec with encodings produced
by an independent implementation (ldap3 2.9.1 / pyasn1 0.6.4); the generating
script is in the file.
