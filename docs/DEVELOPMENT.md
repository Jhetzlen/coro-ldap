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
| `JHETZ_LDAP_BUILD_NET` | `ON` (`OFF` with fuzzers) | `jhetz::ldap_net`, `jhetz::ldap_ad` (Active Directory, DESIGN.md section 12) and their tests; fetches Corosio + Capy, needs OpenSSL |
| `JHETZ_LDAP_WITH_GSSAPI` | `OFF` | SASL GSSAPI (Kerberos) in `jhetz::ldap_net`, its tests and example; needs the GSS-API library (pkg-config `krb5-gssapi`). The installed package then has the component `gssapi` |
| `JHETZ_LDAP_BUILD_FUZZERS` | `OFF` | libFuzzer targets (Clang only) |
| `JHETZ_LDAP_SANITIZE` | `OFF` | ASan + UBSan on every target |
| `JHETZ_LDAP_WERROR` | `ON` (`OFF` as a subproject, and on clang-cl) | warnings are errors in our own targets (never in Corosio, Capy or Catch2); off when added with `add_subdirectory` or FetchContent, so a newer compiler's new warnings do not break consumers. `/WX` on MSVC; off on clang-cl, not built yet (`/W4` still shows the warnings; `-DJHETZ_LDAP_WERROR=ON` adds `/WX`) |
| `JHETZ_LDAP_BUILD_BENCH` | `OFF` | `jhetz_ldap_decode_bench`, and with `JHETZ_LDAP_BUILD_NET` `jhetz_ldap_connection_bench` and `jhetz_ldap_paged_bench` (see below; not run by ctest or CI) |
| `JHETZ_LDAP_COVERAGE` | `OFF` | Clang source-based coverage on our own targets (see [Coverage](#coverage)) |
| `JHETZ_LDAP_CLANG_TIDY` | `OFF` | run clang-tidy (`.clang-tidy`) on our own targets while building them (see [clang-tidy](#clang-tidy)) |

## Windows

Status: the code has been ported to Windows (Winsock through Corosio, the
CryptoAPI trust store and chain verification, wide file paths, MSVC-safe code and CMake). The
Linux development setup has no Windows toolchain and checks the port only
by syntax checks against the mingw-w64 headers. A first MSVC build ran on
2026-11-06 (Visual Studio 2022 17.14, MSVC 19.44, vcpkg's ICU 79.1 and
OpenSSL 3.6.5): `/W4` clean, 751 of 752 tests passing in RelWithDebInfo
(coro-ldap-0wp is the one left). clang-cl and MinGW have not been built.

Compilers: MSVC 19.40 (Visual Studio 2022 17.10) or newer, clang-cl on such
a toolset (configure checks `MSVC_VERSION` for both), or MinGW-w64 with GCC
16+. Clang's GNU driver aimed at `x86_64-pc-windows-msvc` (`clang++
--target=...`, not clang-cl) gets no check of the MSVC STL's version: CMake
does not set `MSVC` for it and the libstdc++ probe passes vacuously, so an
old Visual Studio STL shows up only as compile errors.

### Syntax check with mingw-w64

Without root, from Arch's packages (headers only; `build/main` configured
first, for the fetched Capy, Corosio and Catch2; OpenSSL's and ICU's
headers are the host's; needs curl, bsdtar and clang; run from the
repository root):

```sh
M=$PWD/build/mingw; mkdir -p $M/root $M/deps
for p in extra/any/mingw-w64-headers extra/any/mingw-w64-winpthreads extra/x86_64/mingw-w64-gcc; do
  curl -sfL https://archlinux.org/packages/$p/download/ | bsdtar -xf - -C $M/root usr/x86_64-w64-mingw32/include
done
ln -sfn /usr/include/openssl $M/deps/openssl; ln -sfn /usr/include/unicode $M/deps/unicode
I=$M/root/usr/x86_64-w64-mingw32/include; C=$I/c++/$(ls $I/c++ | tail -1); D=$PWD/build/main/_deps
for f in $(ls src/*.cpp src/*/*.cpp tests/*.cpp tests/net/*.cpp examples/*.cpp fuzz/*_replay.cpp bench/*.cpp \
           | grep -v -e trust_store_default -e sasl_gssapi); do
  clang++ --target=x86_64-w64-mingw32 -std=c++23 -fsyntax-only -nostdinc++ -nostdlibinc \
    -isystem $C -isystem $C/x86_64-w64-mingw32 -isystem $C/backward -isystem $I -isystem $M/deps \
    -D_CRT_SECURE_NO_WARNINGS -DNOMINMAX -DWIN32_LEAN_AND_MEAN -DCERT_CHAIN_PARA_HAS_EXTRA_FIELDS \
    -DBOOST_CAPY_NO_LIB -DBOOST_CAPY_STATIC_LINK -DBOOST_COROSIO_HAS_OPENSSL \
    -DBOOST_COROSIO_NO_LIB -DBOOST_COROSIO_STATIC_LINK -DJHETZ_LDAPSEARCH='"jhetz-ldapsearch.exe"' \
    -Iinclude -isystem $D/corosio-src/include -isystem $D/capy-src/include \
    -isystem $D/catch2-src/src -isystem $D/catch2-build/generated-includes \
    -Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion -Wshadow -Wno-c2y-extensions $f || echo "FAIL $f"
done
```

`sasl_gssapi.cpp` is left out (Linux only, below), and
`trust_store_default.cpp`, which Windows builds replace with
`trust_store_win.cpp`.

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

The vcpkg bundled with Visual Studio (`VC\vcpkg`) has no classic mode
(`vcpkg install icu openssl` fails): put a `vcpkg.json` listing `icu` and
`openssl` (with a `builtin-baseline`, which `vcpkg x-update-baseline
--add-initial-baseline` adds) in a directory of its own, run `vcpkg install
--triplet x64-windows --x-install-root=<dir>` there, and configure with
`-DVCPKG_MANIFEST_MODE=OFF -DVCPKG_INSTALLED_DIR=<dir>` besides the
toolchain file and triplet.

CMake 4.5.0-rc3 stops in Capy's `CMakeLists.txt` (`source_group(TREE)`
given `capy.hpp`, outside its tree); the CMake bundled with Visual Studio
(3.31, `Common7\IDE\CommonExtensions\Microsoft\CMake`) configures.

Run the tests from a Release or RelWithDebInfo build: in Debug, MSVC's
checked iterators (`_ITERATOR_DEBUG_LEVEL=2`) make every container allocate
a proxy from its allocator, so the allocation-counting tests (`[pmr]`,
`[alloc]`, the read and write buffers' counts) fail there.

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
`jhetz_ldap_net` links `crypt32`. Warnings are errors on MSVC (`/WX`) as
with GCC and Clang, but not by default on clang-cl, which has not been
built yet (`-DJHETZ_LDAP_WERROR=ON` turns it on).
Corosio's and Capy's targets get none of these flags, so no `/bigobj`
either; MSVC 19.44 built them without C1128 (too many sections), but if it
comes up, add `/bigobj` to `CMAKE_CXX_FLAGS`. The `compile.*` tests (the mapping's
compile-time diagnostics) are not registered with MSVC or clang-cl.

### Behaviour that differs on Windows

- Default verification: with no `ca_file`, `ca_dir` or `ca_pem`, the
  server's chain is verified by CryptoAPI (`CertGetCertificateChain` and
  `CertVerifyCertificateChainPolicy` with the SSL policy, as wldap32
  does), whose verdict replaces OpenSSL's on the chain: the roots Windows
  fetches on demand (AuthRoot auto-update) are found, and Windows' own
  distrust, NotBefore and name constraint rules apply. The host name is
  still matched by OpenSSL, with `host_matching` as on Linux, and so are
  the leaf's key size and purpose; CryptoAPI holds the rest of the chain
  to OpenSSL's security level (a `CERT_STRONG_SIGN_PARA`). Revocation
  is checked for every certificate but the root, soft-fail: a CRL or OCSP
  responder that cannot be reached in time is not an error, a revoked
  certificate is. The revocation fetches together are bounded by what is
  left of the connect or StartTLS timeout and at most 20 s; AIA and
  AuthRoot fetches have Windows' own per-URL timeout, and can make a
  connect overrun its timeout. CryptoAPI blocks the io thread throughout
  (every other operation on that io_context waits). A rejection's
  context ends in `Windows certificate chain: <reason> (0x<HRESULT>)`.
  DESIGN.md has the reasoning.
- The `ROOT` store is still copied into OpenSSL per connection (a root is
  skipped when its extended key usage property excludes serverAuth, its
  disallowed usage property lists serverAuth, it has a
  `CERT_DISALLOWED_FILETIME_PROP_ID` or a `CERT_NOT_BEFORE_FILETIME_PROP_ID`
  applying to serverAuth, or it is also in the `Disallowed` store), and a
  store that cannot be enumerated to the end fails the connect; with
  CryptoAPI deciding on the chain, that copy no longer decides anything.
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
  1601-to-1970 offset, as documented in `ad/filetime.hpp`.

### Linux only

- SASL GSSAPI: configure stops on `JHETZ_LDAP_WITH_GSSAPI` (SSPI is not
  implemented).
- The integration tests (`run_slapd.sh`, `run_openldap.sh`, `run_kdc.sh`,
  `run_samba_ad.sh`), coverage (`run_coverage.sh`, Clang only and rejected
  for clang-cl) and the fuzzers (configure stops on
  `JHETZ_LDAP_BUILD_FUZZERS`). The `*_fuzz_replay` tests do run on Windows.
- `JHETZ_LDAP_SANITIZE` is ASan only on MSVC and clang-cl (no UBSan) and is
  refused with MinGW (no ASan runtime).
- A few `net.*` tests need Linux interfaces (the `getaddrinfo` interposer,
  `getifaddrs` for a link-local address) and skip elsewhere.

### Seen in the first Windows build

- MSVC 19.44 refuses what GCC and Clang accept: a `constexpr` function
  calling ICU's `U_FAILURE` (a plain inline function in C++), `const auto
  *` for a `std::array` iterator (a class there), `request_stop()` on a
  const `std::stop_source` (non-const in the standard, const in
  libstdc++), a `friend class client;` with no prior `sync::client` (bound
  to `ldap::client`), and Catch2 comparing an ordering with `0` (passed as
  an `int`, where MSVC's operators take a literal zero).
- Refused connects: Winsock retries the SYN after an RST and fails with
  `WSAECONNREFUSED` about a second later, where Linux fails at once; a test
  that connects to `refused_port` needs a timeout above that.
- Large writes: Windows completes an overlapped write of 1 MiB whole, on
  AF_UNIX and on TCP with small socket buffers, where Linux fills the
  socket and parks the writer. A test that needs a parked writer writes
  more (`sasl_layer_tests.cpp`), or fails (coro-ldap-0wp).
- The ldapi, `[tls]` (CryptoAPI chain verification included) and
  `ad_filetime` tests pass.

### Open questions for Windows

- AF_UNIX: which error a connect to a missing socket path gives (the ldapi
  test accepts any "no such file" or "connection refused" condition), and
  whether Corosio's `local_endpoint` and Windows agree on paths near
  `max_path_length`.
- Abstract addresses: Windows' AF_UNIX has been said to accept them;
  connect() refuses them off Linux until that is checked.
- Time zones: `std::chrono::locate_zone` on MSVC uses ICU's tzdb, whose
  abbreviations may differ from IANA's (`ad_filetime_tests.cpp` checks the
  offset, not "CET").
- Static ICU (`U_STATIC_IMPLEMENTATION`, above) and a static OpenSSL's
  extra system libraries.
- CryptoAPI chain verification (coro-ldap-1q5), beyond the `[tls]` tests
  (which pass): that `ldaps://` to a public server chaining to a root not
  yet in `ROOT` connects (AuthRoot fetched); that a revoked server certificate fails with `CRYPT_E_REVOKED` while an
  unreachable CRL distribution point passes (the SSL policy honouring
  `CERT_CHAIN_POLICY_IGNORE_ALL_REV_UNKNOWN_FLAGS`); that
  `SECURITY_FLAG_IGNORE_CERT_CN_INVALID` with a null `pwszServerName`
  skips the name check (a certificate for another name passes CryptoAPI
  and fails OpenSSL's host check); that OpenSSL always reaches the leaf's
  final verify callback after letting chain errors through (a handshake
  failing with "the system certificate chain check did not run" would
  mean not); that the strong signature lists reject a SHA-1-signed
  intermediate and an RSA-1024 CA at the default security level 2
  (`CERT_TRUST_HAS_WEAK_SIGNATURE`) but not a SHA-1 self-signed root (its
  own signature, which OpenSSL does not check either) nor the
  RSA-PSS-signed chains CNG names `RSA`; how long a connect blocks with
  no network for the AuthRoot, AIA and CRL fetches (revocation within the
  timeout and 20 s, AIA and AuthRoot per URL; whether
  `dwUrlRetrievalTimeout` limits those too, which Microsoft does not
  document); and whether the
  `CERT_CHAIN_PARA_HAS_EXTRA_FIELDS` layout matches on MSVC.
- The Winsock test sockets (`tests/net/platform.hpp`): overlapped, so that
  `SO_RCVTIMEO` bounds a blocking `recv`; the CLI test's `cmd.exe` quoting
  (`shell_quote` refuses `"` and `%`).

## Installing

Either add it to the build (`add_subdirectory` or FetchContent) and
link `jhetz::ldap` / `jhetz::ldap_net` / `jhetz::ldap_ad`, or install it
and use the CMake package:

```cmake
find_package(jhetz_ldap 0.1 REQUIRED COMPONENTS net)   # or without `net`
target_link_libraries(app PRIVATE jhetz::ldap_net)     # jhetz::ldap: codec only
# Active Directory operations (ldap::ad over the connection):
find_package(jhetz_ldap 0.1 REQUIRED COMPONENTS net ad)
target_link_libraries(app PRIVATE jhetz::ldap_ad)
```

`cmake --install` installs the headers, the libraries and the `jhetz_ldap`
package (`JHETZ_LDAP_INSTALL`, on when this is the top-level project).
`jhetz::ldap_net` and `jhetz::ldap_ad` are part of the package only when
Capy and Corosio were found as installed packages (on `CMAKE_PREFIX_PATH`;
configure prefers them to fetching): a fetched Corosio does not export its
targets. Without them the
package is the codec only, without the networking headers; fetched
dependencies are never installed with it. The package finds ICU
(`find_dependency(ICU 60 COMPONENTS uc data)`), which the static libraries
need at link time, codec-only too. Corosio at the
pinned commit needs help to install against an installed Capy;
`tests/install/check_install.sh WORK_DIR` does the whole sequence (Capy,
Corosio, jhetz_ldap, then a consumer in `tests/install/consumer/` with the
`net` and `ad` components, also codec-only) and is the reference for doing
it by hand.

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
| `move.cpp` | move `uid=jane` from `ou=people` to `ou=alumni` (`modify_dn` with `.new_superior`; `.new_rdn` alone renames) |
| `delete.cpp` | delete the user `uid=jane` from `ou=alumni` (run `add`, `move`, then `delete`) |
| `password.cpp` | reset a user's password (RFC 3062 Password Modify) |
| `transaction.cpp` | add the user `uid=jane` and set the `manager` of `uid=user001` in one RFC 5805 transaction: both applied, or neither (run `delete` or remove `uid=jane` to run it again) |
| `starttls.cpp` | connect with StartTLS, then bind |
| `cancel.cpp` | search the whole tree; Ctrl-C gives up on it (`capy::when_any` with `ldap::raceable`) |
| `paged.cpp` | page through `ou=people` 100 entries at a time, sorted by `mail` (RFC 2696 paging, RFC 2891 server-side sort) |
| `blocking.cpp` | the same search with the blocking `ldap::sync::connection` |
| `blocking_pool.cpp` | the same search through the blocking pool `ldap::sync::client` |
| `referrals.cpp` | search `dc=example,dc=org` and follow its referrals to hosts under `example.org` (`chase_search` with `make_same_policy_connector`) |
| `gssapi.cpp` | StartTLS, then a Kerberos bind with the default ticket (`sasl_gssapi`; built with `JHETZ_LDAP_WITH_GSSAPI`) |
| `ntlm.cpp` | an NTLMv2 bind to Active Directory with a user name and a password (from `LDAP_PASSWORD`) over ldaps:// (`sasl_ntlm`, SASL GSS-SPNEGO; TLS required by default) |

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

Without a local slapd, `run_openldap.sh` runs `run_slapd.sh` itself in
Docker, with Debian trixie's OpenLDAP (slapd 2.6.10, with the sssvlv and
syncprov overlays and cyrus-sasl's SCRAM and GSSAPI plugins):

```sh
tests/integration/run_openldap.sh ctest --test-dir build/main -L integration --output-on-failure
```

It builds the image `coro-ldap-openldap` from
`tests/integration/openldap/Dockerfile` (Debian packages only, on a pinned
`debian:trixie-*-slim`; from Docker's cache after the first time, and kept)
and starts one container, removed on exit (also on failure or Ctrl-C). The
configuration, certificates and fixture are `run_slapd.sh`'s, with its
Debian defaults: the container runs the script as the calling user, with
the host network (slapd listens on 127.0.0.1 only, as without Docker) and
a temporary directory mounted at the same path as its `TMPDIR`, so the
certificate paths and the ldapi:// socket are the same on the host, where
the command runs. Without a working `docker` the command runs without
slapd, so the test is skipped. Both Docker harnesses (this one and
`run_samba_ad.sh`) assume rootful Docker on Linux: `--network host` and
`--user uid:gid` need the containers on the host's network and its uids.

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

The Docker slapd has the plugin, so only the KDC tools are needed on the
host: `run_openldap.sh` passes `run_kdc.sh`'s Kerberos environment
(`KRB5_CONFIG`, `KRB5_KTNAME`, `KRB5RCACHEDIR` and the realm) to the
container, with their directories mounted at the same paths, and slapd
reaches the KDC on 127.0.0.1:

```sh
tests/integration/run_kdc.sh tests/integration/run_openldap.sh \
  ctest --test-dir build/gssapi -L integration --output-on-failure
```

`kerberos.channel_binding` (same labels) checks the GSSAPI channel
bindings against an in-process MIT acceptor (`gss_accept_sec_context`)
rather than slapd, whose acceptor is given none: it needs the KDC only.

```sh
tests/integration/run_kdc.sh ctest --test-dir build/gssapi -L kerberos --output-on-failure
```

(`integration.gssapi` is skipped there, without slapd.)

With a local slapd, a plugin outside cyrus-sasl's directory is found
through `SASL_PATH`, a colon-separated list of directories replacing the
default one, so list that one too. To use the plugin without installing
it (Arch), extract the package into a scratch directory, as for a local
slapd:

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

### Samba Active Directory

`integration.samba_ad` (labels `integration` and `samba_ad`) runs the
Active Directory paths against Samba AD DCs in Docker:

```sh
tests/integration/run_samba_ad.sh ctest --test-dir build/main -L samba_ad --output-on-failure
```

`run_samba_ad.sh` builds the image `coro-ldap-samba-ad` from
`tests/integration/samba-ad/Dockerfile` (Debian trixie's Samba, 4.22,
on a pinned `debian:trixie-*-slim`; no third-party image) and keeps it;
the domain `CORO.TEST` (NetBIOS `CORO`, DC `DC1.coro.test`, no DNS
server), the throwaway Administrator password and the test users are
provisioned at build time, without privileges or capabilities (the
sysvol's NT ACLs go in `user.NTACL` extended attributes). The first build
takes about a minute, a run then about 15 s. It starts two containers,
which differ only in `ldap server require strong auth`, a global setting
in Samba:

| container | setting | on plain ldap:// | over TLS | Windows equivalent |
|---|---|---|---|---|
| strict (`JHETZ_LDAP_IT_SAMBA_LDAP`, `..._LDAPS`) | `yes` (Samba's default) | SASL binds with signing or sealing only | simple binds; SASL binds with correct channel bindings only | LDAP server signing requirements = require signing, LdapEnforceChannelBinding = 2 ("Always") |
| relaxed (`JHETZ_LDAP_IT_SAMBA_RELAXED_LDAP`, `..._LDAPS`) | `no` | any bind | any bind, channel bindings not checked | signing not required, LdapEnforceChannelBinding = 0 ("Never") |

Samba's third value, `allow_sasl_without_tls_channel_bindings`
(LdapEnforceChannelBinding = 1), is not run. Each container publishes
LDAP and LDAPS on 127.0.0.1 only, from `JHETZ_LDAP_IT_SAMBA_PORT` (4389:
strict 4389 and 4390, relaxed 4391 and 4392). The TLS certificate is the
one Samba generates for itself, `CN=DC1.coro.test` without a
subjectAltName; its CA is copied to a temporary directory under `build/`
(`JHETZ_LDAP_IT_SAMBA_CA`), and the tests connect to 127.0.0.1 with
`tls.server_name` = `DC1.coro.test` (`JHETZ_LDAP_IT_SAMBA_TLS_NAME`) and
`host_name_matching::legacy`, which falls back to the CN. Without a
working `docker` the command runs without Samba and the test is skipped.
The containers are removed on exit. Not in CI.

What it covers:

- `ad::change_password` and `ad::reset_password` (unicodePwd) over
  ldaps:// and StartTLS: a reset as Administrator, a change as the user
  (delete and add), a non-BMP password (surrogate pairs), a password the
  policy refuses (`constraint_violation`, `0000052D`, also for a reset)
  and a wrong old password (`constraint_violation`, `00000056`); through
  `ldap::client` and `sync::connection`; on plain ldap:// over the NTLM
  security layer (integrity and confidentiality, both sealed) a change and
  a reset succeed, while without TLS or a layer (simple bind, NTLM bind
  without a layer on the relaxed DC) `client_errc::tls_required` comes
  before the modify is sent. The core's RFC
  3062 `reset_password` is refused by Samba (`protocol_error`: no
  Password Modify extended operation).
- `sasl_ntlm` binds over ldaps:// and StartTLS: a UPN, `DOMAIN\user`, a
  bare user name, a non-ASCII user (`jörg`, also in upper case) with a
  non-BMP password, a wrong password (`invalid_credentials`, `8009030C`
  data 52e); channel binding: accepted when correct, a wrong binding
  refused (`invalid_credentials`, `80090346`) by both DCs,
  `ntlm_channel_binding::none` refused by the strict DC and accepted by
  the relaxed one; on plain ldap:// `tls_required` before sending,
  `stronger_auth_required` from the strict DC with `require_tls = false`,
  accepted by the relaxed one.
- The NTLM security layer (`security_layer` integrity and
  confidentiality) on plain ldap:// to the strict DC, through a relay
  that records the wire: a bind as Administrator, a 300 000-octet
  `jpegPhoto` written and read back; the client's buffers are 128 KiB at
  most and Samba puts the ModifyRequest cut across them back together,
  Samba's answer comes in buffers of 128 KiB at most too; every buffer is
  the signature (Version 1, sequence numbers from 0) then the message,
  sealed with both levels (no plaintext on the wire).

What Samba does not emulate, compared with Windows AD:

- The diagnostic texts: Samba starts them with the same Win32 code
  (`0000052D: Constraint violation - check_password_restrictions: the
  password is too short. ...`, `00000056: Constraint violation -
  check_password_restrictions: The old password specified doesn't
  match!`), Windows follows it with `AtrErr: DSID-...` details. The
  library reads only the code.
- `strongerAuthRequired` for an unsigned bind on plain ldap:// comes
  with `SASL:[GSS-SPNEGO]: Sign or Seal are required.`, not Windows'
  `00002028: LdapErr: ...`. The bind failures (`8009030C`, `80090346`)
  are in Windows' format.
- Channel bindings a client sends are checked even with `require strong
  auth = no`, where Windows' LdapEnforceChannelBinding = 0 checks none;
  only a client sending no MsvAvChannelBindings passes Samba's optional
  check (an explicit Z(16) does not, hence `ntlm_channel_binding::none`
  leaves the pair out). The MsvAvTargetName (`ldap/127.0.0.1` here) is
  not checked.
- With NTLM signing negotiated over LDAP, Samba seals (and expects
  sealed buffers), which its code says Windows does too; unverified
  against Windows here.
- Group Policy, the registry settings themselves (`LDAPServerIntegrity`,
  `LdapEnforceChannelBinding`) and their per-DC reload: Samba reads
  `ldap server require strong auth` at start, so each policy is a
  container of its own.

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

### Accepted gaps

Paths left uncovered on purpose, of three kinds:

- failure paths that only a fault-injection seam in production code
  (globals, macros, or a hook in every OpenSSL and ICU call) would reach,
  each only forwarding the failure;
- size limits that only an input too large to allocate in a test would
  reach;
- guards that the callers or a compile-time check rule out.

Paths reachable through the seams that exist are tested instead:
allocation failure through the io_context's frame allocator
(`failing_frames`) and the memory resources, protocol misuse through the
mock servers and direct mechanism calls.

- ICU failures in SASLprep (`src/sasl_scram.cpp`, `icu_failure`): ICU
  fails only on its own allocation failure, an internal error, or ICU data
  without the SASLprep profile (`usprep_openByType`).
- OpenSSL failures of PBKDF2, HMAC, SHA-256 and `RAND_bytes`
  (`src/sasl_scram.cpp`): only on OpenSSL's own allocation failure, an
  internal error, or a provider configuration without SHA-256 or a random
  generator.
- `TCP_NODELAY` failing (`src/net/connect.cpp`): Corosio's `set_option`
  returns `setsockopt`'s error code, which on a connected TCP socket is set
  only for a kernel reason.
- Resolver failures caught in `resolve_detached` (`src/net/connect.cpp`,
  the catch-all giving `not_enough_memory`): Corosio's resolver and its
  lookup allocate with the global `operator new`, not the frame allocator
  nor `connect()`'s memory resource, and getaddrinfo's own errors arrive
  as an error code.
- `result_of`'s `logic_error` (`src/connection/operations.cpp`, "response
  without an LDAPResult"): unreachable, since the reader refuses a response
  of another operation first (tested: a SearchResultEntry answering a
  bind, in `tests/net/connection_tests.cpp`).
- A SASLprep input over 512 MiB (`src/sasl_scram.cpp`): a test would
  allocate that much.
- A protected buffer longer than its 4-byte length field
  (`src/net/sasl_layer.cpp`, `protect`): one `wrap` would have to return
  more than 4 GiB.
- The consteval `throw` of the `ldap::dn` and `ldap::rdn` literals
  (`include/jhetz/ldap/dn.hpp`): it runs only at compile time.
- `scope_name(search_scope::subordinate_subtree)` (`src/url.cpp`): `parse()`
  never produces that scope and `url` has no setter for it.
- `outcome_name`'s fallback after a switch over every enumerator
  (`src/connection/referral_chase.cpp`), for a value outside the
  enumeration: the chase records only enumerators.

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
| `ntlm_fuzz` | bytes | the MS-NLMP CHALLENGE_MESSAGE and AUTHENTICATE_MESSAGE parsers fail only with `decode_error`; accepted messages re-encode to messages that parse equal; the client's TargetInfo built from a CHALLENGE_MESSAGE's AV_PAIRs parses back with one MsvAvFlags (MIC bit set) and one MsvAvChannelBindings; a security layer's protected buffer is refused only with `decode_error`, an accepted one's signature re-encodes to its first 16 octets; RC4 applied twice is the identity |
| `ntlm_layer_fuzz` (needs `JHETZ_LDAP_BUILD_NET`) | bytes (a protected buffer, and a message) | for integrity and confidentiality: the client layer's `unwrap()` of the input fails only with `decode_error` or `unexpected_response` and leaves `out` unchanged, and accepts only a genuine server buffer (a fresh server layer wraps the plaintext back into the input); the input wrapped by the client and unwrapped by a server layer (the keys swapped), then back, round-trips twice (sequence numbers 0 and 1), appending to `out`; a wrapped buffer with one bit flipped is refused, `out` unchanged |

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

A fuzz build leaves `JHETZ_LDAP_BUILD_NET` off by default: the fuzzers then
cover the codec and URLs. `ntlm_layer_fuzz` needs OpenSSL's HMAC-MD5 from
`jhetz::ldap_net`, so it is built only with `-DJHETZ_LDAP_BUILD_NET=ON`
(which fetches Corosio and Capy); its `ntlm_layer_fuzz_replay` is built
with the net tests.

Without libFuzzer, the `<target>_replay` tests (part of `ctest`) run the same
entry points on deterministic generated and mutated inputs (about 300,000 for
`ber_fuzz`, 200,000 for `message_fuzz` and `url_fuzz`, 150,000 for `dn_fuzz`,
45,000 for the slower `filter_fuzz`, and 12,000 for `ntlm_layer_fuzz`, whose
inputs each take about twenty HMAC-MD5s and RC4 key schedules).

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

`bench/connection_bench.cpp` (built when `JHETZ_LDAP_BUILD_NET` is on too)
sends CompareRequests over a Unix socket pair to an in-process server that
answers each at once, on an io_context run by one thread: one after
another from a task of the io_context's executor, the same from a task of
`connection::executor()`, and from 64 tasks at once. It prints the time
per operation (best and median of 9 runs of 20,000).

```sh
cmake -B build/bench -G Ninja -DCMAKE_BUILD_TYPE=Release \
      -DJHETZ_LDAP_BUILD_BENCH=ON -DJHETZ_LDAP_BUILD_TESTS=OFF
cmake --build build/bench && build/bench/jhetz_ldap_connection_bench
```

The connection's strand (DESIGN.md section 7, "Threading"), measured
against a worktree of main built the same way (GCC 16.2, Release, same
session, two alternating invocations each, medians):

| Mode | before the strand | on the strand | |
|---|---:|---:|---:|
| sequential, from the io_context's executor | 11.2-11.4 us | 13.4-13.9 us | +19-22% |
| sequential, from `connection::executor()` | 11.2-11.3 us | 12.1-12.7 us | +8-13% |
| 64 tasks at once | 6.1 us | 7.6 us | +24-25% |

A caller off the strand pays for the two posts (onto the strand and back),
a caller on it for the strand's locking of the writer's and reader's
wake-ups only.

`bench/paged_bench.cpp` drains `ldap::search_paged` over a Unix socket
pair from an in-process server that answers each page at once (20,000
entries, pages of 1, 10 and 100), and prints the time per page and per
entry (best and median of 9 runs):

```sh
cmake --build build/bench && build/bench/jhetz_ldap_paged_bench
```

`ldap::search_paged` as a free function, which requests each page through
the same task as `connection::search_stream()` (`detail::search_stream_of`
on the connection's shared state), measured against the member it replaced
(the internal search start, no stream task, no copy of the search_params)
in a worktree of 358238e built the same way (GCC, Release, same session,
five alternating invocations each, medians; the difference is that of each
pair of invocations):

| Page size | member | free function | |
|---:|---:|---:|---:|
| 1 | 21.1-22.9 us/page | 22.4-25.4 us/page | +0.9-2.9 us (+4-13%) |
| 10 | 43.3-45.0 us/page | 45.7-48.0 us/page | +1.2-2.9 us (+3-7%) |
| 100 | 265-270 us/page | 272-274 us/page | +2.6-9.0 us (+1-3%) |

## ThreadSanitizer

`tests/net/thread_tests.cpp` (tag `[threads]`) uses one connection, one
client and one store from many tasks on an io_context run by 4 threads;
the integration test `[threads]` does the same against slapd. Run them,
and the other net tests, under TSan in a Clang build of their own
(`JHETZ_LDAP_SANITIZE` is ASan + UBSan, which TSan excludes;
`jhetz_ldap_alloc_tests`, which replaces operator new / delete as the TSan
runtime does, is left out of a `-fsanitize=thread` build):

```sh
CXX=clang++ cmake -B build/tsan -G Ninja -DCMAKE_BUILD_TYPE=Debug -DJHETZ_LDAP_WERROR=OFF \
      -DJHETZ_LDAP_BUILD_EXAMPLES=OFF \
      -DCMAKE_CXX_FLAGS='-fsanitize=thread -fno-omit-frame-pointer' -DCMAKE_EXE_LINKER_FLAGS=-fsanitize=thread
cmake --build build/tsan --target jhetz_ldap_net_tests jhetz_ldap_integration_tests
build/tsan/tests/jhetz_ldap_net_tests '[threads]'
build/tsan/tests/jhetz_ldap_net_tests '[net]'
tests/integration/run_openldap.sh build/tsan/tests/jhetz_ldap_integration_tests '[threads]'
```

## Golden vectors

`tests/message_golden_tests.cpp` compares the codec with encodings produced
by an independent implementation (ldap3 2.9.1 / pyasn1 0.6.4); the generating
script is in the file. The NTLMv2 golden NEGOTIATE, CHALLENGE and
AUTHENTICATE messages of `tests/net/sasl_ntlm_tests.cpp` come from
`tests/net/ntlm_golden.py` (written from MS-NLMP, stdlib only; run it with
`python3 -I`); the test comment lists the client choices it copies from the
library. Its second part gives the golden security-layer exchange
(signing, sealing and key exchange over plain ldap://, a fixed
ExportedSessionKey) and three protected buffers, both directions, of
"a golden security layer from an independent implementation"; the script
also asserts MS-NLMP 4.2.4.4's sealed buffer and an RFC 6229 RC4 vector.
