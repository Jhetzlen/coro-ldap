# jhetz::ldap - C++23 LDAP client library (work in progress).
#
#   cmake -B build/main -G Ninja -DCMAKE_BUILD_TYPE=Debug
#   cmake --build build/main
#   ctest --test-dir build/main --output-on-failure
#
# See docs/DEVELOPMENT.md for sanitizer and fuzzer builds.
cmake_minimum_required(VERSION 3.25)

project(jhetz_ldap VERSION 0.1.0 LANGUAGES CXX)

option(JHETZ_LDAP_BUILD_TESTS "Build the jhetz::ldap unit tests" ON)
option(JHETZ_LDAP_BUILD_FUZZERS "Build the libFuzzer targets (Clang only)" OFF)
# jhetz::ldap_net needs Corosio + Capy (fetched) and OpenSSL. The fuzzers
# only exercise the codec, so a fuzz build leaves it off by default.
if(JHETZ_LDAP_BUILD_FUZZERS)
    set(jhetz_ldap_net_default OFF)
else()
    set(jhetz_ldap_net_default ON)
endif()
option(JHETZ_LDAP_BUILD_NET "Build jhetz::ldap_net (transports and connect; fetches Corosio and Capy, needs OpenSSL)"
    ${jhetz_ldap_net_default})
option(JHETZ_LDAP_SANITIZE "Build all targets with AddressSanitizer and UBSan" OFF)
# On by default for our own builds; off as a subproject (add_subdirectory,
# FetchContent) so a consumer's newer compiler is not broken by new warnings.
# Off by default on clang-cl (/W4 still shows the warnings): only MSVC itself
# has had a clean Windows build (19.44); -DJHETZ_LDAP_WERROR=ON to try it.
if(PROJECT_IS_TOP_LEVEL AND NOT (MSVC AND CMAKE_CXX_COMPILER_ID STREQUAL "Clang"))
    set(jhetz_ldap_werror_default ON)
else()
    set(jhetz_ldap_werror_default OFF)
endif()
option(JHETZ_LDAP_WERROR "Treat warnings in jhetz::ldap code as errors" ${jhetz_ldap_werror_default})
option(JHETZ_LDAP_COVERAGE "Instrument our own targets for Clang source-based coverage (llvm-cov)" OFF)
option(JHETZ_LDAP_BUILD_BENCH "Build the benchmarks (bench/, not run by ctest)" OFF)
option(JHETZ_LDAP_WITH_GSSAPI "Add SASL GSSAPI (Kerberos) to jhetz::ldap_net (needs the GSS-API library, MIT krb5's libgssapi_krb5, found with pkg-config)" OFF)
option(JHETZ_LDAP_BUILD_EXAMPLES "Build the examples (examples/; need JHETZ_LDAP_BUILD_NET)" ON)
option(JHETZ_LDAP_INSTALL "Generate install rules and the jhetz_ldap CMake package" ${PROJECT_IS_TOP_LEVEL})
option(JHETZ_LDAP_CLANG_TIDY "Run clang-tidy (.clang-tidy) on our own targets while building them" OFF)

# Minimum compilers: GCC 16, Clang 23, and libstdc++ 16 when it is the
# standard library (Clang uses the newest GCC's libstdc++ it finds; install
# g++-16 next to clang++-23, or pass --gcc-install-dir), for the C++23 library
# additions older versions lack (std::print, std::ranges::to, ...), or MSVC
# 19.40 (Visual Studio 2022 17.10). Linux is the supported platform; the
# Windows port (MSVC, clang-cl, MinGW) is code-only so far and not tested
# here. Apple Clang (macOS) is rejected.
if(CMAKE_CXX_COMPILER_ID STREQUAL "AppleClang")
    message(FATAL_ERROR "jhetz::ldap does not support Apple Clang (macOS is not a supported platform)")
endif()
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU" AND CMAKE_CXX_COMPILER_VERSION VERSION_LESS 16)
    message(FATAL_ERROR "jhetz::ldap needs GCC 16 or newer (found ${CMAKE_CXX_COMPILER_VERSION})")
endif()
if(CMAKE_CXX_COMPILER_ID STREQUAL "Clang" AND CMAKE_CXX_COMPILER_VERSION VERSION_LESS 23)
    message(FATAL_ERROR "jhetz::ldap needs Clang 23 or newer (found ${CMAKE_CXX_COMPILER_VERSION})")
endif()
# MSVC_VERSION covers clang-cl too: it uses the MSVC STL of the toolset it
# emulates, and reports that toolset's version.
if(MSVC AND MSVC_VERSION LESS 1940)
    message(FATAL_ERROR "jhetz::ldap needs MSVC 19.40 (Visual Studio 2022 17.10) or newer, or clang-cl on "
        "that toolset (found MSVC_VERSION ${MSVC_VERSION})")
endif()
include(CheckCXXSourceCompiles)
# Re-run the probe on every configure: a cached failure would otherwise keep
# failing after the user installs a newer libstdc++ or changes the flags.
unset(JHETZ_LDAP_STDLIB_RECENT_ENOUGH CACHE)
check_cxx_source_compiles([=[
#include <version>
#if defined(_GLIBCXX_RELEASE) && _GLIBCXX_RELEASE < 16
#error libstdc++ older than 16
#endif
int main() {}
]=] JHETZ_LDAP_STDLIB_RECENT_ENOUGH)
if(NOT JHETZ_LDAP_STDLIB_RECENT_ENOUGH)
    message(FATAL_ERROR "jhetz::ldap needs libstdc++ 16 or newer: install g++-16 (Clang picks the newest "
        "GCC installation's libstdc++) or point Clang at it with --gcc-install-dir")
endif()

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
# No C++20 modules here or in Capy/Corosio. CMake 3.28+ with Ninja scans every
# C++20 source for them by default, and GCC 16 (still 16.2) crashes compiling
# Corosio's uring_scheduler.hpp in module mode (-fmodules). Set before
# FetchContent so the dependencies inherit it.
set(CMAKE_CXX_SCAN_FOR_MODULES OFF)

# Global flags: set before any dependency is fetched so Catch2 is built the
# same way (mixing sanitized and unsanitized code causes false positives).
if(JHETZ_LDAP_SANITIZE)
    if(MINGW)
        message(FATAL_ERROR "JHETZ_LDAP_SANITIZE is not supported with MinGW (no AddressSanitizer runtime); "
            "use MSVC or clang-cl")
    endif()
    if(MSVC)
        # /fsanitize=address is incompatible with the /RTC1 runtime checks
        # CMake puts in the default Debug flags (error D8016), so drop them.
        foreach(var CMAKE_CXX_FLAGS CMAKE_CXX_FLAGS_DEBUG CMAKE_CXX_FLAGS_RELWITHDEBINFO)
            string(REGEX REPLACE "/RTC[1csu]+" "" ${var} "${${var}}")
        endforeach()
        add_compile_options(/fsanitize=address)
    else()
        # -fno-sanitize-recover=all: UBSan findings abort the process instead
        # of printing and continuing, so they fail tests.
        add_compile_options(-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer)
        add_link_options(-fsanitize=address,undefined -fno-sanitize-recover=all)
    endif()
endif()

if(JHETZ_LDAP_BUILD_FUZZERS)
    # clang-cl reports Clang, but the -fsanitize flags below are GCC-style.
    if(WIN32)
        message(FATAL_ERROR "JHETZ_LDAP_BUILD_FUZZERS is not supported on Windows (fuzz on Linux)")
    endif()
    if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
        message(FATAL_ERROR "JHETZ_LDAP_BUILD_FUZZERS requires Clang (libFuzzer)")
    endif()
    # Coverage instrumentation for all code; only fuzz executables link the
    # libFuzzer main (-fsanitize=fuzzer below).
    # -fno-sanitize-recover=all: UBSan findings are reported as crashes.
    add_compile_options(-fsanitize=fuzzer-no-link,address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer)
    add_link_options(-fsanitize=address,undefined -fno-sanitize-recover=all)
endif()

# Coverage (tests/coverage/run_coverage.sh): Clang source-based coverage
# on our own targets only, through jhetz_ldap_warnings below, so Corosio,
# Capy and Catch2 are not instrumented. -O0 so regions and branches map to
# the source as written.
if(JHETZ_LDAP_COVERAGE)
    if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang" OR MSVC)
        message(FATAL_ERROR "JHETZ_LDAP_COVERAGE needs Clang (-fprofile-instr-generate, llvm-cov)")
    endif()
    if(JHETZ_LDAP_SANITIZE OR JHETZ_LDAP_BUILD_FUZZERS)
        message(WARNING "JHETZ_LDAP_COVERAGE is meant for a plain build: turn JHETZ_LDAP_SANITIZE "
            "and JHETZ_LDAP_BUILD_FUZZERS off")
    endif()
endif()

# clang-tidy (JHETZ_LDAP_CLANG_TIDY): CXX_CLANG_TIDY on our own targets only,
# through jhetz_ldap_warnings below, so Corosio, Capy and Catch2 are never
# checked; the checks and the header filter (include/jhetz/ and src/) are in
# .clang-tidy. compile_commands.json is exported by default for a standalone
# run-clang-tidy and clangd (CMake creates the cache entry empty, so an
# explicit -DCMAKE_EXPORT_COMPILE_COMMANDS=OFF still wins).
if(PROJECT_IS_TOP_LEVEL AND "${CMAKE_EXPORT_COMPILE_COMMANDS}" STREQUAL "")
    set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
endif()
if(JHETZ_LDAP_CLANG_TIDY)
    find_program(JHETZ_LDAP_CLANG_TIDY_EXE NAMES clang-tidy-23 clang-tidy REQUIRED)
endif()

# Warnings (and coverage instrumentation) apply to our own targets only, and
# so do the Windows settings: UTF-8 sources and execution charset (/utf-8:
# the sources and tests hold UTF-8 literals), big object files (Corosio's
# templates exceed the default section count), no CRT "deprecated" warnings
# for the standard C functions (getenv, ...), and a lean <windows.h> without
# the min/max macros for anything that pulls in Winsock.
# Clang counts __COUNTER__ (used by Catch2's macros, expanded in our test
# sources) as a C2y extension under -Wpedantic. Clang only: GCC has no such
# warning (it accepts the unknown -Wno- flag, then notes it next to any other
# warning).

function(jhetz_ldap_warnings target)
    if(JHETZ_LDAP_CLANG_TIDY)
        set_target_properties(${target} PROPERTIES CXX_CLANG_TIDY "${JHETZ_LDAP_CLANG_TIDY_EXE}")
    endif()
    if(WIN32)
        target_compile_definitions(${target} PRIVATE _CRT_SECURE_NO_WARNINGS NOMINMAX WIN32_LEAN_AND_MEAN)
    endif()
    if(MSVC)
        target_compile_options(${target} PRIVATE /W4 /utf-8 /bigobj $<$<BOOL:${JHETZ_LDAP_WERROR}>:/WX>)
    else()
        if(MINGW)
            target_compile_options(${target} PRIVATE -Wa,-mbig-obj)
        endif()
        target_compile_options(${target} PRIVATE
            -Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion -Wshadow
            $<$<CXX_COMPILER_ID:Clang>:-Wno-c2y-extensions>
            $<$<BOOL:${JHETZ_LDAP_WERROR}>:-Werror>)
        if(JHETZ_LDAP_COVERAGE)
            target_compile_options(${target} PRIVATE -fprofile-instr-generate -fcoverage-mapping -O0 -g)
            target_link_options(${target} PRIVATE -fprofile-instr-generate)
        endif()
    endif()
endfunction()

# ICU is the Unicode dependency (DESIGN.md decision 6), of the codec too:
# UTF-8 decoding, character properties and LDAPprep for the matching
# rules (RFC 4518, usprep) in jhetz::ldap, SASLprep for SCRAM (usprep) in
# jhetz::ldap_net. `data` too, for a static ICU (libicuuc.so
# already pulls in libicudata). ICU 60+: U8_NEXT's maximal-subpart
# behaviour (Unicode section 3.9) dates from ICU 60.
find_package(ICU 60 COMPONENTS uc data)
if(NOT ICU_FOUND)
    message(FATAL_ERROR "jhetz::ldap needs ICU 60+ (e.g. apt install libicu-dev; on Windows "
        "vcpkg install icu and configure with -DCMAKE_TOOLCHAIN_FILE=<vcpkg>/scripts/buildsystems/vcpkg.cmake)")
endif()

add_library(jhetz_ldap STATIC
    src/ad/diagnostic.cpp
    src/ad/guid.cpp
    src/ad/password_value.cpp
    src/ad/sid.cpp
    src/attribute.cpp
    src/ber.cpp
    src/content_sync.cpp
    src/controls.cpp
    src/dn.cpp
    src/entry.cpp
    src/error.cpp
    src/filter.cpp
    src/format_util.cpp
    src/mapping.cpp
    src/matching.cpp
    src/ntlm_message.cpp
    src/schema.cpp
    src/message.cpp
    src/operations.cpp
    src/referral.cpp
    src/url.cpp
)
add_library(jhetz::ldap ALIAS jhetz_ldap)
include(GNUInstallDirs)
target_include_directories(jhetz_ldap PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)
set_target_properties(jhetz_ldap PROPERTIES EXPORT_NAME ldap)
target_compile_features(jhetz_ldap PUBLIC cxx_std_23)
# PRIVATE: the public headers do not include ICU's.
target_link_libraries(jhetz_ldap PRIVATE ICU::uc ICU::data)
jhetz_ldap_warnings(jhetz_ldap)

if(JHETZ_LDAP_BUILD_NET)
    include(FetchContent)
    # Installed packages (boost_capy, boost_corosio on CMAKE_PREFIX_PATH)
    # are used when found; otherwise these pinned commits are fetched.
    # Local checkouts can be used with
    # -DFETCHCONTENT_SOURCE_DIR_CAPY=... -DFETCHCONTENT_SOURCE_DIR_COROSIO=...
    # SYSTEM: our warning flags must not fire on their headers.
    FetchContent_Declare(capy
        GIT_REPOSITORY https://github.com/cppalliance/capy.git
        GIT_TAG bdadc6adef8c8eb79da6454373175bb1428be524
        SYSTEM
        FIND_PACKAGE_ARGS NAMES boost_capy CONFIG
    )
    FetchContent_Declare(corosio
        GIT_REPOSITORY https://github.com/cppalliance/corosio.git
        GIT_TAG fd8e95a7125047d5385068a4c640da8232b9588e
        SYSTEM
        FIND_PACKAGE_ARGS NAMES boost_corosio CONFIG
    )
    # Not their tests, examples or benchmarks (normal variables: both
    # projects' option() calls honour them, policy CMP0077).
    foreach(var BOOST_CAPY_BUILD_TESTS BOOST_CAPY_BUILD_EXAMPLES BOOST_CAPY_BUILD_BENCH
            BOOST_COROSIO_BUILD_TESTS BOOST_COROSIO_BUILD_EXAMPLES BOOST_COROSIO_BUILD_BENCH)
        set(${var} OFF)
    endforeach()
    FetchContent_MakeAvailable(capy corosio)
    # Fetched (not found as packages): build only the targets we link (Capy
    # always adds its test-suite libraries, unused here), and leave their
    # install rules out of ours, so cmake --install installs jhetz_ldap
    # alone (CMake skips EXCLUDE_FROM_ALL directories' install scripts).
    # FetchContent_Declare(EXCLUDE_FROM_ALL) would need CMake 3.28. Only
    # directories added here: a parent project that made Capy or Corosio
    # available itself (our MakeAvailable then does nothing, but
    # <dep>_SOURCE_DIR is set) keeps its own settings for them.
    get_property(jhetz_ldap_subdirs DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR} PROPERTY SUBDIRECTORIES)
    foreach(dep capy corosio)
        if(DEFINED ${dep}_SOURCE_DIR)
            cmake_path(ABSOLUTE_PATH ${dep}_SOURCE_DIR NORMALIZE OUTPUT_VARIABLE dep_dir)
            if(dep_dir IN_LIST jhetz_ldap_subdirs)
                set_property(DIRECTORY ${dep_dir} PROPERTY EXCLUDE_FROM_ALL ON)
            endif()
        endif()
    endforeach()
    if(NOT TARGET Boost::corosio_openssl)
        message(FATAL_ERROR "jhetz::ldap_net needs OpenSSL (e.g. apt install libssl-dev; on Windows "
            "vcpkg install openssl with the vcpkg toolchain file), or configure with -DJHETZ_LDAP_BUILD_NET=OFF")
    endif()
    add_library(jhetz_ldap_net STATIC
        src/connection/connection.cpp
        src/connection/start_tls.cpp
        src/connection/bind.cpp
        src/connection/core.cpp
        src/connection/sasl_offload.cpp
        src/connection/search.cpp
        src/connection/paged_search.cpp
        src/connection/operations.cpp
        src/connection/password.cpp
        src/connection/transaction.cpp
        src/connection/referral_chase.cpp
        src/connection/same_policy_connector.cpp
        src/directory.cpp
        src/client/client.cpp
        src/sasl_ntlm.cpp
        src/sasl_scram.cpp
        src/sync.cpp
        src/net/connect.cpp
        src/net/host_name.cpp
        src/net/message_io.cpp
        src/net/sasl_layer.cpp
        src/net/channel_binding.cpp
        src/net/tls.cpp
        src/net/transport.cpp
        src/net/trust_store.cpp
    )
    # Default verification's trust anchors (src/net/trust_store.hpp): the
    # CryptoAPI ROOT store and chain verification on Windows, OpenSSL's
    # default paths elsewhere.
    if(WIN32)
        target_sources(jhetz_ldap_net PRIVATE src/net/trust_store_win.cpp)
        # CERT_CHAIN_PARA's dwUrlRetrievalTimeout (verify_system_chain).
        set_source_files_properties(src/net/trust_store_win.cpp PROPERTIES
            COMPILE_DEFINITIONS CERT_CHAIN_PARA_HAS_EXTRA_FIELDS)
        target_link_libraries(jhetz_ldap_net PRIVATE crypt32)
    else()
        target_sources(jhetz_ldap_net PRIVATE src/net/trust_store_default.cpp)
    endif()
    add_library(jhetz::ldap_net ALIAS jhetz_ldap_net)
    set_target_properties(jhetz_ldap_net PROPERTIES EXPORT_NAME ldap_net)
    target_link_libraries(jhetz_ldap_net PUBLIC jhetz_ldap Boost::corosio Boost::corosio_openssl
        PRIVATE ICU::uc ICU::data)
    jhetz_ldap_warnings(jhetz_ldap_net)
    # SASL GSSAPI (sasl_gssapi.hpp), optional: the GSS-API library is found
    # with pkg-config (MIT krb5's krb5-gssapi; Heimdal's heimdal-gssapi
    # should work too, untested). The installed package config finds it
    # the same way.
    if(JHETZ_LDAP_WITH_GSSAPI)
        if(WIN32)
            message(FATAL_ERROR "JHETZ_LDAP_WITH_GSSAPI is not supported on Windows (SSPI is not implemented)")
        endif()
        find_package(PkgConfig)
        if(PkgConfig_FOUND)
            pkg_search_module(JHETZ_LDAP_GSSAPI IMPORTED_TARGET krb5-gssapi heimdal-gssapi)
        endif()
        if(NOT TARGET PkgConfig::JHETZ_LDAP_GSSAPI)
            message(FATAL_ERROR "JHETZ_LDAP_WITH_GSSAPI needs the GSS-API library and pkg-config "
                "(e.g. apt install libkrb5-dev pkg-config), or configure with -DJHETZ_LDAP_WITH_GSSAPI=OFF")
        endif()
        target_sources(jhetz_ldap_net PRIVATE src/sasl_gssapi.cpp)
        target_link_libraries(jhetz_ldap_net PRIVATE PkgConfig::JHETZ_LDAP_GSSAPI)
    endif()
elseif(JHETZ_LDAP_WITH_GSSAPI)
    message(FATAL_ERROR "JHETZ_LDAP_WITH_GSSAPI needs JHETZ_LDAP_BUILD_NET")
endif()

# jhetz::ldap_ad: the Active Directory operations that need the network
# (DESIGN.md, "Active Directory layer"), built on jhetz::ldap_net's public
# API only. Its codec-level headers (include/jhetz/ldap/ad/, sources in
# src/ad/) are in jhetz::ldap.
if(JHETZ_LDAP_BUILD_NET)
    add_library(jhetz_ldap_ad STATIC
        src/ad/password.cpp
    )
    add_library(jhetz::ldap_ad ALIAS jhetz_ldap_ad)
    set_target_properties(jhetz_ldap_ad PROPERTIES EXPORT_NAME ldap_ad)
    target_link_libraries(jhetz_ldap_ad PUBLIC jhetz_ldap_net)
    jhetz_ldap_warnings(jhetz_ldap_ad)
endif()

if(JHETZ_LDAP_BUILD_EXAMPLES AND JHETZ_LDAP_BUILD_NET)
    add_executable(jhetz_ldapsearch examples/ldapsearch.cpp)
    set_target_properties(jhetz_ldapsearch PROPERTIES OUTPUT_NAME jhetz-ldapsearch)
    target_link_libraries(jhetz_ldapsearch PRIVATE jhetz::ldap_net)
    jhetz_ldap_warnings(jhetz_ldapsearch)

    # Small programs showing the main use cases (docs/DEVELOPMENT.md, "Examples").
    set(jhetz_ldap_examples connect search pool modify add delete move password starttls cancel blocking blocking_pool bulk paged syncrepl typed_crud referrals ntlm)
    if(JHETZ_LDAP_WITH_GSSAPI)
        list(APPEND jhetz_ldap_examples gssapi)
    endif()
    foreach(example ${jhetz_ldap_examples})
        add_executable(jhetz_ldap_example_${example} examples/${example}.cpp)
        target_link_libraries(jhetz_ldap_example_${example} PRIVATE jhetz::ldap_net)
        jhetz_ldap_warnings(jhetz_ldap_example_${example})
    endforeach()
endif()

# cmake --install: headers, libraries and the jhetz_ldap package, so
# consumers can find_package(jhetz_ldap) and link jhetz::ldap (codec),
# jhetz::ldap_net (connection, TLS) and jhetz::ldap_ad (Active Directory).
# jhetz::ldap_net and jhetz::ldap_ad need Corosio and Capy
# as installed packages (CMAKE_PREFIX_PATH): a fetched Corosio does not
# export its targets, so it cannot be referenced from our export set.
if(JHETZ_LDAP_INSTALL)
    include(CMakePackageConfigHelpers)
    set(jhetz_ldap_install_targets jhetz_ldap)
    set(JHETZ_LDAP_PACKAGE_NET OFF)
    if(JHETZ_LDAP_BUILD_NET)
        get_target_property(jhetz_ldap_corosio_imported Boost::corosio IMPORTED)
        if(jhetz_ldap_corosio_imported)
            list(APPEND jhetz_ldap_install_targets jhetz_ldap_net jhetz_ldap_ad)
            set(JHETZ_LDAP_PACKAGE_NET ON)
        else()
            message(STATUS "jhetz_ldap: jhetz::ldap_net is not installed: Corosio was fetched, not found "
                "as a package (install Capy and Corosio and add their prefix to CMAKE_PREFIX_PATH)")
        endif()
    endif()
    set(jhetz_ldap_cmakedir ${CMAKE_INSTALL_LIBDIR}/cmake/jhetz_ldap)
    install(TARGETS ${jhetz_ldap_install_targets}
        EXPORT jhetz_ldap-targets
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
    set(JHETZ_LDAP_PACKAGE_GSSAPI OFF)
    if(JHETZ_LDAP_PACKAGE_NET AND JHETZ_LDAP_WITH_GSSAPI)
        set(JHETZ_LDAP_PACKAGE_GSSAPI ON)
        install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
    elseif(JHETZ_LDAP_PACKAGE_NET)
        install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
            PATTERN "sasl_gssapi.hpp" EXCLUDE)
    else()
        # Without jhetz::ldap_net, its headers (they need Corosio, or their
        # implementation is in jhetz::ldap_net) are left out. Keep this list
        # in step with jhetz_ldap_net_headers in tests/CMakeLists.txt and the
        # absence check in tests/install/check_install.sh.
        install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
            PATTERN "net" EXCLUDE
            PATTERN "cancel.hpp" EXCLUDE
            PATTERN "client.hpp" EXCLUDE
            PATTERN "connection.hpp" EXCLUDE
            PATTERN "connection_options.hpp" EXCLUDE
            PATTERN "directory.hpp" EXCLUDE
            PATTERN "paged_search.hpp" EXCLUDE
            PATTERN "referral_chase.hpp" EXCLUDE
            PATTERN "search_stream.hpp" EXCLUDE
            PATTERN "store.hpp" EXCLUDE
            PATTERN "transaction.hpp" EXCLUDE
            PATTERN "sasl_ntlm.hpp" EXCLUDE
            PATTERN "sasl_scram.hpp" EXCLUDE
            PATTERN "sasl_gssapi.hpp" EXCLUDE
            PATTERN "sync.hpp" EXCLUDE
            PATTERN "sync_store.hpp" EXCLUDE
            PATTERN "password.hpp" EXCLUDE)
    endif()
    install(EXPORT jhetz_ldap-targets NAMESPACE jhetz:: DESTINATION ${jhetz_ldap_cmakedir})
    configure_package_config_file(cmake/jhetz_ldap-config.cmake.in
        ${CMAKE_CURRENT_BINARY_DIR}/jhetz_ldap-config.cmake
        INSTALL_DESTINATION ${jhetz_ldap_cmakedir})
    # 0.x: minor versions may break the API.
    write_basic_package_version_file(${CMAKE_CURRENT_BINARY_DIR}/jhetz_ldap-config-version.cmake
        COMPATIBILITY SameMinorVersion)
    install(FILES
        ${CMAKE_CURRENT_BINARY_DIR}/jhetz_ldap-config.cmake
        ${CMAKE_CURRENT_BINARY_DIR}/jhetz_ldap-config-version.cmake
        DESTINATION ${jhetz_ldap_cmakedir})
endif()

if(JHETZ_LDAP_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

if(JHETZ_LDAP_BUILD_FUZZERS)
    add_subdirectory(fuzz)
endif()

# Decode benchmark: default resource vs per-message arena (docs/DEVELOPMENT.md has
# numbers). Build it optimized and without sanitizers.
if(JHETZ_LDAP_BUILD_BENCH)
    add_executable(jhetz_ldap_decode_bench bench/decode_bench.cpp)
    target_link_libraries(jhetz_ldap_decode_bench PRIVATE jhetz::ldap)
    jhetz_ldap_warnings(jhetz_ldap_decode_bench)
endif()
