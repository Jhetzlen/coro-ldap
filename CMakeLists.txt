# jhetz::ldap - C++23 LDAP client library. Building: docs/DEVELOPMENT.md.
cmake_minimum_required(VERSION 3.25)

project(jhetz_ldap VERSION 0.1.0 LANGUAGES CXX)

option(JHETZ_LDAP_BUILD_TESTS "Build the jhetz::ldap unit tests" ON)
option(JHETZ_LDAP_BUILD_FUZZERS "Build the libFuzzer targets (Clang only)" OFF)
# jhetz::ldap is off by default in a fuzz build (the fuzzers exercise
# the codec).
if(JHETZ_LDAP_BUILD_FUZZERS)
    set(jhetz_ldap_client_default OFF)
else()
    set(jhetz_ldap_client_default ON)
endif()
option(JHETZ_LDAP_BUILD_NET "Build jhetz::ldap (transports and connect; fetches Corosio and Capy, needs OpenSSL)"
    ${jhetz_ldap_client_default})
option(JHETZ_LDAP_SANITIZE "Build all targets with AddressSanitizer and UBSan" OFF)
# Warnings as errors for our own builds, not as a subproject nor on
# clang-cl.
if(PROJECT_IS_TOP_LEVEL AND NOT (MSVC AND CMAKE_CXX_COMPILER_ID STREQUAL "Clang"))
    set(jhetz_ldap_werror_default ON)
else()
    set(jhetz_ldap_werror_default OFF)
endif()
option(JHETZ_LDAP_WERROR "Treat warnings in jhetz::ldap code as errors" ${jhetz_ldap_werror_default})
option(JHETZ_LDAP_COVERAGE "Instrument our own targets for Clang source-based coverage (llvm-cov)" OFF)
option(JHETZ_LDAP_WITH_GSSAPI "Add SASL GSSAPI (Kerberos) to jhetz::ldap (needs the GSS-API library, MIT krb5's libgssapi_krb5, found with pkg-config)" OFF)
option(JHETZ_LDAP_BUILD_EXAMPLES "Build the examples (examples/; need JHETZ_LDAP_BUILD_NET)" ON)
option(JHETZ_LDAP_INSTALL "Generate install rules and the jhetz_ldap CMake package" ${PROJECT_IS_TOP_LEVEL})
option(JHETZ_LDAP_CLANG_TIDY "Run clang-tidy (.clang-tidy) on our own targets while building them" OFF)

# Minimum compilers: GCC 16, Clang 23 with libstdc++ 16, or MSVC 19.40;
# Apple Clang is rejected.
if(CMAKE_CXX_COMPILER_ID STREQUAL "AppleClang")
    message(FATAL_ERROR "jhetz::ldap does not support Apple Clang (macOS is not a supported platform)")
endif()
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU" AND CMAKE_CXX_COMPILER_VERSION VERSION_LESS 16)
    message(FATAL_ERROR "jhetz::ldap needs GCC 16 or newer (found ${CMAKE_CXX_COMPILER_VERSION})")
endif()
if(CMAKE_CXX_COMPILER_ID STREQUAL "Clang" AND CMAKE_CXX_COMPILER_VERSION VERSION_LESS 23)
    message(FATAL_ERROR "jhetz::ldap needs Clang 23 or newer (found ${CMAKE_CXX_COMPILER_VERSION})")
endif()
# MSVC_VERSION covers clang-cl too.
if(MSVC AND MSVC_VERSION LESS 1940)
    message(FATAL_ERROR "jhetz::ldap needs MSVC 19.40 (Visual Studio 2022 17.10) or newer, or clang-cl on "
        "that toolset (found MSVC_VERSION ${MSVC_VERSION})")
endif()
include(CheckCXXSourceCompiles)
# Re-run the probe on every configure.
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
# No C++20 modules here or in Capy / Corosio; set before FetchContent.
set(CMAKE_CXX_SCAN_FOR_MODULES OFF)

# Global flags, set before any dependency is fetched so Catch2 matches.
if(JHETZ_LDAP_SANITIZE)
    if(MINGW)
        message(FATAL_ERROR "JHETZ_LDAP_SANITIZE is not supported with MinGW (no AddressSanitizer runtime); "
            "use MSVC or clang-cl")
    endif()
    if(MSVC)
        # Drop /RTC1, which /fsanitize=address refuses (D8016).
        foreach(var CMAKE_CXX_FLAGS CMAKE_CXX_FLAGS_DEBUG CMAKE_CXX_FLAGS_RELWITHDEBINFO)
            string(REGEX REPLACE "/RTC[1csu]+" "" ${var} "${${var}}")
        endforeach()
        add_compile_options(/fsanitize=address)
    else()
        # UBSan findings abort.
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
    # Coverage instrumentation for all code; only the fuzz executables link
    # libFuzzer's main. UBSan findings abort.
    add_compile_options(-fsanitize=fuzzer-no-link,address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer)
    add_link_options(-fsanitize=address,undefined -fno-sanitize-recover=all)
endif()

# Clang source-based coverage of our own targets only, at -O0.
if(JHETZ_LDAP_COVERAGE)
    if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang" OR MSVC)
        message(FATAL_ERROR "JHETZ_LDAP_COVERAGE needs Clang (-fprofile-instr-generate, llvm-cov)")
    endif()
    if(JHETZ_LDAP_SANITIZE OR JHETZ_LDAP_BUILD_FUZZERS)
        message(WARNING "JHETZ_LDAP_COVERAGE is meant for a plain build: turn JHETZ_LDAP_SANITIZE "
            "and JHETZ_LDAP_BUILD_FUZZERS off")
    endif()
endif()

# clang-tidy on our own targets only (.clang-tidy); compile_commands.json
# exported unless set explicitly.
if(PROJECT_IS_TOP_LEVEL AND "${CMAKE_EXPORT_COMPILE_COMMANDS}" STREQUAL "")
    set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
endif()
if(JHETZ_LDAP_CLANG_TIDY)
    find_program(JHETZ_LDAP_CLANG_TIDY_EXE NAMES clang-tidy-23 clang-tidy REQUIRED)
endif()

# Our own targets' warnings, coverage and Windows settings (/utf-8,
# /bigobj, no CRT deprecation, lean <windows.h> without min/max).

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

# ICU 60+ (U8_NEXT's maximal subparts): UTF-8, character properties,
# LDAPprep and SASLprep. `data` for a static ICU.
find_package(ICU 60 COMPONENTS uc data)
if(NOT ICU_FOUND)
    message(FATAL_ERROR "jhetz::ldap needs ICU 60+ (e.g. apt install libicu-dev; on Windows "
        "vcpkg install icu and configure with -DCMAKE_TOOLCHAIN_FILE=<vcpkg>/scripts/buildsystems/vcpkg.cmake)")
endif()

add_library(jhetz_ldap_core STATIC
    src/ad/controls.cpp
    src/ad/diagnostic.cpp
    src/ad/guid.cpp
    src/ad/password_value.cpp
    src/ad/range.cpp
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
    src/idna_util.cpp
    src/mapping.cpp
    src/matching.cpp
    src/ntlm_message.cpp
    src/schema.cpp
    src/message.cpp
    src/operations.cpp
    src/referral.cpp
    src/url.cpp
)
add_library(jhetz::ldap_core ALIAS jhetz_ldap_core)
include(GNUInstallDirs)
target_include_directories(jhetz_ldap_core PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)
set_target_properties(jhetz_ldap_core PROPERTIES EXPORT_NAME ldap_core)
target_compile_features(jhetz_ldap_core PUBLIC cxx_std_23)
# PRIVATE: the public headers do not include ICU's.
target_link_libraries(jhetz_ldap_core PRIVATE ICU::uc ICU::data)
jhetz_ldap_warnings(jhetz_ldap_core)

if(JHETZ_LDAP_BUILD_NET)
    include(FetchContent)
    # Installed boost_capy / boost_corosio packages if found, else these
    # pinned commits (SYSTEM headers).
    FetchContent_Declare(capy
        GIT_REPOSITORY https://github.com/cppalliance/capy.git
        GIT_TAG 6a9569060f999453e1f7b59cc9ae31c808c0778b
        SYSTEM
        FIND_PACKAGE_ARGS NAMES boost_capy CONFIG
    )
    FetchContent_Declare(corosio
        GIT_REPOSITORY https://github.com/cppalliance/corosio.git
        GIT_TAG 2d246de82c62a62d0da9c1e4c81a1865be7f9321
        SYSTEM
        FIND_PACKAGE_ARGS NAMES boost_corosio CONFIG
    )
    # Only their libraries (normal variables: both
    # projects' option() calls honour them, policy CMP0077).
    foreach(var BOOST_CAPY_BUILD_TESTS BOOST_CAPY_BUILD_EXAMPLES BOOST_CAPY_BUILD_BENCH
            BOOST_COROSIO_BUILD_TESTS BOOST_COROSIO_BUILD_EXAMPLES BOOST_COROSIO_BUILD_BENCH)
        set(${var} OFF)
    endforeach()
    FetchContent_MakeAvailable(capy corosio)
    # Fetched dependencies: only the targets we link are built, and their
    # install rules are left out.
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
        message(FATAL_ERROR "jhetz::ldap needs OpenSSL (e.g. apt install libssl-dev; on Windows "
            "vcpkg install openssl with the vcpkg toolchain file), or configure with -DJHETZ_LDAP_BUILD_NET=OFF")
    endif()
    add_library(jhetz_ldap STATIC
        src/connection/connection.cpp
        src/connection/start_tls.cpp
        src/connection/bind.cpp
        src/connection/core.cpp
        src/connection/sasl_offload.cpp
        src/connection/search.cpp
        src/connection/paged_search.cpp
        src/connection/operations.cpp
        src/extended_operations.cpp
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
    # Default verification's trust anchors (src/net/trust_store.hpp).
    if(WIN32)
        target_sources(jhetz_ldap PRIVATE src/net/trust_store_win.cpp)
        # CERT_CHAIN_PARA's dwUrlRetrievalTimeout (verify_system_chain).
        set_source_files_properties(src/net/trust_store_win.cpp PROPERTIES
            COMPILE_DEFINITIONS CERT_CHAIN_PARA_HAS_EXTRA_FIELDS)
        target_link_libraries(jhetz_ldap PRIVATE crypt32)
    else()
        target_sources(jhetz_ldap PRIVATE src/net/trust_store_default.cpp)
    endif()
    add_library(jhetz::ldap ALIAS jhetz_ldap)
    set_target_properties(jhetz_ldap PROPERTIES EXPORT_NAME ldap)
    target_link_libraries(jhetz_ldap PUBLIC jhetz_ldap_core Boost::corosio Boost::corosio_openssl
        PRIVATE ICU::uc ICU::data)
    jhetz_ldap_warnings(jhetz_ldap)
    # SASL GSSAPI, optional: the GSS-API library through pkg-config.
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
        target_sources(jhetz_ldap PRIVATE src/sasl_gssapi.cpp)
        target_link_libraries(jhetz_ldap PRIVATE PkgConfig::JHETZ_LDAP_GSSAPI)
    endif()
elseif(JHETZ_LDAP_WITH_GSSAPI)
    message(FATAL_ERROR "JHETZ_LDAP_WITH_GSSAPI needs JHETZ_LDAP_BUILD_NET")
endif()

# jhetz::ldap_ad: the Active Directory operations over jhetz::ldap's
# public API; its codec-level headers are in jhetz::ldap_core.
if(JHETZ_LDAP_BUILD_NET)
    add_library(jhetz_ldap_ad STATIC
        src/ad/discover.cpp
        src/ad/dirsync.cpp
        src/ad/password.cpp
        src/ad/ranged_values.cpp
    )
    add_library(jhetz::ldap_ad ALIAS jhetz_ldap_ad)
    set_target_properties(jhetz_ldap_ad PROPERTIES EXPORT_NAME ldap_ad)
    # ICU for UTS #46; libresolv (dnsapi on Windows) for SRV lookups.
    target_link_libraries(jhetz_ldap_ad PUBLIC jhetz_ldap PRIVATE ICU::uc ICU::data)
    if(WIN32)
        target_link_libraries(jhetz_ldap_ad PRIVATE dnsapi)
    else()
        target_link_libraries(jhetz_ldap_ad PRIVATE resolv)
    endif()
    jhetz_ldap_warnings(jhetz_ldap_ad)
endif()

if(JHETZ_LDAP_BUILD_EXAMPLES AND JHETZ_LDAP_BUILD_NET)
    add_executable(jhetz_ldapsearch examples/ldapsearch.cpp)
    set_target_properties(jhetz_ldapsearch PROPERTIES OUTPUT_NAME jhetz-ldapsearch)
    target_link_libraries(jhetz_ldapsearch PRIVATE jhetz::ldap)
    jhetz_ldap_warnings(jhetz_ldapsearch)

    # Small programs showing the main use cases (docs/DEVELOPMENT.md, "Examples").
    set(jhetz_ldap_examples connect search pool modify add delete move password starttls cancel blocking chain sync_pool sync_repository bulk paged syncrepl repository referrals ntlm dirsync transaction update_if)
    if(JHETZ_LDAP_WITH_GSSAPI)
        list(APPEND jhetz_ldap_examples gssapi)
    endif()
    foreach(example ${jhetz_ldap_examples})
        add_executable(jhetz_ldap_example_${example} examples/${example}.cpp)
        target_link_libraries(jhetz_ldap_example_${example} PRIVATE jhetz::ldap)
        jhetz_ldap_warnings(jhetz_ldap_example_${example})
    endforeach()
    target_link_libraries(jhetz_ldap_example_dirsync PRIVATE jhetz::ldap_ad)
endif()

# cmake --install: headers, libraries and the jhetz_ldap package;
# jhetz::ldap and jhetz::ldap_ad need Corosio and Capy installed.
# The public headers (and directories) that need jhetz::ldap, under include/:
# left out of a codec-only install, and checked against jhetz::ldap by the
# tests and tests/install/check_install.sh.
set(JHETZ_LDAP_CLIENT_HEADERS
    jhetz/ldap/net
    jhetz/ldap/cancel.hpp jhetz/ldap/client.hpp jhetz/ldap/connection.hpp jhetz/ldap/connection_options.hpp
    jhetz/ldap/directory.hpp jhetz/ldap/extended_operations.hpp jhetz/ldap/paged_search.hpp
    jhetz/ldap/referral_chase.hpp jhetz/ldap/repository.hpp jhetz/ldap/run.hpp jhetz/ldap/search_stream.hpp
    jhetz/ldap/transaction.hpp jhetz/ldap/sasl_ntlm.hpp jhetz/ldap/sasl_scram.hpp jhetz/ldap/sasl_gssapi.hpp
    jhetz/ldap/sync.hpp jhetz/ldap/sync_extended_operations.hpp jhetz/ldap/sync_repository.hpp
    jhetz/ldap/ad/dirsync.hpp jhetz/ldap/ad/discover.hpp jhetz/ldap/ad/password.hpp
    jhetz/ldap/ad/ranged_values.hpp jhetz/ldap/ad/sync.hpp)
string(REPLACE ";" "\n" jhetz_ldap_client_header_lines "${JHETZ_LDAP_CLIENT_HEADERS}")
file(CONFIGURE OUTPUT ${PROJECT_BINARY_DIR}/jhetz_ldap_client_headers.txt
    CONTENT "${jhetz_ldap_client_header_lines}\n")

if(JHETZ_LDAP_INSTALL)
    include(CMakePackageConfigHelpers)
    set(jhetz_ldap_install_targets jhetz_ldap_core)
    set(JHETZ_LDAP_PACKAGE_NET OFF)
    if(JHETZ_LDAP_BUILD_NET)
        get_target_property(jhetz_ldap_corosio_imported Boost::corosio IMPORTED)
        if(jhetz_ldap_corosio_imported)
            list(APPEND jhetz_ldap_install_targets jhetz_ldap jhetz_ldap_ad)
            set(JHETZ_LDAP_PACKAGE_NET ON)
        else()
            message(STATUS "jhetz_ldap: jhetz::ldap is not installed: Corosio was fetched, not found "
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
        set(jhetz_ldap_client_excludes)
        foreach(header ${JHETZ_LDAP_CLIENT_HEADERS})
            string(REPLACE "." "\\." header_regex ${header})
            list(APPEND jhetz_ldap_client_excludes REGEX "/include/${header_regex}$" EXCLUDE)
        endforeach()
        install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR} ${jhetz_ldap_client_excludes})
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

# The server-side codec (testing/), not installed.
if(JHETZ_LDAP_BUILD_TESTS OR JHETZ_LDAP_BUILD_FUZZERS)
    add_subdirectory(testing)
endif()

if(JHETZ_LDAP_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

if(JHETZ_LDAP_BUILD_FUZZERS)
    add_subdirectory(fuzz)
endif()
