# jhetz::ldap - C++23 LDAP client library (work in progress).
#
#   cmake -S ldap -B build/ldap -G Ninja -DCMAKE_BUILD_TYPE=Debug
#   cmake --build build/ldap
#   ctest --test-dir build/ldap --output-on-failure
#
# See README.md for sanitizer and fuzzer builds.
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
option(JHETZ_LDAP_WERROR "Treat warnings in jhetz::ldap code as errors" OFF)
option(JHETZ_LDAP_BUILD_BENCH "Build the benchmarks (bench/, not run by ctest)" OFF)
option(JHETZ_LDAP_BUILD_EXAMPLES "Build the examples (examples/; need JHETZ_LDAP_BUILD_NET)" ON)
option(JHETZ_LDAP_INSTALL "Generate install rules and the jhetz_ldap CMake package" ${PROJECT_IS_TOP_LEVEL})

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
# No C++20 modules here or in Capy/Corosio. CMake 3.28+ with Ninja scans every
# C++20 source for them by default, and GCC 16's scanner (-fdeps-format=p1689r5)
# crashes on Corosio's uring_scheduler.hpp. Set before FetchContent so the
# dependencies inherit it.
set(CMAKE_CXX_SCAN_FOR_MODULES OFF)

# Global flags: set before any dependency is fetched so Catch2 is built the
# same way (mixing sanitized and unsanitized code causes false positives).
if(JHETZ_LDAP_SANITIZE)
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

# Clang 18 reports __cpp_concepts < 202002L, so libstdc++ 13 hides
# std::expected. Clang 18 does implement what <expected> needs, so our targets
# claim the value libstdc++ checks for. It is attached to jhetz_ldap as a
# PUBLIC option below (so everything including our headers gets it), not set
# globally: Corosio, Capy and Catch2 do not use <expected> and are compiled
# unchanged. Only needed for the Clang (fuzz) build; DESIGN.md section 9 lists
# Clang 19+ as the supported Clang.
# Side effect: libstdc++ also keys other features on __cpp_concepts (e.g. the
# conditionally trivial special members of std::variant / std::optional), so
# our translation units and Corosio's see those class templates configured
# differently: in principle an ODR mismatch where such a type crosses into
# Corosio code compiled without the define. In practice the Clang 18 build
# with jhetz::ldap_net passes the whole test suite; supported compilers
# (GCC 13+, Clang 19+) never take this branch.

set(jhetz_ldap_clang18_expected_workaround OFF)
if(CMAKE_CXX_COMPILER_ID STREQUAL "Clang" AND CMAKE_CXX_COMPILER_VERSION VERSION_LESS 19)
    set(jhetz_ldap_clang18_expected_workaround ON)
endif()

if(JHETZ_LDAP_BUILD_FUZZERS)
    if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
        message(FATAL_ERROR "JHETZ_LDAP_BUILD_FUZZERS requires Clang (libFuzzer)")
    endif()
    # Coverage instrumentation for all code; only fuzz executables link the
    # libFuzzer main (-fsanitize=fuzzer below).
    # -fno-sanitize-recover=all: UBSan findings are reported as crashes.
    add_compile_options(-fsanitize=fuzzer-no-link,address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer)
    add_link_options(-fsanitize=address,undefined -fno-sanitize-recover=all)
endif()

# Warnings apply to our own targets only.
# Clang 21+ counts __COUNTER__ (used by Catch2's macros, expanded in our
# test sources) as a C2y extension under -Wpedantic.
include(CheckCXXCompilerFlag)
check_cxx_compiler_flag(-Wno-c2y-extensions JHETZ_LDAP_HAS_WNO_C2Y_EXTENSIONS)

function(jhetz_ldap_warnings target)
    if(MSVC)
        target_compile_options(${target} PRIVATE /W4 $<$<BOOL:${JHETZ_LDAP_WERROR}>:/WX>)
    else()
        target_compile_options(${target} PRIVATE
            -Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion -Wshadow
            $<$<BOOL:${JHETZ_LDAP_HAS_WNO_C2Y_EXTENSIONS}>:-Wno-c2y-extensions>
            $<$<BOOL:${JHETZ_LDAP_WERROR}>:-Werror>)
    endif()
endfunction()

add_library(jhetz_ldap STATIC
    src/attribute.cpp
    src/ber.cpp
    src/controls.cpp
    src/dn.cpp
    src/entry.cpp
    src/error.cpp
    src/filter.cpp
    src/mapping.cpp
    src/schema.cpp
    src/message.cpp
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
if(jhetz_ldap_clang18_expected_workaround)
    target_compile_options(jhetz_ldap PUBLIC -D__cpp_concepts=202002L -Wno-builtin-macro-redefined)
endif()
jhetz_ldap_warnings(jhetz_ldap)

if(JHETZ_LDAP_BUILD_NET)
    include(FetchContent)
    # Installed packages (boost_capy, boost_corosio on CMAKE_PREFIX_PATH)
    # are used when found; otherwise the same pinned commits as
    # examples/corosio are fetched. Local checkouts can be used with
    # -DFETCHCONTENT_SOURCE_DIR_CAPY=... -DFETCHCONTENT_SOURCE_DIR_COROSIO=...
    # SYSTEM: our warning flags must not fire on their headers.
    FetchContent_Declare(capy
        GIT_REPOSITORY https://github.com/cppalliance/capy.git
        GIT_TAG a372a6b054261f29497ac0d19c2a9533f9eaad40
        SYSTEM
        FIND_PACKAGE_ARGS NAMES boost_capy CONFIG
    )
    FetchContent_Declare(corosio
        GIT_REPOSITORY https://github.com/cppalliance/corosio.git
        GIT_TAG 54e28fd40cf7ee6cc18365dd81ad5615c38908cc
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
    # Capy always adds its own test-suite libraries; nothing here uses them.
    foreach(target boost_capy_test_suite boost_capy_test_suite_main)
        if(TARGET ${target})
            set_target_properties(${target} PROPERTIES EXCLUDE_FROM_ALL ON)
        endif()
    endforeach()
    if(NOT TARGET Boost::corosio_openssl)
        message(FATAL_ERROR "jhetz::ldap_net needs OpenSSL (e.g. apt install libssl-dev), "
            "or configure with -DJHETZ_LDAP_BUILD_NET=OFF")
    endif()

    add_library(jhetz_ldap_net STATIC
        src/connection.cpp
        src/sasl_scram.cpp
        src/sync.cpp
        src/net/connect.cpp
        src/net/message_io.cpp
        src/net/tls.cpp
        src/net/transport.cpp
    )
    add_library(jhetz::ldap_net ALIAS jhetz_ldap_net)
    set_target_properties(jhetz_ldap_net PROPERTIES EXPORT_NAME ldap_net)
    target_link_libraries(jhetz_ldap_net PUBLIC jhetz_ldap Boost::corosio Boost::corosio_openssl)
    jhetz_ldap_warnings(jhetz_ldap_net)
endif()

if(JHETZ_LDAP_BUILD_EXAMPLES AND JHETZ_LDAP_BUILD_NET)
    add_executable(jhetz_ldapsearch examples/ldapsearch.cpp)
    set_target_properties(jhetz_ldapsearch PROPERTIES OUTPUT_NAME jhetz-ldapsearch)
    target_link_libraries(jhetz_ldapsearch PRIVATE jhetz::ldap_net)
    jhetz_ldap_warnings(jhetz_ldapsearch)

    # Small programs showing the main use cases (README.md, "Examples").
    foreach(example connect search modify add delete starttls blocking)
        add_executable(jhetz_ldap_example_${example} examples/${example}.cpp)
        target_link_libraries(jhetz_ldap_example_${example} PRIVATE jhetz::ldap_net)
        jhetz_ldap_warnings(jhetz_ldap_example_${example})
    endforeach()
endif()

# cmake --install: headers, libraries and the jhetz_ldap package, so
# consumers can find_package(jhetz_ldap) and link jhetz::ldap (codec) and
# jhetz::ldap_net (connection, TLS). jhetz::ldap_net needs Corosio and Capy
# as installed packages (CMAKE_PREFIX_PATH): a fetched Corosio does not
# export its targets, so it cannot be referenced from our export set.
if(JHETZ_LDAP_INSTALL)
    include(CMakePackageConfigHelpers)
    set(jhetz_ldap_install_targets jhetz_ldap)
    set(JHETZ_LDAP_PACKAGE_NET OFF)
    if(JHETZ_LDAP_BUILD_NET)
        get_target_property(jhetz_ldap_corosio_imported Boost::corosio IMPORTED)
        if(jhetz_ldap_corosio_imported)
            list(APPEND jhetz_ldap_install_targets jhetz_ldap_net)
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
    if(JHETZ_LDAP_PACKAGE_NET)
        install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
    else()
        # Without jhetz::ldap_net, its headers (they need Corosio, or their
        # implementation is in jhetz::ldap_net) are left out.
        install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
            PATTERN "net" EXCLUDE
            PATTERN "connection.hpp" EXCLUDE
            PATTERN "sasl_scram.hpp" EXCLUDE
            PATTERN "sync.hpp" EXCLUDE)
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

# Decode benchmark: default resource vs per-message arena (README.md has
# numbers). Build it optimized and without sanitizers.
if(JHETZ_LDAP_BUILD_BENCH)
    add_executable(jhetz_ldap_decode_bench bench/decode_bench.cpp)
    target_link_libraries(jhetz_ldap_decode_bench PRIVATE jhetz::ldap)
    jhetz_ldap_warnings(jhetz_ldap_decode_bench)
endif()
