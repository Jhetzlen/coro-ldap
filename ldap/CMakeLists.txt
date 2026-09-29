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
option(JHETZ_LDAP_SANITIZE "Build all targets with AddressSanitizer and UBSan" OFF)
option(JHETZ_LDAP_WERROR "Treat warnings in jhetz::ldap code as errors" OFF)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Global flags: set before any dependency is fetched so Catch2 is built the
# same way (mixing sanitized and unsanitized code causes false positives).
if(JHETZ_LDAP_SANITIZE)
    if(MSVC)
        add_compile_options(/fsanitize=address)
    else()
        add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer)
        add_link_options(-fsanitize=address,undefined)
    endif()
endif()

if(CMAKE_CXX_COMPILER_ID STREQUAL "Clang" AND CMAKE_CXX_COMPILER_VERSION VERSION_LESS 19)
    # Clang 18 reports __cpp_concepts < 202002L, so libstdc++ 13 hides
    # std::expected. Clang 18 does implement what <expected> needs, so we
    # claim the value libstdc++ checks for. Only needed for the Clang (fuzz)
    # build; DESIGN.md section 9 lists Clang 19+ as the supported Clang.
    add_compile_options(-D__cpp_concepts=202002L -Wno-builtin-macro-redefined)
endif()

if(JHETZ_LDAP_BUILD_FUZZERS)
    if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
        message(FATAL_ERROR "JHETZ_LDAP_BUILD_FUZZERS requires Clang (libFuzzer)")
    endif()
    # Coverage instrumentation for all code; only fuzz executables link the
    # libFuzzer main (-fsanitize=fuzzer below).
    add_compile_options(-fsanitize=fuzzer-no-link,address,undefined -fno-omit-frame-pointer)
    add_link_options(-fsanitize=address,undefined)
endif()

# Warnings apply to our own targets only.
function(jhetz_ldap_warnings target)
    if(MSVC)
        target_compile_options(${target} PRIVATE /W4 $<$<BOOL:${JHETZ_LDAP_WERROR}>:/WX>)
    else()
        target_compile_options(${target} PRIVATE
            -Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion -Wshadow
            $<$<BOOL:${JHETZ_LDAP_WERROR}>:-Werror>)
    endif()
endfunction()

add_library(jhetz_ldap STATIC
    src/ber.cpp
    src/error.cpp
)
add_library(jhetz::ldap ALIAS jhetz_ldap)
target_include_directories(jhetz_ldap PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
)
target_compile_features(jhetz_ldap PUBLIC cxx_std_23)
jhetz_ldap_warnings(jhetz_ldap)

if(JHETZ_LDAP_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

if(JHETZ_LDAP_BUILD_FUZZERS)
    add_subdirectory(fuzz)
endif()
