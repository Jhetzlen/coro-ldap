# Standalone Boost.Corosio examples (echo server + echo client).
#
# Corosio is not part of a Boost release yet, so it and its dependency
# Capy are fetched from GitHub at pinned commits.
#
#   cmake -S examples/corosio -B build/corosio -G Ninja
#   cmake --build build/corosio
#
# To build against local checkouts instead of downloading, pass
#   -DFETCHCONTENT_SOURCE_DIR_CAPY=/path/to/capy
#   -DFETCHCONTENT_SOURCE_DIR_COROSIO=/path/to/corosio
cmake_minimum_required(VERSION 3.25)

project(corosio_examples LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
# No C++20 modules here or in Capy/Corosio. CMake 3.28+ with Ninja scans every
# C++20 source for them by default, and GCC 16's scanner (-fdeps-format=p1689r5)
# crashes on Corosio's uring_scheduler.hpp. Set before FetchContent so the
# dependencies inherit it.
set(CMAKE_CXX_SCAN_FOR_MODULES OFF)

option(COROSIO_EXAMPLES_WERROR "Treat warnings in the example sources as errors" OFF)

include(FetchContent)

FetchContent_Declare(capy
    GIT_REPOSITORY https://github.com/cppalliance/capy.git
    GIT_TAG a372a6b054261f29497ac0d19c2a9533f9eaad40
    SYSTEM
)
FetchContent_Declare(corosio
    GIT_REPOSITORY https://github.com/cppalliance/corosio.git
    GIT_TAG 54e28fd40cf7ee6cc18365dd81ad5615c38908cc
    SYSTEM
)

# Not their tests, examples or benchmarks (normal variables: both projects'
# option() calls honour them, policy CMP0077). SYSTEM above: our warning
# flags must not fire on their headers.
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

# Same warning set as ldap/CMakeLists.txt, applied to our targets only.
function(corosio_example_warnings target)
    if(MSVC)
        target_compile_options(${target} PRIVATE /W4 $<$<BOOL:${COROSIO_EXAMPLES_WERROR}>:/WX>)
    else()
        target_compile_options(${target} PRIVATE
            -Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion -Wshadow
            $<$<BOOL:${COROSIO_EXAMPLES_WERROR}>:-Werror>)
    endif()
endfunction()

add_executable(corosio_echo_server echo_server.cpp)
target_link_libraries(corosio_echo_server PRIVATE Boost::corosio)

add_executable(corosio_echo_client echo_client.cpp)
target_link_libraries(corosio_echo_client PRIVATE Boost::corosio)

# sync_wait / future bridge returning std::expected (needs C++23).
add_executable(corosio_result_future result_future_example.cpp)
target_link_libraries(corosio_result_future PRIVATE Boost::corosio)
target_compile_features(corosio_result_future PRIVATE cxx_std_23)

foreach(target corosio_echo_server corosio_echo_client corosio_result_future)
    corosio_example_warnings(${target})
endforeach()
