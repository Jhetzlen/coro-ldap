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

include(FetchContent)

FetchContent_Declare(capy
    GIT_REPOSITORY https://github.com/cppalliance/capy.git
    GIT_TAG a372a6b054261f29497ac0d19c2a9533f9eaad40
)
FetchContent_Declare(corosio
    GIT_REPOSITORY https://github.com/cppalliance/corosio.git
    GIT_TAG 54e28fd40cf7ee6cc18365dd81ad5615c38908cc
)

# Don't build the libraries' own tests/examples/benchmarks.
set(BOOST_CAPY_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(BOOST_CAPY_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(BOOST_CAPY_BUILD_BENCH OFF CACHE BOOL "" FORCE)
set(BOOST_COROSIO_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(BOOST_COROSIO_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(BOOST_COROSIO_BUILD_BENCH OFF CACHE BOOL "" FORCE)

FetchContent_MakeAvailable(capy corosio)

add_executable(corosio_echo_server echo_server.cpp)
target_link_libraries(corosio_echo_server PRIVATE Boost::corosio)

add_executable(corosio_echo_client echo_client.cpp)
target_link_libraries(corosio_echo_client PRIVATE Boost::corosio)
