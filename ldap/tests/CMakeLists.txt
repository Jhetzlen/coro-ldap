include(FetchContent)

# SYSTEM: our warning flags must not fire on Catch2's headers.
FetchContent_Declare(Catch2
    GIT_REPOSITORY https://github.com/catchorg/Catch2.git
    GIT_TAG v3.7.1
    GIT_SHALLOW TRUE
    SYSTEM
)
FetchContent_MakeAvailable(Catch2)

list(APPEND CMAKE_MODULE_PATH ${catch2_SOURCE_DIR}/extras)
include(Catch)

add_executable(jhetz_ldap_tests
    ber_reader_tests.cpp
    ber_writer_tests.cpp
    error_tests.cpp
    framer_tests.cpp
)
target_link_libraries(jhetz_ldap_tests PRIVATE jhetz::ldap Catch2::Catch2WithMain)
jhetz_ldap_warnings(jhetz_ldap_tests)
catch_discover_tests(jhetz_ldap_tests)

# Runs the libFuzzer entry point on deterministic inputs, so the fuzz
# properties are checked by every compiler, without libFuzzer.
add_executable(ber_fuzz_replay
    ${PROJECT_SOURCE_DIR}/fuzz/ber_fuzz.cpp
    ${PROJECT_SOURCE_DIR}/fuzz/ber_fuzz_replay.cpp
)
target_link_libraries(ber_fuzz_replay PRIVATE jhetz::ldap)
jhetz_ldap_warnings(ber_fuzz_replay)
add_test(NAME ber_fuzz_replay COMMAND ber_fuzz_replay)
