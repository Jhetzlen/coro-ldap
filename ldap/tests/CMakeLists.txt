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
    attribute_tests.cpp
    ber_reader_tests.cpp
    ber_writer_tests.cpp
    dn_tests.cpp
    error_tests.cpp
    filter_tests.cpp
    framer_tests.cpp
    message_golden_tests.cpp
    message_tests.cpp
    url_tests.cpp
)
target_link_libraries(jhetz_ldap_tests PRIVATE jhetz::ldap Catch2::Catch2WithMain)
jhetz_ldap_warnings(jhetz_ldap_tests)
catch_discover_tests(jhetz_ldap_tests)

# Each <target>_fuzz_replay runs the libFuzzer entry point of fuzz/<target>.cpp
# on deterministic inputs, so the fuzz properties are checked by every
# compiler, without libFuzzer.
foreach(target ber_fuzz message_fuzz filter_fuzz dn_fuzz url_fuzz)
    add_executable(${target}_replay
        ${PROJECT_SOURCE_DIR}/fuzz/${target}.cpp
        ${PROJECT_SOURCE_DIR}/fuzz/${target}_replay.cpp
    )
    target_link_libraries(${target}_replay PRIVATE jhetz::ldap)
    jhetz_ldap_warnings(${target}_replay)
    add_test(NAME ${target}_replay COMMAND ${target}_replay)
endforeach()

# Transport and connect tests (jhetz::ldap_net): in-process servers on
# loopback and Unix domain sockets, Capy mock streams. ctest names start with
# "net.", so `ctest -R "^net\."` runs just these.
if(JHETZ_LDAP_BUILD_NET)
    add_executable(jhetz_ldap_net_tests
        net/connect_tests.cpp
        net/message_io_tests.cpp
    )
    target_link_libraries(jhetz_ldap_net_tests PRIVATE jhetz::ldap_net Catch2::Catch2WithMain)
    jhetz_ldap_warnings(jhetz_ldap_net_tests)
    catch_discover_tests(jhetz_ldap_net_tests TEST_PREFIX "net.")
endif()
