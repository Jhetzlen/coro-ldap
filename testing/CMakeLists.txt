# The server side of the codec for the tests, fuzzers, benchmarks and mock
# servers (docs/DESIGN.md), never installed: jhetz::ldap_testing over
# jhetz::ldap, and jhetz::ldap_testing_net (testing::read_message) for the
# network tests and benchmarks.

add_library(jhetz_ldap_testing STATIC
    src/controls.cpp
    src/filter.cpp
    src/message.cpp
    src/ntlm_message.cpp
)
add_library(jhetz::ldap_testing ALIAS jhetz_ldap_testing)
target_include_directories(jhetz_ldap_testing
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include
    PRIVATE ${PROJECT_SOURCE_DIR}/src)
target_link_libraries(jhetz_ldap_testing PUBLIC jhetz::ldap)
jhetz_ldap_warnings(jhetz_ldap_testing)

if(JHETZ_LDAP_BUILD_NET AND (JHETZ_LDAP_BUILD_TESTS OR JHETZ_LDAP_BUILD_BENCH))
    add_library(jhetz_ldap_testing_net STATIC src/message_io.cpp)
    add_library(jhetz::ldap_testing_net ALIAS jhetz_ldap_testing_net)
    target_include_directories(jhetz_ldap_testing_net PRIVATE ${PROJECT_SOURCE_DIR}/src)
    target_link_libraries(jhetz_ldap_testing_net PUBLIC jhetz_ldap_testing jhetz::ldap_net)
    jhetz_ldap_warnings(jhetz_ldap_testing_net)
endif()
