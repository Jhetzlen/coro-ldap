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
    controls_tests.cpp
    dn_tests.cpp
    error_tests.cpp
    filter_tests.cpp
    mapping_tests.cpp
    framer_tests.cpp
    message_golden_tests.cpp
    message_tests.cpp
    pmr_tests.cpp
    schema_tests.cpp
    url_tests.cpp
)
target_link_libraries(jhetz_ldap_tests PRIVATE jhetz::ldap Catch2::Catch2WithMain)
jhetz_ldap_warnings(jhetz_ldap_tests)
catch_discover_tests(jhetz_ldap_tests)

# Compile tests for the mapping's compile-time checks (DESIGN.md section 4):
# each file in compile/ is compiled with -fsyntax-only and must fail with the
# expected diagnostic (matched in the C locale); ok.cpp must compile, so the
# failures are not due to the command line.
if(NOT MSVC)
    set(jhetz_ldap_compile_flags -std=c++23 -fsyntax-only -I${PROJECT_SOURCE_DIR}/include)
    if(jhetz_ldap_clang18_expected_workaround)
        list(APPEND jhetz_ldap_compile_flags -D__cpp_concepts=202002L -Wno-builtin-macro-redefined)
    endif()
    function(jhetz_ldap_compile_test name expected)
        add_test(NAME compile.${name}
            COMMAND ${CMAKE_CXX_COMPILER} ${jhetz_ldap_compile_flags} ${CMAKE_CURRENT_SOURCE_DIR}/compile/${name}.cpp)
        set_tests_properties(compile.${name} PROPERTIES ENVIRONMENT "LC_ALL=C;LANG=C")
        if(NOT expected STREQUAL "")
            set_tests_properties(compile.${name} PROPERTIES PASS_REGULAR_EXPRESSION "${expected}")
        endif()
    endfunction()
    jhetz_ldap_compile_test(ok "")
    jhetz_ldap_compile_test(unmapped_member "this member is not listed in ldap::schema<T>")
    jhetz_ldap_compile_test(read_only_member "this member is read_only in ldap::schema<T>")
    jhetz_ldap_compile_test(value_type_mismatch "the value's type does not match the member's type")
    jhetz_ldap_compile_test(several_values_single "several values for a single-valued member")
    jhetz_ldap_compile_test(filter_value_mismatch "invalid conversion|no match for .operator==|invalid operands|no viable|cannot initialize")
    jhetz_ldap_compile_test(change_of_other_struct "change<[^>]*device>")
    jhetz_ldap_compile_test(no_value_traits "no ldap::value_traits for this member's value type")
    jhetz_ldap_compile_test(invalid_attribute_name "invalid attribute description")
    jhetz_ldap_compile_test(fields_of_two_structs "every field must be a member of the same struct")
    jhetz_ldap_compile_test(add_without_object_class "declare ldap::object_class")
endif()

# Each <target>_fuzz_replay runs the libFuzzer entry point of fuzz/<target>.cpp
# on deterministic inputs, so the fuzz properties are checked by every
# compiler, without libFuzzer.
foreach(target ber_fuzz message_fuzz filter_fuzz dn_fuzz url_fuzz value_fuzz schema_fuzz)
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
        net/connection_tests.cpp
        net/mapping_ops_tests.cpp
        net/operations_tests.cpp
        net/sasl_scram_tests.cpp
        net/sasl_tests.cpp
        net/start_tls_tests.cpp
        net/sync_tests.cpp
        net/message_io_tests.cpp
    )
    target_link_libraries(jhetz_ldap_net_tests PRIVATE jhetz::ldap_net Catch2::Catch2WithMain)
    # Integration tests against a real slapd (tests/integration/run_slapd.sh
    # starts one and sets JHETZ_LDAP_IT_*): one ctest entry, label
    # "integration", skipped (Catch2 exit code 4) when no server is set up.
    add_executable(jhetz_ldap_integration_tests integration/integration_tests.cpp)
    target_link_libraries(jhetz_ldap_integration_tests PRIVATE jhetz::ldap_net Catch2::Catch2WithMain)
    jhetz_ldap_warnings(jhetz_ldap_integration_tests)
    add_test(NAME integration COMMAND jhetz_ldap_integration_tests)
    set_tests_properties(integration PROPERTIES LABELS integration SKIP_RETURN_CODE 4)

    # sync_tests.cpp runs the CLI against its in-process server.
    if(TARGET jhetz_ldapsearch)
        add_dependencies(jhetz_ldap_net_tests jhetz_ldapsearch)
        target_compile_definitions(jhetz_ldap_net_tests PRIVATE JHETZ_LDAPSEARCH="$<TARGET_FILE:jhetz_ldapsearch>")
    endif()
    jhetz_ldap_warnings(jhetz_ldap_net_tests)
    catch_discover_tests(jhetz_ldap_net_tests TEST_PREFIX "net.")
endif()
