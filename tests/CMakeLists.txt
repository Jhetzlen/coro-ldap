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
# Windows: list the tests when ctest runs, not right after the build, so the
# DLLs (ICU, OpenSSL) only need to be on PATH for ctest.
if(WIN32)
    set(CMAKE_CATCH_DISCOVER_TESTS_DISCOVERY_MODE PRE_TEST)
endif()

add_executable(jhetz_ldap_tests
    ad_tests.cpp
    attribute_tests.cpp
    ber_reader_tests.cpp
    ber_writer_tests.cpp
    content_sync_tests.cpp
    controls_tests.cpp
    dn_tests.cpp
    error_tests.cpp
    filter_tests.cpp
    mapping_tests.cpp
    matching_tests.cpp
    framer_tests.cpp
    message_golden_tests.cpp
    message_tests.cpp
    pmr_tests.cpp
    referral_tests.cpp
    schema_tests.cpp
    url_tests.cpp
    value_semantics_tests.cpp
)
# ICU::uc for its headers: attribute_tests.cpp checks src/icu_util.hpp.
target_link_libraries(jhetz_ldap_tests PRIVATE jhetz::ldap ICU::uc Catch2::Catch2WithMain)
jhetz_ldap_warnings(jhetz_ldap_tests)
catch_discover_tests(jhetz_ldap_tests)

# Replaces the global operator new / delete to count allocations, so it
# gets its own executable.
add_executable(jhetz_ldap_alloc_tests schema_alloc_tests.cpp)
target_link_libraries(jhetz_ldap_alloc_tests PRIVATE jhetz::ldap Catch2::Catch2WithMain)
jhetz_ldap_warnings(jhetz_ldap_alloc_tests)
catch_discover_tests(jhetz_ldap_alloc_tests)

# Compile tests for the mapping's compile-time checks (DESIGN.md section 4)
# and the per-operation request controls (section 3):
# each file in compile/ is compiled with -fsyntax-only and must fail with the
# expected diagnostic (matched in the C locale); ok.cpp must compile, so the
# failures are not due to the command line. discarded_child.cpp compiles but
# must warn ([[nodiscard]], on by default in GCC and Clang).
if(NOT MSVC)
    # CMAKE_CXX_FLAGS too, so flags such as --gcc-install-dir reach the compiler.
    separate_arguments(jhetz_ldap_user_flags UNIX_COMMAND "${CMAKE_CXX_FLAGS}")
    set(jhetz_ldap_compile_flags ${jhetz_ldap_user_flags} -std=c++23 -fsyntax-only -I${PROJECT_SOURCE_DIR}/include)
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
    jhetz_ldap_compile_test(no_value_traits "this member's value type needs an ldap::value_traits<T>")
    jhetz_ldap_compile_test(invalid_attribute_name "invalid attribute description")
    jhetz_ldap_compile_test(fields_of_two_structs "every field must be a member of the same struct")
    jhetz_ldap_compile_test(add_without_object_class "declare ldap::object_class")
    jhetz_ldap_compile_test(syntax_of_temporary "syntax_of_temporary\\.cpp:9:[0-9]+: error: (use of deleted function|call to deleted)")
    # Anchored on the discarding line, so a nodiscard warning from a header does
    # not count; PASS_REGULAR_EXPRESSION ignores the exit code, so fail on errors.
    jhetz_ldap_compile_test(discarded_child "discarded_child\\.cpp:10:[0-9]+: warning: ignoring return value")
    set_tests_properties(compile.discarded_child PROPERTIES FAIL_REGULAR_EXPRESSION "error:")
    # Typed request controls on an operation their specification does not
    # allow (controls.hpp's table, DESIGN.md section 3).
    jhetz_ldap_compile_test(pre_read_on_add "pre_read_on_add\\.cpp:3:[0-9]+: error: .*add_controls")
    jhetz_ldap_compile_test(post_read_on_delete "post_read_on_delete\\.cpp:3:[0-9]+: error: .*del_controls")
    jhetz_ldap_compile_test(paged_on_modify "paged_on_modify\\.cpp:3:[0-9]+: error: .*modify_controls")
    jhetz_ldap_compile_test(relax_rules_on_search "relax_rules_on_search\\.cpp:3:[0-9]+: error: .*search_controls")
    jhetz_ldap_compile_test(assertion_on_extended "assertion_on_extended\\.cpp:3:[0-9]+: error: .*extended_controls")
    jhetz_ldap_compile_test(transaction_specification_on_search "transaction_specification_on_search\\.cpp:3:[0-9]+: error: .*search_controls")
endif()

# Header self-containment: one generated TU per public header, including
# only that header (twice: #pragma once), built with our warnings. The
# codec's headers are built against jhetz::ldap alone, so one that needs
# Corosio or Capy fails here; jhetz::ldap_net's against jhetz::ldap_net.
# A new header is picked up when CMake reconfigures (CONFIGURE_DEPENDS).
file(GLOB_RECURSE jhetz_ldap_public_headers CONFIGURE_DEPENDS
    RELATIVE ${PROJECT_SOURCE_DIR}/include ${PROJECT_SOURCE_DIR}/include/jhetz/ldap/*.hpp)
# The headers that need jhetz::ldap_net; the root CMakeLists.txt's codec-only
# install() EXCLUDE patterns spell the same list (checked by
# tests/install/check_install.sh).
set(jhetz_ldap_net_headers
    jhetz/ldap/cancel.hpp jhetz/ldap/client.hpp jhetz/ldap/connection.hpp jhetz/ldap/connection_options.hpp
    jhetz/ldap/paged_search.hpp jhetz/ldap/referral_chase.hpp jhetz/ldap/search_stream.hpp jhetz/ldap/sync.hpp jhetz/ldap/transaction.hpp
    jhetz/ldap/sasl_scram.hpp jhetz/ldap/sasl_gssapi.hpp)
set(jhetz_ldap_codec_header_tus)
set(jhetz_ldap_net_header_tus)
foreach(header ${jhetz_ldap_public_headers})
    string(REGEX REPLACE "[/.]" "_" stem ${header})
    set(tu ${CMAKE_CURRENT_BINARY_DIR}/header_check/${stem}.cpp)
    file(CONFIGURE OUTPUT ${tu} CONTENT "#include \"${header}\"\n#include \"${header}\" // NOLINT(readability-duplicate-include): included twice on purpose, to check #pragma once\n")
    if(header MATCHES "^jhetz/ldap/net/" OR header IN_LIST jhetz_ldap_net_headers)
        list(APPEND jhetz_ldap_net_header_tus ${tu})
    else()
        list(APPEND jhetz_ldap_codec_header_tus ${tu})
    endif()
endforeach()
add_library(jhetz_ldap_header_check OBJECT ${jhetz_ldap_codec_header_tus})
target_link_libraries(jhetz_ldap_header_check PRIVATE jhetz::ldap)
jhetz_ldap_warnings(jhetz_ldap_header_check)
if(JHETZ_LDAP_BUILD_NET)
    add_library(jhetz_ldap_net_header_check OBJECT ${jhetz_ldap_net_header_tus})
    target_link_libraries(jhetz_ldap_net_header_check PRIVATE jhetz::ldap_net)
    jhetz_ldap_warnings(jhetz_ldap_net_header_check)
endif()

# Each <target>_fuzz_replay runs the libFuzzer entry point of fuzz/<target>.cpp
# on deterministic inputs, so the fuzz properties are checked by every
# compiler, without libFuzzer.
foreach(target ber_fuzz message_fuzz filter_fuzz dn_fuzz url_fuzz value_fuzz schema_fuzz matching_fuzz)
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
        net/channel_binding_tests.cpp
        net/client_tests.cpp
        net/connection_tests.cpp
        net/content_sync_tests.cpp
        net/mapping_ops_tests.cpp
        net/operations_tests.cpp
        net/password_tests.cpp
        net/referral_chase_tests.cpp
        net/transaction_tests.cpp
        net/sasl_scram_tests.cpp
        net/sasl_tests.cpp
        net/start_tls_tests.cpp
        net/sync_tests.cpp
        net/sync_client_tests.cpp
        net/message_io_tests.cpp
    )
    if(JHETZ_LDAP_WITH_GSSAPI)
        target_sources(jhetz_ldap_net_tests PRIVATE net/sasl_gssapi_tests.cpp)
    endif()
    target_link_libraries(jhetz_ldap_net_tests PRIVATE jhetz::ldap_net Catch2::Catch2WithMain)
    # Integration tests against a real slapd (tests/integration/run_slapd.sh
    # starts one and sets JHETZ_LDAP_IT_*): one ctest entry, label
    # "integration", skipped (Catch2 exit code 4) when no server is set up.
    add_executable(jhetz_ldap_integration_tests integration/integration_tests.cpp)
    target_link_libraries(jhetz_ldap_integration_tests PRIVATE jhetz::ldap_net Catch2::Catch2WithMain)
    jhetz_ldap_warnings(jhetz_ldap_integration_tests)
    add_test(NAME integration COMMAND jhetz_ldap_integration_tests)
    set_tests_properties(integration PROPERTIES LABELS integration SKIP_RETURN_CODE 4)
    # SASL GSSAPI against slapd and a throwaway KDC (run_kdc.sh around
    # run_slapd.sh): skipped without them.
    if(JHETZ_LDAP_WITH_GSSAPI)
        add_executable(jhetz_ldap_gssapi_integration_tests integration/gssapi_tests.cpp)
        target_link_libraries(jhetz_ldap_gssapi_integration_tests PRIVATE jhetz::ldap_net Catch2::Catch2WithMain)
        jhetz_ldap_warnings(jhetz_ldap_gssapi_integration_tests)
        add_test(NAME integration.gssapi COMMAND jhetz_ldap_gssapi_integration_tests)
        set_tests_properties(integration.gssapi PROPERTIES LABELS "integration;kerberos" SKIP_RETURN_CODE 4)
        # The channel bindings against an in-process MIT acceptor: needs the
        # KDC only (run_kdc.sh), not slapd; skipped without it.
        add_executable(jhetz_ldap_gssapi_channel_binding_tests integration/gssapi_channel_binding_tests.cpp)
        target_link_libraries(jhetz_ldap_gssapi_channel_binding_tests
            PRIVATE jhetz::ldap_net PkgConfig::JHETZ_LDAP_GSSAPI Catch2::Catch2WithMain)
        jhetz_ldap_warnings(jhetz_ldap_gssapi_channel_binding_tests)
        add_test(NAME kerberos.channel_binding COMMAND jhetz_ldap_gssapi_channel_binding_tests)
        set_tests_properties(kerberos.channel_binding PROPERTIES LABELS "integration;kerberos" SKIP_RETURN_CODE 4)
    endif()

    # sync_tests.cpp runs the CLI against its in-process server.
    if(TARGET jhetz_ldapsearch)
        add_dependencies(jhetz_ldap_net_tests jhetz_ldapsearch)
        target_compile_definitions(jhetz_ldap_net_tests PRIVATE JHETZ_LDAPSEARCH="$<TARGET_FILE:jhetz_ldapsearch>")
    endif()
    jhetz_ldap_warnings(jhetz_ldap_net_tests)
    # A hung network test fails after two minutes, not after ctest's 1500 s.
    catch_discover_tests(jhetz_ldap_net_tests TEST_PREFIX "net." PROPERTIES TIMEOUT 120)
endif()
