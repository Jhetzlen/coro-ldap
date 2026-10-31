# libFuzzer targets, built with -DJHETZ_LDAP_BUILD_FUZZERS=ON (Clang only).
# Executables land in <build>/fuzzers/ so CI can run each one in turn.
foreach(target ber_fuzz message_fuzz filter_fuzz dn_fuzz url_fuzz value_fuzz schema_fuzz matching_fuzz ntlm_fuzz)
    add_executable(${target} ${target}.cpp)
    target_link_libraries(${target} PRIVATE jhetz::ldap)
    target_link_options(${target} PRIVATE -fsanitize=fuzzer)
    jhetz_ldap_warnings(${target})
    set_target_properties(${target} PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/fuzzers)
endforeach()
