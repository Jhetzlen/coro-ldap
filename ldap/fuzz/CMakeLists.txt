# libFuzzer targets, built with -DJHETZ_LDAP_BUILD_FUZZERS=ON (Clang only).
# Executables land in <build>/fuzzers/ so CI can run each one in turn.
add_executable(ber_fuzz ber_fuzz.cpp)
target_link_libraries(ber_fuzz PRIVATE jhetz::ldap)
target_link_options(ber_fuzz PRIVATE -fsanitize=fuzzer)
jhetz_ldap_warnings(ber_fuzz)
set_target_properties(ber_fuzz PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/fuzzers)
