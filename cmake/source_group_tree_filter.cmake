# Included before Capy's and Corosio's project(): in their directories,
# source_group(TREE <root>) leaves out the files outside <root>, which
# CMake 4.5 rejects; elsewhere it forwards unchanged. Defined once, and not
# over another override.
set(jhetz_ldap_source_group_tree_filter ON)
include_guard(GLOBAL)
get_property(jhetz_ldap_defined GLOBAL PROPERTY JHETZ_LDAP_SOURCE_GROUP_TREE_FILTER)
if(jhetz_ldap_defined OR COMMAND _source_group)
    return()
endif()
set_property(GLOBAL PROPERTY JHETZ_LDAP_SOURCE_GROUP_TREE_FILTER ON)

# `jhetz_ldap_value` as a quoted CMake argument, appended to the caller's
# variable named `jhetz_ldap_var`.
function(jhetz_ldap_append_quoted jhetz_ldap_var jhetz_ldap_value)
    string(REPLACE "\\" "\\\\" jhetz_ldap_value "${jhetz_ldap_value}")
    string(REPLACE "\"" "\\\"" jhetz_ldap_value "${jhetz_ldap_value}")
    string(REPLACE "$" "\\$" jhetz_ldap_value "${jhetz_ldap_value}")
    set(${jhetz_ldap_var} "${${jhetz_ldap_var}} \"${jhetz_ldap_value}\"" PARENT_SCOPE)
endfunction()

# Calls CMake's _source_group with every argument quoted, empty ones and
# semicolons kept.
function(source_group)
    set(call "")
    if(jhetz_ldap_source_group_tree_filter AND ARGC GREATER 1 AND "${ARGV0}" STREQUAL "TREE")
        cmake_parse_arguments(PARSE_ARGV 2 arg "" "PREFIX" "FILES")
        set(root "${ARGV1}")
        cmake_path(ABSOLUTE_PATH root BASE_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}" NORMALIZE)
        jhetz_ldap_append_quoted(call "TREE")
        jhetz_ldap_append_quoted(call "${ARGV1}")
        if("PREFIX" IN_LIST ARGN)
            jhetz_ldap_append_quoted(call "PREFIX")
            jhetz_ldap_append_quoted(call "${arg_PREFIX}")
        endif()
        jhetz_ldap_append_quoted(call "FILES")
        foreach(file IN LISTS arg_FILES)
            set(path "${file}")
            cmake_path(ABSOLUTE_PATH path BASE_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}" NORMALIZE)
            cmake_path(IS_PREFIX root "${path}" NORMALIZE under_root)
            if(under_root)
                jhetz_ldap_append_quoted(call "${file}")
            endif()
        endforeach()
    elseif(ARGC GREATER 0)
        math(EXPR last "${ARGC} - 1")
        foreach(i RANGE ${last})
            jhetz_ldap_append_quoted(call "${ARGV${i}}")
        endforeach()
    endif()
    cmake_language(EVAL CODE "_source_group(${call})")
endfunction()
