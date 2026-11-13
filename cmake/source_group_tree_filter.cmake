# Included before Capy's and Corosio's project() (as
# CMAKE_PROJECT_boost_capy_INCLUDE_BEFORE and
# CMAKE_PROJECT_boost_corosio_INCLUDE_BEFORE). CMake 4.5 rejects a FILES
# path of source_group(TREE <root>) outside <root>, and their
# source_group(TREE .../include/boost/<lib>) is given the top-level
# include/boost/<lib>.hpp. In those projects' directories,
# source_group(TREE) leaves the files outside <root> out (IDE grouping
# only); everywhere else source_group is CMake's own. Their sources are
# not modified.
set(jhetz_ldap_source_group_tree_filter ON)
include_guard(GLOBAL)

# `jhetz_ldap_value` as a quoted CMake argument, appended to the caller's
# variable named `jhetz_ldap_var`.
function(jhetz_ldap_append_quoted jhetz_ldap_var jhetz_ldap_value)
    string(REPLACE "\\" "\\\\" jhetz_ldap_value "${jhetz_ldap_value}")
    string(REPLACE "\"" "\\\"" jhetz_ldap_value "${jhetz_ldap_value}")
    string(REPLACE "$" "\\$" jhetz_ldap_value "${jhetz_ldap_value}")
    set(${jhetz_ldap_var} "${${jhetz_ldap_var}} \"${jhetz_ldap_value}\"" PARENT_SCOPE)
endfunction()

# CMake's own source_group (_source_group) is called through
# cmake_language(EVAL) with every argument quoted, so that empty ones (the
# root group's "") and ones holding a semicolon are passed as they came.
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
