# Run as a FetchContent PATCH_COMMAND in Capy's or Corosio's source
# directory: drops the files directly in include/boost/ (the top-level
# <lib>.hpp, outside the tree) from the FILES of their
# source_group(TREE .../include/boost/<lib>) call. Idempotent.
file(READ CMakeLists.txt content)
string(REGEX REPLACE
    [=[source_group\(TREE ("?\${CMAKE_CURRENT_SOURCE_DIR}/include/boost/[a-z_]+"?) PREFIX "include" FILES \${([A-Z_]+)}\)]=]
    [=[set(jhetz_ldap_tree_files ${\2})
list(FILTER jhetz_ldap_tree_files EXCLUDE REGEX "/include/boost/[^/]+$")
source_group(TREE \1 PREFIX "include" FILES ${jhetz_ldap_tree_files})]=]
    patched "${content}")
if(NOT patched STREQUAL content)
    file(WRITE CMakeLists.txt "${patched}")
endif()
