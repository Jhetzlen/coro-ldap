# ICU, and OpenSSL with JHETZ_LDAP_BUILD_NET: the installed ones (system,
# vcpkg or Conan toolchain, CMAKE_PREFIX_PATH, ICU_ROOT, OPENSSL_ROOT_DIR),
# else, with JHETZ_LDAP_FETCH_DEPS, the missing ones built once by a pinned
# vcpkg in the build tree (docs/DEVELOPMENT.md "Dependencies"). Included
# from CMakeLists.txt: its find_package() results are the caller's.

option(JHETZ_LDAP_FETCH_DEPS "Build ICU and OpenSSL with a pinned vcpkg when they are not installed" ON)
set(JHETZ_LDAP_VCPKG_ROOT "" CACHE PATH
    "The vcpkg that builds missing ICU and OpenSSL (empty: a pinned clone in the build tree)")

# The vcpkg commit whose ports are built, as in .github/vcpkg/vcpkg.json.
set(jhetz_ldap_vcpkg_commit 9eec002df1cd109f8f104cd966a763daf9751489)
set(jhetz_ldap_vcpkg_dir ${CMAKE_BINARY_DIR}/_deps/jhetz_ldap_vcpkg)

# Static libraries on both platforms, so nothing is left to deploy: release
# only on Linux; on Windows both configurations with the DLL CRT, which is
# what /MD and /MDd link. A static C++ library must also have the build's
# _ITERATOR_DEBUG_LEVEL (the linker refuses a mix, LNK2038): when the flags
# set one, an overlay triplet builds both libraries with it. `out` is the
# triplet, `out`_FILE an overlay triplet's text (written only when vcpkg
# runs: a build that finds everything installed writes nothing).
function(jhetz_ldap_vcpkg_triplet out)
    set(${out}_FILE "" PARENT_SCOPE)
    if(MSVC)
        set(arch ${CMAKE_CXX_COMPILER_ARCHITECTURE_ID})
    else()
        set(arch ${CMAKE_SYSTEM_PROCESSOR})
    endif()
    string(TOLOWER "${arch}" arch)
    if(arch MATCHES "^(x64|x86_64|amd64)$")
        set(arch x64)
    elseif(arch MATCHES "^(arm64|aarch64)$")
        set(arch arm64)
    else()
        set(arch "")
    endif()
    if("${arch}" STREQUAL "" OR CMAKE_CROSSCOMPILING OR NOT (CMAKE_SYSTEM_NAME STREQUAL "Linux" OR MSVC))
        set(${out} "" PARENT_SCOPE)
    elseif(MSVC)
        # From CMAKE_CXX_FLAGS (CXXFLAGS) for both configurations, or
        # from CMAKE_CXX_FLAGS_DEBUG for Debug.
        set(idl "")
        set(scope "")
        if(CMAKE_CXX_FLAGS MATCHES "[-/]D *_ITERATOR_DEBUG_LEVEL=([0-2])")
            set(idl ${CMAKE_MATCH_1})
        endif()
        if(CMAKE_CXX_FLAGS_DEBUG MATCHES "[-/]D *_ITERATOR_DEBUG_LEVEL=([0-2])")
            set(idl ${CMAKE_MATCH_1})
            set(scope _DEBUG)
        endif()
        if(idl STREQUAL "")
            set(${out} ${arch}-windows-static-md PARENT_SCOPE)
        else()
            set(name jhetz-ldap-${arch}-windows-static-md-idl${idl}${scope})
            string(TOLOWER ${name} name)
            set(${out} ${name} PARENT_SCOPE)
            string(CONCAT text
                "set(VCPKG_TARGET_ARCHITECTURE ${arch})\n"
                "set(VCPKG_CRT_LINKAGE dynamic)\n"
                "set(VCPKG_LIBRARY_LINKAGE static)\n"
                "set(VCPKG_C_FLAGS${scope} \"/D_ITERATOR_DEBUG_LEVEL=${idl}\")\n"
                "set(VCPKG_CXX_FLAGS${scope} \"/D_ITERATOR_DEBUG_LEVEL=${idl}\")\n")
            set(${out}_FILE "${text}" PARENT_SCOPE)
        endif()
    else()
        set(${out} jhetz-ldap-${arch}-linux PARENT_SCOPE)
        string(CONCAT text
            "set(VCPKG_TARGET_ARCHITECTURE ${arch})\n"
            "set(VCPKG_CRT_LINKAGE dynamic)\n"
            "set(VCPKG_LIBRARY_LINKAGE static)\n"
            "set(VCPKG_CMAKE_SYSTEM_NAME Linux)\n"
            "set(VCPKG_BUILD_TYPE release)\n")
        set(${out}_FILE "${text}" PARENT_SCOPE)
    endif()
endfunction()

function(jhetz_ldap_run what)
    execute_process(COMMAND ${ARGN} RESULT_VARIABLE rc)
    if(NOT rc EQUAL 0)
        list(JOIN ARGN " " command)
        message(FATAL_ERROR "jhetz::ldap: ${what} failed (${rc}): ${command}\n"
            "Building ICU and OpenSSL with vcpkg needs git and, on Linux, curl zip unzip tar pkg-config make "
            "autoconf autoconf-archive automake libtool (docs/DEVELOPMENT.md \"Dependencies\"). Or install "
            "ICU and OpenSSL (Debian: apt install libicu-dev libssl-dev) and configure a new build tree.")
    endif()
endfunction()

# Clones and bootstraps the pinned vcpkg (unless JHETZ_LDAP_VCPKG_ROOT) and
# installs `ports` for `triplet` under `installed` (classic mode).
function(jhetz_ldap_vcpkg_install triplet installed ports)
    file(MAKE_DIRECTORY ${jhetz_ldap_vcpkg_dir}/triplets)
    if(NOT "${jhetz_ldap_triplet_FILE}" STREQUAL "")
        file(WRITE ${jhetz_ldap_vcpkg_dir}/triplets/${triplet}.cmake "${jhetz_ldap_triplet_FILE}")
    endif()
    set(root "${JHETZ_LDAP_VCPKG_ROOT}")
    if("${root}" STREQUAL "")
        set(root ${jhetz_ldap_vcpkg_dir}/vcpkg)
        if(NOT EXISTS ${root}/.jhetz_ldap_${jhetz_ldap_vcpkg_commit})
            find_package(Git REQUIRED)
            file(REMOVE_RECURSE ${root})
            file(MAKE_DIRECTORY ${root})
            message(STATUS "jhetz::ldap: fetching vcpkg ${jhetz_ldap_vcpkg_commit}")
            jhetz_ldap_run("git init" ${GIT_EXECUTABLE} -C ${root} init -q)
            jhetz_ldap_run("git fetch" ${GIT_EXECUTABLE} -C ${root} fetch -q --depth 1
                https://github.com/microsoft/vcpkg.git ${jhetz_ldap_vcpkg_commit})
            jhetz_ldap_run("git checkout" ${GIT_EXECUTABLE} -C ${root} -c advice.detachedHead=false checkout -q FETCH_HEAD)
            file(TOUCH ${root}/.jhetz_ldap_${jhetz_ldap_vcpkg_commit})
        endif()
    endif()
    if(WIN32)
        set(exe ${root}/vcpkg.exe)
        set(bootstrap ${root}/bootstrap-vcpkg.bat)
    else()
        set(exe ${root}/vcpkg)
        set(bootstrap ${root}/bootstrap-vcpkg.sh)
    endif()
    if(NOT EXISTS ${exe})
        jhetz_ldap_run("vcpkg bootstrap" ${bootstrap} -disableMetrics)
    endif()
    list(JOIN ports " " port_list)
    message(STATUS "jhetz::ldap: building ${port_list} with vcpkg (${triplet}); "
        "the first time takes 10 to 30 minutes, later builds reuse vcpkg's binary cache")
    # --classic: the consumer's own vcpkg.json, if any, is not ours to install.
    jhetz_ldap_run("vcpkg install" ${CMAKE_COMMAND} -E env VCPKG_DISABLE_METRICS=1 --unset=VCPKG_ROOT
        ${exe} install ${ports} --classic --triplet=${triplet}
        --overlay-triplets=${jhetz_ldap_vcpkg_dir}/triplets
        --vcpkg-root=${root} --x-install-root=${installed})
endfunction()

# Points FindICU (port `icu`) or FindOpenSSL (`openssl`) at the vcpkg
# prefix (a macro: the hints are the caller's variables). What an earlier
# search cached is dropped, so no installed library is mixed with the
# prefix's headers. On Windows the library paths are given: the debug ones
# are in debug/lib, which neither module searches.
macro(jhetz_ldap_use_vcpkg_port port)
    set(jhetz_ldap_p ${jhetz_ldap_vcpkg_prefix})
    if("${port}" STREQUAL "icu")
        foreach(var ICU_INCLUDE_DIR ICU_UC_LIBRARY_RELEASE ICU_UC_LIBRARY_DEBUG ICU_DATA_LIBRARY_RELEASE
                ICU_DATA_LIBRARY_DEBUG)
            unset(${var} CACHE)
        endforeach()
        set(ICU_ROOT ${jhetz_ldap_p})
        if(MSVC AND EXISTS ${jhetz_ldap_p}/include/unicode/utf8.h)
            set(ICU_INCLUDE_DIR ${jhetz_ldap_p}/include CACHE PATH "")
            set(ICU_UC_LIBRARY_RELEASE ${jhetz_ldap_p}/lib/icuuc.lib CACHE FILEPATH "")
            set(ICU_UC_LIBRARY_DEBUG ${jhetz_ldap_p}/debug/lib/icuucd.lib CACHE FILEPATH "")
            set(ICU_DATA_LIBRARY_RELEASE ${jhetz_ldap_p}/lib/icudt.lib CACHE FILEPATH "")
            set(ICU_DATA_LIBRARY_DEBUG ${jhetz_ldap_p}/debug/lib/icudtd.lib CACHE FILEPATH "")
        endif()
    else()
        foreach(var OPENSSL_INCLUDE_DIR OPENSSL_SSL_LIBRARY OPENSSL_CRYPTO_LIBRARY LIB_EAY_RELEASE
                LIB_EAY_DEBUG SSL_EAY_RELEASE SSL_EAY_DEBUG __pkg_config_checked__OPENSSL)
            unset(${var} CACHE)
        endforeach()
        set(OPENSSL_ROOT_DIR ${jhetz_ldap_p})
        set(OPENSSL_USE_STATIC_LIBS TRUE)
        if(MSVC AND EXISTS ${jhetz_ldap_p}/include/openssl/ssl.h)
            set(OPENSSL_INCLUDE_DIR ${jhetz_ldap_p}/include CACHE PATH "")
            set(LIB_EAY_RELEASE ${jhetz_ldap_p}/lib/libcrypto.lib CACHE FILEPATH "")
            set(LIB_EAY_DEBUG ${jhetz_ldap_p}/debug/lib/libcrypto.lib CACHE FILEPATH "")
            set(SSL_EAY_RELEASE ${jhetz_ldap_p}/lib/libssl.lib CACHE FILEPATH "")
            set(SSL_EAY_DEBUG ${jhetz_ldap_p}/debug/lib/libssl.lib CACHE FILEPATH "")
        endif()
    endif()
endmacro()

# FindOpenSSL; for vcpkg's, pkg-config reads only the prefix's .pc files
# (FindOpenSSL takes a static OpenSSL's dependencies from them, and the
# system's would name its own, such as zlib).
macro(jhetz_ldap_find_openssl)
    if(UNIX AND "openssl" IN_LIST jhetz_ldap_vcpkg_ports)
        if(DEFINED ENV{PKG_CONFIG_LIBDIR})
            set(jhetz_ldap_pc_libdir "$ENV{PKG_CONFIG_LIBDIR}")
        else()
            unset(jhetz_ldap_pc_libdir)
        endif()
        set(ENV{PKG_CONFIG_LIBDIR} ${jhetz_ldap_vcpkg_prefix}/lib/pkgconfig)
        find_package(OpenSSL QUIET)
        if(DEFINED jhetz_ldap_pc_libdir)
            set(ENV{PKG_CONFIG_LIBDIR} "${jhetz_ldap_pc_libdir}")
        else()
            unset(ENV{PKG_CONFIG_LIBDIR})
        endif()
    else()
        find_package(OpenSSL QUIET)
    endif()
endmacro()

jhetz_ldap_vcpkg_triplet(jhetz_ldap_triplet)
set(jhetz_ldap_vcpkg_installed ${jhetz_ldap_vcpkg_dir}/installed)
set(jhetz_ldap_vcpkg_prefix ${jhetz_ldap_vcpkg_installed}/${jhetz_ldap_triplet})
set(jhetz_ldap_vcpkg_stamp ${jhetz_ldap_vcpkg_prefix}/.jhetz_ldap_ports)
set(jhetz_ldap_dep_ports icu openssl)
set(jhetz_ldap_dep_vars ICU_INCLUDE_DIR OPENSSL_INCLUDE_DIR)
# The ports an earlier configure built (the stamp: the commit, then the
# ports), found there again without searching.
set(jhetz_ldap_vcpkg_ports "")
if(JHETZ_LDAP_FETCH_DEPS AND NOT "${jhetz_ldap_triplet}" STREQUAL "" AND EXISTS ${jhetz_ldap_vcpkg_stamp})
    file(STRINGS ${jhetz_ldap_vcpkg_stamp} jhetz_ldap_stamp)
    list(POP_FRONT jhetz_ldap_stamp jhetz_ldap_stamp_commit)
    if(jhetz_ldap_stamp_commit STREQUAL jhetz_ldap_vcpkg_commit)
        set(jhetz_ldap_vcpkg_ports ${jhetz_ldap_stamp})
    endif()
endif()
foreach(port IN LISTS jhetz_ldap_vcpkg_ports)
    jhetz_ldap_use_vcpkg_port(${port})
endforeach()
# Cached from another triplet's prefix (the flags changed the triplet):
# searched again, so the libraries match the build.
foreach(port var IN ZIP_LISTS jhetz_ldap_dep_ports jhetz_ldap_dep_vars)
    if(NOT port IN_LIST jhetz_ldap_vcpkg_ports AND DEFINED CACHE{${var}})
        string(FIND "$CACHE{${var}}" "${jhetz_ldap_vcpkg_installed}/" at)
        if(at EQUAL 0)
            jhetz_ldap_use_vcpkg_port(${port})
        endif()
    endif()
endforeach()

find_package(ICU 60 QUIET COMPONENTS uc data)
set(jhetz_ldap_missing "")
if(NOT ICU_FOUND)
    list(APPEND jhetz_ldap_missing icu)
endif()
if(JHETZ_LDAP_BUILD_NET)
    jhetz_ldap_find_openssl()
    if(NOT OPENSSL_FOUND)
        list(APPEND jhetz_ldap_missing openssl)
    endif()
endif()

# Only the missing ones: an installed ICU or OpenSSL stays in use.
if(jhetz_ldap_missing AND JHETZ_LDAP_FETCH_DEPS AND NOT DEFINED VCPKG_TOOLCHAIN
        AND NOT "${jhetz_ldap_triplet}" STREQUAL "")
    jhetz_ldap_vcpkg_install(${jhetz_ldap_triplet} ${jhetz_ldap_vcpkg_installed} "${jhetz_ldap_missing}")
    list(APPEND jhetz_ldap_vcpkg_ports ${jhetz_ldap_missing})
    list(REMOVE_DUPLICATES jhetz_ldap_vcpkg_ports)
    list(JOIN jhetz_ldap_vcpkg_ports "\n" jhetz_ldap_stamp)
    file(WRITE ${jhetz_ldap_vcpkg_stamp} "${jhetz_ldap_vcpkg_commit}\n${jhetz_ldap_stamp}\n")
    foreach(port IN LISTS jhetz_ldap_missing)
        jhetz_ldap_use_vcpkg_port(${port})
    endforeach()
    if("icu" IN_LIST jhetz_ldap_missing)
        find_package(ICU 60 QUIET COMPONENTS uc data)
    endif()
    if("openssl" IN_LIST jhetz_ldap_missing)
        jhetz_ldap_find_openssl()
    endif()
endif()

if(NOT ICU_FOUND)
    message(FATAL_ERROR "jhetz::ldap needs ICU 60+: install it (e.g. apt install libicu-dev), use a vcpkg or "
        "Conan toolchain, or leave JHETZ_LDAP_FETCH_DEPS on (Linux and MSVC) to build it with vcpkg")
endif()
if(JHETZ_LDAP_BUILD_NET AND NOT OPENSSL_FOUND)
    message(FATAL_ERROR "jhetz::ldap needs OpenSSL: install it (e.g. apt install libssl-dev), use a vcpkg or "
        "Conan toolchain, leave JHETZ_LDAP_FETCH_DEPS on (Linux and MSVC) to build it with vcpkg, "
        "or configure with -DJHETZ_LDAP_BUILD_NET=OFF")
endif()

# What was found in the prefix is vcpkg's, stamp or not.
foreach(port var IN ZIP_LISTS jhetz_ldap_dep_ports jhetz_ldap_dep_vars)
    if(NOT port IN_LIST jhetz_ldap_vcpkg_ports AND DEFINED CACHE{${var}})
        string(FIND "$CACHE{${var}}" "${jhetz_ldap_vcpkg_prefix}/" at)
        if(at EQUAL 0)
            list(APPEND jhetz_ldap_vcpkg_ports ${port})
        endif()
    endif()
endforeach()

# A vcpkg-built ICU is static: its headers need U_STATIC_IMPLEMENTATION on
# Windows, and its libraries libdl and the threads library on Linux.
# RelWithDebInfo and MinSizeRel link the release libraries.
if("icu" IN_LIST jhetz_ldap_vcpkg_ports)
    foreach(t ICU::uc ICU::data)
        set_target_properties(${t} PROPERTIES
            MAP_IMPORTED_CONFIG_RELWITHDEBINFO Release MAP_IMPORTED_CONFIG_MINSIZEREL Release)
    endforeach()
    if(WIN32)
        set_property(TARGET ICU::uc APPEND PROPERTY INTERFACE_COMPILE_DEFINITIONS U_STATIC_IMPLEMENTATION)
    else()
        find_package(Threads REQUIRED)
        set_property(TARGET ICU::uc APPEND PROPERTY INTERFACE_LINK_LIBRARIES ${CMAKE_DL_LIBS} Threads::Threads)
    endif()
endif()
if(JHETZ_LDAP_BUILD_NET AND "openssl" IN_LIST jhetz_ldap_vcpkg_ports)
    foreach(t OpenSSL::SSL OpenSSL::Crypto)
        set_target_properties(${t} PROPERTIES
            MAP_IMPORTED_CONFIG_RELWITHDEBINFO Release MAP_IMPORTED_CONFIG_MINSIZEREL Release)
    endforeach()
endif()
