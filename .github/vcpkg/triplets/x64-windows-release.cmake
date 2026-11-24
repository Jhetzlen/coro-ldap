# x64-windows without the debug build. ICU and OpenSSL are used through
# their DLLs, each with its own CRT, so a Debug (/MDd) build links the
# release DLLs.
set(VCPKG_TARGET_ARCHITECTURE x64)
set(VCPKG_CRT_LINKAGE dynamic)
set(VCPKG_LIBRARY_LINKAGE dynamic)
set(VCPKG_BUILD_TYPE release)
