import os

from conan import ConanFile
from conan.errors import ConanInvalidConfiguration
from conan.tools.build import check_min_cppstd
from conan.tools.cmake import CMake, CMakeDeps, CMakeToolchain, cmake_layout
from conan.tools.files import copy, get, rmdir
from conan.tools.gnu import PkgConfig
from conan.tools.scm import Version
from conan.tools.system.package_manager import Apt, Dnf, PacMan, Yum, Zypper

required_conan_version = ">=2.1"


class JhetzLdapConan(ConanFile):
    name = "jhetz-ldap"
    description = "C++23 LDAP client library: the LDAP codec, and an async connection on Corosio/Capy coroutines."
    license = "BSL-1.0"
    homepage = "https://github.com/Jhetzlen/coro-ldap"
    url = "https://github.com/Jhetzlen/coro-ldap"
    topics = ("ldap", "coroutines", "asn1", "tls", "sasl")
    package_type = "library"
    settings = "os", "arch", "compiler", "build_type"
    options = {
        "shared": [True, False],
        "fPIC": [True, False],
        "net": [True, False],
        "gssapi": [True, False],
    }
    default_options = {
        "shared": False,
        "fPIC": True,
        "net": True,
        "gssapi": False,
        # ICU's data built into libicudata, so no ICU_DATA at run time.
        "icu/*:data_packaging": "library",
    }

    _min_compilers = {"gcc": "16", "clang": "23", "msvc": "194"}

    def config_options(self):
        if self.settings.os == "Windows":
            del self.options.fPIC

    def configure(self):
        if self.options.shared:
            self.options.rm_safe("fPIC")
        if not self.options.net:
            self.options.rm_safe("gssapi")

    def layout(self):
        cmake_layout(self, src_folder="src")

    def requirements(self):
        self.requires("icu/[>=74 <80]")
        if self.options.net:
            self.requires("corosio/cci.20261120", transitive_headers=True, transitive_libs=True)
            self.requires("capy/cci.20261119", transitive_headers=True, transitive_libs=True)
            self.requires("openssl/[>=3 <4]")

    def validate(self):
        check_min_cppstd(self, 23)
        compiler = str(self.settings.compiler)
        if compiler == "apple-clang":
            raise ConanInvalidConfiguration(f"{self.ref} does not support Apple Clang")
        minimum = self._min_compilers.get(compiler)
        if minimum and Version(self.settings.compiler.version) < minimum:
            raise ConanInvalidConfiguration(f"{self.ref} needs {compiler} {minimum} or newer")
        if self.options.shared:
            raise ConanInvalidConfiguration(f"{self.ref} builds static libraries only")
        if self.options.get_safe("gssapi") and self.settings.os == "Windows":
            raise ConanInvalidConfiguration(f"{self.ref}: gssapi is not supported on Windows")

    def system_requirements(self):
        if not self.options.get_safe("gssapi"):
            return
        Apt(self).install(["libkrb5-dev", "pkg-config"])
        Dnf(self).install(["krb5-devel", "pkgconf"])
        Yum(self).install(["krb5-devel", "pkgconf"])
        Zypper(self).install(["krb5-devel", "pkg-config"])
        PacMan(self).install(["krb5", "pkgconf"])

    def source(self):
        get(self, **self.conan_data["sources"][self.version], strip_root=True)

    def generate(self):
        tc = CMakeToolchain(self)
        tc.cache_variables["JHETZ_LDAP_BUILD_NET"] = bool(self.options.net)
        tc.cache_variables["JHETZ_LDAP_WITH_GSSAPI"] = bool(self.options.get_safe("gssapi"))
        tc.cache_variables["JHETZ_LDAP_INSTALL"] = True
        tc.cache_variables["JHETZ_LDAP_BUILD_TESTS"] = False
        tc.cache_variables["JHETZ_LDAP_BUILD_EXAMPLES"] = False
        tc.cache_variables["JHETZ_LDAP_BUILD_FUZZERS"] = False
        tc.cache_variables["JHETZ_LDAP_BUILD_BENCH"] = False
        tc.cache_variables["JHETZ_LDAP_WERROR"] = False
        tc.cache_variables["FETCHCONTENT_FULLY_DISCONNECTED"] = True
        tc.cache_variables["CMAKE_CXX_SCAN_FOR_MODULES"] = False
        tc.generate()
        CMakeDeps(self).generate()

    def build(self):
        cmake = CMake(self)
        cmake.configure()
        cmake.build()

    def package(self):
        copy(self, "LICENSE", self.source_folder, os.path.join(self.package_folder, "licenses"))
        cmake = CMake(self)
        cmake.install()
        rmdir(self, os.path.join(self.package_folder, "lib", "cmake"))

    def _gssapi_libs(self, component):
        for module in ("krb5-gssapi", "heimdal-gssapi"):
            try:
                pc = PkgConfig(self, module)
                pc.libs  # noqa: B018 (raises if the module is missing)
            except Exception:
                continue
            component.system_libs.extend(pc.libs)
            component.libdirs.extend(d for d in pc.libdirs if d not in component.libdirs)
            component.sharedlinkflags.extend(pc.linkflags)
            component.exelinkflags.extend(pc.linkflags)
            return
        raise ConanInvalidConfiguration("jhetz-ldap gssapi needs the system GSS-API library (pkg-config krb5-gssapi)")

    def package_info(self):
        self.cpp_info.set_property("cmake_file_name", "jhetz_ldap")
        self.cpp_info.set_property("cmake_target_name", "jhetz::jhetz_ldap")
        icu = ["icu::icu-uc", "icu::icu-data"]

        core = self.cpp_info.components["ldap_core"]
        core.set_property("cmake_target_name", "jhetz::ldap_core")
        core.libs = ["jhetz_ldap_core"]
        core.requires = list(icu)

        if not self.options.net:
            return

        net = self.cpp_info.components["ldap"]
        net.set_property("cmake_target_name", "jhetz::ldap")
        net.libs = ["jhetz_ldap"]
        net.requires = ["ldap_core", "corosio::corosio", "corosio::corosio_openssl", "capy::capy",
                        "openssl::ssl", "openssl::crypto"] + icu
        if self.settings.os == "Windows":
            net.system_libs = ["crypt32"]
        if self.options.get_safe("gssapi"):
            self._gssapi_libs(net)

        ad = self.cpp_info.components["ldap_ad"]
        ad.set_property("cmake_target_name", "jhetz::ldap_ad")
        ad.libs = ["jhetz_ldap_ad"]
        ad.requires = ["ldap"] + icu
        ad.system_libs = ["dnsapi"] if self.settings.os == "Windows" else ["resolv"]
