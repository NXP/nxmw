#
# Copyright 2022-2023 NXP
# SPDX-License-Identifier: BSD-3-Clause
#

"""
Create CMake Projects

"""
import os
import platform
import stat
import sys

__VERSION__ = "2018.08.11_00"

NINJA_EXE = r"C:/_ddm/opt/bin/ninja.exe"

class CMakeGenertor:  # pylint: disable=too-many-public-methods
    """
    Cmake generator class
    """

    def __init__(self, cmake_exe, root_dir):
        self.cmake_exe = cmake_exe
        self.source_root_dir = os.path.abspath(root_dir)
        target_root_dir = "%s/../%s_build" % (root_dir, os.path.basename(self.source_root_dir))
        self.target_root_dir = os.path.abspath(target_root_dir)
        self.warn_if_target_root_dir_not_empty()

    def warn_if_target_root_dir_not_empty(self):
        """
        This function returns whether the directory is empty or not.
        """
        if not os.path.exists(self.target_root_dir):
            os.makedirs(self.target_root_dir)
        have_some_file = False
        for entry in os.listdir(self.target_root_dir):
            if os.path.isfile('%s/%s' % (self.target_root_dir, entry)):
                have_some_file = True
        if have_some_file:
            print("WARNING: %s is having stray files." % (self.target_root_dir,))
            print("WARNING: The contents of this directory would be overwritten")

    def generate_msvc(self, msvc_name, options, message):
        """
        Generate msvc
        """
        os.chdir(self.target_root_dir)
        target_dir = "%s/%s" % (self.target_root_dir, msvc_name)
        try:
            os.makedirs(target_dir)
        except OSError:
            pass
        os.chdir(target_dir)
        cmake_d = self._update_cmaked(options)
        cmake_d.append("-A Win32")
        self._cmake(cmake_d, message)
        return options

    def generate_native(self, msvc_name, options, message):
        """
        Generate native
        :return: options
        """
        os.chdir(self.target_root_dir)
        target_dir = "%s/%s" % (self.target_root_dir, msvc_name)
        try:
            os.makedirs(target_dir)
        except OSError:
            pass
        os.chdir(target_dir)
        if os.path.exists("/usr/local/ssl"):
            print("INFO: Using OPENSSL from '/usr/local/ssl'")
            options["OPENSSL_ROOT_DIR"] = "/usr/local/ssl"
        cmake_d = self._update_cmaked(options)
        if self.akm_native_is_setup():
            cmake_d.append("-Wno-dev")
        self._cmake(cmake_d, message)
        return options

    def generate_eclipse(self, eclipse_name, options, message):
        """
        Generate eclipse
        :return: options
        """
        os.chdir(self.target_root_dir)
        target_dir = "%s/%s-%s" % (self.target_root_dir,
                                   os.path.basename(self.source_root_dir),
                                   eclipse_name)
        try:
            os.makedirs(target_dir)
        except OSError:
            pass
        os.chdir(target_dir)
        generator = "Eclipse CDT4 - Unix Makefiles"
        values = {
            "CMAKE_ECLIPSE_VERSION": "4.5 (Mars)",
            "CMAKE_EXPORT_COMPILE_COMMANDS": "ON",
        }
        cmake_d = self._update_cmaked(values, options)
        cmake_d.append("-G \"%s\"" % (generator,))
        self._cmake(cmake_d, message)
        return options

    def generate_sublime(self, sublime_name, options, message):
        """
        Generate sublime
        :return: Options
        """
        os.chdir(self.target_root_dir)
        target_dir = "%s/%s" % (self.target_root_dir, sublime_name)
        try:
            os.makedirs(target_dir)
        except OSError:
            pass
        os.chdir(target_dir)
        generator = "Sublime Text 2 - Unix Makefiles"
        values = {
            "CMAKE_EXPORT_COMPILE_COMMANDS": "ON",
        }
        if os.path.exists(NINJA_EXE):
            values["CMAKE_MAKE_PROGRAM"] = NINJA_EXE
        cmake_d = self._update_cmaked(values, options)
        cmake_d.append("-G \"%s\"" % (generator,))
        self._cmake(cmake_d, message)
        return options

    def generate_xcode(self, xcode_name, options, message):
        """
        Generate xcode
        :return: Options
        """
        os.chdir(self.target_root_dir)
        target_dir = "%s/%s" % (self.target_root_dir, xcode_name)
        try:
            os.makedirs(target_dir)
        except OSError:
            pass
        os.chdir(target_dir)
        values = {
            "NXMW_Host": "Darwin",
        }
        generator = "Xcode"
        cmake_d = self._update_cmaked(values, options)
        cmake_d.append("-G \"%s\"" % (generator,))
        self._cmake(cmake_d, message)
        return options

    def _create_edit_cache(self, cmake_d):
        if 'nt' == os.name:  # pylint: disable=misplaced-comparison-constant
            with open("_cmake_editcache.bat", "w") as ec:
                ec.write("cd /d %~dp0\n")
                cmake_gui = self.cmake_exe.replace(".exe", "-gui.exe")
                if cmake_gui == "cmake":
                    cmake_gui = "cmake-gui.exe"
                ec.write("call %s .\n" % (cmake_gui,))
                ec.write("pause\n" % ())
            with open("_cmake_here.bat", "w") as ec:
                ec.write("cd /d %~dp0\n")
                ec.write("call %s . .\n" % (self.cmake_exe,))
            with open("_cmake_build.bat", "w") as ec:
                ec.write("cd /d %~dp0\n")
                ec.write("call %s --build .\n" % (self.cmake_exe,))
                ec.write("pause\n" % ())
            with open("_cmake_createnew.bat", "w") as ec:
                ec.write("cd /d %~dp0\n")
                ec.write("call %s %s %s\n" % (self.cmake_exe, " ".join(cmake_d),
                                              self.source_root_dir))
                ec.write("pause\n" % ())

        elif 'darwin' in sys.platform:
            with open("_cmake_editcache.sh", "w") as ec:
                ec.write("#!/bin/sh\n")
                ec.write("cd %s\n" % (os.path.abspath(os.curdir),))
                ec.write("ccmake .\n")
                ec.write("cmake-gui .\n")
            with open("_cmake_build.sh", "w") as ec:
                ec.write("#!/bin/sh\n")
                ec.write("cd %s\n" % (os.path.abspath(os.curdir),))
                ec.write("cmake --build .\n" % ())
            with open("_cmake_createnew.sh", "w") as ec:
                ec.write("#!/bin/sh\n")
                ec.write("call %s %s %s\n" % (self.cmake_exe, " ".join(cmake_d),
                                              self.source_root_dir))
            for i in ("_cmake_editcache.sh", "_cmake_build.sh", "_cmake_createnew.sh"):
                st = os.stat(i)
                os.chmod(i, st.st_mode | stat.S_IEXEC)
        else:
            pass
            # TODO Shell script that supports cmake-gui and ccmake # pylint: disable=fixme

    def _cmake(self, cmake_d, message):
        if self.is_internal():
            cmake_d.append("-DNXPInternal=ON")
        print("\n")
        print("### %s" % (message,))
        print("#cmake %s" % (" ".join(cmake_d),))
        self._create_edit_cache(cmake_d)
        os.system("%s %s %s" % (
            self.cmake_exe, " ".join(cmake_d), self.source_root_dir))

    def is_internal(self):
        if os.path.exists("%s/scripts/jenkins/cmake_options_check.groovy" % (
                self.source_root_dir,)):
            return True
        return False

    def is_with_el2go(self):
        if os.path.exists("%s/nxp_iot_agent/src/nxp_iot_agent.c" % (
                self.source_root_dir,)):
            return True
        return False

    @classmethod
    def _update_cmaked(cls, values=None, options=None):
        cmake_d = []
        value_and_options = {}
        for the_dict in (values, options):
            if the_dict:
                for k, v in list(the_dict.items()):
                    value_and_options[k] = v

        if cls.is_jenkins():
            if 'CMAKE_BUILD_TYPE' in list(value_and_options.keys()):
                pass
            else:
                value_and_options['CMAKE_BUILD_TYPE'] = "Debug"
        else:
            value_and_options['CMAKE_BUILD_TYPE'] = "Debug"
        for k, v in list(value_and_options.items()):
            if " " in v:
                cmake_d.append("-D%s=\"%s\"" % (k, v))
            else:
                cmake_d.append("-D%s=%s" % (k, v))
        return cmake_d

    @classmethod
    def vs_env_is_setup(cls):
        VSINSTALLDIR = os.getenv("VSINSTALLDIR")
        return bool(VSINSTALLDIR and os.path.exists(VSINSTALLDIR))

    @classmethod
    def is_visual_studio_installed(cls):
        """
        Function performs whether visual studio installed or not
        """
        VS140COMNTOOLS = os.getenv("VS140COMNTOOLS")
        VS120COMNTOOLS = os.getenv("VS120COMNTOOLS")
        if VS140COMNTOOLS and os.path.exists(VS140COMNTOOLS):
            return True
        if VS120COMNTOOLS and os.path.exists(VS120COMNTOOLS):
            return True
        if os.path.exists(r"C:\Program Files (x86)\Microsoft Visual Studio\2017"):
            return True
        if os.path.exists(r"C:\Program Files (x86)\Microsoft Visual Studio\2019"):
            return True
        if os.path.exists(r"C:\Program Files\Microsoft Visual Studio\2022"):
            return True
        return False

    @classmethod
    def mcux_env_is_setup(cls):
        """
        mcux environment setup
        """
        ARMGCC_DIR = os.getenv("ARMGCC_DIR")
        return bool(ARMGCC_DIR and os.path.exists(ARMGCC_DIR))

    @classmethod
    def imx_cross_compilation(cls):
        """
        imx cross compilation
        """
        PKG_CONFIG_SYSROOT_DIR = os.getenv("PKG_CONFIG_SYSROOT_DIR")
        return bool(PKG_CONFIG_SYSROOT_DIR and os.path.exists(PKG_CONFIG_SYSROOT_DIR))

    @classmethod
    def imx_native_compilation(cls):
        """
        imx native compilation
        """
        if 'imx6' in platform.node():
            return True
        if 'imx8' in platform.node():
            return True
        return False

    @classmethod
    def win10_iot_compilation(cls):
        """
        win10 iot compilation
        """
        if os.path.exists(
                r"C:\Program Files (x86)\Microsoft SDKs\UWPNuGetPackages\runtime."
                r"win10-arm.microsoft.net.native.compiler"):
            return True
        return False

    @classmethod
    def rasp_pi_native_compilation(cls):
        """
        raspberry pi native compilation
        """

        try:
            import RPi.GPIO as gpio
            rpi_environment = True
        except (ImportError, RuntimeError):
            if 'raspberrypi' in platform.node():
                rpi_environment = True
            else:
                rpi_environment = False

        return rpi_environment

    @classmethod
    def akm_native_is_setup(cls):
        ANDROID_NDK_ROOT = os.getenv("ANDROID_NDK_ROOT")
        return bool(ANDROID_NDK_ROOT and os.path.exists(ANDROID_NDK_ROOT))

    @classmethod
    def ninja_is_setup(cls):
        if os.path.exists(NINJA_EXE):
            return True
        return False

    @classmethod
    def is_jenkins(cls):
        if 'JENKINS_URL' in list(os.environ.keys()):
            return True
        return False

    @classmethod
    def is_cygwin(cls):
        return bool(
            "CYGWIN" in platform.system().upper() and "posix" == os.name)  # pylint: disable=misplaced-comparison-constant

    @classmethod
    def suggest_how_to_setup_env(cls):
        env_keys = set(os.environ.keys())
        needed_command = None
        for vs_num in range(20, 9, -1):
            vscommontools = "VS%d0COMNTOOLS" % (vs_num,)
            if vscommontools in env_keys:
                if not needed_command:
                    needed_command = 'call "%%%s%%vsvars32.bat"' % (vscommontools,)
                    break
        if needed_command:
            print("Before running this script, run this command:\n    %s" % (needed_command,))


def main():  # pylint: disable=too-many-statements, too-many-branches
    try:
        CMAKE_EXE = os.environ['CMAKE_DIR'] + "\\cmake.exe"
    except KeyError:
        CMAKE_EXE = "cmake.exe"

    if 'nt' == os.name:  # pylint: disable=misplaced-comparison-constant
        if os.path.exists(CMAKE_EXE):
            pass
        elif os.path.exists(r"C:\opt\cmake\bin\cmake.exe"):
            CMAKE_EXE = r"C:\opt\cmake\bin\cmake.exe"

        if os.path.exists(CMAKE_EXE):
            pass
        elif os.path.exists(r"C:\Program Files (x86)\cmake\bin\cmake.exe"):
            CMAKE_EXE = r"C:\Program Files (x86)\cmake\bin\cmake.exe"

        if os.path.exists(CMAKE_EXE):
            pass
        else:
            print("Could not find '%s'. Assuming 'cmake.exe' is in path and running." %
                  (CMAKE_EXE,))
            CMAKE_EXE = 'cmake'
    else:
        CMAKE_EXE = "cmake"

    # in case we are running from any arbitary directory, switch to this
    # directory.
    root_dir = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..")

    gc = CMakeGenertor(CMAKE_EXE, root_dir)
    NXMW_Host = ""
    if os.name == 'nt':
        NXMW_Host = "PCWindows"
    elif gc.is_cygwin():
        NXMW_Host = "Cygwin"
    elif "linux" in sys.platform:
        if gc.is_jenkins():
            NXMW_Host = "PCLinux32"
        else:
            NXMW_Host = "PCLinux64"
    elif 'darwin' in sys.platform:
        NXMW_Host = "Darwin"

    if 'nt' == os.name:  # pylint: disable=misplaced-comparison-constant
        if gc.is_visual_studio_installed() or gc.vs_env_is_setup():
            e = gc.generate_msvc("se_x86", {
                "NXMW_NX_Type": "NX_R_DA",
                "NXMW_Host": NXMW_Host,
                "NXMW_HostCrypto": "MBEDTLS",
                "NXMW_SMCOM": "VCOM",
            }, "Connect to Secure Authenticator from PC")
            if gc.is_internal():
                e["WithDllSupport"] = "ON"
                e["NXMW_NX_Type"] = "None"
                e["NXMW_SMCOM"] = "None"
                e = gc.generate_msvc("mbed_x86", e,
                                     "Pure SW Implementaiton with medTLS")
                e["NXMW_HostCrypto"] = "OPENSSL"
                e = gc.generate_msvc("openssl_x86", e,

                                     "Pure SW Implementaiton with OpenSSL")
    if gc.is_jenkins():
        gc.generate_eclipse("eclipse_openssl", {
            "NXMW_Host": "PCLinux32",
            "NXMW_HostCrypto": "OPENSSL",
            "NXMW_NX_Type": "None",
            "NXMW_SMCOM": "None",
        }, "Pure SW Implementaiton with Eclipse IDE and OpenSSL")

    if gc.mcux_env_is_setup():
        arm = gc.generate_eclipse("eclipse_arm", {
            "CMAKE_TOOLCHAIN_FILE": root_dir + "/scripts/armgcc_force_cpp.cmake",
            "NXMW_NX_Type": "NX_R_DA",
            "NXMW_Host": "lpcxpresso55s",
            "NXMW_SMCOM": "T1oI2C_GP1_0",
            "NXMW_MBedTLS" : "2_X",
        }, "Cross compilation setup with Eclipse")

    if "linux" in sys.platform:
        if "rpi" in sys.argv or gc.imx_native_compilation() or gc.rasp_pi_native_compilation():
            pass
        else:
            gc.generate_eclipse("linux_native_nx_vcom", {
                "NXMW_NX_Type": "NX_R_DA",
                "NXMW_Host": NXMW_Host,
                "NXMW_HostCrypto": "OPENSSL",
                "NXMW_SMCOM": "VCOM",
                "NXMW_OpenSSL": "3_0"
            }, "VCOM on Linux")
            gc.generate_eclipse("linux_native_nx_jrcp_v1_am", {
                "NXMW_NX_Type": "NX_R_DA",
                "NXMW_Host": NXMW_Host,
                "NXMW_HostCrypto": "OPENSSL",
                "NXMW_SMCOM": "JRCP_V1_AM",
                "NXMW_OpenSSL": "3_0"
            }, "JRCP_V1_AM on Linux")

    if False and gc.ninja_is_setup():
        gc.generate_sublime("subl_x86", {
            "NXMW_NX_Type": "NX_R_DA",
            "NXMW_HostCrypto": "MBEDTLS",
            "NXMW_Host": NXMW_Host,
            "NXMW_SMCOM": "None",
        }, "Using sublime")

    if gc.rasp_pi_native_compilation() or "rpi" in sys.argv:
        e = gc.generate_native("raspbian_native_nx_t1oi2c", {
            "NXMW_NX_Type": "NX_R_DA",
            "NXMW_HostCrypto": "OPENSSL",
            "NXMW_OpenSSL": "3_0",
            "NXMW_Host": "Raspbian",
            "NXMW_SMCOM": "T1oI2C_GP1_0",
            "WithSharedLIB": "ON",
        }, "Using Raspberry PI")
        gc.generate_eclipse("eclipse_jrcp_v1_am", {
                "NXMW_NX_Type": "NX_R_DA",
                "NXMW_Host": "Raspbian",
                "NXMW_HostCrypto": "OPENSSL",
                "NXMW_OpenSSL": "3_0",
                "NXMW_SMCOM": "JRCP_V1_AM"
            }, "JRCP_V1_AM on Raspbian")

if __name__ == "__main__":
    main()
