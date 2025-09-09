# Copyright 2022-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
#

import os

import cmake_features  # pylint: disable=import-error

LIST_NX_SE_TYPE = [
    ("None", "Compiling without any NX Type Support", True),
    ("NX_R_DA", "Application (DF name 0xD2760000850101)", True),
    ("NX_PICC", "MF (DF name 0xD2760000850100)", True),
]

DEPREATCED_LIST = [
]

for e, _, _ in LIST_NX_SE_TYPE:
    pass

#
# THIS is used for CMake GUI
#

ENABLED_FOR_NX = True

LIST_NX_VERSIONS = [
    ("01_00_00", "OS version 1.0.0", ENABLED_FOR_NX),
    ("02_00_00", "OS version 2.0.0", ENABLED_FOR_NX),
]

#
# THIS is used for GTE Checks
# Greater than equal to!
#
LIST_NX_VERSIONS_ALL = [
    "01_00_00",
    "02_00_00",
]

LIST_OPENSSL = [
    ("1_1_1", "Use latest 1.1.1 version (Only applicable on PC)", True),
    ("3_0", "Use 3.0 version (Only applicable on PC)", True),
]

LIST_MBEDTLS = [
    ("2_X", "Use 2.X version", True),
    ("3_X", "Use 3.X version", True),
]

LIST_SMCOM = [
    ("None", "Not using any Communication layer", True),
    ("VCOM", "Virtual COM Port", True),
    ("T1oI2C_GP1_0", "GP Spec", True),
    ("PCSC", "CCID PC/SC reader interface", True),
    ("JRCP_V1_AM", (
        "Socket Interface Old Implementation.",
        "This is the interface used from Host PC when when we run jrcpv1_server",
        "from the linux PC."), True),
]

LIST_HOST = [
    ("PCWindows", "PC/Laptop Windows", True),
    ("PCLinux64", "PC/Laptop Linux64", True),
    ("lpcxpresso55s", "Embedded LPCXpresso55s", True),
    ("Raspbian", "Embedded Linux on RaspBerry PI", True),
    ("frdmmcxa153", "Embedded frdmmcxa153", True),
    ("frdmmcxn947", "Embedded frdmmcxn947", True),
]

LIST_RTOS = [
    ("Default", "No specific RTOS. Either bare matal on embedded system" +
     " or native linux or Windows OS", True),
    ("FreeRTOS", "Free RTOS for embedded systems", True),
]

LIST_HOSTCRYPTO = [
    ("MBEDTLS", "Use mbedTLS as host crypto", True),
    ("OPENSSL", "Use OpenSSL as host crypto", True),
    ("None",
     ("NO Host Crypto",
      "Note,  the security of configuring Nx to be used without HostCrypto",
      "needs to be assessed from system security point of view"

      ), True),
]

for e, _, _ in LIST_HOSTCRYPTO:
    pass

LIST_NX_AUTHLIST = [
    ("None", "Use the default session (i.e. session less) login", True),
    ("SIGMA_I_Verifier", "SIGMA I Verifier", True),
    ("SIGMA_I_Prover", "SIGMA I Prover", True),
    ("SYMM_Auth", "Symmetric Authentication", True),
]

for e, _, _ in LIST_NX_AUTHLIST:
    pass

LIST_LOG = [
    ("Default", "Default Logging", True),
    ("Verbose", "Very Verbose logging", True),
    ("Silent", "Totally silent logging", True),

    # #> .. note:: This is NXP internal Option
    ("SeggerRTT", "Segger Real Time Transfer (For Test Automation, NXP Internal)", False),
]

CMAKE_BUILD_TYPE = [
    # See https://cmake.org/cmake/help/latest/variable/CMAKE_BUILD_TYPE.html"
    ("Debug", "For developer", True),
    ("Release", "Optimization enabled and debug symbols removed", True),
    ("RelWithDebInfo", "Optimization enabled but with debug symbols", True),
    ("", "Empty Allowed", True),
    # ("MinSizeRel", "For Developer"),
]

LIST_SECURE_TUNNELING = [
    ("None", "Plain Text", True),
    ("NTAG_AES128_AES256_EV2", "NTAG AES-128 or AES-256 (EV2) Secure Channel. Only valid for Sigma-I. Host supports both AES-128 and AES-256. The secure channel security strength is selected based on the SE configuration.", True),
    ("NTAG_AES128_EV2", "Only NTAG AES-128 (EV2) Secure Channel", True),
    ("NTAG_AES256_EV2", "Only NTAG AES-256 (EV2) Secure Channel", True),
]

for e, _, _ in LIST_SECURE_TUNNELING:
    pass

LIST_HOST_PK_CACHE = [
    ("Disabled", "Host's Public Key And Parent Certificates Cache Disabled", True),
    ("Enabled", "Host's Public Key And Parent Certificates Cache Enabled", True),
]

for e, _, _ in LIST_HOST_PK_CACHE:
    pass

LIST_HOST_CERT_COMPRESS = [
    ("Disabled", "Host's Certificate Compress Disabled", True),
    # ("Enabled", "Host's Certificate Compress Enabled", True),
]

for e, _, _ in LIST_HOST_CERT_COMPRESS:
    pass

LIST_HOST_CURVE = [
    ("NIST_P", "EC Curve NIST-P", True),
    ("BRAINPOOL", "EC Curve Brainpool", True),
]

for e, _, _ in LIST_HOST_CURVE:
    pass

LIST_CERT_REPO_ID = [
    ("0", "Certificate Repository 0", True),
    ("1", "Certificate Repository 1", True),
    ("2", "Certificate Repository 2", True),
    ("3", "Certificate Repository 3", True),
    ("4", "Certificate Repository 4", True),
    ("5", "Certificate Repository 5", True),
    ("6", "Certificate Repository 6", True),
    ("7", "Certificate Repository 7", True),
]

for e, _, _ in LIST_CERT_REPO_ID:
    pass

LIST_CERT_SK_ID = [
    ("0", "Certificate Private KeyId 0", True),
    ("1", "Certificate Private KeyId 1", True),
    ("2", "Certificate Private KeyId 2", True),
    ("3", "Certificate Private KeyId 3", True),
    ("4", "Certificate Private KeyId 4", True),
]

for e, _, _ in LIST_CERT_SK_ID:
    pass

LIST_CA_ROOT_KEY_ID = [
    ("0", "CA Root KeyId 0", True),
    ("1", "CA Root KeyId 1", True),
    ("2", "CA Root KeyId 2", True),
    ("3", "CA Root KeyId 3", True),
    ("4", "CA Root KeyId 4", True),
]

for e, _, _ in LIST_CA_ROOT_KEY_ID:
    pass

LIST_APP_KEY_ID = [
    ("0", "Application KeyId 0", True),
    ("1", "Application KeyId 1", True),
    ("2", "Application KeyId 2", True),
    ("3", "Application KeyId 3", True),
    ("4", "Application KeyId 4", True),
]

for e, _, _ in LIST_APP_KEY_ID:
    pass

LIST_DIVERSIFY_SYMM_AUTH = [
    ("Disabled", "Symm Auth Key Diversification Disabled", True),
    ("Enabled", "Symm Auth Key Diversification Enabled", True),
]

for e, _, _ in LIST_DIVERSIFY_SYMM_AUTH:
    pass

LIST_ENABLE_ALL_AUTH = [
    ("Disabled", "Enable only required authentication code (Based on NXMW_Auth Cmake option)", True),
    ("Enabled", "Enable all authentication code", True),
]

for e, _, _ in LIST_ENABLE_ALL_AUTH:
    pass

LIST_MBEDTLS_ALT = [
    ("SSS", "Use SSS Layer ALT implementation", True),
    ("PSA", "Enable TF-M based on PSA as ALT", True),
    ("None", ("Not using any mbedTLS_ALT", "", "When this is selected, cloud demos can not work with mbedTLS"), True),
]

for e, _, _ in LIST_MBEDTLS_ALT:
    pass

LIST_SA_TYPE = [
    ("A30", "Enable A30 host cert for sigma-I authentication", True),
    ("NTAG_X_DNA", "Enable NTAG_X_DNA host cert for sigma-I authentication", True),
    ("NXP_INT_CONFIG", "Enable NXP_INT_CONFIG host cert for sigma-I authentication", True),
    ("Other", "Enable Other host cert for sigma-I authentication", True),
]

for e, _, _ in LIST_SA_TYPE:
    pass

LIST_CMSIS_Driver = [
    ("Disabled", "CMSIS I2C driver Disabled", True),
    ("Enabled", "CMSIS I2C driver Enabled", True),
]

for e, _, _ in LIST_CMSIS_Driver:
    pass

ALL_VALUES = [
    ("NXMW_NX_Type", "NX_R_DA",
     ("The NX Secure Authenticator Type",
      "You can compile host library for different OS Applications of NX Secure Authenticator listed below.",
      ), LIST_NX_SE_TYPE),
    ("NXMW_Host", "PCWindows",
     ("Host where the software stack is running", "",
      "e.g. Windows, PC Linux, Embedded Linux, Kinetis like embedded platform",
      ), LIST_HOST),
    ("NXMW_SMCOM", "VCOM",
     ("Communication Interface", "",
      "How the host library communicates to the Secure Authenticator.",
      "This may be directly over an I2C interface on embedded platform.",
      "Or sometimes over Remote protocol like JRCP_V1_AM / VCOM from PC."
      ), LIST_SMCOM),
    ("NXMW_HostCrypto", "MBEDTLS",
     ("Counterpart Crypto on Host", "",
      "What is being used as a cryptographic library on the host.",
      "As of now only OpenSSL / mbedTLS is supported",
      ), LIST_HOSTCRYPTO),
    ("NXMW_RTOS", "Default",
     ("Choice of Operating system", "",
      "Default would mean nothing special.",
      "i.e. Without any RTOS on embedded system, or default APIs on PC/Linux",
      ), LIST_RTOS),
    ("NXMW_Auth", "SYMM_Auth",
     ("NX Authentication", "",
      "This settings is used by examples to connect using various options",
      "to authenticate with the Nx SE.",
        "Refer to :numref:`nx-auth-sessions` --- :ref:`nx-auth-sessions` for the combinations of session auth and secure tunneling modes."
      ), LIST_NX_AUTHLIST),
    ("NXMW_Log", "Default",
     ("Logging",
      ), LIST_LOG),
    ("CMAKE_BUILD_TYPE", "Debug",
     ("See https://cmake.org/cmake/help/latest/variable/CMAKE_BUILD_TYPE.html", "",
      "For embedded builds, this choices sets optimization levels.",
      "For MSVC builds, build type is selected from IDE As well",
      ), CMAKE_BUILD_TYPE),
    ("NXMW_Secure_Tunneling", "NTAG_AES128_EV2",
     ("Secure Tunneling(Secure Messaging)", "",
      "Successful Symmetric authentication and SIGMA-I mutual authentication results in the establishment of",
      "session keys and session IVs.",
      "These are used to encrypt and integrity protect the payloads to be exchanged.",
      "Refer to :numref:`nx-auth-sessions` --- :ref:`nx-auth-sessions` for the combinations of session auth and secure tunneling modes."
      ), LIST_SECURE_TUNNELING),
    ("NXMW_Auth_Asymm_Host_PK_Cache", "Enabled",
     ("Host public key cache", "",
      "Support a cache of validated public keys and parent certificates on host.",
      "This is utilized to accelerate protocol execution time by removing the need ",
      "to validate public key and certificates that have been previously verified. Refer to :numref:`nx-auth-sessions` --- :ref:`nx-auth-sessions` for more information.","",
      "Secure authenticator cache is enabled by Cmd.SetConfiguration. Ref to section 4.6.2 for more information."
      ), LIST_HOST_PK_CACHE),
    ("NXMW_Auth_Asymm_Cert_Repo_Id", "0",
     ("Certificate Repository Id", "",
      "Certificate Repository Id is used to identify certificate repository. Used in both personalization and demos with Sigma-I authentication. ",
      "In personalization, it indicates repository to be initialized. In demos, it indicates repository to be used for Sigma-I authentication"
      ), LIST_CERT_REPO_ID),
    ("NXMW_Auth_Asymm_Cert_SK_Id", "0",
     ("Certificate Private Key Id", "",
      "Id of ECC private key associated with this ",
      "repository. Used in personalization for Sigma-I."
      ), LIST_CERT_SK_ID),
    ("NXMW_Auth_Asymm_CA_Root_Key_Id", "0",
     ("Key ID of CA Root Public Key", "",
      "Id of CA root public key associated with this ",
      "repository. Used in personalization for Sigma-I."
      ), LIST_CA_ROOT_KEY_ID),
    ("NXMW_Auth_Symm_App_Key_Id", "0",
     ("application Key ID", "",
      "Indicate application key which is used in symmetric authentication."
      ), LIST_APP_KEY_ID),
    ("NXMW_Auth_Asymm_Host_Curve", "NIST_P",
     ("Host EC domain curve type", "",
      "EC domain curve used for session key generation and ",
      "session signature. Used in demos with Sigma-I authentication."
      ), LIST_HOST_CURVE),
    ("NXMW_OpenSSL", "1_1_1",
     ("For PC, which OpenSSL to pick up", "",
      "On Linux based builds, this option has no impact, because the build system",
      "picks up the default available/installed OpenSSL from the system directly.",
      ), LIST_OPENSSL),
     ("NXMW_MBedTLS", "2_X",
      ("Which MBedTLS version to choose",
       ), LIST_MBEDTLS),
    ("NXMW_Auth_Symm_Diversify", "Disabled",
     ("Diversification of symmetric authentication key", "",
      "When enabled, key used for symmetric authentication is diversification key derived from master key.", "",
      "Otherwise master key is used.",
      ), LIST_DIVERSIFY_SYMM_AUTH),
    ("NXMW_All_Auth_Code", "Disabled",
     ("Enable all authentication code",
      "When enabled, all the authentication code is enabled in nx library.",
      ), LIST_ENABLE_ALL_AUTH),
    ("NXMW_mbedTLS_ALT", "None",
     ("ALT Engine implementation for mbedTLS", "",
      "When set to None, mbedTLS would not use ALT "
      "Implementation to connect to / use Secure Authenticator.",
      "This needs to be set to PSA for PSA example over SSS APIs",
      ), LIST_MBEDTLS_ALT),
    ("NXMW_SA_Type", "A30",
     ("Enable host certificates of A30 for sigma-I Authentication",
      "When Secure Authenticator type is selected, respective host certificates are enabled in nx library.",
      ), LIST_SA_TYPE),
    ("NXMW_CMSIS_DRIVER", "Disabled",
     ("CMSIS I2C driver for communicating with SA", "",
      "CMSIS I2C driver for communicating with SA. (Disabled by Default)",
      ), LIST_CMSIS_Driver),
]

ALL_PATH_VALUES = [
    ("NXMW_AUTH_CERT_INCLUDE_DIR", "C:/nxp/configuration/cert_depth3_PKCS7_rev1",
     ("Host Certificate And Keys Directory", "",
      "Directory which includes host certificate, keypairs, cached certificates "
      )),
]

CMAKE_OPTIONS_CHECK_GROOVY_FOOTER = r'''
// Manual

'''

COPYRIGHT = ["",
             " Copyright 2023-2024 NXP",
             "",
             " SPDX-License-Identifier: BSD-3-Clause",
             "",
             " #############################################################",
             " This file is generated using a script",
             " #############################################################",
             "",
             # " Update `cmake_options_check.py` and `cmake_options_check.py`",
             # " instead of modifying this file.",
             # "",
             ]


class CMakeOptionsValue:  # pylint: disable=too-many-instance-attributes
    """
    Generates skeleton files for various APIs in SSS Layer
    """

    # cm_val : Cmake File object
    # cm_gv : Groovy File object
    def __init__(self, cm_val, cm_gv, cm_rst_v, cm_sh, cm_makin, cm_cmiin):  # pylint: disable=too-many-arguments
        self.cm_gv = cm_gv
        self.cm_val = cm_val
        self.cm_rst_v = cm_rst_v
        self.cm_sh = cm_sh
        self.cm_makin = cm_makin
        self.cm_cmiin = cm_cmiin
        self.prepend = ""
        self.condition = ""

        self.cm_f = cmake_features.CMakeFeatures(
            self.cm_val, self.cm_gv, self.cm_rst_v, self.cm_sh, self.cm_makin, self.cm_cmiin)
        # Header fle generated by cmake_features()
        self.cm_hin = None

    def run(self):
        self.cm_f.open()
        self.cm_hin = self.cm_f.get_h_file()
        for f in (self.cm_sh, self.cm_val, self.cm_makin, self.cm_cmiin):
            if f is not None:
                f.write(("\n#".join(COPYRIGHT)).strip())
                f.write("\n")
        for option, default_value, description, option_list in ALL_VALUES:
            self.write_option(option, default_value, description, option_list)
        for option, default_value, description, option_list in ALL_VALUES:
            self.write_with_cmake_names(option, description, option_list)
        for option, default_value, description, option_list in ALL_VALUES:
            self.write_option_description(option, description, option_list)

        #for option, default_value, description in ALL_PATH_VALUES:
        #    self.write_path_option(option, default_value, description)
        #for option, default_value, description in ALL_PATH_VALUES:
        #    self.write_path_with_cmake_names(option, description)
        #for option, default_value, description in ALL_PATH_VALUES:
        #    self.write_path_option_description(option, description)

        #self.cm_f.write_features()

        for sh in (self.cm_makin, self.cm_cmiin, self.cm_rst_v, self.cm_hin):
            if sh is not None:
                sh.write("\n\n")
        if self.cm_cmiin is not None:
            self.cm_cmiin.write("# ")

        if os.path.exists("cmake_options_check.py"):
            import cmake_options_check  # pylint: disable=import-error

            cmake_options_check.generate_cmake_options_check_file(
                self.cm_hin, self.cm_cmiin)

        if self.cm_hin is not None:
            self.cm_hin.write("/** ")

        for sh in (self.cm_makin, self.cm_cmiin,):
            if sh is not None:
                sh.write("\n# ")
        for f in (self.cm_makin, self.cm_cmiin, self.cm_hin):
            if f is not None:
                f.write("Deprecated items. Used here for backwards compatibility.")
        if self.cm_hin is not None:
            self.cm_hin.write(" */")
        if self.cm_rst_v is not None:
            self.cm_rst_v.write("""
.. _deprecated-defines:

Deprecated Defines
========================

Kept and for time being for backwards compatibility.  They will be removed in
some future release.

""")
        for sh in (self.cm_makin, self.cm_cmiin, self.cm_rst_v, self.cm_hin):
            if sh is not None:
                sh.write("\n\n")
        for old_name, new_name in DEPREATCED_LIST:
            if self.cm_rst_v is not None:
                self.cm_rst_v.write(
                "- ``%s`` is renamed to ``%s``\n" % (old_name, new_name))
            if self.cm_makin is not None:
                self.cm_makin.write("%s := ${%s}\n" % (old_name, new_name))
            if self.cm_cmiin is not None:
                self.cm_cmiin.write("SET(%s %s)\n" % (old_name, new_name))
            if self.cm_hin is not None:
                self.cm_hin.write("#define %s (%s)\n" % (old_name, new_name))

        self.cm_f.close()

    def write_option(self, option, default_value, description, option_list):
        """
        write cmake options
        """
        option_values_internal = []
        option_values_public = []

        for value, _, public in option_list:
            option_values_internal.append(value)
            if self.cm_gv is not None:
                self.cm_gv.write("\ndoWith%s_%s_ON=\" -D%s=%s\"\n" % (
                option, value, option, value))

            if public:
                option_values_public.append(value)
        if default_value not in option_values_internal:
            raise Exception("option_list=%s does not have default_value=%s" % (
                str(option_list), default_value))
        cm_description = description[0]
        if self.cm_val is not None:
            self.cm_val.write(SET_AND_SET_PROPERTY % (
                option, default_value, cm_description, option, ";".join(
                    option_values_internal),
                option, ";".join(option_values_public)))

    def write_path_option(self, option, default_value, description):
        """
        write cmake options
        """
        cm_description = description[0]
        self.cm_val.write(PATH_SET % (
            option, default_value, cm_description))

    @classmethod
    def get_sss_have_opt_val(cls, option, option_value):
        """
        Create Cmake Options
        :return: SSS_HAVE definitions
        """
        uoption = option.upper()
        if uoption.startswith("NXMW_"):
            uoption = uoption[5:]
        uoption_value = option_value.upper()
        return "SSS_HAVE_%s_%s" % (uoption, uoption_value)

    def get_sss_have_opt(cls, option):
        """
        Create Cmake Options
        :return: SSS_HAVE definitions
        """
        uoption = option.upper()
        if uoption.startswith("NXMW_"):
            uoption = uoption[5:]
        return "SSS_HAVE_%s" % (uoption)

    def write_with_cmake_names(self, option, description, option_list):
        """
        write cmake names
        """
        option_values = []
        if self.cm_makin is not None:
            self.cm_makin.write("\n# ")
            self.cm_makin.write("\n# ".join(description, ))
            self.cm_makin.write("\n")
        for value, _, _ in option_list:
            option_values.append(value)
        for option_value in option_values:
            # uoption_value = ""
            # uoption = option.upper()
            # if option_value:
            #     uoption_value = option_value.upper()
            sss_have_opt_val = self.get_sss_have_opt_val(option, option_value)
            if self.cm_makin is not None:
                self.cm_makin.write("%s := ${%s}\n" %
                                (sss_have_opt_val, sss_have_opt_val))
            if self.cm_val is not None:
                self.cm_val.write(
                    "IF(\"${%s}\" STREQUAL \"%s\")\n" % (option, option_value))
                self.cm_val.write("    # SET(With%s_%s ON)\n" %
                                  (option, option_value))
                self.cm_val.write("    SET(%s \"1\")\n" % (sss_have_opt_val,))
                self.cm_val.write("ELSE()\n")
                self.cm_val.write("    # SET(With%s_%s OFF)\n" %
                                  (option, option_value))
                self.cm_val.write("    SET(%s \"0\")\n" % (sss_have_opt_val,))
                self.cm_val.write("ENDIF()\n\n")
        for option_value in option_values[:1]:
            if self.cm_val is not None:
                self.cm_val.write(
                    "IF(\"${%s}\" STREQUAL \"%s\")\n" % (option, option_value))
                self.cm_val.write("    # OK\n")
        for option_value in option_values[1:]:
            if self.cm_val is not None:
                self.cm_val.write(
                    "ELSEIF(\"${%s}\" STREQUAL \"%s\")\n" % (option, option_value))
                self.cm_val.write("    # OK\n")
        if self.cm_val is not None:
            self.cm_val.write("ELSE()\n")
            self.cm_val.write("    MESSAGE(SEND_ERROR \"For '%s' '${%s}' is invalid.\")\n"
                              % (option, option))
            self.cm_val.write("    MESSAGE(STATUS \"Only supported values are '%s'\")\n"
                              % (", ".join(option_values)))
            self.cm_val.write("ENDIF()\n\n")

    def write_path_with_cmake_names(self, option, description):
        """
        write cmake names
        """
        option_values = []
        self.cm_makin.write("\n# ")
        self.cm_makin.write("\n# ".join(description, ))
        self.cm_makin.write("\n")

        sss_have_opt = self.get_sss_have_opt(option)
        self.cm_makin.write("%s := \"${%s}\"\n" % (sss_have_opt, sss_have_opt))
        self.cm_val.write("SET(%s \"${%s}\")\n" % (sss_have_opt, option))

    def write_option_description(self, option, o_description, option_list):
        """
        Cmake option description
        """
        if self.cm_rst_v is not None:
            self.cm_rst_v.write("\n")
            self.cm_rst_v.write(".. _cmake-option-%s:\n\n" % (option,))
            self.cm_rst_v.write("%s\n" % (option,))
            self.cm_rst_v.write("%s\n" % ("=" * (20 + len(option)),))
        if tuple == type(o_description):
            sh_description = "\n# ".join(o_description)
            rst_description = "\n    ".join(o_description)
        else:
            sh_description = o_description
            rst_description = o_description
        if self.cm_cmiin is not None:
            self.cm_cmiin.write("\n# %s\n" % (sh_description,))
        if self.cm_sh is not None:
            self.cm_sh.write("\n\n### %s : %s\n" % (option, sh_description))
        if self.isHFileOption(option):
            if self.cm_hin is not None:
                self.cm_hin.write("\n\n/** %s : %s\n */\n" %
                    (option, sh_description.replace("\n#", "\n *")))
        if self.cm_rst_v is not None:
            self.cm_rst_v.write("\n")
            self.cm_rst_v.write(".. option:: %s\n" % (option,))
            self.cm_rst_v.write("\n")
            self.cm_rst_v.write("    %s\n" % (rst_description,))
            self.cm_rst_v.write("\n")
        for option_value, o_value_description, public in option_list:
            if public:
                if self.cm_rst_v is not None:
                    self.cm_rst_v.write("    ``-D%s=%s``" %
                                        (option, option_value,))
            if tuple == type(o_value_description):
                sh_value_description = "\n# ".join(o_value_description)
                rst_value_description = "\n        ".join(o_value_description)
                if not public:
                    sh_value_description += "\n# NXP Internal\n"
                if self.cm_sh is not None:
                    self.cm_sh.write("\n#")
                    self.cm_sh.write(sh_value_description)
                    self.cm_sh.write("\n")
            else:
                sh_value_description = o_value_description
                rst_value_description = o_value_description
            for er in (self.cm_makin, self.cm_cmiin):
                if er is not None:
                    if sh_value_description:
                        er.write("\n# ")
                        er.write(sh_value_description)
                        er.write("\n")

            if public:
                if rst_value_description:
                    if self. cm_rst_v is not None:
                        self.cm_rst_v.write(": %s" % (rst_value_description,))
            if self.cm_rst_v is not None:
                self.cm_rst_v.write("\n\n")
            if tuple == type(o_value_description):
                if self.cm_sh is not None:
                    self.cm_sh.write("\ndo%s_%s_ON=\"-D%s=%s\"\n" %
                                 (option, option_value, option, option_value))
            else:
                if self.cm_sh is not None:
                    self.cm_sh.write("\ndo%s_%s_ON=\"-D%s=%s\" #%s\n" % (option,
                                                                     option_value,
                                                                     option,
                                                                     option_value,
                                                                     sh_value_description))
            if option_value:
                sss_have_opt_val = self.get_sss_have_opt_val(
                    option, option_value)
                if self.isHFileOption(option):
                    if self.cm_hin is not None:
                        self.cm_hin.write("\n/** %s */\n" %
                                          sh_value_description.replace("\n#", "\n *"))
                        self.cm_hin.write("#cmakedefine01 %s\n" %
                                          (sss_have_opt_val,))
                if self.cm_cmiin is not None:
                    self.cm_cmiin.write("SET(%s ${%s})\n" % (
                        sss_have_opt_val, sss_have_opt_val))
                if self.cm_makin is not None:
                    self.cm_makin.write("%s := ${%s}\n" % (
                        sss_have_opt_val, sss_have_opt_val))
        if self.isHFileOption(option):
            if self.cm_hin is not None:
                self.cm_hin.write("\n#if (( 0                             \\\n")
            for option_value, _, _ in option_list:
                sss_have_opt_val = self.get_sss_have_opt_val(
                    option, option_value)
                if self.cm_hin is not None:
                    self.cm_hin.write("    + %-30s \\\n" % (sss_have_opt_val))
            if self.cm_hin is not None:
                self.cm_hin.write("    ) > 1)\n")
                self.cm_hin.write(
                    "#        error \"Enable only one of '%s'\"\n" % (option,))
                self.cm_hin.write("#endif\n\n")
                self.cm_hin.write("\n#if (( 0                             \\\n")
            for option_value, _, _ in option_list:
                sss_have_opt_val = self.get_sss_have_opt_val(
                    option, option_value)
                if self.cm_hin is not None:
                    self.cm_hin.write("    + %-30s \\\n" % (sss_have_opt_val))
            if self.cm_hin is not None:
                self.cm_hin.write("    ) == 0)\n")
                self.cm_hin.write(
                    "#        error \"Enable at-least one of '%s'\"\n" % (option,))
                self.cm_hin.write("#endif\n\n")

    def write_path_option_description(self, option, o_description):
        """
        Cmake option description
        """
        self.cm_rst_v.write("\n")
        self.cm_rst_v.write(".. _cmake-option-%s:\n\n" % (option,))
        self.cm_rst_v.write("%s\n" % (option,))
        self.cm_rst_v.write("%s\n" % ("=" * (20 + len(option)),))
        if tuple == type(o_description):
            sh_description = "\n# ".join(o_description)
            rst_description = "\n    ".join(o_description)
        else:
            sh_description = o_description
            rst_description = o_description
        self.cm_cmiin.write("\n# %s\n" % (sh_description,))
        # self.cm_sh.write("\n\n### %s : %s\n" % (option, sh_description))
        if self.isHFileOption(option):
            self.cm_hin.write("\n\n/** %s : %s\n */\n" %
                              (option, sh_description.replace("\n#", "\n *")))
        self.cm_rst_v.write("\n")
        self.cm_rst_v.write(".. option:: %s\n" % (option,))
        self.cm_rst_v.write("\n")
        self.cm_rst_v.write("    %s\n" % (rst_description,))
        self.cm_rst_v.write("\n")

        self.cm_rst_v.write("    ``-D%s=[Path]``" % (option, ))
        self.cm_rst_v.write("\n\n")

        sss_have_opt = self.get_sss_have_opt(option)
        self.cm_cmiin.write("SET(%s \"${%s}\")\n" % (
            sss_have_opt, sss_have_opt))

        self.cm_hin.write("#cmakedefine %s \"${%s}\"\n" % (
            sss_have_opt, sss_have_opt))

    def mark_as_depreceted(self, key_words):
        for key_word in key_words:
            self.cm_val.write("\n")
            self.cm_val.write("IF(%s)\n" % (key_word,))
            self.cm_val.write(
                '    MESSAGE(WARNING "Keyword \'%s\' is deprecated.")\n' % (key_word,))
            self.cm_val.write("ENDIF()\n")

    def isHFileOption(self, option):
        if option in (
                "CMAKE_BUILD_TYPE",
        ):
            return False
        return True

def generate_cmake_options_value_files():
    """
    Generate cmake options value files
    """
    cm_gv = None
    if os.path.exists("jenkins/cmake_options_check.groovy"):
        cm_gv = open("jenkins/cmake_options_check.groovy", "w")
    cm_val = None
    if os.path.exists("cmake_options_value.cmake"):
        cm_val = open("cmake_options_value.cmake", "w")
    cm_rst_v = None
    if os.path.exists("cmake_options_values.rst.txt"):
        cm_rst_v = open("cmake_options_values.rst.txt", "w")
    cm_sh = None
    if os.path.exists("cmake_options.sh"):
        cm_sh = open("cmake_options.sh", "w")
    cm_makin = None
    if os.path.exists("cmake_options.mak.in"):
        cm_makin = open("cmake_options.mak.in", "w")
    cm_cmiin = None
    if os.path.exists("cmake_options_installed.cmake.in"):
        cm_cmiin = open("cmake_options_installed.cmake.in", "w")

    cm_check = CMakeOptionsValue(
        cm_val, cm_gv, cm_rst_v, cm_sh, cm_makin, cm_cmiin)
    cm_check.run()
    CMakeOptionsFileToRST(cm_gv, cm_sh).run()
    if cm_gv is not None:
        cm_gv.write(CMAKE_OPTIONS_CHECK_GROOVY_FOOTER)
    if cm_gv is not None:
        cm_gv.write("\nreturn this;\n")

    for k in (cm_gv, cm_val, cm_rst_v, cm_sh):
        if k is not None:
            k.close()

class CMakeOptionsFileToRST:
    """
    Write CMake options to RST file.
    """

    def __init__(self, cm_gv, cm_sh):
        self.to_write = []
        self.cm_gv = cm_gv
        self.cm_sh = cm_sh
        self.cm_cmake = None
        self.cm_rst = None

    def run(self):
        self.cm_cmake = open("cmake_options.cmake")
        self.cm_rst = open("cmake_options.rst", "w")
        self.cmake_to_rst()
        self.cm_cmake.close()
        self.cm_rst.close()

    def cmake_to_rst(self):
        """
        write cmake to rst
        """
        for l in self.cm_cmake:
            if l.startswith("##"):
                pass
            elif l.startswith("# "):
                if self.cm_rst is not None:
                    self.cm_rst.write(l[2:])
            elif l.strip() == "#":
                if self.cm_rst is not None:
                    self.cm_rst.write("\n")
            elif l.startswith("#> "):
                if self.cm_rst is not None:
                    self.to_write.append(l[3:])
            elif l.startswith("#"):
                if self.cm_rst is not None:
                    self.cm_rst.write(l[1:])
            elif l.startswith("OPTION("):
                self.cmake_option_to_rst(l)
            elif l.strip() == "":
                if self.cm_rst is not None:
                    self.cm_rst.write("\n")
            else:
                pass

    def cmake_option_to_rst(self, op_line):
        """
        write cmake options to rst
        """
        assert op_line.startswith("OPTION(")
        (eoption, description, evalue) = op_line.split('"')
        option = eoption[7:].strip()
        if "NXPInternal" == option:  # pylint: disable=misplaced-comparison-constant
            value = "OFF. (ON only within NXP)"
        elif "ON" in evalue:
            value = "ON"
        elif "OFF" in evalue:
            value = "OFF"
        else:
            value = "Unknown"

        if self.cm_rst is not None:
            self.cm_rst.write(".. option:: %s\n\n" % (option,))
            self.cm_rst.write("    - %s" % (description,))
            self.cm_rst.write("\n")
            self.cm_rst.write("    - Default is %s\n" % (value,))
        if self.to_write:
            if self.cm_rst is not None:
                self.cm_rst.write("\n")
            while self.to_write:
                v = self.to_write.pop().strip()
                if v.startswith(":") or v.startswith("."):
                    if self.cm_rst is not None:
                        self.cm_rst.write("    %s" % (v,))
                else:
                    if self.cm_rst is not None:
                        self.cm_rst.write("    - %s" % (v,))
            if self.cm_rst is not None:
                self.cm_rst.write("\n")
        if self.cm_rst is not None:
            self.cm_rst.write("\n")
            self.cm_rst.write("\n")
        if self.cm_gv is not None:
            self.cm_gv.write('do%s_ON="-D%s=ON"\n' % (option, option,))
            self.cm_gv.write('do%s_OFF="-D%s=OFF"\n' % (option, option,))
        if self.cm_sh is not None:
            self.cm_sh.write("\n# %s\n" % description)
            self.cm_sh.write('do%s_ON="-D%s=ON"\n' % (option, option,))
            self.cm_sh.write('do%s_OFF="-D%s=OFF"\n' % (option, option,))


SET_AND_SET_PROPERTY = """
SET(
    %s
    "%s"
    CACHE
        STRING
        "%s"
)

IF(NXPInternal)
    SET_PROPERTY(
        CACHE %s
        PROPERTY
            STRINGS
            "%s;"
    )
ELSE()
    SET_PROPERTY(
        CACHE %s
        PROPERTY
            STRINGS
            "%s;"
    )
ENDIF()
"""

PATH_SET = """
SET(
    %s
    "%s"
    CACHE
        PATH
        "%s"
)
"""


def main():
    script_root_dir = os.path.dirname(os.path.realpath(__file__))
    if os.path.abspath(os.curdir) != script_root_dir:
        os.chdir(script_root_dir)
    generate_cmake_options_value_files()


if __name__ == "__main__":
    main()
