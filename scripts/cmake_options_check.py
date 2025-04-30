# Copyright 2022-2023 NXP
#
# NXP Internal. Not to be shared outside NXP
#

"""

Check Options

"""

import cmake_options  # pylint: disable=import-error

__VERSION__ = "2019.07.28_00"

IMPL_TYPES = ["sscp", "se05x", "mbedtls", "openssl"]

LIST_NX_TYPE = ["NX_R_DA", "NX_PICC"]

LIST_SMCOM_EMBEDDED = ["SCI2C", "T1oI2C_GP1_0", ]

LIST_SMCOM_EMBEDDED_K4F =  LIST_SMCOM_EMBEDDED + [ "PN7150", ]

LIST_MBEDTLS_ALT = ["SSS"]

LIST_HOST_CRYPTO_ANY = [
    "MBEDTLS",
    "OPENSSL",
    "USER",
]

LIST_NX_VERSIONS_ALL = cmake_options.LIST_NX_VERSIONS_ALL


LIST_EMBEDDED_PLATFORM = [
    "LPCXPRESSO55S",
    "FRDMMCXA153",
    "FRDMMCXN947",
]


class WithCondition:
    """docstring for condition"""

    def __init__(self, option_check, if_condition):
        self.option_check = option_check
        self.if_condition = if_condition
        self.old_prepend = self.option_check.prepend
        self.old_condition = self.option_check.condition
        self.option_check.prepend = self.option_check.prepend + "    "
        self.option_check.condition = "[for %s]" % (if_condition,)

    def __enter__(self):
        self.option_check.cm.write("\n%sIF(%s)\n" % (
            self.old_prepend,
            self.if_condition
        ))
        return self.option_check

    def __exit__(self, *args):
        self.option_check.cm.write("%sENDIF(%s)\n" % (
            self.old_prepend,
            self.if_condition
        ))
        self.option_check.prepend = self.old_prepend
        self.option_check.condition = self.old_condition


class CMakeOptionsCheck:
    """
    Generates skeleton files for various APIs in SSS Layer
    """

    # CM : Cmake File object
    # GV : Groovy File object
    def __init__(self, cm, cm_hin, cm_cmiin):
        self.cm = cm
        self.prepend = ""
        self.condition = ""
        self.cm_hin = cm_hin
        self.cm_cmiin = cm_cmiin

    def addVersionInformation(self):
        """
        Add version information
        """
        self.cm_hin.write("\n/* Version checks GTE - Greater Than Or Equal To */\n")
        for k in self.cm, self.cm_cmiin:
            k.write("\n# Version checks GTE - Greater Than Or Equal To\n")
        self.cm_hin.write("#if SSS_HAVE_NX_TYPE\n")
        for k in self.cm, self.cm_cmiin:
            k.write("IF(SSS_HAVE_NX_TYPE)\n")
        for i1 in range(len(LIST_NX_VERSIONS_ALL) - 1, -1, -1):
            self.cm_hin.write("#    if SSS_HAVE_NX_VER_%s\n" % (LIST_NX_VERSIONS_ALL[i1],))
            for k in self.cm, self.cm_cmiin:
                k.write("    IF(SSS_HAVE_NX_VER_%s)\n" % (LIST_NX_VERSIONS_ALL[i1]))
            for i2 in range(len(LIST_NX_VERSIONS_ALL) - 1, i1, -1):
                self.cm_hin.write(
                    "#        define SSS_HAVE_NX_VER_GTE_%s 0\n" % (LIST_NX_VERSIONS_ALL[i2],))
                for k in self.cm, self.cm_cmiin:
                    k.write("         SET(SSS_HAVE_NX_VER_GTE_%s OFF)\n" % (LIST_NX_VERSIONS_ALL[i2],))
            for i2 in range(i1, -1, -1):
                self.cm_hin.write(
                    "#        define SSS_HAVE_NX_VER_GTE_%s 1\n" % (LIST_NX_VERSIONS_ALL[i2],))
                for k in self.cm, self.cm_cmiin:
                    k.write("         SET(SSS_HAVE_NX_VER_GTE_%s ON)\n" % (LIST_NX_VERSIONS_ALL[i2],))
            self.cm_hin.write("#    endif /* SSS_HAVE_NX_VER_%s */\n" % (LIST_NX_VERSIONS_ALL[i1],))
            for k in self.cm, self.cm_cmiin:
                k.write("    ENDIF()\n\n")
        self.cm_hin.write("#else //SSS_HAVE_NX_TYPE\n")
        for k in self.cm, self.cm_cmiin:
            k.write("ELSE() #SSS_HAVE_NX_TYPE\n")
        for e in LIST_NX_VERSIONS_ALL:
            self.cm_hin.write("#   define SSS_HAVE_NX_VER_GTE_%s 0\n" % (e,))
            for k in self.cm, self.cm_cmiin:
                k.write("     SET(SSS_HAVE_NX_VER_GTE_%s OFF)\n" % (e,))
        self.cm_hin.write("#endif // SSS_HAVE_NX_TYPE\n")
        for k in self.cm, self.cm_cmiin:
            k.write("ENDIF() #SSS_HAVE_NX_TYPE\n")

    def run(self):
        self.cm.write(("\n#".join(cmake_options.COPYRIGHT)).strip())
        self.cm.write("\n")
        self.set_when_either_of("SSS_HAVE_NX_TYPE_", LIST_NX_TYPE, "SSS_HAVE_NX_TYPE")
        self.set_when_either_of("SSS_HAVE_MBEDTLS_ALT_", LIST_MBEDTLS_ALT, "SSS_HAVE_MBEDTLS_ALT")
        self.set_when_either_of("SSS_HAVE_HOSTCRYPTO_", LIST_HOST_CRYPTO_ANY, "SSS_HAVE_HOSTCRYPTO_ANY")

        self.set_when_either_of("SSS_HAVE_HOST_", LIST_EMBEDDED_PLATFORM, "SSS_HAVE_HOST_EMBEDDED")

        with WithCondition(self, "SSS_HAVE_HOST_FRDMK64F AND SSS_HAVE_NX_TYPE") as emb:
            emb.either_of("SSS_HAVE_SMCOM_", LIST_SMCOM_EMBEDDED_K4F)  # pylint: disable=no-member
        with WithCondition(self, "SSS_HAVE_HOST_EVKMIMXRT1060 AND SSS_HAVE_NX_TYPE") as emb:
            emb.either_of("SSS_HAVE_SMCOM_", LIST_SMCOM_EMBEDDED)  # pylint: disable=no-member

        self.mark_as_depreceted([
        ])
        for old_name, new_name in cmake_options.DEPREATCED_LIST:
            self.cm.write("SET(%s ${%s})\n" % (old_name, new_name))

        #self.addVersionInformation()

    def write_values(self, prefix, impl_types):
        for impl_type in impl_types:
            uhave_type = "%s_%s" % (prefix.upper(), impl_type.upper())
            have_type = "%s%s" % (prefix, impl_type)
            value_type = "SSS_HAVE_%s" % (uhave_type,)
            self.cm.write("\n")
            self.cm.write("IF(%s)\n" % (have_type,))
            self.cm.write("    SET(%s \"1\")\n" % (value_type,))
            self.cm.write("ELSE()\n")
            self.cm.write("    SET(%s \"0\")\n" % (value_type,))
            self.cm.write("ENDIF()\n")

    def only_one_of(self, prefix, impl_types):
        have_types = []
        for impl_type in impl_types:
            have_type = "%s%s" % (prefix, impl_type)
            have_types.append(have_type)
        for i in range(len(have_types)):  # pylint: disable=consider-using-enumerate
            for k in range(i + 1, len(have_types)):
                t1 = have_types[i]
                t2 = have_types[k]
                if not self.condition:
                    self.cm.write("\n")
                self.cm.write("%sIF(%s AND %s)\n" % (self.prepend, t1, t2))
                self.cm.write('%s    MESSAGE(FATAL_ERROR '
                              '"Can not set both \'%s\' AND \'%s\'%s")\n'
                              % (self.prepend, t1, t2, self.condition))
                self.cm.write("%sENDIF()\n" % (self.prepend,))
        if prefix[-1] == "_":
            prefix = prefix[:-1]

    def set_when_either_of(self, prefix, impl_types, new_variable):
        have_types = []
        for impl_type in impl_types:
            have_type = "%s%s" % (prefix, impl_type)
            have_types.append(have_type)
        sss_have_types = []
        for impl_type in impl_types:
            sss_have_type = "%s%s" % (prefix, impl_type.upper())
            sss_have_types.append(sss_have_type)
        if len(have_types) > 4:
            self.cm.write("%sIF(\n    %s\n)\n"
                          % (self.prepend, "\n     OR ".join(have_types)))
        else:
            self.cm.write("%sIF(%s)\n" % (self.prepend,
                                          " OR ".join(have_types)))
        self.cm.write("%s    SET(%s ON)\n" % (self.prepend, new_variable))
        self.cm.write("%sELSE()\n" % (self.prepend,))
        self.cm.write("%s    SET(%s OFF)\n" % (self.prepend, new_variable))
        self.cm.write("%sENDIF()\n" % (self.prepend,))
        self.cm_hin.write("#define %s \\\n (%s)\n\n" % (new_variable, " | ".join(sss_have_types)))
        # self.cm.write('%sMESSAGE(STATUS "%s = ${%s}")\n' % (self.prepend, new_variable, new_variable))

    def either_of(self, prefix, impl_types):
        have_types = []
        for impl_type in impl_types:
            have_type = "%s%s" % (prefix, impl_type.upper())
            have_types.append(have_type)
        if not self.condition:
            self.cm.write("\n")
        if len(have_types) > 4:
            self.cm.write("%sIF(\n    NOT\n    (%s\n     )\n)\n"
                          % (self.prepend, "\n     OR ".join(have_types)))
        else:
            self.cm.write("%sIF(NOT (%s))\n" % (self.prepend,
                                                " OR ".join(have_types)))
        if len(" ".join(have_types)) > 40:
            self.cm.write('%s    MESSAGE(\n%s        FATAL_ERROR\n' % (
                self.prepend,
                self.prepend,
            ))
            self.cm.write('%s            "One of \'%s\' must be set%s."\n%s    )\n' % (
                self.prepend,
                ", ".join(have_types),
                self.condition,
                self.prepend,
            ))
        else:
            self.cm.write('%s    MESSAGE(FATAL_ERROR "One of \'%s\' must be set%s.")\n' % (
                self.prepend,
                ", ".join(have_types),
                self.condition,
            ))
        self.cm.write("%sENDIF()\n" % (self.prepend,))

    def mark_as_depreceted(self, key_words):
        for key_word in key_words:
            self.cm.write("\n")
            self.cm.write("IF(%s)\n" % (key_word,))
            self.cm.write('    MESSAGE(WARNING "Keyword \'%s\' is deprecated.")\n'
                          % (key_word,))
            self.cm.write("ENDIF()\n")


def generate_cmake_options_check_file(cm_hin, cm_cmiin):  # pylint: disable=consider-using-with
    """
    This function generate cmake options check file
    """
    cm = open("cmake_options_check.cmake", "w")
    cm_check = CMakeOptionsCheck(cm, cm_hin, cm_cmiin)
    cm_check.run()
    for k in (cm,):
        k.close()


# def main():
#     script_root_dir = os.path.dirname(os.path.realpath(__file__))
#     if os.path.abspath(os.curdir) != script_root_dir:
#         os.chdir(script_root_dir)
#     generate_cmake_options_check_file()


if __name__ == '__main__':
    cmake_options.main()
