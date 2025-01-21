#
# Copyright 2019 NXP
# SPDX-License-Identifier: BSD-3-Clause
#

"""
# Used by cmake_options.py
"""

AUTH_LAYERS = (
    ("AUTH_AC_BITMAP", "CA Root Key Access Condition Bitmap"),
)

# High level crypto operations
# For all LAYERS
AUTH_COMMON_FTR_L1 = (
    ("Bit00", "Bit0"),
    ("Bit01", "Bit1"),
    ("Bit02", "Bit2"),
    ("Bit03", "Bit3"),
    ("Bit04", "Bit4"),
    ("Bit05", "Bit5"),
    ("Bit06", "Bit6"),
    ("Bit07", "Bit7"),
    ("Bit08", "Bit8"),
    ("Bit09", "Bit9"),
    ("Bit10", "Bit10"),
    ("Bit11", "Bit11"),
    ("Bit12", "Bit12"),
)


NOT_AVAILABLE = {

}

FSL_FTR_START = r"""/*
 *
 * Copyright 2023 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef SSS_APIS_INC_FSL_SSS_FTR_H_
#define SSS_APIS_INC_FSL_SSS_FTR_H_

/* ************************************************************************** */
/* Defines                                                                    */
/* ************************************************************************** */

/* clang-format off */

"""

FSL_FTR_END = r"""

/* ========= Calculated values : START ====================== */

/* Should we expose, SSS APIs */
#define SSS_HAVE_SSS ( 0             \
    + SSS_HAVE_NX_TYPE               \
    + SSS_HAVE_HOSTCRYPTO_OPENSSL    \
    + SSS_HAVE_HOSTCRYPTO_MBEDTLS    \
    )

#if SSS_HAVE_AUTH_SYMM_APP_KEY_ID_0
#   define SSS_HAVE_AUTH_SYMM_APP_KEY_ID 0
#elif SSS_HAVE_AUTH_SYMM_APP_KEY_ID_1
#   define SSS_HAVE_AUTH_SYMM_APP_KEY_ID 1
#elif SSS_HAVE_AUTH_SYMM_APP_KEY_ID_2
#   define SSS_HAVE_AUTH_SYMM_APP_KEY_ID 2
#elif SSS_HAVE_AUTH_SYMM_APP_KEY_ID_3
#   define SSS_HAVE_AUTH_SYMM_APP_KEY_ID 3
#else
#   define SSS_HAVE_AUTH_SYMM_APP_KEY_ID 4
#endif

#if SSS_HAVE_AUTH_ASYMM_CERT_REPO_ID_0
#   define SSS_AUTH_ASYMM_CERT_REPO_ID 0
#elif SSS_HAVE_AUTH_ASYMM_CERT_REPO_ID_1
#   define SSS_AUTH_ASYMM_CERT_REPO_ID 1
#elif SSS_HAVE_AUTH_ASYMM_CERT_REPO_ID_2
#   define SSS_AUTH_ASYMM_CERT_REPO_ID 2
#elif SSS_HAVE_AUTH_ASYMM_CERT_REPO_ID_3
#   define SSS_AUTH_ASYMM_CERT_REPO_ID 3
#elif SSS_HAVE_AUTH_ASYMM_CERT_REPO_ID_4
#   define SSS_AUTH_ASYMM_CERT_REPO_ID 4
#elif SSS_HAVE_AUTH_ASYMM_CERT_REPO_ID_5
#   define SSS_AUTH_ASYMM_CERT_REPO_ID 5
#elif SSS_HAVE_AUTH_ASYMM_CERT_REPO_ID_6
#   define SSS_AUTH_ASYMM_CERT_REPO_ID 6
#else
#   define SSS_AUTH_ASYMM_CERT_REPO_ID 7
#endif

#if SSS_HAVE_AUTH_ASYMM_CERT_SK_ID_0
#   define SSS_AUTH_ASYMM_CERT_SK_ID 0
#elif SSS_HAVE_AUTH_ASYMM_CERT_SK_ID_1
#   define SSS_AUTH_ASYMM_CERT_SK_ID 1
#elif SSS_HAVE_AUTH_ASYMM_CERT_SK_ID_2
#   define SSS_AUTH_ASYMM_CERT_SK_ID 2
#elif SSS_HAVE_AUTH_ASYMM_CERT_SK_ID_3
#   define SSS_AUTH_ASYMM_CERT_SK_ID 3
#else
#   define SSS_AUTH_ASYMM_CERT_SK_ID 4
#endif

#if SSS_HAVE_AUTH_ASYMM_CA_ROOT_KEY_ID_0
#   define SSS_AUTH_ASYMM_CA_ROOT_KEY_ID 0
#elif SSS_HAVE_AUTH_ASYMM_CA_ROOT_KEY_ID_1
#   define SSS_AUTH_ASYMM_CA_ROOT_KEY_ID 1
#elif SSS_HAVE_AUTH_ASYMM_CA_ROOT_KEY_ID_2
#   define SSS_AUTH_ASYMM_CA_ROOT_KEY_ID 2
#elif SSS_HAVE_AUTH_ASYMM_CA_ROOT_KEY_ID_3
#   define SSS_AUTH_ASYMM_CA_ROOT_KEY_ID 3
#else
#   define SSS_AUTH_ASYMM_CA_ROOT_KEY_ID 4
#endif

#   define SSS_AUTH_CERT_AC_MAP  ( \
 (NXMW_AUTH_AC_BITMAP_Bit12<<12) \
 | (NXMW_AUTH_AC_BITMAP_Bit11<<11) \
 | (NXMW_AUTH_AC_BITMAP_Bit10<<10) \
 | (NXMW_AUTH_AC_BITMAP_Bit09<<9) \
 | (NXMW_AUTH_AC_BITMAP_Bit08<<8) \
 | (NXMW_AUTH_AC_BITMAP_Bit07<<7) \
 | (NXMW_AUTH_AC_BITMAP_Bit06<<6) \
 | (NXMW_AUTH_AC_BITMAP_Bit05<<5) \
 | (NXMW_AUTH_AC_BITMAP_Bit04<<4) \
 | (NXMW_AUTH_AC_BITMAP_Bit03<<3) \
 | (NXMW_AUTH_AC_BITMAP_Bit02<<2) \
 | (NXMW_AUTH_AC_BITMAP_Bit01<<1) \
 | (NXMW_AUTH_AC_BITMAP_Bit00<<0) \
 )

/* ========= Calculated values : END ======================== */

/* clang-format on */

#endif /* SSS_APIS_INC_FSL_SSS_FTR_H_ */
"""


class CMakeFeatures:  # pylint: disable=too-few-public-methods
    """
    Generates skeleton files for various features for SSS Layer
    """

    def __init__(self, cm_val, cm_gv, cm_rst_v, cm_sh, cm_makin, cm_cmiin):  # pylint: disable=too-many-arguments
        self.cm_val = cm_val
        self.cm_rst_v = cm_rst_v
        self.fsl_f_in = None
        self.cm_gv = cm_gv
        self.cm_sh = cm_sh
        self.cm_makin = cm_makin
        self.cm_cmiin = cm_cmiin

    def open(self):  # pylint: disable=unspecified-encoding
        """
        perform open operation
        :return: None
        """

        self.fsl_f_in = open("../lib/sss/inc/fsl_sss_ftr.h.in", "w")
        self.fsl_f_in.write(FSL_FTR_START)
        self.fsl_f_in.write("\n/* # CMake Features : Start */\n")

    def get_h_file(self):
        return self.fsl_f_in

    def close(self):
        """
        perform close operation
        :return: None
        """
        self.fsl_f_in.write("\n/* # CMake Features : END */\n")
        self.fsl_f_in.write(FSL_FTR_END)
        self.fsl_f_in.close()

    def write_features(self):
        """
        Add cmake options
        :return: None
        """
        self.cm_rst_v.write(RSTV_HEADER_CMAKE_OPTIONS)
        self._add_values()
        self._set_composite_values()

    def _add_values(self):
        self.cm_val.write("\n# Add Options\n")
        self._header_log("Feature selection/values")
        for l, l_desc in AUTH_LAYERS:
            self.cm_val.write("# %s\n" % (l,))
            for e, e_desc in AUTH_COMMON_FTR_L1:
                self._add_plain_entry("NXMW", e, l, e_desc, l_desc)

    def _header_log(self, text):
        self.fsl_f_in.write("\n")
        self.fsl_f_in.write("/* %s *\n" % ("=" * 70,))
        buffer_text = "=" * (70 - 4 - len(text))
        self.fsl_f_in.write(" * == %s %s *\n" % (text, buffer_text))
        self.fsl_f_in.write(" * %s */\n" % ("=" * 70,))
        self.fsl_f_in.write("\n")

    def _set_composite_values(self):
        self.cm_val.write("\n# Add Values\n")
        self._header_log("Computed Options")

    def _set_composite_plain_entry(self, e, se_desc):
        options = []
        for l, _ in LAYERS:
            options.append("SSSFTR_%s_%s" % (l, e))
        self._set_or_options(options, e, se_desc)

    def _set_or_options(self, options, e, se_desc):
        self.cm_val.write("# %s\n" % (se_desc,))
        self.cm_val.write("IF(")
        self.cm_val.write(" OR ".join(options))
        self.cm_val.write(")\n")
        self.cm_val.write("    SET(SSSFTR_%s ON)\n" % (e,))
        self.cm_val.write("ELSE()\n")
        self.cm_val.write("    SET(SSSFTR_%s OFF)\n" % (e,))
        self.cm_val.write("ENDIF()\n")
        self.fsl_f_in.write("/** %s */\n" % (se_desc,))
        self.fsl_f_in.write("#define SSSFTR_%s %s(%s)\n" % (
            e, " " * (17 - len(e)), " + ".join(options)))

    @classmethod
    def _rstrip_string(cls, s):
        sa = s.split('\n')
        sar = [line.rstrip() for line in sa]
        sars = '\n'.join(sar)
        return sars

    def _add_plain_entry(self, prefix, e, l, full_description, p_desc=None, pp_desc=None):  # pylint: disable=too-many-arguments
        sssftr = "%s_%s_%s" % (prefix, l, e)
        if sssftr in NOT_AVAILABLE:
            default_value = "OFF"
        else:
            default_value = "ON"
        if tuple == type(full_description):
            short_description = full_description[0]
            rst_description = self._rstrip_string("\n    ".join(full_description))
            sh_description = self._rstrip_string("\n# ".join(full_description))
            c_description = self._rstrip_string("\n * ".join(full_description))

        else:
            short_description = full_description
            rst_description = full_description
            sh_description = full_description
            c_description = full_description
        if p_desc:
            short_description = "%s : %s" % (p_desc, short_description)
            rst_description = "%s : %s" % (p_desc, rst_description)
            sh_description = "%s : %s" % (p_desc, sh_description)
            c_description = "%s : %s" % (p_desc, c_description)
        if pp_desc:
            short_description = "%s : %s" % (pp_desc, short_description)
            rst_description = "%s : %s" % (pp_desc, rst_description)
            sh_description = "%s : %s" % (pp_desc, sh_description)
            c_description = "%s : %s" % (pp_desc, c_description)

        self.cm_val.write("SET(%s %s\n" % (sssftr, default_value))
        self.cm_val.write("    CACHE BOOL\n")
        self.cm_val.write("    \"%s\")\n" % (short_description,))
        self.cm_rst_v.write(".. option:: %s\n" % (sssftr,))
        self.cm_rst_v.write("\n")
        self.cm_rst_v.write("    %s\n\n" % (rst_description,))
        self.fsl_f_in.write("\n/** %s */\n" % (c_description,))
        self.cm_gv.write("\ndo%s_ON= '-D%s=ON'\n" % (sssftr, sssftr))
        self.cm_gv.write("\ndo%s_OFF= '-D%s=OFF'\n" % (sssftr, sssftr))
        for e in (self.cm_sh, self.cm_makin, self.cm_cmiin):  # pylint: disable=redefined-argument-from-local
            e.write("# %s\n" % (sh_description,))
        self.cm_sh.write("\ndo%s_ON=\"-D%s=ON\"\n" % (sssftr, sssftr))
        self.cm_makin.write("%s := ${%s}\n" % (sssftr, sssftr))
        self.cm_cmiin.write("SET(%s ${%s})\n" % (sssftr, sssftr))
        self.cm_sh.write("\ndo%s_OFF=\"-D%s=OFF\"\n" % (sssftr, sssftr))
        self.fsl_f_in.write("#cmakedefine01 %s\n" % (sssftr,))


RSTV_HEADER_CMAKE_OPTIONS = r"""

.. _sssftr-control:

Access condition bitmap for CA root key
=======================================

"""

if __name__ == '__main__':
    import cmake_options  # pylint: disable=import-error

    cmake_options.main()
