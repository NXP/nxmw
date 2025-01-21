#
# Copyright 2023 NXP
# SPDX-License-Identifier: BSD-3-Clause
#

ADD_SUBDIRECTORY(ex_sdm_provision)

IF (SSS_HAVE_AUTH_NONE AND SSS_HAVE_HOSTCRYPTO_ANY)
    ADD_SUBDIRECTORY(ex_sdm_file_read)
    ADD_SUBDIRECTORY(ex_sdm_mac)
ENDIF()
