#
# Copyright 2023-2025 NXP
# SPDX-License-Identifier: BSD-3-Clause
#

IF (SSS_HAVE_AUTH_SIGMA_I_VERIFIER OR SSS_HAVE_AUTH_SIGMA_I_PROVER OR SSS_HAVE_AUTH_SYMM_AUTH)
    ADD_SUBDIRECTORY(ex_sdm_provision)
    IF (SSS_HAVE_HOST_FRDMMCXN947 AND SSS_HAVE_SA_TYPE_NTAG_X_DNA)
        ADD_SUBDIRECTORY(sdm_apps/sdm_prov_encpicc_sig)
        ADD_SUBDIRECTORY(sdm_apps/sdm_prov_uid_rctr_sig)
        IF (SSS_HAVE_ALL_AUTH_CODE_ENABLED)
            ADD_SUBDIRECTORY(sdm_apps/sdm_ver_encpicc_sig)
            ADD_SUBDIRECTORY(sdm_apps/sdm_ver_uid_rctr_sig)
        ENDIF()
    ENDIF()
ENDIF()
IF (SSS_HAVE_AUTH_NONE AND SSS_HAVE_HOSTCRYPTO_ANY)
    ADD_SUBDIRECTORY(ex_sdm_file_read)
    ADD_SUBDIRECTORY(ex_sdm_mac)
ENDIF()
