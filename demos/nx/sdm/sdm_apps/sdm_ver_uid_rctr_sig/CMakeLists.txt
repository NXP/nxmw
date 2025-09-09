#
# Copyright 2025 NXP
# SPDX-License-Identifier: BSD-3-Clause
#

PROJECT(ex_sdm_ver_uid_rctr_sig)

FILE(
    GLOB
    files
    *.c
    ${NXMW_TOP_DIR}/demos/nx/sdm/sdm_apps/sdm_utils/ex_sdm_util.c
)

ADD_EXECUTABLE(
    ${PROJECT_NAME}
    ${KSDK_STARTUP_FILE} ${files}
)

TARGET_INCLUDE_DIRECTORIES(
    ${PROJECT_NAME}
    PRIVATE ${NXMW_TOP_DIR}/demos/nx/sdm/sdm_apps/sdm_utils/
    PRIVATE .
    PRIVATE ..
)

TARGET_LINK_LIBRARIES(
    ${PROJECT_NAME}
    ex_common
)

IF(SSS_HAVE_HOSTCRYPTO_MBEDTLS)
    TARGET_LINK_LIBRARIES(${PROJECT_NAME} mbedtls)
ENDIF()

IF(SSS_HAVE_HOSTCRYPTO_OPENSSL)
    TARGET_LINK_LIBRARIES(${PROJECT_NAME} ${OPENSSL_LIBRARIES})
ENDIF()

IF(NXPInternal)
    TARGET_COMPILE_DEFINITIONS(
        ${PROJECT_NAME}
        PRIVATE
        USE_ROOT_USBIF=0
    )
ENDIF()

CREATE_BINARY(${PROJECT_NAME})
