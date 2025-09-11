#
# Copyright 2025 NXP
# SPDX-License-Identifier: BSD-3-Clause
#
#

PROJECT(mbedtls_3_x_lwip_client)

FILE(
    GLOB
    src_files
    *.c
    ${NXMW_TOP_DIR}/demos/nx/mbedtls_3_x_lwip_client/ssl/ssl_test_lib.c
    ${NXMW_TOP_DIR}/../mcuxsdk/middleware/mbedtls3x/tests/src/helpers.c
    ${NXMW_TOP_DIR}/../mcuxsdk/middleware/mbedtls3x/tests/src/certs.c
    ${NXMW_TOP_DIR}/../mcuxsdk/middleware/mbedtls3x/programs/test/query_config.c
    ${NXMW_TOP_DIR}/../mcuxsdk/middleware/nxp_iot_agent/net_crypto/mbedtls/net_lwip.c
    ${NXMW_TOP_DIR}/boards/ksdk/common/utils/sm_demo_utils.c
    ${NXMW_TOP_DIR}/boards/ksdk/common/utils/sm_demo_utils.h
    *.h
)

    IF(SSS_HAVE_NX_TYPE)
        FILE(
            GLOB
            ax_files
            ${NXMW_TOP_DIR}/lib/hostlib/nx_utils/app_boot.h
        )
    ENDIF()

IF(
    "${CMAKE_CXX_COMPILER_ID}"
    MATCHES
    "MSVC"
)
    ADD_EXECUTABLE(
        ${PROJECT_NAME}
        ${KSDK_STARTUP_FILE}
        ${ax_files}
        ${src_files}
    )
ELSE()
    ADD_EXECUTABLE(
        ${PROJECT_NAME}
        ${KSDK_STARTUP_FILE}
        ${ax_files}
        ${src_files}

    )
ENDIF()

TARGET_INCLUDE_DIRECTORIES(
    ${PROJECT_NAME}
    PRIVATE
        ${NXMW_TOP_DIR}/demos/nx/mbedtls_3_x_lwip_client/ssl/
        ${NXMW_TOP_DIR}/../mcuxsdk/middleware/lwip/port
        ${NXMW_TOP_DIR}/../mcuxsdk/middleware/mbedtls3x/tests/include
        ${NXMW_TOP_DIR}/../mcuxsdk/middleware/mbedtls3x/programs/test/
        ${NXMW_TOP_DIR}/../mcuxsdk/middleware/mbedtls3x/programs/
        ${NXMW_TOP_DIR}/../mcuxsdk/middleware/mbedtls3x/programs/ssl/
        ${NXMW_TOP_DIR}/../mcuxsdk/drivers/mcx_enet/
        ${NXMW_TOP_DIR}/boards/ksdk/common/utils
)

TARGET_LINK_LIBRARIES(
    ${PROJECT_NAME} ex_common
)

IF(SSS_HAVE_RTOS_FREERTOS)
    TARGET_LINK_LIBRARIES(${PROJECT_NAME} freertos-ip freertos-kernel)
ENDIF()

IF(
    "${CMAKE_CXX_COMPILER_ID}"
    MATCHES
    "MSVC"
)
    IF(NXPInternal)
        TARGET_COMPILE_OPTIONS(${PROJECT_NAME} PRIVATE /wd4127 # conditional expression is constant
        )
    ENDIF()
ENDIF()

CREATE_BINARY(${PROJECT_NAME})
