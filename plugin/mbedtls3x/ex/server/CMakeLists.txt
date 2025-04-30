#
# Copyright 2025 NXP
# SPDX-License-Identifier: Apache-2.0
#
#

PROJECT(mbedtls_3x_server)

ADD_EXECUTABLE(
    ${PROJECT_NAME}
    ${NXMW_TOP_DIR}/../mcuxsdk/middleware/mbedtls3x/programs/ssl/ssl_server2.c
    ${NXMW_TOP_DIR}/../mcuxsdk/middleware/mbedtls3x/tests/src/certs.c
    ${NXMW_TOP_DIR}/../mcuxsdk/middleware/mbedtls3x/tests/src/helpers.c
    ${NXMW_TOP_DIR}/../mcuxsdk/middleware/mbedtls3x/programs/test/query_config.c
    ${NXMW_TOP_DIR}/../mcuxsdk/middleware/mbedtls3x/programs/ssl/ssl_test_lib.c
    ${NXMW_TOP_DIR}/../mcuxsdk/middleware/mbedtls3x/tests/src/psa_crypto_helpers.c
)

TARGET_INCLUDE_DIRECTORIES(
    ${PROJECT_NAME}
    PRIVATE ${NXMW_TOP_DIR}/../mcuxsdk/middleware/mbedtls3x/tests/include
)

IF(SSS_HAVE_KSDK)
    TARGET_LINK_LIBRARIES(${PROJECT_NAME} mbedtls)
ELSE() # KSDK
    TARGET_LINK_LIBRARIES(
        ${PROJECT_NAME}
        mbedtls
        smCom
        ex_common
    )
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

ADD_CUSTOM_COMMAND(
    TARGET ${PROJECT_NAME}
    POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:${PROJECT_NAME}> ${NXMW_TOP_DIR}/tools
    COMMENT "Copy exe to ${NXMW_TOP_DIR}/tools"
)

CREATE_BINARY(${PROJECT_NAME})