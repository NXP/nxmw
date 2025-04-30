# Copyright 2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
#
PROJECT(psa_example)

FILE(
    GLOB
    files
    *.c
)

ADD_EXECUTABLE(
    ${PROJECT_NAME}
    ${KSDK_STARTUP_FILE} ${files}
)

TARGET_INCLUDE_DIRECTORIES(
    ${PROJECT_NAME}
    PUBLIC ${NXMW_TOP_DIR}lib/sss/ex/inc
    PUBLIC ${NXMW_TOP_DIR}/plugin/psa/psa_alt_lib/
    PUBLIC ${NXMW_TOP_DIR}/plugin/psa/psa_alt_lib/src
)

IF(SSS_HAVE_KSDK)
    TARGET_LINK_LIBRARIES(
        ${PROJECT_NAME}
        board
        ex_common
        mbedtls
        psa_alt_lib
    )
ELSE()
    TARGET_LINK_LIBRARIES(
        ${PROJECT_NAME}
        ex_common
        mbedtls
        psa_alt_lib
    )
ENDIF()

CREATE_BINARY(${PROJECT_NAME})