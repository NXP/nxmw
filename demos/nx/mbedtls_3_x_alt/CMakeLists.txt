#
# Copyright 2025 NXP
# SPDX-License-Identifier: BSD-3-Clause
#
#

PROJECT(ex_mbedtls_3_x_alt)

FILE(
    GLOB
    ${PROJECT_NAME}_files
    *.c
    *.h
)

ADD_EXECUTABLE(
    ${PROJECT_NAME}
    ${KSDK_STARTUP_FILE} ${${PROJECT_NAME}_files}
)

TARGET_LINK_LIBRARIES(
    ${PROJECT_NAME}
    ex_common
)

CREATE_BINARY(${PROJECT_NAME})
