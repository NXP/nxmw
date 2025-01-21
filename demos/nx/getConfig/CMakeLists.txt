#
# Copyright 2019 NXP
# SPDX-License-Identifier: BSD-3-Clause
#
#

PROJECT(ex_get_config)

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
    ${PROJECT_NAME} ex_common
)

CREATE_BINARY(${PROJECT_NAME})
