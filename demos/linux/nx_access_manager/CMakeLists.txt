#
# Copyright 2024 NXP
# SPDX-License-Identifier: BSD-3-Clause
#

PROJECT(accessManager)

FILE(
    GLOB
    ${PROJECT_NAME}_files
    src/*.c
    src/*.h
)

ADD_EXECUTABLE(
    ${PROJECT_NAME}
    ${KSDK_STARTUP_FILE} ${${PROJECT_NAME}_files}
)

TARGET_LINK_LIBRARIES(
    ${PROJECT_NAME} smCom ex_common
)

CREATE_BINARY(${PROJECT_NAME})