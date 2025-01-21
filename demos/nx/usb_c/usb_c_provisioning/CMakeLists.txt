#
# Copyright 2023 NXP
# SPDX-License-Identifier: BSD-3-Clause
#

PROJECT(usb_c_provisioning)

FILE(
    GLOB
    files
    *.c
)

ADD_EXECUTABLE(
    ${PROJECT_NAME}
    ${KSDK_STARTUP_FILE} ${files}
)

TARGET_LINK_LIBRARIES(
    ${PROJECT_NAME}
    ex_common
    SSS_APIs
)

TARGET_INCLUDE_DIRECTORIES(
    ${PROJECT_NAME}
    PRIVATE ..
)

CREATE_BINARY(${PROJECT_NAME})
