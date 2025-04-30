#
# Copyright 2023 NXP
# SPDX-License-Identifier: BSD-3-Clause
#

PROJECT(sa_qi_receiver)

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
    qi_transmitter
)

CREATE_BINARY(${PROJECT_NAME})
