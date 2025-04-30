#
# Copyright 2023 NXP
# SPDX-License-Identifier: BSD-3-Clause
#
#

PROJECT(qi_transmitter)

FILE(
    GLOB
    files
    *.c
    port/*.c
)

ADD_LIBRARY(
    ${PROJECT_NAME}
    ${files}
)

TARGET_INCLUDE_DIRECTORIES(
    ${PROJECT_NAME}
    PUBLIC .
    PUBLIC ../inc
    PUBLIC port
)

TARGET_LINK_LIBRARIES(
    ${PROJECT_NAME}
    ex_common
)
