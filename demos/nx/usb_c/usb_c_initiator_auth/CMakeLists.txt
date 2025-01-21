#
# Copyright 2023 NXP
# SPDX-License-Identifier: BSD-3-Clause
#
#

PROJECT(usb_c_initiator_auth)

FILE(
    GLOB
    files
    *.c
    *.h
)

ADD_LIBRARY(
    ${PROJECT_NAME}
    ${files}
)

TARGET_INCLUDE_DIRECTORIES(
    ${PROJECT_NAME}
    PUBLIC .
    PUBLIC ..
)

TARGET_LINK_LIBRARIES(
    ${PROJECT_NAME}
    ex_common
    SSS_APIs
)