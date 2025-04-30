# Copyright 2020 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
#
#

PROJECT(nx_Personalization)

ADD_EXECUTABLE(
    ${PROJECT_NAME}
    ${KSDK_STARTUP_FILE}
    nx_Personalization.c
    nx_Personalization_default.c
    nx_Personalization_fs.c
    nx_Personalization_mgncertrepo.c
    nx_Personalization_helpers.c
)

TARGET_INCLUDE_DIRECTORIES(
    ${PROJECT_NAME}
    PRIVATE .
)

TARGET_LINK_LIBRARIES(
    ${PROJECT_NAME}
    ex_common
)

CREATE_BINARY(${PROJECT_NAME})
