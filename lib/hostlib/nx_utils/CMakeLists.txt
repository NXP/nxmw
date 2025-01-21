#
# Copyright 2019,2020 NXP
# SPDX-License-Identifier: BSD-3-Clause
#
#

PROJECT(nx_utils)

FILE(
    GLOB
    nx_utils_files
    sm_connect.c
)

IF(SSS_HAVE_KSDK)
    LIST(
        APPEND
        nx_utils_files
    )
ENDIF()

IF(SSS_HAVE_RTOS_FREERTOS AND SSS_HAVE_KSDK)
    LIST(
        APPEND
        nx_utils_files
        sm_demo_utils_rtos.c
    )
ENDIF()

ADD_LIBRARY(nx_utils ${nx_utils_files})

IF(
    "${CMAKE_CXX_COMPILER_ID}"
    STREQUAL
    "GNU"
)
    TARGET_COMPILE_OPTIONS(${PROJECT_NAME} PRIVATE -Wno-stringop-overflow)
ENDIF()

TARGET_LINK_LIBRARIES(nx_utils smCom)

IF(SSS_HAVE_RTOS_FREERTOS)
    TARGET_LINK_LIBRARIES(nx_utils freertos-kernel)
    TARGET_LINK_LIBRARIES(nx_utils freertos-ip)
ENDIF()
