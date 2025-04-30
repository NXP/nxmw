#
# Copyright 2024 NXP
# SPDX-License-Identifier: BSD-3-Clause
#
#

MACRO(DO_PROVISOING_PROJECT PROVISOING_PROJECT_NAME)

    PROJECT(cloud_provisioning_${PROVISOING_PROJECT_NAME})

    FILE(
        GLOB
        headers
        *.h
    )

    ADD_EXECUTABLE(
        ${PROJECT_NAME}
        ${KSDK_STARTUP_FILE}
        ${headers}
        provisioning.c
        provisioning_${PROVISOING_PROJECT_NAME}.c
    )

    TARGET_INCLUDE_DIRECTORIES(
        ${PROJECT_NAME}
        PRIVATE ${NXMW_TOP_DIR}/lib/sss/ex/inc
        PRIVATE ${NXMW_TOP_DIR}/boards/ksdk/common
    )

    TARGET_LINK_LIBRARIES(
        ${PROJECT_NAME}
        ex_common
    )

    IF(SSS_HAVE_RTOS_FREERTOS)
        TARGET_LINK_LIBRARIES(${PROJECT_NAME} freertos-ip)
    ENDIF()

    CREATE_BINARY(${PROJECT_NAME})
ENDMACRO()

DO_PROVISOING_PROJECT(aws)
