#
# Copyright 2024 NXP
# SPDX-License-Identifier: BSD-3-Clause
#
#

PROJECT(cloud_aws)

FILE(
    GLOB
    files
    ${NXMW_TOP_DIR}/lib/sss/ex/inc/*.h
    ${NXMW_TOP_DIR}/boards/ksdk/common/utils/*.c
    ${NXMW_TOP_DIR}/boards/ksdk/common/utils/*.h
    *.h
    ${NXMW_TOP_DIR}/boards/ksdk/common/*.h
    ledHandler.c
)


IF(SSS_HAVE_KSDK)
    FILE(
        GLOB
        lwip_files
        aws_jitr_demo_Main_lwip.c
        aws_jitr_task_lwip.c
    )
ENDIF()

ADD_EXECUTABLE(
    ${PROJECT_NAME}
    ${KSDK_STARTUP_FILE}
    ${lwip_files}
    ${files}
)

TARGET_INCLUDE_DIRECTORIES(
    ${PROJECT_NAME}
    PUBLIC ${NXMW_TOP_DIR}/boards/ksdk/common
    PUBLIC ${NXMW_TOP_DIR}/lib/sss/ex/inc
    PUBLIC ${NXMW_TOP_DIR}/boards/ksdk/common/utils
    PUBLIC ${NXMW_TOP_DIR}/../mcuxsdk/components/aws_iot/using_mbedtls_pkcs11
    PUBLIC .
)

TARGET_LINK_LIBRARIES(
    ${PROJECT_NAME}
    ex_common
)

IF(SSS_HAVE_RTOS_FREERTOS)
    TARGET_LINK_LIBRARIES(${PROJECT_NAME} freertos-ip freertos-kernel)

ENDIF()

CREATE_BINARY(${PROJECT_NAME})
