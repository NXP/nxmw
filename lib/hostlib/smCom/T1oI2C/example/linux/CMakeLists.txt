#
# Copyright 2024 NXP
# SPDX-License-Identifier: BSD-3-Clause
#

PROJECT(ex_t1oi2c)

FILE(
    GLOB
    ${PROJECT_NAME}_files
    main.c
    ${NXMW_TOP_DIR}/lib/hostlib/smCom/T1oI2C/phNxpEse_Api.c
    ${NXMW_TOP_DIR}/lib/hostlib/smCom/T1oI2C/phNxpEseProto7816_3.c
    ${NXMW_TOP_DIR}/lib/hostlib/smCom/T1oI2C/phNxpEsePal_i2c.c
    ${NXMW_TOP_DIR}/lib/hostlib/nx_log/nxLog.c
    ${NXMW_TOP_DIR}/boards/generic/sm_timer.c
    ${NXMW_TOP_DIR}/boards/linux/i2c_a7.c
)

ADD_EXECUTABLE(
    ${PROJECT_NAME}
    ${${PROJECT_NAME}_files}
)

TARGET_INCLUDE_DIRECTORIES(
    ${PROJECT_NAME}
    PUBLIC ${NXMW_TOP_DIR}/lib/sss/port/default
    PUBLIC ${NXMW_TOP_DIR}/boards/inc
    PUBLIC ${NXMW_TOP_DIR}/lib/hostlib/nx_log
    PUBLIC ${NXMW_TOP_DIR}/lib/hostlib/nx_utils
    PUBLIC ${NXMW_TOP_DIR}/lib/hostlib/smCom
    PUBLIC ${NXMW_TOP_DIR}/lib/hostlib/smCom/T1oI2C
)

IF(SSS_HAVE_HOST_LINUX_LIKE)
    ADD_DEFINITIONS(-DT1OI2C_RETRY_ON_I2C_FAILED)
ENDIF()

CREATE_BINARY(${PROJECT_NAME})