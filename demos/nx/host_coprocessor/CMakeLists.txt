#
# Copyright 2025 NXP
# SPDX-License-Identifier: BSD-3-Clause
#
#

PROJECT(nx_host_coprocessor)
FILE(
    GLOB
    files
    *.c
    *.h
    #${NXMW_TOP_DIR}/demos/nx/host_coprocessor/host_copro_txn.c
    ${NXMW_TOP_DIR}/lib/hostlib/smCom/T1oI2C/phNxpEse_Api.c
    ${NXMW_TOP_DIR}/lib/hostlib/smCom/T1oI2C/phNxpEseProto7816_3.c
    ${NXMW_TOP_DIR}/lib/hostlib/smCom/T1oI2C/phNxpEsePal_i2c.c
    ${NXMW_TOP_DIR}/boards/platform/platform.c
)

IF (SSS_HAVE_HOST_FRDMMCXA153)
LIST(
    REMOVE_ITEM
    files
    ${NXMW_TOP_DIR}/boards/frdmmcxa153/pin_mux.c
)
LIST(
    APPEND
    files
    ${NXMW_TOP_DIR}/boards/frdmmcxa153/host_coprocessor/pin_mux.c
)
ENDIF()

ADD_EXECUTABLE(
    ${PROJECT_NAME}
    ${KSDK_STARTUP_FILE} ${files}
)

TARGET_LINK_LIBRARIES(
    ${PROJECT_NAME}
    board
)

TARGET_INCLUDE_DIRECTORIES(
    ${PROJECT_NAME}
    PUBLIC ${NXMW_TOP_DIR}/boards/inc
    PUBLIC ${NXMW_TOP_DIR}/lib/hostlib/smCom
    PUBLIC ${NXMW_TOP_DIR}/lib/hostlib/smCom/T1oI2C
    PUBLIC ${NXMW_TOP_DIR}/lib/sss/port/default
    PUBLIC ${NXMW_TOP_DIR}/boards/platform
)

CREATE_BINARY(${PROJECT_NAME})
