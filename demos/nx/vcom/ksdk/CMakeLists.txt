# Copyright 2019-2020, 2022-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
#

PROJECT(vcom)

FILE(
    GLOB
    ${PROJECT_NAME}_files
    *.c
    *.h
    ${NXMW_TOP_DIR}/../mcuxsdk/middleware/usb/device/class/cdc/*.c
    ${NXMW_TOP_DIR}/../mcuxsdk/middleware/usb/osa/usb_osa_bm.c
    ${NXMW_TOP_DIR}/../mcuxsdk/middleware/usb/device/class/usb_device_cdc_acm.c
    ${NXMW_TOP_DIR}/../mcuxsdk/middleware/usb/device/class/usb_device_class.c
    ${NXMW_TOP_DIR}/../mcuxsdk/middleware/usb/device/usb_device_ch9.c
    ${NXMW_TOP_DIR}/../mcuxsdk/middleware/usb/device/usb_device_dci.c
    ${NXMW_TOP_DIR}/boards/platform/platform.c
)

IF(SSS_HAVE_HOST_FRDMMCXA153)
    FILE(
        GLOB
        frdmmcxa153_files
        ${NXMW_TOP_DIR}/../mcuxsdk/middleware/usb/device/usb_device_khci.c
    )
ENDIF()

IF(SSS_HAVE_HOST_FRDMMCXN947)
    FILE(
        GLOB
        frdmmcxn947_files
        ${NXMW_TOP_DIR}/../mcuxsdk/middleware/usb/device/usb_device_ehci.c
        ${NXMW_TOP_DIR}/../mcuxsdk/middleware/usb/phy/usb_phy.c
    )
ENDIF()

IF(SSS_HAVE_HOST_LPCXPRESSO55S)
    FILE(
        GLOB
        lpcxpresso55s_files
        ${NXMW_TOP_DIR}/../mcuxsdk/middleware/usb/device/usb_device_ehci.c
        ${NXMW_TOP_DIR}/../mcuxsdk/middleware/usb/device/usb_device_lpcip3511.c
        ${NXMW_TOP_DIR}/../mcuxsdk/middleware/usb/phy/usb_phy.c
        ${NXMW_TOP_DIR}/../mcuxsdk/components/osa/fsl_os_abstraction_bm.c
        ${NXMW_TOP_DIR}/../mcuxsdk/drivers/common/fsl_common_arm.c
    )
ENDIF()

ADD_EXECUTABLE(
    ${PROJECT_NAME}
    ${KSDK_STARTUP_FILE}
    ${${PROJECT_NAME}_files}
    ${frdmmcxa153_files}
    ${frdmmcxn947_files}
    ${lpcxpresso55s_files}
)

TARGET_LINK_LIBRARIES(
    ${PROJECT_NAME}
    nx_utils
    smCom
    board
)

IF(SSS_HAVE_HOST_LPCXPRESSO55S)
    TARGET_INCLUDE_DIRECTORIES(
        ${PROJECT_NAME}
        PRIVATE
            .
            ${NXMW_TOP_DIR}/boards/platform
            ${NXMW_TOP_DIR}/boards/lpcxpresso55s69/usb_vcom
            ${NXMW_TOP_DIR}/../mcuxsdk/middleware/usb/device
            ${NXMW_TOP_DIR}/../mcuxsdk/middleware/usb/device/class
            ${NXMW_TOP_DIR}/../mcuxsdk/middleware/usb/include
            ${NXMW_TOP_DIR}/../mcuxsdk/middleware/usb/osa
            ${NXMW_TOP_DIR}/../mcuxsdk/middleware/usb/phy
            ${NXMW_TOP_DIR}/../mcuxsdk/components/lists
            ${NXMW_TOP_DIR}/../mcuxsdk/components/serial_manager/usb_cdc_adapter
    )
ENDIF()


IF(SSS_HAVE_HOST_FRDMMCXA153)
    TARGET_INCLUDE_DIRECTORIES(
        ${PROJECT_NAME}
        PRIVATE
            .
            ${NXMW_TOP_DIR}/../mcuxsdk/middleware/usb/device
            ${NXMW_TOP_DIR}/../mcuxsdk/middleware/usb/device/class
            ${NXMW_TOP_DIR}/../mcuxsdk/middleware/usb/include
            ${NXMW_TOP_DIR}/../mcuxsdk/middleware/usb/osa
            ${NXMW_TOP_DIR}/../mcuxsdk/middleware/usb/phy
            ${NXMW_TOP_DIR}/boards/platform
            ${NXMW_TOP_DIR}/../mcuxsdk/components/serial_manager/usb_cdc_adapter
            ${NXMW_TOP_DIR}/boards/frdmmcxa153/usb_vcom

    )
ENDIF()

IF(SSS_HAVE_HOST_FRDMMCXN947)
    TARGET_INCLUDE_DIRECTORIES(
        ${PROJECT_NAME}
        PRIVATE
            .
            ${NXMW_TOP_DIR}/../mcuxsdk/middleware/usb/device
            ${NXMW_TOP_DIR}/../mcuxsdk/middleware/usb/device/class
            ${NXMW_TOP_DIR}/../mcuxsdk/middleware/usb/include
            ${NXMW_TOP_DIR}/../mcuxsdk/middleware/usb/osa
            ${NXMW_TOP_DIR}/../mcuxsdk/middleware/usb/phy
            ${NXMW_TOP_DIR}/boards/platform
            ${NXMW_TOP_DIR}/../mcuxsdk/components/serial_manager/usb_cdc_adapter
            ${NXMW_TOP_DIR}/boards/frdmmcxn947/usb_vcom
    )
ENDIF()


TARGET_COMPILE_DEFINITIONS(
    ${PROJECT_NAME}
    PRIVATE USB_STACK_BM
)

CREATE_BINARY(${PROJECT_NAME})
