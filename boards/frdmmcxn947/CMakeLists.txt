# Copyright 2025 NXP
#
# NXP Confidential. This software is owned or controlled by NXP and may only
# be used strictly in accordance with the applicable license terms.  By
# expressly accepting such terms or by downloading, installing, activating
# and/or otherwise using the software, you are agreeing that you have read,
# and that you agree to comply with and are bound by, such license terms.  If
# you do not agree to be bound by the applicable license terms, then you may
# not retain, install, activate or otherwise use the software.
#

# frdmmcxn947

PROJECT(board)

FILE(
    GLOB
    board_files
    ${NXMW_TOP_DIR}/boards/ksdk/nx_reset.c
    ${NXMW_TOP_DIR}/boards/ksdk/se_pit_config.c
    ${NXMW_TOP_DIR}/boards/ksdk/timer_kinetis.c
    ${NXMW_TOP_DIR}/boards/frdmmcxn947/board.c
    ${NXMW_TOP_DIR}/boards/frdmmcxn947/clock_config.c
    ${NXMW_TOP_DIR}/boards/frdmmcxn947/platform_frdmmcxn947.c
    ${NXMW_TOP_DIR}/boards/frdmmcxn947/pin_mux.c
    ${NXMW_TOP_DIR}/../mcuxsdk/components/serial_manager/fsl_component_serial_manager.c
    ${NXMW_TOP_DIR}/../mcuxsdk/components/serial_manager/fsl_component_serial_port_uart.c
    ${NXMW_TOP_DIR}/../mcuxsdk/components/uart/fsl_adapter_lpuart.c
    ${NXMW_TOP_DIR}/../mcuxsdk/components/lists/fsl_component_generic_list.c
    ${NXMW_TOP_DIR}/../mcuxsdk/components/phy/device/phyksz8081/fsl_phyksz8081.c
    ${NXMW_TOP_DIR}/../mcuxsdk/components/phy/device/phylan8741/fsl_phylan8741.c
    ${NXMW_TOP_DIR}/../mcuxsdk/devices/MCX/MCXN/MCXN947/drivers/fsl_clock.c
    ${NXMW_TOP_DIR}/../mcuxsdk/drivers/lpflexcomm/lpi2c/fsl_lpi2c.c
    ${NXMW_TOP_DIR}/../mcuxsdk/drivers/lpflexcomm/lpuart/fsl_lpuart.c
    ${NXMW_TOP_DIR}/../mcuxsdk/drivers/lpflexcomm/fsl_lpflexcomm.c
    ${NXMW_TOP_DIR}/../mcuxsdk/drivers/i3c/fsl_i3c.c
    ${NXMW_TOP_DIR}/../mcuxsdk/drivers/mcx_spc/fsl_spc.c
    ${NXMW_TOP_DIR}/../mcuxsdk/drivers/gpio/fsl_gpio.c
    ${NXMW_TOP_DIR}/../mcuxsdk/devices/MCX/MCXN/MCXN947/drivers/fsl_reset.c
    ${NXMW_TOP_DIR}/../mcuxsdk/devices/MCX/MCXN/MCXN947/system_MCXN947_cm33_core0.c
    ${NXMW_TOP_DIR}/../mcuxsdk/components/debug_console/fsl_debug_console.c
    ${NXMW_TOP_DIR}/../mcuxsdk/components/str/fsl_str.c
)

IF((SSS_HAVE_NX_TYPE) AND (NOT(SSS_HAVE_SMCOM_PN7150)))
    LIST(
        APPEND
        board_files
        ${NXMW_TOP_DIR}/boards/frdmmcxn947/i2c_frdmmcxn947.c
    )
ENDIF()

IF(SSS_HAVE_RTOS_FREERTOS)
    LIST(
        APPEND
        board_files
        ${NXMW_TOP_DIR}/boards/ksdk/timer_kinetis_freertos.c
        ${NXMW_TOP_DIR}/../mcuxsdk/rtos/freertos/freertos-drivers/lpflexcomm/lpi2c/fsl_lpi2c_freertos.c
        ${NXMW_TOP_DIR}/../mcuxsdk/components/osa/fsl_os_abstraction_free_rtos.c
    )
ELSE()
    LIST(
        APPEND
        board_files
        ${NXMW_TOP_DIR}/boards/ksdk/timer_kinetis_bm.c
        ${NXMW_TOP_DIR}/../mcuxsdk/components/osa/fsl_os_abstraction_bm.c
    )
ENDIF()

ADD_LIBRARY(board ${board_files})

TARGET_INCLUDE_DIRECTORIES(
    board
    PRIVATE
        ${NXMW_TOP_DIR}/boards/inc
        ${NXMW_TOP_DIR}/lib/hostlib/smCom
        ${NXMW_TOP_DIR}/lib/hostlib/nx_utils
        ${NXMW_TOP_DIR}/lib/hostlib/nx_log
)

TARGET_INCLUDE_DIRECTORIES(
    board
    PUBLIC ${NXMW_TOP_DIR}/boards/platform
    PUBLIC ${NXMW_TOP_DIR}/boards/frdmmcxn947/freertos
    PUBLIC ${NXMW_TOP_DIR}/../mcuxsdk/middleware/mbedtls/port/ksdk
    PUBLIC ${NXMW_TOP_DIR}/../mcuxsdk/middleware/lwip/src/include
    PUBLIC ${NXMW_TOP_DIR}/../mcuxsdk/middleware/lwip/port
    PUBLIC ${NXMW_TOP_DIR}/../mcuxsdk/components/osa
    PUBLIC ${NXMW_TOP_DIR}/../mcuxsdk/components/lists
    PUBLIC ${NXMW_TOP_DIR}/../mcuxsdk/components/phy
    PUBLIC ${NXMW_TOP_DIR}/../mcuxsdk/components/phy/device/phyksz8081
    PUBLIC ${NXMW_TOP_DIR}/../mcuxsdk/components/phy/mdio/enet
    PUBLIC ${NXMW_TOP_DIR}/../mcuxsdk/components/serial_mwm
    PUBLIC ${NXMW_TOP_DIR}/../mcuxsdk/components/phy/device/phylan8741
    PUBLIC ${NXMW_TOP_DIR}/../mcuxsdk/components/uart
    PUBLIC ${NXMW_TOP_DIR}/../mcuxsdk/components/gpio
    PUBLIC ${NXMW_TOP_DIR}/../mcuxsdk/components/debug_console
    PUBLIC ${NXMW_TOP_DIR}/../mcuxsdk/components/serial_manager
    PUBLIC ${NXMW_TOP_DIR}/../mcuxsdk/components/osa/config
    PUBLIC ${NXMW_TOP_DIR}/../freertos/corejson/source/include
    PUBLIC ${NXMW_TOP_DIR}/../mcuxsdk/devices/MCX/MCXN/MCXN947
    PUBLIC ${NXMW_TOP_DIR}/../mcuxsdk/devices/MCX/MCXN/MCXN947/drivers
    PUBLIC ${NXMW_TOP_DIR}/../mcuxsdk/devices/MCX/MCXN/periph
    PUBLIC ${NXMW_TOP_DIR}/../mcuxsdk/arch/arm/CMSIS/Core/Include
    PUBLIC ${NXMW_TOP_DIR}/../mcuxsdk/drivers/common
    PUBLIC ${NXMW_TOP_DIR}/../mcuxsdk/drivers/flexcomm/usart
    PUBLIC ${NXMW_TOP_DIR}/../mcuxsdk/drivers/flexcomm
    PUBLIC ${NXMW_TOP_DIR}/../mcuxsdk/drivers/puf
    PUBLIC ${NXMW_TOP_DIR}/../mcuxsdk/rtos/freertos/freertos-kernel/include
    PUBLIC ${NXMW_TOP_DIR}/../mcuxsdk/rtos/freertos/freertos-drivers/flexcomm/i2c
    PUBLIC ${NXMW_TOP_DIR}/../mcuxsdk/rtos/freertos/freertos-drivers/flexcomm/usart
    PUBLIC ${NXMW_TOP_DIR}/boards/frdmmcxn947
    PUBLIC ${NXMW_TOP_DIR}/../mcuxsdk/drivers/lpflexcomm/lpuart
    PUBLIC ${NXMW_TOP_DIR}/../mcuxsdk/drivers/lpflexcomm/lpi2c
    PUBLIC ${NXMW_TOP_DIR}/../mcuxsdk/drivers/gpio
    PUBLIC ${NXMW_TOP_DIR}/../mcuxsdk/drivers/port
    PUBLIC ${NXMW_TOP_DIR}/../mcuxsdk/drivers/i3c
    PUBLIC ${NXMW_TOP_DIR}/../mcuxsdk/drivers/mcx_spc
    PUBLIC ${NXMW_TOP_DIR}/../mcuxsdk/drivers/lpflexcomm
    PUBLIC ${NXMW_TOP_DIR}/../mcuxsdk/rtos/freertos/freertos-drivers/lpflexcomm/lpi2c
)

IF(NOT SSS_HAVE_LOG_SEGGERRTT)
    TARGET_LINK_LIBRARIES(board mwlog)
ENDIF()

IF(SSS_HAVE_RTOS_FREERTOS)
    TARGET_LINK_LIBRARIES(board freertos-kernel)
ENDIF()

TARGET_LINK_LIBRARIES(
    board -Wl,--start-group
)
TARGET_LINK_LIBRARIES(
    board
    debug
    m
)
TARGET_LINK_LIBRARIES(
    board
    debug
    c
)
TARGET_LINK_LIBRARIES(
    board
    debug
    gcc
)
TARGET_LINK_LIBRARIES(
    board
    debug
    nosys
)
TARGET_LINK_LIBRARIES(
    board
    optimized
    m
)
TARGET_LINK_LIBRARIES(
    board
    optimized
    c
)
TARGET_LINK_LIBRARIES(
    board
    optimized
    gcc
)
TARGET_LINK_LIBRARIES(
    board
    optimized
    nosys
)

TARGET_LINK_LIBRARIES(
    board -Wl,--end-group
)

IF(SSS_HAVE_HOSTCRYPTO_MBEDTLS)
    TARGET_COMPILE_DEFINITIONS(
        ${PROJECT_NAME}
        PUBLIC MBEDTLS # FIXME : This must eventually not be needed because sss APIs should be enough
    )
ENDIF()

TARGET_COMPILE_OPTIONS(
    ${PROJECT_NAME}
    PRIVATE -Wno-error=old-style-declaration
)
