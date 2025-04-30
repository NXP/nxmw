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

# lpcxpresso55s69

PROJECT(board)

FILE(
    GLOB
    board_files
    ${NXMW_TOP_DIR}/boards/ksdk/nx_reset.c
    ${NXMW_TOP_DIR}/boards/ksdk/se_pit_config.c
    ${NXMW_TOP_DIR}/boards/ksdk/timer_kinetis.c
    ${NXMW_TOP_DIR}/boards/lpcxpresso55s69/board.c
    ${NXMW_TOP_DIR}/boards/lpcxpresso55s69/clock_config.c
    ${NXMW_TOP_DIR}/boards/lpcxpresso55s69/platform_lpcxpresso55s69.c
    ${NXMW_TOP_DIR}/boards/lpcxpresso55s69/pin_mux.c
    ${NXMW_TOP_DIR}/../mcuxsdk/components/debug_console/fsl_debug_console.c
    ${NXMW_TOP_DIR}/../mcuxsdk/components/serial_manager/fsl_component_serial_manager.c
    ${NXMW_TOP_DIR}/../mcuxsdk/components/serial_manager/fsl_component_serial_port_uart.c
    ${NXMW_TOP_DIR}/../mcuxsdk/components/uart/fsl_adapter_usart.c
    ${NXMW_TOP_DIR}/../mcuxsdk/components/str/fsl_str.c
    ${NXMW_TOP_DIR}/../mcuxsdk/drivers/flexcomm/fsl_flexcomm.c
    ${NXMW_TOP_DIR}/../mcuxsdk/drivers/lpc_gpio/fsl_gpio.c
    ${NXMW_TOP_DIR}/../mcuxsdk/drivers/flexcomm/i2c/fsl_i2c.c
    ${NXMW_TOP_DIR}/../mcuxsdk/drivers/flexcomm/usart/fsl_usart.c
    ${NXMW_TOP_DIR}/../mcuxsdk/drivers/rng_1/fsl_rng.c
    ${NXMW_TOP_DIR}/../mcuxsdk/drivers/iap1/fsl_iap.c
    ${NXMW_TOP_DIR}/../mcuxsdk/drivers/hashcrypt/fsl_hashcrypt.c
    ${NXMW_TOP_DIR}/../mcuxsdk/drivers/casper/fsl_casper.c
    ${NXMW_TOP_DIR}/../mcuxsdk/devices/LPC/LPC5500/LPC55S69/drivers/fsl_reset.c
    ${NXMW_TOP_DIR}/../mcuxsdk/devices/LPC/LPC5500/LPC55S69/drivers/fsl_clock.c
    ${NXMW_TOP_DIR}/../mcuxsdk/devices/LPC/LPC5500/LPC55S69/drivers/fsl_power.c
    ${NXMW_TOP_DIR}/../mcuxsdk/devices/LPC/LPC5500/LPC55S69/system_LPC55S69_cm33_core0.c
    ${NXMW_TOP_DIR}/../mcuxsdk/devices/LPC/LPC5500/LPC55S69/system_LPC55S69_cm33_core1.c
)

IF((SSS_HAVE_NX_TYPE) AND (NOT(SSS_HAVE_SMCOM_PN7150)))
    LIST(
        APPEND
        board_files
        ${NXMW_TOP_DIR}/boards/lpcxpresso55s69/i2c_lpc55sxx.c
    )
ENDIF()

IF(SSS_HAVE_RTOS_FREERTOS)
    LIST(
        APPEND
        board_files
        ${NXMW_TOP_DIR}/boards/ksdk/timer_kinetis_freertos.c
        ${NXMW_TOP_DIR}/../mcuxsdk/rtos/freertos/freertos-drivers/flexcomm/usart/fsl_usart_freertos.c
        ${NXMW_TOP_DIR}/../mcuxsdk/rtos/freertos/freertos-drivers/flexcomm/i2c/fsl_i2c_freertos.c
        ${NXMW_TOP_DIR}/../mcuxsdk/components/osa/fsl_os_abstraction_free_rtos.c
        ${NXMW_TOP_DIR}/../mcuxsdk/components/serial_mwm/serial_mwm.c
        ${NXMW_TOP_DIR}/../mcuxsdk/components/serial_mwm/serial_mwm_usart.c
    )
ELSE()
    LIST(
        APPEND
        board_files
        ${NXMW_TOP_DIR}/boards/ksdk/timer_kinetis_bm.c
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
    PUBLIC ${NXMW_TOP_DIR}/boards/lpcxpresso55s69/freertos
    PUBLIC ${NXMW_TOP_DIR}/../mcuxsdk/middleware/mbedtls/port/ksdk
    PUBLIC ${NXMW_TOP_DIR}/../mcuxsdk/components/osa
    PUBLIC ${NXMW_TOP_DIR}/../mcuxsdk/components/osa/config
    PUBLIC ${NXMW_TOP_DIR}/../mcuxsdk/components/phy
    PUBLIC ${NXMW_TOP_DIR}/../mcuxsdk/components/phy/device/phyksz8081
    PUBLIC ${NXMW_TOP_DIR}/../mcuxsdk/components/uart
    PUBLIC ${NXMW_TOP_DIR}/../mcuxsdk/components/debug_console
    PUBLIC ${NXMW_TOP_DIR}/../mcuxsdk/components/serial_manager
    PUBLIC ${NXMW_TOP_DIR}/../mcuxsdk/components/lists
    PUBLIC ${NXMW_TOP_DIR}/../mcuxsdk/components/serial_mwm
    PUBLIC ${NXMW_TOP_DIR}/../mcuxsdk/devices/LPC/LPC5500/LPC55S69
    PUBLIC ${NXMW_TOP_DIR}/../mcuxsdk/devices/LPC/LPC5500/LPC55S69/drivers
    PUBLIC ${NXMW_TOP_DIR}/../mcuxsdk/devices/LPC/LPC5500/periph
    PUBLIC ${NXMW_TOP_DIR}/../mcuxsdk/arch/arm/CMSIS/Core/Include
    PUBLIC ${NXMW_TOP_DIR}/../mcuxsdk/drivers/common
    PUBLIC ${NXMW_TOP_DIR}/../mcuxsdk/drivers/flexcomm/usart
    PUBLIC ${NXMW_TOP_DIR}/../mcuxsdk/drivers/flexcomm
    PUBLIC ${NXMW_TOP_DIR}/../mcuxsdk/drivers/lpc_gpio
    PUBLIC ${NXMW_TOP_DIR}/../mcuxsdk/drivers/lpc_iocon
    PUBLIC ${NXMW_TOP_DIR}/../mcuxsdk/drivers/common
    PUBLIC ${NXMW_TOP_DIR}/../mcuxsdk/drivers/rng_1
    PUBLIC ${NXMW_TOP_DIR}/../mcuxsdk/drivers/iap1
    PUBLIC ${NXMW_TOP_DIR}/../mcuxsdk/drivers/puf
    PUBLIC ${NXMW_TOP_DIR}/../mcuxsdk/drivers/flexcomm/i2c
    PUBLIC ${NXMW_TOP_DIR}/../mcuxsdk/rtos/freertos/freertos-kernel/include
    PUBLIC ${NXMW_TOP_DIR}/../mcuxsdk/rtos/freertos/freertos-drivers/flexcomm/i2c
    PUBLIC ${NXMW_TOP_DIR}/../mcuxsdk/rtos/freertos/freertos-drivers/flexcomm/usart
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


IF(
    "${CMAKE_CXX_COMPILER_ID}"
    STREQUAL
    "GNU"
)
    TARGET_COMPILE_OPTIONS(
        ${PROJECT_NAME}
        PRIVATE -Wno-sign-compare
    )

ENDIF()
