# Copyright 2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
#

# frdmmcxa156

PROJECT(board)

FILE(
    GLOB
    board_files
    ${NXMW_TOP_DIR}/boards/ksdk/nx_reset.c
    ${NXMW_TOP_DIR}/boards/ksdk/se_pit_config.c
    ${NXMW_TOP_DIR}/boards/ksdk/timer_kinetis.c
    ${NXMW_TOP_DIR}/boards/frdmmcxa156/board.c
    ${NXMW_TOP_DIR}/boards/frdmmcxa156/clock_config.c
    ${NXMW_TOP_DIR}/boards/frdmmcxa156/platform_frdmmcxa156.c
    ${NXMW_TOP_DIR}/boards/frdmmcxa156/pin_mux.c
    ${NXMW_TOP_DIR}/../mcuxsdk/components/serial_manager/fsl_component_serial_manager.c
    ${NXMW_TOP_DIR}/../mcuxsdk/components/serial_manager/fsl_component_serial_port_uart.c
    ${NXMW_TOP_DIR}/../mcuxsdk/components/uart/fsl_adapter_lpuart.c
    ${NXMW_TOP_DIR}/../mcuxsdk/components/lists/fsl_component_generic_list.c
    ${NXMW_TOP_DIR}/../mcuxsdk/devices/MCX/MCXA/MCXA156/drivers/fsl_clock.c
    ${NXMW_TOP_DIR}/../mcuxsdk/drivers/lpi2c/fsl_lpi2c.c
    ${NXMW_TOP_DIR}/../mcuxsdk/drivers/lpuart/fsl_lpuart.c
    ${NXMW_TOP_DIR}/../mcuxsdk/drivers/mcx_spc/fsl_spc.c
    ${NXMW_TOP_DIR}/../mcuxsdk/drivers/gpio/fsl_gpio.c
    ${NXMW_TOP_DIR}/../mcuxsdk/devices/MCX/MCXA/MCXA156/drivers/fsl_reset.c
    ${NXMW_TOP_DIR}/../mcuxsdk/devices/MCX/MCXA/MCXA156/system_MCXA156.c
    ${NXMW_TOP_DIR}/../mcuxsdk/components/debug_console/fsl_debug_console.c
    ${NXMW_TOP_DIR}/../mcuxsdk/components/str/fsl_str.c
)

IF(SSS_HAVE_NX_TYPE AND SSS_HAVE_CMSIS_DRIVER_ENABLED)
    LIST(
        APPEND
        board_files
        ${NXMW_TOP_DIR}/boards/cmsis_driver/i2c_cmsis.c
        ${NXMW_TOP_DIR}/boards/cmsis_driver/hardware_init.c
        ${NXMW_TOP_DIR}/../mcuxsdk/components/cmsis_drivers/cmsis_lpi2c/fsl_lpi2c_cmsis.c
        ${NXMW_TOP_DIR}/../mcuxsdk/components/cmsis_drivers/cmsis_gpio/fsl_gpio_cmsis.c
    )
ENDIF()

IF((SSS_HAVE_NX_TYPE) AND (NOT(SSS_HAVE_SMCOM_PN7150)))
    LIST(
        APPEND
        board_files
        ${NXMW_TOP_DIR}/boards/frdmmcxa156/i2c_frdmmcxa156.c
    )
ENDIF()

IF(SSS_HAVE_RTOS_FREERTOS)
    # Not supported
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

IF (SSS_HAVE_CMSIS_DRIVER_ENABLED)
TARGET_INCLUDE_DIRECTORIES(
    board
        PUBLIC
            ${NXMW_TOP_DIR}/../mcuxsdk/components/cmsis_drivers/cmsis_lpi2c/
            ${NXMW_TOP_DIR}/../mcuxsdk/arch/arm/CMSIS/Driver/Include/
            ${NXMW_TOP_DIR}/../mcuxsdk/drivers/lpi2c/
            ${NXMW_TOP_DIR}/../mcuxsdk/drivers/edma4/
            ${NXMW_TOP_DIR}/boards/cmsis_driver/
            ${NXMW_TOP_DIR}/../mcuxsdk/arch/arm/CMSIS/Driver/Include/GPIO/
            ${NXMW_TOP_DIR}/../mcuxsdk/components/cmsis_drivers/cmsis_gpio/
)
ENDIF()

TARGET_INCLUDE_DIRECTORIES(
    board
    PUBLIC ${NXMW_TOP_DIR}/boards/platform
    PUBLIC ${NXMW_TOP_DIR}/boards/ksdk/common/utils
    PUBLIC ${NXMW_TOP_DIR}/../mcuxsdk/middleware/mbedtls/port/ksdk
    PUBLIC ${NXMW_TOP_DIR}/../mcuxsdk/middleware/lwip/src/include
    PUBLIC ${NXMW_TOP_DIR}/../mcuxsdk/middleware/lwip/port
    PUBLIC ${NXMW_TOP_DIR}/../mcuxsdk/components/osa
    PUBLIC ${NXMW_TOP_DIR}/../mcuxsdk/components/lists
    PUBLIC ${NXMW_TOP_DIR}/../mcuxsdk/components/phy
    PUBLIC ${NXMW_TOP_DIR}/../mcuxsdk/components/serial_mwm
    PUBLIC ${NXMW_TOP_DIR}/../mcuxsdk/components/uart
    PUBLIC ${NXMW_TOP_DIR}/../mcuxsdk/components/str
    PUBLIC ${NXMW_TOP_DIR}/../mcuxsdk/components/assert
    PUBLIC ${NXMW_TOP_DIR}/../mcuxsdk/components/debug_console
    PUBLIC ${NXMW_TOP_DIR}/../mcuxsdk/components/debug_console/config
    PUBLIC ${NXMW_TOP_DIR}/../mcuxsdk/components/serial_manager
    PUBLIC ${NXMW_TOP_DIR}/../mcuxsdk/components/osa/config
    PUBLIC ${NXMW_TOP_DIR}/../freertos/corejson/source/include
    PUBLIC ${NXMW_TOP_DIR}/../mcuxsdk/devices/MCX/MCXA/MCXA156
    PUBLIC ${NXMW_TOP_DIR}/../mcuxsdk/devices/MCX/MCXA/MCXA156/drivers
    PUBLIC ${NXMW_TOP_DIR}/../mcuxsdk/devices/MCX/MCXA/periph1
    PUBLIC ${NXMW_TOP_DIR}/../mcuxsdk/arch/arm/CMSIS/Core/Include
    PUBLIC ${NXMW_TOP_DIR}/../mcuxsdk/drivers/common
    PUBLIC ${NXMW_TOP_DIR}/../mcuxsdk/drivers/flexcomm/usart
    PUBLIC ${NXMW_TOP_DIR}/../mcuxsdk/drivers/flexcomm
    PUBLIC ${NXMW_TOP_DIR}/../mcuxsdk/drivers/puf
    PUBLIC ${NXMW_TOP_DIR}/../mcuxsdk/drivers/lpi2c/
    PUBLIC ${NXMW_TOP_DIR}/../mcuxsdk/rtos/freertos/freertos-kernel/include
    PUBLIC ${NXMW_TOP_DIR}/../mcuxsdk/rtos/freertos/freertos-drivers/flexcomm/i2c
    PUBLIC ${NXMW_TOP_DIR}/../mcuxsdk/rtos/freertos/freertos-drivers/flexcomm/usart
    PUBLIC ${NXMW_TOP_DIR}/boards/frdmmcxa156
    PUBLIC ${NXMW_TOP_DIR}/../mcuxsdk/drivers/lpuart
    PUBLIC ${NXMW_TOP_DIR}/../mcuxsdk/drivers/gpio
    PUBLIC ${NXMW_TOP_DIR}/../mcuxsdk/drivers/port
    PUBLIC ${NXMW_TOP_DIR}/../mcuxsdk/drivers/mcx_spc
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

IF(
    "${CMAKE_CXX_COMPILER_ID}"
    STREQUAL
    "GNU"
)
    TARGET_COMPILE_OPTIONS(
        ${PROJECT_NAME}
        PRIVATE -Wno-error=old-style-declaration
    )
    NXMW_DISABLE_EXTRA_WARNINGS(${PROJECT_NAME})

ENDIF()