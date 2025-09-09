# Copyright 2019,2024 NXP
#
# SPDX-License-Identifier: Apache-2.0
#

PROJECT(freertos-kernel)

FILE(
    GLOB
    files
    ../../mcuxsdk/rtos/freertos/freertos-kernel/croutine.c
    ../../mcuxsdk/rtos/freertos/freertos-kernel/event_groups.c
    ../../mcuxsdk/rtos/freertos/freertos-kernel/list.c
    ../../mcuxsdk/rtos/freertos/freertos-kernel/queue.c
    ../../mcuxsdk/rtos/freertos/freertos-kernel/stream_buffer.c
    ../../mcuxsdk/rtos/freertos/freertos-kernel/tasks.c
    ../../mcuxsdk/rtos/freertos/freertos-kernel/timers.c
    ../../mcuxsdk/components/aws_iot/logging/logging.c
)

IF(SSS_HAVE_HOST_LPCXPRESSO55S OR SSS_HAVE_HOST_FRDMMCXN947)
    FILE(
        GLOB
        port_files
        ../../mcuxsdk/rtos/freertos/freertos-kernel/portable/GCC/ARM_CM33_NTZ/non_secure/*.c
        ../../mcuxsdk/rtos/freertos/freertos-kernel/portable/MemMang/heap_4.c
        ../boards/ksdk/common/freertos/FreeRTOSConfig.c
    )
ENDIF()

IF( SSS_HAVE_NX_TYPE)
    LIST(
        APPEND
        port_files
        ${NXMW_TOP_DIR}/lib/hostlib/nx_utils/sm_demo_utils_rtos.c
    )
ENDIF()

ADD_LIBRARY(${PROJECT_NAME} ${files} ${port_files})

TARGET_INCLUDE_DIRECTORIES(
    ${PROJECT_NAME}
    PUBLIC ${NXMW_TOP_DIR}/sss/ex/inc
    PUBLIC ${NXMW_TOP_DIR}/boards/ksdk/common
    PUBLIC ../../mcuxsdk/rtos/freertos/freertos-kernel/portable/GCC/ARM_CM33_NTZ/non_secure
    PUBLIC ../../mcuxsdk/rtos/freertos/freertos-kernel/include
    PUBLIC ../../mcuxsdk/components/aws_iot/logging
    PUBLIC ../../mcuxsdk/components/debug_console
    PUBLIC ../../mcuxsdk/drivers/common
    PUBLIC ../../mcuxsdk/arch/arm/CMSIS/Core/Include
)

IF(SSS_HAVE_HOST_LPCXPRESSO55S)
    TARGET_INCLUDE_DIRECTORIES(
        ${PROJECT_NAME}
        PUBLIC ${NXMW_TOP_DIR}/boards/lpcxpresso55s69/freertos
        PUBLIC ../../mcuxsdk/devices/LPC/LPC5500/periph
    )
ENDIF()

IF(SSS_HAVE_HOST_FRDMMCXN947)
    TARGET_INCLUDE_DIRECTORIES(
        ${PROJECT_NAME}
        PUBLIC ../../mcuxsdk/rtos/freertos/freertos-kernel/portable/GCC/ARM_CM33_NTZ/non_secure
        PUBLIC ../boards/frdmmcxn947/freertos
        PUBLIC ../../mcuxsdk/devices/MCX/MCXN/MCXN947
        PUBLIC ../../mcuxsdk/devices/MCX/MCXN/periph
        PUBLIC ../../mcuxsdk/devices/MCX/MCXN/MCXN947/drivers
    )
ENDIF()

ADD_DEFINITIONS(-DSSS_USE_FTR_FILE)

TARGET_COMPILE_OPTIONS(
        ${PROJECT_NAME}
        PRIVATE -Wno-sign-compare
    )




#######################################################################################

PROJECT(freertos-ip)

FILE(
    GLOB
    files
    ../../mcuxsdk/rtos/freertos/corejson/source/core_json.c
    ../../mcuxsdk/rtos/freertos/corepkcs11/source/core_pkcs11.c
    ../../mcuxsdk/rtos/freertos/coremqtt/source/core_mqtt.c
    ../../mcuxsdk/rtos/freertos/coremqtt/source/core_mqtt_serializer.c
    ../../mcuxsdk/rtos/freertos/coremqtt/source/core_mqtt_state.c
    ../../mcuxsdk/rtos/freertos/backoffalgorithm/source/backoff_algorithm.c
    ../../mcuxsdk/rtos/freertos/corepkcs11/source/core_pki_utils.c
)

IF(SSS_HAVE_KSDK)
    IF(SSS_HAVE_HOST_FRDMMCXN947)
        FILE(
            GLOB
            port_files
            ../../mcuxsdk/middleware/lwip/src/core/*.c
            ../../mcuxsdk/middleware/lwip/src/core/ipv4/*.c
            ../../mcuxsdk/middleware/lwip/src/api/*.c
            ../../mcuxsdk/middleware/lwip/src/netif/ethernet.c
            ../../mcuxsdk/middleware/lwip/port/ethernetif.c
            ../../mcuxsdk/middleware/lwip/port/ethernetif_mmac.c
            ../../mcuxsdk/middleware/lwip/port/enet_ethernetif.c
            ../../mcuxsdk/components/aws_iot/using_mbedtls_pkcs11/*.c
            ../../mcuxsdk/middleware/lwip/port/sys_arch/dynamic/sys_arch.c
            ../../mcuxsdk/drivers/mcx_enet/fsl_enet.c
            ../../mcuxsdk/middleware/lwip/port/sys_arch.c
            ../../mcuxsdk/middleware/lwip/src/api/netdb.c
            ../../mcuxsdk/middleware/lwip/src/api/sockets.c
            ../../mcuxsdk/middleware/lwip/port/enet_ethernetif_lpc.c
        )
    ENDIF()

    # IF(SSS_HAVE_HOST_FRDMMCXN947)
    #     LIST(
    #         APPEND
    #         port_files
    #         ../../mcuxsdk/middleware/lwip/port/enet_ethernetif_lpc.c
    #     )
    # ELSE()
    #     LIST(
    #         APPEND
    #         port_files
    #         ../../mcuxsdk/middleware/lwip/port/enet_ethernetif_kinetis.c
    #     )
    # ENDIF()

    FILE (
        GLOB
        pkcs11_files
        ${NXMW_TOP_DIR}/plugin/pkcs11/*.c
    )

ENDIF()

# IF(SSS_HAVE_HOST_LPCXPRESSO55S)
#     FILE(
#         GLOB
#         port_files
#         ../../mcuxsdk/components/aws_iot/using_mbedtls_wifi_serial/using_mbedtls.c
#     )
# ENDIF()

ADD_LIBRARY(
    ${PROJECT_NAME}
    ${files}
    ${port_files}
    ${alt_files}
    ${pkcs11_files}
)

TARGET_INCLUDE_DIRECTORIES(
    ${PROJECT_NAME}
    PUBLIC ../../mcuxsdk/rtos/freertos/corepkcs11/source/include
    PUBLIC ../../mcuxsdk/components/aws_iot/logging
    PUBLIC ../../mcuxsdk/rtos/freertos/freertos-kernel/template/ARM_CM4F
    PUBLIC ../../mcuxsdk/middleware/pkcs11
    PUBLIC ../../mcuxsdk/rtos/freertos/corejson/source/include
    PUBLIC ../../mcuxsdk/rtos/freertos/coremqtt/source/include
    PUBLIC ../../mcuxsdk/rtos/freertos/coremqtt/source/interface
    PUBLIC ../../mcuxsdk/rtos/freertos/backoffalgorithm/source/include
    PUBLIC ../../mcuxsdk/rtos/freertos/freertos-kernel/template/
    PUBLIC ../../mcuxsdk/examples/aws_examples/common/
    PUBLIC ../../mcuxsdk/components/aws_iot/using_mbedtls_pkcs11
    PUBLIC ../../mcuxsdk/components/aws_iot/using_mbedtls_wifi_serial
    PUBLIC ../../mcuxsdk/components/serial_mwm
    PUBLIC ../../mcuxsdk/components/gpio
)

IF(SSS_HAVE_KSDK)
    TARGET_INCLUDE_DIRECTORIES(
        ${PROJECT_NAME}
        PUBLIC ../boards/ksdk/common
        PUBLIC ../boards/ksdk/gcp
        PUBLIC ../../mcuxsdk/middleware/lwip/port/sys_arch/dynamic
        PUBLIC ../../mcuxsdk/drivers/mcx_enet
        PUBLIC ../../mcuxsdk/middleware/lwip/port
        PUBLIC ../../mcuxsdk/middleware/lwip/src
        PUBLIC ../../mcuxsdk/middleware/lwip/src/include
        PUBLIC ../../mcuxsdk/middleware/lwip/src/include/lwip
        PUBLIC ${NXMW_TOP_DIR}/plugin/pkcs11
    )
ENDIF()

IF(SSS_HAVE_HOST_FRDMMCXN947)
    ADD_DEFINITIONS(-DUSE_RTOS=1)
    ADD_DEFINITIONS(-DEXAMPLE_USE_MCXN_ENET_PORT)
    ADD_DEFINITIONS(-DLPC_ENET)
    ADD_DEFINITIONS(-DCHECKSUM_GEN_UDP=1)
    ADD_DEFINITIONS(-DCHECKSUM_GEN_TCP=1)
    ADD_DEFINITIONS(-DCHECKSUM_GEN_ICMP=1)
    ADD_DEFINITIONS(-DCHECKSUM_GEN_ICMP6=1)
    ADD_DEFINITIONS(-DCHECKSUM_CHECK_IP=1)
    ADD_DEFINITIONS(-DCHECKSUM_CHECK_UDP=1)
    ADD_DEFINITIONS(-DCHECKSUM_CHECK_TCP=1)
    ADD_DEFINITIONS(-DCHECKSUM_CHECK_ICMP=1)
    ADD_DEFINITIONS(-DCHECKSUM_CHECK_ICMP6=1)
    ADD_DEFINITIONS(-DLWIP_DISABLE_PBUF_POOL_SIZE_SANITY_CHECKS=1)
    ADD_DEFINITIONS(-DLWIP_SUPPORT_CUSTOM_PBUF=1)
ENDIF()

TARGET_LINK_LIBRARIES(
    ${PROJECT_NAME}
    mbedtls
    freertos-kernel
    ex_common
)

IF(
    "${CMAKE_CXX_COMPILER_ID}"
    STREQUAL
    "GNU"
)
    TARGET_COMPILE_OPTIONS(
        ${PROJECT_NAME}
        PRIVATE -Wno-error=unused-variable
        PRIVATE -Wno-unused-variable
        PRIVATE -Wno-address-of-packed-member
        PRIVATE -Wno-unused-function
        PRIVATE -Wno-array-bounds
    )
    NXMW_DISABLE_EXTRA_WARNINGS(${PROJECT_NAME})

ENDIF()
