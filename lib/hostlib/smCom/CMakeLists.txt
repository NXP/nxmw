#
# Copyright 2022-2024 NXP
# SPDX-License-Identifier: BSD-3-Clause
#
#

# Common and Communication Layers

PROJECT(smCom)

IF(SSS_HAVE_HOST_PCWINDOWS AND SSS_HAVE_SMCOM_VCOM)
    FILE(
        GLOB
        smCom_vcom_sources
        smComSerial*.h
        smComSerial_win32.c
    )
ENDIF()

IF(SSS_HAVE_HOST_PCWINDOWS AND SSS_HAVE_SMCOM_PCSC)
    FILE(
        GLOB
        smCom_pcsc_sources
        smComPCSC.c
        smComPCSC.h
    )
ENDIF()

IF( (SSS_HAVE_HOST_PCLINUX OR SSS_HAVE_HOST_RASPBIAN) AND SSS_HAVE_SMCOM_VCOM)
    FILE(
        GLOB
        smCom_vcom_sources
        smComSerial*.h
        smComSerial_PCLinux.c
        smComSocket_fd.c
    )
ENDIF()

IF((SSS_HAVE_HOST_PCLINUX OR SSS_HAVE_HOST_RASPBIAN) AND SSS_HAVE_SMCOM_JRCP_V1_AM)
    FILE(
        GLOB
        smCom_jrcpv1_sources
        smComSocket*.h
        smComSocket_linux.c
        smComSocket_fd.c
    )
ENDIF()

IF(SSS_HAVE_HOST_PCWINDOWS AND SSS_HAVE_SMCOM_JRCP_V1_AM)
    FILE(
        GLOB
        smCom_jrcpv1_sources
        smComSocket*.h
        smComSocket_win32.c
    )
ENDIF()

IF(SSS_HAVE_SMCOM_T1OI2C_GP1_0)
    FILE(
        GLOB
        smCom_T1oI2C_GP1_0_sources
        T1oI2C/*.c
        smComT1oI2C*.h
        smComT1oI2C*.c
    )
    #ADD_DEFINITIONS(-DT1OI2C_SEND_DEEP_PWR_DOWN)

    IF(SSS_HAVE_HOST_LINUX_LIKE)
        ADD_DEFINITIONS(-DT1OI2C_RETRY_ON_I2C_FAILED)
    ENDIF()
ENDIF()


#TODO - Can be moved to boards library at root
IF(SSS_HAVE_SMCOM_T1OI2C_GP1_0 AND (SSS_HAVE_HOST_RASPBIAN OR SSS_HAVE_HOST_PCLINUX64))
    FILE(
        GLOB
        smCom_T1oI2C_i2c_sources
        ${NXMW_TOP_DIR}/boards/linux/i2c_a7.c
        ${NXMW_TOP_DIR}/boards/linux/gpio_nx.c
    )
ENDIF()


IF(SSS_HAVE_SMCOM_PN7150)
    FILE(
        GLOB
        smCom_pn7150_sources
        smCom/smComPN7150*.h
        smCom/smComPN7150*.c
    )
ENDIF()

IF(SSS_HAVE_KSDK)
# timer files are included as part of boards library
ELSE()
    SET(
        smCom_timer_sources
        ${NXMW_TOP_DIR}/boards/generic/sm_timer.c
    )
ENDIF()

FILE(
    GLOB
    smCom_sources
    smCom.c
    ../nx_utils/nx_host_gpio.c
    ${smCom_vcom_sources}
    ${smCom_timer_sources}
    ${smCom_T1oI2C_GP1_0_sources}
    ${smCom_jrcpv1_sources}
    ${smCom_T1oI2C_i2c_sources}
    ${smCom_pn7150_sources}
    ${smCom_pcsc_sources}
)

ADD_LIBRARY(smCom ${smCom_sources})

TARGET_INCLUDE_DIRECTORIES(
    smCom
    PUBLIC .
    PUBLIC ../inc
    PUBLIC ../nx_auth
    PUBLIC ../nx_apdu/inc
    PUBLIC ../nx_utils
    PUBLIC ../nx_log
    PUBLIC ../../../tst/tstUtil/
    PUBLIC ../log
    PUBLIC T1oI2C
    PRIVATE ${NXMW_TOP_DIR}/lib/sss/ex/inc
    PRIVATE ${NXMW_TOP_DIR}/lib/sss/inc
    PUBLIC ${NXMW_TOP_DIR}/boards/inc
)

IF(SSS_HAVE_KSDK)
    INCLUDE_DIRECTORIES(${NXMW_TOP_DIR}/lib/sss/port/ksdk)
ELSE()
    INCLUDE_DIRECTORIES(${NXMW_TOP_DIR}/lib/sss/port/default)
ENDIF()

IF(SSS_HAVE_LOG_SEGGERRTT)
    TARGET_LINK_LIBRARIES(smCom board)
ELSE()
    # Board library is included from mwlog
    TARGET_LINK_LIBRARIES(smCom mwlog)
ENDIF()

IF(SSS_HAVE_SMCOM_PN7150)
    TARGET_LINK_LIBRARIES(smCom PN7150Nfc)
    TARGET_COMPILE_DEFINITIONS(smCom PUBLIC SMCOM_PN7150)
ENDIF()

IF(SSS_HAVE_SMCOM_PCSC)
    TARGET_COMPILE_DEFINITIONS(smCom PUBLIC SMCOM_PCSC)
    IF(SSS_HAVE_HOST_PCLINUX)
        TARGET_INCLUDE_DIRECTORIES(smCom PRIVATE /usr/include/PCSC)
    ENDIF()
ENDIF()

IF(SSS_HAVE_HOST_RASPBIAN AND SSS_HAVE_SMCOM_T1OI2C_GP1_0)
    TARGET_COMPILE_DEFINITIONS(smCom PUBLIC SSS_HAVE_HOST_RASPBIAN)
ENDIF()

IF(SSS_HAVE_SMCOM_VCOM)
    TARGET_COMPILE_DEFINITIONS(smCom PUBLIC RJCT_VCOM)
ENDIF()

IF(SSS_HAVE_SMCOM_T1OI2C_GP1_0)
    TARGET_COMPILE_DEFINITIONS(smCom PRIVATE T1oI2C_GP1_0)
ENDIF()

IF(SSS_HAVE_SMCOM_JRCP_V1_AM)
    TARGET_COMPILE_DEFINITIONS(smCom PUBLIC JRCP_V1_AM)
ENDIF()

IF(SSS_HAVE_LOG_SEGGERRTT)
    TARGET_LINK_LIBRARIES(smCom seggerrtt)
ENDIF()

IF(CMAKE_COMPILER_IS_GNUCC AND (NOT SSS_HAVE_KSDK))
    TARGET_LINK_LIBRARIES(smCom -lpthread)
ENDIF()

IF(SSS_HAVE_HOST_PCLINUX)
    TARGET_LINK_LIBRARIES(smCom -lrt)
ENDIF()

IF(SSS_HAVE_SMCOM_PCSC)
    IF(SSS_HAVE_HOST_PCWINDOWS)
        TARGET_LINK_LIBRARIES(${PROJECT_NAME} Winscard)
    ENDIF()
    IF(SSS_HAVE_HOST_PCLINUX)
        TARGET_LINK_LIBRARIES(${PROJECT_NAME} pcsclite)
    ENDIF()
ENDIF()

IF(SSS_HAVE_RTOS_FREERTOS AND SSS_HAVE_HOST_PCWINDOWS)
    TARGET_LINK_LIBRARIES(${PROJECT_NAME} freertos-kernel)
ENDIF()

IF((SSS_HAVE_HOST_LINUX_LIKE) AND NOT(NXPInternal))
    ADD_CUSTOM_COMMAND(
        TARGET ${PROJECT_NAME}
        POST_BUILD
        COMMAND sudo cp $<TARGET_FILE:${PROJECT_NAME}> /usr/local/lib/
        COMMENT "Copying lib${PROJECT_NAME}.so to /usr/local/lib/"
    )
ENDIF()
