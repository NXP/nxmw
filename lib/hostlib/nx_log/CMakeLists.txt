#
# Copyright 2024 NXP
# SPDX-License-Identifier: BSD-3-Clause
#

PROJECT(mwlog)

FILE(
    GLOB
    source_files
    *.h
    )

IF(NOT SSS_HAVE_LOG_SEGGERRTT)
    IF(NOT SSS_HAVE_HOST_LPCXPRESSO55S_NS)
        FILE(
            GLOB
            nxLog_sources
            nxLog.c
        )
    ENDIF()
ENDIF()

IF(BUILD_SHARED_LIBS)
    ADD_LIBRARY(${PROJECT_NAME} SHARED ${source_files} ${nxLog_sources})
ELSE()
    ADD_LIBRARY(${PROJECT_NAME} ${source_files} ${nxLog_sources})
ENDIF()

TARGET_INCLUDE_DIRECTORIES(
    ${PROJECT_NAME}
    PUBLIC .
    PUBLIC ../nx_utils
    PUBLIC ${NXMW_TOP_DIR}/boards/inc
    PUBLIC ${NXMW_TOP_DIR}/boards/platform
)

IF(SSS_HAVE_KSDK)
    TARGET_LINK_LIBRARIES(${PROJECT_NAME} board)
ENDIF()

IF(SSS_HAVE_RTOS_FREERTOS)
    TARGET_LINK_LIBRARIES(${PROJECT_NAME} freertos-kernel)
ENDIF()

IF(CMAKE_COMPILER_IS_GNUCC AND (NOT SSS_HAVE_KSDK))
    TARGET_LINK_LIBRARIES(${PROJECT_NAME} -lpthread)
ENDIF()

IF((SSS_HAVE_HOST_LINUX_LIKE) AND NOT(NXPInternal))
    ADD_CUSTOM_COMMAND(
        TARGET ${PROJECT_NAME}
        POST_BUILD
        COMMAND sudo cp $<TARGET_FILE:${PROJECT_NAME}> /usr/local/lib/
        COMMENT "Copying lib${PROJECT_NAME}.so to /usr/local/lib/"
    )
ENDIF()
