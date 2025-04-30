#
# Copyright 2019,2020,2025 NXP
# SPDX-License-Identifier: BSD-3-Clause
#
#

PROJECT(nx_apdu)

FILE(
    GLOB
    sources
    src/nx_apdu.c
    src/nx_apdu_tlv.c
    src/nxSecureMsg_Com.c
    inc/*.h
)

ADD_LIBRARY(${PROJECT_NAME} ${sources})

TARGET_LINK_LIBRARIES(
    ${PROJECT_NAME} smCom
)

TARGET_INCLUDE_DIRECTORIES(
    ${PROJECT_NAME}
    PUBLIC inc
    PUBLIC ../inc
    PUBLIC ${NXMW_TOP_DIR}/lib/sss/ex/inc
    PUBLIC ${NXMW_TOP_DIR}/lib/sss/inc
    PUBLIC ${NXMW_TOP_DIR}/lib/hostlib/smCom
)
IF(SSS_HAVE_HOSTCRYPTO_MBEDTLS)
    IF(SSS_HAVE_MBEDTLS_3_X)
        TARGET_INCLUDE_DIRECTORIES(
            ${PROJECT_NAME}
                PUBLIC ../../../../mcuxsdk/middleware/mbedtls3x/include
        )
    ELSE()
        TARGET_INCLUDE_DIRECTORIES(
            ${PROJECT_NAME}
            PUBLIC ../../../../mcuxsdk/middleware/mbedtls/include
            PUBLIC ../../../../mcuxsdk/middleware/mbedtls/library
        )
    ENDIF()
ENDIF()

IF(SSS_HAVE_KSDK)
    TARGET_INCLUDE_DIRECTORIES(
        ${PROJECT_NAME}
        PUBLIC ${NXMW_TOP_DIR}/lib/sss/port/ksdk
    )
ELSE()
    TARGET_INCLUDE_DIRECTORIES(
        ${PROJECT_NAME}
        PUBLIC ${NXMW_TOP_DIR}/lib/sss/port/default
    )
ENDIF()

IF(SSS_HAVE_HOSTCRYPTO_MBEDTLS)
    TARGET_COMPILE_DEFINITIONS(
        ${PROJECT_NAME}
        PUBLIC MBEDTLS # FIXME : This must eventually not be needed because sss APIs should be enough
    )
ENDIF()

IF(
    "${CMAKE_CXX_COMPILER_ID}"
    MATCHES
    "MSVC"
)
    IF(NXPInternal)
        TARGET_COMPILE_OPTIONS(
        ${PROJECT_NAME}
        PUBLIC /wd4200 # zero-sized array in struct/union
        )
    ENDIF()
ENDIF()

IF((SSS_HAVE_HOST_LINUX_LIKE) AND NOT(NXPInternal))
    ADD_CUSTOM_COMMAND(
        TARGET ${PROJECT_NAME}
        POST_BUILD
        COMMAND sudo cp $<TARGET_FILE:${PROJECT_NAME}> /usr/local/lib/
        COMMENT "Copying lib${PROJECT_NAME}.so to /usr/local/lib/"
    )
ENDIF()
