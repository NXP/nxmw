#
# Copyright 2019,2020 NXP
# SPDX-License-Identifier: BSD-3-Clause
#
#

PROJECT(ex_common)

FILE(
    GLOB
    files
    ex_sss_boot_connectstring.c
    ex_sss_boot.c
    *.h
    ../inc/*.h
)

if (SSS_HAVE_HOST_EMBEDDED)
    FILE(
        GLOB
        board_files
        ${NXMW_TOP_DIR}/boards/platform/platform.c
    )
ENDIF()

IF(SSS_HAVE_NX_TYPE)
    FILE(
        GLOB
        nx_files
        ex_sss_nx.c
    )
ENDIF()

IF(SSS_HAVE_HOSTCRYPTO_MBEDTLS OR SSS_HAVE_HOSTCRYPTO_OPENSSL)
    FILE(
        GLOB
        mbedtls_files
        ex_sss_boot_sw.c
    )
ENDIF()

ADD_LIBRARY(
    ${PROJECT_NAME}
    ${files}
    ${nx_files}
    ${mbedtls_files}
    ${board_files}
)

TARGET_LINK_LIBRARIES(
    ${PROJECT_NAME} SSS_APIs
)

TARGET_INCLUDE_DIRECTORIES(
    ${PROJECT_NAME}
    PUBLIC ../inc
    PUBLIC ${NXMW_TOP_DIR}/boards/platform
)

IF(
    "${CMAKE_CXX_COMPILER_ID}"
    MATCHES
    "MSVC"
)
    IF(NXPInternal)
        TARGET_COMPILE_OPTIONS(${PROJECT_NAME} PRIVATE /wd4127 # conditional expression is constant
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
