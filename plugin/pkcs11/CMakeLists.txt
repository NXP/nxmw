#
# Copyright 2024-2025 NXP
# SPDX-License-Identifier: BSD-3-Clause
#
#

PROJECT(sss_pkcs11)

FILE(
    GLOB
    files
    ${PROJECT_NAME}.c
)

FILE(
    GLOB
    pkcs11_files
    *.c
)

ADD_DEFINITIONS(-DPKCS11_LIBRARY)
ADD_DEFINITIONS(-DPKCS11_SESSION_OPEN)

ADD_LIBRARY(${PROJECT_NAME} SHARED ${files} ${pkcs11_files})

TARGET_INCLUDE_DIRECTORIES(
    ${PROJECT_NAME}
    PRIVATE ${NXMW_TOP_DIR}/plugin/pkcs11
    PRIVATE ${NXMW_TOP_DIR}/ext/pkcs11/published/2-40-errata-1
)

TARGET_LINK_LIBRARIES(
    ${PROJECT_NAME} ex_common
)

IF(
    "${CMAKE_CXX_COMPILER_ID}"
    MATCHES
    "MSVC"
)
    TARGET_COMPILE_OPTIONS(
        ${PROJECT_NAME}
        PRIVATE
            /wd4310
            /wd4267
    )
ENDIF()

IF(SSS_HAVE_HOST_LINUX_LIKE)
    INSTALL(TARGETS ${PROJECT_NAME} DESTINATION lib)
ENDIF()

ADD_CUSTOM_COMMAND(
    TARGET ${PROJECT_NAME}
    POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:${PROJECT_NAME}> ${NXMW_TOP_DIR}/plugin/pkcs11/bin
    COMMENT "Copy dll to ${NXMW_TOP_DIR}/plugin/pkcs11/bin"
)
