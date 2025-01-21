#
# Copyright 2019,2020,2023-2024 NXP
# SPDX-License-Identifier: BSD-3-Clause
#
#

PROJECT(SSS_APIs LANGUAGES C)

FILE(
    GLOB
    API_FILES
    inc/*.h
    inc/*.h.in
    src/*.c
    src/nx/*.c
    src/mbedtls/*.c
    src/openssl/*.c
    src/keystore/*.c
    port/default/*.h
)

ADD_LIBRARY(${PROJECT_NAME} ${API_FILES})

TARGET_INCLUDE_DIRECTORIES(
    ${PROJECT_NAME}
    PUBLIC inc
)

IF(SSS_HAVE_KSDK)
    TARGET_INCLUDE_DIRECTORIES(${PROJECT_NAME} PUBLIC port/ksdk)
ELSE()
    TARGET_INCLUDE_DIRECTORIES(${PROJECT_NAME} PUBLIC port/default)
ENDIF()

IF(SSS_HAVE_HOSTCRYPTO_MBEDTLS)
    TARGET_LINK_LIBRARIES(${PROJECT_NAME} mbedtls)
ENDIF()

IF(SSS_HAVE_HOSTCRYPTO_OPENSSL)
    TARGET_LINK_LIBRARIES(${PROJECT_NAME} ${OPENSSL_LIBRARIES})
ENDIF()

IF(SSS_HAVE_NX_TYPE)
    TARGET_LINK_LIBRARIES(
        ${PROJECT_NAME}
        nx_apdu
        nx_utils
    )
ENDIF()

TARGET_LINK_LIBRARIES(
    ${PROJECT_NAME} smCom
)

IF(SSS_HAVE_HOST_LINUX_LIKE)
    INSTALL(TARGETS ${PROJECT_NAME} DESTINATION lib)
ENDIF()

IF(SSS_HAVE_HOSTCRYPTO_ANY)
    IF(SSS_HAVE_HOST_LINUX_LIKE)
        INSTALL(
            DIRECTORY inc/ port/default/
            DESTINATION ${NXMW_INSTALL_INC_DIR}
            FILES_MATCHING
            PATTERN "*.h"
        )
        IF(NOT(NXPInternal))
            ADD_CUSTOM_COMMAND(
                TARGET ${PROJECT_NAME}
                POST_BUILD
                COMMAND sudo cp $<TARGET_FILE:${PROJECT_NAME}> /usr/local/lib/
                COMMENT "Copying lib${PROJECT_NAME}.so to /usr/local/lib/"
            )
        ENDIF()
    ENDIF()

    IF(SSS_HAVE_HOST_LINUX_LIKE)
        INSTALL(TARGETS ${PROJECT_NAME} DESTINATION lib)
    ENDIF(SSS_HAVE_HOST_LINUX_LIKE)

ENDIF(SSS_HAVE_HOSTCRYPTO_ANY)
