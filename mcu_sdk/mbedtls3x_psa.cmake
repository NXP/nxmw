# Copyright 2023 NXP
#
# SPDX-License-Identifier: Apache-2.0
#
#
# Manually create project. mbedTLS has it's own CMakeLists.txt
#
PROJECT(mbedtls)

FILE(
    GLOB
    mbedtls_sources
    ${NXMW_TOP_DIR}/../mcuxsdk/middleware/mbedtls3x/library/*.c
    ${NXMW_TOP_DIR}/../mcuxsdk/middleware/mbedtls3x/library/*.h
    ${NXMW_TOP_DIR}/../mcuxsdk/middleware/mbedtls3x/include/mbedtls/*.h
    ${NXMW_TOP_DIR}/../mcuxsdk/middleware/mbedtls3x/include/psa/*.h
)

LIST(
    REMOVE_ITEM
    mbedtls_sources
    ${NXMW_TOP_DIR}/../mcuxsdk/middleware/mbedtls3x/library/psa_crypto.c
)

LIST(
    APPEND
    mbedtls_sources
    ${NXMW_TOP_DIR}/plugin/psa/psa_alt_lib/src/psa_crypto.c
)

IF(SSS_HAVE_KSDK)

    LIST(
        REMOVE_ITEM
        mbedtls_sources
        ${NXMW_TOP_DIR}/../mcuxsdk/middleware/mbedtls3x/library/psa_its_file.c
    )

    LIST(
        APPEND
        mbedtls_sources
        ${NXMW_TOP_DIR}/plugin/psa/psa_alt_lib/src/internal_trusted_storage.c
    )

    LIST(
        REMOVE_ITEM
        mbedtls_sources
        ${NXMW_TOP_DIR}/../mcuxsdk/middleware/mbedtls3x/library/psa_crypto_random_impl.h
    )

    LIST(
        APPEND
        mbedtls_sources
        ${NXMW_TOP_DIR}/plugin/psa/psa_alt_lib/inc/sss_psa_crypto_random_impl.h
    )

    LIST(
        APPEND
        mbedtls_sources
        ${NXMW_TOP_DIR}/plugin/psa/psa_alt_lib/inc/psa/error.h
    )

    LIST(
        APPEND
        mbedtls_sources
        ${NXMW_TOP_DIR}/plugin/psa/psa_alt_lib/inc/psa/internal_trusted_storage.h
    )

ENDIF()

ADD_LIBRARY(
    ${PROJECT_NAME}
    ${mbedtls_sources}
)

TARGET_INCLUDE_DIRECTORIES(
    ${PROJECT_NAME}
    PUBLIC ${NXMW_TOP_DIR}/../mcuxsdk/middleware/mbedtls3x/include
    PUBLIC ${NXMW_TOP_DIR}/../mcuxsdk/middleware/mbedtls3x/library
    PUBLIC ${NXMW_TOP_DIR}/plugin/psa/config
    PUBLIC ${NXMW_TOP_DIR}/plugin/psa/psa_alt_lib/inc
    PUBLIC ${NXMW_TOP_DIR}/plugin/psa/port
    PUBLIC ${NXMW_TOP_DIR}/lib/sss/inc
    PUBLIC ${NXMW_TOP_DIR}/lib/sss/ex/inc
    PUBLIC ${NXMW_TOP_DIR}/lib/hostlib/nx_apdu/inc
    PUBLIC ${NXMW_TOP_DIR}/lib/hostlib/nx_log
    PUBLIC ${NXMW_TOP_DIR}/lib/hostlib/nx_utils
    PUBLIC ${NXMW_TOP_DIR}/lib/hostlib/smCom
    PUBLIC ${NXMW_TOP_DIR}/lib/hostlib/smCom/T1oI2C/
)

IF(SSS_HAVE_KSDK)

    TARGET_LINK_LIBRARIES(
        ${PROJECT_NAME}
        board
    )
    TARGET_INCLUDE_DIRECTORIES(${PROJECT_NAME} PUBLIC ${NXMW_TOP_DIR}/lib/sss/port/ksdk)
    TARGET_COMPILE_DEFINITIONS(${PROJECT_NAME} PUBLIC MBEDTLS_CONFIG_FILE=\"sss_ksdk_mbedtls_3x_psa_config.h\")
    TARGET_COMPILE_DEFINITIONS(${PROJECT_NAME} PUBLIC MBEDTLS_USER_CONFIG_FILE=\"sss_ksdk_mbedtls_3x_psa_config.h\")
ELSE()
    TARGET_INCLUDE_DIRECTORIES(${PROJECT_NAME} PUBLIC ${NXMW_TOP_DIR}/lib/sss/port/default)
    TARGET_COMPILE_DEFINITIONS(${PROJECT_NAME} PUBLIC MBEDTLS_USER_CONFIG_FILE=\"sss_x86_mbedtls_3x_psa_config.h\")
    IF(SSS_HAVE_HOST_PCWINDOWS)
        TARGET_LINK_LIBRARIES(
            ${PROJECT_NAME}
            Bcrypt
        )
    ENDIF()
    IF(SSS_HAVE_SMCOM_PCSC)
        TARGET_LINK_LIBRARIES(
            ${PROJECT_NAME}
            ws2_32
        )
    ENDIF()
ENDIF()

TARGET_COMPILE_DEFINITIONS(${PROJECT_NAME} PUBLIC MBEDTLS_DRIVER_CONFIG_FILE=\"sss_psa_crypto_driver_wrappers.h\")

IF(
    CMAKE_CXX_COMPILER
    MATCHES
    ".*clang"
    OR CMAKE_CXX_COMPILER_ID
       STREQUAL
       "AppleClang"
)
    TARGET_COMPILE_OPTIONS(
        ${PROJECT_NAME}
        PRIVATE -Wno-unused-function
        PRIVATE -Wno-error=pointer-sign
        PRIVATE -Wno-error=format
        PRIVATE -Wno-format
        PRIVATE -Wno-error=unused-const-variable
        PRIVATE -Wno-unused-const-variable
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
            PRIVATE /wd4245 # '=': conversion from 'int' to 'mbedtls_mpi_uint', signed/unsigned misma
            PRIVATE /wd4310 # cast truncates constant value
            PRIVATE /wd4389 # '==': signed/unsigned mismatch
            PRIVATE /wd4132 # const object should be initialized
            PRIVATE /wd4127 # conditional expression is constant
            PRIVATE /wd4701 # potentially uninitialized local variable
            PRIVATE /wd4477 # 'printf' : format string '%d'
            PRIVATE /wd4200 # nonstandard extension used
            PRIVATE /wd4057 # mbedtls code warning
            PRIVATE /wd4295 # array is too small to include a terminating null character
            PRIVATE /wd4703 # potentially unintialized local pointer
            PRIVATE /wd4702 # unreachable code
            PRIVATE /wd4706 # assignment within conditional expression
        )
    ENDIF()
ENDIF()

IF(
    "${CMAKE_CXX_COMPILER_ID}"
    STREQUAL
    "GNU"
)
    TARGET_COMPILE_OPTIONS(
        ${PROJECT_NAME}
        PRIVATE -Wno-unused-function
        PRIVATE -Wno-error=pointer-sign
        PRIVATE -Wno-error=format
        PRIVATE -Wno-format
    )

    SET(GCC_VERSION_WITH_UNUSED_CONST 6.3.0)
    IF(
        GCC_VERSION_WITH_UNUSED_CONST
        VERSION_LESS
        CMAKE_CXX_COMPILER_VERSION
    )
        TARGET_COMPILE_OPTIONS(
            ${PROJECT_NAME}
            PRIVATE -Wno-error=unused-const-variable
            PRIVATE -Wno-unused-const-variable
        )
    ENDIF()
ENDIF()
