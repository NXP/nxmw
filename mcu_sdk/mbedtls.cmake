# Copyright 2019-2025 NXP
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
    ../../mcuxsdk/middleware/mbedtls/library/*.c
    ../../mcuxsdk/middleware/mbedtls/library/*.h
    ../../mcuxsdk/middleware/mbedtls/include/mbedtls/*.h
)

IF((SSS_HAVE_KSDK) AND (NOT SSS_HAVE_HOST_FRDMMCXA153))
    FILE(
        GLOB
        mbedtls_ksdk_sources
        ../../mcuxsdk/middleware/mbedtls/port/ksdk/*.c
        ../../mcuxsdk/middleware/mbedtls/port/ksdk/*.h
    )
ENDIF()

ADD_LIBRARY(
    ${PROJECT_NAME}
    ${mbedtls_ksdk_sources}
    ${mbedtls_sources}
)

TARGET_INCLUDE_DIRECTORIES(
    ${PROJECT_NAME}
    PUBLIC ../../mcuxsdk/middleware/mbedtls/include
    PUBLIC ../../mcuxsdk/middleware/mbedtls/library
    PUBLIC ../../mcuxsdk/drivers/hashcrypt
    PUBLIC ../../mcuxsdk/drivers/casper
    PUBLIC ../../mcuxsdk/drivers/rng
)

IF(SSS_HAVE_KSDK)
    TARGET_INCLUDE_DIRECTORIES(${PROJECT_NAME}
        PUBLIC
        ${NXMW_TOP_DIR}/lib/sss/port/ksdk
        ../../mcuxsdk/middleware/mbedtls/port/ksdk
        )
    IF(SSS_HAVE_HOST_FRDMMCXA153)
        TARGET_COMPILE_DEFINITIONS(${PROJECT_NAME} PUBLIC MBEDTLS_CONFIG_FILE=\"ksdk_mcxa_mbedtls_config.h\")
    ELSE()
        TARGET_COMPILE_DEFINITIONS(${PROJECT_NAME} PUBLIC MBEDTLS_CONFIG_FILE=\"ksdk_mbedtls_config.h\")
        TARGET_COMPILE_DEFINITIONS(${PROJECT_NAME} PUBLIC MBEDTLS_USER_CONFIG_FILE=\"sss_ksdk_mbedtls_2x_usr_config.h\")
    ENDIF ()

    TARGET_LINK_LIBRARIES(
        ${PROJECT_NAME}
        board
    )
ELSE()
    TARGET_INCLUDE_DIRECTORIES(${PROJECT_NAME} PUBLIC ${NXMW_TOP_DIR}/lib/sss/port/default)
    TARGET_COMPILE_DEFINITIONS(${PROJECT_NAME} PUBLIC MBEDTLS_USER_CONFIG_FILE=\"sss_x86_mbedtls_2x_usr_config.h\")
ENDIF()


IF(
    "${CMAKE_C_COMPILER}"
    MATCHES
    ".*clang"
    OR "${CMAKE_CXX_COMPILER_ID}"
       STREQUAL
       "AppleClang"
)
    # MESSAGE(STATUS "-- No warning for mbedtls")
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
            PUBLIC /wd4127 # conditional expression is constant
            PRIVATE /wd4701 # potentially uninitialized local variable
            PRIVATE /wd4477 # 'printf' : format string '%d'
            PRIVATE /wd4200 # zero-sized array in struct/union
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
            PRIVATE -Wno-implicit-function-declaration
            PRIVATE -Wno-error=unused-const-variable
            PRIVATE -Wno-unused-const-variable
        )
    ENDIF()
ENDIF()
