# Copyright 2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
#
#

PROJECT(psa_alt_lib)

IF(SSS_HAVE_KSDK)
    FILE(
        GLOB
        ${PROJECT_NAME}_files
        src/psa_alt.c
        src/psa_alt_utils.c
        src/psa_alt_flash.c
        src/sss_psa_alt.c
    )
ELSE()
    FILE(
        GLOB
        ${PROJECT_NAME}_files
        src/psa_alt.c
        src/psa_alt_utils.c
        src/sss_psa_alt.c
    )
ENDIF()

GET_FILENAME_COMPONENT(
    psa_crypto_file
    ${NXMW_TOP_DIR}/../mcuxsdk/middleware/mbedtls3x/library/psa_crypto.c
    ABSOLUTE
)

LIST(
    REMOVE_ITEM
    ${PROJECT_NAME}_files
    "${psa_crypto_file}"
)

LIST(
    APPEND
    ${PROJECT_NAME}_files
    ${NXMW_TOP_DIR}/plugin/psa/psa_alt_lib/src/psa_crypto.c
)

ADD_LIBRARY(${PROJECT_NAME} ${${PROJECT_NAME}_files})

TARGET_LINK_LIBRARIES(
    ${PROJECT_NAME}
    ex_common
)

IF(SSS_HAVE_KSDK)
    TARGET_INCLUDE_DIRECTORIES(
        ${PROJECT_NAME}
        PUBLIC ${NXMW_TOP_DIR}/lib/sss/ex/inc
        PUBLIC ${NXMW_TOP_DIR}/../mcuxsdk/middleware/mbedtls3x/library
        PUBLIC ${NXMW_TOP_DIR}/../mcuxsdk/middleware/mbedtls3x/include
        PUBLIC ${NXMW_TOP_DIR}/../mcuxsdk/middleware/mbedtls3x/include/psa
        PUBLIC ${NXMW_TOP_DIR}/../mcuxsdk/devices/LPC/LPC5500/LPC55S69
        PUBLIC ${NXMW_TOP_DIR}/../mcuxsdk/devices/LPC/LPC5500/LPC55S69/drivers
        PUBLIC inc
    )
ELSE()
    TARGET_INCLUDE_DIRECTORIES(
        ${PROJECT_NAME}
        PUBLIC ${NXMW_TOP_DIR}/lib/sss/ex/inc
        PUBLIC ${NXMW_TOP_DIR}/../mcuxsdk/middleware/mbedtls3x/library
        PUBLIC ${NXMW_TOP_DIR}/../mcuxsdk/middleware/mbedtls3x/include
        PUBLIC ${NXMW_TOP_DIR}/../mcuxsdk/middleware/mbedtls3x/include/psa
        PUBLIC ${NXMW_TOP_DIR}/plugin/psa/psa_alt_lib/inc/
        PUBLIC ${NXMW_TOP_DIR}/plugin/psa/psa_alt_lib/inc/psa/
        PUBLIC inc
    )
ENDIF()

IF(
    "${CMAKE_CXX_COMPILER_ID}"
    STREQUAL
    "GNU"
)
    TARGET_COMPILE_OPTIONS(
        ${PROJECT_NAME}
        PRIVATE -Wno-error=type-limits
    )
ENDIF()


# CREATE_BINARY(${PROJECT_NAME})