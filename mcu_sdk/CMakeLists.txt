# Copyright 2025 NXP
#
# SPDX-License-Identifier: Apache-2.0
#


IF(SSS_HAVE_MBEDTLS_3_X)
    IF(SSS_HAVE_MBEDTLS_ALT_PSA)
        INCLUDE(mbedtls3x_psa.cmake)
    ELSE()
        INCLUDE(mbedtls3x.cmake)
    ENDIF()
ELSE()
    INCLUDE(mbedtls.cmake)
ENDIF()

IF(SSS_HAVE_RTOS_FREERTOS)
    INCLUDE(amazon-freertos.cmake)
ENDIF()