# .. Copyright 2022-2024 NXP
# ..
# .. SPDX-License-Identifier: BSD-3-Clause
# ..

# .. _se-cmake-options:

# ============================================
#  CMake Options
# ============================================

# .. include:: cmake_options_values.rst.txt


#> Create shared libraries.  Applicable for Engine DLL and other use cases.
OPTION(WithSharedLIB "Create and use shared libraries" OFF)

# NXP Internal Options
# ============================================
#
# These options are not supported outside NXP.
#
#> .. note:: For deliveries outside NXP, this option is disabled.
OPTION(NXPInternal "NXP Internal" OFF)

#> .. For internal testing.
OPTION(WithCodeCoverage "Compile with Code Coverage" OFF)


#.. Automatic generated options
INCLUDE(scripts/cmake_options_values.cmake)

# Other Variables
# ============================================

# .. option:: NXMW_INSTALL_INC_DIR
#
#     - Location where library header files are installed for linux based targets. (Used for Linux)
#     - Default location is ``</usr/local/>include/nx``
#
SET(NXMW_INSTALL_INC_DIR "include/nx")

# .. option:: NXMW_INSTALL_SHARE_DIR
#
#     - Location where miscellaneous scripts
#       get copiled for linux based targets. (Used for Linux)
#     - e.g. ``cmake_options.mak`` which has current cmake build settings.
#     - Default location is ``</usr/local/>share/nx``
#
SET(NXMW_INSTALL_SHARE_DIR "share/nx")

# .. # End of documented part .....

IF("${CMAKE_BUILD_TYPE}" STREQUAL "")
    SET(CMAKE_BUILD_TYPE "Debug")
ENDIF()

# .. To build shared libraries
IF(WithSharedLIB)
    SET(BUILD_SHARED_LIBS ON)
ELSE()
    SET(BUILD_SHARED_LIBS OFF)
ENDIF()

MESSAGE(STATUS "BUILD_TYPE: " ${CMAKE_BUILD_TYPE})

IF(SSS_HAVE_HOST_PCLINUX32 OR SSS_HAVE_HOST_PCLINUX64)
    SET(SSS_HAVE_HOST_PCLINUX ON)
ELSE()
    SET(SSS_HAVE_HOST_PCLINUX OFF)
ENDIF()

IF(SSS_HAVE_HOST_PCLINUX
   OR SSS_HAVE_HOST_RASPBIAN
   OR SSS_HAVE_HOST_IMXLINUX
   OR SSS_HAVE_HOST_CYGWIN
)
    SET(SSS_HAVE_HOST_LINUX_LIKE ON)
ELSE()
    SET(SSS_HAVE_HOST_LINUX_LIKE OFF)
ENDIF()

IF(
    SSS_HAVE_HOST_LINUX_LIKE
    OR SSS_HAVE_HOST_PCWINDOWS
    OR SSS_HAVE_HOST_DARWIN
)
    SET(SSS_HAVE_HOST_WITH_FILE_SYSTEM ON)
ELSE()
    SET(SSS_HAVE_HOST_WITH_FILE_SYSTEM OFF)
ENDIF()

IF(SSS_HAVE_HOSTCRYPTO_OPENSSL)
    IF(SSS_HAVE_HOST_PCLINUX32)
        MESSAGE(STATUS "OpenSSL: Enforcing 32bit linux from /usr/lib/i386-linux-gnu")
        LINK_DIRECTORIES("/usr/lib/i386-linux-gnu")
        SET(OPENSSL_LIBRARIES ssl crypto)
    ENDIF()
    IF(SSS_HAVE_HOST_PCLINUX64
       OR SSS_HAVE_HOST_IMXLINUX
       OR SSS_HAVE_HOST_RASPBIAN
       OR SSS_HAVE_HOST_CYGWIN
    )
        IF(OPENSSL_INSTALL_PREFIX)
            MESSAGE(STATUS "OpenSSL: Using: ${OPENSSL_INSTALL_PREFIX}")
            INCLUDE_DIRECTORIES("${OPENSSL_INSTALL_PREFIX}/include")
            SET(OPENSSL_LIBRARIES ${OPENSSL_INSTALL_PREFIX}/lib/libssl.so ${OPENSSL_INSTALL_PREFIX}/lib/libcrypto.so)
        ELSE()
            FIND_PACKAGE(OpenSSL) # Find the OpenSSL Package
            IF(OPENSSL_FOUND)
                MESSAGE(STATUS "Found: " ${OPENSSL_LIBRARIES})
                INCLUDE_DIRECTORIES(${OPENSSL_INCLUDE_DIR})
            ELSE()
                MESSAGE(WARNING "Building with OpenSSL Engine expected to fail")
            ENDIF()
        ENDIF()
    ELSEIF(SSS_HAVE_HOST_PCWINDOWS)
        # Currently SSS_HAVE_HOST_PCWINDOWS implies SSS_HAVE_HOSTCRYPTO_MBEDTLS
        IF(SSS_HAVE_OPENSSL_1_1_1)
            INCLUDE_DIRECTORIES(${NXMW_TOP_DIR}/ext/openssl/include)
            IF(
                "${CMAKE_CXX_COMPILER_ID}"
                MATCHES
                "MSVC"
            )
                SET(OPENSSL_LIBRARIES
                    libssl
                    libcrypto
                    Crypt32
                    Ws2_32
                )
            ELSE()
                # MINGW
                SET(OPENSSL_LIBRARIES
                    ssl
                    crypto
                    Crypt32
                    Ws2_32
                )
            ENDIF()
        ELSE()
            INCLUDE_DIRECTORIES(${NXMW_TOP_DIR}/ext/openssl-30/include)
            IF(
                "${CMAKE_CXX_COMPILER_ID}"
                MATCHES
                "MSVC"
            )
                SET(OPENSSL_LIBRARIES
                    libssl
                    libcrypto
                    Crypt32
                    Ws2_32
                )
            ELSE()
                # MINGW
                MESSAGE(FATAL_ERROR "Openssl 3.0 binaries for mingw not available")
            ENDIF()
        ENDIF()
    ELSEIF(SSS_HAVE_HOST_DARWIN)
        IF(OPENSSL_INSTALL_PREFIX)
            # /usr/local/Cellar/openssl/1.0.2s/
            MESSAGE(STATUS "OpenSSL: Using: ${OPENSSL_INSTALL_PREFIX}")
            INCLUDE_DIRECTORIES("${OPENSSL_INSTALL_PREFIX}/include")
            INCLUDE_DIRECTORIES("${OPENSSL_INSTALL_PREFIX}/lib")
            SET(OPENSSL_LIBRARIES ${OPENSSL_INSTALL_PREFIX}/lib/libssl.a ${OPENSSL_INSTALL_PREFIX}/lib/libcrypto.a)
        ELSE()
            FIND_PACKAGE(OpenSSL) # Find the OpenSSL Package
            IF(OPENSSL_FOUND)
                MESSAGE(STATUS "Found: " ${OPENSSL_LIBRARIES})
                INCLUDE_DIRECTORIES(${OPENSSL_INCLUDE_DIR})
            ELSE()
                MESSAGE(WARNING "Building with OpenSSL Engine expected to fail")
                MESSAGE(WARNING "You can set OPENSSL_INSTALL_PREFIX")
            ENDIF()
        ENDIF()
    ELSEIF(SSS_HAVE_HOST_WIN10IOT)
        IF(SSS_HAVE_OpenSSL_1_0_2)
            INCLUDE_DIRECTORIES(${NXMW_TOP_DIR}/ext/openssl-102/Win10IoT/include)
            SET(OPENSSL_LIBRARIES libeay32 ssleay32)
        ELSE()
            MESSAGE(FATAL "SSS_HAVE_HOST_WIN10IOT needs SSS_HAVE_OpenSSL_1_0_2")
        ENDIF()
    ENDIF()
ENDIF(SSS_HAVE_HOSTCRYPTO_OPENSSL)

IF(SSS_HAVE_NX_TYPE_NX_R_DA OR SSS_HAVE_NX_TYPE_NX_PICC)
    SET(SSS_HAVE_NX_TYPE ON)
ELSE()
    SET(SSS_HAVE_NX_TYPE OFF)
ENDIF()

IF(SSS_HAVE_SMCOM_T1OI2C_GP1_0)
    ADD_DEFINITIONS(-DT1oI2C )
ENDIF()

IF(SSS_HAVE_SMCOM_JRCP_V1_AM)
    ADD_DEFINITIONS(-DJRCP_V1_AM )
ENDIF()

IF(SSS_HAVE_LOG_SEGGERRTT)
    ADD_DEFINITIONS(-DUSE_SERGER_RTT)
ENDIF()

IF(SSS_HAVE_HOST_LPCXPRESSO55S)
    SET(SSS_HAVE_KSDK ON)
    SET(KSDK_BoardName "lpcxpresso55s69")
    SET(KSDK_CPUName "LPC55S69")
ELSEIF(SSS_HAVE_HOST_FRDMMCXA153)
    SET(SSS_HAVE_KSDK ON)
    SET(KSDK_BoardName "frdmmcxa153")
    SET(KSDK_CPUName "CPU_MCXA153VLH")
ELSEIF(SSS_HAVE_HOST_FRDMMCXN947)
    SET(SSS_HAVE_KSDK ON)
    SET(KSDK_BoardName "frdmmcxn947")
    SET(KSDK_CPUName "CPU_MCXN947VDF")
ELSE()
    SET(SSS_HAVE_KSDK OFF)
ENDIF()

IF(SSS_HAVE_RTOS_FREERTOS)
    ADD_DEFINITIONS(-DUSE_RTOS -DSDK_OS_FREE_RTOS -DFSL_RTOS_FREE_RTOS)
ENDIF()

IF(SSS_HAVE_KSDK)
    INCLUDE(scripts/ksdk.cmake)
ELSEIF(
    SSS_HAVE_HOST_LINUX_LIKE
    OR SSS_HAVE_HOST_PCWINDOWS
    OR SSS_HAVE_HOST_WIN10IOT
)
    INCLUDE(scripts/native.cmake)
ELSEIF(SSS_HAVE_HOST_DARWIN)
    INCLUDE(scripts/native.cmake)
ELSEIF(SSS_HAVE_HOST_ANDROID)
    INCLUDE(scripts/android.cmake)
ELSEIF("${CMAKE_SYSTEM_NAME}" STREQUAL "CYGWIN")
    INCLUDE(scripts/native.cmake)
ELSE()
    # .. Falling back on Native
    INCLUDE(scripts/native.cmake)
ENDIF()

MESSAGE(STATUS "CMAKE_CXX_COMPILER_ID = ${CMAKE_CXX_COMPILER_ID}")
MESSAGE(STATUS "CMAKE_SYSTEM_NAME = ${CMAKE_SYSTEM_NAME}")

IF(SSS_HAVE_KSDK)
    INCLUDE_DIRECTORIES(${NXMW_TOP_DIR}/sss/port/ksdk)
ELSE()
    INCLUDE_DIRECTORIES(${NXMW_TOP_DIR}/sss/port/default)
ENDIF()






# .. Checks and balances ########

IF(NOT
   CMAKE_C_COMPILER_ID
   STREQUAL
   "GNU"
)
    IF(WithCodeCoverage)
        MESSAGE(FATAL_ERROR "Code coverage only with GCC")
    ENDIF()
ENDIF()

IF(SSS_HAVE_RTOS_FREERTOS AND SSS_HAVE_RTOS_DEFAULT)
    MESSAGE(FATAL_ERROR "Can not set SSS_HAVE_RTOS_FREERTOS AND SSS_HAVE_RTOS_DEFAULT")
ENDIF()

IF(SSS_HAVE_SMCOM_RC663_VCOM)
    IF(NOT WithNXPNFCRdLib)
        MESSAGE(FATAL_ERROR "'SSS_HAVE_SMCOM_RC663_VCOM' Needs 'WithNXPNFCRdLib'")
    ENDIF()
ENDIF()

IF(WithNXPNFCRdLib)
    IF(SSS_HAVE_HOST_PCLINUX)
        MESSAGE(FATAL_ERROR "Can not set both 'WithNXPNFCRdLib' AND 'SSS_HAVE_HOST_PCLINUX'")
    ENDIF()

    IF(NOT SSS_HAVE_HOST_LPCXPRESSO55S)
        MESSAGE(FATAL_ERROR " 'WithNXPNFCRdLib' Can only work with 'lpcxpresso55s'")
    ENDIF()

ENDIF()

IF(SSS_HAVE_KSDK)
    IF(SSS_HAVE_HOSTCRYPTO_OPENSSL)
        MESSAGE(FATAL_ERROR "Can not set both 'KSDK ' AND 'OPENSSL'")
    ENDIF()
ENDIF()

IF(SSS_HAVE_NX_TYPE)
    MESSAGE(STATUS "NXMW_Auth - ${NXMW_Auth}")
ENDIF(SSS_HAVE_NX_TYPE)

IF(SSS_HAVE_NX_TYPE_NX_PICC)
    IF(NOT SSS_HAVE_SECURE_TUNNELING_NONE)
        MESSAGE(FATAL_ERROR "Can only use SSS_HAVE_SECURE_TUNNELING_NONE at PICC Level")
    ENDIF()

    IF(NOT SSS_HAVE_AUTH_NONE)
        MESSAGE(FATAL_ERROR "Can only use SSS_HAVE_AUTH_NONE at PICC Level")
    ENDIF()
ENDIF()


IF(SSS_HAVE_NX_TYPE_NX_R_DA)
    IF(SSS_HAVE_AUTH_SIGMA_I_VERIFIER OR SSS_HAVE_AUTH_SIGMA_I_PROVER OR SSS_HAVE_AUTH_SYMM_AUTH)
        IF(SSS_HAVE_SECURE_TUNNELING_NONE)
                MESSAGE(FATAL_ERROR "Cannot use SSS_HAVE_SECURE_TUNNELING_NONE for SIGMA / SYMM Authentication. Select NTAG_AES128_AES256_EV2 OR NTAG_AES128_EV2 OR NTAG_AES256_EV2")
        ENDIF()
    ENDIF()

    IF(SSS_HAVE_AUTH_SYMM_AUTH)
        IF(SSS_HAVE_SECURE_TUNNELING_NTAG_AES128_AES256_EV2)
            MESSAGE(FATAL_ERROR "Cannot use SSS_HAVE_SECURE_TUNNELING_NTAG_AES128_AES256_EV2 with SYMM Auth")
        ENDIF()
    ENDIF()

    IF(SSS_HAVE_AUTH_NONE)
        IF(NOT SSS_HAVE_SECURE_TUNNELING_NONE)
            MESSAGE(FATAL_ERROR "With Auth as None, Secure-tunneling has to be None")
        ENDIF()
    ENDIF()
ENDIF()

IF(SSS_HAVE_HOSTCRYPTO_MBEDTLS)
    IF(SSS_HAVE_MBEDTLS_2_X)
        IF(SSS_HAVE_MBEDTLS_ALT_SSS OR  SSS_HAVE_MBEDTLS_ALT_PSA)
            MESSAGE(FATAL_ERROR "Mbedtls2x with SSS or PSA,/
            not supported")
        ENDIF()
    ENDIF()
ENDIF()

IF (SSS_HAVE_RTOS_FREERTOS AND SSS_HAVE_HOST_FRDMMCXA153)
    MESSAGE(FATAL_ERROR "FreeRTOS not supported on MCXA platform")
ENDIF()

IF(SSS_HAVE_CMSIS_DRIVER_ENABLED)
    IF(NOT(SSS_HAVE_HOST_FRDMMCXN947 OR SSS_HAVE_HOST_FRDMMCXA153))
        MESSAGE(FATAL_ERROR "CMSIS Driver is supported only on MCXA and MCXN platform")
    ENDIF()
ENDIF()


INCLUDE(scripts/cmake_options_check.cmake)

# .. By default, we don't have it
SET(SSS_HAVE_ECC 0)

IF(SSS_HAVE_NX_TYPE_NX_R_DA)
    SET(SSS_HAVE_ECC 1)
ENDIF()

IF(WithNXPNFCRdLib)
    SET(SSS_HAVE_NXPNFCRDLIB 1)
ELSE()
    SET(SSS_HAVE_NXPNFCRDLIB 0)
ENDIF()

IF(SSS_HAVE_KSDK)
    SET(NFC_663_SPI ON)
    SET(NFC_663_VCOM OFF)
ELSE()
    SET(NFC_663_SPI OFF)
    SET(NFC_663_VCOM ON)
ENDIF()

IF(SSS_HAVE_SBL_SBL_LPC55S)
    IF(NOT SSS_HAVE_HOST_LPCXPRESSO55S_S)
        MESSAGE(FATAL_ERROR "Use secure host for SBL bootable applications.")
    ENDIF()
ENDIF()
SET(eSEName "eSEName-NA")

IF(SSS_HAVE_NX_TYPE)
    SET(eSEName "nx")
ENDIF()
IF(SSS_HAVE_NX_TYPE_NX_R_DA OR SSS_HAVE_NX_TYPE_NX_PICC)
    SET(eSEName "nx")
ENDIF()
SET(NXPProprietary ON)
