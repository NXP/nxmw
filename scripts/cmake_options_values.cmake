# Copyright 2023-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
#
# #############################################################
# This file is generated using a script
# #############################################################
#

SET(
    NXMW_NX_Type
    "NX_R_DA"
    CACHE
        STRING
        "The NX Secure Authenticator Type"
)

IF(NXPInternal)
    SET_PROPERTY(
        CACHE NXMW_NX_Type
        PROPERTY
            STRINGS
            "None;NX_R_DA;NX_PICC;"
    )
ELSE()
    SET_PROPERTY(
        CACHE NXMW_NX_Type
        PROPERTY
            STRINGS
            "None;NX_R_DA;NX_PICC;"
    )
ENDIF()

SET(
    NXMW_Host
    "PCWindows"
    CACHE
        STRING
        "Host where the software stack is running"
)

IF(NXPInternal)
    SET_PROPERTY(
        CACHE NXMW_Host
        PROPERTY
            STRINGS
            "PCWindows;PCLinux64;lpcxpresso55s;Raspbian;frdmmcxa153;frdmmcxa156;frdmmcxn947;"
    )
ELSE()
    SET_PROPERTY(
        CACHE NXMW_Host
        PROPERTY
            STRINGS
            "PCWindows;PCLinux64;lpcxpresso55s;Raspbian;frdmmcxa153;frdmmcxa156;frdmmcxn947;"
    )
ENDIF()

SET(
    NXMW_SMCOM
    "VCOM"
    CACHE
        STRING
        "Communication Interface"
)

IF(NXPInternal)
    SET_PROPERTY(
        CACHE NXMW_SMCOM
        PROPERTY
            STRINGS
            "None;VCOM;T1oI2C_GP1_0;PCSC;JRCP_V1_AM;"
    )
ELSE()
    SET_PROPERTY(
        CACHE NXMW_SMCOM
        PROPERTY
            STRINGS
            "None;VCOM;T1oI2C_GP1_0;PCSC;JRCP_V1_AM;"
    )
ENDIF()

SET(
    NXMW_HostCrypto
    "MBEDTLS"
    CACHE
        STRING
        "Counterpart Crypto on Host"
)

IF(NXPInternal)
    SET_PROPERTY(
        CACHE NXMW_HostCrypto
        PROPERTY
            STRINGS
            "MBEDTLS;OPENSSL;None;"
    )
ELSE()
    SET_PROPERTY(
        CACHE NXMW_HostCrypto
        PROPERTY
            STRINGS
            "MBEDTLS;OPENSSL;None;"
    )
ENDIF()

SET(
    NXMW_RTOS
    "Default"
    CACHE
        STRING
        "Choice of Operating system"
)

IF(NXPInternal)
    SET_PROPERTY(
        CACHE NXMW_RTOS
        PROPERTY
            STRINGS
            "Default;FreeRTOS;"
    )
ELSE()
    SET_PROPERTY(
        CACHE NXMW_RTOS
        PROPERTY
            STRINGS
            "Default;FreeRTOS;"
    )
ENDIF()

SET(
    NXMW_Auth
    "SYMM_Auth"
    CACHE
        STRING
        "NX Authentication"
)

IF(NXPInternal)
    SET_PROPERTY(
        CACHE NXMW_Auth
        PROPERTY
            STRINGS
            "None;SIGMA_I_Verifier;SIGMA_I_Prover;SYMM_Auth;"
    )
ELSE()
    SET_PROPERTY(
        CACHE NXMW_Auth
        PROPERTY
            STRINGS
            "None;SIGMA_I_Verifier;SIGMA_I_Prover;SYMM_Auth;"
    )
ENDIF()

SET(
    NXMW_Log
    "Default"
    CACHE
        STRING
        "Logging"
)

IF(NXPInternal)
    SET_PROPERTY(
        CACHE NXMW_Log
        PROPERTY
            STRINGS
            "Default;Verbose;Silent;SeggerRTT;"
    )
ELSE()
    SET_PROPERTY(
        CACHE NXMW_Log
        PROPERTY
            STRINGS
            "Default;Verbose;Silent;"
    )
ENDIF()

SET(
    CMAKE_BUILD_TYPE
    "Debug"
    CACHE
        STRING
        "See https://cmake.org/cmake/help/latest/variable/CMAKE_BUILD_TYPE.html"
)

IF(NXPInternal)
    SET_PROPERTY(
        CACHE CMAKE_BUILD_TYPE
        PROPERTY
            STRINGS
            "Debug;Release;RelWithDebInfo;;"
    )
ELSE()
    SET_PROPERTY(
        CACHE CMAKE_BUILD_TYPE
        PROPERTY
            STRINGS
            "Debug;Release;RelWithDebInfo;;"
    )
ENDIF()

SET(
    NXMW_Secure_Tunneling
    "NTAG_AES128_EV2"
    CACHE
        STRING
        "Secure Tunneling(Secure Messaging)"
)

IF(NXPInternal)
    SET_PROPERTY(
        CACHE NXMW_Secure_Tunneling
        PROPERTY
            STRINGS
            "None;NTAG_AES128_AES256_EV2;NTAG_AES128_EV2;NTAG_AES256_EV2;"
    )
ELSE()
    SET_PROPERTY(
        CACHE NXMW_Secure_Tunneling
        PROPERTY
            STRINGS
            "None;NTAG_AES128_AES256_EV2;NTAG_AES128_EV2;NTAG_AES256_EV2;"
    )
ENDIF()

SET(
    NXMW_Auth_Asymm_Host_PK_Cache
    "Enabled"
    CACHE
        STRING
        "Host public key cache"
)

IF(NXPInternal)
    SET_PROPERTY(
        CACHE NXMW_Auth_Asymm_Host_PK_Cache
        PROPERTY
            STRINGS
            "Disabled;Enabled;"
    )
ELSE()
    SET_PROPERTY(
        CACHE NXMW_Auth_Asymm_Host_PK_Cache
        PROPERTY
            STRINGS
            "Disabled;Enabled;"
    )
ENDIF()

SET(
    NXMW_Auth_Asymm_Cert_Repo_Id
    "0"
    CACHE
        STRING
        "Certificate Repository Id"
)

IF(NXPInternal)
    SET_PROPERTY(
        CACHE NXMW_Auth_Asymm_Cert_Repo_Id
        PROPERTY
            STRINGS
            "0;1;2;3;4;5;6;7;"
    )
ELSE()
    SET_PROPERTY(
        CACHE NXMW_Auth_Asymm_Cert_Repo_Id
        PROPERTY
            STRINGS
            "0;1;2;3;4;5;6;7;"
    )
ENDIF()

SET(
    NXMW_Auth_Asymm_Cert_SK_Id
    "0"
    CACHE
        STRING
        "Certificate Private Key Id"
)

IF(NXPInternal)
    SET_PROPERTY(
        CACHE NXMW_Auth_Asymm_Cert_SK_Id
        PROPERTY
            STRINGS
            "0;1;2;3;4;"
    )
ELSE()
    SET_PROPERTY(
        CACHE NXMW_Auth_Asymm_Cert_SK_Id
        PROPERTY
            STRINGS
            "0;1;2;3;4;"
    )
ENDIF()

SET(
    NXMW_Auth_Asymm_CA_Root_Key_Id
    "0"
    CACHE
        STRING
        "Key ID of CA Root Public Key"
)

IF(NXPInternal)
    SET_PROPERTY(
        CACHE NXMW_Auth_Asymm_CA_Root_Key_Id
        PROPERTY
            STRINGS
            "0;1;2;3;4;"
    )
ELSE()
    SET_PROPERTY(
        CACHE NXMW_Auth_Asymm_CA_Root_Key_Id
        PROPERTY
            STRINGS
            "0;1;2;3;4;"
    )
ENDIF()

SET(
    NXMW_Auth_Symm_App_Key_Id
    "0"
    CACHE
        STRING
        "application Key ID"
)

IF(NXPInternal)
    SET_PROPERTY(
        CACHE NXMW_Auth_Symm_App_Key_Id
        PROPERTY
            STRINGS
            "0;1;2;3;4;"
    )
ELSE()
    SET_PROPERTY(
        CACHE NXMW_Auth_Symm_App_Key_Id
        PROPERTY
            STRINGS
            "0;1;2;3;4;"
    )
ENDIF()

SET(
    NXMW_Auth_Asymm_Host_Curve
    "NIST_P"
    CACHE
        STRING
        "Host EC domain curve type"
)

IF(NXPInternal)
    SET_PROPERTY(
        CACHE NXMW_Auth_Asymm_Host_Curve
        PROPERTY
            STRINGS
            "NIST_P;BRAINPOOL;"
    )
ELSE()
    SET_PROPERTY(
        CACHE NXMW_Auth_Asymm_Host_Curve
        PROPERTY
            STRINGS
            "NIST_P;BRAINPOOL;"
    )
ENDIF()

SET(
    NXMW_OpenSSL
    "1_1_1"
    CACHE
        STRING
        "For PC, which OpenSSL to pick up"
)

IF(NXPInternal)
    SET_PROPERTY(
        CACHE NXMW_OpenSSL
        PROPERTY
            STRINGS
            "1_1_1;3_0;"
    )
ELSE()
    SET_PROPERTY(
        CACHE NXMW_OpenSSL
        PROPERTY
            STRINGS
            "1_1_1;3_0;"
    )
ENDIF()

SET(
    NXMW_MBedTLS
    "2_X"
    CACHE
        STRING
        "Which MBedTLS version to choose"
)

IF(NXPInternal)
    SET_PROPERTY(
        CACHE NXMW_MBedTLS
        PROPERTY
            STRINGS
            "2_X;3_X;"
    )
ELSE()
    SET_PROPERTY(
        CACHE NXMW_MBedTLS
        PROPERTY
            STRINGS
            "2_X;3_X;"
    )
ENDIF()

SET(
    NXMW_Auth_Symm_Diversify
    "Disabled"
    CACHE
        STRING
        "Diversification of symmetric authentication key"
)

IF(NXPInternal)
    SET_PROPERTY(
        CACHE NXMW_Auth_Symm_Diversify
        PROPERTY
            STRINGS
            "Disabled;Enabled;"
    )
ELSE()
    SET_PROPERTY(
        CACHE NXMW_Auth_Symm_Diversify
        PROPERTY
            STRINGS
            "Disabled;Enabled;"
    )
ENDIF()

SET(
    NXMW_All_Auth_Code
    "Disabled"
    CACHE
        STRING
        "Enable all authentication code"
)

IF(NXPInternal)
    SET_PROPERTY(
        CACHE NXMW_All_Auth_Code
        PROPERTY
            STRINGS
            "Disabled;Enabled;"
    )
ELSE()
    SET_PROPERTY(
        CACHE NXMW_All_Auth_Code
        PROPERTY
            STRINGS
            "Disabled;Enabled;"
    )
ENDIF()

SET(
    NXMW_mbedTLS_ALT
    "None"
    CACHE
        STRING
        "ALT Engine implementation for mbedTLS"
)

IF(NXPInternal)
    SET_PROPERTY(
        CACHE NXMW_mbedTLS_ALT
        PROPERTY
            STRINGS
            "SSS;PSA;None;"
    )
ELSE()
    SET_PROPERTY(
        CACHE NXMW_mbedTLS_ALT
        PROPERTY
            STRINGS
            "SSS;PSA;None;"
    )
ENDIF()

SET(
    NXMW_SA_Type
    "A30"
    CACHE
        STRING
        "Enable host certificates of A30 for sigma-I Authentication"
)

IF(NXPInternal)
    SET_PROPERTY(
        CACHE NXMW_SA_Type
        PROPERTY
            STRINGS
            "A30;NTAG_X_DNA;NXP_INT_CONFIG;Other;"
    )
ELSE()
    SET_PROPERTY(
        CACHE NXMW_SA_Type
        PROPERTY
            STRINGS
            "A30;NTAG_X_DNA;NXP_INT_CONFIG;Other;"
    )
ENDIF()

SET(
    NXMW_CMSIS_Driver
    "Disabled"
    CACHE
        STRING
        "CMSIS Driver diabled"
)

IF(NXPInternal)
    SET_PROPERTY(
        CACHE NXMW_CMSIS_Driver
        PROPERTY
            STRINGS
            "Disabled;Enabled;"
    )
ELSE()
    SET_PROPERTY(
        CACHE NXMW_CMSIS_Driver
        PROPERTY
            STRINGS
            "Disabled;Enabled;"
    )
ENDIF()
IF("${NXMW_NX_Type}" STREQUAL "None")
    # SET(WithNXMW_NX_Type_None ON)
    SET(SSS_HAVE_NX_TYPE_NONE "1")
ELSE()
    # SET(WithNXMW_NX_Type_None OFF)
    SET(SSS_HAVE_NX_TYPE_NONE "0")
ENDIF()

IF("${NXMW_NX_Type}" STREQUAL "NX_R_DA")
    # SET(WithNXMW_NX_Type_NX_R_DA ON)
    SET(SSS_HAVE_NX_TYPE_NX_R_DA "1")
ELSE()
    # SET(WithNXMW_NX_Type_NX_R_DA OFF)
    SET(SSS_HAVE_NX_TYPE_NX_R_DA "0")
ENDIF()

IF("${NXMW_NX_Type}" STREQUAL "NX_PICC")
    # SET(WithNXMW_NX_Type_NX_PICC ON)
    SET(SSS_HAVE_NX_TYPE_NX_PICC "1")
ELSE()
    # SET(WithNXMW_NX_Type_NX_PICC OFF)
    SET(SSS_HAVE_NX_TYPE_NX_PICC "0")
ENDIF()

IF("${NXMW_NX_Type}" STREQUAL "None")
    # OK
ELSEIF("${NXMW_NX_Type}" STREQUAL "NX_R_DA")
    # OK
ELSEIF("${NXMW_NX_Type}" STREQUAL "NX_PICC")
    # OK
ELSE()
    MESSAGE(SEND_ERROR "For 'NXMW_NX_Type' '${NXMW_NX_Type}' is invalid.")
    MESSAGE(STATUS "Only supported values are 'None, NX_R_DA, NX_PICC'")
ENDIF()

IF("${NXMW_Host}" STREQUAL "PCWindows")
    # SET(WithNXMW_Host_PCWindows ON)
    SET(SSS_HAVE_HOST_PCWINDOWS "1")
ELSE()
    # SET(WithNXMW_Host_PCWindows OFF)
    SET(SSS_HAVE_HOST_PCWINDOWS "0")
ENDIF()

IF("${NXMW_Host}" STREQUAL "PCLinux64")
    # SET(WithNXMW_Host_PCLinux64 ON)
    SET(SSS_HAVE_HOST_PCLINUX64 "1")
ELSE()
    # SET(WithNXMW_Host_PCLinux64 OFF)
    SET(SSS_HAVE_HOST_PCLINUX64 "0")
ENDIF()

IF("${NXMW_Host}" STREQUAL "lpcxpresso55s")
    # SET(WithNXMW_Host_lpcxpresso55s ON)
    SET(SSS_HAVE_HOST_LPCXPRESSO55S "1")
ELSE()
    # SET(WithNXMW_Host_lpcxpresso55s OFF)
    SET(SSS_HAVE_HOST_LPCXPRESSO55S "0")
ENDIF()

IF("${NXMW_Host}" STREQUAL "Raspbian")
    # SET(WithNXMW_Host_Raspbian ON)
    SET(SSS_HAVE_HOST_RASPBIAN "1")
ELSE()
    # SET(WithNXMW_Host_Raspbian OFF)
    SET(SSS_HAVE_HOST_RASPBIAN "0")
ENDIF()

IF("${NXMW_Host}" STREQUAL "frdmmcxa153")
    # SET(WithNXMW_Host_frdmmcxa153 ON)
    SET(SSS_HAVE_HOST_FRDMMCXA153 "1")
ELSE()
    # SET(WithNXMW_Host_frdmmcxa153 OFF)
    SET(SSS_HAVE_HOST_FRDMMCXA153 "0")
ENDIF()

IF("${NXMW_Host}" STREQUAL "frdmmcxa156")
    # SET(WithNXMW_Host_frdmmcxa156 ON)
    SET(SSS_HAVE_HOST_FRDMMCXA156 "1")
ELSE()
    # SET(WithNXMW_Host_frdmmcxa156 OFF)
    SET(SSS_HAVE_HOST_FRDMMCXA156 "0")
ENDIF()

IF("${NXMW_Host}" STREQUAL "frdmmcxn947")
    # SET(WithNXMW_Host_frdmmcxn947 ON)
    SET(SSS_HAVE_HOST_FRDMMCXN947 "1")
ELSE()
    # SET(WithNXMW_Host_frdmmcxn947 OFF)
    SET(SSS_HAVE_HOST_FRDMMCXN947 "0")
ENDIF()

IF("${NXMW_Host}" STREQUAL "PCWindows")
    # OK
ELSEIF("${NXMW_Host}" STREQUAL "PCLinux64")
    # OK
ELSEIF("${NXMW_Host}" STREQUAL "lpcxpresso55s")
    # OK
ELSEIF("${NXMW_Host}" STREQUAL "Raspbian")
    # OK
ELSEIF("${NXMW_Host}" STREQUAL "frdmmcxa153")
    # OK
ELSEIF("${NXMW_Host}" STREQUAL "frdmmcxa156")
    # OK
ELSEIF("${NXMW_Host}" STREQUAL "frdmmcxn947")
    # OK
ELSE()
    MESSAGE(SEND_ERROR "For 'NXMW_Host' '${NXMW_Host}' is invalid.")
    MESSAGE(STATUS "Only supported values are 'PCWindows, PCLinux64, lpcxpresso55s, Raspbian, frdmmcxa153, frdmmcxa156, frdmmcxn947'")
ENDIF()

IF("${NXMW_SMCOM}" STREQUAL "None")
    # SET(WithNXMW_SMCOM_None ON)
    SET(SSS_HAVE_SMCOM_NONE "1")
ELSE()
    # SET(WithNXMW_SMCOM_None OFF)
    SET(SSS_HAVE_SMCOM_NONE "0")
ENDIF()

IF("${NXMW_SMCOM}" STREQUAL "VCOM")
    # SET(WithNXMW_SMCOM_VCOM ON)
    SET(SSS_HAVE_SMCOM_VCOM "1")
ELSE()
    # SET(WithNXMW_SMCOM_VCOM OFF)
    SET(SSS_HAVE_SMCOM_VCOM "0")
ENDIF()

IF("${NXMW_SMCOM}" STREQUAL "T1oI2C_GP1_0")
    # SET(WithNXMW_SMCOM_T1oI2C_GP1_0 ON)
    SET(SSS_HAVE_SMCOM_T1OI2C_GP1_0 "1")
ELSE()
    # SET(WithNXMW_SMCOM_T1oI2C_GP1_0 OFF)
    SET(SSS_HAVE_SMCOM_T1OI2C_GP1_0 "0")
ENDIF()

IF("${NXMW_SMCOM}" STREQUAL "PCSC")
    # SET(WithNXMW_SMCOM_PCSC ON)
    SET(SSS_HAVE_SMCOM_PCSC "1")
ELSE()
    # SET(WithNXMW_SMCOM_PCSC OFF)
    SET(SSS_HAVE_SMCOM_PCSC "0")
ENDIF()

IF("${NXMW_SMCOM}" STREQUAL "JRCP_V1_AM")
    # SET(WithNXMW_SMCOM_JRCP_V1_AM ON)
    SET(SSS_HAVE_SMCOM_JRCP_V1_AM "1")
ELSE()
    # SET(WithNXMW_SMCOM_JRCP_V1_AM OFF)
    SET(SSS_HAVE_SMCOM_JRCP_V1_AM "0")
ENDIF()

IF("${NXMW_SMCOM}" STREQUAL "None")
    # OK
ELSEIF("${NXMW_SMCOM}" STREQUAL "VCOM")
    # OK
ELSEIF("${NXMW_SMCOM}" STREQUAL "T1oI2C_GP1_0")
    # OK
ELSEIF("${NXMW_SMCOM}" STREQUAL "PCSC")
    # OK
ELSEIF("${NXMW_SMCOM}" STREQUAL "JRCP_V1_AM")
    # OK
ELSE()
    MESSAGE(SEND_ERROR "For 'NXMW_SMCOM' '${NXMW_SMCOM}' is invalid.")
    MESSAGE(STATUS "Only supported values are 'None, VCOM, T1oI2C_GP1_0, PCSC, JRCP_V1_AM'")
ENDIF()

IF("${NXMW_HostCrypto}" STREQUAL "MBEDTLS")
    # SET(WithNXMW_HostCrypto_MBEDTLS ON)
    SET(SSS_HAVE_HOSTCRYPTO_MBEDTLS "1")
ELSE()
    # SET(WithNXMW_HostCrypto_MBEDTLS OFF)
    SET(SSS_HAVE_HOSTCRYPTO_MBEDTLS "0")
ENDIF()

IF("${NXMW_HostCrypto}" STREQUAL "OPENSSL")
    # SET(WithNXMW_HostCrypto_OPENSSL ON)
    SET(SSS_HAVE_HOSTCRYPTO_OPENSSL "1")
ELSE()
    # SET(WithNXMW_HostCrypto_OPENSSL OFF)
    SET(SSS_HAVE_HOSTCRYPTO_OPENSSL "0")
ENDIF()

IF("${NXMW_HostCrypto}" STREQUAL "None")
    # SET(WithNXMW_HostCrypto_None ON)
    SET(SSS_HAVE_HOSTCRYPTO_NONE "1")
ELSE()
    # SET(WithNXMW_HostCrypto_None OFF)
    SET(SSS_HAVE_HOSTCRYPTO_NONE "0")
ENDIF()

IF("${NXMW_HostCrypto}" STREQUAL "MBEDTLS")
    # OK
ELSEIF("${NXMW_HostCrypto}" STREQUAL "OPENSSL")
    # OK
ELSEIF("${NXMW_HostCrypto}" STREQUAL "None")
    # OK
ELSE()
    MESSAGE(SEND_ERROR "For 'NXMW_HostCrypto' '${NXMW_HostCrypto}' is invalid.")
    MESSAGE(STATUS "Only supported values are 'MBEDTLS, OPENSSL, None'")
ENDIF()

IF("${NXMW_RTOS}" STREQUAL "Default")
    # SET(WithNXMW_RTOS_Default ON)
    SET(SSS_HAVE_RTOS_DEFAULT "1")
ELSE()
    # SET(WithNXMW_RTOS_Default OFF)
    SET(SSS_HAVE_RTOS_DEFAULT "0")
ENDIF()

IF("${NXMW_RTOS}" STREQUAL "FreeRTOS")
    # SET(WithNXMW_RTOS_FreeRTOS ON)
    SET(SSS_HAVE_RTOS_FREERTOS "1")
ELSE()
    # SET(WithNXMW_RTOS_FreeRTOS OFF)
    SET(SSS_HAVE_RTOS_FREERTOS "0")
ENDIF()

IF("${NXMW_RTOS}" STREQUAL "Default")
    # OK
ELSEIF("${NXMW_RTOS}" STREQUAL "FreeRTOS")
    # OK
ELSE()
    MESSAGE(SEND_ERROR "For 'NXMW_RTOS' '${NXMW_RTOS}' is invalid.")
    MESSAGE(STATUS "Only supported values are 'Default, FreeRTOS'")
ENDIF()

IF("${NXMW_Auth}" STREQUAL "None")
    # SET(WithNXMW_Auth_None ON)
    SET(SSS_HAVE_AUTH_NONE "1")
ELSE()
    # SET(WithNXMW_Auth_None OFF)
    SET(SSS_HAVE_AUTH_NONE "0")
ENDIF()

IF("${NXMW_Auth}" STREQUAL "SIGMA_I_Verifier")
    # SET(WithNXMW_Auth_SIGMA_I_Verifier ON)
    SET(SSS_HAVE_AUTH_SIGMA_I_VERIFIER "1")
ELSE()
    # SET(WithNXMW_Auth_SIGMA_I_Verifier OFF)
    SET(SSS_HAVE_AUTH_SIGMA_I_VERIFIER "0")
ENDIF()

IF("${NXMW_Auth}" STREQUAL "SIGMA_I_Prover")
    # SET(WithNXMW_Auth_SIGMA_I_Prover ON)
    SET(SSS_HAVE_AUTH_SIGMA_I_PROVER "1")
ELSE()
    # SET(WithNXMW_Auth_SIGMA_I_Prover OFF)
    SET(SSS_HAVE_AUTH_SIGMA_I_PROVER "0")
ENDIF()

IF("${NXMW_Auth}" STREQUAL "SYMM_Auth")
    # SET(WithNXMW_Auth_SYMM_Auth ON)
    SET(SSS_HAVE_AUTH_SYMM_AUTH "1")
ELSE()
    # SET(WithNXMW_Auth_SYMM_Auth OFF)
    SET(SSS_HAVE_AUTH_SYMM_AUTH "0")
ENDIF()

IF("${NXMW_Auth}" STREQUAL "None")
    # OK
ELSEIF("${NXMW_Auth}" STREQUAL "SIGMA_I_Verifier")
    # OK
ELSEIF("${NXMW_Auth}" STREQUAL "SIGMA_I_Prover")
    # OK
ELSEIF("${NXMW_Auth}" STREQUAL "SYMM_Auth")
    # OK
ELSE()
    MESSAGE(SEND_ERROR "For 'NXMW_Auth' '${NXMW_Auth}' is invalid.")
    MESSAGE(STATUS "Only supported values are 'None, SIGMA_I_Verifier, SIGMA_I_Prover, SYMM_Auth'")
ENDIF()

IF("${NXMW_Log}" STREQUAL "Default")
    # SET(WithNXMW_Log_Default ON)
    SET(SSS_HAVE_LOG_DEFAULT "1")
ELSE()
    # SET(WithNXMW_Log_Default OFF)
    SET(SSS_HAVE_LOG_DEFAULT "0")
ENDIF()

IF("${NXMW_Log}" STREQUAL "Verbose")
    # SET(WithNXMW_Log_Verbose ON)
    SET(SSS_HAVE_LOG_VERBOSE "1")
ELSE()
    # SET(WithNXMW_Log_Verbose OFF)
    SET(SSS_HAVE_LOG_VERBOSE "0")
ENDIF()

IF("${NXMW_Log}" STREQUAL "Silent")
    # SET(WithNXMW_Log_Silent ON)
    SET(SSS_HAVE_LOG_SILENT "1")
ELSE()
    # SET(WithNXMW_Log_Silent OFF)
    SET(SSS_HAVE_LOG_SILENT "0")
ENDIF()

IF("${NXMW_Log}" STREQUAL "SeggerRTT")
    # SET(WithNXMW_Log_SeggerRTT ON)
    SET(SSS_HAVE_LOG_SEGGERRTT "1")
ELSE()
    # SET(WithNXMW_Log_SeggerRTT OFF)
    SET(SSS_HAVE_LOG_SEGGERRTT "0")
ENDIF()

IF("${NXMW_Log}" STREQUAL "Default")
    # OK
ELSEIF("${NXMW_Log}" STREQUAL "Verbose")
    # OK
ELSEIF("${NXMW_Log}" STREQUAL "Silent")
    # OK
ELSEIF("${NXMW_Log}" STREQUAL "SeggerRTT")
    # OK
ELSE()
    MESSAGE(SEND_ERROR "For 'NXMW_Log' '${NXMW_Log}' is invalid.")
    MESSAGE(STATUS "Only supported values are 'Default, Verbose, Silent, SeggerRTT'")
ENDIF()

IF("${CMAKE_BUILD_TYPE}" STREQUAL "Debug")
    # SET(WithCMAKE_BUILD_TYPE_Debug ON)
    SET(SSS_HAVE_CMAKE_BUILD_TYPE_DEBUG "1")
ELSE()
    # SET(WithCMAKE_BUILD_TYPE_Debug OFF)
    SET(SSS_HAVE_CMAKE_BUILD_TYPE_DEBUG "0")
ENDIF()

IF("${CMAKE_BUILD_TYPE}" STREQUAL "Release")
    # SET(WithCMAKE_BUILD_TYPE_Release ON)
    SET(SSS_HAVE_CMAKE_BUILD_TYPE_RELEASE "1")
ELSE()
    # SET(WithCMAKE_BUILD_TYPE_Release OFF)
    SET(SSS_HAVE_CMAKE_BUILD_TYPE_RELEASE "0")
ENDIF()

IF("${CMAKE_BUILD_TYPE}" STREQUAL "RelWithDebInfo")
    # SET(WithCMAKE_BUILD_TYPE_RelWithDebInfo ON)
    SET(SSS_HAVE_CMAKE_BUILD_TYPE_RELWITHDEBINFO "1")
ELSE()
    # SET(WithCMAKE_BUILD_TYPE_RelWithDebInfo OFF)
    SET(SSS_HAVE_CMAKE_BUILD_TYPE_RELWITHDEBINFO "0")
ENDIF()

IF("${CMAKE_BUILD_TYPE}" STREQUAL "")
    # SET(WithCMAKE_BUILD_TYPE_ ON)
    SET(SSS_HAVE_CMAKE_BUILD_TYPE_ "1")
ELSE()
    # SET(WithCMAKE_BUILD_TYPE_ OFF)
    SET(SSS_HAVE_CMAKE_BUILD_TYPE_ "0")
ENDIF()

IF("${CMAKE_BUILD_TYPE}" STREQUAL "Debug")
    # OK
ELSEIF("${CMAKE_BUILD_TYPE}" STREQUAL "Release")
    # OK
ELSEIF("${CMAKE_BUILD_TYPE}" STREQUAL "RelWithDebInfo")
    # OK
ELSEIF("${CMAKE_BUILD_TYPE}" STREQUAL "")
    # OK
ELSE()
    MESSAGE(SEND_ERROR "For 'CMAKE_BUILD_TYPE' '${CMAKE_BUILD_TYPE}' is invalid.")
    MESSAGE(STATUS "Only supported values are 'Debug, Release, RelWithDebInfo, '")
ENDIF()

IF("${NXMW_Secure_Tunneling}" STREQUAL "None")
    # SET(WithNXMW_Secure_Tunneling_None ON)
    SET(SSS_HAVE_SECURE_TUNNELING_NONE "1")
ELSE()
    # SET(WithNXMW_Secure_Tunneling_None OFF)
    SET(SSS_HAVE_SECURE_TUNNELING_NONE "0")
ENDIF()

IF("${NXMW_Secure_Tunneling}" STREQUAL "NTAG_AES128_AES256_EV2")
    # SET(WithNXMW_Secure_Tunneling_NTAG_AES128_AES256_EV2 ON)
    SET(SSS_HAVE_SECURE_TUNNELING_NTAG_AES128_AES256_EV2 "1")
ELSE()
    # SET(WithNXMW_Secure_Tunneling_NTAG_AES128_AES256_EV2 OFF)
    SET(SSS_HAVE_SECURE_TUNNELING_NTAG_AES128_AES256_EV2 "0")
ENDIF()

IF("${NXMW_Secure_Tunneling}" STREQUAL "NTAG_AES128_EV2")
    # SET(WithNXMW_Secure_Tunneling_NTAG_AES128_EV2 ON)
    SET(SSS_HAVE_SECURE_TUNNELING_NTAG_AES128_EV2 "1")
ELSE()
    # SET(WithNXMW_Secure_Tunneling_NTAG_AES128_EV2 OFF)
    SET(SSS_HAVE_SECURE_TUNNELING_NTAG_AES128_EV2 "0")
ENDIF()

IF("${NXMW_Secure_Tunneling}" STREQUAL "NTAG_AES256_EV2")
    # SET(WithNXMW_Secure_Tunneling_NTAG_AES256_EV2 ON)
    SET(SSS_HAVE_SECURE_TUNNELING_NTAG_AES256_EV2 "1")
ELSE()
    # SET(WithNXMW_Secure_Tunneling_NTAG_AES256_EV2 OFF)
    SET(SSS_HAVE_SECURE_TUNNELING_NTAG_AES256_EV2 "0")
ENDIF()

IF("${NXMW_Secure_Tunneling}" STREQUAL "None")
    # OK
ELSEIF("${NXMW_Secure_Tunneling}" STREQUAL "NTAG_AES128_AES256_EV2")
    # OK
ELSEIF("${NXMW_Secure_Tunneling}" STREQUAL "NTAG_AES128_EV2")
    # OK
ELSEIF("${NXMW_Secure_Tunneling}" STREQUAL "NTAG_AES256_EV2")
    # OK
ELSE()
    MESSAGE(SEND_ERROR "For 'NXMW_Secure_Tunneling' '${NXMW_Secure_Tunneling}' is invalid.")
    MESSAGE(STATUS "Only supported values are 'None, NTAG_AES128_AES256_EV2, NTAG_AES128_EV2, NTAG_AES256_EV2'")
ENDIF()

IF("${NXMW_Auth_Asymm_Host_PK_Cache}" STREQUAL "Disabled")
    # SET(WithNXMW_Auth_Asymm_Host_PK_Cache_Disabled ON)
    SET(SSS_HAVE_AUTH_ASYMM_HOST_PK_CACHE_DISABLED "1")
ELSE()
    # SET(WithNXMW_Auth_Asymm_Host_PK_Cache_Disabled OFF)
    SET(SSS_HAVE_AUTH_ASYMM_HOST_PK_CACHE_DISABLED "0")
ENDIF()

IF("${NXMW_Auth_Asymm_Host_PK_Cache}" STREQUAL "Enabled")
    # SET(WithNXMW_Auth_Asymm_Host_PK_Cache_Enabled ON)
    SET(SSS_HAVE_AUTH_ASYMM_HOST_PK_CACHE_ENABLED "1")
ELSE()
    # SET(WithNXMW_Auth_Asymm_Host_PK_Cache_Enabled OFF)
    SET(SSS_HAVE_AUTH_ASYMM_HOST_PK_CACHE_ENABLED "0")
ENDIF()

IF("${NXMW_Auth_Asymm_Host_PK_Cache}" STREQUAL "Disabled")
    # OK
ELSEIF("${NXMW_Auth_Asymm_Host_PK_Cache}" STREQUAL "Enabled")
    # OK
ELSE()
    MESSAGE(SEND_ERROR "For 'NXMW_Auth_Asymm_Host_PK_Cache' '${NXMW_Auth_Asymm_Host_PK_Cache}' is invalid.")
    MESSAGE(STATUS "Only supported values are 'Disabled, Enabled'")
ENDIF()

IF("${NXMW_Auth_Asymm_Cert_Repo_Id}" STREQUAL "0")
    # SET(WithNXMW_Auth_Asymm_Cert_Repo_Id_0 ON)
    SET(SSS_HAVE_AUTH_ASYMM_CERT_REPO_ID_0 "1")
ELSE()
    # SET(WithNXMW_Auth_Asymm_Cert_Repo_Id_0 OFF)
    SET(SSS_HAVE_AUTH_ASYMM_CERT_REPO_ID_0 "0")
ENDIF()

IF("${NXMW_Auth_Asymm_Cert_Repo_Id}" STREQUAL "1")
    # SET(WithNXMW_Auth_Asymm_Cert_Repo_Id_1 ON)
    SET(SSS_HAVE_AUTH_ASYMM_CERT_REPO_ID_1 "1")
ELSE()
    # SET(WithNXMW_Auth_Asymm_Cert_Repo_Id_1 OFF)
    SET(SSS_HAVE_AUTH_ASYMM_CERT_REPO_ID_1 "0")
ENDIF()

IF("${NXMW_Auth_Asymm_Cert_Repo_Id}" STREQUAL "2")
    # SET(WithNXMW_Auth_Asymm_Cert_Repo_Id_2 ON)
    SET(SSS_HAVE_AUTH_ASYMM_CERT_REPO_ID_2 "1")
ELSE()
    # SET(WithNXMW_Auth_Asymm_Cert_Repo_Id_2 OFF)
    SET(SSS_HAVE_AUTH_ASYMM_CERT_REPO_ID_2 "0")
ENDIF()

IF("${NXMW_Auth_Asymm_Cert_Repo_Id}" STREQUAL "3")
    # SET(WithNXMW_Auth_Asymm_Cert_Repo_Id_3 ON)
    SET(SSS_HAVE_AUTH_ASYMM_CERT_REPO_ID_3 "1")
ELSE()
    # SET(WithNXMW_Auth_Asymm_Cert_Repo_Id_3 OFF)
    SET(SSS_HAVE_AUTH_ASYMM_CERT_REPO_ID_3 "0")
ENDIF()

IF("${NXMW_Auth_Asymm_Cert_Repo_Id}" STREQUAL "4")
    # SET(WithNXMW_Auth_Asymm_Cert_Repo_Id_4 ON)
    SET(SSS_HAVE_AUTH_ASYMM_CERT_REPO_ID_4 "1")
ELSE()
    # SET(WithNXMW_Auth_Asymm_Cert_Repo_Id_4 OFF)
    SET(SSS_HAVE_AUTH_ASYMM_CERT_REPO_ID_4 "0")
ENDIF()

IF("${NXMW_Auth_Asymm_Cert_Repo_Id}" STREQUAL "5")
    # SET(WithNXMW_Auth_Asymm_Cert_Repo_Id_5 ON)
    SET(SSS_HAVE_AUTH_ASYMM_CERT_REPO_ID_5 "1")
ELSE()
    # SET(WithNXMW_Auth_Asymm_Cert_Repo_Id_5 OFF)
    SET(SSS_HAVE_AUTH_ASYMM_CERT_REPO_ID_5 "0")
ENDIF()

IF("${NXMW_Auth_Asymm_Cert_Repo_Id}" STREQUAL "6")
    # SET(WithNXMW_Auth_Asymm_Cert_Repo_Id_6 ON)
    SET(SSS_HAVE_AUTH_ASYMM_CERT_REPO_ID_6 "1")
ELSE()
    # SET(WithNXMW_Auth_Asymm_Cert_Repo_Id_6 OFF)
    SET(SSS_HAVE_AUTH_ASYMM_CERT_REPO_ID_6 "0")
ENDIF()

IF("${NXMW_Auth_Asymm_Cert_Repo_Id}" STREQUAL "7")
    # SET(WithNXMW_Auth_Asymm_Cert_Repo_Id_7 ON)
    SET(SSS_HAVE_AUTH_ASYMM_CERT_REPO_ID_7 "1")
ELSE()
    # SET(WithNXMW_Auth_Asymm_Cert_Repo_Id_7 OFF)
    SET(SSS_HAVE_AUTH_ASYMM_CERT_REPO_ID_7 "0")
ENDIF()

IF("${NXMW_Auth_Asymm_Cert_Repo_Id}" STREQUAL "0")
    # OK
ELSEIF("${NXMW_Auth_Asymm_Cert_Repo_Id}" STREQUAL "1")
    # OK
ELSEIF("${NXMW_Auth_Asymm_Cert_Repo_Id}" STREQUAL "2")
    # OK
ELSEIF("${NXMW_Auth_Asymm_Cert_Repo_Id}" STREQUAL "3")
    # OK
ELSEIF("${NXMW_Auth_Asymm_Cert_Repo_Id}" STREQUAL "4")
    # OK
ELSEIF("${NXMW_Auth_Asymm_Cert_Repo_Id}" STREQUAL "5")
    # OK
ELSEIF("${NXMW_Auth_Asymm_Cert_Repo_Id}" STREQUAL "6")
    # OK
ELSEIF("${NXMW_Auth_Asymm_Cert_Repo_Id}" STREQUAL "7")
    # OK
ELSE()
    MESSAGE(SEND_ERROR "For 'NXMW_Auth_Asymm_Cert_Repo_Id' '${NXMW_Auth_Asymm_Cert_Repo_Id}' is invalid.")
    MESSAGE(STATUS "Only supported values are '0, 1, 2, 3, 4, 5, 6, 7'")
ENDIF()

IF("${NXMW_Auth_Asymm_Cert_SK_Id}" STREQUAL "0")
    # SET(WithNXMW_Auth_Asymm_Cert_SK_Id_0 ON)
    SET(SSS_HAVE_AUTH_ASYMM_CERT_SK_ID_0 "1")
ELSE()
    # SET(WithNXMW_Auth_Asymm_Cert_SK_Id_0 OFF)
    SET(SSS_HAVE_AUTH_ASYMM_CERT_SK_ID_0 "0")
ENDIF()

IF("${NXMW_Auth_Asymm_Cert_SK_Id}" STREQUAL "1")
    # SET(WithNXMW_Auth_Asymm_Cert_SK_Id_1 ON)
    SET(SSS_HAVE_AUTH_ASYMM_CERT_SK_ID_1 "1")
ELSE()
    # SET(WithNXMW_Auth_Asymm_Cert_SK_Id_1 OFF)
    SET(SSS_HAVE_AUTH_ASYMM_CERT_SK_ID_1 "0")
ENDIF()

IF("${NXMW_Auth_Asymm_Cert_SK_Id}" STREQUAL "2")
    # SET(WithNXMW_Auth_Asymm_Cert_SK_Id_2 ON)
    SET(SSS_HAVE_AUTH_ASYMM_CERT_SK_ID_2 "1")
ELSE()
    # SET(WithNXMW_Auth_Asymm_Cert_SK_Id_2 OFF)
    SET(SSS_HAVE_AUTH_ASYMM_CERT_SK_ID_2 "0")
ENDIF()

IF("${NXMW_Auth_Asymm_Cert_SK_Id}" STREQUAL "3")
    # SET(WithNXMW_Auth_Asymm_Cert_SK_Id_3 ON)
    SET(SSS_HAVE_AUTH_ASYMM_CERT_SK_ID_3 "1")
ELSE()
    # SET(WithNXMW_Auth_Asymm_Cert_SK_Id_3 OFF)
    SET(SSS_HAVE_AUTH_ASYMM_CERT_SK_ID_3 "0")
ENDIF()

IF("${NXMW_Auth_Asymm_Cert_SK_Id}" STREQUAL "4")
    # SET(WithNXMW_Auth_Asymm_Cert_SK_Id_4 ON)
    SET(SSS_HAVE_AUTH_ASYMM_CERT_SK_ID_4 "1")
ELSE()
    # SET(WithNXMW_Auth_Asymm_Cert_SK_Id_4 OFF)
    SET(SSS_HAVE_AUTH_ASYMM_CERT_SK_ID_4 "0")
ENDIF()

IF("${NXMW_Auth_Asymm_Cert_SK_Id}" STREQUAL "0")
    # OK
ELSEIF("${NXMW_Auth_Asymm_Cert_SK_Id}" STREQUAL "1")
    # OK
ELSEIF("${NXMW_Auth_Asymm_Cert_SK_Id}" STREQUAL "2")
    # OK
ELSEIF("${NXMW_Auth_Asymm_Cert_SK_Id}" STREQUAL "3")
    # OK
ELSEIF("${NXMW_Auth_Asymm_Cert_SK_Id}" STREQUAL "4")
    # OK
ELSE()
    MESSAGE(SEND_ERROR "For 'NXMW_Auth_Asymm_Cert_SK_Id' '${NXMW_Auth_Asymm_Cert_SK_Id}' is invalid.")
    MESSAGE(STATUS "Only supported values are '0, 1, 2, 3, 4'")
ENDIF()

IF("${NXMW_Auth_Asymm_CA_Root_Key_Id}" STREQUAL "0")
    # SET(WithNXMW_Auth_Asymm_CA_Root_Key_Id_0 ON)
    SET(SSS_HAVE_AUTH_ASYMM_CA_ROOT_KEY_ID_0 "1")
ELSE()
    # SET(WithNXMW_Auth_Asymm_CA_Root_Key_Id_0 OFF)
    SET(SSS_HAVE_AUTH_ASYMM_CA_ROOT_KEY_ID_0 "0")
ENDIF()

IF("${NXMW_Auth_Asymm_CA_Root_Key_Id}" STREQUAL "1")
    # SET(WithNXMW_Auth_Asymm_CA_Root_Key_Id_1 ON)
    SET(SSS_HAVE_AUTH_ASYMM_CA_ROOT_KEY_ID_1 "1")
ELSE()
    # SET(WithNXMW_Auth_Asymm_CA_Root_Key_Id_1 OFF)
    SET(SSS_HAVE_AUTH_ASYMM_CA_ROOT_KEY_ID_1 "0")
ENDIF()

IF("${NXMW_Auth_Asymm_CA_Root_Key_Id}" STREQUAL "2")
    # SET(WithNXMW_Auth_Asymm_CA_Root_Key_Id_2 ON)
    SET(SSS_HAVE_AUTH_ASYMM_CA_ROOT_KEY_ID_2 "1")
ELSE()
    # SET(WithNXMW_Auth_Asymm_CA_Root_Key_Id_2 OFF)
    SET(SSS_HAVE_AUTH_ASYMM_CA_ROOT_KEY_ID_2 "0")
ENDIF()

IF("${NXMW_Auth_Asymm_CA_Root_Key_Id}" STREQUAL "3")
    # SET(WithNXMW_Auth_Asymm_CA_Root_Key_Id_3 ON)
    SET(SSS_HAVE_AUTH_ASYMM_CA_ROOT_KEY_ID_3 "1")
ELSE()
    # SET(WithNXMW_Auth_Asymm_CA_Root_Key_Id_3 OFF)
    SET(SSS_HAVE_AUTH_ASYMM_CA_ROOT_KEY_ID_3 "0")
ENDIF()

IF("${NXMW_Auth_Asymm_CA_Root_Key_Id}" STREQUAL "4")
    # SET(WithNXMW_Auth_Asymm_CA_Root_Key_Id_4 ON)
    SET(SSS_HAVE_AUTH_ASYMM_CA_ROOT_KEY_ID_4 "1")
ELSE()
    # SET(WithNXMW_Auth_Asymm_CA_Root_Key_Id_4 OFF)
    SET(SSS_HAVE_AUTH_ASYMM_CA_ROOT_KEY_ID_4 "0")
ENDIF()

IF("${NXMW_Auth_Asymm_CA_Root_Key_Id}" STREQUAL "0")
    # OK
ELSEIF("${NXMW_Auth_Asymm_CA_Root_Key_Id}" STREQUAL "1")
    # OK
ELSEIF("${NXMW_Auth_Asymm_CA_Root_Key_Id}" STREQUAL "2")
    # OK
ELSEIF("${NXMW_Auth_Asymm_CA_Root_Key_Id}" STREQUAL "3")
    # OK
ELSEIF("${NXMW_Auth_Asymm_CA_Root_Key_Id}" STREQUAL "4")
    # OK
ELSE()
    MESSAGE(SEND_ERROR "For 'NXMW_Auth_Asymm_CA_Root_Key_Id' '${NXMW_Auth_Asymm_CA_Root_Key_Id}' is invalid.")
    MESSAGE(STATUS "Only supported values are '0, 1, 2, 3, 4'")
ENDIF()

IF("${NXMW_Auth_Symm_App_Key_Id}" STREQUAL "0")
    # SET(WithNXMW_Auth_Symm_App_Key_Id_0 ON)
    SET(SSS_HAVE_AUTH_SYMM_APP_KEY_ID_0 "1")
ELSE()
    # SET(WithNXMW_Auth_Symm_App_Key_Id_0 OFF)
    SET(SSS_HAVE_AUTH_SYMM_APP_KEY_ID_0 "0")
ENDIF()

IF("${NXMW_Auth_Symm_App_Key_Id}" STREQUAL "1")
    # SET(WithNXMW_Auth_Symm_App_Key_Id_1 ON)
    SET(SSS_HAVE_AUTH_SYMM_APP_KEY_ID_1 "1")
ELSE()
    # SET(WithNXMW_Auth_Symm_App_Key_Id_1 OFF)
    SET(SSS_HAVE_AUTH_SYMM_APP_KEY_ID_1 "0")
ENDIF()

IF("${NXMW_Auth_Symm_App_Key_Id}" STREQUAL "2")
    # SET(WithNXMW_Auth_Symm_App_Key_Id_2 ON)
    SET(SSS_HAVE_AUTH_SYMM_APP_KEY_ID_2 "1")
ELSE()
    # SET(WithNXMW_Auth_Symm_App_Key_Id_2 OFF)
    SET(SSS_HAVE_AUTH_SYMM_APP_KEY_ID_2 "0")
ENDIF()

IF("${NXMW_Auth_Symm_App_Key_Id}" STREQUAL "3")
    # SET(WithNXMW_Auth_Symm_App_Key_Id_3 ON)
    SET(SSS_HAVE_AUTH_SYMM_APP_KEY_ID_3 "1")
ELSE()
    # SET(WithNXMW_Auth_Symm_App_Key_Id_3 OFF)
    SET(SSS_HAVE_AUTH_SYMM_APP_KEY_ID_3 "0")
ENDIF()

IF("${NXMW_Auth_Symm_App_Key_Id}" STREQUAL "4")
    # SET(WithNXMW_Auth_Symm_App_Key_Id_4 ON)
    SET(SSS_HAVE_AUTH_SYMM_APP_KEY_ID_4 "1")
ELSE()
    # SET(WithNXMW_Auth_Symm_App_Key_Id_4 OFF)
    SET(SSS_HAVE_AUTH_SYMM_APP_KEY_ID_4 "0")
ENDIF()

IF("${NXMW_Auth_Symm_App_Key_Id}" STREQUAL "0")
    # OK
ELSEIF("${NXMW_Auth_Symm_App_Key_Id}" STREQUAL "1")
    # OK
ELSEIF("${NXMW_Auth_Symm_App_Key_Id}" STREQUAL "2")
    # OK
ELSEIF("${NXMW_Auth_Symm_App_Key_Id}" STREQUAL "3")
    # OK
ELSEIF("${NXMW_Auth_Symm_App_Key_Id}" STREQUAL "4")
    # OK
ELSE()
    MESSAGE(SEND_ERROR "For 'NXMW_Auth_Symm_App_Key_Id' '${NXMW_Auth_Symm_App_Key_Id}' is invalid.")
    MESSAGE(STATUS "Only supported values are '0, 1, 2, 3, 4'")
ENDIF()

IF("${NXMW_Auth_Asymm_Host_Curve}" STREQUAL "NIST_P")
    # SET(WithNXMW_Auth_Asymm_Host_Curve_NIST_P ON)
    SET(SSS_HAVE_AUTH_ASYMM_HOST_CURVE_NIST_P "1")
ELSE()
    # SET(WithNXMW_Auth_Asymm_Host_Curve_NIST_P OFF)
    SET(SSS_HAVE_AUTH_ASYMM_HOST_CURVE_NIST_P "0")
ENDIF()

IF("${NXMW_Auth_Asymm_Host_Curve}" STREQUAL "BRAINPOOL")
    # SET(WithNXMW_Auth_Asymm_Host_Curve_BRAINPOOL ON)
    SET(SSS_HAVE_AUTH_ASYMM_HOST_CURVE_BRAINPOOL "1")
ELSE()
    # SET(WithNXMW_Auth_Asymm_Host_Curve_BRAINPOOL OFF)
    SET(SSS_HAVE_AUTH_ASYMM_HOST_CURVE_BRAINPOOL "0")
ENDIF()

IF("${NXMW_Auth_Asymm_Host_Curve}" STREQUAL "NIST_P")
    # OK
ELSEIF("${NXMW_Auth_Asymm_Host_Curve}" STREQUAL "BRAINPOOL")
    # OK
ELSE()
    MESSAGE(SEND_ERROR "For 'NXMW_Auth_Asymm_Host_Curve' '${NXMW_Auth_Asymm_Host_Curve}' is invalid.")
    MESSAGE(STATUS "Only supported values are 'NIST_P, BRAINPOOL'")
ENDIF()

IF("${NXMW_OpenSSL}" STREQUAL "1_1_1")
    # SET(WithNXMW_OpenSSL_1_1_1 ON)
    SET(SSS_HAVE_OPENSSL_1_1_1 "1")
ELSE()
    # SET(WithNXMW_OpenSSL_1_1_1 OFF)
    SET(SSS_HAVE_OPENSSL_1_1_1 "0")
ENDIF()

IF("${NXMW_OpenSSL}" STREQUAL "3_0")
    # SET(WithNXMW_OpenSSL_3_0 ON)
    SET(SSS_HAVE_OPENSSL_3_0 "1")
ELSE()
    # SET(WithNXMW_OpenSSL_3_0 OFF)
    SET(SSS_HAVE_OPENSSL_3_0 "0")
ENDIF()

IF("${NXMW_OpenSSL}" STREQUAL "1_1_1")
    # OK
ELSEIF("${NXMW_OpenSSL}" STREQUAL "3_0")
    # OK
ELSE()
    MESSAGE(SEND_ERROR "For 'NXMW_OpenSSL' '${NXMW_OpenSSL}' is invalid.")
    MESSAGE(STATUS "Only supported values are '1_1_1, 3_0'")
ENDIF()

IF("${NXMW_MBedTLS}" STREQUAL "2_X")
    # SET(WithNXMW_MBedTLS_2_X ON)
    SET(SSS_HAVE_MBEDTLS_2_X "1")
ELSE()
    # SET(WithNXMW_MBedTLS_2_X OFF)
    SET(SSS_HAVE_MBEDTLS_2_X "0")
ENDIF()

IF("${NXMW_MBedTLS}" STREQUAL "3_X")
    # SET(WithNXMW_MBedTLS_3_X ON)
    SET(SSS_HAVE_MBEDTLS_3_X "1")
ELSE()
    # SET(WithNXMW_MBedTLS_3_X OFF)
    SET(SSS_HAVE_MBEDTLS_3_X "0")
ENDIF()

IF("${NXMW_MBedTLS}" STREQUAL "2_X")
    # OK
ELSEIF("${NXMW_MBedTLS}" STREQUAL "3_X")
    # OK
ELSE()
    MESSAGE(SEND_ERROR "For 'NXMW_MBedTLS' '${NXMW_MBedTLS}' is invalid.")
    MESSAGE(STATUS "Only supported values are '2_X, 3_X'")
ENDIF()

IF("${NXMW_Auth_Symm_Diversify}" STREQUAL "Disabled")
    # SET(WithNXMW_Auth_Symm_Diversify_Disabled ON)
    SET(SSS_HAVE_AUTH_SYMM_DIVERSIFY_DISABLED "1")
ELSE()
    # SET(WithNXMW_Auth_Symm_Diversify_Disabled OFF)
    SET(SSS_HAVE_AUTH_SYMM_DIVERSIFY_DISABLED "0")
ENDIF()

IF("${NXMW_Auth_Symm_Diversify}" STREQUAL "Enabled")
    # SET(WithNXMW_Auth_Symm_Diversify_Enabled ON)
    SET(SSS_HAVE_AUTH_SYMM_DIVERSIFY_ENABLED "1")
ELSE()
    # SET(WithNXMW_Auth_Symm_Diversify_Enabled OFF)
    SET(SSS_HAVE_AUTH_SYMM_DIVERSIFY_ENABLED "0")
ENDIF()

IF("${NXMW_Auth_Symm_Diversify}" STREQUAL "Disabled")
    # OK
ELSEIF("${NXMW_Auth_Symm_Diversify}" STREQUAL "Enabled")
    # OK
ELSE()
    MESSAGE(SEND_ERROR "For 'NXMW_Auth_Symm_Diversify' '${NXMW_Auth_Symm_Diversify}' is invalid.")
    MESSAGE(STATUS "Only supported values are 'Disabled, Enabled'")
ENDIF()

IF("${NXMW_All_Auth_Code}" STREQUAL "Disabled")
    # SET(WithNXMW_All_Auth_Code_Disabled ON)
    SET(SSS_HAVE_ALL_AUTH_CODE_DISABLED "1")
ELSE()
    # SET(WithNXMW_All_Auth_Code_Disabled OFF)
    SET(SSS_HAVE_ALL_AUTH_CODE_DISABLED "0")
ENDIF()

IF("${NXMW_All_Auth_Code}" STREQUAL "Enabled")
    # SET(WithNXMW_All_Auth_Code_Enabled ON)
    SET(SSS_HAVE_ALL_AUTH_CODE_ENABLED "1")
ELSE()
    # SET(WithNXMW_All_Auth_Code_Enabled OFF)
    SET(SSS_HAVE_ALL_AUTH_CODE_ENABLED "0")
ENDIF()

IF("${NXMW_All_Auth_Code}" STREQUAL "Disabled")
    # OK
ELSEIF("${NXMW_All_Auth_Code}" STREQUAL "Enabled")
    # OK
ELSE()
    MESSAGE(SEND_ERROR "For 'NXMW_All_Auth_Code' '${NXMW_All_Auth_Code}' is invalid.")
    MESSAGE(STATUS "Only supported values are 'Disabled, Enabled'")
ENDIF()

IF("${NXMW_mbedTLS_ALT}" STREQUAL "SSS")
    # SET(WithNXMW_mbedTLS_ALT_SSS ON)
    SET(SSS_HAVE_MBEDTLS_ALT_SSS "1")
ELSE()
    # SET(WithNXMW_mbedTLS_ALT_SSS OFF)
    SET(SSS_HAVE_MBEDTLS_ALT_SSS "0")
ENDIF()

IF("${NXMW_mbedTLS_ALT}" STREQUAL "PSA")
    # SET(WithNXMW_mbedTLS_ALT_PSA ON)
    SET(SSS_HAVE_MBEDTLS_ALT_PSA "1")
ELSE()
    # SET(WithNXMW_mbedTLS_ALT_PSA OFF)
    SET(SSS_HAVE_MBEDTLS_ALT_PSA "0")
ENDIF()

IF("${NXMW_mbedTLS_ALT}" STREQUAL "None")
    # SET(WithNXMW_mbedTLS_ALT_None ON)
    SET(SSS_HAVE_MBEDTLS_ALT_NONE "1")
ELSE()
    # SET(WithNXMW_mbedTLS_ALT_None OFF)
    SET(SSS_HAVE_MBEDTLS_ALT_NONE "0")
ENDIF()

IF("${NXMW_mbedTLS_ALT}" STREQUAL "SSS")
    # OK
ELSEIF("${NXMW_mbedTLS_ALT}" STREQUAL "PSA")
    # OK
ELSEIF("${NXMW_mbedTLS_ALT}" STREQUAL "None")
    # OK
ELSE()
    MESSAGE(SEND_ERROR "For 'NXMW_mbedTLS_ALT' '${NXMW_mbedTLS_ALT}' is invalid.")
    MESSAGE(STATUS "Only supported values are 'SSS, PSA, None'")
ENDIF()

IF("${NXMW_SA_Type}" STREQUAL "A30")
    # SET(WithNXMW_SA_Type_A30 ON)
    SET(SSS_HAVE_SA_TYPE_A30 "1")
ELSE()
    # SET(WithNXMW_SA_Type_A30 OFF)
    SET(SSS_HAVE_SA_TYPE_A30 "0")
ENDIF()

IF("${NXMW_SA_Type}" STREQUAL "NTAG_X_DNA")
    # SET(WithNXMW_SA_Type_NTAG_X_DNA ON)
    SET(SSS_HAVE_SA_TYPE_NTAG_X_DNA "1")
ELSE()
    # SET(WithNXMW_SA_Type_NTAG_X_DNA OFF)
    SET(SSS_HAVE_SA_TYPE_NTAG_X_DNA "0")
ENDIF()

IF("${NXMW_SA_Type}" STREQUAL "NXP_INT_CONFIG")
    # SET(WithNXMW_SA_Type_NXP_INT_CONFIG ON)
    SET(SSS_HAVE_SA_TYPE_NXP_INT_CONFIG "1")
ELSE()
    # SET(WithNXMW_SA_Type_NXP_INT_CONFIG OFF)
    SET(SSS_HAVE_SA_TYPE_NXP_INT_CONFIG "0")
ENDIF()

IF("${NXMW_SA_Type}" STREQUAL "Other")
    # SET(WithNXMW_SA_Type_Other ON)
    SET(SSS_HAVE_SA_TYPE_OTHER "1")
ELSE()
    # SET(WithNXMW_SA_Type_Other OFF)
    SET(SSS_HAVE_SA_TYPE_OTHER "0")
ENDIF()

IF("${NXMW_SA_Type}" STREQUAL "A30")
    # OK
ELSEIF("${NXMW_SA_Type}" STREQUAL "NTAG_X_DNA")
    # OK
ELSEIF("${NXMW_SA_Type}" STREQUAL "NXP_INT_CONFIG")
    # OK
ELSEIF("${NXMW_SA_Type}" STREQUAL "Other")
    # OK
ELSE()
    MESSAGE(SEND_ERROR "For 'NXMW_SA_Type' '${NXMW_SA_Type}' is invalid.")
    MESSAGE(STATUS "Only supported values are 'A30, NTAG_X_DNA, NXP_INT_CONFIG, Other'")
ENDIF()

IF("${NXMW_CMSIS_Driver}" STREQUAL "Disabled")
    # SET(WithNXMW_CMSIS_Driver_Disabled ON)
    SET(SSS_HAVE_CMSIS_DRIVER_DISABLED "1")
ELSE()
    # SET(WithNXMW_CMSIS_Driver_Disabled OFF)
    SET(SSS_HAVE_CMSIS_DRIVER_DISABLED "0")
ENDIF()

IF("${NXMW_CMSIS_Driver}" STREQUAL "Enabled")
    # SET(WithNXMW_CMSIS_Driver_Enabled ON)
    SET(SSS_HAVE_CMSIS_DRIVER_ENABLED "1")
ELSE()
    # SET(WithNXMW_CMSIS_Driver_Enabled OFF)
    SET(SSS_HAVE_CMSIS_DRIVER_ENABLED "0")
ENDIF()

IF("${NXMW_CMSIS_Driver}" STREQUAL "Disabled")
    # OK
ELSEIF("${NXMW_CMSIS_Driver}" STREQUAL "Enabled")
    # OK
ELSE()
    MESSAGE(SEND_ERROR "For 'NXMW_CMSIS_Driver' '${NXMW_CMSIS_Driver}' is invalid.")
    MESSAGE(STATUS "Only supported values are 'Disabled, Enabled'")
ENDIF()