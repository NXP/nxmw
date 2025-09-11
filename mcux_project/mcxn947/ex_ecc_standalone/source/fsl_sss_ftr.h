/*
 *
 * Copyright 2023 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef SSS_APIS_INC_FSL_SSS_FTR_H_
#define SSS_APIS_INC_FSL_SSS_FTR_H_

/* ************************************************************************** */
/* Defines                                                                    */
/* ************************************************************************** */

/* clang-format off */


/* # CMake Features : Start */


/** NXMW_NX_Type : The NX Secure Authenticator Type
 * You can compile host library for different OS Applications of NX Secure Authenticator listed below.
 */

/** Compiling without any NX Type Support */
#define SSS_HAVE_NX_TYPE_NONE 0

/** Application (DF name 0xD2760000850101) */
#define SSS_HAVE_NX_TYPE_NX_R_DA 1

/** MF (DF name 0xD2760000850100) */
#define SSS_HAVE_NX_TYPE_NX_PICC 0

#if (( 0                             \
    + SSS_HAVE_NX_TYPE_NONE          \
    + SSS_HAVE_NX_TYPE_NX_R_DA       \
    + SSS_HAVE_NX_TYPE_NX_PICC       \
    ) > 1)
#        error "Enable only one of 'NXMW_NX_Type'"
#endif


#if (( 0                             \
    + SSS_HAVE_NX_TYPE_NONE          \
    + SSS_HAVE_NX_TYPE_NX_R_DA       \
    + SSS_HAVE_NX_TYPE_NX_PICC       \
    ) == 0)
#        error "Enable at-least one of 'NXMW_NX_Type'"
#endif



/** NXMW_Host : Host where the software stack is running
 *
 * e.g. Windows, PC Linux, Embedded Linux, Kinetis like embedded platform
 */

/** PC/Laptop Windows */
#define SSS_HAVE_HOST_PCWINDOWS 0

/** PC/Laptop Linux64 */
#define SSS_HAVE_HOST_PCLINUX64 0

/** Embedded LPCXpresso55s */
#define SSS_HAVE_HOST_LPCXPRESSO55S 0

/** Embedded Linux on RaspBerry PI */
#define SSS_HAVE_HOST_RASPBIAN 0

/** Embedded frdmmcxa153 */
#define SSS_HAVE_HOST_FRDMMCXA153 0

/** Embedded frdmmcxn947 */
#define SSS_HAVE_HOST_FRDMMCXN947 1

#if (( 0                             \
    + SSS_HAVE_HOST_PCWINDOWS        \
    + SSS_HAVE_HOST_PCLINUX64        \
    + SSS_HAVE_HOST_LPCXPRESSO55S    \
    + SSS_HAVE_HOST_RASPBIAN         \
    + SSS_HAVE_HOST_FRDMMCXA153      \
    + SSS_HAVE_HOST_FRDMMCXN947      \
    ) > 1)
#        error "Enable only one of 'NXMW_Host'"
#endif


#if (( 0                             \
    + SSS_HAVE_HOST_PCWINDOWS        \
    + SSS_HAVE_HOST_PCLINUX64        \
    + SSS_HAVE_HOST_LPCXPRESSO55S    \
    + SSS_HAVE_HOST_RASPBIAN         \
    + SSS_HAVE_HOST_FRDMMCXA153      \
    + SSS_HAVE_HOST_FRDMMCXN947      \
    ) == 0)
#        error "Enable at-least one of 'NXMW_Host'"
#endif



/** NXMW_SMCOM : Communication Interface
 *
 * How the host library communicates to the Secure Authenticator.
 * This may be directly over an I2C interface on embedded platform.
 * Or sometimes over Remote protocol like JRCP_V1_AM / VCOM from PC.
 */

/** Not using any Communication layer */
#define SSS_HAVE_SMCOM_NONE 0

/** Virtual COM Port */
#define SSS_HAVE_SMCOM_VCOM 0

/** GP Spec */
#define SSS_HAVE_SMCOM_T1OI2C_GP1_0 1

/** CCID PC/SC reader interface */
#define SSS_HAVE_SMCOM_PCSC 0

/** Socket Interface Old Implementation.
 * This is the interface used from Host PC when when we run jrcpv1_server
 * from the linux PC. */
#define SSS_HAVE_SMCOM_JRCP_V1_AM 0

#if (( 0                             \
    + SSS_HAVE_SMCOM_NONE            \
    + SSS_HAVE_SMCOM_VCOM            \
    + SSS_HAVE_SMCOM_T1OI2C_GP1_0    \
    + SSS_HAVE_SMCOM_PCSC            \
    + SSS_HAVE_SMCOM_JRCP_V1_AM      \
    ) > 1)
#        error "Enable only one of 'NXMW_SMCOM'"
#endif


#if (( 0                             \
    + SSS_HAVE_SMCOM_NONE            \
    + SSS_HAVE_SMCOM_VCOM            \
    + SSS_HAVE_SMCOM_T1OI2C_GP1_0    \
    + SSS_HAVE_SMCOM_PCSC            \
    + SSS_HAVE_SMCOM_JRCP_V1_AM      \
    ) == 0)
#        error "Enable at-least one of 'NXMW_SMCOM'"
#endif



/** NXMW_HostCrypto : Counterpart Crypto on Host
 *
 * What is being used as a cryptographic library on the host.
 * As of now only OpenSSL / mbedTLS is supported
 */

/** Use mbedTLS as host crypto */
#define SSS_HAVE_HOSTCRYPTO_MBEDTLS 1

/** Use OpenSSL as host crypto */
#define SSS_HAVE_HOSTCRYPTO_OPENSSL 0

/** NO Host Crypto
 * Note,  the security of configuring Nx to be used without HostCrypto
 * needs to be assessed from system security point of view */
#define SSS_HAVE_HOSTCRYPTO_NONE 0

#if (( 0                             \
    + SSS_HAVE_HOSTCRYPTO_MBEDTLS    \
    + SSS_HAVE_HOSTCRYPTO_OPENSSL    \
    + SSS_HAVE_HOSTCRYPTO_NONE       \
    ) > 1)
#        error "Enable only one of 'NXMW_HostCrypto'"
#endif


#if (( 0                             \
    + SSS_HAVE_HOSTCRYPTO_MBEDTLS    \
    + SSS_HAVE_HOSTCRYPTO_OPENSSL    \
    + SSS_HAVE_HOSTCRYPTO_NONE       \
    ) == 0)
#        error "Enable at-least one of 'NXMW_HostCrypto'"
#endif



/** NXMW_RTOS : Choice of Operating system
 *
 * Default would mean nothing special.
 * i.e. Without any RTOS on embedded system, or default APIs on PC/Linux
 */

/** No specific RTOS. Either bare matal on embedded system or native linux or Windows OS */
#define SSS_HAVE_RTOS_DEFAULT 1

/** Free RTOS for embedded systems */
#define SSS_HAVE_RTOS_FREERTOS 0

#if (( 0                             \
    + SSS_HAVE_RTOS_DEFAULT          \
    + SSS_HAVE_RTOS_FREERTOS         \
    ) > 1)
#        error "Enable only one of 'NXMW_RTOS'"
#endif


#if (( 0                             \
    + SSS_HAVE_RTOS_DEFAULT          \
    + SSS_HAVE_RTOS_FREERTOS         \
    ) == 0)
#        error "Enable at-least one of 'NXMW_RTOS'"
#endif



/** NXMW_Auth : NX Authentication
 *
 * This settings is used by examples to connect using various options
 * to authenticate with the Nx SE.
 * Refer to :numref:`nx-auth-sessions` --- :ref:`nx-auth-sessions` for the combinations of session auth and secure tunneling modes.
 */

/** Use the default session (i.e. session less) login */
#define SSS_HAVE_AUTH_NONE 0

/** SIGMA I Verifier */
#define SSS_HAVE_AUTH_SIGMA_I_VERIFIER 0

/** SIGMA I Prover */
#define SSS_HAVE_AUTH_SIGMA_I_PROVER 0

/** Symmetric Authentication */
#define SSS_HAVE_AUTH_SYMM_AUTH 1

#if (( 0                             \
    + SSS_HAVE_AUTH_NONE             \
    + SSS_HAVE_AUTH_SIGMA_I_VERIFIER \
    + SSS_HAVE_AUTH_SIGMA_I_PROVER   \
    + SSS_HAVE_AUTH_SYMM_AUTH        \
    ) > 1)
#        error "Enable only one of 'NXMW_Auth'"
#endif


#if (( 0                             \
    + SSS_HAVE_AUTH_NONE             \
    + SSS_HAVE_AUTH_SIGMA_I_VERIFIER \
    + SSS_HAVE_AUTH_SIGMA_I_PROVER   \
    + SSS_HAVE_AUTH_SYMM_AUTH        \
    ) == 0)
#        error "Enable at-least one of 'NXMW_Auth'"
#endif



/** NXMW_Log : Logging
 */

/** Default Logging */
#define SSS_HAVE_LOG_DEFAULT 1

/** Very Verbose logging */
#define SSS_HAVE_LOG_VERBOSE 0

/** Totally silent logging */
#define SSS_HAVE_LOG_SILENT 0

/** Segger Real Time Transfer (For Test Automation, NXP Internal) */
#define SSS_HAVE_LOG_SEGGERRTT 0

#if (( 0                             \
    + SSS_HAVE_LOG_DEFAULT           \
    + SSS_HAVE_LOG_VERBOSE           \
    + SSS_HAVE_LOG_SILENT            \
    + SSS_HAVE_LOG_SEGGERRTT         \
    ) > 1)
#        error "Enable only one of 'NXMW_Log'"
#endif


#if (( 0                             \
    + SSS_HAVE_LOG_DEFAULT           \
    + SSS_HAVE_LOG_VERBOSE           \
    + SSS_HAVE_LOG_SILENT            \
    + SSS_HAVE_LOG_SEGGERRTT         \
    ) == 0)
#        error "Enable at-least one of 'NXMW_Log'"
#endif



/** NXMW_Secure_Tunneling : Secure Tunneling(Secure Messaging)
 *
 * Successful Symmetric authentication and SIGMA-I mutual authentication results in the establishment of
 * session keys and session IVs.
 * These are used to encrypt and integrity protect the payloads to be exchanged.
 * Refer to :numref:`nx-auth-sessions` --- :ref:`nx-auth-sessions` for the combinations of session auth and secure tunneling modes.
 */

/** Plain Text */
#define SSS_HAVE_SECURE_TUNNELING_NONE 0

/** NTAG AES-128 or AES-256 (EV2) Secure Channel. Only valid for Sigma-I. Host supports both AES-128 and AES-256. The secure channel security strength is selected based on the SE configuration. */
#define SSS_HAVE_SECURE_TUNNELING_NTAG_AES128_AES256_EV2 0

/** Only NTAG AES-128 (EV2) Secure Channel */
#define SSS_HAVE_SECURE_TUNNELING_NTAG_AES128_EV2 1

/** Only NTAG AES-256 (EV2) Secure Channel */
#define SSS_HAVE_SECURE_TUNNELING_NTAG_AES256_EV2 0

#if (( 0                             \
    + SSS_HAVE_SECURE_TUNNELING_NONE \
    + SSS_HAVE_SECURE_TUNNELING_NTAG_AES128_AES256_EV2 \
    + SSS_HAVE_SECURE_TUNNELING_NTAG_AES128_EV2 \
    + SSS_HAVE_SECURE_TUNNELING_NTAG_AES256_EV2 \
    ) > 1)
#        error "Enable only one of 'NXMW_Secure_Tunneling'"
#endif


#if (( 0                             \
    + SSS_HAVE_SECURE_TUNNELING_NONE \
    + SSS_HAVE_SECURE_TUNNELING_NTAG_AES128_AES256_EV2 \
    + SSS_HAVE_SECURE_TUNNELING_NTAG_AES128_EV2 \
    + SSS_HAVE_SECURE_TUNNELING_NTAG_AES256_EV2 \
    ) == 0)
#        error "Enable at-least one of 'NXMW_Secure_Tunneling'"
#endif



/** NXMW_Auth_Asymm_Host_PK_Cache : Host public key cache
 *
 * Support a cache of validated public keys and parent certificates on host.
 * This is utilized to accelerate protocol execution time by removing the need
 * to validate public key and certificates that have been previously verified. Refer to :numref:`nx-auth-sessions` --- :ref:`nx-auth-sessions` for more information.
 *
 * Secure authenticator cache is enabled by Cmd.SetConfiguration. Ref to section 4.6.2 for more information.
 */

/** Host's Public Key And Parent Certificates Cache Disabled */
#define SSS_HAVE_AUTH_ASYMM_HOST_PK_CACHE_DISABLED 0

/** Host's Public Key And Parent Certificates Cache Enabled */
#define SSS_HAVE_AUTH_ASYMM_HOST_PK_CACHE_ENABLED 1

#if (( 0                             \
    + SSS_HAVE_AUTH_ASYMM_HOST_PK_CACHE_DISABLED \
    + SSS_HAVE_AUTH_ASYMM_HOST_PK_CACHE_ENABLED \
    ) > 1)
#        error "Enable only one of 'NXMW_Auth_Asymm_Host_PK_Cache'"
#endif


#if (( 0                             \
    + SSS_HAVE_AUTH_ASYMM_HOST_PK_CACHE_DISABLED \
    + SSS_HAVE_AUTH_ASYMM_HOST_PK_CACHE_ENABLED \
    ) == 0)
#        error "Enable at-least one of 'NXMW_Auth_Asymm_Host_PK_Cache'"
#endif



/** NXMW_Auth_Asymm_Cert_Repo_Id : Certificate Repository Id
 *
 * Certificate Repository Id is used to identify certificate repository. Used in both personalization and demos with Sigma-I authentication.
 * In personalization, it indicates repository to be initialized. In demos, it indicates repository to be used for Sigma-I authentication
 */

/** Certificate Repository 0 */
#define SSS_HAVE_AUTH_ASYMM_CERT_REPO_ID_0 1

/** Certificate Repository 1 */
#define SSS_HAVE_AUTH_ASYMM_CERT_REPO_ID_1 0

/** Certificate Repository 2 */
#define SSS_HAVE_AUTH_ASYMM_CERT_REPO_ID_2 0

/** Certificate Repository 3 */
#define SSS_HAVE_AUTH_ASYMM_CERT_REPO_ID_3 0

/** Certificate Repository 4 */
#define SSS_HAVE_AUTH_ASYMM_CERT_REPO_ID_4 0

/** Certificate Repository 5 */
#define SSS_HAVE_AUTH_ASYMM_CERT_REPO_ID_5 0

/** Certificate Repository 6 */
#define SSS_HAVE_AUTH_ASYMM_CERT_REPO_ID_6 0

/** Certificate Repository 7 */
#define SSS_HAVE_AUTH_ASYMM_CERT_REPO_ID_7 0

#if (( 0                             \
    + SSS_HAVE_AUTH_ASYMM_CERT_REPO_ID_0 \
    + SSS_HAVE_AUTH_ASYMM_CERT_REPO_ID_1 \
    + SSS_HAVE_AUTH_ASYMM_CERT_REPO_ID_2 \
    + SSS_HAVE_AUTH_ASYMM_CERT_REPO_ID_3 \
    + SSS_HAVE_AUTH_ASYMM_CERT_REPO_ID_4 \
    + SSS_HAVE_AUTH_ASYMM_CERT_REPO_ID_5 \
    + SSS_HAVE_AUTH_ASYMM_CERT_REPO_ID_6 \
    + SSS_HAVE_AUTH_ASYMM_CERT_REPO_ID_7 \
    ) > 1)
#        error "Enable only one of 'NXMW_Auth_Asymm_Cert_Repo_Id'"
#endif


#if (( 0                             \
    + SSS_HAVE_AUTH_ASYMM_CERT_REPO_ID_0 \
    + SSS_HAVE_AUTH_ASYMM_CERT_REPO_ID_1 \
    + SSS_HAVE_AUTH_ASYMM_CERT_REPO_ID_2 \
    + SSS_HAVE_AUTH_ASYMM_CERT_REPO_ID_3 \
    + SSS_HAVE_AUTH_ASYMM_CERT_REPO_ID_4 \
    + SSS_HAVE_AUTH_ASYMM_CERT_REPO_ID_5 \
    + SSS_HAVE_AUTH_ASYMM_CERT_REPO_ID_6 \
    + SSS_HAVE_AUTH_ASYMM_CERT_REPO_ID_7 \
    ) == 0)
#        error "Enable at-least one of 'NXMW_Auth_Asymm_Cert_Repo_Id'"
#endif



/** NXMW_Auth_Asymm_Cert_SK_Id : Certificate Private Key Id
 *
 * Id of ECC private key associated with this
 * repository. Used in personalization for Sigma-I.
 */

/** Certificate Private KeyId 0 */
#define SSS_HAVE_AUTH_ASYMM_CERT_SK_ID_0 1

/** Certificate Private KeyId 1 */
#define SSS_HAVE_AUTH_ASYMM_CERT_SK_ID_1 0

/** Certificate Private KeyId 2 */
#define SSS_HAVE_AUTH_ASYMM_CERT_SK_ID_2 0

/** Certificate Private KeyId 3 */
#define SSS_HAVE_AUTH_ASYMM_CERT_SK_ID_3 0

/** Certificate Private KeyId 4 */
#define SSS_HAVE_AUTH_ASYMM_CERT_SK_ID_4 0

#if (( 0                             \
    + SSS_HAVE_AUTH_ASYMM_CERT_SK_ID_0 \
    + SSS_HAVE_AUTH_ASYMM_CERT_SK_ID_1 \
    + SSS_HAVE_AUTH_ASYMM_CERT_SK_ID_2 \
    + SSS_HAVE_AUTH_ASYMM_CERT_SK_ID_3 \
    + SSS_HAVE_AUTH_ASYMM_CERT_SK_ID_4 \
    ) > 1)
#        error "Enable only one of 'NXMW_Auth_Asymm_Cert_SK_Id'"
#endif


#if (( 0                             \
    + SSS_HAVE_AUTH_ASYMM_CERT_SK_ID_0 \
    + SSS_HAVE_AUTH_ASYMM_CERT_SK_ID_1 \
    + SSS_HAVE_AUTH_ASYMM_CERT_SK_ID_2 \
    + SSS_HAVE_AUTH_ASYMM_CERT_SK_ID_3 \
    + SSS_HAVE_AUTH_ASYMM_CERT_SK_ID_4 \
    ) == 0)
#        error "Enable at-least one of 'NXMW_Auth_Asymm_Cert_SK_Id'"
#endif



/** NXMW_Auth_Asymm_CA_Root_Key_Id : Key ID of CA Root Public Key
 *
 * Id of CA root public key associated with this
 * repository. Used in personalization for Sigma-I.
 */

/** CA Root KeyId 0 */
#define SSS_HAVE_AUTH_ASYMM_CA_ROOT_KEY_ID_0 1

/** CA Root KeyId 1 */
#define SSS_HAVE_AUTH_ASYMM_CA_ROOT_KEY_ID_1 0

/** CA Root KeyId 2 */
#define SSS_HAVE_AUTH_ASYMM_CA_ROOT_KEY_ID_2 0

/** CA Root KeyId 3 */
#define SSS_HAVE_AUTH_ASYMM_CA_ROOT_KEY_ID_3 0

/** CA Root KeyId 4 */
#define SSS_HAVE_AUTH_ASYMM_CA_ROOT_KEY_ID_4 0

#if (( 0                             \
    + SSS_HAVE_AUTH_ASYMM_CA_ROOT_KEY_ID_0 \
    + SSS_HAVE_AUTH_ASYMM_CA_ROOT_KEY_ID_1 \
    + SSS_HAVE_AUTH_ASYMM_CA_ROOT_KEY_ID_2 \
    + SSS_HAVE_AUTH_ASYMM_CA_ROOT_KEY_ID_3 \
    + SSS_HAVE_AUTH_ASYMM_CA_ROOT_KEY_ID_4 \
    ) > 1)
#        error "Enable only one of 'NXMW_Auth_Asymm_CA_Root_Key_Id'"
#endif


#if (( 0                             \
    + SSS_HAVE_AUTH_ASYMM_CA_ROOT_KEY_ID_0 \
    + SSS_HAVE_AUTH_ASYMM_CA_ROOT_KEY_ID_1 \
    + SSS_HAVE_AUTH_ASYMM_CA_ROOT_KEY_ID_2 \
    + SSS_HAVE_AUTH_ASYMM_CA_ROOT_KEY_ID_3 \
    + SSS_HAVE_AUTH_ASYMM_CA_ROOT_KEY_ID_4 \
    ) == 0)
#        error "Enable at-least one of 'NXMW_Auth_Asymm_CA_Root_Key_Id'"
#endif



/** NXMW_Auth_Symm_App_Key_Id : application Key ID
 *
 * Indicate application key which is used in symmetric authentication.
 */

/** Application KeyId 0 */
#define SSS_HAVE_AUTH_SYMM_APP_KEY_ID_0 1

/** Application KeyId 1 */
#define SSS_HAVE_AUTH_SYMM_APP_KEY_ID_1 0

/** Application KeyId 2 */
#define SSS_HAVE_AUTH_SYMM_APP_KEY_ID_2 0

/** Application KeyId 3 */
#define SSS_HAVE_AUTH_SYMM_APP_KEY_ID_3 0

/** Application KeyId 4 */
#define SSS_HAVE_AUTH_SYMM_APP_KEY_ID_4 0

#if (( 0                             \
    + SSS_HAVE_AUTH_SYMM_APP_KEY_ID_0 \
    + SSS_HAVE_AUTH_SYMM_APP_KEY_ID_1 \
    + SSS_HAVE_AUTH_SYMM_APP_KEY_ID_2 \
    + SSS_HAVE_AUTH_SYMM_APP_KEY_ID_3 \
    + SSS_HAVE_AUTH_SYMM_APP_KEY_ID_4 \
    ) > 1)
#        error "Enable only one of 'NXMW_Auth_Symm_App_Key_Id'"
#endif


#if (( 0                             \
    + SSS_HAVE_AUTH_SYMM_APP_KEY_ID_0 \
    + SSS_HAVE_AUTH_SYMM_APP_KEY_ID_1 \
    + SSS_HAVE_AUTH_SYMM_APP_KEY_ID_2 \
    + SSS_HAVE_AUTH_SYMM_APP_KEY_ID_3 \
    + SSS_HAVE_AUTH_SYMM_APP_KEY_ID_4 \
    ) == 0)
#        error "Enable at-least one of 'NXMW_Auth_Symm_App_Key_Id'"
#endif



/** NXMW_Auth_Asymm_Host_Curve : Host EC domain curve type
 *
 * EC domain curve used for session key generation and
 * session signature. Used in demos with Sigma-I authentication.
 */

/** EC Curve NIST-P */
#define SSS_HAVE_AUTH_ASYMM_HOST_CURVE_NIST_P 1

/** EC Curve Brainpool */
#define SSS_HAVE_AUTH_ASYMM_HOST_CURVE_BRAINPOOL 0

#if (( 0                             \
    + SSS_HAVE_AUTH_ASYMM_HOST_CURVE_NIST_P \
    + SSS_HAVE_AUTH_ASYMM_HOST_CURVE_BRAINPOOL \
    ) > 1)
#        error "Enable only one of 'NXMW_Auth_Asymm_Host_Curve'"
#endif


#if (( 0                             \
    + SSS_HAVE_AUTH_ASYMM_HOST_CURVE_NIST_P \
    + SSS_HAVE_AUTH_ASYMM_HOST_CURVE_BRAINPOOL \
    ) == 0)
#        error "Enable at-least one of 'NXMW_Auth_Asymm_Host_Curve'"
#endif



/** NXMW_OpenSSL : For PC, which OpenSSL to pick up
 *
 * On Linux based builds, this option has no impact, because the build system
 * picks up the default available/installed OpenSSL from the system directly.
 */

/** Use latest 1.1.1 version (Only applicable on PC) */
#define SSS_HAVE_OPENSSL_1_1_1 1

/** Use 3.0 version (Only applicable on PC) */
#define SSS_HAVE_OPENSSL_3_0 0

#if (( 0                             \
    + SSS_HAVE_OPENSSL_1_1_1         \
    + SSS_HAVE_OPENSSL_3_0           \
    ) > 1)
#        error "Enable only one of 'NXMW_OpenSSL'"
#endif


#if (( 0                             \
    + SSS_HAVE_OPENSSL_1_1_1         \
    + SSS_HAVE_OPENSSL_3_0           \
    ) == 0)
#        error "Enable at-least one of 'NXMW_OpenSSL'"
#endif



/** NXMW_MBedTLS : Which MBedTLS version to choose
 */

/** Use 2.X version */
#define SSS_HAVE_MBEDTLS_2_X 1

/** Use 3.X version */
#define SSS_HAVE_MBEDTLS_3_X 0

#if (( 0                             \
    + SSS_HAVE_MBEDTLS_2_X           \
    + SSS_HAVE_MBEDTLS_3_X           \
    ) > 1)
#        error "Enable only one of 'NXMW_MBedTLS'"
#endif


#if (( 0                             \
    + SSS_HAVE_MBEDTLS_2_X           \
    + SSS_HAVE_MBEDTLS_3_X           \
    ) == 0)
#        error "Enable at-least one of 'NXMW_MBedTLS'"
#endif



/** NXMW_Auth_Symm_Diversify : Diversification of symmetric authentication key
 *
 * When enabled, key used for symmetric authentication is diversification key derived from master key.
 *
 * Otherwise master key is used.
 */

/** Symm Auth Key Diversification Disabled */
#define SSS_HAVE_AUTH_SYMM_DIVERSIFY_DISABLED 1

/** Symm Auth Key Diversification Enabled */
#define SSS_HAVE_AUTH_SYMM_DIVERSIFY_ENABLED 0

#if (( 0                             \
    + SSS_HAVE_AUTH_SYMM_DIVERSIFY_DISABLED \
    + SSS_HAVE_AUTH_SYMM_DIVERSIFY_ENABLED \
    ) > 1)
#        error "Enable only one of 'NXMW_Auth_Symm_Diversify'"
#endif


#if (( 0                             \
    + SSS_HAVE_AUTH_SYMM_DIVERSIFY_DISABLED \
    + SSS_HAVE_AUTH_SYMM_DIVERSIFY_ENABLED \
    ) == 0)
#        error "Enable at-least one of 'NXMW_Auth_Symm_Diversify'"
#endif



/** NXMW_All_Auth_Code : Enable all authentication code
 * When enabled, all the authentication code is enabled in nx library.
 */

/** Enable only required authentication code (Based on NXMW_Auth Cmake option) */
#define SSS_HAVE_ALL_AUTH_CODE_DISABLED 1

/** Enable all authentication code */
#define SSS_HAVE_ALL_AUTH_CODE_ENABLED 0

#if (( 0                             \
    + SSS_HAVE_ALL_AUTH_CODE_DISABLED \
    + SSS_HAVE_ALL_AUTH_CODE_ENABLED \
    ) > 1)
#        error "Enable only one of 'NXMW_All_Auth_Code'"
#endif


#if (( 0                             \
    + SSS_HAVE_ALL_AUTH_CODE_DISABLED \
    + SSS_HAVE_ALL_AUTH_CODE_ENABLED \
    ) == 0)
#        error "Enable at-least one of 'NXMW_All_Auth_Code'"
#endif



/** NXMW_mbedTLS_ALT : ALT Engine implementation for mbedTLS
 *
 * When set to None, mbedTLS would not use ALT Implementation to connect to / use Secure Authenticator.
 * This needs to be set to PSA for PSA example over SSS APIs
 */

/** Use SSS Layer ALT implementation */
#define SSS_HAVE_MBEDTLS_ALT_SSS 0

/** Enable TF-M based on PSA as ALT */
#define SSS_HAVE_MBEDTLS_ALT_PSA 0

/** Not using any mbedTLS_ALT
 *
 * When this is selected, cloud demos can not work with mbedTLS */
#define SSS_HAVE_MBEDTLS_ALT_NONE 1

#if (( 0                             \
    + SSS_HAVE_MBEDTLS_ALT_SSS       \
    + SSS_HAVE_MBEDTLS_ALT_PSA       \
    + SSS_HAVE_MBEDTLS_ALT_NONE      \
    ) > 1)
#        error "Enable only one of 'NXMW_mbedTLS_ALT'"
#endif


#if (( 0                             \
    + SSS_HAVE_MBEDTLS_ALT_SSS       \
    + SSS_HAVE_MBEDTLS_ALT_PSA       \
    + SSS_HAVE_MBEDTLS_ALT_NONE      \
    ) == 0)
#        error "Enable at-least one of 'NXMW_mbedTLS_ALT'"
#endif



/** NXMW_SA_Type : Enable host certificates of A30 for sigma-I Authentication
 * When Secure Authenticator type is selected, respective host certificates are enabled in nx library.
 */

/** Enable A30 host cert for sigma-I authentication */
#define SSS_HAVE_SA_TYPE_A30 1

/** Enable NTAG_X_DNA host cert for sigma-I authentication */
#define SSS_HAVE_SA_TYPE_NTAG_X_DNA 0

/** Enable NXP_INT_CONFIG host cert for sigma-I authentication */
#define SSS_HAVE_SA_TYPE_NXP_INT_CONFIG 0

/** Enable Other host cert for sigma-I authentication */
#define SSS_HAVE_SA_TYPE_OTHER 0

#if (( 0                             \
    + SSS_HAVE_SA_TYPE_A30           \
    + SSS_HAVE_SA_TYPE_NTAG_X_DNA    \
    + SSS_HAVE_SA_TYPE_NXP_INT_CONFIG \
    + SSS_HAVE_SA_TYPE_OTHER         \
    ) > 1)
#        error "Enable only one of 'NXMW_SA_Type'"
#endif


#if (( 0                             \
    + SSS_HAVE_SA_TYPE_A30           \
    + SSS_HAVE_SA_TYPE_NTAG_X_DNA    \
    + SSS_HAVE_SA_TYPE_NXP_INT_CONFIG \
    + SSS_HAVE_SA_TYPE_OTHER         \
    ) == 0)
#        error "Enable at-least one of 'NXMW_SA_Type'"
#endif



/** NXMW_CMSIS_DRIVER : CMSIS I2C driver for communicating with SA
 *
 * CMSIS I2C driver for communicating with SA. (Disabled by Default)
 */

/** CMSIS I2C driver Disabled */
#define SSS_HAVE_CMSIS_DRIVER_DISABLED 1

/** CMSIS I2C driver Enabled */
#define SSS_HAVE_CMSIS_DRIVER_ENABLED 0

#if (( 0                             \
    + SSS_HAVE_CMSIS_DRIVER_DISABLED \
    + SSS_HAVE_CMSIS_DRIVER_ENABLED  \
    ) > 1)
#        error "Enable only one of 'NXMW_CMSIS_DRIVER'"
#endif


#if (( 0                             \
    + SSS_HAVE_CMSIS_DRIVER_DISABLED \
    + SSS_HAVE_CMSIS_DRIVER_ENABLED  \
    ) == 0)
#        error "Enable at-least one of 'NXMW_CMSIS_DRIVER'"
#endif




#define SSS_HAVE_NX_TYPE \
 (SSS_HAVE_NX_TYPE_NX_R_DA | SSS_HAVE_NX_TYPE_NX_PICC)

#define SSS_HAVE_MBEDTLS_ALT \
 (SSS_HAVE_MBEDTLS_ALT_SSS)

#define SSS_HAVE_HOSTCRYPTO_ANY \
 (SSS_HAVE_HOSTCRYPTO_MBEDTLS | SSS_HAVE_HOSTCRYPTO_OPENSSL | SSS_HAVE_HOSTCRYPTO_USER)

#define SSS_HAVE_HOST_EMBEDDED \
 (SSS_HAVE_HOST_LPCXPRESSO55S | SSS_HAVE_HOST_FRDMMCXA153 | SSS_HAVE_HOST_FRDMMCXN947)

/** Deprecated items. Used here for backwards compatibility. */


/* # CMake Features : END */


/* ========= Calculated values : START ====================== */

/* Should we expose, SSS APIs */
#define SSS_HAVE_SSS ( 0             \
    + SSS_HAVE_NX_TYPE               \
    + SSS_HAVE_HOSTCRYPTO_OPENSSL    \
    + SSS_HAVE_HOSTCRYPTO_MBEDTLS    \
    )

#if SSS_HAVE_AUTH_SYMM_APP_KEY_ID_0
#   define SSS_HAVE_AUTH_SYMM_APP_KEY_ID 0
#elif SSS_HAVE_AUTH_SYMM_APP_KEY_ID_1
#   define SSS_HAVE_AUTH_SYMM_APP_KEY_ID 1
#elif SSS_HAVE_AUTH_SYMM_APP_KEY_ID_2
#   define SSS_HAVE_AUTH_SYMM_APP_KEY_ID 2
#elif SSS_HAVE_AUTH_SYMM_APP_KEY_ID_3
#   define SSS_HAVE_AUTH_SYMM_APP_KEY_ID 3
#else
#   define SSS_HAVE_AUTH_SYMM_APP_KEY_ID 4
#endif

#if SSS_HAVE_AUTH_ASYMM_CERT_REPO_ID_0
#   define SSS_AUTH_ASYMM_CERT_REPO_ID 0
#elif SSS_HAVE_AUTH_ASYMM_CERT_REPO_ID_1
#   define SSS_AUTH_ASYMM_CERT_REPO_ID 1
#elif SSS_HAVE_AUTH_ASYMM_CERT_REPO_ID_2
#   define SSS_AUTH_ASYMM_CERT_REPO_ID 2
#elif SSS_HAVE_AUTH_ASYMM_CERT_REPO_ID_3
#   define SSS_AUTH_ASYMM_CERT_REPO_ID 3
#elif SSS_HAVE_AUTH_ASYMM_CERT_REPO_ID_4
#   define SSS_AUTH_ASYMM_CERT_REPO_ID 4
#elif SSS_HAVE_AUTH_ASYMM_CERT_REPO_ID_5
#   define SSS_AUTH_ASYMM_CERT_REPO_ID 5
#elif SSS_HAVE_AUTH_ASYMM_CERT_REPO_ID_6
#   define SSS_AUTH_ASYMM_CERT_REPO_ID 6
#else
#   define SSS_AUTH_ASYMM_CERT_REPO_ID 7
#endif

#if SSS_HAVE_AUTH_ASYMM_CERT_SK_ID_0
#   define SSS_AUTH_ASYMM_CERT_SK_ID 0
#elif SSS_HAVE_AUTH_ASYMM_CERT_SK_ID_1
#   define SSS_AUTH_ASYMM_CERT_SK_ID 1
#elif SSS_HAVE_AUTH_ASYMM_CERT_SK_ID_2
#   define SSS_AUTH_ASYMM_CERT_SK_ID 2
#elif SSS_HAVE_AUTH_ASYMM_CERT_SK_ID_3
#   define SSS_AUTH_ASYMM_CERT_SK_ID 3
#else
#   define SSS_AUTH_ASYMM_CERT_SK_ID 4
#endif

#if SSS_HAVE_AUTH_ASYMM_CA_ROOT_KEY_ID_0
#   define SSS_AUTH_ASYMM_CA_ROOT_KEY_ID 0
#elif SSS_HAVE_AUTH_ASYMM_CA_ROOT_KEY_ID_1
#   define SSS_AUTH_ASYMM_CA_ROOT_KEY_ID 1
#elif SSS_HAVE_AUTH_ASYMM_CA_ROOT_KEY_ID_2
#   define SSS_AUTH_ASYMM_CA_ROOT_KEY_ID 2
#elif SSS_HAVE_AUTH_ASYMM_CA_ROOT_KEY_ID_3
#   define SSS_AUTH_ASYMM_CA_ROOT_KEY_ID 3
#else
#   define SSS_AUTH_ASYMM_CA_ROOT_KEY_ID 4
#endif

#   define SSS_AUTH_CERT_AC_MAP  ( \
 (NXMW_AUTH_AC_BITMAP_Bit12<<12) \
 | (NXMW_AUTH_AC_BITMAP_Bit11<<11) \
 | (NXMW_AUTH_AC_BITMAP_Bit10<<10) \
 | (NXMW_AUTH_AC_BITMAP_Bit09<<9) \
 | (NXMW_AUTH_AC_BITMAP_Bit08<<8) \
 | (NXMW_AUTH_AC_BITMAP_Bit07<<7) \
 | (NXMW_AUTH_AC_BITMAP_Bit06<<6) \
 | (NXMW_AUTH_AC_BITMAP_Bit05<<5) \
 | (NXMW_AUTH_AC_BITMAP_Bit04<<4) \
 | (NXMW_AUTH_AC_BITMAP_Bit03<<3) \
 | (NXMW_AUTH_AC_BITMAP_Bit02<<2) \
 | (NXMW_AUTH_AC_BITMAP_Bit01<<1) \
 | (NXMW_AUTH_AC_BITMAP_Bit00<<0) \
 )

/* ========= Calculated values : END ======================== */

/* clang-format on */

#endif /* SSS_APIS_INC_FSL_SSS_FTR_H_ */
