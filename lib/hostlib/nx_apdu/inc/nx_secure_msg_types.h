/*
*
* Copyright 2022-2023 NXP
* SPDX-License-Identifier: BSD-3-Clause
*/

#ifndef NX_SECURE_MSG_TYPES_H_
#define NX_SECURE_MSG_TYPES_H_

/* ************************************************************************** */
/* Includes                                                                   */
/* ************************************************************************** */
#if defined(SSS_USE_FTR_FILE)
#include "fsl_sss_ftr.h"
#else
#include "fsl_sss_ftr_default.h"
#endif
#include "fsl_sss_api.h"
#include "sm_api.h"

#define NX_MAX_CERT_DEPTH 3
#define NX_SHA256_BYTE_LEN 32
#define NX_ECDSA_P256_SIG_BUFFER_SIZE 80
#define NX_PUBLIC_KEY_BUFFER_SIZE 256
#define NX_LEAF_CERT_CACHE_MAX 5
#define NX_LEAF_CERT_CACHE_ITEM_NA (NX_LEAF_CERT_CACHE_MAX + 1) // Invaid item number
#define NX_PARENT_CERT_CACHE_MAX 5
#define NX_CERT_MAPPING_TABLE_MAX 20
#define NX_MAX_CERT_BUFFER_SIZE 1024
#define NX_ECDSA_V4_RANDOM_LEN 16
#define NX_MAX_INCLUDE_DIR_LENGTH 150
#define NX_PCD_CAPABILITIES_LEN 6
#define NX_PD_CAPABILITIES_LEN 6
#define NX_SYMM_AUTH_APPKEY_MAX_SIZE 32

typedef enum
{
    knx_AuthType_None = 0,

    /** SIGMA-I Verifier */
    knx_AuthType_SIGMA_I_Verifier = 2,

    /** SIGMA-I Prover */
    knx_AuthType_SIGMA_I_Prover = 3,

    /** Symm Authentication */
    knx_AuthType_SYMM_AUTH = 5,
} nx_auth_type_t;

typedef enum
{
    /** Not Authenticated */
    kVCState_NotAuthenticated = 0,

    /** Not Partially Authenticated */
    kVCState_PartiallyAuthenticated = 1,

    /** Not Authenticated AES */
    kVCState_AuthenticatedAES = 2,

    /** Not Authenticated ECC */
    kVCState_AuthenticatedECC = 3,
} nx_auth_satus_t;

typedef enum
{
    knx_SecureSymmType_None = 0,
    /** NTAG AES-128/256 Secure Channel */
    knx_SecureSymmType_AES128_AES256_NTAG = 1,
    /** AES-256 Secure Channel */
    knx_SecureSymmType_AES256_CCM = 2,
    /** AES-128 Secure Channel */
    knx_SecureSymmType_AES128_NTAG = 3,
    /** AES-256 Secure Channel */
    knx_SecureSymmType_AES256_NTAG = 4,
} nx_secure_symm_type_t;

typedef enum
{
    /** Host disable Tx compress certificate */
    knx_AuthCompress_Disabled = 0,
    /** Host enable Tx compress certificate */
    knx_AuthCompress_Enabled = 1,
} auth_compress_type_t;

typedef enum
{
    /** Host disable certificate cache */
    knx_AuthCache_Disabled = 0,
    /** Host enable certificate cache */
    knx_AuthCache_Enabled = 1,
} auth_cache_type_t;

typedef enum
{
    EV2_CommMode_PLAIN = 0x00,
    EV2_CommMode_MAC   = 0x01,
    EV2_CommMode_FULL  = 0x11,
    EV2_CommMode_NA    = 0x7FFFFFFF,
} nx_ev2_comm_mode_t;

typedef struct
{
    sss_object_t k_e1;
    sss_object_t k_m1;
    sss_object_t k_e2; // EV2 ENC
    sss_object_t k_m2; // EV2 MAC
    uint8_t iv_e1[13];
    sss_object_t kdfCmac; // AES 256 CMAC key used for session key generation

    uint16_t CmdCtr; //EV2 command counter
    uint32_t TI;     //EV2 Transaction Identifier

    /** Handle differnt types of auth.. Asymm / Symm */
    nx_auth_type_t authType;
    uint32_t seKeySize;
    nx_secure_symm_type_t selectedSecureTunnelType;
    auth_compress_type_t hostCompressType;
    auth_cache_type_t hostCacheType;
    sss_cipher_type_t hostEphemCurveType;
    uint16_t certACMap;
} nx_auth_sigma_dynamic_ctx_t;

typedef struct
{
    /** Key version no to use for chanel
        authentication in EV2 secure messaging     */
    uint8_t keyVerNo;
    /** Encryption key object */
    sss_object_t Enc;
    sss_object_t Mac; //!< static secure channel authentication key obj
    sss_object_t Dek; //!< data encryption key obj

    uint8_t seCertRepoId;                            // '00' - '07' certificate repository Id
    nx_secure_symm_type_t supportedSecureTunnelType; // AES 128/256 only or both.
    sss_cipher_type_t hostCertCurveType;
    sss_object_t leafCertKeypair;
    sss_object_t ephemKeypair;
    /** SE ephemeral public key */
    sss_object_t seEphemPubKey;
    /** SE public key in leaf certificate */
    sss_object_t seLeafCertPubKey;
    sss_status_t (*fp_find_hash_from_cache)(uint8_t *pCertHashBuf, size_t certHashBufLen, int *index);
    sss_status_t (*fp_get_pk_from_cache)(int index, uint8_t *pPublicKeyBuf, size_t *pPublicKeyBufLen);
    sss_status_t (*fp_insert_hash_pk_to_cache)(
        uint8_t *pCertHashBuf, size_t certHashBufLen, uint8_t *publicKey, size_t publicKeyLen);
    sss_status_t (*fp_get_parent_cert_from_cache)(int index, uint8_t *pCertBuf, size_t *pCertBufLen);
    sss_status_t (*fp_insert_parent_cert_to_cache)(uint8_t *pCertBuf, size_t certBufLen);
} nx_auth_sigma_static_ctx_t;

typedef struct
{
    uint8_t keyNo;                          // Application KeyID
    sss_object_t k_e2;                      // EV2 ENC
    sss_object_t k_m2;                      // EV2 MAC
    uint16_t CmdCtr;                        //EV2 command counter
    uint32_t TI;                            //EV2 Transaction Identifier
    uint8_t PDCap2[NX_PD_CAPABILITIES_LEN]; // PD capabilities
    /** Handle differnt types of auth.. */
    nx_auth_type_t authType;
    /** Handle differnt status of auth.. */
    nx_secure_symm_type_t selectedSecureTunnelType;
    nx_auth_satus_t authStatus;
} nx_auth_symm_dynamic_ctx_t;

typedef struct
{
    sss_object_t appKey; //!< SSS appl Enc Key object
    size_t appKeySize;
    uint8_t PCDCap2[NX_PCD_CAPABILITIES_LEN]; // PCD capabilities
    uint8_t PCDCap2Len;                       // PCD capabilities Length
} nx_auth_symm_static_ctx_t;

typedef struct
{
    nx_auth_sigma_static_ctx_t static_ctx; //!< .static keys data
    nx_auth_sigma_dynamic_ctx_t dyn_ctx;   //!<  session keys data
} nx_auth_sigma_ctx_t;

typedef struct
{
    nx_auth_symm_static_ctx_t static_ctx; //!< .static keys data
    nx_auth_symm_dynamic_ctx_t dyn_ctx;   //!<  session keys data
} nx_auth_symm_ctx_t;

/** Authentication context */
typedef struct _nx_auth_ctx_t
{
    /** How exactly we are going to authenticat ot the system.
     *
     * Since ``ctx`` is a union, this is needed to know exactly how
     * we are going to authenticate.
     */

    nx_auth_type_t authType;

    /** Depending on ``authType``, the input and output parameters.
     *
     * This has both input and output parameters.
     *
     * Input is for Keys that are used to initiate the connection.
     * While connecting, session keys/parameters are generated and they
     * are also part of this context.
     *
     * In any case, we connect to only one type
     */
    union {
        nx_auth_sigma_ctx_t sigmai;
        nx_auth_symm_ctx_t symmAuth;
    } ctx;
} nx_auth_ctx_t;

/** Connection context */
typedef struct
{
    /** to support binary compatibility/check, sizeOfStucture helps */
    uint16_t sizeOfStucture;

    /** If we need to authenticate, add required objects for authentication */
    nx_auth_ctx_t auth;

    /* =================================== */
    /* Implementation specific part starts */
    /* =================================== */

    /** How exactly are we going to connect physically */
    SSS_Conn_Type_t connType;

    /** Connection port name for Socket names, etc. */
    const char *portName;

    /** 12C address on embedded devices. */
    U32 i2cAddress;

    /*
     * When set to 0:
     *  Do not skip file selection and run as-is.
     *
     * When set to 1:
     *  Skip selection of file.
     *
     */
    uint8_t skip_select_file : 1;

    /**Connection data context */
    void *conn_ctx;

} nx_connect_ctx_t;

#endif /* NX_SECURE_MSG_TYPES_H_ */
