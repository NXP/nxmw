/*
*
* Copyright 2024 NXP
* SPDX-License-Identifier: BSD-3-Clause
*/

#ifndef FSL_SSS_NX_AUTH_TYPES_H
#define FSL_SSS_NX_AUTH_TYPES_H

#ifdef __cplusplus
extern "C" {
#endif

#include "nx_secure_msg_const.h"
#include "nx_apdu_tlv.h"
#if SSS_HAVE_HOSTCRYPTO_MBEDTLS
#include "fsl_sss_mbedtls_apis.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/asn1write.h"
#endif
#if SSS_HAVE_HOSTCRYPTO_OPENSSL
#include "fsl_sss_openssl_apis.h"
#endif
#include "fsl_sss_nx_auth_keys.h"

#define NX_AES256_CCM_TAG_LENGH 8
#define NX_SIGNATURE_ASN1_BYTE_LEN 72
#define NX_EC_PRIVATE_KEY_BYTE_LEN 32
#define NX_MAX_CERT_CONTAINER_NUM 50
#define NX_AUTH_SYMM_APP_KEY_ID SSS_HAVE_AUTH_SYMM_APP_KEY_ID
#define NX_KEY_BIT_LENGTH 256
#define NX_SYMM_AUTH_SESSION_VECTOR_LEN 32
#define NX_SYMM_AUTH_SV_PART1_LEN 6
#define NX_SYMM_AUTH_RNDA15_14_BUF_LEN 2
#define NX_SYMM_AUTH_RNDA13_8_BUF_LEN 6
#define NX_SYMM_AUTH_RNDA7_0_BUF_LEN 8
#define NX_SYMM_AUTH_RNDB15_10_BUF_LEN 6
#define NX_SYMM_AUTH_RNDB9_0_BUF_LEN 10
#define NX_SYMM_AUTH_XOR_RESULT_BUF_LEN 6
#define NX_SYMM_AUTH_RNDA_DASH_RESP_OFFSET 4
#define NX_SYMM_AUTH_PDCAP2_RESP_OFFSET 20
#define NX_SYMM_AUTH_PCDCAP2_RESP_OFFSET 26
#define NX_SYMM_AUTH_MACDATA_BUF_SIZE 16
#define NX_SYMM_AUTH_DATATOMAC_BUF_SIZE 32
#define NX_SYMM_AUTH_EV2_FIRST_PART1_RESP_LEN 16
#define NX_SYMM_AUTH_EV2_FIRST_PART2_RESP_LEN 32
#define NX_SYMM_AUTH_RANDOM_LEN 16
#define NX_SYMM_AUTH_AES128_KEY_SIZE 16
#define NX_SYMM_AUTH_AES256_KEY_SIZE 32
#define NX_AUTH_EV2FIRST_DECRYPT_BUF_SIZE 32
#define NX_AUTH_EV2FIRST_ENCRYPT_BUF_SIZE 32
#define NX_AUTH_EV2FIRST_PLAINRSP_SIZE 32
#define NX_SYMM_AUTH_EV2_NON_FIRST_RESP_LEN 16
#define NX_SYMM_AUTH_INITIAL_VECTOR_SIZE 16

#define NX_SYMM_AUTH_INITIAL_VECTOR                                                                    \
    {                                                                                                  \
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 \
    }

#define NX_SYMM_AUTH_SV1_PART              \
    {                                      \
        0xA5, 0x5A, 0x00, 0x01, 0x00, 0x80 \
    }
#define NX_SYMM_AUTH_SV2_PART              \
    {                                      \
        0x5A, 0xA5, 0x00, 0x01, 0x00, 0x80 \
    }
#define NX_SYMM_AUTH_SV1A_PART1            \
    {                                      \
        0xA5, 0x5A, 0x00, 0x01, 0x01, 0x00 \
    }
#define NX_SYMM_AUTH_SV1B_PART1            \
    {                                      \
        0xA5, 0x5A, 0x00, 0x02, 0x01, 0x00 \
    }
#define NX_SYMM_AUTH_SV2A_PART1            \
    {                                      \
        0x5A, 0xA5, 0x00, 0x01, 0x01, 0x00 \
    }
#define NX_SYMM_AUTH_SV2B_PART1            \
    {                                      \
        0x5A, 0xA5, 0x00, 0x02, 0x01, 0x00 \
    }

#define EX_MAX_INCLUDE_DIR_LENGTH 150
#define EX_MAX_EXTRA_DIR_PART1_LENGTH 50
#define EX_MAX_EXTRA_FILE_NAME_LENGTH 60
#define EX_MAX_EXTRA_DIR_LENGTH (EX_MAX_EXTRA_DIR_PART1_LENGTH + EX_MAX_EXTRA_FILE_NAME_LENGTH)
#define UNSECURE_LOGGING_OF_APP_KEYS 0

/** Cert level */
typedef enum
{
    /** Invalid */
    NX_CERT_LEVEL_NA = 0,
    /** Leaf certificate */
    NX_CERT_LEVEL_LEAF = 0x1,
    /** P1 certificate */
    NX_CERT_LEVEL_P1 = 0x2,
    /** P2 certificate */
    NX_CERT_LEVEL_P2 = 0x3,
} nx_cert_level_t;

/** CA Cert level */
typedef enum
{
    /** Invalid */
    NX_CA_CERT_LEVEL_NA = 0,
    /** Root certificate */
    NX_CA_CERT_LEVEL_ROOT = 0x1,
    /** Level 0 = P1 certificate */
    NX_CA_CERT_LEVEL_0 = 0x2,
    /** Level 1 = P2 certificate */
    NX_CA_CERT_LEVEL_1 = 0x3,
} nx_ca_cert_level_t;

/** Cert request tag */
typedef enum
{
    /** Invalid */
    NX_CERT_REQ_TAG_NA = 0,
    /** Leaf certificate */
    NX_CERT_REQ_TAG_LEAF = 0x80,
    /** P1 certificate */
    NX_CERT_REQ_TAG_P1 = 0x81,
    /** P2 certificate */
    NX_CERT_REQ_TAG_P2 = 0x82,
} nx_cert_req_tag_t;

typedef enum
{
    /** The next ASN tag is nested inside the current one */
    NX_Qualifier_Nested = 0x81,
    /** The next ASN tag follows the current one */
    NX_Qualifier_Follow = 0x82,
    /** End of list */
    NX_Qualifier_End = 0x83,
} nx_qualifier_tag_t;

typedef struct
{
    auth_compress_type_t compressType;
    auth_cache_type_t cacheType;
    sss_cipher_type_t hostEphemCurveType;
    sss_cipher_type_t hostCertCurveType;
    uint8_t seCertRepoID; // Device leaf cert repository id
    uint16_t certACMap;   // Certificate AC map already known.
} sigma_i_parameter_t;

typedef struct
{
    uint8_t keyNo;
    size_t appKeySize;
    uint8_t appKey[NX_SYMM_AUTH_APPKEY_MAX_SIZE];
    uint8_t PCDCap2[NX_PCD_CAPABILITIES_LEN]; // PD capabilities
    uint8_t PCDCap2Len;
} symm_auth_parameter_t;

typedef enum
{
    kCertDir,
    kCertCacheDir,
} nx_auth_dir_type_t;

#if SSS_HAVE_HOSTCRYPTO_ANY
typedef struct
{
#if SSS_HAVE_HOSTCRYPTO_MBEDTLS
    mbedtls_x509_crt deviceLeafCert;
    mbedtls_x509_crt deviceCACertList[NX_MAX_CERT_DEPTH]; // Root CA, P1, P2
    int deviceCACertListNum;
#elif SSS_HAVE_HOSTCRYPTO_OPENSSL
    X509_STORE *rootCAStore;
    X509_STORE_CTX *storeCtx;
    STACK_OF(X509) * caCertStack;
    X509 *deviceCACertList[NX_MAX_CERT_DEPTH]; // Root CA, P1, P2
    int deviceCACertListNum;
    X509 *deviceCert[NX_MAX_CERT_DEPTH];
#endif
} nx_device_cert_ctx_host_t;
#endif //#if SSS_HAVE_HOSTCRYPTO_ANY

typedef enum
{
    kDeviceCert,
    kDeviceCACert,
} nx_auth_cert_type_t;

#ifdef __cplusplus
} /* extern "c"*/
#endif

#endif /* FSL_SSS_NX_AUTH_H */
