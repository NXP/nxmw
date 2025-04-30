/*
 * Copyright 2024-2025 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __SSS_PKCS11_PAL_H__
#define __SSS_PKCS11_PAL_H__

/* ********************** Include files ********************** */

#if defined(SSS_USE_FTR_FILE)
#include "fsl_sss_ftr.h"
#else
#include "fsl_sss_ftr_default.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(USE_RTOS) && USE_RTOS == 1 /* FreeRTOS includes. */
#include "FreeRTOS.h"
#include "semphr.h"
#include "task.h"
#endif

#include "sss_pkcs11_utils.h"
#include "nxEnsure.h"
#include "nxLog_msg.h"
#include "nx_apdu.h"
#include "fsl_sss_nx_apis.h"
#include "nx_const.h"
#include "nx_enums.h"
#include "nx_apdu_tlv.h"
#include "fsl_sss_util_asn1_der.h"
#include "ex_sss_ports.h"
#include "ex_sss_boot.h"

#if SSS_HAVE_HOSTCRYPTO_MBEDTLS
#include "fsl_sss_mbedtls_apis.h"
#endif
#if SSS_HAVE_HOSTCRYPTO_OPENSSL
#include "fsl_sss_openssl_apis.h"
#endif

#if defined(PKCS11_LIBRARY)
#if (__GNUC__ && defined(SSS_HAVE_HOST_EMBEDDED) && !(SSS_HAVE_HOST_EMBEDDED))
#include <errno.h>
#include <pthread.h>
#include <sys/types.h>
#include <unistd.h>
#endif //#if (__GNUC__ && !SSS_HAVE_HOST_EMBEDDED)
#endif //#if defined(PKCS11_LIBRARY)

/* ********************** Global variables ********************** */
extern ex_sss_boot_ctx_t *pex_sss_demo_boot_ctx;

/* ********************** Defines ********************** */
#define MAX_SYMM_KEY_ID (0x17)
#define MIN_SYMM_KEY_ID (0x10)
#define MAX_KEY_IDS 5
#define MAX_CERT_IDS 32
#define ASYMM_ID_MASK ((0x1) << 28)
#define CERT_ID_MASK ((0x2) << 28)
#define SYMM_ID_MASK ((0x4) << 28)
#define MAX_SYMM_IDS 8
#define RESERVE_FILE_IDS 3
#define AES_BLOCK_SIZE 16
#define OID_START_INDEX 2
#define MAX_ID_COUNT 1
#define MAX_KEY_ID_LENGTH 4
#define MAX_SIGN_RAW 64
#define PKCS11_TOKEN_LABEL                               \
    {                                                    \
        'S', 'S', 'S', '_', 'P', 'K', 'C', 'S', '1', '1' \
    }
#define PKCS11_MANUFACTURER \
    {                       \
        'N', 'X', 'P'       \
    }
#define PKCS11_LIBRARY_VERSION  \
    (CK_VERSION)                \
    {                           \
        .major = 4, .minor = 8, \
    }
#define CKA_SSS_ID CKA_VENDOR_DEFINED + CKA_OBJECT_ID
/**
 * @brief Definitions for parameter checking
 */
#define pkcs11CREATEOBJECT_MINIMUM_ATTRIBUTE_COUNT 2
/* Public key identifier for EC Keys */
#define ID_ECPUBLICKEY                           \
    {                                            \
        0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01 \
    }
#define pkcs11NO_OPERATION ((CK_MECHANISM_TYPE)0xFFFFFFFFF)
#define pkcs11INVALID_OBJECT_CLASS ((CK_OBJECT_CLASS)0x0FFFFFFF)
#define pkcs11INVALID_KEY_TYPE ((CK_KEY_TYPE)0x0FFFFFFF)

#define BEGIN_PUBLIC "-----BEGIN PUBLIC KEY-----\n"
#define END_PUBLIC "\n-----END PUBLIC KEY-----"

/* Path to store public key pem file */
#if (defined(SSS_HAVE_HOST_EMBEDDED) && !(SSS_HAVE_HOST_EMBEDDED))
#if defined(__linux__)
#define PUBLIC_KEY_PEM_FILE "scripts/keys/public_key.pem"
#define OS_PATH_SEPARATOR '/'
#else
#define PUBLIC_KEY_PEM_FILE "scripts\\keys\\public_key.pem"
#define OS_PATH_SEPARATOR '\\'
#endif
#endif //!SSS_HAVE_HOST_EMBEDDED

#define NX_VER_MAJOR (2u)
#define NX_VER_MINOR (0u)
#define CHECK_FOR_ASYMM_ID(id) ((uint32_t)(id & ASYMM_ID_MASK))
#define CHECK_FOR_CERT_ID(id) ((uint32_t)(id & CERT_ID_MASK))
#define CHECK_FOR_SYMM_ID(id) ((uint32_t)(id & SYMM_ID_MASK))
/*
 * Top level OID tuples
 */
#define MBEDTLS_OID_ISO_MEMBER_BODIES "\x2a" /* {iso(1) member-body(2)} */

/*
 * ISO Member bodies OID parts
 */
#define MBEDTLS_OID_COUNTRY_US "\x86\x48"     /* {us(840)} */
#define MBEDTLS_OID_ORG_ANSI_X9_62 "\xce\x3d" /* ansi-X9-62(10045) */
#define MBEDTLS_OID_ANSI_X9_62 MBEDTLS_OID_ISO_MEMBER_BODIES MBEDTLS_OID_COUNTRY_US MBEDTLS_OID_ORG_ANSI_X9_62

/*
 * ECParameters namedCurve identifiers, from RFC 5480, RFC 5639, and SEC2
 */

/* secp256r1 OBJECT IDENTIFIER ::= {
 *   iso(1) member-body(2) us(840) ansi-X9-62(10045) curves(3) prime(1) 7 } */
#define MBEDTLS_OID_EC_GRP_SECP256R1 MBEDTLS_OID_ANSI_X9_62 "\x03\x01\x07"

/* brainpoolP256r1 */
#define OID_EC_GRP_BP256R1 "\x2B\x24\x03\x03\x02\x08\x01\x01\x07"

/* ********************** structure definition *************** */

/**
 * @brief Session structure.
 */
typedef struct P11Session
{
    CK_ULONG ulState;
    CK_BBOOL xOpened;
    CK_MECHANISM_TYPE xOperationInProgress;
    CK_BBOOL digestUpdateCalled;
    CK_OBJECT_HANDLE xOperationKeyHandle;
    CK_BBOOL xFindObjectInit;
    CK_OBJECT_CLASS xFindObjectClass;
    uint32_t xFindObjectTotalFound;
    uint16_t xFindObjectOutputOffset;
    CK_KEY_TYPE xFindObjectKeyType;
    CK_BBOOL labelPresent;
    CK_BBOOL keyIdPresent;
    CK_BBOOL CheckCertId;
    CK_BBOOL CheckSymmId;
    char keyId[MAX_KEY_ID_LENGTH];
    char label[32];
    size_t labelLen;
    void *mechParameter;
    CK_ULONG mechParameterLen;
    sss_digest_t digest_ctx;
    CK_FLAGS xFlags;
    sss_mac_t ctx_hmac;
} P11Session_t, *P11SessionPtr_t;

/* ********************** FUnction declarations ********************** */

CK_RV pkcs11_parse_sign_mechanism(P11SessionPtr_t pxSession, sss_algorithm_t *algorithm);
CK_RV pkcs11_parse_encryption_mechanism(P11SessionPtr_t pxSession, sss_algorithm_t *algorithm);
CK_RV pkcs11_parse_digest_mechanism(P11SessionPtr_t pxSession, sss_algorithm_t *algorithm);
CK_RV pkcs11_get_attribute_parameter_index(
    CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_ATTRIBUTE_TYPE type, CK_ULONG_PTR index);
CK_RV pkcs11_get_digest_algorithm(const sss_algorithm_t algorithm, sss_algorithm_t *digest_algo);
CK_RV pkcs11_setASNTLV(uint8_t tag, uint8_t *component, const size_t componentLen, uint8_t *key, size_t *keyLen);
CK_RV pkcs11_ecSignatureToRandS(uint8_t *signature, size_t *sigLen);
CK_RV pkcs11_ecRandSToSignature(uint8_t *rands, const size_t rands_len, uint8_t *output, size_t *outputLen);
CK_BBOOL pkcs11_is_X509_certificate(uint32_t xObject);
CK_RV pkcs11_label_to_keyId(unsigned char *label, size_t labelSize, uint32_t *keyId);
CK_RV pkcs11_parse_certificate_get_attribute(
    uint32_t xObject, CK_ATTRIBUTE_TYPE attributeType, uint8_t *pData, CK_ULONG *ulAttrLength);
smStatus_t pkcs11_read_key_id_list(uint32_t *idlist, size_t *idlistlen, CK_ULONG ulMaxObjectCount);
smStatus_t pkcs11_read_cert_id_list(uint32_t *certidlist, size_t *certidlistlen);
smStatus_t pkcs11_read_symm_id_list(uint32_t *symmidlist, size_t *symmidlistlen);
smStatus_t cert_file_exists(CK_OBJECT_HANDLE xObject, uint32_t *keyId);
smStatus_t pkcs11_get_cert_file(CK_OBJECT_HANDLE xObject, uint8_t *cert, size_t *certLen);
smStatus_t pkcs11_get_validated_cert_id(CK_OBJECT_HANDLE xObject, uint8_t *keyId);
sss_status_t pkcs11_get_validated_object_id(P11SessionPtr_t pxSession, CK_OBJECT_HANDLE xObject, uint8_t *keyId);
sss_status_t pkcs11_get_validated_sss_object(
    P11SessionPtr_t pxSession, CK_OBJECT_HANDLE xObject, sss_object_t *pSSSObject);
sss_status_t pkcs11_get_validated_sss_symm_object(
    P11SessionPtr_t pxSession, CK_OBJECT_HANDLE xObject, sss_object_t *pSSSObject);
sss_status_t pkcs11_get_validated_symm_object_id(P11SessionPtr_t pxSession, CK_OBJECT_HANDLE xObject, uint8_t *keyId);
CK_RV pkcs11_is_valid_keytype(sss_algorithm_t algorithm, sss_cipher_type_t *cipher, sss_object_t *pSSSObject);
P11SessionPtr_t prvSessionPointerFromHandle(CK_SESSION_HANDLE xSession);
int pkcs11GetPubKeyDer(unsigned char *pubkey, size_t *publen);
int get_file_path(char *pubKeyFilePath, const char *fileName, size_t fileNameLen);

CK_RV pkcs11_nx_symmetric_encrypt(P11SessionPtr_t pxSessionObj,
    sss_algorithm_t algorithm,
    CK_BYTE_PTR pData,
    CK_ULONG ulDataLen,
    CK_BYTE_PTR pEncryptedData,
    CK_ULONG_PTR pulEncryptedDataLen);
CK_RV pkcs11_nx_symmetric_decrypt(P11SessionPtr_t pxSessionObj,
    sss_algorithm_t algorithm,
    CK_BYTE_PTR pData,
    CK_ULONG ulDataLen,
    CK_BYTE_PTR pEncryptedData,
    CK_ULONG_PTR pulEncryptedDataLen);
CK_RV pkcs11_check_key_id(
    sss_key_store_t *keystore, sss_object_t *sss_object, sss_cipher_type_t CipherType, uint32_t keyId);
sss_status_t pkcs11_sss_create_token_asymm(sss_key_store_t *keystore,
    sss_object_t *CreateObject,
    U32 ObjectId,
    sss_key_part_t KeyPart,
    sss_cipher_type_t CipherType,
    U8 *buffer,
    U32 bufferLen,
    U32 bitLen);
sss_status_t pkcs11_sss_create_token_cert(U32 ObjectId, U8 *buffer, U32 bufferLen);
sss_status_t pkcs11_sss_create_token_symm(sss_key_store_t *keystore,
    sss_object_t *CreateObject,
    U32 ObjectId,
    sss_key_part_t KeyPart,
    sss_cipher_type_t CipherType,
    U8 *buffer,
    U32 bufferLen,
    U32 bitLen);
sss_status_t pkcs11_sss_create_token_hmac(sss_key_store_t *keystore,
    sss_object_t *CreateObject,
    U32 ObjectId,
    sss_key_part_t KeyPart,
    sss_cipher_type_t CipherType,
    U8 *buffer,
    U32 bufferLen,
    U32 bitLen);

CK_RV pkcs11_ecPublickeyGetEcParams(uint8_t *input, size_t *dataLen);
CK_RV pkcs11_get_ec_info(uint8_t *params, size_t *KeyBitLen, sss_cipher_type_t *cipher);

/* Mutex handling function */
int sss_pkcs11_mutex_init(void);
int sss_pkcs11_mutex_lock(void);
int sss_pkcs11_mutex_unlock(void);
int sss_pkcs11_mutex_destroy(void);

#endif // __SSS_PKCS11_PAL_H__
