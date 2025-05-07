/*
 *
 * Copyright 2022-2024 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 */

/* ************************************************************************** */
/* Includes                                                                   */
/* ************************************************************************** */

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "ex_sss_boot.h"
#include "fsl_sss_nx_apis.h"
#include "fsl_sss_nx_auth_types.h"
#include "fsl_sss_nx_auth_keys.h"
#include "nxEnsure.h"
#include "nxLog_msg.h"
#include "nx_Personalization.h"
#include "fsl_sss_util_asn1_der.h"
#include "nx_apdu.h"
#if SSS_HAVE_HOSTCRYPTO_MBEDTLS
#include "mbedtls/asn1write.h"
#include "mbedtls/x509_crt.h"
#elif SSS_HAVE_HOSTCRYPTO_OPENSSL
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#endif

/* ************************************************************************** */
/* Local Defines                                                              */
/* ************************************************************************** */
#define EX_DEVICE_LEAF_CERT "device_leaf_certificate.der"
#define EX_DEVICE_P1_CERT "device_p1_certificate.der"
#define EX_DEVICE_P2_CERT "device_p2_certificate.der"
#define EX_DEVICE_LEAF_KEY "device_leaf_keypair.der"
#define EX_HOST_ROOT_CERT "host_root_certificate.der"
#define EX_HOST_LEAF_CERT "host_leaf_certificate.der"
#define EX_HOST_LEAF_CERT_MAPPING "host_leaf_cert_mapping.bin"
#define EX_HOST_P1_CERT_MAPPING "host_p1_cert_mapping.bin"
#define EX_HOST_P2_CERT_MAPPING "host_p2_cert_mapping.bin"
#define EX_HOST_LEAF_CERT_TEMPLATE "host_leaf_cert_template.der"
#define EX_HOST_P1_CERT_TEMPLATE "host_p1_cert_template.der"
#define EX_HOST_P2_CERT_TEMPLATE "host_p2_cert_template.der"

#define EX_DEVICE_CERT_REPO_ID SSS_AUTH_ASYMM_CERT_REPO_ID
#define EX_DEVICE_LEAF_CERT_KEYPAIR_ID SSS_AUTH_ASYMM_CERT_SK_ID
#define EX_HOST_ROOT_CERT_PUBKEY_ID SSS_AUTH_ASYMM_CA_ROOT_KEY_ID
#define EX_HOST_CA_ROOT_KEY_ACCESS_RIGHT                                                           \
    ((1 << Nx_AC_Bitmap_13_Shift) | (1 << Nx_AC_Bitmap_12_Shift) | (1 << Nx_AC_Bitmap_11_Shift) |  \
        (1 << Nx_AC_Bitmap_10_Shift) | (1 << Nx_AC_Bitmap_9_Shift) | (1 << Nx_AC_Bitmap_8_Shift) | \
        (1 << Nx_AC_Bitmap_7_Shift) | (1 << Nx_AC_Bitmap_6_Shift) | (1 << Nx_AC_Bitmap_5_Shift) |  \
        (1 << Nx_AC_Bitmap_4_Shift) | (1 << Nx_AC_Bitmap_3_Shift) | (1 << Nx_AC_Bitmap_2_Shift) |  \
        (1 << Nx_AC_Bitmap_1_Shift) | (1 << Nx_AC_Bitmap_0_Shift))

#define EX_DEVICE_CERT_REPO_SIZE 0xC00

/* ************************************************************************** */
/* Structures and Typedefs                                                    */
/* ************************************************************************** */

/* ************************************************************************** */
/* Global Variables                                                           */
/* ************************************************************************** */
static ex_sss_boot_ctx_t g_nx_provison_boot_ctx;

/* ************************************************************************** */
/* Function declarations                                               */
/* ************************************************************************** */

#ifdef EX_SSS_SIGMA_I_CERT_INCLUDE_DIR
sss_status_t nx_provision_read_file_from_fs(char *fileName, uint8_t *buffer, size_t *bufferLen);
sss_status_t nx_provision_full_file_name(char *dirName, char *fileName, Nx_ECCurve_t curveType, char *fullPathFileName);
bool nx_provision_dir_exists(const char *pathname);
#endif

sss_status_t nx_provision_get_default_host_cert(
    NX_CERTIFICATE_LEVEL_t level, Nx_ECCurve_t curveType, uint8_t *buffer, size_t *bufferLen);
sss_status_t nx_provision_get_default_se_leaf_keypair(Nx_ECCurve_t curveType, uint8_t *buffer, size_t *bufferLen);
sss_status_t nx_provision_get_default_se_cert(
    NX_CERTIFICATE_LEVEL_t level, Nx_ECCurve_t curveType, uint8_t *buffer, size_t *bufferLen);
sss_status_t nx_provision_get_default_host_cert_mapping(
    NX_CERTIFICATE_LEVEL_t level, uint8_t *buffer, size_t *bufferLen);

#if SSS_HAVE_NX_TYPE
int nx_perso_util_asn1_get_ec_pair_key_index(const uint8_t *input,
    size_t inLen,
    uint8_t *pubkeyIndex,
    size_t *publicKeyLen,
    uint8_t *prvkeyIndex,
    size_t *privateKeyLen);
sss_status_t sss_nx_provision_load_host_root_CA_pubkey(ex_sss_boot_ctx_t *pCtx,
    Nx_ECCurve_t curveType,
    uint8_t hostRootPubKeyId,
    uint16_t accessRight,
    uint8_t *certBuf,
    size_t certLen,
    uint8_t *pkASN1TagList,
    size_t pkASN1TagListLen,
    uint8_t *subjectNameTagList,
    size_t subjectNameTagListLen);

sss_status_t sss_nx_provision_import_se_leaf_private_key(ex_sss_boot_ctx_t *pCtx,
    uint8_t seLeafCertKeyId,
    Nx_ECCurve_t seCertCurveType,
    uint8_t *seLeafPKBuf,
    size_t seLeafPKBufLen);
sss_status_t nx_provision_create_se_repository(
    ex_sss_boot_ctx_t *pCtx, uint8_t repoID, uint8_t privateKeyId, uint16_t repoSize);
sss_status_t nx_provision_load2se_uncompressed_cert(
    ex_sss_boot_ctx_t *pCtx, NX_CERTIFICATE_LEVEL_t certLevel, uint8_t repoID, uint8_t *certBuf, size_t certBufLen);
sss_status_t nx_provision_load2se_cert_mapping(ex_sss_boot_ctx_t *pCtx,
    uint8_t repoID,
    NX_CERTIFICATE_LEVEL_t certLevel,
    uint8_t *certMappingBuf,
    size_t certMappingBufLen);
sss_status_t nx_provision_activate_se_cert_repo(ex_sss_boot_ctx_t *pCtx, uint8_t repoID);

#endif // SSS_HAVE_NX_TYPE

#define EX_SSS_BOOT_PCONTEXT (&g_nx_provison_boot_ctx)
#define EX_SSS_BOOT_EXPOSE_ARGC_ARGV 1
#include <ex_sss_main_inc.h>

/* ************************************************************************** */
/* Functions                                                                  */
/* ************************************************************************** */

static sss_status_t nx_provision_get_cert_tlv_field(uint8_t *certBuf,
    size_t certBufLen,
    uint8_t *asn1TagList,
    size_t asn1TagListLen,
    uint8_t **dataBuf,
    size_t *dataBufLen)
{
    sss_status_t status = kStatus_SSS_Fail;
    size_t i            = 0;
    int ret             = -1;
    uint8_t fieldTag = 0, qualifierTag = 0;
    uint8_t *pCert = NULL, *certEnd = NULL, *pTag = NULL;
    size_t len = 0;

    if ((certBuf == NULL) || (asn1TagList == NULL) || (dataBuf == NULL) || (dataBufLen == NULL)) {
        goto exit;
    }

    pCert   = certBuf;
    len     = certBufLen;
    certEnd = pCert + len;

    for (i = 0; (((i + 1) < asn1TagListLen) && (i <= (SIZE_MAX - 2))); i = i + 2) {
        fieldTag     = asn1TagList[i];
        qualifierTag = asn1TagList[i + 1];

        pTag = pCert;

        if (fieldTag != 0x00) {
            if ((ret = sss_util_asn1_get_tag(&pCert, certEnd, &len, fieldTag)) != 0) {
                LOG_E("Parse certificate tag 0x%x error", fieldTag);
                goto exit;
            }
        }
        else {
            // 0x00 tag, in fact, is padding for BIT STRING.
            pCert++;
            len = 0;
        }

        if (qualifierTag == NX_Qualifier_Nested) {
            ;
        }
        else if (qualifierTag == NX_Qualifier_Follow) {
            pCert += len;
        }
        else if (qualifierTag == NX_Qualifier_End) {
            // pCert point to value field, len is the value field length.
            break;
        }
        else {
            LOG_E("Invalid Qualifier Tag 0x%x error", qualifierTag);
            goto exit;
        }
    }

    if (qualifierTag != NX_Qualifier_End) {
        LOG_E("No Qualifier End Tag found");
        goto exit;
    }

    // pTag is start of tag field
    *dataBuf = pTag;
    ENSURE_OR_GO_EXIT((UINT_MAX - (size_t)(pCert - pTag)) >= len);
    *dataBufLen = pCert - pTag + len;

    status = kStatus_SSS_Success;
exit:
    return status;
}

#if SSS_HAVE_HOSTCRYPTO_MBEDTLS

static int fake_parse_crt_ext_cb(void *p_ctx,
    mbedtls_x509_crt const *crt,
    mbedtls_x509_buf const *oid,
    int critical,
    const unsigned char *cp,
    const unsigned char *end)
{
    return 0;
}

static sss_status_t nx_provision_parse_certificate_type(uint8_t *certBuf, size_t certBufLen, bool *isPKCS7)
{
    sss_status_t status      = kStatus_SSS_Fail;
    mbedtls_x509_crt certObj = {0}, x509CertObj = {0};
    int result                = -1;
    uint8_t *x509CertBuf      = NULL;
    size_t x509CertBufLen     = 0;
    uint8_t x509ASN1TagList[] = EX_X509_CERT_INSIDE_PKCS7_ASN1_LIST; // X.509 inside PKCS#7
    size_t x509ASN1TagListLen = sizeof(x509ASN1TagList);

    ENSURE_OR_GO_EXIT(certBuf != NULL);
    ENSURE_OR_GO_EXIT(isPKCS7 != NULL);

    // Parse SE leaf cert. Decide PKCS7/X509 and version.
    mbedtls_x509_crt_init(&certObj);
    result = mbedtls_x509_crt_parse_der_with_ext_cb(
        &certObj, (const unsigned char *)certBuf, certBufLen, 0, fake_parse_crt_ext_cb, NULL);
    if (result != 0) {
        LOG_D("mbedtls parse certificates failed. It maybe PKCS#7 certificate", result);

        // Get X.509 from PKCS#7 certificate
        status = nx_provision_get_cert_tlv_field(
            certBuf, certBufLen, x509ASN1TagList, x509ASN1TagListLen, &x509CertBuf, &x509CertBufLen);
        if (status != kStatus_SSS_Success) {
            LOG_E("Decode certificate failed. It's neither PKCS#7 nor X.509 certificate");
            goto exit;
        }

        // Decode X.507 certificate
        mbedtls_x509_crt_init(&x509CertObj);
        result = mbedtls_x509_crt_parse_der_with_ext_cb(
            &x509CertObj, (const unsigned char *)x509CertBuf, x509CertBufLen, 0, fake_parse_crt_ext_cb, NULL);
        if (result != 0) {
            LOG_E("mbedtls parse certificates failed. It's neither PKCS#7 nor X.509 certificate");
            goto exit;
        }

        *isPKCS7 = true;
    }
    else {
        // X.509 Certificate.
        *isPKCS7 = false;
    }

    status = kStatus_SSS_Success;

exit:
    mbedtls_x509_crt_free(&certObj);
    mbedtls_x509_crt_free(&x509CertObj);
    return status;
}

#elif SSS_HAVE_HOSTCRYPTO_OPENSSL

static sss_status_t nx_provision_parse_certificate_type(uint8_t *certBuf, size_t certBufLen, bool *isPKCS7)
{
    sss_status_t status       = kStatus_SSS_Fail;
    uint8_t *x509CertBuf      = NULL;
    size_t x509CertBufLen     = 0;
    uint8_t x509ASN1TagList[] = EX_X509_CERT_INSIDE_PKCS7_ASN1_LIST; // X.509 inside PKCS#7
    size_t x509ASN1TagListLen = sizeof(x509ASN1TagList);
    int version               = -1;
    X509 *x509                = NULL;
    const uint8_t *certBufPtr = certBuf;

    ENSURE_OR_GO_EXIT(certBuf != NULL);
    ENSURE_OR_GO_EXIT(isPKCS7 != NULL);

    // Parse SE leaf cert. Decide PKCS7/X509 and version.

    ENSURE_OR_GO_EXIT(certBufLen <= LONG_MAX);
    x509 = d2i_X509(NULL, &certBufPtr, certBufLen);
    if (x509 == NULL) {
        LOG_D("openssl parse certificates failed. It maybe PKCS#7 certificate");

        // Get X.509 from PKCS#7 certificate
        status = nx_provision_get_cert_tlv_field(
            certBuf, certBufLen, x509ASN1TagList, x509ASN1TagListLen, &x509CertBuf, &x509CertBufLen);
        if (status != kStatus_SSS_Success) {
            LOG_E("Decode certificate failed. It's neither PKCS#7 nor X.509 certificate");
            goto exit;
        }

        const uint8_t *x509CertBufPtr = x509CertBuf;
        // Decode X.507 certificate
        ENSURE_OR_GO_EXIT(x509CertBufLen <= LONG_MAX);
        x509 = d2i_X509(NULL, &x509CertBufPtr, x509CertBufLen);
        if (x509 == NULL) {
            LOG_E("Openssl parse certificates failed");
            goto exit;
        }

        version = ((int)X509_get_version(x509)) + 1;

        *isPKCS7 = true;
    }
    else {
        version = ((int)X509_get_version(x509)) + 1;
        // X.509 Certificate.
        *isPKCS7 = false;
    }

    status = kStatus_SSS_Success;

exit:
    if (x509 != NULL) {
        X509_free(x509);
    }
    return status;
}
#endif

static sss_status_t nx_provision_get_host_cert(
    NX_CERTIFICATE_LEVEL_t level, Nx_ECCurve_t curveType, uint8_t *buffer, size_t *bufferLen)
{
    sss_status_t status = kStatus_SSS_Fail;
    size_t maxBuffLen   = 0;

#ifdef EX_SSS_SIGMA_I_CERT_INCLUDE_DIR
    char *rootCertName                                                         = EX_HOST_ROOT_CERT;
    char *leafCertName                                                         = EX_HOST_LEAF_CERT;
    char *fileName                                                             = NULL;
    char *cert_key_path_env                                                    = NULL;
    char fullPathFileName[EX_MAX_INCLUDE_DIR_LENGTH + EX_MAX_EXTRA_DIR_LENGTH] = {0};

    ENSURE_OR_GO_EXIT(buffer != NULL);
    ENSURE_OR_GO_EXIT(bufferLen != NULL);
    ENSURE_OR_GO_EXIT((level == NX_CERTIFICATE_LEVEL_ROOT) || (level == NX_CERTIFICATE_LEVEL_LEAF));
    maxBuffLen = *bufferLen;

    if (level == NX_CERTIFICATE_LEVEL_ROOT) {
        fileName = rootCertName;
    }
    else {
        fileName = leafCertName;
    }
#if defined(_MSC_VER)
    size_t sz = 0;
    _dupenv_s(&cert_key_path_env, &sz, EX_SSS_SIGMA_I_CERT_PATH_ENV_VAR);
#else
    cert_key_path_env = getenv(EX_SSS_SIGMA_I_CERT_PATH_ENV_VAR);
#endif //_MSC_VER

    if (cert_key_path_env != NULL) // Get file from Path indicated by ENV
    {
        LOG_I("Using certificate/key from:'%s' (ENV=%s)", cert_key_path_env, EX_SSS_SIGMA_I_CERT_PATH_ENV_VAR);

        status = nx_provision_full_file_name(cert_key_path_env, fileName, curveType, fullPathFileName);
        ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

        status = nx_provision_read_file_from_fs(fullPathFileName, buffer, &maxBuffLen);
#if defined(_MSC_VER)
        if (cert_key_path_env) {
            free(cert_key_path_env);
        }
#endif //_MSC_VER
    }
    else if (nx_provision_dir_exists(EX_SSS_SIGMA_I_CERT_INCLUDE_DIR) == true) // Get file from default path
    {
        LOG_I(
            "Using certificate/key from:'%s' (Default path). "
            "You can specify certificates/keys file using ENV=%s",
            EX_SSS_SIGMA_I_CERT_INCLUDE_DIR,
            EX_SSS_SIGMA_I_CERT_PATH_ENV_VAR);

        status = nx_provision_full_file_name(EX_SSS_SIGMA_I_CERT_INCLUDE_DIR, fileName, curveType, fullPathFileName);
        ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

        status = nx_provision_read_file_from_fs(fullPathFileName, buffer, &maxBuffLen);
    }
    else // Get default value.
    {
        LOG_I(
            "Using certificate/key from nxmw/demos/nx/nx_Personalization/nx_Personalization.h "
            "(cert_depth3_x509_rev1)");
        status = nx_provision_get_default_host_cert(level, curveType, buffer, &maxBuffLen);
    }
#else

    ENSURE_OR_GO_EXIT(buffer != NULL);
    ENSURE_OR_GO_EXIT(bufferLen != NULL);
    ENSURE_OR_GO_EXIT((level == NX_CERTIFICATE_LEVEL_ROOT) || (level == NX_CERTIFICATE_LEVEL_LEAF));

    maxBuffLen = *bufferLen;

    // Get default value.
    LOG_I(
        "Using certificate/key from nxmw/demos/nx/nx_Personalization/nx_Personalization.h"
        "(cert_depth3_x509_rev1)");
    status = nx_provision_get_default_host_cert(level, curveType, buffer, &maxBuffLen);
#endif

    *bufferLen = maxBuffLen;
exit:
    return status;
}

static sss_status_t nx_provision_get_se_cert(
    NX_CERTIFICATE_LEVEL_t level, Nx_ECCurve_t curveType, uint8_t *buffer, size_t *bufferLen)
{
    sss_status_t status = kStatus_SSS_Fail;
    size_t maxBuffLen   = 0;

#ifdef EX_SSS_SIGMA_I_CERT_INCLUDE_DIR
    char *leafCertName                                                         = EX_DEVICE_LEAF_CERT;
    char *p1CertName                                                           = EX_DEVICE_P1_CERT;
    char *p2CertName                                                           = EX_DEVICE_P2_CERT;
    char *fileName                                                             = NULL;
    char *cert_key_path_env                                                    = NULL;
    char fullPathFileName[EX_MAX_INCLUDE_DIR_LENGTH + EX_MAX_EXTRA_DIR_LENGTH] = {0};

    ENSURE_OR_GO_EXIT(buffer != NULL);
    ENSURE_OR_GO_EXIT(bufferLen != NULL);
    ENSURE_OR_GO_EXIT((level == NX_CERTIFICATE_LEVEL_LEAF) || (level == NX_CERTIFICATE_LEVEL_P1) ||
                      (level == NX_CERTIFICATE_LEVEL_P2));

    maxBuffLen = *bufferLen;

    if (level == NX_CERTIFICATE_LEVEL_LEAF) {
        fileName = leafCertName;
    }
    else if (level == NX_CERTIFICATE_LEVEL_P1) {
        fileName = p1CertName;
    }
    else {
        fileName = p2CertName;
    }

#if defined(_MSC_VER)
    size_t sz = 0;
    _dupenv_s(&cert_key_path_env, &sz, EX_SSS_SIGMA_I_CERT_PATH_ENV_VAR);
#else
    cert_key_path_env = getenv(EX_SSS_SIGMA_I_CERT_PATH_ENV_VAR);
#endif //_MSC_VER

    if (cert_key_path_env != NULL) {
        // Get file from Path indicated by ENV
        LOG_D("Using certificate/key from:'%s' (ENV=%s)", cert_key_path_env, EX_SSS_SIGMA_I_CERT_PATH_ENV_VAR);

        status = nx_provision_full_file_name(cert_key_path_env, fileName, curveType, fullPathFileName);
        ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

        status = nx_provision_read_file_from_fs(fullPathFileName, buffer, &maxBuffLen);
#if defined(_MSC_VER)
        if (cert_key_path_env) {
            free(cert_key_path_env);
        }
#endif //_MSC_VER
    }
    else if (nx_provision_dir_exists(EX_SSS_SIGMA_I_CERT_INCLUDE_DIR) == true) {
        LOG_D(
            "Using certificate/key from:'%s' (Default path). "
            "You can specify certificates/keys file using ENV=%s",
            EX_SSS_SIGMA_I_CERT_INCLUDE_DIR,
            EX_SSS_SIGMA_I_CERT_PATH_ENV_VAR);

        status = nx_provision_full_file_name(EX_SSS_SIGMA_I_CERT_INCLUDE_DIR, fileName, curveType, fullPathFileName);
        ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

        status = nx_provision_read_file_from_fs(fullPathFileName, buffer, &maxBuffLen);
    }
    else {
        // Get default value.
        LOG_D("Using default SE certificates");
        status = nx_provision_get_default_se_cert(level, curveType, buffer, &maxBuffLen);
    }
#else

    ENSURE_OR_GO_EXIT(buffer != NULL);
    ENSURE_OR_GO_EXIT(bufferLen != NULL);

    maxBuffLen = *bufferLen;

    // Get default value.
    LOG_D("Using default SE certificates");
    status = nx_provision_get_default_se_cert(level, curveType, buffer, &maxBuffLen);
#endif

    *bufferLen = maxBuffLen;
exit:
    return status;
}

static sss_status_t nx_provision_parse_keypair_get_private_key(
    uint8_t *keyPairBuf, size_t keyPairBufLen, uint8_t *privKeyBuf, size_t *privKeyBufLen)
{
    sss_status_t status = kStatus_SSS_Success;
    int ret             = -1;
    uint8_t publicIndex = 0, privateIndex = 0;
    size_t pubLen = 0, privLen = 0;

    ENSURE_OR_GO_EXIT(keyPairBuf != NULL);
    ENSURE_OR_GO_EXIT(privKeyBuf != NULL);
    ENSURE_OR_GO_EXIT(privKeyBufLen != NULL);

    ret = nx_perso_util_asn1_get_ec_pair_key_index(
        keyPairBuf, keyPairBufLen, &publicIndex, &pubLen, &privateIndex, &privLen);
    if (ret == 0) {
        if (privLen <= 0) {
            status = kStatus_SSS_Fail;
        }
        ENSURE_OR_GO_EXIT(privateIndex < keyPairBufLen);
        memcpy(&privKeyBuf[0], &keyPairBuf[privateIndex], privLen);
        *privKeyBufLen = privLen;
    }
    else {
        status = kStatus_SSS_Fail;
    }

exit:
    return status;
}

static sss_status_t nx_provision_get_se_leaf_keypair(Nx_ECCurve_t curveType, uint8_t *buffer, size_t *bufferLen)
{
    sss_status_t status = kStatus_SSS_Fail;
    size_t maxBuffLen   = 0;

#ifdef EX_SSS_SIGMA_I_CERT_INCLUDE_DIR
    char *fileName                                                             = EX_DEVICE_LEAF_KEY;
    char *cert_key_path_env                                                    = NULL;
    char fullPathFileName[EX_MAX_INCLUDE_DIR_LENGTH + EX_MAX_EXTRA_DIR_LENGTH] = {0};

    ENSURE_OR_GO_EXIT(buffer != NULL);
    ENSURE_OR_GO_EXIT(bufferLen != NULL);

    maxBuffLen = *bufferLen;
#if defined(_MSC_VER)
    size_t sz = 0;
    _dupenv_s(&cert_key_path_env, &sz, EX_SSS_SIGMA_I_CERT_PATH_ENV_VAR);
#else
    cert_key_path_env = getenv(EX_SSS_SIGMA_I_CERT_PATH_ENV_VAR);
#endif //_MSC_VER

    if (cert_key_path_env != NULL) {
        // Get file from Path indicated by ENV
        LOG_D("Using certificate/key from:'%s' (ENV=%s)", cert_key_path_env, EX_SSS_SIGMA_I_CERT_PATH_ENV_VAR);

        status = nx_provision_full_file_name(cert_key_path_env, fileName, curveType, fullPathFileName);
        ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

        status = nx_provision_read_file_from_fs(fullPathFileName, buffer, &maxBuffLen);
#if defined(_MSC_VER)
        if (cert_key_path_env) {
            free(cert_key_path_env);
        }
#endif //_MSC_VER
    }
    else if (nx_provision_dir_exists(EX_SSS_SIGMA_I_CERT_INCLUDE_DIR) == true) {
        LOG_D(
            "Using certificate/key from:'%s' (Default path). "
            "You can specify certificates/keys file using ENV=%s",
            EX_SSS_SIGMA_I_CERT_INCLUDE_DIR,
            EX_SSS_SIGMA_I_CERT_PATH_ENV_VAR);

        status = nx_provision_full_file_name(EX_SSS_SIGMA_I_CERT_INCLUDE_DIR, fileName, curveType, fullPathFileName);
        ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

        status = nx_provision_read_file_from_fs(fullPathFileName, buffer, &maxBuffLen);
    }
    else {
        // Get default value.
        LOG_D("Using certificate/key from nxmw/demos/nx/nx_Personalization/nx_Personalization.h");
        status = nx_provision_get_default_se_leaf_keypair(curveType, buffer, &maxBuffLen);
    }
#else

    ENSURE_OR_GO_EXIT(buffer != NULL);
    ENSURE_OR_GO_EXIT(bufferLen != NULL);

    maxBuffLen = *bufferLen;

    // Get default value.
    LOG_D("Using certificate/key from nxmw/demos/nx/nx_Personalization/nx_Personalization.h");
    status = nx_provision_get_default_se_leaf_keypair(curveType, buffer, &maxBuffLen);
#endif

    *bufferLen = maxBuffLen;
exit:
    return status;
}

static sss_status_t nx_provision_get_host_cert_mapping(
    NX_CERTIFICATE_LEVEL_t level, Nx_ECCurve_t curveType, uint8_t *buffer, size_t *bufferLen)
{
    sss_status_t status = kStatus_SSS_Fail;
    size_t maxBuffLen   = 0;

#ifdef EX_SSS_SIGMA_I_CERT_INCLUDE_DIR
    char *leafMappingName                                                      = EX_HOST_LEAF_CERT_MAPPING;
    char *p1MappingName                                                        = EX_HOST_P1_CERT_MAPPING;
    char *p2MappingName                                                        = EX_HOST_P2_CERT_MAPPING;
    char *fileName                                                             = NULL;
    char *cert_key_path_env                                                    = NULL;
    char fullPathFileName[EX_MAX_INCLUDE_DIR_LENGTH + EX_MAX_EXTRA_DIR_LENGTH] = {0};

    ENSURE_OR_GO_EXIT(buffer != NULL);
    ENSURE_OR_GO_EXIT(bufferLen != NULL);
    ENSURE_OR_GO_EXIT((level == NX_CERTIFICATE_LEVEL_LEAF) || (level == NX_CERTIFICATE_LEVEL_P1) ||
                      (level == NX_CERTIFICATE_LEVEL_P2));

    maxBuffLen = *bufferLen;

    if (level == NX_CERTIFICATE_LEVEL_LEAF) {
        fileName = leafMappingName;
    }
    else if (level == NX_CERTIFICATE_LEVEL_P1) {
        fileName = p1MappingName;
    }
    else {
        fileName = p2MappingName;
    }

#if defined(_MSC_VER)
    size_t sz = 0;
    _dupenv_s(&cert_key_path_env, &sz, EX_SSS_SIGMA_I_CERT_PATH_ENV_VAR);
#else
    cert_key_path_env = getenv(EX_SSS_SIGMA_I_CERT_PATH_ENV_VAR);
#endif //_MSC_VER

    if (cert_key_path_env != NULL) {
        // Get file from Path indicated by ENV
        LOG_D("Using certificate/key from:'%s' (ENV=%s)", cert_key_path_env, EX_SSS_SIGMA_I_CERT_PATH_ENV_VAR);

        status = nx_provision_full_file_name(cert_key_path_env, fileName, curveType, fullPathFileName);
        ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

        status = nx_provision_read_file_from_fs(fullPathFileName, buffer, &maxBuffLen);
#if defined(_MSC_VER)
        if (cert_key_path_env) {
            free(cert_key_path_env);
        }
#endif //_MSC_VER
    }
    else if (nx_provision_dir_exists(EX_SSS_SIGMA_I_CERT_INCLUDE_DIR) == true) {
        LOG_D(
            "Using certificate/key from:'%s' (Default path). "
            "You can specify certificates/keys file using ENV=%s",
            EX_SSS_SIGMA_I_CERT_INCLUDE_DIR,
            EX_SSS_SIGMA_I_CERT_PATH_ENV_VAR);

        status = nx_provision_full_file_name(EX_SSS_SIGMA_I_CERT_INCLUDE_DIR, fileName, curveType, fullPathFileName);
        ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

        status = nx_provision_read_file_from_fs(fullPathFileName, buffer, &maxBuffLen);
    }
    else {
        // Get default value.
        LOG_D("Using default host mapping");
        status = nx_provision_get_default_host_cert_mapping(level, buffer, &maxBuffLen);
    }
#else

    ENSURE_OR_GO_EXIT(buffer != NULL);
    ENSURE_OR_GO_EXIT(bufferLen != NULL);

    maxBuffLen = *bufferLen;

    // Get default value.
    LOG_D("Using default host mapping");
    status = nx_provision_get_default_host_cert_mapping(level, buffer, &maxBuffLen);
#endif

    *bufferLen = maxBuffLen;
exit:
    return status;
}

static sss_status_t nx_provision_load_se_cert_mapping(ex_sss_boot_ctx_t *pCtx, Nx_ECCurve_t certCurveType)
{
    sss_status_t status              = kStatus_SSS_Fail;
    uint8_t repoID                   = EX_DEVICE_CERT_REPO_ID;
    NX_CERTIFICATE_LEVEL_t certLevel = NX_CERTIFICATE_LEVEL_LEAF;
    uint8_t certMappingBuf[1024]     = {0};
    size_t certMappingBufLen         = sizeof(certMappingBuf);

    ENSURE_OR_GO_EXIT(pCtx != NULL);

    for (certLevel = NX_CERTIFICATE_LEVEL_LEAF; certLevel <= NX_CERTIFICATE_LEVEL_P2; certLevel++) {
        memset(certMappingBuf, 0, sizeof(certMappingBuf));
        certMappingBufLen = sizeof(certMappingBuf);

        status = nx_provision_get_host_cert_mapping(certLevel, certCurveType, certMappingBuf, &certMappingBufLen);
        if ((status == kStatus_SSS_Success) && (certMappingBufLen != 0)) {
            status = nx_provision_load2se_cert_mapping(pCtx, repoID, certLevel, certMappingBuf, certMappingBufLen);
            if (status != kStatus_SSS_Success) {
                goto exit;
            }
        }
        else {
            LOG_I("Mapping data at level %d is not available. Skip it", certLevel);
        }
    }

    status = kStatus_SSS_Success;
exit:
    return status;
}

/****************************** Load function *******************************/

static sss_status_t nx_load_host_root_CA_pubkey(ex_sss_boot_ctx_t *pCtx, Nx_ECCurve_t curveType, uint16_t acBitmap)
{
    sss_status_t status   = kStatus_SSS_Fail;
    uint8_t certBuf[1024] = {0};
    size_t certLen        = sizeof(certBuf);
    bool isPKCS7          = false;

    uint8_t *subjectNameTagList       = NULL;
    size_t subjectNameTagListLen      = 0;
    uint8_t subjectNamePKCS7TagList[] = EX_ROOT_CERT_SUBJECT_NAME_PKCS7_ASN1_LIST;
    size_t subjectNamePKCS7TagListLen = sizeof(subjectNamePKCS7TagList);
    uint8_t subjectNameX509TagList[]  = EX_ROOT_CERT_SUBJECT_NAME_X509_ASN1_LIST;
    size_t subjectNameX509TagListLen  = sizeof(subjectNameX509TagList);

    uint8_t *pkASN1TagList   = NULL;
    size_t pkASN1TagListLen  = 0;
    uint8_t pkPKCS7TagList[] = EX_ROOT_CERT_PUBKEY_PKCS7_ASN1_LIST;
    size_t pkPKCS7TagListLen = sizeof(pkPKCS7TagList);
    uint8_t pkX509TagList[]  = EX_ROOT_CERT_PUBKEY_X509_ASN1_LIST;
    size_t pkX509TagListLen  = sizeof(pkX509TagList);

    ENSURE_OR_GO_EXIT(pCtx != NULL);

    status = nx_provision_get_host_cert(NX_CERTIFICATE_LEVEL_ROOT, curveType, certBuf, &certLen);
    if (status != kStatus_SSS_Success) {
        LOG_W("host_root_certificates is not found. Use leaf certificate which is assumed to be self signed");
        status = nx_provision_get_host_cert(NX_CERTIFICATE_LEVEL_LEAF, curveType, certBuf, &certLen);
        ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);
    }

    status = nx_provision_parse_certificate_type(certBuf, certLen, &isPKCS7);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    if (isPKCS7 == true) {
        // X.509 Certificate wrapped in PKCS#7.
        subjectNameTagList    = subjectNamePKCS7TagList;
        subjectNameTagListLen = subjectNamePKCS7TagListLen;

        pkASN1TagList    = pkPKCS7TagList;
        pkASN1TagListLen = pkPKCS7TagListLen;
    }
    else {
        // X.509 Certificate.
        subjectNameTagList    = subjectNameX509TagList;
        subjectNameTagListLen = subjectNameX509TagListLen;

        pkASN1TagList    = pkX509TagList;
        pkASN1TagListLen = pkX509TagListLen;
    }

    status = sss_nx_provision_load_host_root_CA_pubkey(pCtx,
        curveType,
        EX_HOST_ROOT_CERT_PUBKEY_ID,
        acBitmap,
        certBuf,
        certLen,
        pkASN1TagList,
        pkASN1TagListLen,
        subjectNameTagList,
        subjectNameTagListLen);

    if (status != kStatus_SSS_Success) {
        goto exit;
    }

    status = kStatus_SSS_Success;
exit:
    return status;
}

static sss_status_t nx_load_se_leaf_keypair_and_cert(ex_sss_boot_ctx_t *pCtx, Nx_ECCurve_t seCertCurveType)
{
    sss_status_t status          = kStatus_SSS_Fail;
    uint8_t seLeafKeyBuf[256]    = {0};
    size_t seLeafKeyBufLen       = sizeof(seLeafKeyBuf);
    uint8_t seLeafPrviKeyBuf[32] = {0};
    size_t seLeafPrviKeyBufLen   = sizeof(seLeafPrviKeyBuf);
    uint8_t certBuf[1024]        = {0};
    size_t certBufLen            = sizeof(certBuf);

    // Load SE leaf cert.
    status = nx_provision_get_se_cert(NX_CERTIFICATE_LEVEL_LEAF, seCertCurveType, certBuf, &certBufLen);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    status = nx_provision_get_se_leaf_keypair(seCertCurveType, seLeafKeyBuf, &seLeafKeyBufLen);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    status = nx_provision_parse_keypair_get_private_key(
        seLeafKeyBuf, seLeafKeyBufLen, seLeafPrviKeyBuf, &seLeafPrviKeyBufLen);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    status = sss_nx_provision_import_se_leaf_private_key(
        pCtx, EX_DEVICE_LEAF_CERT_KEYPAIR_ID, seCertCurveType, seLeafPrviKeyBuf, seLeafPrviKeyBufLen);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    // Create device repository
    status = nx_provision_create_se_repository(
        pCtx, EX_DEVICE_CERT_REPO_ID, EX_DEVICE_LEAF_CERT_KEYPAIR_ID, EX_DEVICE_CERT_REPO_SIZE);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    status = nx_provision_load_se_cert_mapping(pCtx, seCertCurveType);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    // Load device leaf uncompressed certificate
    status = nx_provision_load2se_uncompressed_cert(
        pCtx, NX_CERTIFICATE_LEVEL_LEAF, EX_DEVICE_CERT_REPO_ID, certBuf, certBufLen);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

exit:
    return status;
}

static sss_status_t nx_load_se_uncompressed_cert(
    ex_sss_boot_ctx_t *pCtx, NX_CERTIFICATE_LEVEL_t certLevel, uint8_t repoID, Nx_ECCurve_t seCertCurveType)
{
    sss_status_t status        = kStatus_SSS_Fail;
    smStatus_t sm_status       = SM_NOT_OK;
    int tlvRet                 = 0;
    sss_nx_session_t *pSession = NULL;
    uint8_t taggedCert[1024]   = {0};
    size_t taggedCertLen       = 0;
    uint8_t *pCert             = NULL;
    uint8_t certBuf[1024]      = {0};
    size_t certBufLen          = sizeof(certBuf);

    ENSURE_OR_GO_EXIT(pCtx != NULL);
    pSession = (sss_nx_session_t *)&pCtx->session;

    status = nx_provision_get_se_cert(certLevel, seCertCurveType, certBuf, &certBufLen);
    if ((status == kStatus_SSS_Success) && (certBufLen != 0)) {
        // 7F 21 <uncompressed cert>
        taggedCertLen = 0;
        taggedCert[0] = 0x7F;
        pCert         = &taggedCert[1];
        tlvRet        = TLVSET_u8buf(
            "cert", &pCert, &taggedCertLen, NX_TAG_UNCOMPRESSED_CERT, certBuf, certBufLen, sizeof(taggedCert) - 1);
        if (0 != tlvRet) {
            goto exit;
        }

        if (taggedCertLen > (UINT16_MAX - 1)) {
            goto exit;
        }

        sm_status = nx_ManageCertRepo_LoadCert(
            &pSession->s_ctx, repoID, certLevel, taggedCert, (uint16_t)(taggedCertLen + 1), Nx_CommMode_NA);
        if (sm_status != SM_OK) {
            LOG_E("Load certificate Failed");
            goto exit;
        }
    }
    else {
        LOG_W("P%d Certificate doesn't exist. Skip it.", certLevel);
    }

    status = kStatus_SSS_Success;
exit:
    return status;
}

static sss_status_t nx_activate_se_cert_repo(ex_sss_boot_ctx_t *pCtx, uint8_t repoID)
{
    sss_status_t status        = kStatus_SSS_Fail;
    sss_nx_session_t *pSession = NULL;
    smStatus_t sm_status       = SM_NOT_OK;

    ENSURE_OR_GO_EXIT(NULL != pCtx)
    pSession = (sss_nx_session_t *)&pCtx->session;

    sm_status = nx_ManageCertRepo_ActivateRepo(&pSession->s_ctx, repoID, Nx_CommMode_NA);
    if (sm_status != SM_OK) {
        LOG_E("Activate repository Failed");
        goto exit;
    }

    status = kStatus_SSS_Success;

exit:

    return status;
}

sss_status_t ex_sss_entry(ex_sss_boot_ctx_t *pCtx)
{
    sss_status_t status = kStatus_SSS_Fail;

    int argc          = gex_sss_argc;
    const char **argv = gex_sss_argv;

    int parameter_error    = 1;
    Nx_ECCurve_t curveType = Nx_ECCurve_NA; // BP-256 or NIST-P 256
    uint16_t acBitmap      = EX_HOST_CA_ROOT_KEY_ACCESS_RIGHT;
    long int inputBitmap   = 0x3FFF; /* Default value */
    int tmp_argc           = argc;

    if (argc <= 2) {
        /* Set default values */
#if (SSS_HAVE_AUTH_ASYMM_HOST_CURVE_NIST_P)
        curveType = Nx_ECCurve_NIST_P256;
#elif (SSS_HAVE_AUTH_ASYMM_HOST_CURVE_BRAINPOOL)
        curveType = Nx_ECCurve_Brainpool256;
#endif
        parameter_error = 0;
    }
    else if (argc == 4 || argc == 6) {
        parameter_error = 0;
        do {
            if (strcmp(argv[tmp_argc - 3], "-c") == 0) {
                if (strcmp(argv[tmp_argc - 2], "bp") == 0) {
                    LOG_I("Brainpool 256");
                    curveType = Nx_ECCurve_Brainpool256;
                }
                else if (strcmp(argv[tmp_argc - 2], "nistp") == 0) {
                    LOG_I("NIST-P 256");
                    curveType = Nx_ECCurve_NIST_P256;
                }
                else {
                    parameter_error = 1;
                    break;
                }
            }
            else if (strcmp(argv[tmp_argc - 3], "-m") == 0) {
                inputBitmap = strtol(argv[tmp_argc - 2], NULL, 16);
                if ((inputBitmap >= 0) && (inputBitmap <= NX_AC_BITMAP_MAX)) {
                    LOG_I("AC Bitmap is 0x%x", inputBitmap);
                    acBitmap = (uint16_t)inputBitmap;
                }
                else {
                    parameter_error = 1;
                    break;
                }
            }
            else {
                parameter_error = 1;
                break;
            }
            tmp_argc = tmp_argc - 2;
        } while (tmp_argc >= 4);
    }
    else {
        parameter_error = 1;
    }

    if (1 == parameter_error) {
        printf("\nUSAGE:\n");
        printf("  %s -c {bp|nistp} -m [AC bitmap] <port_name>\n", gex_sss_argv[0]);
        printf("  Default is Nist 256, Bitmap 0x3FFF\n");
        printf("  Example: %s -c bp -m 0x3FFF \"COM5\"\n", gex_sss_argv[0]);
        goto exit;
    }

    LOG_I("Nx provision start \n");

#ifdef EX_SSS_SIGMA_I_CERT_INCLUDE_DIR
    LOG_I("******************************* NOTE ********************************************");
    LOG_I("Default top level certificate directory is: %s", EX_SSS_SIGMA_I_CERT_INCLUDE_DIR);
    LOG_I("To override this directory path, you need to set env variable as follows:");
    LOG_I("NX_AUTH_CERT_DIR=..\\nxmw\\binaries\\configuration\\cert_depth3_x509_rev1");
    LOG_I("********************************************************************************* \n");
#endif

    // Load host root CA public key
    status = nx_load_host_root_CA_pubkey(pCtx, curveType, acBitmap);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    // Load leaf key pair and certificate
    status = nx_load_se_leaf_keypair_and_cert(pCtx, curveType);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    // Load SE P1 certificate
    status = nx_load_se_uncompressed_cert(pCtx, NX_CERTIFICATE_LEVEL_P1, EX_DEVICE_CERT_REPO_ID, curveType);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    // Load SE P2 certificate
    status = nx_load_se_uncompressed_cert(pCtx, NX_CERTIFICATE_LEVEL_P2, EX_DEVICE_CERT_REPO_ID, curveType);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    // Activate the certificate repository so it is ready for use
    status = nx_activate_se_cert_repo(pCtx, EX_DEVICE_CERT_REPO_ID);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

exit:
    if (kStatus_SSS_Success == status) {
        LOG_I("nx_Personalization Example Success !!!...");
    }
    else {
        LOG_E("nx_Personalization Example Failed !!!...");
    }
    return status;
}
