/*
 *
 * Copyright 2023-2024 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "ex_sss_boot.h"
#include "fsl_sss_nx_apis.h"
#include "nxLog_msg.h"
#include "nx_apdu.h"
#include "nx_const.h"
#include "nx_apdu_tlv.h"
#include "fsl_sss_util_asn1_der.h"
#include "nxEnsure.h"
#include "fsl_sss_nx_auth_types.h"
#include "ex_sss_originality_check.h"

#if SSS_HAVE_HOSTCRYPTO_MBEDTLS
#include "mbedtls/x509_crt.h"
#include "mbedtls/asn1write.h"
#endif
#if SSS_HAVE_HOSTCRYPTO_OPENSSL
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#endif

static ex_sss_boot_ctx_t gex_sss_boot_ctx = {0};

#define EX_SSS_BOOT_PCONTEXT (&gex_sss_boot_ctx)
#define EX_SSS_BOOT_EXPOSE_ARGC_ARGV 0

#include <ex_sss_main_inc.h>

#define EX_SSS_ORG_CHECK_OPTA_A_DATA                                                                                \
    {                                                                                                               \
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,                     \
    }
#define EX_SSS_ORG_CHECK_OPTA_A_DATA_LEN 32

#define EX_SSS_ORG_CHECK_KEY_ID 1
#define EX_SSS_ORG_CHECK_STANDARD_FILE_NUM 1
#define EX_SSS_ORG_CHECK_RANDOM_LENGTH 16
#define EX_SSS_ORG_CHECK_BUFFER_LENGTH 100

#ifndef MAKE_TEST_ID
#define MAKE_TEST_ID(ID) (0xEF000000u + ID)
#endif /* MAKE_TEST_ID */

#if SSS_HAVE_HOSTCRYPTO_MBEDTLS
static int ex_parse_crt_ext_cb(void *p_ctx,
    mbedtls_x509_crt const *crt,
    mbedtls_x509_buf const *oid,
    int critical,
    const unsigned char *cp,
    const unsigned char *end);
static sss_status_t ex_parse_x509_cert_mbedtls(mbedtls_x509_crt *cert, unsigned char *certBuf, size_t certBufLen);
sss_status_t ex_get_public_key_mbedtls(
    mbedtls_x509_crt *cert, uint8_t *pubKey, size_t *pubKeyLen, sss_cipher_type_t *cipherType);
#elif SSS_HAVE_HOSTCRYPTO_OPENSSL
static sss_status_t ex_parse_x509_cert_openssl(X509 **cert, unsigned char *certBuf, size_t certBufLen);
sss_status_t ex_get_public_key_openssl(X509 *cert, uint8_t *pubKey, size_t *pubKeyLen, sss_cipher_type_t *cipherType);
#endif

static sss_status_t ex_orginality_check_parse_cert(
    uint8_t *data, size_t dataLen, uint8_t *pubKey, size_t *pubKeyLen, sss_cipher_type_t *cipherType);
static sss_status_t ex_orginality_check_get_random(uint8_t *pBuf, size_t bufLen);
static sss_status_t ex_orginality_check_util_encode_asn1_signature(
    uint8_t *signatureAsn1, size_t *signatureLenAsn1, uint8_t *rawSignature, size_t rawSignatureLen);
static sss_status_t ex_orginality_check_get_cert_tlv_field(uint8_t *certBuf,
    size_t certBufLen,
    uint8_t *asn1TagList,
    size_t asn1TagListLen,
    uint8_t **dataBuf,
    size_t *dataBufLen);
static sss_status_t ex_orginality_check_verify_cert(ex_sss_boot_ctx_t *pCtx, uint8_t *data, size_t dataLen);

#if SSS_HAVE_HOSTCRYPTO_MBEDTLS
static int ex_parse_crt_ext_cb(void *p_ctx,
    mbedtls_x509_crt const *crt,
    mbedtls_x509_buf const *oid,
    int critical,
    const unsigned char *cp,
    const unsigned char *end)
{
    return 0;
}

/**
 * @brief         Parse certificate and get x509 object.
 *
 *                Parse certificate and get x509 object from it.
 *
 * @param[out]        cert                  mbedTLS Cert container.
 * @param[in]         certBuf               Cert buffer.
 * @param[in]         certBufLen            Cert buffer length.
 *
 * @return        Status of searching.
 */
static sss_status_t ex_parse_x509_cert_mbedtls(mbedtls_x509_crt *cert, unsigned char *certBuf, size_t certBufLen)
{
    int ret             = -1;
    sss_status_t status = kStatus_SSS_Fail;

    if ((cert == NULL) || (certBuf == NULL)) {
        LOG_E("No certificates");
        goto exit;
    }

    // Parse X.509 certificate.
    ret = mbedtls_x509_crt_parse_der_with_ext_cb(
        cert, (const unsigned char *)certBuf, certBufLen, 0, ex_parse_crt_ext_cb, NULL);
    if (ret != 0) {
        LOG_E("mbedtls parse certificates failed %d", ret);
        goto exit;
    }

    status = kStatus_SSS_Success;

exit:
    return status;
}

/**
 * @brief         Parse Certificate and get public key.
 *
 *                Parse certificate. Get public key and its curves type.
 *
 * @param[in]         cert                  Certificate object.
 * @param[out]        pubKey                Public key.
 * @param[out]        pubKeyLen             Public key length.
 * @param[out]        cipherType            Public key cipher type.
 *
 * @return        Status of searching.
 */
sss_status_t ex_get_public_key_mbedtls(
    mbedtls_x509_crt *cert, uint8_t *pubKey, size_t *pubKeyLen, sss_cipher_type_t *cipherType)
{
    uint8_t *p = NULL, *end = NULL;
    size_t len                    = 0;
    int ret                       = -1;
    sss_status_t status           = kStatus_SSS_Fail;
    uint8_t ecPublicKey_oid[]     = {0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01}; // ecPublicKey 1.2.840.10045.2.1
    uint8_t brainpoolP256r1_oid[] = {
        0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07};                   // brainpoolP256r1 1.3.36.3.3.2.8.1.1.7
    uint8_t prime256v1_oid[] = {0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07}; // prime256v1 1.2.840.10045.3.1.7

    if ((cert == NULL) || (pubKey == NULL) || (pubKeyLen == NULL) || (cipherType == NULL)) {
        LOG_E("Input parameters are invalid");
        goto exit;
    }

    p   = cert->pk_raw.p;
    len = cert->pk_raw.len;
    end = p + len;

    // SEQ
    if ((ret = sss_util_asn1_get_tag(&p, end, &len, SSS_UTIL_ASN1_CONSTRUCTED | SSS_UTIL_ASN1_SEQUENCE)) != 0) {
        LOG_E("Public key 1st SEQ error");
        goto exit;
    }

    // SEQ
    if ((ret = sss_util_asn1_get_tag(&p, end, &len, SSS_UTIL_ASN1_CONSTRUCTED | SSS_UTIL_ASN1_SEQUENCE)) != 0) {
        LOG_E("Public key 2nd SEQ error");
        goto exit;
    }

    // Obj ID: public key
    if ((ret = sss_util_asn1_get_tag(&p, end, &len, SSS_UTIL_ASN1_OID)) != 0) {
        LOG_E("Public key obj id error");
        goto exit;
    }

    if ((len != sizeof(ecPublicKey_oid)) || (memcmp(p, &ecPublicKey_oid[0], len) != 0)) {
        LOG_E("PKCS7 CERT obj id is not 1.2.840.113549.1.7.2(signedData)");
        goto exit;
    }

    // Obj ID: curves
    p = p + len;
    if ((ret = sss_util_asn1_get_tag(&p, end, &len, SSS_UTIL_ASN1_OID)) != 0) {
        LOG_E("Public key obj id error");
        goto exit;
    }

    if ((len == sizeof(brainpoolP256r1_oid)) && (memcmp(p, &brainpoolP256r1_oid[0], len) == 0)) {
        // Brain pool 256 Curves.
        *cipherType = kSSS_CipherType_EC_BRAINPOOL;
    }
    else if ((len == sizeof(prime256v1_oid)) && (memcmp(p, &prime256v1_oid[0], len) == 0)) {
        // NIST-P 256 Curves
        *cipherType = kSSS_CipherType_EC_NIST_P;
    }
    else {
        LOG_E("Invalid Cipher Type.");
        goto exit;
    }

    if ((cert->pk_raw.len) <= *pubKeyLen) {
        memcpy(pubKey, cert->pk_raw.p, (cert->pk_raw.len));
        *pubKeyLen = (cert->pk_raw.len);
    }
    else {
        LOG_E("Not enough space for public key.");
        goto exit;
    }

    status = kStatus_SSS_Success;

exit:
    return status;
}

#elif SSS_HAVE_HOSTCRYPTO_OPENSSL

/**
 * @brief         Parse certificate and get x509 object.
 *
 *                Parse certificate and get x509 object from it.
 *
 * @param[out]        cert                  OpenSSL Cert container.
 * @param[in]         certBuf               Cert buffer.
 * @param[in]         certBufLen            Cert buffer length.
 *
 * @return        Status of searching.
 */
static sss_status_t ex_parse_x509_cert_openssl(X509 **cert, unsigned char *certBuf, size_t certBufLen)
{
    sss_status_t status             = kStatus_SSS_Fail;
    X509 *x509                      = NULL;
    const unsigned char *certBufPtr = certBuf;

    if ((cert == NULL) || (certBuf == NULL)) {
        LOG_E("No certificates");
        goto exit;
    }

    if (certBufLen > INT_MAX) {
        LOG_E("Invalid certificate length");
        goto exit;
    }

    x509 = d2i_X509(NULL, &certBufPtr, (int)certBufLen);

    // Parse X.509 certificate.
    if (x509 == NULL) {
        LOG_E("Openssl parse certificates failed");
        goto exit;
    }

    *cert = x509;

    status = kStatus_SSS_Success;

exit:
    return status;
}

/**
 * @brief         Parse Certificate and get public key.
 *
 *                Parse certificate. Get public key and its curves type.
 *
 * @param[in]         cert                  Certificate object.
 * @param[out]        pubKey                Public key.
 * @param[out]        pubKeyLen             Public key length.
 * @param[out]        cipherType            Public key cipher type.
 *
 * @return        Status of searching.
 */
sss_status_t ex_get_public_key_openssl(X509 *cert, uint8_t *pubKey, size_t *pubKeyLen, sss_cipher_type_t *cipherType)
{
    uint8_t *p = NULL, *end = NULL;
    size_t len                    = 0;
    int ret                       = -1;
    sss_status_t status           = kStatus_SSS_Fail;
    uint8_t ecPublicKey_oid[]     = {0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01}; // ecPublicKey 1.2.840.10045.2.1
    uint8_t brainpoolP256r1_oid[] = {
        0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07};                   // brainpoolP256r1 1.3.36.3.3.2.8.1.1.7
    uint8_t prime256v1_oid[] = {0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07}; // prime256v1 1.2.840.10045.3.1.7
    uint8_t *key_buffer      = NULL;
    EVP_PKEY *pkey           = NULL;
    int key_buffer_len       = 0;

    if ((cert == NULL) || (pubKey == NULL) || (pubKeyLen == NULL) || (cipherType == NULL)) {
        LOG_E("Input parameters are invalid");
        goto exit;
    }

    // Get EVP_PKEY from certifictate
    pkey = X509_get_pubkey(cert);
    if (pkey == NULL) {
        LOG_E("EVP_PKEY is NULL");
        goto exit;
    }

    // Get public key from EVP_PKEY
    key_buffer_len = i2d_PUBKEY(pkey, &key_buffer);
    if (key_buffer_len <= 0) {
        LOG_E("key_buffer_len <= 0");
        goto exit;
    }

    p   = key_buffer;
    len = key_buffer_len;
    end = p + len;

    // SEQ
    if ((ret = sss_util_asn1_get_tag(&p, end, &len, SSS_UTIL_ASN1_CONSTRUCTED | SSS_UTIL_ASN1_SEQUENCE)) != 0) {
        LOG_E("Public key 1st SEQ error");
        goto exit;
    }

    // SEQ
    if ((ret = sss_util_asn1_get_tag(&p, end, &len, SSS_UTIL_ASN1_CONSTRUCTED | SSS_UTIL_ASN1_SEQUENCE)) != 0) {
        LOG_E("Public key 2nd SEQ error");
        goto exit;
    }

    // Obj ID: public key
    if ((ret = sss_util_asn1_get_tag(&p, end, &len, SSS_UTIL_ASN1_OID)) != 0) {
        LOG_E("Public key obj id error");
        goto exit;
    }

    if ((len != sizeof(ecPublicKey_oid)) || (memcmp(p, &ecPublicKey_oid[0], len) != 0)) {
        LOG_E("PKCS7 CERT obj id is not 1.2.840.113549.1.7.2(signedData)");
        goto exit;
    }

    // Obj ID: curves
    p = p + len;
    if ((ret = sss_util_asn1_get_tag(&p, end, &len, SSS_UTIL_ASN1_OID)) != 0) {
        LOG_E("Public key obj id error");
        goto exit;
    }

    if ((len == sizeof(brainpoolP256r1_oid)) && (memcmp(p, &brainpoolP256r1_oid[0], len) == 0)) {
        // Brain pool 256 Curves.
        *cipherType = kSSS_CipherType_EC_BRAINPOOL;
    }
    else if ((len == sizeof(prime256v1_oid)) && (memcmp(p, &prime256v1_oid[0], len) == 0)) {
        // NIST-P 256 Curves
        *cipherType = kSSS_CipherType_EC_NIST_P;
    }
    else {
        LOG_E("Invalid Cipher Type.");
        goto exit;
    }

    if ((size_t)key_buffer_len <= *pubKeyLen) {
        memcpy(pubKey, key_buffer, key_buffer_len);
        *pubKeyLen = key_buffer_len;
    }
    else {
        LOG_E("Not enough space for public key.");
        goto exit;
    }

    status = kStatus_SSS_Success;
exit:
    if (pkey != NULL) {
        EVP_PKEY_free(pkey);
    }
    if (key_buffer != NULL) {
        OPENSSL_free(key_buffer);
    }
    return status;
}
#endif

static sss_status_t ex_orginality_check_parse_cert(
    uint8_t *data, size_t dataLen, uint8_t *pubKey, size_t *pubKeyLen, sss_cipher_type_t *cipherType)
{
    sss_status_t status = kStatus_SSS_Fail;
    uint32_t len        = 0;
    uint8_t *pCert      = NULL;
    size_t certLen      = 0;

#if SSS_HAVE_HOSTCRYPTO_MBEDTLS
    mbedtls_x509_crt deviceLeafCert = {0};
#elif SSS_HAVE_HOSTCRYPTO_OPENSSL
    X509 *deviceCert = NULL;
#endif

    ENSURE_OR_GO_EXIT(NULL != data)

#if (SSS_HAVE_SA_TYPE_A30 || SSS_HAVE_SA_TYPE_NTAG_X_DNA || SSS_HAVE_SA_TYPE_OTHER)
    pCert   = data;
    certLen = len = ((data[2] << 8) | (data[3] << 0)) + EX_CERT_TAG_LENGTH;
#else
    pCert            = data + 3;
    certLen = len = (data[2] << 16) | (data[1] << 8) | (data[0] << 0);
#endif

#if SSS_HAVE_HOSTCRYPTO_MBEDTLS
    mbedtls_x509_crt_init(&deviceLeafCert);

    // Parse leaf certificate and add it to container.
    status = ex_parse_x509_cert_mbedtls(&deviceLeafCert, pCert, certLen);
    if (status != kStatus_SSS_Success) {
        LOG_E("ex_parse_x509_cert_mbedtls failed");
        goto exit;
    }

    status = ex_get_public_key_mbedtls(&deviceLeafCert, pubKey, pubKeyLen, cipherType);
    if (status != kStatus_SSS_Success) {
        LOG_E("ex_get_public_key_mbedtls failed");
        goto exit;
    }

    mbedtls_x509_crt_free(&deviceLeafCert);
#elif SSS_HAVE_HOSTCRYPTO_OPENSSL
    // Parse leaf certificate and add it to container.
    status = ex_parse_x509_cert_openssl(&deviceCert, pCert, certLen);
    if (status != kStatus_SSS_Success) {
        LOG_E("ex_parse_x509_cert_openssl failed");
        goto exit;
    }

    status = ex_get_public_key_openssl(deviceCert, pubKey, pubKeyLen, cipherType);
    if (status != kStatus_SSS_Success) {
        LOG_E("ex_get_public_key_openssl failed");
        goto exit;
    }

    if (deviceCert != NULL) {
        X509_free(deviceCert);
    }
#endif

    status = kStatus_SSS_Success;

exit:
    return status;
}

static sss_status_t ex_orginality_check_get_random(uint8_t *pBuf, size_t bufLen)
{
    sss_status_t sss_status       = kStatus_SSS_Fail;
    sss_rng_context_t sss_rng_ctx = {0};

    ENSURE_OR_GO_EXIT(pBuf != NULL);

    sss_status = sss_rng_context_init(&sss_rng_ctx, &(gex_sss_boot_ctx.host_session));
    ENSURE_OR_GO_EXIT(sss_status == kStatus_SSS_Success);

    sss_status = sss_rng_get_random(&sss_rng_ctx, pBuf, bufLen);

exit:
    if (sss_rng_ctx.session != NULL) {
        sss_rng_context_free(&sss_rng_ctx);
    }
    return sss_status;
}

/* Encode ASN.1 Signature */
static sss_status_t ex_orginality_check_util_encode_asn1_signature(
    uint8_t *signatureAsn1, size_t *signatureLenAsn1, uint8_t *rawSignature, size_t rawSignatureLen)
{
    sss_status_t status = kStatus_SSS_Fail;
    size_t offset       = 0;

    if ((signatureAsn1 == NULL) || (signatureLenAsn1 == NULL) || (rawSignature == NULL) ||
        (rawSignatureLen != NX_RAW_SIGNATURE_LENGTH)) {
        goto exit;
    }

    /* ASN! format - 0x30|Rem len|0x02|r_len|r|0x02|s_len|s */

    signatureAsn1[0] = 0x30;
    signatureAsn1[1] = (uint8_t)(rawSignatureLen + 2 /* Tag + len */ + 2 /* Tag + len */);

    /* Update R value*/
    signatureAsn1[2] = 0x02;
    signatureAsn1[3] = (uint8_t)32;
    if ((rawSignature[0] & 0x80) == 0x80) /* Check for first byte of R */
    {
        signatureAsn1[1]++;
        signatureAsn1[3]++;
        signatureAsn1[4] = 0x00;
        memcpy(&signatureAsn1[5], &rawSignature[0], 32);
        offset = 5 + 32;
    }
    else {
        memcpy(&signatureAsn1[4], &rawSignature[0], 32);
        offset = 4 + 32;
    }

    *signatureLenAsn1 = offset;

    /* Update S value*/
    signatureAsn1[offset + 0] = 0x02;
    signatureAsn1[offset + 1] = (uint8_t)32;
    if ((rawSignature[32] & 0x80) == 0x80) /* Check for first byte of S */
    {
        signatureAsn1[1]++;
        if (signatureAsn1[offset + 1] > (UINT8_MAX - 1)) {
            goto exit;
        }
        signatureAsn1[offset + 1]++;
        signatureAsn1[offset + 2] = 0x00;
        memcpy(&signatureAsn1[offset + 3], &rawSignature[32], 32);
        *signatureLenAsn1 += 3 + 32;
    }
    else {
        memcpy(&signatureAsn1[offset + 2], &rawSignature[32], 32);
        *signatureLenAsn1 += 2 + 32;
    }

    status = kStatus_SSS_Success;
exit:
    return status;
}

/**
 * @brief         Get value offset indicated by the ASN.1 tag list
 *
 *                This API parses ASN.1 tag list item and get the whole TLV.
 *
 * @param[in]         certBuf           Current certificate buffer
 * @param[in]         certBufLen        Current certificate buffer length.
 * @param[in]         asn1TagList       ASN.1 tag list
 * @param[in]         asn1TagListLen    ASN.1 tag list length.
 * @param[out]        dataBuf           ASN.1 field data buffer.
 * @param[out]        dataBufLen        ASN.1 field data buffer length.
 *
 * @return        Status
 */
static sss_status_t ex_orginality_check_get_cert_tlv_field(uint8_t *certBuf,
    size_t certBufLen,
    uint8_t *asn1TagList,
    size_t asn1TagListLen,
    uint8_t **dataBuf,
    size_t *dataBufLen)
{
    sss_status_t status = kStatus_SSS_Fail;
    size_t i            = 0;
    int ret             = 0;
    uint8_t fieldTag = 0, qualifierTag = 0;
    uint8_t *pCert = NULL, *certEnd = NULL, *pTag = NULL;
    size_t len = 0;

    if ((certBuf == NULL) || (asn1TagList == NULL) || (dataBuf == NULL) || (dataBufLen == NULL)) {
        goto exit;
    }

    pCert   = certBuf;
    len     = certBufLen;
    certEnd = pCert + len;

    ENSURE_OR_GO_EXIT(asn1TagListLen <= (UINT_MAX - 1));
    for (i = 0; (i + 1) < asn1TagListLen; i = i + 2) {
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

static sss_status_t ex_orginality_check_verify_cert(ex_sss_boot_ctx_t *pCtx, uint8_t *data, size_t dataLen)
{
    sss_status_t status = kStatus_SSS_Fail;

    sss_object_t public_key_object     = {0};
    sss_cipher_type_t cipher_type      = kSSS_CipherType_EC_NIST_P;
    uint8_t certBodyX509TagList[]      = EX_CERT_BODY_X509_ASN1_LIST;
    size_t certBodyX509TagListLen      = sizeof(certBodyX509TagList);
    uint8_t certSignatureX509TagList[] = EX_CERT_SIGNATURE_X509_ASN1_LIST;
    size_t certSignatureX509TagListLen = sizeof(certSignatureX509TagList);
    uint8_t *certBody                  = NULL;
    size_t certBodyLen                 = 0;
    uint8_t *sigBuf                    = NULL;
    size_t sigBufLen                   = 0;
    uint8_t origCAPubKey[]             = EX_ORIG_CA_PUBLIC_KEY;
    size_t origCAPubKeyLen             = sizeof(origCAPubKey);
    uint8_t *origCert                  = NULL;
    size_t origCertLen                 = 0;

    sss_digest_t md       = {0};
    uint8_t digest[32]    = {0};
    size_t digestLen      = sizeof(digest);
    sss_asymmetric_t asym = {0};

    ENSURE_OR_GO_EXIT((pCtx != NULL) && (data != NULL));

#if (SSS_HAVE_SA_TYPE_A30 || SSS_HAVE_SA_TYPE_NTAG_X_DNA || SSS_HAVE_SA_TYPE_OTHER)
    origCert    = data;
    origCertLen = ((data[2] << 8) | (data[3] << 0)) + EX_CERT_TAG_LENGTH;
#else
    origCert    = data + 3;
    origCertLen = (data[2] << 16) | (data[1] << 8) | (data[0] << 0);
#endif
    ENSURE_OR_GO_EXIT(origCertLen <= dataLen);

    // Init Public Key.
    status = sss_key_object_init(&public_key_object, &(pCtx->host_ks));
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    status = sss_key_object_allocate_handle(&public_key_object,
        MAKE_TEST_ID(__LINE__),
        kSSS_KeyPart_Public,
        cipher_type,
        256 / 8,
        kKeyObject_Mode_Transient);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    status = sss_key_store_set_key(
        &(pCtx->host_ks), &public_key_object, (const uint8_t *)origCAPubKey, origCAPubKeyLen, 256, NULL, 0);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    // Get certificate body
    status = ex_orginality_check_get_cert_tlv_field(
        origCert, origCertLen, certBodyX509TagList, certBodyX509TagListLen, &certBody, &certBodyLen);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    // sha256(leaf cert body)
    status = sss_digest_context_init(&md, &pCtx->host_session, kAlgorithm_SSS_SHA256, kMode_SSS_Digest);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    status = sss_digest_one_go(&md, (const uint8_t *)certBody, certBodyLen, digest, &digestLen);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    if (md.session != NULL) {
        sss_digest_context_free(&md);
    }

    // Get signature from certificate.
    status = ex_orginality_check_get_cert_tlv_field(
        origCert, origCertLen, certSignatureX509TagList, certSignatureX509TagListLen, &sigBuf, &sigBufLen);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    // ECDSA sign (sha256 leaf cert body)
    status = sss_asymmetric_context_init(
        &asym, &pCtx->host_session, &public_key_object, kAlgorithm_SSS_SHA256, kMode_SSS_Verify);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    status = sss_asymmetric_verify_digest(&asym, digest, digestLen, sigBuf, sigBufLen);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    status = kStatus_SSS_Success;

exit:
    if (md.session != NULL) {
        sss_digest_context_free(&md);
    }
    if (asym.session != NULL) {
        sss_asymmetric_context_free(&asym);
    }
    if (public_key_object.keyStore != NULL) {
        sss_key_object_free(&public_key_object);
    }
    return status;
}

sss_status_t ex_sss_entry(ex_sss_boot_ctx_t *pCtx)
{
    sss_status_t status  = kStatus_SSS_Fail;
    smStatus_t sm_status = SM_NOT_OK;

    sss_nx_session_t *pSession                            = NULL;
    uint8_t fileNo                                        = EX_SSS_ORG_CHECK_STANDARD_FILE_NUM;
    size_t offset                                         = 0x0;
    uint8_t data[500]                                     = {0};
    size_t dataLen                                        = sizeof(data);
    uint8_t pubkey[128]                                   = {0};
    size_t pubkeyLen                                      = sizeof(pubkey);
    sss_cipher_type_t pubKeyCipherType                    = kSSS_CipherType_NONE;
    uint8_t optsA[]                                       = EX_SSS_ORG_CHECK_OPTA_A_DATA;
    size_t optsALen                                       = sizeof(optsA);
    uint8_t rndA[EX_SSS_ORG_CHECK_RANDOM_LENGTH]          = {0};
    size_t rndALen                                        = sizeof(rndA);
    uint8_t rndB[EX_SSS_ORG_CHECK_BUFFER_LENGTH]          = {0};
    size_t rndBLen                                        = sizeof(rndB);
    uint8_t sigB[EX_SSS_ORG_CHECK_BUFFER_LENGTH]          = {0};
    size_t sigBLen                                        = sizeof(sigB);
    uint8_t asn1Signature[EX_SSS_ORG_CHECK_BUFFER_LENGTH] = {0};
    size_t asn1SignatureLen                               = sizeof(asn1Signature);
    sss_object_t publicKeyObject                          = {0};
    uint8_t verifySrcData[2 + 1 + 2 + EX_SSS_ORG_CHECK_OPTA_A_DATA_LEN + EX_SSS_ORG_CHECK_RANDOM_LENGTH * 2] = {
        0}; // 0xF0F0[||OptsA]||RndB||RndA
    size_t verifySrcDataLen        = 0;
    size_t optsAOffset             = 0;
    sss_asymmetric_t asymVerifyCtx = {0};

    if (NULL == pCtx) {
        return status;
    }
    pSession = (sss_nx_session_t *)&pCtx->session;

#if EX_SSS_BOOT_OPEN_HOST_SESSION && SSS_HAVE_HOSTCRYPTO_ANY && SSS_HAVE_AUTH_NONE
#if defined(USE_RTOS) && USE_RTOS == 1
    status = ex_sss_boot_open_host_session((pCtx));
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);
#endif
#endif

    // Generate 16 bytes random
    status = ex_orginality_check_get_random(rndA, rndALen);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);
    LOG_MAU8_I("Generate RndA", rndA, rndALen);
    LOG_MAU8_I("Use OptsA", optsA, optsALen);

    LOG_I("Send Cmd.ISOInternalAuthenticate.");
    status    = kStatus_SSS_Fail;
    sm_status = nx_ISOInternalAuthenticate(
        &pSession->s_ctx, EX_SSS_ORG_CHECK_KEY_ID, optsA, optsALen, rndA, sizeof(rndA), rndB, &rndBLen, sigB, &sigBLen);
    ENSURE_OR_GO_EXIT(SM_OK == sm_status);
    ENSURE_OR_GO_EXIT(EX_SSS_ORG_CHECK_RANDOM_LENGTH == rndBLen);

    // Turn the signature into ASN.1 format.
    status = ex_orginality_check_util_encode_asn1_signature(asn1Signature, &asn1SignatureLen, sigB, sigBLen);
    ENSURE_OR_GO_EXIT(kStatus_SSS_Success == status);

    LOG_MAU8_I("Rx RndB", rndB, rndBLen);
    LOG_MAU8_I("Rx Signature", sigB, sigBLen);

    LOG_I("Read certificate.");
    sm_status = nx_ReadData(&pSession->s_ctx, fileNo, offset, 0, &data[0], &dataLen, Nx_CommMode_NA);
    ENSURE_OR_GO_EXIT(SM_OK == sm_status);

    status = ex_orginality_check_verify_cert(pCtx, data, dataLen);
    ENSURE_OR_GO_EXIT(kStatus_SSS_Success == status);
    LOG_I("Verify Cert.Orig against the Originality CA Public key Success.");

    // Get public key and curve type from certificate.
    LOG_I("Get public key from certificate.");
    status = ex_orginality_check_parse_cert(data, dataLen, pubkey, &pubkeyLen, &pubKeyCipherType);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    // Set public key as host keyobject.
    status = sss_key_object_init(&publicKeyObject, &pCtx->host_ks);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    status = sss_key_object_allocate_handle(&publicKeyObject,
        MAKE_TEST_ID(__LINE__),
        kSSS_KeyPart_Public,
        pubKeyCipherType,
        256 / 8,
        kKeyObject_Mode_Persistent);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    status = sss_key_store_set_key(&pCtx->host_ks, &publicKeyObject, pubkey, pubkeyLen, 256, NULL, 0);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    LOG_MAU8_I("Public key", pubkey, pubkeyLen);

    // Data to be verified.
    verifySrcData[0] = 0xF0;
    verifySrcData[1] = 0xF0;
    verifySrcData[2] = NX_TAG_OPTS_A;
    if (optsALen <= 0x7Fu) {
        verifySrcData[3] = (uint8_t)optsALen;
        optsAOffset      = 4;
    }
    else { // if (optsALen <= 0xFFu)
        verifySrcData[3] = (uint8_t)(0x80 /* Extended */ | 0x01 /* Additional Length */);
        verifySrcData[4] = (uint8_t)((optsALen >> 0 * 8) & 0xFF);
        optsAOffset      = 5;
    }
    memcpy(&verifySrcData[optsAOffset], optsA, optsALen);
    memcpy(&verifySrcData[optsAOffset + optsALen], rndB, rndBLen);
    memcpy(&verifySrcData[optsAOffset + optsALen + rndBLen], rndA, rndALen);
    verifySrcDataLen = optsAOffset + optsALen + rndBLen + rndALen;

    status = sss_asymmetric_context_init(&asymVerifyCtx,
        &(gex_sss_boot_ctx.host_session),
        &publicKeyObject,
        kAlgorithm_SSS_ECDSA_SHA256,
        kMode_SSS_Verify);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    status =
        sss_asymmetric_verify_one_go(&asymVerifyCtx, verifySrcData, verifySrcDataLen, asn1Signature, asn1SignatureLen);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    LOG_I("Verify Signature Success.");

    LOG_I("Originality Check Example Success !!!...");

exit:
    if (publicKeyObject.keyStore != NULL) {
        sss_key_object_free(&publicKeyObject);
    }
    if (asymVerifyCtx.session != NULL) {
        sss_asymmetric_context_free(&asymVerifyCtx);
    }

#if EX_SSS_BOOT_OPEN_HOST_SESSION && SSS_HAVE_HOSTCRYPTO_ANY && SSS_HAVE_AUTH_NONE
#if defined(USE_RTOS) && USE_RTOS == 1
    if (pCtx->host_ks.session != NULL) {
        sss_host_key_store_context_free(&pCtx->host_ks);
    }
    if (pCtx->host_session.subsystem != kType_SSS_SubSystem_NONE) {
        sss_host_session_close(&pCtx->host_session);
    }
#endif
#endif

    return status;
}
