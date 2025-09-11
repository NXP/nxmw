/*
 *
 * Copyright 2023-2024 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "usb_c_common.h"
#include "fsl_sss_nx_apis.h"
#include "fsl_sss_util_asn1_der.h"
#include "usb_c_initiator_helper_port.h"
#include "nxEnsure.h"

#if defined(SSS_USE_FTR_FILE)
#include "fsl_sss_ftr.h"
#else
#include "fsl_sss_ftr_default.h"
#endif

#if SSS_HAVE_HOSTCRYPTO_MBEDTLS
#include "fsl_sss_mbedtls_apis.h"
#endif

#if SSS_HAVE_HOSTCRYPTO_OPENSSL
#include "fsl_sss_openssl_apis.h"
#endif

#if SSS_HAVE_HOSTCRYPTO_MBEDTLS
#include "mbedtls/x509_crt.h"
#endif

#if SSS_HAVE_HOSTCRYPTO_OPENSSL
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#endif

extern uint8_t usb_c_rootca_cert[];
extern size_t usb_c_rootca_cert_len;
extern sss_session_t *pghostSession;
extern sss_key_store_t *pghostKeyStore;

/** @brief Ec RandS To Signature.
 * This function generates signature from RandS.
 *
 * @param rawSignature - Pointer to a location where rands recieved.
 * @param rawSignatureLen - Length in bytes of generated rands.
 * @param asn1Signature - Output buffer containing the signature data.
 * @param asn1SignatureLen - Size of the output in bytes.
 *
 * @returns Status of the operation
 * @retval  0 The operation has completed successfully.
 * @retval -1 The requested function could not be performed.
 */
// ASN.1 encoded signature
//  30 44 02 20 [32B] 02 20 [32B]
//  30 45 02 21 00 [32B] 02 20 [32B]
//  30 45 02 20 [32B] 02 21 00 [32B]
//  30 46 02 21 00 [32B] 02 21 00 [32B]
static int encodeASN1Signature(
    uint8_t *rawSignature, const size_t rawSignatureLen, uint8_t *asn1Signature, size_t *asn1SignatureLen)
{
    int ret             = -1;
    size_t requiredSize = 4 + 32 + 2 + 32; // 30 44 02 20 [32B] 02 20 [32B]

    if ((rawSignature == NULL) || (asn1Signature == NULL) || (asn1SignatureLen == NULL)) {
        LOG_E("Invalid input parameters");
        goto exit;
    }

    if (rawSignatureLen != RAW_SIGNATURE_SIZE_BYTES) {
        LOG_E("Invalid raw signature");
        goto exit;
    }

    if ((rawSignature[0] & 0x80) == 0x80) { // R requires extra 0x00
        requiredSize++;
    }
    if ((rawSignature[RAW_SIGNATURE_SIZE_BYTES / 2] & 0x80) == 0x80) { // S requires extra 0x00
        requiredSize++;
    }

    if (*asn1SignatureLen < requiredSize) {
        LOG_E("Too small buffer for ASN.1 signature. Required %lu bytes", requiredSize);
        goto exit;
    }

    asn1Signature[0] = 0x30;
    asn1Signature[2] = 0x02;
    if (((rawSignature[0] & 0x80) == 0x00) &&
        ((rawSignature[RAW_SIGNATURE_SIZE_BYTES / 2] & 0x80) == 0x00)) { //  30 44 02 20 [32B] 02 20 [32B]
        asn1Signature[1] = 0x44;
        asn1Signature[3] = 0x20;
        memcpy(&(asn1Signature[4]), rawSignature, RAW_SIGNATURE_SIZE_BYTES / 2);
        asn1Signature[4 + 32]     = 0x02;
        asn1Signature[4 + 32 + 1] = 0x20;
        memcpy(
            &(asn1Signature[4 + 32 + 2]), &(rawSignature[RAW_SIGNATURE_SIZE_BYTES / 2]), RAW_SIGNATURE_SIZE_BYTES / 2);
        *asn1SignatureLen = 70;
    }
    else if (((rawSignature[0] & 0x80) == 0x80) &&
             ((rawSignature[RAW_SIGNATURE_SIZE_BYTES / 2] & 0x80) == 0x00)) { //  30 45 02 21 00 [32B] 02 20 [32B]
        asn1Signature[1] = 0x45;
        asn1Signature[3] = 0x21;
        asn1Signature[4] = 0x00;
        memcpy(&(asn1Signature[5]), rawSignature, RAW_SIGNATURE_SIZE_BYTES / 2);
        asn1Signature[5 + 32]     = 0x02;
        asn1Signature[5 + 32 + 1] = 0x20;
        memcpy(
            &(asn1Signature[5 + 32 + 2]), &(rawSignature[RAW_SIGNATURE_SIZE_BYTES / 2]), RAW_SIGNATURE_SIZE_BYTES / 2);
        *asn1SignatureLen = 71;
    }
    else if (((rawSignature[0] & 0x80) == 0x00) &&
             ((rawSignature[RAW_SIGNATURE_SIZE_BYTES / 2] & 0x80) == 0x80)) { //  30 45 02 20 [32B] 02 21 00 [32B]
        asn1Signature[1] = 0x45;
        asn1Signature[3] = 0x20;
        memcpy(&(asn1Signature[4]), rawSignature, RAW_SIGNATURE_SIZE_BYTES / 2);
        asn1Signature[4 + 32]     = 0x02;
        asn1Signature[4 + 32 + 1] = 0x21;
        asn1Signature[4 + 32 + 2] = 0x00;
        memcpy(
            &(asn1Signature[4 + 32 + 3]), &(rawSignature[RAW_SIGNATURE_SIZE_BYTES / 2]), RAW_SIGNATURE_SIZE_BYTES / 2);
        *asn1SignatureLen = 71;
    }
    else { //  30 46 02 21 00 [32B] 02 21 00 [32B]
        asn1Signature[1] = 0x46;
        asn1Signature[3] = 0x21;
        asn1Signature[4] = 0x00;
        memcpy(&(asn1Signature[5]), rawSignature, RAW_SIGNATURE_SIZE_BYTES / 2);
        asn1Signature[5 + 32]     = 0x02;
        asn1Signature[5 + 32 + 1] = 0x21;
        asn1Signature[5 + 32 + 2] = 0x00;
        memcpy(
            &(asn1Signature[5 + 32 + 3]), &(rawSignature[RAW_SIGNATURE_SIZE_BYTES / 2]), RAW_SIGNATURE_SIZE_BYTES / 2);
        *asn1SignatureLen = 72;
    }

    ret = 0;

exit:
    return ret;
}

static sss_status_t swapRandS(uint8_t *data, size_t dataLen)
{
    sss_status_t sss_status = kStatus_SSS_Fail;
    uint32_t i              = 0;
    uint8_t tmpValue        = 0;

    if (data == NULL) {
        LOG_E("Input data in NULL!!!");
        goto exit;
    }

    if (dataLen != 32) {
        LOG_E("Signature R and S can only be 32B!!!");
        goto exit;
    }

    for (i = 0; i < 16; i++) {
        tmpValue     = data[i];
        data[i]      = data[31 - i];
        data[31 - i] = tmpValue;
    }

    sss_status = kStatus_SSS_Success;

exit:
    return sss_status;
}

static sss_status_t hostVerifySignature(
    uint8_t *publicKey, size_t publicKeyLen, uint8_t *input, size_t inputLen, uint8_t *signature, size_t signatureLen)
{
    sss_status_t sss_status           = kStatus_SSS_Fail;
    sss_object_t hostPublicKeyObject  = {0};
    sss_digest_t digest_ctx           = {0};
    sss_asymmetric_t verificationCtx  = {0};
    uint8_t digest[DIGEST_SIZE_BYTES] = {0};
    size_t digestLen                  = sizeof(digest);

    sss_status = sss_host_key_object_init(&hostPublicKeyObject, pghostKeyStore);
    if (kStatus_SSS_Success != sss_status) {
        LOG_E("sss_host_key_object_init failed");
        goto cleanup;
    }

    sss_status = sss_host_key_object_allocate_handle(&hostPublicKeyObject,
        __LINE__,
        kSSS_KeyPart_Public,
        kSSS_CipherType_EC_NIST_P,
        publicKeyLen,
        kKeyObject_Mode_Transient);
    if (kStatus_SSS_Success != sss_status) {
        LOG_E("sss_host_key_object_allocate_handle failed");
        goto cleanup;
    }

    sss_status =
        sss_host_key_store_set_key(pghostKeyStore, &hostPublicKeyObject, publicKey, publicKeyLen, 256, NULL, 0);
    if (kStatus_SSS_Success != sss_status) {
        LOG_E("sss_host_key_store_set_key failed");
        goto cleanup;
    }

    sss_status = sss_host_digest_context_init(&digest_ctx, pghostSession, kAlgorithm_SSS_SHA256, kMode_SSS_Digest);
    if (kStatus_SSS_Success != sss_status) {
        LOG_E("sss_host_digest_context_init failed");
        goto cleanup;
    }

    sss_status = sss_host_digest_one_go(&digest_ctx, input, inputLen, digest, &digestLen);
    if (kStatus_SSS_Success != sss_status) {
        LOG_E("sss_host_digest_one_go failed");
        goto cleanup;
    }
    if (digest_ctx.session != NULL) {
        sss_host_digest_context_free(&digest_ctx);
    }

    sss_status = sss_host_asymmetric_context_init(
        &verificationCtx, pghostSession, &hostPublicKeyObject, kAlgorithm_SSS_ECDSA_SHA256, kMode_SSS_Verify);
    if (kStatus_SSS_Success != sss_status) {
        LOG_E("sss_host_asymmetric_context_init failed");
        goto cleanup;
    }

    sss_status = sss_host_asymmetric_verify_digest(&verificationCtx, digest, digestLen, signature, signatureLen);
    if (kStatus_SSS_Success != sss_status) {
        LOG_E("sss_host_asymmetric_verify_digest failed");
        goto cleanup;
    }

cleanup:
    sss_host_key_store_erase_key(pghostKeyStore, &hostPublicKeyObject);
    if (digest_ctx.session != NULL) {
        sss_host_digest_context_free(&digest_ctx);
    }
    if (verificationCtx.session != NULL) {
        sss_host_asymmetric_context_free(&verificationCtx);
    }
    if (hostPublicKeyObject.keyStore != NULL) {
        sss_host_key_object_free(&hostPublicKeyObject);
    }
    return sss_status;
}

static void parseCertGetPublicKey(uint8_t *pCert, size_t certLen, uint8_t *pPucPublicKey, size_t *pucPublicKeylen)
{
    int ret            = -1;
    unsigned char *p   = NULL;
    unsigned char *end = NULL;
    size_t len         = 0;

    if ((NULL == pCert) || (NULL == pucPublicKeylen)) {
        LOG_E("Invalid input parameter");
        return;
    }
    p   = pCert;
    end = pCert + certLen;

    /* Parse first sequence tag */
    ret = sss_util_asn1_get_tag(&p, end, &len, SSS_UTIL_ASN1_SEQUENCE | SSS_UTIL_ASN1_CONSTRUCTED);
    if (ret != 0) {
        LOG_E("Error parsing ASN.1 data : %d", __LINE__);
        goto exit;
    }
    /* p now points to TBS bytes */
    /* Parse sequence tag of TBSCertificate */
    ret = sss_util_asn1_get_tag(&p, end, &len, SSS_UTIL_ASN1_SEQUENCE | SSS_UTIL_ASN1_CONSTRUCTED);
    if (ret != 0) {
        LOG_E("Error parsing ASN.1 data : %d", __LINE__);
        goto exit;
    }
    /* p now points to Certificate version */
    /* Parse 0xA0 tag of Certificate version */
    ret = sss_util_asn1_get_tag(&p, end, &len, SSS_UTIL_ASN1_CONTEXT_SPECIFIC | SSS_UTIL_ASN1_CONSTRUCTED);
    if (ret != 0) {
        LOG_E("Error parsing ASN.1 data : %d", __LINE__);
        goto exit;
    }
    p += len;
    /* p now points to Certificate serial number */
    /* Parse MBEDTLS_ASN1_INTEGER tag of Certificate version */
    ret = sss_util_asn1_get_tag(&p, end, &len, SSS_UTIL_ASN1_INTEGER);
    if (ret != 0) {
        LOG_E("Error parsing ASN.1 data : %d", __LINE__);
        goto exit;
    }
    p += len;
    /* p now points to Certificate signature algorithm */
    /* Parse sequence tag of Certificate version */
    ret = sss_util_asn1_get_tag(&p, end, &len, SSS_UTIL_ASN1_SEQUENCE | SSS_UTIL_ASN1_CONSTRUCTED);
    if (ret != 0) {
        LOG_E("Error parsing ASN.1 data : %d", __LINE__);
        goto exit;
    }
    p += len;
    /* p now points to Certificate Issuer */
    /* Parse sequence tag of Certificate version */
    ret = sss_util_asn1_get_tag(&p, end, &len, SSS_UTIL_ASN1_SEQUENCE | SSS_UTIL_ASN1_CONSTRUCTED);
    if (ret != 0) {
        LOG_E("Error parsing ASN.1 data : %d", __LINE__);
        goto exit;
    }
    p += len;
    /* p now points to Certificate Validity */
    /* Parse sequence tag of Certificate version */
    ret = sss_util_asn1_get_tag(&p, end, &len, SSS_UTIL_ASN1_SEQUENCE | SSS_UTIL_ASN1_CONSTRUCTED);
    if (ret != 0) {
        LOG_E("Error parsing ASN.1 data : %d", __LINE__);
        goto exit;
    }
    p += len;
    /* p now points to Certificate Subject */
    /* Parse sequence tag of Certificate version */
    ret = sss_util_asn1_get_tag(&p, end, &len, SSS_UTIL_ASN1_SEQUENCE | SSS_UTIL_ASN1_CONSTRUCTED);
    if (ret != 0) {
        LOG_E("Error parsing ASN.1 data : %d", __LINE__);
        goto exit;
    }
    p += len;
    /* p now points to Certificate Subject Public Key Info */
    /* Parse sequence tag of Certificate version */
    ret = sss_util_asn1_get_tag(&p, end, &len, SSS_UTIL_ASN1_SEQUENCE | SSS_UTIL_ASN1_CONSTRUCTED);
    if (ret != 0) {
        LOG_E("Error parsing ASN.1 data : %d", __LINE__);
        goto exit;
    }
    /* p now points to Certificate Public Key algorithm */
    /* Parse sequence tag of Certificate version */
    ret = sss_util_asn1_get_tag(&p, end, &len, SSS_UTIL_ASN1_SEQUENCE | SSS_UTIL_ASN1_CONSTRUCTED);
    if (ret != 0) {
        LOG_E("Error parsing ASN.1 data : %d", __LINE__);
        goto exit;
    }
    p += len;
    /* p now points to Certificate Public Key */
    /* Parse sequence tag of Certificate version */
    ret = sss_util_asn1_get_tag(&p, end, &len, SSS_UTIL_ASN1_BIT_STRING);
    if (ret != 0) {
        LOG_E("Error parsing ASN.1 data : %d", __LINE__);
        goto exit;
    }
    else if ((len != 0x41) && (len != 0x42)) {
        LOG_E("Invalid certificate public key length %d(%d)", len, __LINE__);
        goto exit;
    }

    if (*p == 0x00) {
        p++;
        len--;
    }
    p++;
    len--;

    if ((p + len) > end) {
        LOG_E("Invalid certificate object");
        *pucPublicKeylen = 0;
    }
    else if (len > *pucPublicKeylen) {
        LOG_E("Insufficient buffer");
        *pucPublicKeylen = 0;
    }
    else {
        if (len > 0) {
            if (NULL == pPucPublicKey) {
                LOG_E("NULL buffer to copy");
                goto exit;
            }
            memcpy((void *)pPucPublicKey, (void *)p, len);
            *pucPublicKeylen = len;
        }
    }

    return;

exit:
    *pucPublicKeylen = 0;
}

static int parseCertificatesGetLeafCert(uint8_t *pCerts, size_t certsLen, uint8_t **pLeafCert, size_t *leafCertLen)
{
    int ret               = -1;
    unsigned char *p      = NULL;
    unsigned char *end    = NULL;
    size_t len            = 0;
    size_t leafCertOffset = 0;

    if ((NULL == pCerts) || (NULL == pLeafCert) || (NULL == leafCertLen)) {
        LOG_E("Invalid input parameter");
        goto exit;
    }

    p   = pCerts;
    end = pCerts + certsLen;

    while (p < end) {
        leafCertOffset = p - pCerts;

        /* Parse first sequence tag */
        ret = sss_util_asn1_get_tag(&p, end, &len, SSS_UTIL_ASN1_SEQUENCE | SSS_UTIL_ASN1_CONSTRUCTED);
        if (ret != 0) {
            LOG_E("Error parsing ASN.1 data : %d", __LINE__);
            goto exit;
        }

        p += len;
    }

    *pLeafCert = pCerts + leafCertOffset;
    if (certsLen < leafCertOffset) {
        ret = -1;
        goto exit;
    }
    *leafCertLen = certsLen - leafCertOffset;

    ret = 0;
exit:
    return ret;
}

#if SSS_HAVE_HOSTCRYPTO_MBEDTLS
static int hostParseCertExCb(void *p_ctx,
    mbedtls_x509_crt const *crt,
    mbedtls_x509_buf const *oid,
    int critical,
    const unsigned char *cp,
    const unsigned char *end)
{
    return 0;
}

static int hostVerifyCertificates(uint8_t *certificates, size_t certificates_size)
{
    int ret                                  = -1;
    unsigned char *p                         = NULL;
    unsigned char *end                       = NULL;
    size_t len                               = 0;
    size_t i                                 = 0;
    uint8_t *certList[MAX_CERT_CHAIN_DEPTH]  = {0};
    size_t certLenList[MAX_CERT_CHAIN_DEPTH] = {0};
    size_t certListCnt                       = 0;
    mbedtls_x509_crt certChain               = {0};
    mbedtls_x509_crt rootCert                = {0};
    uint32_t flags                           = 0;

    if (NULL == certificates) {
        goto exit;
    }
    p   = certificates;
    end = certificates + certificates_size;

    // Get all certificates pointer
    while (p < end) {
        if (i >= MAX_CERT_CHAIN_DEPTH) {
            ret = -1;
            goto exit;
        }
        certList[i] = p;

        /* Parse first sequence tag */
        ret = sss_util_asn1_get_tag(&p, end, &len, SSS_UTIL_ASN1_SEQUENCE | SSS_UTIL_ASN1_CONSTRUCTED);
        if (ret != 0) {
            LOG_E("Error parsing ASN.1 data : %d", __LINE__);
            goto exit;
        }

        p += len;
        certLenList[i] = (p - certList[i]);
        i++;
    }

    certListCnt = i;

    mbedtls_x509_crt_init(&certChain);
    mbedtls_x509_crt_init(&rootCert);

    // Add certificate chain to container
    for (i = certListCnt; i > 0; i--) {
        ret = mbedtls_x509_crt_parse_der_with_ext_cb(
            &certChain, (const unsigned char *)certList[i - 1], certLenList[i - 1], 0, hostParseCertExCb, NULL);
        if (ret != 0) {
            LOG_E("Error parsing certificate");
            goto exit;
        }
    }

    // Add root CA certificate chain to container
    ret = mbedtls_x509_crt_parse_der_with_ext_cb(
        &rootCert, (const unsigned char *)usb_c_rootca_cert, usb_c_rootca_cert_len, 0, hostParseCertExCb, NULL);
    if (ret != 0) {
        LOG_E("Error parsing root CA certificate");
        goto exit;
    }

    // Verify certificate chain with root CA certificate.
    ret = mbedtls_x509_crt_verify(&certChain, &rootCert, NULL, NULL, &flags, NULL, NULL);
    if (ret != 0) {
        LOG_E("Verify X.509 certificate Failed");
        goto exit;
    }

    ret = 0;

exit:
#if SSS_HAVE_HOSTCRYPTO_MBEDTLS
    mbedtls_x509_crt_free(&certChain);
    mbedtls_x509_crt_free(&rootCert);
#endif

    return ret;
}

#elif SSS_HAVE_HOSTCRYPTO_OPENSSL

static int hostVerifyCertificates(uint8_t *certificates, size_t certificates_size)
{
    int ret            = -1;
    unsigned char *p   = NULL;
    unsigned char *end = NULL;
    size_t len         = 0;
    size_t i = 0, j = 0;
    uint8_t *certList[MAX_CERT_CHAIN_DEPTH]  = {0};
    size_t certLenList[MAX_CERT_CHAIN_DEPTH] = {0};
    size_t certListCnt                       = 0;

    unsigned char *certBuf          = NULL;
    const unsigned char *certBufPtr = NULL;
    size_t certBufLen               = 0;
    STACK_OF(X509) *certStack       = NULL;

    X509_STORE *rootCAStore                = NULL;
    X509_STORE_CTX *storeCtx               = NULL;
    STACK_OF(X509) *caCertStack            = NULL;
    int x509_ret                           = -1;
    X509 *deviceCert[MAX_CERT_CHAIN_DEPTH] = {0};
    X509 *rootCert                         = NULL;

    if (NULL == certificates) {
        goto exit;
    }
    p   = certificates;
    end = certificates + certificates_size;

    // Get all certificates pointer
    while (p < end) {
        if (i >= MAX_CERT_CHAIN_DEPTH) {
            ret = -1;
            goto exit;
        }
        certList[i] = p;

        /* Parse first sequence tag */
        ret = sss_util_asn1_get_tag(&p, end, &len, SSS_UTIL_ASN1_SEQUENCE | SSS_UTIL_ASN1_CONSTRUCTED);
        if (ret != 0) {
            LOG_E("Error parsing ASN.1 data : %d", __LINE__);
            goto exit;
        }

        p += len;
        certLenList[i] = (p - certList[i]);
        i++;
    }

    certListCnt = i;
    ret         = -1;

    // Init store, ctx and stack
    rootCAStore = X509_STORE_new();
    storeCtx    = X509_STORE_CTX_new();
    caCertStack = sk_X509_new_null();

    // Get X509 object for root CA certificate
    certBuf    = usb_c_rootca_cert;
    certBufLen = usb_c_rootca_cert_len;
    certBufPtr = certBuf;

    rootCert = d2i_X509(NULL, &certBufPtr, certBufLen);
    x509_ret = X509_STORE_add_cert(rootCAStore, rootCert);
    ENSURE_OR_GO_EXIT(x509_ret == 1);

    for (i = certListCnt; i > 0; i--) {
        certBuf    = certList[i - 1];
        certBufLen = certLenList[i - 1];

        if (j >= MAX_CERT_CHAIN_DEPTH) {
            ret = -1;
            goto exit;
        }
        certBufPtr = certBuf;
        // Get X509 object for leaf and intermediate CA certificates
        deviceCert[j] = d2i_X509(NULL, &certBufPtr, certBufLen);
        ENSURE_OR_GO_EXIT(deviceCert[j] != NULL);

        if (j != 0) {
            // Not Leaf certificate. Add to intermediate CA certificate chain
            sk_X509_push(caCertStack, deviceCert[j]);
        }

        j++;
    }

    // Verify leaf certificate and intermediate CA certificate with root CA certificate
    certStack = caCertStack;
    X509_STORE_CTX_cleanup(storeCtx);

    ret = X509_STORE_CTX_init(storeCtx, rootCAStore, deviceCert[0], certStack);
    if (ret != 1) {
        ret = -1;
        LOG_E("X509_STORE_CTX_init failed");
        goto exit;
    }

    ret = X509_verify_cert(storeCtx);
    if (ret != 1) {
        ret = -1;
        LOG_E("X509 Verification Failed");
        goto exit;
    }

    ret = 0;

exit:
    for (i = 0; i < certListCnt; i++) {
        if (deviceCert[i] != NULL) {
            X509_free(deviceCert[i]);
        }
    }
    if (rootCert != NULL) {
        X509_free(rootCert);
    }
    sk_X509_pop_free(caCertStack, X509_free);
    X509_STORE_CTX_cleanup(storeCtx);
    X509_STORE_CTX_free(storeCtx);
    X509_STORE_free(rootCAStore);

    return ret;
}

#endif

static int hostVerifyChallenge(
    uint8_t *pPublicKey, size_t publicKeyLen, uint8_t *pChallengeRequest, uint8_t *pChallengeResponse)
{
    int ret                          = -1;
    sss_status_t sss_status          = kStatus_SSS_Fail;
    uint8_t publicKeyWithHeader[100] = {0};
    uint8_t asn1Signature[72]        = {0};
    size_t asn1SignatureLen          = sizeof(asn1Signature);
    uint8_t swapSignature[64]        = {0};

    usb_c_challenge_request_t *pMsgRequest   = (usb_c_challenge_request_t *)pChallengeRequest;
    usb_c_challenge_response_t *pMsgResponse = (usb_c_challenge_response_t *)pChallengeResponse;
    usb_c_msg_for_signature_t msgContent     = {0};

    if ((pMsgRequest == NULL) || (pMsgResponse == NULL)) {
        LOG_E("Input pointer is NULL");
        goto cleanup;
    }

    // Encode ASN.1 public key
    memcpy(publicKeyWithHeader, gecc_der_header_nist256, der_ecc_nistp256_header_len);
    memcpy(&publicKeyWithHeader[der_ecc_nistp256_header_len], pPublicKey, publicKeyLen);

    // Message content to be verified
    memcpy(&(msgContent.reqMsg), pMsgRequest, sizeof(msgContent.reqMsg));
    memcpy(&(msgContent.respMsg), pMsgResponse, sizeof(msgContent.respMsg));

    // Swap signature R and S.
    memcpy(swapSignature, pMsgResponse->signature, sizeof(pMsgResponse->signature));
    sss_status = swapRandS(swapSignature, sizeof(swapSignature) / 2);
    if (sss_status != kStatus_SSS_Success) {
        LOG_E("Swap signature R failed");
        goto cleanup;
    }

    sss_status = swapRandS(&(swapSignature[RAW_SIGNATURE_SIZE_BYTES / 2]), sizeof(swapSignature) / 2);
    if (sss_status != kStatus_SSS_Success) {
        LOG_E("Swap signature S failed");
        goto cleanup;
    }

    // Encode ASN.1 signature.
    if (0 != encodeASN1Signature(swapSignature, RAW_SIGNATURE_SIZE_BYTES, asn1Signature, &asn1SignatureLen)) {
        LOG_E("Cannot create ASN.1 signature");
        goto cleanup;
    }

    LOG_MAU8_I("Message Content", (uint8_t *)(&msgContent), sizeof(msgContent));

    // Verify signature.
    sss_status = hostVerifySignature(publicKeyWithHeader,
        publicKeyLen + der_ecc_nistp256_header_len,
        (uint8_t *)(&msgContent),
        sizeof(msgContent),
        asn1Signature,
        asn1SignatureLen);
    if (sss_status == kStatus_SSS_Success) {
        LOG_I("Challenge successfully verified");
        ret = 0;
    }

cleanup:
    return ret;
}

static int getRandom(uint8_t *pBuf, size_t bufLen)
{
    int ret                       = -1;
    sss_status_t sss_status       = kStatus_SSS_Fail;
    sss_rng_context_t sss_rng_ctx = {0};

    sss_status = sss_rng_context_init(&sss_rng_ctx, pghostSession);
    if (sss_status != kStatus_SSS_Success) {
        goto exit;
    }

    sss_status = sss_rng_get_random(&sss_rng_ctx, pBuf, bufLen);
    if (sss_status != kStatus_SSS_Success) {
        goto exit;
    }

    ret = 0;

exit:
    if (sss_rng_ctx.session != NULL) {
        sss_rng_context_free(&sss_rng_ctx);
    }
    return ret;
}

static int hostGetSha256Hash(const uint8_t *pInput, size_t inputLen, uint8_t *pOutput, size_t *pOutputLen)
{
    int ret                 = -1;
    sss_status_t status     = kStatus_SSS_Fail;
    sss_session_t *pSession = pghostSession;
    sss_digest_t digest     = {0};
    size_t chunk            = 0;
    size_t offset           = 0;

    if ((pInput == NULL) || (pOutput == NULL) || (pOutputLen == NULL)) {
        LOG_E("Calculate digest with wrong parameter!!!");
        goto exit;
    }

    status = sss_host_digest_context_init(&digest, pSession, kAlgorithm_SSS_SHA256, kMode_SSS_Digest);
    if (status != kStatus_SSS_Success) {
        LOG_E("sss_digest_context_init Failed!!!");
        goto exit;
    }

    status = sss_host_digest_init(&digest);
    if (status != kStatus_SSS_Success) {
        LOG_E("sss_digest_one_go Failed!!!");
        goto exit;
    }

    do {
        chunk = (inputLen > NX_MAX_SHA_INPUT_LEN) ? NX_MAX_SHA_INPUT_LEN : inputLen;

        status = sss_host_digest_update(&digest, pInput + offset, chunk);
        ENSURE_OR_GO_EXIT(kStatus_SSS_Success == status);
        if (chunk > (UINT_MAX - offset)) {
            goto exit;
        }
        offset += chunk;
        inputLen -= chunk;
    } while (inputLen > 0);

    status = sss_host_digest_finish(&digest, pOutput, pOutputLen);
    if (status != kStatus_SSS_Success) {
        LOG_E("sss_digest_finish Failed!!!");
        goto exit;
    }

    ret = 0;
exit:
    if (digest.session != NULL) {
        sss_host_digest_context_free(&digest);
    }
    return ret;
}

/* doc:start:usb_c-auth-port */
/* Port to implement RNG to get 16 byte nonce value
 * for authentication operation.
 * This API does not guarantee the randomness of the RNG.
 * User should make sure that the RNG seed is from a trusted source
 * and that the randomness of the source is NIST compliant
 */
int port_getRandomNonce(uint8_t *nonce, size_t *pNonceLen)
{
    int ret              = -1;
    size_t random_length = 0;

    if ((NULL == nonce) || (NULL == pNonceLen)) {
        goto exit;
    }
    random_length = (*pNonceLen > NONCE_LEN) ? NONCE_LEN : (*pNonceLen);
    *pNonceLen    = random_length;

    ret = getRandom(nonce, random_length);
    if (0 != ret) {
        *pNonceLen = 0;
    }
exit:
    return ret;
}

/* Port to implement function which will
 * parse an X.509 certificate and extract the public key
 * from it.
 */
void port_parseCertGetPublicKey(uint8_t *pCert, size_t certLen, uint8_t *pPublicKey, size_t *publicKeylen)
{
    parseCertGetPublicKey(pCert, certLen, pPublicKey, publicKeylen);
}

/* Port to implement function which will
 * parse an X.509 certificates and extract the leaf certificate
 * from it.
 */
int port_parseCertificatesGetLeafCert(uint8_t *pCerts, size_t certsLen, uint8_t **pLeafCert, size_t *leafCertLen)
{
    return parseCertificatesGetLeafCert(pCerts, certsLen, pLeafCert, leafCertLen);
}

/* Port to implement function which will
 * verify the complete certificate chain as passed in certificate_chain
 */
/*
int port_hostVerifyCertificateChain(uint8_t *certificate_chain,
    size_t certificate_chain_size,
    uint16_t pucCertOffset,
    uint16_t manufacturerCertLenOffset)
{
    return hostVerifyCertificateChain(
        certificate_chain, certificate_chain_size, pucCertOffset, manufacturerCertLenOffset);
}
*/

int port_hostVerifyCertificates(uint8_t *certificates, size_t certificates_size)
{
    return hostVerifyCertificates(certificates, certificates_size);
}

/* Port to implement function which will
 * verify CHALLENGE on host
 */
int port_hostVerifyChallenge(
    uint8_t *pPublicKey, size_t publicKeyLen, uint8_t *pChallengeRequest, uint8_t *pChallengeResponse)
{
    return hostVerifyChallenge(pPublicKey, publicKeyLen, pChallengeRequest, pChallengeResponse);
}

/* Port to implement function which will
 * do digest sha256 on host
 */
int port_getSha256Hash(const uint8_t *pInput, size_t inputLen, uint8_t *pOutput, size_t *pOutputLen)
{
    return hostGetSha256Hash(pInput, inputLen, pOutput, pOutputLen);
}
/* doc:end:usb_c-auth-port */
