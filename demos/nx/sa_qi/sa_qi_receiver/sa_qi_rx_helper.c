/* Copyright 2023 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "sa_qi_rx_helper.h"
#include "qi_transmitter.h"
#include "qi_tx_helper.h"

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

#define NIST_256_HEADER_LEN 26
#define PUBKEY_LEN_MAX 256

/*
 This is a simple function to insert a TLV into a buffer.
 params:
    tag             - ASN.1 Tag
    component       - byte array to be inserted
    componentLen    - Size of component to be inserted
    key             - Buffer into which component will be inserted
    keyLen          - Size of the buffer (key).

 Note : This function inserts the component at the end of the buffer and updates the
        keyLen to where the component is inserted with tag. (Points to the tag)
*/

static int SetASNTLV(uint8_t tag, uint8_t *component, const size_t componentLen, uint8_t *key, size_t *keyLen)
{
    int ret = -1;

    if ((NULL == component) || (NULL == key) || (NULL == keyLen)) {
        goto exit;
    }

    if (componentLen <= 0) {
        goto exit;
    }

    if (*keyLen < componentLen) {
        goto exit;
    }

    *keyLen = *keyLen - componentLen;
    memcpy(&key[*keyLen], component, componentLen);

    if (componentLen <= 127) {
        if (*keyLen < 1) {
            goto exit;
        }
        *keyLen      = *keyLen - 1;
        key[*keyLen] = (uint8_t)componentLen;
    }
    else if (componentLen <= 255) {
        if (*keyLen < 2) {
            goto exit;
        }
        *keyLen          = *keyLen - 2;
        key[*keyLen]     = 0x81;
        key[*keyLen + 1] = (uint8_t)componentLen;
    }
    else {
        if (*keyLen < 3) {
            goto exit;
        }
        *keyLen          = *keyLen - 3;
        key[*keyLen]     = 0x82;
        key[*keyLen + 1] = (componentLen & 0x00FF00) >> 8;
        key[*keyLen + 2] = (componentLen & 0x00FF);
    }
    if (*keyLen < 1) {
        goto exit;
    }
    *keyLen = *keyLen - 1;

    key[*keyLen] = tag;

    ret = 0;

exit:
    return ret;
}

/** @brief Ec RandS To Signature.
 * This function generates signature from RandS.
 *
 * @param rands - Pointer to a location where rands recieved.
 * @param rands_len - Length in bytes of generated rands.
 * @param output - Output buffer containing the signature data.
 * @param outputLen - Size of the output in bytes.
 *
 * @returns Status of the operation
 * @retval  0 The operation has completed successfully.
 * @retval -1 The requested function could not be performed.
 */

static int EcRandSToSignature(uint8_t *rands, const size_t rands_len, uint8_t *output, size_t *outputLen)
{
    int xResult            = -1;
    uint8_t signature[256] = {0};
    size_t signatureLen    = sizeof(signature);
    size_t componentLen    = (rands_len) / 2;
    uint8_t tag            = MBEDTLS_ASN1_INTEGER;
    size_t totalLen        = 0;

    if ((NULL == rands) || (NULL == output) || (NULL == outputLen)) {
        goto exit;
    }

    xResult = SetASNTLV(tag, &rands[componentLen], componentLen, signature, &signatureLen);
    if (xResult != 0) {
        goto exit;
    }

    xResult = SetASNTLV(tag, &rands[0], componentLen, signature, &signatureLen);
    if (xResult != 0) {
        goto exit;
    }

    totalLen = sizeof(signature) - signatureLen;

    if (totalLen <= 127) {
        if (signatureLen < 1) {
            xResult = -1;
            goto exit;
        }
        signatureLen = signatureLen - 1;

        signature[signatureLen] = (uint8_t)totalLen;
    }
    else if (totalLen <= 255) {
        if (signatureLen < 2) {
            xResult = -1;
            goto exit;
        }
        signatureLen = signatureLen - 2;

        signature[signatureLen]     = 0x81;
        signature[signatureLen + 1] = (uint8_t)totalLen;
    }
    else {
        if (signatureLen < 3) {
            xResult = -1;
            goto exit;
        }
        signatureLen = signatureLen - 3;

        signature[signatureLen]     = 0x82;
        signature[signatureLen + 1] = (totalLen & 0x00FF00) >> 8;
        signature[signatureLen + 2] = (totalLen & 0x00FF);
    }
    if (signatureLen < 1) {
        return -1;
    }
    signatureLen = signatureLen - 1;

    signature[signatureLen] = MBEDTLS_ASN1_SEQUENCE | MBEDTLS_ASN1_CONSTRUCTED;

    totalLen = sizeof(signature) - signatureLen;
    memcpy(&output[0], &signature[signatureLen], totalLen);
    *outputLen = totalLen;

    xResult = 0;

exit:
    return xResult;
}

static int set_secp256r1nist_header(uint8_t *pbKey, size_t *pbKeyByteLen)
{
    int ret        = -1;
    unsigned int i = 0;
    /* clang-format off */
    uint8_t temp[PUBKEY_LEN_MAX] = {0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D,
                      0x02, 0x01, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01,
                      0x07, 0x03, 0x42, 0x00};
    /* clang-format on */

    if ((NULL == pbKey) || (NULL == pbKeyByteLen)) {
        goto exit;
    }

    if (*pbKeyByteLen > (sizeof(temp) - NIST_256_HEADER_LEN)) {
        LOG_E("pbKeyByteLen looks large- no enough space to prepend the header!");
        goto exit;
    }

    for (i = 0; i < *pbKeyByteLen; i++) {
        temp[NIST_256_HEADER_LEN + i] = pbKey[i];
    }

    *pbKeyByteLen = *pbKeyByteLen + NIST_256_HEADER_LEN;
    memcpy(pbKey, temp, *pbKeyByteLen);

    ret = 0;
exit:
    return ret;
}

int parseCertGetTBS(uint8_t *pCert, size_t certLen, uint8_t *pgetTbs, size_t *pTbslen)
{
    int ret             = -1;
    unsigned char *pTbs = NULL;
    unsigned char *p    = NULL;
    unsigned char *end  = NULL;
    size_t len          = 0;
    size_t length       = 0;

    if ((NULL == pCert) || (NULL == pTbslen)) {
        goto exit;
    }
    p   = pCert;
    end = pCert + certLen;

    /* Parse first sequence tag */
    ret = mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_SEQUENCE | MBEDTLS_ASN1_CONSTRUCTED);
    if (ret != 0) {
        LOG_E("Error parsing ASN.1 data : %d", __LINE__);
        goto exit;
    }

    /* p is now pointing to TBS */
    pTbs = p;
    p++;

    if ((*p & 0x80) == 0x80) {
        if ((*p & 0x7F) == 0x01) {
            length = *(p + 1) + 3u;
        }
        else if ((*(p)&0x7F) == 0x02) {
            length = (size_t)(*(p + 1) << 8);
            if (length > (UINT_MAX - (*(p + 2) + 4u))) {
                LOG_E("Parsing the TLV-Length field failed");
                ret = -1;
                goto exit;
            }
            length += (*(p + 2) + 4u);
        }
    }
    do {
        if ((p + length) > end) {
            LOG_E("Invalid certificate object");
            *pTbslen = 0;
            ret      = -1;
            goto exit;
        }
        else if (length > *pTbslen) {
            LOG_E("Insufficient buffer");
            *pTbslen = 0;
            ret      = -1;
            goto exit;
        }
        if (length > 0) {
            if (NULL == pTbslen) {
                LOG_E("NULL buffer to copy");
                ret = -1;
                goto exit;
            }
            memcpy(pgetTbs, pTbs, length);
            *pTbslen = length;
        }
        else {
            *pTbslen = 0;
        }
    } while (0);
    ret = 0;

exit:
    return ret;
}

void parseCertGetSignature(uint8_t *pCert, size_t certLen, uint8_t *pSignature, size_t *pSignaturelen)
{
    int ret            = -1;
    unsigned char *p   = NULL;
    unsigned char *end = NULL;
    size_t len         = 0;

    if ((NULL == pCert) || (NULL == pSignature) || (NULL == pSignaturelen)) {
        LOG_E("Invalid input parameter");
        goto exit;
    }
    p   = pCert;
    end = pCert + certLen;

    /* Parse first sequence tag */
    ret = mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_SEQUENCE | MBEDTLS_ASN1_CONSTRUCTED);

    if (ret != 0) {
        LOG_E("Error parsing ASN.1 data : %d", __LINE__);
        goto exit;
    }
    /* p now points to TBS bytes */
    /* Parse sequence tag of TBSCertificate */
    ret = mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_SEQUENCE | MBEDTLS_ASN1_CONSTRUCTED);

    if (ret != 0) {
        LOG_E("Error parsing ASN.1 data : %d", __LINE__);
        goto exit;
    }
    p += len;

    /* p now points to Certificate signature algorithm */
    /* Parse sequence tag of Certificate signature algorithm */
    ret = mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_SEQUENCE | MBEDTLS_ASN1_CONSTRUCTED);
    if (ret != 0) {
        LOG_E("Error parsing ASN.1 data : %d", __LINE__);
        goto exit;
    }
    p += len;

    /* p now points to Certificate signature*/
    /* Parse sequence tag of Certificate signature */
    ret = mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_BIT_STRING);
    if (ret != 0) {
        LOG_E("Error parsing ASN.1 data : %d", __LINE__);
        goto exit;
    }
    if (*p == 0x00) {
        p++;
        len--;
    }
    do {
        if ((p + len) > end) {
            LOG_E("Invalid certificate object");
            *pSignaturelen = 0;
            break;
        }
        else if (len > *pSignaturelen) {
            LOG_E("Insufficient buffer");
            *pSignaturelen = 0;
            break;
        }

        if ((len == SIGNATURE_SIZE) || (len == SIGNATURE_WITH_PAD_SIZE)) {
            memcpy(pSignature, p, len);
            *pSignaturelen = len;
        }
        else {
            LOG_E("Invalid certificate Signature length %d(%d)", len, __LINE__);
            *pSignaturelen = 0;
        }
    } while (0);
exit:
    return;
}

static sss_status_t nx_getDigestSHA256(const uint8_t *pInput, size_t inputLen, uint8_t *pOutput, size_t *pOutputLen)
{
    sss_status_t sss_status = kStatus_SSS_Fail;
    sss_digest_t digest_ctx = {0};
    size_t chunk            = 0;
    size_t offset           = 0;

    sss_status = sss_digest_context_init(&digest_ctx, pgSssSession, kAlgorithm_SSS_SHA256, kMode_SSS_Digest);
    if (kStatus_SSS_Success != sss_status) {
        LOG_E("sss_digest_context_init failed");
        goto cleanup;
    }
    sss_status = sss_digest_init(&digest_ctx);
    if (kStatus_SSS_Success != sss_status) {
        LOG_E("sss_digest_context_init failed");
        goto cleanup;
    }

    do {
        chunk      = (inputLen > NX_WRITE_MAX_LEN_DIGEST) ? NX_WRITE_MAX_LEN_DIGEST : inputLen;
        sss_status = sss_digest_update(&digest_ctx, pInput + offset, chunk);
        if (kStatus_SSS_Success != sss_status) {
            LOG_E("sss_digest_update failed");
        }
        if ((UINT_MAX - offset) < chunk) {
            sss_status = kStatus_SSS_Fail;
            goto cleanup;
        }
        offset += chunk;
        inputLen -= chunk;
    } while (inputLen > 0);

    sss_status = sss_digest_finish(&digest_ctx, pOutput, pOutputLen);
    if (kStatus_SSS_Success != sss_status) {
        LOG_E("sss_digest_finish failed");
    }

cleanup:
    if (digest_ctx.session != NULL) {
        sss_host_digest_context_free(&digest_ctx);
    }
    return sss_status;
}

sss_status_t nxVerifySignature(
    uint8_t *publicKey, size_t publicKeyLen, uint8_t *input, size_t inputLen, uint8_t *signature, size_t signatureLen)
{
    sss_status_t sss_status              = kStatus_SSS_Fail;
    uint8_t keyId                        = 2;
    sss_object_t hostPublicKeyObject     = {0};
    sss_digest_t digest_ctx              = {0};
    sss_asymmetric_t verificationCtx     = {0};
    uint8_t digest[DIGEST_SIZE_BYTES]    = {0};
    size_t digestLen                     = sizeof(digest);
    size_t keylen                        = KEY_BIT_LENGTH / 8;
    uint8_t publicKeyDer[KEY_BIT_LENGTH] = {0};
    size_t publicKeyDerLen               = publicKeyLen;

    if (NULL == publicKey) {
        goto cleanup;
    }

    sss_status = sss_digest_context_init(&digest_ctx, pgSssSession, kAlgorithm_SSS_SHA256, kMode_SSS_Digest);
    if (kStatus_SSS_Success != sss_status) {
        LOG_E("sss_digest_context_init failed");
        goto cleanup;
    }

    sss_status = sss_digest_one_go(&digest_ctx, input, inputLen, digest, &digestLen);
    if (kStatus_SSS_Success != sss_status) {
        LOG_E("sss_digest_one_go failed");
        goto cleanup;
    }

    if (digest_ctx.session != NULL) {
        sss_digest_context_free(&digest_ctx);
    }

    sss_status = sss_key_object_init(&hostPublicKeyObject, pgKeyStore);
    if (kStatus_SSS_Success != sss_status) {
        LOG_E("sss_key_object_init failed");
        goto cleanup;
    }

    sss_status = sss_key_object_allocate_handle(&hostPublicKeyObject,
        keyId,
        kSSS_KeyPart_Public,
        kSSS_CipherType_EC_NIST_P,
        keylen,
        kKeyObject_Mode_Persistent);
    if (kStatus_SSS_Success != sss_status) {
        LOG_E("sss_key_object_allocate_handle failed");
        goto cleanup;
    }

    memcpy(publicKeyDer, publicKey, publicKeyLen);
    if (0 != set_secp256r1nist_header(publicKeyDer, &publicKeyDerLen)) {
        LOG_E("set_secp256r1nist_header failed");
        sss_status = kStatus_SSS_Fail;
        goto cleanup;
    }

    sss_status =
        sss_key_store_set_key(pgKeyStore, &hostPublicKeyObject, publicKeyDer, publicKeyDerLen, KEY_BIT_LENGTH, NULL, 0);
    if (kStatus_SSS_Success != sss_status) {
        LOG_E("sss_key_store_set_key failed");
        goto cleanup;
    }

    sss_status = sss_asymmetric_context_init(
        &verificationCtx, pgSssSession, &hostPublicKeyObject, kAlgorithm_SSS_ECDSA_SHA256, kMode_SSS_Verify);
    if (kStatus_SSS_Success != sss_status) {
        LOG_E("sss_asymmetric_context_init failed");
        goto cleanup;
    }

    sss_status = sss_asymmetric_verify_digest(&verificationCtx, digest, digestLen, signature, signatureLen);
    if (kStatus_SSS_Success != sss_status) {
        LOG_E("sss_asymmetric_verify_digest failed");
        goto cleanup;
    }

cleanup:
    if (digest_ctx.session != NULL) {
        sss_digest_context_free(&digest_ctx);
    }
    if (verificationCtx.session != NULL) {
        sss_asymmetric_context_free(&verificationCtx);
    }
    if (hostPublicKeyObject.keyStore != NULL) {
        sss_key_object_free(&hostPublicKeyObject);
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
        goto exit;
    }
    p   = pCert;
    end = pCert + certLen;

    /* Parse first sequence tag */
    ret = mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_SEQUENCE | MBEDTLS_ASN1_CONSTRUCTED);
    if (ret != 0) {
        LOG_E("Error parsing ASN.1 data : %d", __LINE__);
    }
    /* p now points to TBS bytes */
    /* Parse sequence tag of TBSCertificate */
    ret = mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_SEQUENCE | MBEDTLS_ASN1_CONSTRUCTED);
    if (ret != 0) {
        LOG_E("Error parsing ASN.1 data : %d", __LINE__);
    }
    /* p now points to Certificate version */
    /* Parse 0xA0 tag of Certificate version */
    ret = mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED);
    if (ret != 0) {
        LOG_E("Error parsing ASN.1 data : %d", __LINE__);
    }
    p += len;
    /* p now points to Certificate serial number */
    /* Parse MBEDTLS_ASN1_INTEGER tag of Certificate version */
    ret = mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_INTEGER);
    if (ret != 0) {
        LOG_E("Error parsing ASN.1 data : %d", __LINE__);
    }
    p += len;
    /* p now points to Certificate signature algorithm */
    /* Parse sequence tag of Certificate version */
    ret = mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_SEQUENCE | MBEDTLS_ASN1_CONSTRUCTED);
    if (ret != 0) {
        LOG_E("Error parsing ASN.1 data : %d", __LINE__);
    }
    p += len;
    /* p now points to Certificate Issuer */
    /* Parse sequence tag of Certificate version */
    ret = mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_SEQUENCE | MBEDTLS_ASN1_CONSTRUCTED);
    if (ret != 0) {
        LOG_E("Error parsing ASN.1 data : %d", __LINE__);
    }
    p += len;
    /* p now points to Certificate Validity */
    /* Parse sequence tag of Certificate version */
    ret = mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_SEQUENCE | MBEDTLS_ASN1_CONSTRUCTED);
    if (ret != 0) {
        LOG_E("Error parsing ASN.1 data : %d", __LINE__);
    }
    p += len;
    /* p now points to Certificate Subject */
    /* Parse sequence tag of Certificate version */
    ret = mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_SEQUENCE | MBEDTLS_ASN1_CONSTRUCTED);
    if (ret != 0) {
        LOG_E("Error parsing ASN.1 data : %d", __LINE__);
    }
    p += len;
    /* p now points to Certificate Subject Public Key Info */
    /* Parse sequence tag of Certificate version */
    ret = mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_SEQUENCE | MBEDTLS_ASN1_CONSTRUCTED);
    if (ret != 0) {
        LOG_E("Error parsing ASN.1 data : %d", __LINE__);
    }
    /* p now points to Certificate Public Key algorithm */
    /* Parse sequence tag of Certificate version */
    ret = mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_SEQUENCE | MBEDTLS_ASN1_CONSTRUCTED);
    if (ret != 0) {
        LOG_E("Error parsing ASN.1 data : %d", __LINE__);
    }
    p += len;
    /* p now points to Certificate Public Key */
    /* Parse sequence tag of Certificate version */
    ret = mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_BIT_STRING);
    if (ret != 0) {
        LOG_E("Error parsing ASN.1 data : %d", __LINE__);
    }
    if (*p == 0x00) {
        ENSURE_OR_GO_EXIT(len > 2);
        p++;
        len--;
    }
    ENSURE_OR_GO_EXIT(len > 1);
    p++;
    len--;

    do {
        if ((p + len) > end) {
            LOG_E("Invalid certificate object");
            *pucPublicKeylen = 0;
            break;
        }
        else if (len > *pucPublicKeylen) {
            LOG_E("Insufficient buffer");
            *pucPublicKeylen = 0;
            break;
        }
        //Compressed Public Key 32Bytes or Uncompressed Public Key 64
        if ((len == COMPRESSED_KEY_SIZE) || (len == UNCOMPRESSED_KEY_SIZE) || (len == UNCOMPRESSED_WITH_PAD_KEY_SIZE)) {
            if (NULL == pPucPublicKey) {
                LOG_E("NULL buffer to copy pPucPublicKey");
                goto exit;
            }
            memcpy((void *)pPucPublicKey, (void *)p, len);
            *pucPublicKeylen = len;
        }
        else {
            LOG_E("Invalid certificate public key length %d(%d)", len, __LINE__);
            *pucPublicKeylen = 0;
        }
    } while (0);
exit:
    return;
}

static int nxVerifyPuc(
    uint8_t *response_buffer, size_t response_size, uint16_t pucCertOffset, uint16_t manufacturerCertLenOffset)
{
    sss_status_t sss_status    = kStatus_SSS_Fail;
    int ret                    = -1;
    uint8_t mcertPublicKey[71] = {0};
    size_t mcertpublicKeylen   = sizeof(mcertPublicKey);
    uint8_t pucSignature[80]   = {0};
    size_t pucSignaturelen     = sizeof(pucSignature);
    uint8_t pucTbs[1024]       = {0};
    size_t pucTbslen           = sizeof(pucTbs);

    if (NULL == response_buffer) {
        LOG_E("Invalid input parameter");
        goto exit;
    }

    /* Certificate chain verification */
    if (response_size < (size_t)pucCertOffset) {
        LOG_W("Invalid cert offset");
        goto exit;
    }

    if (response_size < (size_t)manufacturerCertLenOffset) {
        LOG_W("Invalid cert offset");
        goto exit;
    }

    if (0 !=
        parseCertGetTBS(&response_buffer[pucCertOffset], (size_t)(response_size - pucCertOffset), pucTbs, &pucTbslen)) {
        LOG_W("Parsing Certificate TBS failed");
        goto exit;
    }

    parseCertGetSignature(
        &response_buffer[pucCertOffset], (size_t)(response_size - pucCertOffset), pucSignature, &pucSignaturelen);

    parseCertGetPublicKey(&response_buffer[manufacturerCertLenOffset],
        (size_t)(pucCertOffset - manufacturerCertLenOffset),
        &mcertPublicKey[1],
        &mcertpublicKeylen);
    if (mcertpublicKeylen > DIGEST_SIZE_BYTES) {
        /* Uncompressed key */
        mcertPublicKey[0] = 0x04;
        mcertpublicKeylen++;
    }
    else {
        LOG_W(
            "Compressed key found in manufacturer certificate. Cannot verify certificate chain\n\t\
Add your implementation to create uncompressed key from a compressed key at %s:%d",
            __FUNCTION__,
            __LINE__);
        goto exit;
    }

    if (mcertpublicKeylen > sizeof(mcertPublicKey)) {
        LOG_W("Invalid key length");
        goto exit;
    }

    sss_status = nxVerifySignature(mcertPublicKey, mcertpublicKeylen, pucTbs, pucTbslen, pucSignature, pucSignaturelen);
    if (sss_status != kStatus_SSS_Success) {
        LOG_W("Failed to verify PUC certificate");
        goto exit;
    }
    else {
        LOG_I("PUC successfully verified");
    }

    ret = 0;

exit:
    return ret;
}

static int nxVerifyMcert(
    uint8_t *response_buffer, size_t response_size, uint16_t pucCertOffset, uint16_t manufacturerCertLenOffset)
{
    sss_status_t sss_status     = kStatus_SSS_Fail;
    int ret                     = -1;
    uint8_t rootcaPublicKey[71] = {0};
    size_t rootcapublicKeylen   = sizeof(rootcaPublicKey);
    uint8_t mcertSignature[80]  = {0};
    size_t mcertSignaturelen    = sizeof(mcertSignature);
    uint8_t mcertTbs[1024]      = {0};
    size_t mcertTbslen          = sizeof(mcertTbs);

    if (NULL == response_buffer) {
        LOG_E("Invalid input parameter");
        goto exit;
    }

    /* Certificate chain verification */

    if (response_size < (size_t)manufacturerCertLenOffset) {
        LOG_W("Invalid cert offset");
        goto exit;
    }

    if (pucCertOffset < manufacturerCertLenOffset) {
        LOG_E("Invalid cert offset");
        goto exit;
    }

    if (0 != parseCertGetTBS(&response_buffer[manufacturerCertLenOffset],
                 (size_t)(pucCertOffset - manufacturerCertLenOffset),
                 mcertTbs,
                 &mcertTbslen)) {
        LOG_E("Parsing Certificate TBS failed");
        goto exit;
    }

    parseCertGetSignature(&response_buffer[manufacturerCertLenOffset],
        (size_t)(pucCertOffset - manufacturerCertLenOffset),
        mcertSignature,
        &mcertSignaturelen);

    parseCertGetPublicKey(qi_rootca_cert, (size_t)(qi_rootca_cert_len), &rootcaPublicKey[1], &rootcapublicKeylen);
    if (rootcapublicKeylen > DIGEST_SIZE_BYTES) {
        /* Uncompressed key */
        rootcaPublicKey[0] = 0x04;
        rootcapublicKeylen++;
    }
    else {
        LOG_W("Compressed key found in root CA certificate. Cannot verify certificate chain");
        goto exit;
    }

    if (rootcapublicKeylen > sizeof(rootcaPublicKey)) {
        LOG_W("Invalid key length");
        goto exit;
    }

    sss_status = nxVerifySignature(
        rootcaPublicKey, rootcapublicKeylen, mcertTbs, mcertTbslen, mcertSignature, mcertSignaturelen);
    if (sss_status != kStatus_SSS_Success) {
        LOG_W("Failed to verify MCERT certificate");
        goto exit;
    }
    else {
        LOG_I("Manufacturer certificate successfully verified");
    }

    ret = 0;
exit:
    return ret;
}

static int nxVerifyCertificateChain(
    uint8_t *response_buffer, size_t response_size, uint16_t pucCertOffset, uint16_t manufacturerCertLenOffset)
{
    int ret = -1;

    if (0 != nxVerifyPuc(response_buffer, response_size, pucCertOffset, manufacturerCertLenOffset)) {
        LOG_W("Failed to verify PUC certificate");
        goto exit;
    }

    if (0 != nxVerifyMcert(response_buffer, response_size, pucCertOffset, manufacturerCertLenOffset)) {
        LOG_W("Failed to verify Manufacturer certificate. Did you update RootCA certificate in sa_qi_rootcert.c?");
        goto exit;
    }

    ret = 0;

exit:
    return ret;
}

int nxVerifyChallenge(uint8_t *pPublicKey,
    size_t publicKeyLen,
    uint8_t *pCertificateChainHash,
    uint8_t *pChallengeRequest,
    uint8_t *pChallengeResponse)
{
    int ret                               = -1;
    sss_status_t sss_status               = kStatus_SSS_Fail;
    uint8_t tbsAuth[TBS_AUTH_BUFFER_SIZE] = {0};
    uint8_t *pTbsAuth                     = &tbsAuth[0];
    uint8_t asn1Signature[72]             = {0};
    size_t asn1SignatureLen               = sizeof(asn1Signature);

    if ((NULL == pCertificateChainHash) || (NULL == pChallengeRequest) || (NULL == pChallengeResponse)) {
        goto cleanup;
    }

    *pTbsAuth++ = CHALLENGE_AUTH_RESPONSE_PREFIX;
    memcpy(pTbsAuth, pCertificateChainHash, DIGEST_SIZE_BYTES);
    pTbsAuth += DIGEST_SIZE_BYTES;
    memcpy(pTbsAuth, pChallengeRequest, MAX_CMD_SIZE_CHALLENGE);
    pTbsAuth += MAX_CMD_SIZE_CHALLENGE;
    memcpy(pTbsAuth, pChallengeResponse, 3);

    if (0 != EcRandSToSignature(&pChallengeResponse[3], DIGEST_SIZE_BYTES * 2, asn1Signature, &asn1SignatureLen)) {
        LOG_E("Cannot create ASN.1 signature");
        goto cleanup;
    }

    LOG_MAU8_I("TBSAuth", tbsAuth, sizeof(tbsAuth));

    sss_status =
        nxVerifySignature(pPublicKey, publicKeyLen, tbsAuth, TBS_AUTH_BUFFER_SIZE, asn1Signature, asn1SignatureLen);
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

    sss_status = sss_rng_context_init(&sss_rng_ctx, pgSssSession);
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

/* doc:start:qi-auth-port */
/* nx to implement RNG to get 16 byte nonce value
 * for authentication operation.
 * This API does not guarantee the randomness of the RNG.
 * User should make sure that the RNG seed is from a trusted source
 * and that the randomness of the source is NIST compliant
 */
int nx_getRandomNonce(uint8_t *nonce, size_t *pNonceLen)
{
    int ret              = -1;
    size_t random_length = 0;

    if (NULL == pNonceLen) {
        goto exit;
    }
    random_length = (*pNonceLen > NONCE_LEN) ? NONCE_LEN : (*pNonceLen);
    *pNonceLen    = random_length;

    ret = getRandom(nonce, random_length);
    if (0 != ret) {
        *pNonceLen = 0;
    }
    ret = 0;

exit:
    return ret;
}

/* doc:start:qi-auth- */
/* nx use to calculate digest of certificate chain
 * to verify received digest.
 */
int nx_getDigest(uint8_t *pInput, size_t inputLen, uint8_t *pOutput, size_t *pOutputLen)
{
    sss_status_t sss_status = kStatus_SSS_Fail;
    int ret                 = -1;
    sss_status              = nx_getDigestSHA256(pInput, inputLen, pOutput, pOutputLen);
    if (sss_status != kStatus_SSS_Success) {
        goto exit;
    }
    ret = 0;

exit:
    return ret;
}

/* Port to implement function which will
 * parse an X.509 certificate and extract the public key
 * from it.
 */
void nx_parseCertGetPublicKey(uint8_t *pCert, size_t certLen, uint8_t *pPublicKey, size_t *publicKeylen)
{
    parseCertGetPublicKey(pCert, certLen, pPublicKey, publicKeylen);
}

/* Port to implement function which will
 * verify the complete certificate chain as passed in certificate_chain
 */
int nx_VerifyCertificateChain(uint8_t *certificate_chain,
    size_t certificate_chain_size,
    uint16_t pucCertOffset,
    uint16_t manufacturerCertLenOffset)
{
    return nxVerifyCertificateChain(
        certificate_chain, certificate_chain_size, pucCertOffset, manufacturerCertLenOffset);
}

/* Port to implement function which will
 * verify CHALLENGE on host
 */
int nx_VerifyChallenge(uint8_t *pPublicKey,
    size_t publicKeyLen,
    uint8_t *pCertificateChainHash,
    uint8_t *pChallengeRequest,
    uint8_t *pChallengeResponse)
{
    return nxVerifyChallenge(pPublicKey, publicKeyLen, pCertificateChainHash, pChallengeRequest, pChallengeResponse);
}
/* doc:end:qi-auth-port */

void getPublicKeyFromSlot(uint8_t slot_id, uint8_t *pPublicKey, size_t *pPublicKeyLen)
{
    uint32_t keyId = QI_SLOT_ID_TO_KEY_ID(slot_id);
    readObjectWithChunking(keyId, QI_DBG_PUBLIC_KEY_OFFSET, QI_DBG_PUBLIC_KEY_LENGTH, pPublicKey, pPublicKeyLen);
}
