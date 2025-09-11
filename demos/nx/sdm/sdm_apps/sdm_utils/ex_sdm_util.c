/*
 *
 * Copyright 2025 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "fsl_sss_api.h"
#include "fsl_sss_nx_apis.h"
#include "sm_types.h"
#include "nxLog_msg.h"
#include "ex_sss_boot.h"
#include "nx_apdu.h"
#include "nx_enums.h"
#include "nxEnsure.h"
#include "fsl_sss_util_asn1_der.h"
#include "fsl_sss_nx_auth.h"
#include "ex_sdm_util.h"

int set_secp256r1nist_header(uint8_t *pbKey, size_t *pbKeyByteLen)
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

sss_status_t sdm_verify_data_signature(ex_sss_boot_ctx_t *pCtx,
    uint8_t *plainData,
    size_t plainDataLen,
    uint8_t *pubKey,
    size_t pubKeyLen,
    uint8_t *signData,
    size_t signDataLen)
{
    int ret                                            = -1;
    sss_status_t status                                = kStatus_SSS_Fail;
    uint8_t signHexData[EX_SSS_SDM_SDMSignatureLength] = {0};
    size_t signHexDataLen                              = sizeof(signHexData);
    uint8_t signatureAsn1[100]                         = {0};
    size_t signatureAsn1Len                            = sizeof(signatureAsn1);
    sss_object_t keyObject                             = {0};
    sss_asymmetric_t asymmCtx                          = {0};
    uint8_t publicKeyDer[KEY_BIT_LENGTH]               = {0};
    size_t publicKeyDerLen                             = pubKeyLen;

    if ((pCtx == NULL) || (signData == NULL) || (plainData == NULL)) {
        LOG_E("Invalid input parameter");
        goto cleanup;
    }

    // Set ECC Public Key
    status = sss_key_object_init(&keyObject, &pCtx->host_ks);
    ENSURE_OR_GO_CLEANUP(kStatus_SSS_Success == status);

    status = sss_key_object_allocate_handle(&keyObject,
        MAKE_TEST_ID(__LINE__),
        kSSS_KeyPart_Public,
        EX_SSS_SDM_ECC_CURVE_TYPE,
        256 / 8,
        kKeyObject_Mode_Transient);
    ENSURE_OR_GO_CLEANUP(kStatus_SSS_Success == status);

    LOG_I("Verify with ECC public key");
    LOG_MAU8_D("Public key:", pubKey, pubKeyLen);

    memcpy(publicKeyDer, pubKey, pubKeyLen);
    if (0 != set_secp256r1nist_header(publicKeyDer, &publicKeyDerLen)) {
        LOG_E("set_secp256r1nist_header failed");
        status = kStatus_SSS_Fail;
        goto cleanup;
    }
    LOG_MAU8_D("publicKeyDer ", publicKeyDer, publicKeyDerLen);
    status = sss_key_store_set_key(&pCtx->host_ks, &keyObject, publicKeyDer, publicKeyDerLen, 256, NULL, 0);
    ENSURE_OR_GO_CLEANUP(kStatus_SSS_Success == status);

    // Signature in Hex. Comes from read out data.
    ret = sdm_ascii_to_hex(signData, signDataLen, signHexData, &signHexDataLen);
    ENSURE_OR_GO_CLEANUP(0 == ret);
    LOG_MAU8_D("Signature in hex:", signHexData, signHexDataLen);

    //Why is this needed?
    status = sss_util_encode_asn1_signature(signatureAsn1, &signatureAsn1Len, signHexData, signHexDataLen);
    ENSURE_OR_GO_CLEANUP(kStatus_SSS_Success == status);
    LOG_MAU8_I("Signature in ASN.1:", signatureAsn1, signatureAsn1Len);

    // Verify Signature value
    status = sss_asymmetric_context_init(
        &asymmCtx, &pCtx->host_session, &keyObject, kAlgorithm_SSS_SHA256, kMode_SSS_Verify);
    ENSURE_OR_GO_CLEANUP(kStatus_SSS_Success == status);

    status = sss_asymmetric_verify_one_go(&asymmCtx, plainData, plainDataLen, signatureAsn1, signatureAsn1Len);
    ENSURE_OR_GO_CLEANUP(kStatus_SSS_Success == status);

    LOG_I("Verify signature passed.");

cleanup:

    if (asymmCtx.session != NULL) {
        sss_asymmetric_context_free(&asymmCtx);
    }
    if (keyObject.keyStore != NULL) {
        sss_key_object_free(&keyObject);
    }

    return status;
}

void parseCertGetPublicKey(uint8_t *pCert, size_t certLen, uint8_t *pPucPublicKey, size_t *pucPublicKeylen)
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
        else {
            *pucPublicKeylen = 0;
        }
    }

    return;

exit:
    *pucPublicKeylen = 0;
}

int sdm_ascii_to_hex(uint8_t *asciiBuf, size_t asciiBufLen, uint8_t *hexBuf, size_t *hexBufLen)
{
    int ret                                                           = -1;
    size_t i                                                          = 0;
    long int val                                                      = -1;
    uint8_t asciiData[EX_SSS_SDM_ENCRYPTED_ASCII_PLACEHOLDER_MAX_LEN] = {0};
    char asciiByte[3]                                                 = {0}; // xx'0'

    if ((asciiBuf == NULL) || (hexBuf == NULL) || (hexBufLen == NULL) ||
        (asciiBufLen > EX_SSS_SDM_ENCRYPTED_ASCII_PLACEHOLDER_MAX_LEN)) {
        LOG_E("Invalid input parameter");
        goto exit;
    }

    if ((asciiBufLen % 2) != 0) {
        LOG_E("ASCII buffer length is odd");
        goto exit;
    }

    if ((*hexBufLen) < (asciiBufLen / 2)) {
        LOG_E("Hex buffer length is not enough");
        goto exit;
    }

    memcpy(asciiData, asciiBuf, asciiBufLen);

    for (i = 0; i < (asciiBufLen / 2); i++) {
        memset(&(asciiByte[0]), 0, sizeof(asciiByte));
        memcpy(&(asciiByte[0]), &(asciiBuf[i * 2]), 2);

        val = strtol(asciiByte, NULL, 16);
        if ((val < 0) || (val > UINT8_MAX)) {
            LOG_E("Integer conversion failed");
            goto exit;
        }
        hexBuf[i] = (uint8_t)val;
    }
    *hexBufLen = (asciiBufLen / 2);

    ret = 0;
exit:
    return ret;
}

sss_status_t sdm_decrypt_picc_data(
    ex_sss_boot_ctx_t *pCtx, uint8_t *encData, size_t encDataLen, uint8_t *outPlainData, size_t *outPlainDataLen)
{
    sss_status_t status                                              = kStatus_SSS_Fail;
    int ret                                                          = -1;
    uint8_t piccData[EX_SSS_SDM_ENCRYPTED_ASCII_PLACEHOLDER_MAX_LEN] = {0};
    size_t piccDataLen                                               = sizeof(piccData);
    uint8_t iv[]                                                     = EX_SSS_SDM_PICCDATA_IV_VALUE;
    size_t ivlen                                                     = sizeof(iv);
    sss_symmetric_t symmCtx                                          = {0};
    sss_object_t metaReadKeyObj                                      = {0};
    uint8_t metaReadKey[]                                            = EX_SSS_SDM_META_READ_AES_KEY;
    size_t metaReadKeySize                                           = sizeof(metaReadKey);

    if ((pCtx == NULL) || (encData == NULL) || (outPlainData == NULL) || (outPlainDataLen == NULL)) {
        LOG_E("Invalid input parameter");
        goto cleanup;
    }

    // Set Key_SDMMetaRead Value
    status = sss_key_object_init(&metaReadKeyObj, &pCtx->host_ks);
    ENSURE_OR_GO_CLEANUP(kStatus_SSS_Success == status);

    status = sss_key_object_allocate_handle(&metaReadKeyObj,
        MAKE_TEST_ID(__LINE__),
        kSSS_KeyPart_Default,
        kSSS_CipherType_AES,
        metaReadKeySize,
        kKeyObject_Mode_Transient);
    ENSURE_OR_GO_CLEANUP(kStatus_SSS_Success == status);

    status = sss_key_store_set_key(
        &pCtx->host_ks, &metaReadKeyObj, metaReadKey, metaReadKeySize, metaReadKeySize * 8, NULL, 0);
    ENSURE_OR_GO_CLEANUP(kStatus_SSS_Success == status);

    // PICC data from ASCII to HEX
    ret = sdm_ascii_to_hex(encData, encDataLen, piccData, &piccDataLen);
    ENSURE_OR_GO_CLEANUP(0 == ret);
    ret = -1;

    if (piccDataLen > *outPlainDataLen) {
        LOG_E("Data buffer not enought");
        goto cleanup;
    }

    status = sss_symmetric_context_init(
        &symmCtx, &pCtx->host_session, &metaReadKeyObj, kAlgorithm_SSS_AES_CBC, kMode_SSS_Decrypt);
    ENSURE_OR_GO_CLEANUP(kStatus_SSS_Success == status);

    status = sss_cipher_one_go(&symmCtx, iv, ivlen, piccData, outPlainData, piccDataLen);
    ENSURE_OR_GO_CLEANUP(kStatus_SSS_Success == status);

    *outPlainDataLen = piccDataLen;
    LOG_MAU8_I("Decrypted PICC data in HEX", outPlainData, *outPlainDataLen);

cleanup:

    if (symmCtx.session != NULL) {
        sss_symmetric_context_free(&symmCtx);
    }
    if (metaReadKeyObj.keyStore != NULL) {
        sss_key_object_free(&metaReadKeyObj);
    }

    return status;
}