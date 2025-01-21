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
#include "ex_sdm_file_read.h"
#include "nxEnsure.h"

static ex_sss_boot_ctx_t gex_sss_boot_ctx = {0};

#define EX_SSS_BOOT_PCONTEXT (&gex_sss_boot_ctx)
#define EX_SSS_BOOT_EXPOSE_ARGC_ARGV 0

#ifndef MAKE_TEST_ID
#define MAKE_TEST_ID(ID) (0xEF000000u + ID)
#endif /* MAKE_TEST_ID */

#include <ex_sss_main_inc.h>

static int sdm_ascii_to_hex(uint8_t *asciiBuf, size_t asciiBufLen, uint8_t *hexBuf, size_t *hexBufLen);
static sss_status_t sdm_decrypt_picc_data(
    ex_sss_boot_ctx_t *pCtx, uint8_t *encData, size_t encDataLen, uint8_t *outPlainData, size_t *outPlainDataLen);
static sss_status_t sdm_calculate_session_keys(ex_sss_boot_ctx_t *pCtx,
    uint8_t *vcuid,
    size_t vcuidLen,
    uint32_t sdmReadCtr,
    sss_object_t *keyEncObj,
    sss_object_t *keyMacObj);
static sss_status_t sdm_decrypt_file_data(ex_sss_boot_ctx_t *pCtx,
    uint8_t *encData,
    size_t encDataLen,
    uint32_t sdmReadCtr,
    sss_object_t *keyEncObj,
    uint8_t *plainFileData,
    size_t *plainFileDataLen);
static sss_status_t sdm_verify_data_signature(
    ex_sss_boot_ctx_t *pCtx, uint8_t *plainData, size_t plainDataLen, uint8_t *signData, size_t signDataLen);

static int sdm_ascii_to_hex(uint8_t *asciiBuf, size_t asciiBufLen, uint8_t *hexBuf, size_t *hexBufLen)
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

static sss_status_t sdm_decrypt_picc_data(
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

static sss_status_t sdm_calculate_session_keys(ex_sss_boot_ctx_t *pCtx,
    uint8_t *vcuid,
    size_t vcuidLen,
    uint32_t sdmReadCtr,
    sss_object_t *keyEncObj,
    sss_object_t *keyMacObj)
{
    sss_status_t status = kStatus_SSS_Fail;
    /* clang-format off */
    uint8_t sv1[EX_SSS_SDM_SV_BUF_MAX_LEN]  = {0xC3, 0x3C, 0x00, 0x01, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    uint8_t sv2[EX_SSS_SDM_SV_BUF_MAX_LEN]  = {0x3C, 0xC3, 0x00, 0x01, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    uint8_t sv1a[EX_SSS_SDM_SV_BUF_MAX_LEN] = {0xC3, 0x3C, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    uint8_t sv1b[EX_SSS_SDM_SV_BUF_MAX_LEN] = {0xC3, 0x3C, 0x00, 0x02, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    uint8_t sv2a[EX_SSS_SDM_SV_BUF_MAX_LEN] = {0x3C, 0xC3, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    uint8_t sv2b[EX_SSS_SDM_SV_BUF_MAX_LEN] = {0x3C, 0xC3, 0x00, 0x02, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    /* clang-format on */

    size_t svindex = EX_SSS_SDM_SV_CONSTANT_BYTES_LEN;
    size_t sv1Len  = 0;
    size_t sv2Len  = 0;
    size_t sv1aLen = 0;
    size_t sv2aLen = 0;
    size_t sv1bLen = 0;
    size_t sv2bLen = 0;

    uint8_t keyEnc[EX_SSS_SDM_AES_KEY_BIT_LEN_256 / 8] = {0}; // Can be 128 or 256 bit
    size_t keyEncLen                                   = sizeof(keyEnc);
    size_t tmpKeyEncLen                                = sizeof(keyEnc);
    uint8_t keyMac[EX_SSS_SDM_AES_KEY_BIT_LEN_256 / 8] = {0};
    size_t keyMacLen                                   = sizeof(keyMac);
    size_t tmpkeyMacLen                                = sizeof(keyMac);
    sss_object_t fileReadKeyObj                        = {0};
    uint8_t fileReadKey[]                              = EX_SSS_SDM_FILE_READ_AES_KEY;
    size_t fileReadKeySize                             = sizeof(fileReadKey);
    sss_mac_t macCtx                                   = {0};

    if ((pCtx == NULL) || (vcuid == NULL) || (keyEncObj == NULL) || (keyMacObj == NULL)) {
        LOG_E("Invalid input parameter");
        goto cleanup;
    }

    if ((vcuidLen != EX_SSS_SDM_7BYTE_VCUID_LENGTH_IN_PICCDATA) &&
        (vcuidLen != EX_SSS_SDM_10BYTE_VCUID_LENGTH_IN_PICCDATA)) {
        LOG_E("Invalid input parameter");
        goto cleanup;
    }

    // Set Key_SDMMetaRead Value
    status = sss_key_object_init(&fileReadKeyObj, &pCtx->host_ks);
    ENSURE_OR_GO_CLEANUP(kStatus_SSS_Success == status);

    status = sss_key_object_allocate_handle(&fileReadKeyObj,
        MAKE_TEST_ID(__LINE__),
        kSSS_KeyPart_Default,
        kSSS_CipherType_AES,
        fileReadKeySize,
        kKeyObject_Mode_Transient);
    ENSURE_OR_GO_CLEANUP(kStatus_SSS_Success == status);

    status = sss_key_store_set_key(
        &pCtx->host_ks, &fileReadKeyObj, fileReadKey, fileReadKeySize, fileReadKeySize * 8, NULL, 0);
    ENSURE_OR_GO_CLEANUP(kStatus_SSS_Success == status);

    if (fileReadKeySize == EX_SSS_SDM_AES_KEY_BIT_LEN_128 / 8) {
        // SV1 = 0xC3||0x3C||0x00||0x01||0x00||0x80||VCUID||SDMReadCtr[||ZeroPadding]
        // SV2 = 0x3C||0xC3||0x00||0x01||0x00||0x80[||VCUID][||SDMReadCtr][||ZeroPadding]

        if (vcuidLen == EX_SSS_SDM_7BYTE_VCUID_LENGTH_IN_PICCDATA) {
            sv1Len  = EX_SSS_SDM_SV_CONSTANT_BYTES_LEN;
            svindex = EX_SSS_SDM_SV_CONSTANT_BYTES_LEN;
            memcpy(&sv1[svindex], vcuid, vcuidLen);
            sv1Len += vcuidLen;
            svindex += vcuidLen;
            sv1[svindex + 0] = (uint8_t)(sdmReadCtr & 0xFF);
            sv1[svindex + 1] = (uint8_t)((sdmReadCtr >> 8) & 0xFF);
            sv1[svindex + 2] = (uint8_t)((sdmReadCtr >> 16) & 0xFF);
            sv1Len += EX_SSS_SDM_READ_CNTR_LEN;

            sv2Len  = EX_SSS_SDM_SV_CONSTANT_BYTES_LEN;
            svindex = EX_SSS_SDM_SV_CONSTANT_BYTES_LEN;
            memcpy(&sv2[svindex], vcuid, vcuidLen);
            sv2Len += vcuidLen;
            svindex += vcuidLen;
            sv2[svindex + 0] = (uint8_t)(sdmReadCtr & 0xFF);
            sv2[svindex + 1] = (uint8_t)((sdmReadCtr >> 8) & 0xFF);
            sv2[svindex + 2] = (uint8_t)((sdmReadCtr >> 16) & 0xFF);
            sv2Len += EX_SSS_SDM_READ_CNTR_LEN;
        }
        else if (vcuidLen == EX_SSS_SDM_10BYTE_VCUID_LENGTH_IN_PICCDATA) {
            sv1Len  = EX_SSS_SDM_SV_CONSTANT_BYTES_LEN;
            svindex = EX_SSS_SDM_SV_CONSTANT_BYTES_LEN;
            memcpy(&sv1[svindex], vcuid, vcuidLen);
            sv1Len += vcuidLen;
            svindex += vcuidLen;
            sv1[svindex + 0] = (uint8_t)(sdmReadCtr & 0xFF);
            sv1[svindex + 1] = (uint8_t)((sdmReadCtr >> 8) & 0xFF);
            sv1[svindex + 2] = (uint8_t)((sdmReadCtr >> 16) & 0xFF);
            svindex += EX_SSS_SDM_READ_CNTR_LEN;
            sv1Len += EX_SSS_SDM_READ_CNTR_LEN;
            memset(&sv1[svindex], EX_SSS_SDM_ZERO_PADDING_BYTE, EX_SSS_SDM_ZERO_PADDING_LEN);
            sv1Len += EX_SSS_SDM_ZERO_PADDING_LEN;

            sv2Len  = EX_SSS_SDM_SV_CONSTANT_BYTES_LEN;
            svindex = EX_SSS_SDM_SV_CONSTANT_BYTES_LEN;
            memcpy(&sv2[svindex], vcuid, vcuidLen);
            sv2Len += vcuidLen;
            svindex += vcuidLen;
            sv2[svindex + 0] = (uint8_t)(sdmReadCtr & 0xFF);
            sv2[svindex + 1] = (uint8_t)((sdmReadCtr >> 8) & 0xFF);
            sv2[svindex + 2] = (uint8_t)((sdmReadCtr >> 16) & 0xFF);
            svindex += EX_SSS_SDM_READ_CNTR_LEN;
            sv2Len += EX_SSS_SDM_READ_CNTR_LEN;
            memset(&sv2[svindex], EX_SSS_SDM_ZERO_PADDING_BYTE, EX_SSS_SDM_ZERO_PADDING_LEN);
            sv2Len += EX_SSS_SDM_ZERO_PADDING_LEN;
        }

        // K_SesSDMFileReadENC = MAC(K_SDMFileRead, SV1)
        // K_SesSDMFileReadMAC = MAC(K_SDMFileRead, SV2)
        status =
            sss_mac_context_init(&macCtx, &pCtx->host_session, &fileReadKeyObj, kAlgorithm_SSS_CMAC_AES, kMode_SSS_Mac);
        ENSURE_OR_GO_CLEANUP(kStatus_SSS_Success == status);

        status = sss_mac_one_go(&macCtx, &sv1[0], sv1Len, keyEnc, &keyEncLen);
        ENSURE_OR_GO_CLEANUP(kStatus_SSS_Success == status);

        status = sss_mac_one_go(&macCtx, &sv2[0], sv2Len, keyMac, &keyMacLen);
        ENSURE_OR_GO_CLEANUP(kStatus_SSS_Success == status);
    }
    else if (fileReadKeySize == EX_SSS_SDM_AES_KEY_BIT_LEN_256 / 8) {
        // SV1a = 0xC3||0x3C||0x00||0x01||0x01||0x00||VCUID||SDMReadCtr[||ZeroPadding]
        // SV1b = 0xC3||0x3C||0x00||0x02||0x01||0x00||VCUID||SDMReadCtr[||ZeroPadding]
        // SV2a = 0x3C||0xC3||0x00||0x01||0x01||0x00[||VCUID][||SDMReadCtr][||ZeroPadding]
        // SV2b = 0x3C||0xC3||0x00||0x02||0x01||0x00[||VCUID][||SDMReadCtr][||ZeroPadding]
        if (vcuidLen == EX_SSS_SDM_7BYTE_VCUID_LENGTH_IN_PICCDATA) {
            sv1aLen = EX_SSS_SDM_SV_CONSTANT_BYTES_LEN;
            svindex = EX_SSS_SDM_SV_CONSTANT_BYTES_LEN;
            memcpy(&sv1a[svindex], vcuid, vcuidLen);
            sv1aLen += vcuidLen;
            svindex += vcuidLen;
            sv1a[svindex + 0] = (uint8_t)(sdmReadCtr & 0xFF);
            sv1a[svindex + 1] = (uint8_t)((sdmReadCtr >> 8) & 0xFF);
            sv1a[svindex + 2] = (uint8_t)((sdmReadCtr >> 16) & 0xFF);
            sv1aLen += EX_SSS_SDM_READ_CNTR_LEN;

            sv1bLen = EX_SSS_SDM_SV_CONSTANT_BYTES_LEN;
            svindex = EX_SSS_SDM_SV_CONSTANT_BYTES_LEN;
            memcpy(&sv1b[svindex], vcuid, vcuidLen);
            sv1bLen += vcuidLen;
            svindex += vcuidLen;
            sv1b[svindex]   = (uint8_t)(sdmReadCtr & 0xFF);
            sv1b[++svindex] = (uint8_t)((sdmReadCtr >> 8) & 0xFF);
            sv1b[++svindex] = (uint8_t)((sdmReadCtr >> 16) & 0xFF);
            sv1bLen += EX_SSS_SDM_READ_CNTR_LEN;

            sv2aLen = EX_SSS_SDM_SV_CONSTANT_BYTES_LEN;
            svindex = EX_SSS_SDM_SV_CONSTANT_BYTES_LEN;
            memcpy(&sv2a[svindex], vcuid, vcuidLen);
            sv2aLen += vcuidLen;
            svindex += vcuidLen;
            sv2a[svindex + 0] = (uint8_t)(sdmReadCtr & 0xFF);
            sv2a[svindex + 1] = (uint8_t)((sdmReadCtr >> 8) & 0xFF);
            sv2a[svindex + 2] = (uint8_t)((sdmReadCtr >> 16) & 0xFF);
            sv2aLen += EX_SSS_SDM_READ_CNTR_LEN;

            sv2bLen = EX_SSS_SDM_SV_CONSTANT_BYTES_LEN;
            svindex = EX_SSS_SDM_SV_CONSTANT_BYTES_LEN;
            memcpy(&sv2b[svindex], vcuid, vcuidLen);
            sv2bLen += vcuidLen;
            svindex += vcuidLen;
            sv2b[svindex + 0] = (uint8_t)(sdmReadCtr & 0xFF);
            sv2b[svindex + 1] = (uint8_t)((sdmReadCtr >> 8) & 0xFF);
            sv2b[svindex + 2] = (uint8_t)((sdmReadCtr >> 16) & 0xFF);
            sv2bLen += EX_SSS_SDM_READ_CNTR_LEN;
        }
        else if (vcuidLen == EX_SSS_SDM_10BYTE_VCUID_LENGTH_IN_PICCDATA) {
            sv1aLen = EX_SSS_SDM_SV_CONSTANT_BYTES_LEN;
            svindex = EX_SSS_SDM_SV_CONSTANT_BYTES_LEN;
            memcpy(&sv1a[svindex], vcuid, vcuidLen);
            sv1aLen += vcuidLen;
            svindex += vcuidLen;
            sv1a[svindex + 0] = (uint8_t)(sdmReadCtr & 0xFF);
            sv1a[svindex + 1] = (uint8_t)((sdmReadCtr >> 8) & 0xFF);
            sv1a[svindex + 2] = (uint8_t)((sdmReadCtr >> 16) & 0xFF);
            svindex += EX_SSS_SDM_READ_CNTR_LEN;
            sv1aLen += EX_SSS_SDM_READ_CNTR_LEN;
            memset(&sv1a[svindex], EX_SSS_SDM_ZERO_PADDING_BYTE, EX_SSS_SDM_ZERO_PADDING_LEN);
            sv1aLen += EX_SSS_SDM_ZERO_PADDING_LEN;

            sv1bLen = EX_SSS_SDM_SV_CONSTANT_BYTES_LEN;
            svindex = EX_SSS_SDM_SV_CONSTANT_BYTES_LEN;
            memcpy(&sv1b[svindex], vcuid, vcuidLen);
            sv1bLen += vcuidLen;
            svindex += vcuidLen;
            sv1b[svindex + 0] = (uint8_t)(sdmReadCtr & 0xFF);
            sv1b[svindex + 1] = (uint8_t)((sdmReadCtr >> 8) & 0xFF);
            sv1b[svindex + 2] = (uint8_t)((sdmReadCtr >> 16) & 0xFF);
            svindex += EX_SSS_SDM_READ_CNTR_LEN;
            sv1bLen += EX_SSS_SDM_READ_CNTR_LEN;
            memset(&sv1b[svindex], EX_SSS_SDM_ZERO_PADDING_BYTE, EX_SSS_SDM_ZERO_PADDING_LEN);
            sv1bLen += EX_SSS_SDM_ZERO_PADDING_LEN;

            sv2aLen = EX_SSS_SDM_SV_CONSTANT_BYTES_LEN;
            svindex = EX_SSS_SDM_SV_CONSTANT_BYTES_LEN;
            memcpy(&sv2a[svindex], vcuid, vcuidLen);
            sv2aLen += vcuidLen;
            svindex += vcuidLen;
            sv2a[svindex + 0] = (uint8_t)(sdmReadCtr & 0xFF);
            sv2a[svindex + 1] = (uint8_t)((sdmReadCtr >> 8) & 0xFF);
            sv2a[svindex + 2] = (uint8_t)((sdmReadCtr >> 16) & 0xFF);
            svindex += EX_SSS_SDM_READ_CNTR_LEN;
            sv2aLen += EX_SSS_SDM_READ_CNTR_LEN;
            memset(&sv2a[svindex], EX_SSS_SDM_ZERO_PADDING_BYTE, EX_SSS_SDM_ZERO_PADDING_LEN);
            sv2aLen += EX_SSS_SDM_ZERO_PADDING_LEN;

            sv2bLen = EX_SSS_SDM_SV_CONSTANT_BYTES_LEN;
            svindex = EX_SSS_SDM_SV_CONSTANT_BYTES_LEN;
            memcpy(&sv2b[svindex], vcuid, vcuidLen);
            sv2bLen += vcuidLen;
            svindex += vcuidLen;
            sv2b[svindex + 0] = (uint8_t)(sdmReadCtr & 0xFF);
            sv2b[svindex + 1] = (uint8_t)((sdmReadCtr >> 8) & 0xFF);
            sv2b[svindex + 2] = (uint8_t)((sdmReadCtr >> 16) & 0xFF);
            svindex += EX_SSS_SDM_READ_CNTR_LEN;
            sv2bLen += EX_SSS_SDM_READ_CNTR_LEN;
            memset(&sv2b[svindex], EX_SSS_SDM_ZERO_PADDING_BYTE, EX_SSS_SDM_ZERO_PADDING_LEN);
            sv2bLen += EX_SSS_SDM_ZERO_PADDING_LEN;
        }
        // K_SesSDMFileReadENC = MAC(KSDMFileRead, SV1a)||MAC(KSDMFileRead, SV1b)
        // K_SesSDMFileReadMAC = MAC(KSDMFileRead, SV2a)||MAC(KSDMFileRead, SV2b)
        status =
            sss_mac_context_init(&macCtx, &pCtx->host_session, &fileReadKeyObj, kAlgorithm_SSS_CMAC_AES, kMode_SSS_Mac);
        ENSURE_OR_GO_CLEANUP(kStatus_SSS_Success == status);

        keyEncLen    = 0;
        tmpKeyEncLen = sizeof(keyEnc);
        status       = sss_mac_one_go(&macCtx, sv1a, sv1aLen, &(keyEnc[0]), &tmpKeyEncLen); // First part of enc key
        ENSURE_OR_GO_CLEANUP(kStatus_SSS_Success == status);
        keyEncLen += tmpKeyEncLen;

        tmpKeyEncLen = sizeof(keyEnc);
        status       = sss_mac_one_go(&macCtx, sv1b, sv1bLen, &(keyEnc[16]), &tmpKeyEncLen); // Second part of enc key
        ENSURE_OR_GO_CLEANUP(kStatus_SSS_Success == status);
        keyEncLen += tmpKeyEncLen;

        keyMacLen    = 0;
        tmpkeyMacLen = sizeof(keyMac);
        status       = sss_mac_one_go(&macCtx, sv2a, sv2aLen, &keyMac[0], &tmpkeyMacLen); // First part of mac key
        ENSURE_OR_GO_CLEANUP(kStatus_SSS_Success == status);
        keyMacLen += tmpkeyMacLen;

        tmpkeyMacLen = sizeof(keyMac);
        status       = sss_mac_one_go(&macCtx, sv2b, sv2bLen, &keyMac[16], &tmpkeyMacLen); // Second part of mac key
        ENSURE_OR_GO_CLEANUP(kStatus_SSS_Success == status);
        keyMacLen += tmpkeyMacLen;
    }
    else {
        LOG_E("Invalid key size.");
        goto cleanup;
    }

    // Set ENC and MAC key object
    status = sss_key_object_init(keyEncObj, &pCtx->host_ks);
    ENSURE_OR_GO_CLEANUP(kStatus_SSS_Success == status);

    status = sss_key_object_allocate_handle(keyEncObj,
        MAKE_TEST_ID(__LINE__),
        kSSS_KeyPart_Default,
        kSSS_CipherType_AES,
        fileReadKeySize,
        kKeyObject_Mode_Transient);
    ENSURE_OR_GO_CLEANUP(kStatus_SSS_Success == status);

    status = sss_key_store_set_key(&pCtx->host_ks, keyEncObj, keyEnc, keyEncLen, fileReadKeySize * 8, NULL, 0);
    ENSURE_OR_GO_CLEANUP(kStatus_SSS_Success == status);

    status = sss_key_object_init(keyMacObj, &pCtx->host_ks);
    ENSURE_OR_GO_CLEANUP(kStatus_SSS_Success == status);

    status = sss_key_object_allocate_handle(keyMacObj,
        MAKE_TEST_ID(__LINE__),
        kSSS_KeyPart_Default,
        kSSS_CipherType_AES,
        fileReadKeySize,
        kKeyObject_Mode_Transient);
    ENSURE_OR_GO_CLEANUP(kStatus_SSS_Success == status);

    status = sss_key_store_set_key(&pCtx->host_ks, keyMacObj, keyMac, keyMacLen, fileReadKeySize * 8, NULL, 0);
    ENSURE_OR_GO_CLEANUP(kStatus_SSS_Success == status);

cleanup:

    if (macCtx.session != NULL) {
        sss_mac_context_free(&macCtx);
    }
    // Release K_SDMFileRead
    if (fileReadKeyObj.keyStore != NULL) {
        sss_key_object_free(&fileReadKeyObj);
    }

    return status;
}

static sss_status_t sdm_decrypt_file_data(ex_sss_boot_ctx_t *pCtx,
    uint8_t *encData,
    size_t encDataLen,
    uint32_t sdmReadCtr,
    sss_object_t *keyEncObj,
    uint8_t *plainFileData,
    size_t *plainFileDataLen)
{
    sss_status_t status                          = kStatus_SSS_Fail;
    int ret                                      = -1;
    uint8_t encHexData[EX_SSS_SDM_SDMENCLength]  = {0};
    size_t encHexDataLen                         = sizeof(encHexData);
    uint8_t iv[EX_SSS_SDM_IV_DATA_LENGTH]        = {0};
    size_t ivLen                                 = sizeof(iv);
    uint8_t dataForIV[EX_SSS_SDM_IV_DATA_LENGTH] = {0};
    uint8_t sdmEncIV[EX_SSS_SDM_IV_DATA_LENGTH]  = {0};
    size_t sdmEncIVLen                           = sizeof(sdmEncIV);
    sss_symmetric_t symmCtx                      = {0};

    if ((pCtx == NULL) || (encData == NULL) || (keyEncObj == NULL) || (plainFileData == NULL) ||
        (plainFileDataLen == NULL)) {
        LOG_E("Invalid input parameter");
        goto exit;
    }

    // Enc data in Hex
    ret = sdm_ascii_to_hex(encData, encDataLen, encHexData, &encHexDataLen);
    ENSURE_OR_GO_EXIT(0 == ret);
    LOG_MAU8_D("SDMENCFileData in HEX", encHexData, encHexDataLen);

    // Enough plain data buffer
    ENSURE_OR_GO_EXIT(*plainFileDataLen >= encHexDataLen);

    // Calculate SDM enc IV.
    dataForIV[0] = (uint8_t)(sdmReadCtr & 0xFF);
    dataForIV[1] = (uint8_t)((sdmReadCtr >> 8) & 0xFF);
    dataForIV[2] = (uint8_t)((sdmReadCtr >> 16) & 0xFF);
    status =
        sss_symmetric_context_init(&symmCtx, &pCtx->host_session, keyEncObj, kAlgorithm_SSS_AES_CBC, kMode_SSS_Encrypt);
    ENSURE_OR_GO_EXIT(kStatus_SSS_Success == status);

    status = sss_cipher_one_go(&symmCtx, iv, ivLen, dataForIV, sdmEncIV, sizeof(dataForIV));
    if (status != kStatus_SSS_Success) {
        if (symmCtx.session != NULL) {
            sss_symmetric_context_free(&symmCtx);
        }
        goto exit;
    }

    if (symmCtx.session != NULL) {
        sss_symmetric_context_free(&symmCtx);
    }

    LOG_MAU8_D("IV used for decrypt SDMENCFileData", sdmEncIV, sizeof(dataForIV));

    // Decrpyt SDMEnc Data
    status =
        sss_symmetric_context_init(&symmCtx, &pCtx->host_session, keyEncObj, kAlgorithm_SSS_AES_CBC, kMode_SSS_Decrypt);
    ENSURE_OR_GO_EXIT(kStatus_SSS_Success == status);

    status = sss_cipher_one_go(&symmCtx, sdmEncIV, sdmEncIVLen, encHexData, plainFileData, encHexDataLen);
    if (status != kStatus_SSS_Success) {
        if (symmCtx.session != NULL) {
            sss_symmetric_context_free(&symmCtx);
        }
        goto exit;
    }

    *plainFileDataLen = encHexDataLen;
    LOG_MAU8_I("Decrypted file data", plainFileData, encHexDataLen);

exit:
    if (symmCtx.session != NULL) {
        sss_symmetric_context_free(&symmCtx);
    }
    return status;
}

static sss_status_t sdm_verify_data_signature(
    ex_sss_boot_ctx_t *pCtx, uint8_t *plainData, size_t plainDataLen, uint8_t *signData, size_t signDataLen)
{
    int ret                                            = -1;
    sss_status_t status                                = kStatus_SSS_Fail;
    uint8_t signHexData[EX_SSS_SDM_SDMSignatureLength] = {0};
    size_t signHexDataLen                              = sizeof(signHexData);
    uint8_t signatureAsn1[100]                         = {0};
    size_t signatureAsn1Len                            = sizeof(signatureAsn1);
    sss_object_t keyObject                             = {0};
    uint8_t publicKeyValue[]                           = EX_SSS_SDM_ECC_PUBLIC_KEY;
    sss_asymmetric_t asymmCtx                          = {0};

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
    LOG_MAU8_D("Public key:", publicKeyValue, sizeof(publicKeyValue));

    status = sss_key_store_set_key(&pCtx->host_ks, &keyObject, publicKeyValue, sizeof(publicKeyValue), 256, NULL, 0);
    ENSURE_OR_GO_CLEANUP(kStatus_SSS_Success == status);

    // Signature in Hex. Comes from read out data.
    ret = sdm_ascii_to_hex(signData, signDataLen, signHexData, &signHexDataLen);
    ENSURE_OR_GO_CLEANUP(0 == ret);

    LOG_MAU8_D("Signature in hex:", signHexData, signHexDataLen);

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

sss_status_t ex_sss_entry(ex_sss_boot_ctx_t *pCtx)
{
    sss_status_t status                               = kStatus_SSS_Fail;
    smStatus_t sm_status                              = SM_NOT_OK;
    sss_nx_session_t *pSession                        = NULL;
    uint8_t fileNo                                    = EX_SSS_SDM_NDEF_FILE_NUMBER;
    size_t offset                                     = 0x0;
    uint8_t data[EX_SSS_SDM_NDEF_FILE_SIZE * 2]       = {0};
    size_t dataLen                                    = sizeof(data);
    uint8_t plainPICCData[EX_SSS_SDM_PICCDATA_LENGTH] = {0};
    size_t plainPICCDataLen                           = sizeof(plainPICCData);
    uint32_t hostSDMCtr = 0, seSDMCtr = 0;
    uint8_t piccDataTag                                         = 0;
    uint8_t *pVCUID                                             = NULL;
    sss_object_t sesKeyEncObj                                   = {0}; // Session key
    sss_object_t sesKeyMacObj                                   = {0};
    uint8_t plainVCUID[EX_SSS_SDM_VCUID_MAX_LENGTH_IN_PICCDATA] = {0};
    size_t plainVCUIDLen                                        = 0;
    size_t sdmReadCtrOffsetInPiccData                           = 0;
    uint8_t plainFileData[EX_SSS_SDM_SDMENCLength]              = {0};
    size_t plainFileDataLen                                     = sizeof(plainFileData);
    uint32_t memSize                                            = 0;

    if (pCtx == NULL) {
        LOG_E("Invalid Parameter!");
        goto exit;
    }

    LOG_I("Note: The demo is supposed to be run after Cmd.ChangeFileSettings. So SDMReadCtr is reset to 0x000000!");

    pSession = (sss_nx_session_t *)&pCtx->session;

    sm_status =
        nx_ReadData(&pSession->s_ctx, fileNo, offset, EX_SSS_SDM_NDEF_FILE_SIZE, &data[0], &dataLen, Nx_CommMode_NA);
    ENSURE_OR_GO_EXIT(SM_OK == sm_status);
    sm_status = SM_NOT_OK;
    hostSDMCtr++;
    LOG_MAU8_I("Read NDEF File", data, dataLen);

    // PICC data
    LOG_I("Decrypt Encrypted PICCData @0x%x (Length 0x%x)", EX_SSS_SDM_PICCDATA_OFFSET, EX_SSS_SDM_PICCDATA_LENGTH);
    status = sdm_decrypt_picc_data(
        pCtx, &(data[EX_SSS_SDM_PICCDATA_OFFSET]), EX_SSS_SDM_PICCDATA_LENGTH, plainPICCData, &plainPICCDataLen);
    ENSURE_OR_GO_EXIT(kStatus_SSS_Success == status);
    ENSURE_OR_GO_EXIT(plainPICCDataLen == (EX_SSS_SDM_PICCDATA_LENGTH / 2));

    piccDataTag = plainPICCData[EX_SSS_SDM_TAG_OFFSET_IN_PICCDATA];
    if ((piccDataTag & EX_SSS_SDM_PICCDATA_TAG_VCUID_MASK) == EX_SSS_SDM_PICCDATA_TAG_VCUID_ENABLE) {
        if ((piccDataTag & EX_SSS_SDM_PICCDATA_TAG_VCUID_LENGTH_MASK) == EX_SSS_SDM_7BYTE_VCUID_LENGTH_IN_PICCDATA) {
            plainVCUIDLen              = EX_SSS_SDM_7BYTE_VCUID_LENGTH_IN_PICCDATA;
            sdmReadCtrOffsetInPiccData = EX_SSS_SDM_SDMREADCTR_OFFSET_IN_PICCDATA_7BYTE_UID;
        }
        else if ((piccDataTag & EX_SSS_SDM_PICCDATA_TAG_VCUID_LENGTH_MASK) ==
                 EX_SSS_SDM_10BYTE_VCUID_LENGTH_IN_PICCDATA) {
            plainVCUIDLen              = EX_SSS_SDM_10BYTE_VCUID_LENGTH_IN_PICCDATA;
            sdmReadCtrOffsetInPiccData = EX_SSS_SDM_SDMREADCTR_OFFSET_IN_PICCDATA_10BYTE_UID;
        }
        else {
            LOG_E("Invalid VCUID length");
            goto exit;
        }
    }

    pVCUID = &plainPICCData[EX_SSS_SDM_VCUID_OFFSET_IN_PICCDATA];

    if ((piccDataTag & EX_SSS_SDM_PICCDATA_TAG_SDMREACTR_MASK) == EX_SSS_SDM_PICCDATA_TAG_SDMREACTR_ENABLE) {
        seSDMCtr = ((plainPICCData[sdmReadCtrOffsetInPiccData + 2] << 16) |
                    (plainPICCData[sdmReadCtrOffsetInPiccData + 1] << 8) |
                    (plainPICCData[sdmReadCtrOffsetInPiccData + 0] << 0));
        if (hostSDMCtr != seSDMCtr) {
            LOG_W("Readout SDMReadCtr(0x%x) is different from host SDMReadCtr(0x%x)!", seSDMCtr, hostSDMCtr);
            LOG_W("Overwrite host SDMReadCtr. This is only for demo purpose and should not be done in real case!");
            hostSDMCtr = seSDMCtr;
        }
        else {
            LOG_I("Get SDMCtr from PICCData 0x%x. It's same to the SDMCtr stored on host", seSDMCtr);
        }
    }

    memcpy(plainVCUID, pVCUID, plainVCUIDLen);
    LOG_MAU8_I("Get VCUID from PICCData.", plainVCUID, plainVCUIDLen);

    status = sdm_calculate_session_keys(pCtx, plainVCUID, plainVCUIDLen, hostSDMCtr, &sesKeyEncObj, &sesKeyMacObj);
    ENSURE_OR_GO_EXIT(kStatus_SSS_Success == status);

    LOG_I("Decrypt SDMENCFileData @0x%x (Length 0x%x)", EX_SSS_SDM_SDMENCOffset, EX_SSS_SDM_SDMENCLength);
    status = sdm_decrypt_file_data(pCtx,
        &data[EX_SSS_SDM_SDMENCOffset],
        EX_SSS_SDM_SDMENCLength,
        hostSDMCtr,
        &sesKeyEncObj,
        plainFileData,
        &plainFileDataLen);
    ENSURE_OR_GO_EXIT(kStatus_SSS_Success == status);

    LOG_I("GPIO Status @0x%x: 0x%02x-0x%02x-0x%02x",
        EX_SSS_SDM_GPIOStatusOffset,
        plainFileData[EX_SSS_SDM_GPIOStatusOffset - EX_SSS_SDM_SDMENCOffset],
        plainFileData[EX_SSS_SDM_GPIOStatusOffset - EX_SSS_SDM_SDMENCOffset + 1],
        plainFileData[EX_SSS_SDM_GPIOStatusOffset - EX_SSS_SDM_SDMENCOffset + 2]);

    LOG_I("Verify Signature @0x%x(Length 0x%x) with data @0x%x(Length 0x%x))",
        EX_SSS_SDM_SDMMACOffset,
        EX_SSS_SDM_SDMSignatureLength,
        EX_SSS_SDM_SDMMACInputOffset,
        EX_SSS_SDM_SDMMACOffset - EX_SSS_SDM_SDMMACInputOffset);
    status = sdm_verify_data_signature(pCtx,
        &data[EX_SSS_SDM_SDMMACInputOffset],
        EX_SSS_SDM_SDMMACOffset - EX_SSS_SDM_SDMMACInputOffset,
        &data[EX_SSS_SDM_SDMMACOffset],
        EX_SSS_SDM_SDMSignatureLength);
    ENSURE_OR_GO_EXIT(kStatus_SSS_Success == status);

    // Read file again. SDMCtr doesn't increase
    memset(data, 0, sizeof(data));
    dataLen = sizeof(data);
    sm_status =
        nx_ReadData(&pSession->s_ctx, fileNo, offset, EX_SSS_SDM_NDEF_FILE_SIZE, &data[0], &dataLen, Nx_CommMode_NA);
    ENSURE_OR_GO_EXIT(SM_OK == sm_status);
    sm_status = SM_NOT_OK;
    LOG_MAU8_I("Read NDEF File Again", data, dataLen);
    LOG_I("Current SDMCtr 0x%x", hostSDMCtr);

    status = sdm_calculate_session_keys(pCtx, plainVCUID, plainVCUIDLen, hostSDMCtr, &sesKeyEncObj, &sesKeyMacObj);
    ENSURE_OR_GO_EXIT(kStatus_SSS_Success == status);

    LOG_I("Decrypt SDMENCFileData @0x%x (Length 0x%x)", EX_SSS_SDM_SDMENCOffset, EX_SSS_SDM_SDMENCLength);
    status = sdm_decrypt_file_data(pCtx,
        &data[EX_SSS_SDM_SDMENCOffset],
        EX_SSS_SDM_SDMENCLength,
        hostSDMCtr,
        &sesKeyEncObj,
        plainFileData,
        &plainFileDataLen);
    ENSURE_OR_GO_EXIT(kStatus_SSS_Success == status);

    LOG_I("Verify Signature @0x%x(Length 0x%x) with data @0x%x(Length 0x%x))",
        EX_SSS_SDM_SDMMACOffset,
        EX_SSS_SDM_SDMSignatureLength,
        EX_SSS_SDM_SDMMACInputOffset,
        EX_SSS_SDM_SDMMACOffset - EX_SSS_SDM_SDMMACInputOffset);
    status = sdm_verify_data_signature(pCtx,
        &data[EX_SSS_SDM_SDMMACInputOffset],
        EX_SSS_SDM_SDMMACOffset - EX_SSS_SDM_SDMMACInputOffset,
        &data[EX_SSS_SDM_SDMMACOffset],
        EX_SSS_SDM_SDMSignatureLength);
    ENSURE_OR_GO_EXIT(kStatus_SSS_Success == status);

    LOG_I("Get Free Memory");
    sm_status = nx_FreeMem(&pSession->s_ctx, &memSize);
    if (sm_status != SM_OK) {
        LOG_E("nx_FreeMem Failed");
        status = kStatus_SSS_Fail;
    }

    // Read file 3rd time. SDMCtr increase due to nx_FreeMem has been sent.
    memset(data, 0, sizeof(data));
    dataLen = sizeof(data);
    sm_status =
        nx_ReadData(&pSession->s_ctx, fileNo, offset, EX_SSS_SDM_NDEF_FILE_SIZE, &data[0], &dataLen, Nx_CommMode_NA);
    ENSURE_OR_GO_EXIT(SM_OK == sm_status);
    sm_status = SM_NOT_OK;
    hostSDMCtr++;
    LOG_MAU8_I("Read NDEF File for 3rd time", data, dataLen);
    LOG_I("Current SDMCtr 0x%x", hostSDMCtr);

    status = sdm_calculate_session_keys(pCtx, plainVCUID, plainVCUIDLen, hostSDMCtr, &sesKeyEncObj, &sesKeyMacObj);
    ENSURE_OR_GO_EXIT(kStatus_SSS_Success == status);

    LOG_I("Decrypt SDMENCFileData @0x%x (Length 0x%x)", EX_SSS_SDM_SDMENCOffset, EX_SSS_SDM_SDMENCLength);
    status = sdm_decrypt_file_data(pCtx,
        &data[EX_SSS_SDM_SDMENCOffset],
        EX_SSS_SDM_SDMENCLength,
        hostSDMCtr,
        &sesKeyEncObj,
        plainFileData,
        &plainFileDataLen);
    ENSURE_OR_GO_EXIT(kStatus_SSS_Success == status);

    LOG_I("Verify Signature @0x%x(Length 0x%x) with data @0x%x(Length 0x%x))",
        EX_SSS_SDM_SDMMACOffset,
        EX_SSS_SDM_SDMSignatureLength,
        EX_SSS_SDM_SDMMACInputOffset,
        EX_SSS_SDM_SDMMACOffset - EX_SSS_SDM_SDMMACInputOffset);
    status = sdm_verify_data_signature(pCtx,
        &data[EX_SSS_SDM_SDMMACInputOffset],
        EX_SSS_SDM_SDMMACOffset - EX_SSS_SDM_SDMMACInputOffset,
        &data[EX_SSS_SDM_SDMMACOffset],
        EX_SSS_SDM_SDMSignatureLength);
    ENSURE_OR_GO_EXIT(kStatus_SSS_Success == status);

exit:
    if (kStatus_SSS_Success == status) {
        LOG_I("SDM File Verify Example Success !!!...");
    }
    else {
        LOG_E("SDM File Verify Example Failed !!!...");
    }
    return status;
}