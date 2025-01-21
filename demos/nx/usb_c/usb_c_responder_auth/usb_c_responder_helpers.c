/*
 *
 * Copyright 2023-2024 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "usb_c_responder.h"
#include "usb_c_responder_helpers.h"
#include "usb_c_responder_port.h"

#include "nxLog_msg.h"
#include <nx_apdu.h>
#include <nx_enums.h>

#include <string.h>
#include <limits.h>

smStatus_t getPopulatedSlots(sss_session_t *pSession, uint8_t *pSlotsPopulated)
{
    smStatus_t retStatus = SM_NOT_OK;
    uint8_t fileNo       = 0;
    int slotNum          = -1;
    uint8_t i            = 0;
    bool fileExists      = false;
    uint8_t fIDList[32]  = {0};
    size_t fIDListLen    = sizeof(fIDList);

    if ((pSession == NULL) || (pSlotsPopulated == NULL)) {
        LOG_E("Add certificate with wrong parameter!!!");
        goto exit;
    }

    for (slotNum = 0; slotNum < MAX_SLOTS; slotNum++) {
        fileExists = false;
        fileNo     = USB_C_SLOT_ID_TO_CERT_FILE_ID(slotNum);

        /* Check if certificate file exists */
        retStatus = nx_GetFileIDs(&((sss_nx_session_t *)pSession)->s_ctx, fIDList, &fIDListLen);
        if (retStatus != SM_OK) {
            LOG_E("Check file exist failed!!!");
            goto exit;
        }

        for (i = 0; i < fIDListLen; i++) {
            if (fileNo == fIDList[i]) {
                fileExists = true;
                break;
            }
        }

        if (fileExists) {
            *pSlotsPopulated = *pSlotsPopulated | (1 << slotNum);
        }
    }

exit:
    return retStatus;
}

sss_status_t generateRandom(sss_session_t *pSession, uint8_t *pBuf, size_t bufLen)
{
    sss_status_t sss_status       = kStatus_SSS_Fail;
    sss_rng_context_t sss_rng_ctx = {0};

    if ((pSession == NULL) || (pBuf == NULL)) {
        LOG_E("Add certificate with wrong parameter!!!");
        goto exit;
    }

    sss_status = sss_rng_context_init(&sss_rng_ctx, pSession);
    if (sss_status != kStatus_SSS_Success) {
        goto exit;
    }

    sss_status = sss_rng_get_random(&sss_rng_ctx, pBuf, bufLen);
    if (sss_status != kStatus_SSS_Success) {
        goto exit;
    }

    sss_status = kStatus_SSS_Success;

exit:
    if (sss_rng_ctx.session != NULL) {
        sss_rng_context_free(&sss_rng_ctx);
    }
    return sss_status;
}

sss_status_t swapRandS(uint8_t *data, size_t dataLen)
{
    sss_status_t sss_status = kStatus_SSS_Fail;
    uint32_t i;
    uint8_t tmpValue = 0;

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

smStatus_t EcSignatureToRandS(uint8_t *signature, size_t *sigLen)
{
    smStatus_t retStatus = SM_NOT_OK;
    uint8_t rands[128]   = {0};
    int index            = 0;
    size_t i             = 0;
    size_t len           = 0;

    if ((NULL == signature) || (NULL == sigLen)) {
        goto exit;
    }
    if (signature[index++] != 0x30) {
        goto exit;
    }
    if (signature[index++] != (*sigLen - 2)) {
        goto exit;
    }
    if (signature[index++] != 0x02) {
        goto exit;
    }

    len = signature[index++];
    if (len & 0x01) {
        len--;
        index++;
    }

    for (i = 0; i < len; i++) {
        rands[i] = signature[index++];
    }

    if (signature[index++] != 0x02) {
        goto exit;
    }

    len = signature[index++];
    if (len & 0x01) {
        len--;
        index++;
    }

    len = len + i;
    for (; i < len; i++) {
        rands[i] = signature[index++];
    }

    memcpy(&signature[0], &rands[0], i);
    *sigLen = i;

    retStatus = SM_OK;

exit:
    return retStatus;
}

sss_status_t getSha256Hash(
    sss_session_t *pSession, const uint8_t *pInput, size_t inputLen, uint8_t *pOutput, size_t *pOutputLen)
{
    sss_status_t status = kStatus_SSS_Fail;
    sss_digest_t digest = {0};
    size_t chunk        = 0;
    size_t offset       = 0;

    if ((pSession == NULL) || (pInput == NULL) || (pOutput == NULL) || (pOutputLen == NULL)) {
        LOG_E("Calculate digest with wrong parameter!!!");
        goto exit;
    }

    status = sss_digest_context_init(&digest, pSession, kAlgorithm_SSS_SHA256, kMode_SSS_Digest);
    if (status != kStatus_SSS_Success) {
        LOG_E("sss_digest_context_init Failed!!!");
        goto exit;
    }

    status = sss_digest_init(&digest);
    if (status != kStatus_SSS_Success) {
        LOG_E("sss_digest_one_go Failed!!!");
        goto exit;
    }

    do {
        chunk = (inputLen > NX_MAX_SHA_INPUT_LEN) ? NX_MAX_SHA_INPUT_LEN : inputLen;

        status = sss_digest_update(&digest, pInput + offset, chunk);
        ENSURE_OR_GO_EXIT(kStatus_SSS_Success == status);
        if (chunk > (UINT_MAX - offset)) {
            status = kStatus_SSS_Fail;
            goto exit;
        }
        offset += chunk;
        inputLen -= chunk;
    } while (inputLen > 0);

    status = sss_digest_finish(&digest, pOutput, pOutputLen);
    if (status != kStatus_SSS_Success) {
        LOG_E("sss_digest_finish Failed!!!");
        goto exit;
    }

    status = kStatus_SSS_Success;
exit:
    if (digest.session != NULL) {
        sss_digest_context_free(&digest);
    }
    return status;
}
