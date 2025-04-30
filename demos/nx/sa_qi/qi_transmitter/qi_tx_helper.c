/*
 *
 * Copyright 2023-2024 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "qi_transmitter.h"
#include "qi_tx_helper.h"
#include "qi_tx_port.h"

#include "nxLog_msg.h"
#include <string.h>

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

#define SA_QI_CREDENTIALS_MAX_SIZE 4

uint8_t tmp_qi_ec_priv_key[]       = QI_EC_PRIV_KEY_TX;
uint8_t tmp_qi_certificate_chain[] = QI_CERTIFICATE_CHAIN;

const sa_qi_credentials_t kSaQiCredential[SA_QI_CREDENTIALS_MAX_SIZE] = {
    {&tmp_qi_certificate_chain[0],
        sizeof(tmp_qi_certificate_chain),
        &tmp_qi_ec_priv_key[0],
        sizeof(tmp_qi_ec_priv_key)},
    {NULL, 0, NULL, 0},
    {NULL, 0, NULL, 0},
    {NULL, 0, NULL, 0},
};

smStatus_t getPopulatedSlots(uint8_t *pSlotsPopulated)
{
    smStatus_t retStatus = SM_NOT_OK;

    if (NULL == pSlotsPopulated) {
        goto exit;
    }
    uint8_t i = 0;
    for (i = 0; i < 4; i++) {
        if (((kSaQiCredential + i)->qi_certificate_chain) != NULL) {
            if ((*pSlotsPopulated | (1 << i)) > UINT8_MAX) {
                LOG_E("Error reading the populated slots");
                return retStatus;
            }
            *pSlotsPopulated = (uint8_t)(*pSlotsPopulated | (1 << i));
        }
    }
    retStatus = SM_OK;
exit:
    return retStatus;
}

smStatus_t ReadSize(uint32_t certChainId, uint16_t *objectSize)
{
    smStatus_t retStatus      = SM_NOT_OK;
    uint8_t pSlotsPopulated   = 0x00;
    uint8_t requestedSlotMask = 0x0F;
    uint8_t slotsReturned     = 0x00;
    uint8_t slotIdIndex       = 0xFF;
    slotIdIndex               = (uint8_t)QI_DBG_EXTRACT_SLOT_ID(certChainId);
    retStatus                 = getPopulatedSlots(&pSlotsPopulated);

    if (NULL == objectSize) {
        goto exit;
    }

    if (retStatus != SM_OK) {
        goto exit;
    }
    retStatus     = SM_NOT_OK;
    slotsReturned = requestedSlotMask & pSlotsPopulated;
    if ((slotsReturned) & (0x01 << slotIdIndex)) {
        if ((certChainId & 0xF0) == QI_PROVISIONING_CERT_ID_OFFSET && SA_QI_CREDENTIALS_MAX_SIZE > slotIdIndex) {
            *objectSize = (kSaQiCredential + slotIdIndex)->qi_certificate_chain_len;
            retStatus   = SM_OK;
        }
        else if ((certChainId & 0xF0) == QI_PROVISIONING_KEY_ID_OFFSET && SA_QI_CREDENTIALS_MAX_SIZE > slotIdIndex) {
            *objectSize = (kSaQiCredential + slotIdIndex)->qi_ec_priv_key_len;
            retStatus   = SM_OK;
        }
    }
exit:
    return retStatus;
}

smStatus_t ReadObject(uint32_t certChainId, uint16_t offsetMC, uint16_t Length, uint8_t *pData, size_t *readSize)
{
    smStatus_t retStatus      = SM_NOT_OK;
    uint8_t pSlotsPopulated   = 0x00;
    uint8_t requestedSlotMask = 0x0F;
    uint8_t slotsReturned     = 0x00;
    uint8_t slotIdIndex       = 0xFF;

    if ((NULL == pData) || (NULL == readSize)) {
        goto exit;
    }

    slotIdIndex = (uint8_t)QI_DBG_EXTRACT_SLOT_ID(certChainId);

    retStatus = getPopulatedSlots(&pSlotsPopulated);
    if (retStatus != SM_OK) {
        goto exit;
    }
    slotsReturned = requestedSlotMask & pSlotsPopulated;
    if ((slotsReturned) & (0x01 << slotIdIndex)) {
        if ((certChainId & 0xF0) == QI_PROVISIONING_CERT_ID_OFFSET) {
            memcpy(pData, &((kSaQiCredential + slotIdIndex)->qi_certificate_chain[0]) + offsetMC, Length);
            *readSize = Length;
            retStatus = SM_OK;
        }
        else if ((certChainId & 0xF0) == QI_PROVISIONING_KEY_ID_OFFSET) {
            memcpy(pData, &((kSaQiCredential + slotIdIndex)->qi_ec_priv_key[0]) + offsetMC, Length);
            *readSize = Length;
            retStatus = SM_OK;
        }
    }

exit:
    return retStatus;
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

smStatus_t getSha256Hash(
    sss_session_t *session_ctx, const uint8_t *pInput, size_t inputLen, uint8_t *pOutput, size_t *pOutputLen)
{
    smStatus_t sm_status = SM_NOT_OK;
    size_t chunk         = 0;
    size_t offset        = 0;

    sss_status_t sss_status = kStatus_SSS_Fail;
    sss_digest_t digest_ctx = {0};
    sss_status = sss_host_digest_context_init(&digest_ctx, session_ctx, kAlgorithm_SSS_SHA256, kMode_SSS_Digest);
    ENSURE_OR_GO_EXIT(kStatus_SSS_Success == sss_status);

    sss_status = sss_host_digest_init(&digest_ctx);
    ENSURE_OR_GO_EXIT(kStatus_SSS_Success == sss_status);

    do {
        chunk      = (inputLen > NX_MAX_SHA_INPUT_LEN) ? NX_MAX_SHA_INPUT_LEN : inputLen;
        sss_status = sss_host_digest_update(&digest_ctx, pInput + offset, chunk);
        ENSURE_OR_GO_EXIT(kStatus_SSS_Success == sss_status);
        if (chunk > (UINT_MAX - offset)) {
            sm_status = SM_NOT_OK;
            goto exit;
        }
        offset += chunk;
        inputLen -= chunk;
    } while (inputLen > 0);

    sss_status = sss_host_digest_finish(&digest_ctx, pOutput, pOutputLen);
    ENSURE_OR_GO_EXIT(kStatus_SSS_Success == sss_status);

    if (sss_status == kStatus_SSS_Success) {
        sm_status = SM_OK;
    }

exit:
    if (digest_ctx.session != NULL) {
        sss_host_digest_context_free(&digest_ctx);
    }
    return sm_status;
}

smStatus_t readObjectWithChunking(
    uint32_t certChainId, uint16_t offset, uint16_t bytesToRead, uint8_t *pData, size_t *pdataLen)
{
    smStatus_t retStatus       = SM_NOT_OK;
    size_t outputSizeRemaining = 0;
    size_t readSize            = 0;
    uint16_t chunk             = 0;
    uint16_t chunkOffset       = 0;

    if (NULL == pdataLen) {
        goto exit;
    }

    outputSizeRemaining = *pdataLen;
    readSize            = *pdataLen;

    do {
        chunk = (bytesToRead > NX_MAX_SHA_INPUT_LEN) ? NX_MAX_SHA_INPUT_LEN : bytesToRead;
        if ((UINT16_MAX - offset) < chunkOffset) {
            retStatus = SM_NOT_OK;
            break;
        }
        retStatus = ReadObject(certChainId, offset + chunkOffset, chunk, pData + chunkOffset, &readSize);
        if (retStatus != SM_OK) {
            LOG_E("ReadObject Failed");
            break;
        }
        if ((UINT16_MAX - chunkOffset) < chunk) {
            retStatus = SM_NOT_OK;
            break;
        }
        chunkOffset += chunk;
        if (bytesToRead < chunk) {
            retStatus = SM_NOT_OK;
            break;
        }
        bytesToRead -= chunk;
        outputSizeRemaining = outputSizeRemaining - readSize;
        readSize            = outputSizeRemaining;
    } while (0 != bytesToRead);

    *pdataLen = *pdataLen - outputSizeRemaining;

exit:
    return retStatus;
}

smStatus_t getManufacturerCertificateLength(uint32_t certChainId, uint16_t *N_MC)
{
    smStatus_t retStatus        = SM_NOT_OK;
    uint16_t offsetMC           = (uint16_t)(DIGEST_SIZE_BYTES + 2 + DIGEST_SIZE_BYTES + 1);
    uint8_t certMCLengthBuff[3] = {0};
    size_t certMCLengthBuff_len = sizeof(certMCLengthBuff);

    if (NULL == N_MC) {
        goto exit;
    }

    retStatus = ReadObject(certChainId, offsetMC, 0x03, certMCLengthBuff, &certMCLengthBuff_len);
    if (retStatus != SM_OK) {
        LOG_E("ReadObject Failed");
        return retStatus;
    }

    if ((certMCLengthBuff[0] & 0x80) == 0x80) {
        if ((certMCLengthBuff[0] & 0x7F) == 0x01) {
            *N_MC = certMCLengthBuff[1] + 3u;
        }
        else if ((certMCLengthBuff[0] & 0x7F) == 0x02) {
            *N_MC = certMCLengthBuff[1] << 8;
            if (*N_MC > (UINT16_MAX - (certMCLengthBuff[2] + 4u))) {
                LOG_E("Parsing the TLV->Length field failed");
                return retStatus;
            }
            *N_MC += (certMCLengthBuff[2] + 4u);
        }
    }
    else {
        *N_MC = certMCLengthBuff[0] + 2u;
    }

exit:
    return retStatus;
}
