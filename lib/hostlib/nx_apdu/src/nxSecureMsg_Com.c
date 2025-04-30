/*
*
* Copyright 2022-2024 NXP
* SPDX-License-Identifier: BSD-3-Clause
*/

#include <string.h>
#include <assert.h>
#include <limits.h>

#if defined(SSS_USE_FTR_FILE)
#include "fsl_sss_ftr.h"
#else
#include "fsl_sss_ftr_default.h"
#endif

#include "nxLog_msg.h"
#include "nx_secure_msg_apis.h"
#include "nxEnsure.h"
#include "nx_enums.h"

#if SSS_HAVE_HOSTCRYPTO_MBEDTLS
#include "fsl_sss_mbedtls_apis.h"
#endif
#if SSS_HAVE_HOSTCRYPTO_OPENSSL
#include "fsl_sss_openssl_apis.h"
#endif

#define EV2_DATA_PAD_BYTE 0x80
#define EV2_KEY_SIZE 16

/* ************************************************************************** */
/* Functions : Private function declaration                                   */
/* ************************************************************************** */

/**
* To Apply Encryption on Plain Data
*/

/* All these APIs are used only for authenticated sessions */
#if ((defined(SSS_HAVE_HOSTCRYPTO_ANY) && (SSS_HAVE_HOSTCRYPTO_ANY)) &&                \
     ((defined(SSS_HAVE_AUTH_SIGMA_I_VERIFIER) && (SSS_HAVE_AUTH_SIGMA_I_VERIFIER)) || \
         (defined(SSS_HAVE_AUTH_SIGMA_I_PROVER) && (SSS_HAVE_AUTH_SIGMA_I_PROVER)) ||  \
         (defined(SSS_HAVE_AUTH_SYMM_AUTH) && (SSS_HAVE_AUTH_SYMM_AUTH)) ||            \
         (defined(SSS_HAVE_ALL_AUTH_CODE_ENABLED) && (SSS_HAVE_ALL_AUTH_CODE_ENABLED))))

static uint16_t nx_AES_EV2_MAC_Verify(uint8_t *rspBuf_mac, size_t rspBuf_mac_len, uint8_t *respMac, size_t respMac_len);

static uint16_t nx_AES_EV2_Restore_RAPDU(
    uint8_t *rspBuf, size_t *pRspBufLen, uint8_t *plaintextResponse, size_t plaintextRespLen);

static void nx_PadCommandAPDU(uint8_t *cmdApduBuf, size_t *cmdApduBufLen);

uint16_t nx_Decrypt_AES_EV2_ResponseAPDU(
    pSeSession_t session_ctx, uint8_t cmdByte, uint8_t *rspBuf, size_t *pRspBufLen, void *options)
{
    sss_status_t sss_status                              = kStatus_SSS_Fail;
    uint16_t status                                      = SCP_FAIL;
    uint8_t respMac[16]                                  = {0};
    sss_mac_t macCtx                                     = {0};
    size_t signatureLen                                  = sizeof(respMac);
    size_t compareoffset                                 = 0;
    uint8_t plaintextResponse[NX_MAX_BUF_SIZE_CMD]       = {0};
    nx_ev2_comm_mode_t CommMode                          = EV2_CommMode_NA;
    sss_algorithm_t algorithm                            = kAlgorithm_SSS_CMAC_AES;
    sss_mode_t mode                                      = kMode_SSS_Mac;
    uint8_t apduPayloadToMAC_Verify[NX_MAX_BUF_SIZE_CMD] = {0};
    uint8_t apduPayloadToDecrypt[NX_MAX_BUF_SIZE_CMD]    = {0};
    uint8_t gen_iv_Buf[16]                               = {0};
    uint8_t enc_iv[16]                                   = {0};
    size_t enc_iv_len                                    = sizeof(enc_iv);
    nx_ev2_comm_mode_t *preCommMode                      = (nx_ev2_comm_mode_t *)options; // Pre-configured CommMode.
    sss_object_t *pMacKey = NULL, *pEncKey = NULL;

    size_t offset        = 0;
    sss_symmetric_t symm = {0};
    uint8_t iv[16]       = {0};
    uint8_t *pIv         = (uint8_t *)iv;

    ENSURE_OR_GO_EXIT(NULL != pRspBufLen);
    ENSURE_OR_GO_EXIT(NULL != rspBuf);
    ENSURE_OR_GO_EXIT(NULL != session_ctx);
    ENSURE_OR_GO_EXIT((SIZE_MAX - (*pRspBufLen)) >= 1);
    ENSURE_OR_GO_EXIT(*pRspBufLen >= 1); // Non-zero length of response is expected

    if (preCommMode == NULL) {
        status = nx_get_command_commMode(cmdByte, &CommMode);
        ENSURE_OR_GO_EXIT(status == SCP_OK);
    }
    else {
        CommMode = *preCommMode;
    }

    if (session_ctx->authType == knx_AuthType_SIGMA_I_Verifier ||
        session_ctx->authType == knx_AuthType_SIGMA_I_Prover) {
        ENSURE_OR_GO_EXIT(session_ctx->ctx.pdynSigICtx != NULL);
        pMacKey = &session_ctx->ctx.pdynSigICtx->k_m2;
        pEncKey = &session_ctx->ctx.pdynSigICtx->k_e2;
    }
    else if (session_ctx->authType == knx_AuthType_SYMM_AUTH) {
        ENSURE_OR_GO_EXIT(session_ctx->ctx.pdynSymmAuthCtx != NULL);
        pMacKey = &session_ctx->ctx.pdynSymmAuthCtx->k_m2;
        pEncKey = &session_ctx->ctx.pdynSymmAuthCtx->k_e2;
    }

    if (CommMode == EV2_CommMode_FULL || CommMode == EV2_CommMode_MAC) {
        // RC || CmdCtr || TI || RespData/E(RespData)
        apduPayloadToMAC_Verify[offset++] = rspBuf[*pRspBufLen - 1]; //return code
        if (session_ctx->authType == knx_AuthType_SIGMA_I_Verifier ||
            session_ctx->authType == knx_AuthType_SIGMA_I_Prover) {
            apduPayloadToMAC_Verify[offset++] = (session_ctx->ctx.pdynSigICtx->CmdCtr & 0x00FF);
            apduPayloadToMAC_Verify[offset++] = (session_ctx->ctx.pdynSigICtx->CmdCtr & 0xFF00) >> 8;
            apduPayloadToMAC_Verify[offset++] = (session_ctx->ctx.pdynSigICtx->TI & 0x000000FF);
            apduPayloadToMAC_Verify[offset++] = (session_ctx->ctx.pdynSigICtx->TI & 0x0000FF00) >> 8;
            apduPayloadToMAC_Verify[offset++] = (session_ctx->ctx.pdynSigICtx->TI & 0x00FF0000) >> 16;
            apduPayloadToMAC_Verify[offset++] = (session_ctx->ctx.pdynSigICtx->TI & 0xFF000000) >> 24;
        }
        else if (session_ctx->authType == knx_AuthType_SYMM_AUTH) {
            apduPayloadToMAC_Verify[offset++] = (session_ctx->ctx.pdynSymmAuthCtx->CmdCtr & 0x00FF);
            apduPayloadToMAC_Verify[offset++] = (session_ctx->ctx.pdynSymmAuthCtx->CmdCtr & 0xFF00) >> 8;
            apduPayloadToMAC_Verify[offset++] = (session_ctx->ctx.pdynSymmAuthCtx->TI & 0x000000FF);
            apduPayloadToMAC_Verify[offset++] = (session_ctx->ctx.pdynSymmAuthCtx->TI & 0x0000FF00) >> 8;
            apduPayloadToMAC_Verify[offset++] = (session_ctx->ctx.pdynSymmAuthCtx->TI & 0x00FF0000) >> 16;
            apduPayloadToMAC_Verify[offset++] = (session_ctx->ctx.pdynSymmAuthCtx->TI & 0xFF000000) >> 24;
        }
        if ((*pRspBufLen >= (NTAG_AES128_EV2_COMMAND_MAC_SIZE + 2)) &&
            ((*pRspBufLen - NTAG_AES128_EV2_COMMAND_MAC_SIZE - 2) <= (sizeof(apduPayloadToMAC_Verify) - offset))) {
            memcpy(&apduPayloadToMAC_Verify[offset], rspBuf, (*pRspBufLen - NTAG_AES128_EV2_COMMAND_MAC_SIZE - 2));

            if ((UINT_MAX - offset) < (*pRspBufLen - NTAG_AES128_EV2_COMMAND_MAC_SIZE - 2)) {
                status = SCP_FAIL;
                goto exit;
            }
            offset += (size_t)(*pRspBufLen - NTAG_AES128_EV2_COMMAND_MAC_SIZE - 2);
        }
        else {
            LOG_E("Not enought buffer for MAC verification");
            status = SCP_FAIL;
            goto exit;
        }

        // MAC for RC || CmdCtr || TI || RespData/E(RespData)
        ENSURE_OR_GO_EXIT(pMacKey != NULL);
        sss_status = sss_host_mac_context_init(&macCtx, pMacKey->keyStore->session, pMacKey, algorithm, mode);
        ENSURE_OR_GO_EXIT(sss_status == kStatus_SSS_Success);

        sss_status = sss_host_mac_one_go(
            &macCtx, apduPayloadToMAC_Verify, offset, respMac, &signatureLen); //need to check macToAdd and maclen
        ENSURE_OR_GO_EXIT(sss_status == kStatus_SSS_Success);

        sss_host_mac_context_free(&macCtx);

        // Get the even-numbered bytes and compared to the MAC in response
        compareoffset = *pRspBufLen - NTAG_AES128_EV2_COMMAND_MAC_SIZE - 2;

        sss_status = kStatus_SSS_Fail;
        status     = nx_AES_EV2_MAC_Verify(rspBuf, compareoffset, respMac, signatureLen);
        if (status == SCP_OK) {
            sss_status = kStatus_SSS_Success;
        }
        else {
            ENSURE_OR_GO_EXIT(sss_status == kStatus_SSS_Success);
        }
        LOG_MAU8_D("Mac verified :", respMac, signatureLen);

        if (CommMode == EV2_CommMode_MAC) {
            // Return plain text response.
            memcpy(&rspBuf[*pRspBufLen - NTAG_AES128_EV2_COMMAND_MAC_SIZE - 2],
                &rspBuf[*pRspBufLen - 2],
                2); // Copy SW1 SW2 to plain response
            *pRspBufLen -= NTAG_AES128_EV2_COMMAND_MAC_SIZE;
            LOG_MAU8_D("Decrypted the response", rspBuf, *pRspBufLen);

            status = SCP_OK;
            goto exit;
        }
    }

    // Decrypt Response Data Field in case Reponse Mac verified OK
    if (CommMode == EV2_CommMode_FULL && ((*pRspBufLen - NTAG_AES128_EV2_COMMAND_MAC_SIZE - 2) > 0)) {
        size_t dataLen = 0;

        // Calculate IV for decryption
        // IV for RespData = E(KSesAuthENC; 0x5A||0xA5||TI||CmdCtr||0x0000000000000000)
        offset               = 0;
        gen_iv_Buf[offset++] = 0x5Au;
        gen_iv_Buf[offset++] = 0xA5u;
        if (session_ctx->authType == knx_AuthType_SIGMA_I_Verifier ||
            session_ctx->authType == knx_AuthType_SIGMA_I_Prover) {
            gen_iv_Buf[offset++] = (session_ctx->ctx.pdynSigICtx->TI & 0x000000FFu);
            gen_iv_Buf[offset++] = (session_ctx->ctx.pdynSigICtx->TI & 0x0000FF00u) >> 8u;
            gen_iv_Buf[offset++] = (session_ctx->ctx.pdynSigICtx->TI & 0x00FF0000u) >> 16u;
            gen_iv_Buf[offset++] = (session_ctx->ctx.pdynSigICtx->TI & 0xFF000000u) >> 24u;
            gen_iv_Buf[offset++] = (session_ctx->ctx.pdynSigICtx->CmdCtr & 0x00FFu);
            gen_iv_Buf[offset++] = (session_ctx->ctx.pdynSigICtx->CmdCtr & 0xFF00u) >> 8u;
        }
        else if (session_ctx->authType == knx_AuthType_SYMM_AUTH) {
            gen_iv_Buf[offset++] = (session_ctx->ctx.pdynSymmAuthCtx->TI & 0x000000FFu);
            gen_iv_Buf[offset++] = (session_ctx->ctx.pdynSymmAuthCtx->TI & 0x0000FF00u) >> 8u;
            gen_iv_Buf[offset++] = (session_ctx->ctx.pdynSymmAuthCtx->TI & 0x00FF0000u) >> 16u;
            gen_iv_Buf[offset++] = (session_ctx->ctx.pdynSymmAuthCtx->TI & 0xFF000000u) >> 24u;
            gen_iv_Buf[offset++] = (session_ctx->ctx.pdynSymmAuthCtx->CmdCtr & 0x00FFu);
            gen_iv_Buf[offset++] = (session_ctx->ctx.pdynSymmAuthCtx->CmdCtr & 0xFF00u) >> 8u;
        }
        ENSURE_OR_GO_EXIT(pEncKey != NULL);
        sss_status = sss_host_symmetric_context_init(
            &symm, pEncKey->keyStore->session, pEncKey, kAlgorithm_SSS_AES_CBC, kMode_SSS_Encrypt);
        ENSURE_OR_GO_EXIT(sss_status == kStatus_SSS_Success);

        sss_status = sss_host_cipher_one_go(&symm, pIv, EV2_KEY_SIZE, gen_iv_Buf, enc_iv, enc_iv_len);
        ENSURE_OR_GO_EXIT(sss_status == kStatus_SSS_Success);

        sss_host_symmetric_context_free(&symm);

        // This is data payload in response
        ENSURE_OR_GO_EXIT((*pRspBufLen) > NTAG_AES128_EV2_COMMAND_MAC_SIZE + 2);

        dataLen = ((*pRspBufLen) - NTAG_AES128_EV2_COMMAND_MAC_SIZE - 2);
        memcpy(apduPayloadToDecrypt, rspBuf, dataLen);

        pIv        = (uint8_t *)enc_iv;
        sss_status = sss_host_symmetric_context_init(
            &symm, pEncKey->keyStore->session, pEncKey, kAlgorithm_SSS_AES_CBC, kMode_SSS_Decrypt);
        ENSURE_OR_GO_EXIT(sss_status == kStatus_SSS_Success);

        ENSURE_OR_GO_EXIT(dataLen <= sizeof(plaintextResponse));
        sss_status = sss_host_cipher_one_go(&symm, pIv, EV2_KEY_SIZE, apduPayloadToDecrypt, plaintextResponse, dataLen);
        ENSURE_OR_GO_EXIT(sss_status == kStatus_SSS_Success);

        sss_host_symmetric_context_free(&symm);

        // Remove padding
        sss_status = kStatus_SSS_Fail;
        status     = nx_AES_EV2_Restore_RAPDU(rspBuf, pRspBufLen, plaintextResponse, dataLen);
        if (status == SCP_OK) {
            sss_status = kStatus_SSS_Success;
        }
        else {
            ENSURE_OR_GO_EXIT(sss_status == kStatus_SSS_Success);
        }
    }
    else if (CommMode == EV2_CommMode_FULL && ((*pRspBufLen - NTAG_AES128_EV2_COMMAND_MAC_SIZE - 2) == 0)) {
        memcpy(&rspBuf[0], &rspBuf[*pRspBufLen - 2], 2); // Copy SW1 SW2 to plain response
        *pRspBufLen -= NTAG_AES128_EV2_COMMAND_MAC_SIZE;
        LOG_MAU8_D("Decrypted the response", rspBuf, *pRspBufLen);
    }

    status = SCP_OK;
exit:
    return status;
}

sss_status_t nx_AES_EV2_Encrypt_CommandAPDU(
    pSeSession_t session_ctx, uint8_t *cmdData, size_t cmdDataLen, uint8_t *encCmdData, size_t *encCmdDataLen)
{
    sss_status_t sss_status                           = kStatus_SSS_Fail;
    sss_symmetric_t symmCtx1                          = {0};
    sss_symmetric_t symmCtx2                          = {0};
    uint8_t iv[16]                                    = {0};
    uint8_t *pIv                                      = (uint8_t *)iv;
    uint8_t apduPayloadToEncrypt[NX_MAX_BUF_SIZE_CMD] = {0};
    size_t ref_dataLen                                = 0;

    uint8_t gen_iv_Buf[16] = {0};
    uint8_t enc_iv[16]     = {0};
    size_t enc_iv_len      = sizeof(enc_iv);
    uint8_t offset         = 0;

    sss_object_t *pEncKey = NULL;

    ENSURE_OR_GO_CLEANUP(NULL != session_ctx);
    ENSURE_OR_GO_CLEANUP(NULL != cmdData);
    ENSURE_OR_GO_CLEANUP(NULL != encCmdData);
    ENSURE_OR_GO_CLEANUP(NULL != encCmdDataLen);

    LOG_D("FN: %s", __FUNCTION__);
    if (session_ctx->authType == knx_AuthType_SIGMA_I_Verifier ||
        session_ctx->authType == knx_AuthType_SIGMA_I_Prover) {
        ENSURE_OR_GO_CLEANUP(session_ctx->ctx.pdynSigICtx != NULL);
        pEncKey = &session_ctx->ctx.pdynSigICtx->k_e2;
    }
    else if (session_ctx->authType == knx_AuthType_SYMM_AUTH) {
        ENSURE_OR_GO_CLEANUP(session_ctx->ctx.pdynSymmAuthCtx != NULL);
        pEncKey = &session_ctx->ctx.pdynSymmAuthCtx->k_e2;
    }
    else {
        LOG_E("Invalid auth type");
        goto cleanup;
    }

    ref_dataLen = cmdDataLen;

    memcpy(&apduPayloadToEncrypt, cmdData, cmdDataLen);
    nx_PadCommandAPDU(apduPayloadToEncrypt, &ref_dataLen);

    // GET IV
    gen_iv_Buf[offset++] = 0xA5;
    gen_iv_Buf[offset++] = 0x5A;
    if (session_ctx->authType == knx_AuthType_SIGMA_I_Verifier ||
        session_ctx->authType == knx_AuthType_SIGMA_I_Prover) {
        gen_iv_Buf[offset++] = (session_ctx->ctx.pdynSigICtx->TI & 0x000000FF);
        gen_iv_Buf[offset++] = (session_ctx->ctx.pdynSigICtx->TI & 0x0000FF00) >> 8;
        gen_iv_Buf[offset++] = (session_ctx->ctx.pdynSigICtx->TI & 0x00FF0000) >> 16;
        gen_iv_Buf[offset++] = (session_ctx->ctx.pdynSigICtx->TI & 0xFF000000) >> 24;
        gen_iv_Buf[offset++] = (session_ctx->ctx.pdynSigICtx->CmdCtr & 0x00FF);
        gen_iv_Buf[offset++] = (session_ctx->ctx.pdynSigICtx->CmdCtr & 0xFF00) >> 8;
    }
    else if (session_ctx->authType == knx_AuthType_SYMM_AUTH) {
        gen_iv_Buf[offset++] = (session_ctx->ctx.pdynSymmAuthCtx->TI & 0x000000FF);
        gen_iv_Buf[offset++] = (session_ctx->ctx.pdynSymmAuthCtx->TI & 0x0000FF00) >> 8;
        gen_iv_Buf[offset++] = (session_ctx->ctx.pdynSymmAuthCtx->TI & 0x00FF0000) >> 16;
        gen_iv_Buf[offset++] = (session_ctx->ctx.pdynSymmAuthCtx->TI & 0xFF000000) >> 24;
        gen_iv_Buf[offset++] = (session_ctx->ctx.pdynSymmAuthCtx->CmdCtr & 0x00FF);
        gen_iv_Buf[offset++] = (session_ctx->ctx.pdynSymmAuthCtx->CmdCtr & 0xFF00) >> 8;
    }
    ENSURE_OR_GO_CLEANUP(pEncKey != NULL);
    sss_status = sss_host_symmetric_context_init(&symmCtx1,
        pEncKey->keyStore->session,
        pEncKey,
        kAlgorithm_SSS_AES_CBC,
        kMode_SSS_Encrypt); //need to check kAlgorithm_SSS_AES_CBC or Decrypt
    ENSURE_OR_GO_CLEANUP(sss_status == kStatus_SSS_Success);

    sss_status = sss_host_cipher_one_go(&symmCtx1, pIv, EV2_KEY_SIZE, gen_iv_Buf, enc_iv, enc_iv_len);
    ENSURE_OR_GO_CLEANUP(sss_status == kStatus_SSS_Success);

    pIv = (uint8_t *)enc_iv;

    sss_status = sss_host_symmetric_context_init(&symmCtx2,
        pEncKey->keyStore->session,
        pEncKey,
        kAlgorithm_SSS_AES_CBC,
        kMode_SSS_Encrypt); //need to check kAlgorithm_SSS_AES_CBC
    ENSURE_OR_GO_CLEANUP(sss_status == kStatus_SSS_Success);

    sss_status = sss_host_cipher_one_go(&symmCtx2, pIv, EV2_KEY_SIZE, apduPayloadToEncrypt, encCmdData, ref_dataLen);
    ENSURE_OR_GO_CLEANUP(sss_status == kStatus_SSS_Success);

    *encCmdDataLen = ref_dataLen;

cleanup:

    if (symmCtx1.session != NULL) {
        sss_host_symmetric_context_free(&symmCtx1);
    }
    if (symmCtx2.session != NULL) {
        sss_host_symmetric_context_free(&symmCtx2);
    }
    return sss_status;
}

sss_status_t nx_AES_EV2_MAC_CommandAPDU(pSeSession_t session_ctx,
    uint8_t cmdByte,
    uint8_t *cmdHeader,
    size_t cmdHeaderLen,
    uint8_t *cmdData,
    size_t cmdDataLen,
    uint8_t *txBuf,
    size_t *ptxBufLen)
{
    sss_status_t sss_status                       = kStatus_SSS_Fail;
    sss_algorithm_t algorithm                     = kAlgorithm_SSS_CMAC_AES;
    sss_mode_t mode                               = kMode_SSS_Mac;
    sss_mac_t macCtx                              = {0};
    size_t i                                      = 0;
    size_t j                                      = 1;
    uint8_t macToAdd[16]                          = {0}; //need to chec length of mac
    size_t macLen                                 = sizeof(macToAdd);
    uint8_t apduPayloadToMAC[NX_MAX_BUF_SIZE_CMD] = {0};
    size_t offset                                 = 0;
    sss_object_t *pMacKey                         = NULL;

    LOG_D("FN: %s", __FUNCTION__);

    ENSURE_OR_GO_CLEANUP(NULL != session_ctx)
    ENSURE_OR_GO_CLEANUP(NULL != ptxBufLen)

    if (session_ctx->authType == knx_AuthType_SIGMA_I_Verifier ||
        session_ctx->authType == knx_AuthType_SIGMA_I_Prover) {
        ENSURE_OR_GO_CLEANUP(session_ctx->ctx.pdynSigICtx != NULL);
        pMacKey = &session_ctx->ctx.pdynSigICtx->k_m2;
    }
    else if (session_ctx->authType == knx_AuthType_SYMM_AUTH) {
        ENSURE_OR_GO_CLEANUP(session_ctx->ctx.pdynSymmAuthCtx != NULL);
        pMacKey = &session_ctx->ctx.pdynSymmAuthCtx->k_m2;
    }
    else {
        LOG_E("Invalid auth type");
        goto cleanup;
    }

    apduPayloadToMAC[offset++] = cmdByte;
    if (session_ctx->authType == knx_AuthType_SIGMA_I_Verifier ||
        session_ctx->authType == knx_AuthType_SIGMA_I_Prover) {
        apduPayloadToMAC[offset++] = (session_ctx->ctx.pdynSigICtx->CmdCtr & 0x00FF);
        apduPayloadToMAC[offset++] = (session_ctx->ctx.pdynSigICtx->CmdCtr & 0xFF00) >> 8;
        apduPayloadToMAC[offset++] = (session_ctx->ctx.pdynSigICtx->TI & 0x000000FF);
        apduPayloadToMAC[offset++] = (session_ctx->ctx.pdynSigICtx->TI & 0x0000FF00) >> 8;
        apduPayloadToMAC[offset++] = (session_ctx->ctx.pdynSigICtx->TI & 0x00FF0000) >> 16;
        apduPayloadToMAC[offset++] = (session_ctx->ctx.pdynSigICtx->TI & 0xFF000000) >> 24;
    }
    else if (session_ctx->authType == knx_AuthType_SYMM_AUTH) {
        apduPayloadToMAC[offset++] = (session_ctx->ctx.pdynSymmAuthCtx->CmdCtr & 0x00FF);
        apduPayloadToMAC[offset++] = (session_ctx->ctx.pdynSymmAuthCtx->CmdCtr & 0xFF00) >> 8;
        apduPayloadToMAC[offset++] = (session_ctx->ctx.pdynSymmAuthCtx->TI & 0x000000FF);
        apduPayloadToMAC[offset++] = (session_ctx->ctx.pdynSymmAuthCtx->TI & 0x0000FF00) >> 8;
        apduPayloadToMAC[offset++] = (session_ctx->ctx.pdynSymmAuthCtx->TI & 0x00FF0000) >> 16;
        apduPayloadToMAC[offset++] = (session_ctx->ctx.pdynSymmAuthCtx->TI & 0xFF000000) >> 24;
    }

    ENSURE_OR_GO_CLEANUP((UINT_MAX - offset) >= cmdHeaderLen);
    if ((cmdHeaderLen > 0) && (NULL != cmdHeader)) {
        memcpy(&apduPayloadToMAC[offset], cmdHeader, cmdHeaderLen);
        ENSURE_OR_GO_CLEANUP(UINT_MAX > offset + cmdHeaderLen);
        offset += cmdHeaderLen;
    }

    if ((cmdDataLen > 0) && (NULL != cmdData)) {
        ENSURE_OR_GO_CLEANUP(offset < NX_MAX_BUF_SIZE_CMD);
        memcpy(&apduPayloadToMAC[offset], cmdData, cmdDataLen);
        ENSURE_OR_GO_CLEANUP(UINT_MAX > offset + cmdDataLen);
        offset += cmdDataLen;
    }

    ENSURE_OR_GO_CLEANUP(pMacKey != NULL);
    sss_status = sss_host_mac_context_init(&macCtx, pMacKey->keyStore->session, pMacKey, algorithm, mode);
    ENSURE_OR_GO_CLEANUP(sss_status == kStatus_SSS_Success);

    sss_status =
        sss_host_mac_one_go(&macCtx, apduPayloadToMAC, offset, macToAdd, &macLen); //need to check macToAdd and maclen
    ENSURE_OR_GO_CLEANUP(sss_status == kStatus_SSS_Success);

    //copy request handle data to txBuf
    i = 0;
    if ((cmdHeaderLen > 0) && (NULL != cmdHeader)) {
        memcpy(&txBuf[i], cmdHeader, cmdHeaderLen);
        i += cmdHeaderLen;
    }

    if ((UINT_MAX - i) < cmdDataLen) {
        sss_status = kStatus_SSS_Fail;
        goto cleanup;
    }
    if ((cmdDataLen > 0) && (NULL != cmdData)) {
        memcpy(&txBuf[i], cmdData, cmdDataLen);
        i += cmdDataLen;
    }

    while ((macLen > 0) && (j <= 15)) {
        if (i >= (*ptxBufLen)) {
            sss_status = kStatus_SSS_Fail;
            goto cleanup;
        }
        txBuf[i++] = macToAdd[j];
        j += 2;
    }

    *ptxBufLen = i;

cleanup:
    if (macCtx.session != NULL) {
        sss_host_mac_context_free(&macCtx);
    }
    return sss_status;
}

static uint16_t nx_AES_EV2_MAC_Verify(uint8_t *rspBuf, size_t compareoffset, uint8_t *respMac, size_t respMac_len)
{
    uint8_t ref_mac_value[8] = {0};
    uint8_t i = 0, j = 1;

    while (j <= 15) {
        ref_mac_value[i++] = respMac[j];
        j += 2;
    }
    if (memcmp(&rspBuf[compareoffset], ref_mac_value, NTAG_AES128_EV2_COMMAND_MAC_SIZE) != 0) {
        return SCP_FAIL;
    }

    return SCP_OK;
}

sss_status_t nx_AES_EV2_Plain_CommandAPDU(pSeSession_t session_ctx,
    uint8_t *cmdHeader,
    size_t cmdHeaderLen,
    uint8_t *cmdData,
    size_t dataLen,
    uint8_t *txBuf,
    size_t *ptxBufLen)
{
    sss_status_t sss_status = kStatus_SSS_Fail;
    size_t i                = 0;

    ENSURE_OR_GO_CLEANUP(NULL != session_ctx);
    ENSURE_OR_GO_CLEANUP(NULL != txBuf);
    ENSURE_OR_GO_CLEANUP(NULL != ptxBufLen);

    if (session_ctx->authType == knx_AuthType_SIGMA_I_Verifier ||
        session_ctx->authType == knx_AuthType_SIGMA_I_Prover) {
        ENSURE_OR_GO_CLEANUP(session_ctx->ctx.pdynSigICtx != NULL);
    }
    else if (session_ctx->authType == knx_AuthType_SYMM_AUTH) {
        ENSURE_OR_GO_CLEANUP(session_ctx->ctx.pdynSymmAuthCtx != NULL);
    }
    else {
        LOG_E("Invalid auth type");
        goto cleanup;
    }

    LOG_D("FN: %s", __FUNCTION__);

    if ((cmdHeader != NULL) && (cmdHeaderLen > 0) && (cmdHeaderLen <= NX_MAX_BUF_SIZE_CMD)) {
        memcpy(&txBuf[i], cmdHeader, cmdHeaderLen);
        i += cmdHeaderLen;
    }
    ENSURE_OR_GO_CLEANUP((UINT_MAX - i) >= dataLen);
    if ((cmdData != NULL) && (dataLen > 0)) {
        memcpy(&txBuf[i], cmdData, dataLen);
        i += dataLen;
    }

    *ptxBufLen = i;

    sss_status = kStatus_SSS_Success;

cleanup:
    return sss_status;
}

void nx_AES_EV2_CommandAPDU_log(
    uint8_t cmdByte, uint8_t *cmdHeader, size_t cmdHeaderLen, uint8_t *cmdData, size_t cmdDataLen)
{
    LOG_MAU8_D(" Input:Native Command code", &cmdByte, sizeof(cmdByte));
    if ((cmdHeader != NULL) && (cmdHeaderLen > 0)) {
        LOG_MAU8_D(" Input:Native Command Header", cmdHeader, cmdHeaderLen);
    }
    if ((cmdData != NULL) && (cmdDataLen > 0)) {
        LOG_MAU8_D(" Input:Native Command Data", cmdData, cmdDataLen);
    }
}

static void nx_PadCommandAPDU(uint8_t *cmdApduBuf, size_t *cmdApduBufLen)
{
    uint16_t zeroBytesToPad = 0;

    ENSURE_OR_GO_EXIT(cmdApduBufLen != NULL);
    ENSURE_OR_GO_EXIT(cmdApduBuf != NULL);
    ENSURE_OR_GO_EXIT((UINT_MAX - 1) > (*cmdApduBufLen));
    ENSURE_OR_GO_EXIT((*cmdApduBufLen) - 1 < NX_MAX_BUF_SIZE_CMD);

    // pad the payload and adjust the length of the APDU
    cmdApduBuf[(*cmdApduBufLen)] = EV2_DATA_PAD_BYTE; //need to check
    *cmdApduBufLen += 1;
    zeroBytesToPad = (EV2_KEY_SIZE - ((*cmdApduBufLen) % EV2_KEY_SIZE)) % EV2_KEY_SIZE; //need to check
    ENSURE_OR_GO_EXIT((NX_MAX_BUF_SIZE_CMD - (*cmdApduBufLen)) > zeroBytesToPad);
    while (zeroBytesToPad > 0) {
        cmdApduBuf[(*cmdApduBufLen)] = 0x00;
        ENSURE_OR_GO_EXIT((UINT_MAX - 1) > (*cmdApduBufLen));
        *cmdApduBufLen += 1;
        zeroBytesToPad--;
    }

    LOG_D("FN: %s", __FUNCTION__);
    LOG_MAU8_D("Input: cmdApduBuf", cmdApduBuf, *cmdApduBufLen);

exit:
    return;
}

uint16_t nx_get_command_commMode(uint8_t cmdByte, nx_ev2_comm_mode_t *CommMode)
{
    uint16_t ret = SCP_FAIL;

    ENSURE_OR_GO_EXIT(NULL != CommMode)

    switch (cmdByte) {
    case NX_INS_GET_CARDUID:
    case NX_INS_MGMT_CERT_REPO:
    case NX_INS_SET_CONFIG:
    case NX_INS_CHANGE_FILE_SETTING:
    case NX_INS_GET_CONFIG:
    case NX_INS_CHANGE_KEY:
    case NX_INS_GET_FILE_COUNTERS:
        *CommMode = EV2_CommMode_FULL;
        break;
    case NX_INS_GET_VERSION:
    case NX_INS_GET_KEY_VERSION:
    case NX_INS_GET_KEY_SETTINGS:
    case NX_INS_GET_ISO_FILE_IDS:
    case NX_INS_GET_FILE_IDS:
    case NX_INS_CREATE_STD_DATA_FILE:
    case NX_INS_CREATE_COUNTER_FILE:
    case NX_INS_GET_FILE_SETTINGS:
    case NX_INS_FREE_MEM:
    case NX_INS_ACTIVATE_CONFIG:
        *CommMode = EV2_CommMode_MAC;
        break;
    case NX_INS_ADDITIONAL_FRAME_REQ:
    case NX_INS_ISO_SELECT_FILE:
    case NX_INS_PROCESS_SM:
        *CommMode = (EV2_CommMode_PLAIN & 0x0F);
        break;
    default:
        goto exit;
    }
    ret = SCP_OK;
exit:
    return ret;
}

static uint16_t nx_AES_EV2_Restore_RAPDU(
    uint8_t *rspBuf, size_t *pRspBufLen, uint8_t *plaintextResponse, size_t plaintextRespLen)
{
    uint16_t status     = SCP_DECODE_FAIL;
    size_t i            = 0;
    int removePaddingOk = 0;

    i = plaintextRespLen;
    ENSURE_OR_GO_EXIT(pRspBufLen != NULL);
    ENSURE_OR_GO_EXIT(plaintextResponse != NULL);
    ENSURE_OR_GO_EXIT(rspBuf != NULL);
    ENSURE_OR_GO_EXIT((*pRspBufLen) >= 2);
    while (i > 1) {
        if (plaintextResponse[i - 1] == 0x00) {
            i--;
        }
        else if (plaintextResponse[i - 1] == EV2_DATA_PAD_BYTE) {
            // We have found padding delimitor
            memcpy(rspBuf, plaintextResponse, i - 1);
            memcpy(&rspBuf[i - 1], &rspBuf[*pRspBufLen - 2], 2); // Copy SW1 SW2 to plain response
            *pRspBufLen     = (i - 1) + 2;                       // Include SW1 SW2
            removePaddingOk = 1;
            LOG_MAU8_D("Decrypted the response", rspBuf, *pRspBufLen);
            break;
        }
        else {
            // We've found a non-padding character while removing padding
            // Most likely the cipher text was not properly decoded.
            LOG_E("RAPDU Decoding failed No Padding found %04X", status);
            break;
        }
    }

    if (removePaddingOk == 0) {
        goto exit;
    }
    status = SCP_OK;
exit:
    return status;
}

#endif //SSS_HAVE_HOSTCRYPTO_ANY && (either of one authentication)
