/*
 *
 * Copyright 2025 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <stddef.h>
#include "nxLog_msg.h"
#include "nxEnsure.h"
#include "sm_timer.h"
#include "phEseStatus.h"
#include "host_copro_utils.h"
#include "host_copro_nx_apdu.h"
#include "host_copro_txn.h"
#include "host_coprocessor.h"

/* ************************************************************************** */
/* Local Defines                                                              */
/* ************************************************************************** */

/* ************************************************************************** */
/* Structures and Typedefs                                                    */
/* ************************************************************************** */

/* ************************************************************************** */
/* Global Variables                                                           */
/* ************************************************************************** */

/* ************************************************************************** */
/* Static function declarations                                               */
/* ************************************************************************** */

static smStatus_t nx_hcpIsogeneralAuth(
    void **conn_ctx, uint8_t *cmdData, size_t cmdLen, uint8_t *rspData, size_t *rspLen);

smStatus_t nx_ProcessSM_Remove(void **conn_ctx,
    Nx_CommMode_t commMode,
    uint8_t *cipherData,
    size_t cipherDataLen,
    uint8_t *plainData,
    size_t *plainDataLen)
{
    smStatus_t retStatus                    = SM_NOT_OK;
    tlvHeader_t hdr                         = {{NX_CLA, INS_NX_PROCESS_SM, NX_P1_DEFAULT, NX_P1_DEFAULT}};
    uint8_t cmdDataBuf[NX_MAX_BUF_SIZE_CMD] = {0};
    size_t cmdDataBufBufLen                 = 0;
    int tlvRet                              = 1;
    uint8_t *pCmdDataBuf                    = &cmdDataBuf[0];
    size_t rspIndex                         = 0;
    uint8_t rspbuf[NX_MAX_BUF_SIZE_RSP]     = {0};
    size_t rspbufLen                        = sizeof(rspbuf);
    uint8_t commModeByte                    = 0;

    ENSURE_OR_GO_CLEANUP(NULL != conn_ctx);
    ENSURE_OR_GO_CLEANUP(NULL != cipherData);
    ENSURE_OR_GO_CLEANUP(NULL != plainData);

    retStatus = SM_NOT_OK; //reinitialized
#if VERBOSE_APDU_LOGS
    // NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "ProcessSM_Remove []");
#endif /* VERBOSE_APDU_LOGS */

    tlvRet = hcp_set_U8(&pCmdDataBuf, &cmdDataBufBufLen, Nx_ProcessSM_Action_Remove);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = hcp_set_U8(&pCmdDataBuf, &cmdDataBufBufLen, Nx_ProcessSM_Operation_Oneshot);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    commModeByte = commMode;
    commModeByte = (commModeByte << 4);
    tlvRet       = hcp_set_U8(&pCmdDataBuf, &cmdDataBufBufLen, commModeByte);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    if (commMode != Nx_CommMode_Plain) {
        if ((cipherData != NULL) && (cipherDataLen >= NX_PROCESSSM_PLAIN_TEXT_LENGTH_MIN) &&
            (cipherDataLen <= NX_PROCESSSM_PLAIN_TEXT_LENGTH_MAX)) {
            tlvRet = hcp_set_u8buf(&pCmdDataBuf, &cmdDataBufBufLen, cipherData, cipherDataLen);
            ENSURE_OR_GO_CLEANUP(0 == tlvRet);
        }
        else {
            goto cleanup;
        }
    }

    retStatus = nx_hcpTXn(conn_ctx, &hdr, NULL, 0, cmdDataBuf, cmdDataBufBufLen, rspbuf, &rspbufLen, 1, 0);

    if (retStatus == SM_OK || retStatus == SM_OK_ALT) {
        retStatus = SM_NOT_OK;

        if ((commMode == Nx_CommMode_Plain) && (rspbufLen != 2)) {
            goto cleanup;
        }
        else if (commMode != Nx_CommMode_Plain) {
            if ((rspbufLen < 2) || (plainData == NULL) || (plainDataLen == NULL)) {
                goto cleanup;
            }

            tlvRet = hcp_get_u8buf(rspbuf, &rspIndex, rspbufLen, plainData, rspbufLen - 2);
            ENSURE_OR_GO_CLEANUP(0 == tlvRet);
            *plainDataLen = rspbufLen - 2;
        }

        retStatus = (rspbuf[rspbufLen - 2] << 8) | (rspbuf[rspbufLen - 1]);
        if (retStatus == SM_OK_ALT) {
            retStatus = SM_OK;
        }
    }

cleanup:
    return retStatus;
}

smStatus_t nx_ProcessSMApply(void **conn_ctx,
    Nx_CommMode_t commMode,
    uint8_t offset,
    uint8_t cmdCtrIncr,
    uint8_t *plainData,
    size_t plainDataLen,
    uint8_t *cipherData,
    size_t *cipherDataLen)
{
    smStatus_t retStatus                    = SM_NOT_OK;
    tlvHeader_t hdr                         = {{NX_CLA, INS_NX_PROCESS_SM, NX_P1_DEFAULT, NX_P1_DEFAULT}};
    uint8_t cmdDataBuf[NX_MAX_BUF_SIZE_CMD] = {0};
    size_t cmdDataBufBufLen                 = 0;
    int tlvRet                              = 1;
    uint8_t *pCmdDataBuf                    = &cmdDataBuf[0];
    size_t rspIndex                         = 0;
    uint8_t rspbuf[NX_MAX_BUF_SIZE_RSP]     = {0};
    size_t rspbufLen                        = sizeof(rspbuf);
    uint8_t commModeByte                    = 0;

    ENSURE_OR_GO_CLEANUP(NULL != conn_ctx);
    ENSURE_OR_GO_CLEANUP(NULL != plainData);
    ENSURE_OR_GO_CLEANUP(NULL != cipherData);

    retStatus = SM_NOT_OK; //reinitialized

#if VERBOSE_APDU_LOGS
    // NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "ProcessSM_Apply []");
#endif /* VERBOSE_APDU_LOGS */

    tlvRet = hcp_set_U8(&pCmdDataBuf, &cmdDataBufBufLen, Nx_ProcessSM_Action_Apply);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = hcp_set_U8(&pCmdDataBuf, &cmdDataBufBufLen, Nx_ProcessSM_Operation_Oneshot);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    commModeByte = commMode;
    commModeByte = (commModeByte << 4);
    tlvRet       = hcp_set_U8(&pCmdDataBuf, &cmdDataBufBufLen, commModeByte);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    if (commMode == Nx_CommMode_FULL) {
        tlvRet = hcp_set_U8(&pCmdDataBuf, &cmdDataBufBufLen, offset);
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);
    }
    else if (commMode == Nx_CommMode_Plain) {
        tlvRet = hcp_set_U8(&pCmdDataBuf, &cmdDataBufBufLen, cmdCtrIncr);
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);
    }

    if (commMode != Nx_CommMode_Plain) {
        if ((plainData != NULL) && (plainDataLen >= NX_PROCESSSM_PLAIN_TEXT_LENGTH_MIN) &&
            (plainDataLen <= NX_PROCESSSM_PLAIN_TEXT_LENGTH_MAX)) {
            tlvRet = hcp_set_u8buf(&pCmdDataBuf, &cmdDataBufBufLen, plainData, plainDataLen);
            ENSURE_OR_GO_CLEANUP(0 == tlvRet);
        }
        else {
            goto cleanup;
        }
    }

    retStatus = nx_hcpTXn(conn_ctx, &hdr, NULL, 0, cmdDataBuf, cmdDataBufBufLen, rspbuf, &rspbufLen, 1, 0);

    if (retStatus == SM_OK || retStatus == SM_OK_ALT) {
        retStatus = SM_NOT_OK;
        if ((commMode == Nx_CommMode_Plain) && (rspbufLen != 2)) {
            goto cleanup;
        }
        else if ((rspbufLen < 2) || (cipherData == NULL) || (cipherDataLen == NULL)) {
            goto cleanup;
        }
        else {
            tlvRet = hcp_get_u8buf(rspbuf, &rspIndex, rspbufLen, cipherData, rspbufLen - 2);
            ENSURE_OR_GO_CLEANUP(0 == tlvRet);
            *cipherDataLen = rspbufLen - 2;
        }
        retStatus = (rspbuf[rspbufLen - 2] << 8) | (rspbuf[rspbufLen - 1]);
        if (retStatus == SM_OK_ALT) {
            retStatus = SM_OK;
        }
    }

cleanup:
    return retStatus;
}

smStatus_t nx_Freemem(void **conn_ctx,
    void **conn2_ctx,
    phNxpEseProto7816_t *pi2c_ps1_ctx,
    phNxpEseProto7816_t *pi2c_ps2_ctx,
    uint32_t *freeMemSize)
{
    smStatus_t retStatus                    = SM_NOT_OK;
    tlvHeader_t hdr                         = {{NX_CLA, NX_INS_FREE_MEM, NX_P1_DEFAULT, NX_P1_DEFAULT}};
    uint8_t cmdDataBuf[NX_MAX_BUF_SIZE_CMD] = {0};
    size_t cmdDataBufLen                    = 0;
    uint8_t rspbuf[NX_MAX_BUF_SIZE_RSP]     = {0};
    size_t rspbufLen                        = sizeof(rspbuf);
    uint8_t *pRspbuf                        = &rspbuf[0];
    uint8_t freeMemBuf[3]                   = {0};
    Nx_CommMode_t commModeByte              = Nx_CommMode_MAC;

    ENSURE_OR_GO_EXIT(NULL != conn_ctx);
    ENSURE_OR_GO_EXIT(NULL != conn2_ctx);
    ENSURE_OR_GO_EXIT(NULL != pi2c_ps1_ctx);
    ENSURE_OR_GO_EXIT(NULL != pi2c_ps2_ctx);
    ENSURE_OR_GO_EXIT(NULL != freeMemSize);

#if VERBOSE_APDU_LOGS
    // NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "nx_hcpFreemem []");
#endif /* VERBOSE_APDU_LOGS */

    retStatus = hcpContextSwitching(pi2c_ps2_ctx, pi2c_ps1_ctx);
    if (retStatus != ESESTATUS_SUCCESS) {
        LOG_E("hcpContextSwitching failed");
        goto exit;
    }
    memset(&cmdDataBuf[0], 0x00, sizeof(cmdDataBuf));
    cmdDataBuf[0]          = NX_HOST_COPRO_FREEMEM;
    cmdDataBufLen          = 1;
    rspbufLen              = sizeof(rspbuf);
    Nx_CommMode_t commMode = Nx_CommMode_MAC;
    LOG_I("ProcessSM_Apply Device 1");
    retStatus = nx_ProcessSMApply(conn_ctx, commModeByte, 0, 0, &cmdDataBuf[0], cmdDataBufLen, &rspbuf[0], &rspbufLen);
    if (retStatus != SM_OK) {
        goto exit;
    }
    //copy the MAC value
    memset(&cmdDataBuf[0], 0x00, sizeof(cmdDataBuf));
    memcpy(&cmdDataBuf[0], &rspbuf[0], rspbufLen);
    cmdDataBufLen = rspbufLen;
    memset(&rspbuf[0], 0x00, sizeof(rspbufLen));
    rspbufLen = sizeof(rspbuf);

    retStatus = hcpContextSwitching(pi2c_ps1_ctx, pi2c_ps2_ctx);
    if (retStatus != ESESTATUS_SUCCESS) {
        LOG_E("hcpContextSwitching failed");
        goto exit;
    }

    retStatus = nx_hcpTXn(conn2_ctx, &hdr, NULL, 0, cmdDataBuf, cmdDataBufLen, pRspbuf, &rspbufLen, 1, 1);
    if (retStatus == SM_OK) {
        retStatus = SM_NOT_OK;

        if (rspbufLen < 2) {
            goto exit;
        }
        else if (rspbufLen > 2) {
            memcpy(freeMemBuf, rspbuf, 3);
            *freeMemSize = (uint32_t)((freeMemBuf[2] << 16) | (freeMemBuf[1] << 8) | freeMemBuf[0]);
        }
        retStatus = (rspbuf[rspbufLen - 2] << 8) | (rspbuf[rspbufLen - 1]);
        if (retStatus == SM_OK_ALT) {
            retStatus = SM_OK;
        }
        else {
            *freeMemSize = 0;
            goto exit;
        }
    }

    retStatus = hcpContextSwitching(pi2c_ps2_ctx, pi2c_ps1_ctx);
    if (retStatus != ESESTATUS_SUCCESS) {
        LOG_E("hcpContextSwitching failed");
        goto exit;
    }

    // RC || RespData || MAC
    cmdDataBuf[0] = 0x00; // RC value
    cmdDataBufLen = 1;
    memcpy(&cmdDataBuf[1], &rspbuf[0], rspbufLen - 2);
    cmdDataBufLen += rspbufLen - 2;
    memset(&rspbuf[0], 0x00, sizeof(rspbufLen));
    rspbufLen = sizeof(rspbuf);

    LOG_I("ProcessSMRemove Device 1");
    retStatus = nx_ProcessSM_Remove(conn_ctx, commMode, &cmdDataBuf[0], cmdDataBufLen, &rspbuf[0], &rspbufLen);
    if (retStatus != SM_OK) {
        *freeMemSize = 0;
        LOG_E("nx_ProcessSM_Remove failed");
        goto exit;
    }

exit:
    return retStatus;
}

static smStatus_t nx_hcpIsogeneralAuth(
    void **conn_ctx, uint8_t *cmdData, size_t cmdLen, uint8_t *rspData, size_t *rspLen)
{
    smStatus_t retStatus                    = SM_NOT_OK;
    tlvHeader_t hdr                         = {{CLA_ISO7816, INS_GP_ISO_GENERAL_AUTHENTICATE, P1_SIGMA_I, P2_SIGMA_I}};
    uint8_t cmdDataBuf[NX_MAX_BUF_SIZE_CMD] = {0};
    size_t cmdDataBufLen                    = 0;
    int tlvRet                              = 1;
    uint8_t *pCmdDataBuf                    = &cmdDataBuf[0];
    uint8_t rspbuf[NX_MAX_BUF_SIZE_RSP]     = {0};
    size_t rspbufLen                        = sizeof(rspbuf);
    uint8_t *pRspbuf                        = &rspbuf[0];
    size_t rspIndex                         = 0;

    ENSURE_OR_GO_CLEANUP(NULL != conn_ctx);
    ENSURE_OR_GO_CLEANUP(NULL != cmdData);
    ENSURE_OR_GO_CLEANUP(NULL != rspData);
    ENSURE_OR_GO_CLEANUP(NULL != rspLen);

#if VERBOSE_APDU_LOGS
    // NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "nx_hcpIsogeneralAuth []");
#endif /* VERBOSE_APDU_LOGS */

    tlvRet = hcp_set_u8buf(&pCmdDataBuf, &cmdDataBufLen, (uint8_t *)cmdData, cmdLen);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    retStatus = nx_hcpTXn(conn_ctx, &hdr, NULL, 0, cmdDataBuf, cmdDataBufLen, pRspbuf, &rspbufLen, 1, 1);
    if (retStatus == SM_OK) {
        retStatus = SM_NOT_OK;

        if (rspbufLen < 2) {
            goto cleanup;
        }
        else if (rspbufLen > 2) {
            tlvRet = hcp_get_u8buf(rspbuf, &rspIndex, rspbufLen, rspData, rspbufLen - 2);
            ENSURE_OR_GO_CLEANUP(0 == tlvRet);
            *rspLen = rspbufLen - 2;
        }
        else {
            *rspLen = 0;
        }

        retStatus = (rspbuf[rspbufLen - 2] << 8) | (rspbuf[rspbufLen - 1]);
    }

cleanup:
    return retStatus;
}

smStatus_t nx_hcpEstablishSession(void **conn_ctx,
    void **conn2_ctx,
    phNxpEseProto7816_t *pi2c_ps1_ctx,
    phNxpEseProto7816_t *pi2c_ps2_ctx,
    uint8_t *cmdData,
    size_t cmdLen,
    uint8_t *rspData,
    size_t *rspLen)
{
    smStatus_t retStatus           = SM_NOT_OK;
    ESESTATUS status               = ESESTATUS_FAILED;
    void **temp                    = conn_ctx;
    phNxpEseProto7816_t *tmpdeinit = pi2c_ps2_ctx;
    phNxpEseProto7816_t *tmpinit   = pi2c_ps1_ctx;
    bool flag                      = true;

    ENSURE_OR_GO_CLEANUP(NULL != conn_ctx);
    ENSURE_OR_GO_CLEANUP(NULL != conn2_ctx);
    ENSURE_OR_GO_CLEANUP(NULL != pi2c_ps1_ctx);
    ENSURE_OR_GO_CLEANUP(NULL != pi2c_ps2_ctx);
    ENSURE_OR_GO_CLEANUP(NULL != cmdData);
    ENSURE_OR_GO_CLEANUP(NULL != rspData);
    ENSURE_OR_GO_CLEANUP(NULL != rspLen);

    while (cmdData[0] != NX_HOST_COPRO_MSG_SESSION_OK) {
        status = hcpContextSwitching(tmpdeinit, tmpinit);
        if (status != ESESTATUS_SUCCESS) {
            LOG_E("hcpContextSwitching failed");
            retStatus = SM_NOT_OK;
            goto cleanup;
        }

        retStatus = nx_hcpIsogeneralAuth(temp, &cmdData[0], cmdLen, &rspData[0], rspLen);
        if (retStatus != SM_OK) {
            LOG_E("nx_hcpIsogeneralAuth failed");
            goto cleanup;
        }

        //copy response data to command data
        memset(&cmdData[0], 0x00, NX_MAX_BUF_SIZE_CMD);
        memcpy(&cmdData[0], &rspData[0], *rspLen);
        cmdLen = *rspLen;

        //clear response data
        *rspLen = NX_MAX_BUF_SIZE_RSP;
        memset(&rspData[0], 0x00, *rspLen);

        //switch host to device or vise versa
        if (flag) {
            tmpdeinit = pi2c_ps1_ctx;
            tmpinit   = pi2c_ps2_ctx;
            temp      = conn2_ctx;
            flag      = false;
        }
        else {
            tmpdeinit = pi2c_ps2_ctx;
            tmpinit   = pi2c_ps1_ctx;
            temp      = conn_ctx;
            flag      = true;
        }
    }

cleanup:
    return retStatus;
}
