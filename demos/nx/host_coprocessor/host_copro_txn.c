/*
 *
 * Copyright 2025 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "phEseTypes.h"
#include "phEseStatus.h"
#include "phNxpEse_Api.h"
#include "platform.h"
#include "phNxpEse_internal.h"
#include "sm_timer.h"
#include "phNxpEseProto7816_3.h"
#include "nxLog_msg.h"
#include "nxEnsure.h"
#include "host_copro_utils.h"
#include "host_copro_txn.h"

/* ************************************************************************** */
/* Local Defines                                                              */
/* ************************************************************************** */

/* ************************************************************************** */
/* Static function declarations                                               */
/* ************************************************************************** */

static ESESTATUS hcpSmComT1oI2C_TransceiveRaw(void *conn_ctx, U8 *pTx, U16 txLen, U8 *pRx, U32 *pRxLen);

static smStatus_t sss_nx_hcp_channel_txnRaw(void *conn_ctx,
    const tlvHeader_t *hdr,
    uint8_t *cmdBuf,
    size_t cmdBufLen,
    uint8_t *rsp,
    size_t *rspLen,
    uint8_t hasle,
    uint8_t isExtended);

/* ************************************************************************** */
/* Public Functions                                                           */
/* ************************************************************************** */

static ESESTATUS hcpSmComT1oI2C_TransceiveRaw(void *conn_ctx, U8 *pTx, U16 txLen, U8 *pRx, U32 *pRxLen)
{
    phNxpEse_data pCmdTrans = {0};
    phNxpEse_data pRspTrans = {0};
    ESESTATUS txnStatus     = ESESTATUS_FAILED;

    pCmdTrans.len    = txLen;
    pCmdTrans.p_data = pTx;

    ENSURE_OR_GO_EXIT(NULL != pRxLen)

    pRspTrans.len    = *pRxLen;
    pRspTrans.p_data = pRx;

    LOG_MAU8_D("APDU Tx>", pTx, txLen);
    txnStatus = phNxpEse_Transceive(conn_ctx, &pCmdTrans, &pRspTrans);
    if (txnStatus == ESESTATUS_SUCCESS) {
        *pRxLen = pRspTrans.len;
        LOG_MAU8_D("APDU Rx<", pRx, pRspTrans.len);
    }
    else {
        *pRxLen = 0;
        LOG_E(" Transcive Failed ");
        return ESESTATUS_FAILED;
    }

exit:
    return txnStatus;
}

static smStatus_t sss_nx_hcp_channel_txnRaw(void *conn_ctx,
    const tlvHeader_t *hdr,
    uint8_t *cmdBuf,
    size_t cmdBufLen,
    uint8_t *rsp,
    size_t *rspLen,
    uint8_t hasle,
    uint8_t isExtended)
{
    uint8_t hdrBuf[10] = {0};
    size_t i           = 0;
    ESESTATUS status   = ESESTATUS_FAILED;
    smStatus_t ret     = SM_NOT_OK;

    if ((hdr == NULL) || (cmdBuf == NULL) || (rsp == NULL) || (rspLen == NULL)) {
        LOG_E("Tx APDU command failed: Wrong parameter.");
        goto exit;
    }

    if ((cmdBufLen >= 256) && (isExtended == 0)) {
        // Lc 1 - 255 Byte for short.
        LOG_E("Construct APDU command failed: too long command.");
        goto exit;
    }

    if ((cmdBufLen >= 65536) && (isExtended == 1)) {
        // Lc 1 - 65535 Byte for extended.
        LOG_E("Construct APDU command failed: too long command.");
        goto exit;
    }

    memcpy(&hdrBuf[i], hdr, sizeof(*hdr));
    i += sizeof(*hdr);

    // Lc + command
    if (cmdBufLen > 0) {
        if (isExtended == 1) {
            // Extended mode
            hdrBuf[i++] = 0x00;
            hdrBuf[i++] = 0xFFu & (cmdBufLen >> 8);
            hdrBuf[i++] = 0xFFu & (cmdBufLen);
        }
        else {
            // Short mode
            hdrBuf[i++] = (uint8_t)cmdBufLen;
        }
        ENSURE_OR_GO_EXIT(SIZE_MAX - i > cmdBufLen);
        ENSURE_OR_GO_EXIT((i + cmdBufLen) <= NX_MAX_BUF_SIZE_CMD);
    }

    memmove(cmdBuf + i, cmdBuf, cmdBufLen);
    memcpy(cmdBuf, hdrBuf, i);
    i += cmdBufLen;

    // Le
    if (hasle == 1) {
        // Short Le: 0x00   // 256Bytes
        // Extended Le: 0x00 0x00   // 65536Bytes
        // Extended Le without Lc: 0x00 0x00 0x00 // 65536Bytes
        ENSURE_OR_GO_EXIT(i < (NX_MAX_BUF_SIZE_CMD));
        cmdBuf[i++] = 0x00;
        if (isExtended == 1) {
            if (cmdBufLen == 0) { // Lc = 0
                ENSURE_OR_GO_EXIT(i < (NX_MAX_BUF_SIZE_CMD - 1));
                cmdBuf[i++] = 0x00;
                cmdBuf[i++] = 0x00;
            }
            else {
                ENSURE_OR_GO_EXIT(i < (NX_MAX_BUF_SIZE_CMD));
                cmdBuf[i++] = 0x00;
            }
        }
    }

    ENSURE_OR_GO_EXIT((*rspLen) <= UINT32_MAX);
    uint32_t U32rspLen = (uint32_t)*rspLen;
    status             = hcpSmComT1oI2C_TransceiveRaw(conn_ctx, cmdBuf, (U16)i, rsp, &U32rspLen);
    if (status != ESESTATUS_SUCCESS) {
        ret = SM_NOT_OK;
        goto exit;
    }
    *rspLen = U32rspLen;
    ret     = SM_OK;

exit:
    return ret;
}

smStatus_t hcpContextSwitching(phNxpEseProto7816_t *deinitconn_ctx, phNxpEseProto7816_t *initconn_ctx)
{
    ESESTATUS status = ESESTATUS_FAILED;

    if (deinitconn_ctx == NULL || initconn_ctx == NULL) {
        goto exit;
    }

    status = phNxpEseProto7816_Retrieve(deinitconn_ctx);
    if (status != TRUE) {
        printf("phNxpEseProto7816_Retrieve Failed\n");
        goto exit;
    }
    status = phNxpEseProto7816_Store(initconn_ctx);
    if (status != TRUE) {
        printf("phNxpEseProto7816_Store Failed\n");
        goto exit;
    }

    status = ESESTATUS_SUCCESS;
exit:
    return status;
}

smStatus_t nx_hcpTXn(void **conn_ctx,
    const tlvHeader_t *hdr,
    uint8_t *cmdHeader,
    size_t cmdHeaderLen,
    uint8_t *cmdData,
    size_t cmdDataLen,
    uint8_t *rsp,
    size_t *rspLen,
    uint8_t hasle,
    uint8_t isExtended)
{
    smStatus_t ret = SM_NOT_OK;

    ENSURE_OR_GO_EXIT(hdr != NULL);
    ENSURE_OR_GO_EXIT((cmdData != NULL) || (cmdDataLen == 0));
    ENSURE_OR_GO_EXIT(rsp != NULL);
    ENSURE_OR_GO_EXIT(rspLen != NULL);

    ret = sss_nx_hcp_channel_txnRaw(conn_ctx, hdr, cmdData, cmdDataLen, rsp, rspLen, hasle, isExtended);
    ENSURE_OR_GO_EXIT(ret == SM_OK);

exit:
    return ret;
}

ESESTATUS nx_hcpSelectApplication(void **conn_ctx, const char *pdeviceName)
{
    /* Send select file command */
    ESESTATUS status               = ESESTATUS_FAILED;
    U8 Cip[64]                     = {0};
    U16 CipLen                     = sizeof(Cip);
    phNxpEse_data AtrRsp           = {0};
    phNxpEse_initParams initParams = {0};
    initParams.initMode            = ESE_MODE_NORMAL;
    unsigned char appletName[]     = APPLET_NAME;
    uint8_t appletNameLen          = APPLET_NAME_LEN;
    uint8_t tx_buf[256]            = {0};
    uint16_t tx_len                = sizeof(tx_buf);
    U8 responseData[256]           = {0};
    U32 responseDataLen            = sizeof(responseData);

    ENSURE_OR_GO_EXIT(NULL != conn_ctx);

    tx_buf[0] = CLA_ISO7816;
    tx_buf[1] = INS_GP_SELECT;
    tx_buf[2] = 4;
    tx_buf[3] = P2_NO_FCI;

    tx_len = 0   /* for indentation */
             + 1 /* CLA */
             + 1 /* INS */
             + 1 /* P1 */
             + 1 /* P2 */;
    if (appletNameLen > 0) {
        tx_buf[4] = (uint8_t)appletNameLen; // We have done ENSURE_OR_GO_CLEANUP(appletNameLen < 255);
        tx_len    = tx_len + 1              /* Lc */
                 + appletNameLen /* Payload */;
        memcpy(&tx_buf[5], appletName, appletNameLen);
        tx_buf[tx_len] = 0x0;
        tx_len         = tx_len + 1; /* Le */
    }
    else {
        tx_len = tx_len /* for indentation */
                 + 0 /* No Lc */;
    }

    /* T=1oi2c open session */
    status = phNxpEse_open(conn_ctx, initParams, pdeviceName);
    if (status != ESESTATUS_SUCCESS) {
        printf("phNxpEse_open Failed\n");
        goto exit;
    }

    AtrRsp.len    = CipLen;
    AtrRsp.p_data = &Cip[0];
    status        = phNxpEse_init(conn_ctx, initParams, &AtrRsp);
    if (status != ESESTATUS_SUCCESS) {
        printf("phNxpEse_init failed\n");
        goto exit;
    }

    status = hcpSmComT1oI2C_TransceiveRaw(conn_ctx, tx_buf, tx_len, responseData, &responseDataLen);
    if (status != ESESTATUS_SUCCESS) {
        printf("phNxpEse_Transceive Failed\n");
        goto exit;
    }

exit:
    return status;
}
