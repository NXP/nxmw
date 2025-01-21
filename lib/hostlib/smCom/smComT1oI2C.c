/*
 *
 * Copyright 2016-2018, 2020, 2022-2024 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 */

/**
 * @par Description
 * This file implements the SmCom T1oI2C communication layer.
 *
 *****************************************************************************/


#include <assert.h>
#include "smComT1oI2C.h"
#include "phNxpEse_Api.h"
#include "phNxpEseProto7816_3.h"
#include "i2c_a7.h"
#include "phEseStatus.h"
#include "sm_apdu.h"

#include "nxLog_msg.h"
#include "nxEnsure.h"

#if defined(SSS_HAVE_SMCOM_T1OI2C_GP1_0) && (SSS_HAVE_SMCOM_T1OI2C_GP1_0) || defined(T1oI2C_GP1_0)

static U32 smComT1oI2C_Transceive(void* conn_ctx, apdu_t * pApdu);
static U32 smComT1oI2C_TransceiveRaw(void* conn_ctx, U8 * pTx, U16 txLen, U8 * pRx, U32 * pRxLen);

U16 smComT1oI2C_Close(void *conn_ctx, U8 mode)
{
    ESESTATUS status = ESESTATUS_FAILED;
    U16 ret          = SMCOM_COM_FAILED;
    /* Do not pass conn_ctx = NULL to next layer.
     * Multiple sessions can be present to different SEs.
     * Since the port information is contained in the conn_ctx,
     * the application must pass conn_ctx to close the connection.
     */
    if (NULL != conn_ctx) {
#ifdef T1OI2C_SEND_DEEP_PWR_DOWN
        status = phNxpEse_deepPwrDown(conn_ctx);
        if(status != ESESTATUS_SUCCESS)
        {
            LOG_E("phNxpEse_deepPwrDown failed ");
            goto exit;
        }
#endif
        status = phNxpEse_close(conn_ctx);
        if(status != ESESTATUS_SUCCESS)
        {
            LOG_E("Failed to close ESE interface and free all resources ");
            goto exit;
        }
    }
    else {
        LOG_I("Invalid conn_ctx");
    }

    ret = SMCOM_OK;
exit:
    return ret;
}


U16 smComT1oI2C_Init(void **conn_ctx, const char *pConnString)
{
    ESESTATUS status = ESESTATUS_FAILED;
    U16 ret          = SMCOM_COM_FAILED;
    phNxpEse_initParams initParams = {0};
    initParams.initMode = ESE_MODE_NORMAL;

    if(conn_ctx != NULL) {
        *conn_ctx = NULL;
    }
    status = phNxpEse_open(conn_ctx, initParams, pConnString);
    if (status != ESESTATUS_SUCCESS)
    {
        LOG_E(" Failed to create physical connection with ESE ");
        goto exit;
    }
    ret = SMCOM_OK;

exit:
    return ret;
}

U16 smComT1oI2C_Resume(void **conn_ctx, const char *pConnString)
{
    ESESTATUS status = ESESTATUS_FAILED;
    U16 ret          = SMCOM_COM_FAILED;
    phNxpEse_initParams initParams = {0};
    initParams.initMode = ESE_MODE_RESUME;

    if(conn_ctx != NULL) {
        *conn_ctx = NULL;
    }
    status = phNxpEse_open(conn_ctx, initParams, pConnString);
    if (status != ESESTATUS_SUCCESS)
    {
        LOG_E(" Failed to create physical connection with ESE ");
        goto exit;
    }
    ret = SMCOM_OK;

exit:
    return ret;
}

U16 smComT1oI2C_Open(void *conn_ctx, U8 mode, U8 seqCnt, U8 *T1oI2Catr, U16 *T1oI2CatrLen)
{
    ESESTATUS status = ESESTATUS_FAILED;
    U16 ret          = SMCOM_COM_FAILED;
    phNxpEse_data AtrRsp = {0};
    phNxpEse_initParams initParams = {0};
    initParams.initMode = ESE_MODE_NORMAL;

    if (NULL == T1oI2CatrLen) {
        return SMCOM_COM_FAILED;
    }

    AtrRsp.len = *T1oI2CatrLen;
    AtrRsp.p_data = T1oI2Catr;

    ENSURE_OR_GO_EXIT(NULL != T1oI2CatrLen)
    if (conn_ctx == NULL) {
        // Connection context is stored in global variable contained in phNxpEse_Api.c
        smComT1oI2C_Init(NULL, NULL);
    }

    status = phNxpEse_init(conn_ctx, initParams, &AtrRsp);
    if (status != ESESTATUS_SUCCESS)
    {
        *T1oI2CatrLen=0;
        LOG_E(" Failed to Open session ");
        goto exit;
    }
    else
    {
       *T1oI2CatrLen = AtrRsp.len ; /*Retrive INF FIELD*/
    }
    return smCom_Init(&smComT1oI2C_Transceive, &smComT1oI2C_TransceiveRaw);
exit:
    return ret;
}

static U32 smComT1oI2C_Transceive(void* conn_ctx, apdu_t * pApdu)
{
    U32 respLen = MAX_APDU_BUF_LENGTH;
    U32 retCode = SMCOM_COM_FAILED;

    ENSURE_OR_GO_EXIT(pApdu != NULL);

    retCode = smComT1oI2C_TransceiveRaw(conn_ctx, (U8 *)pApdu->pBuf, pApdu->buflen, pApdu->pBuf, &respLen);
    pApdu->rxlen = (U16)respLen;
exit:
    return retCode;
}

static U32 smComT1oI2C_TransceiveRaw(void* conn_ctx, U8 * pTx, U16 txLen, U8 * pRx, U32 * pRxLen)
{
    phNxpEse_data pCmdTrans = {0};
    phNxpEse_data pRspTrans = {0};
    ESESTATUS txnStatus     = ESESTATUS_FAILED;
    U32 ret                 = SMCOM_COM_FAILED;

    pCmdTrans.len = txLen;
    pCmdTrans.p_data = pTx;

    ENSURE_OR_GO_EXIT(NULL != pRxLen)

    pRspTrans.len = *pRxLen;
    pRspTrans.p_data = pRx;

    LOG_MAU8_D("APDU Tx>", pTx, txLen);
    txnStatus = phNxpEse_Transceive(conn_ctx, &pCmdTrans, &pRspTrans);
    if ( txnStatus == ESESTATUS_SUCCESS )
    {
        *pRxLen = pRspTrans.len;
        LOG_MAU8_D("APDU Rx<", pRx, pRspTrans.len);
    }
    else
    {
        *pRxLen = 0;
        LOG_E(" Transcive Failed ");
        return SMCOM_SND_FAILED;
    }
    ret = SMCOM_OK;

exit:
    return ret;
}

U16 smComT1oI2C_ComReset(void* conn_ctx)
{
    ESESTATUS status = ESESTATUS_SUCCESS;
    U16 ret          = SMCOM_COM_FAILED;
    status = phNxpEse_deInit(conn_ctx);
    if(status !=ESESTATUS_SUCCESS)
    {
        LOG_E("Failed to Reset 7816 protocol instance ");
        goto exit;
    }
    ret = SMCOM_OK;
exit:
    return ret;
}

#endif // SSS_HAVE_SMCOM_T1OI2C_GP1_0
