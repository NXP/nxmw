/*
 *
 * Copyright 2016-2020 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 */

/**
 * @par Description
 * Interface of installable communication layer to exchange APDU's between Host and Secure Module.
 */

#ifndef _SCCOM_H_
#define _SCCOM_H_

#include "sm_types.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SMCOM_OK 0x9000               //!< Communication successful
#define SMCOM_SND_FAILED 0x7010       //!< Communication failed while sending data
#define SMCOM_RCV_FAILED 0x7011       //!< Communication failed while receiving data
#define SMCOM_COM_FAILED 0x7012       //!< Cannot open communication link with ax device
#define SMCOM_PROTOCOL_FAILED 0x7013  //!< APDU exchange protocol failed to be established successfully
#define SMCOM_NO_ATR 0x7014           //!< No ATR can be retrieved
#define SMCOM_NO_PRIOR_INIT 0x7015    //!< The callbacks doing the actual transfer have not been installed
#define SMCOM_COM_ALREADY_OPEN 0x7016 //!< Communication link is already open with device
#define SMCOM_COM_INIT_FAILED 0x7017  //!< Communication init failed

/**
 * Contains APDU exchanged between Host and Secure Modulde.
 */
typedef struct
{
    U8 cla;
    U8 ins;
    U8 p1;
    U8 p2;
    U8 *pBuf;
    U16 buflen;
    U16 rxlen;
    U8 extendedLength;
    U8 hasData;
    U16 lc;
    U8 lcLength;
    U8 hasLe;
    U16 le;
    U8 leLength;
    U16 offset;
} apdu_t;

/* ------------------------------------------------------------------------- */
typedef U32 (*ApduTransceiveFunction_t)(void *conn_ctx, apdu_t *pAdpu);
typedef U32 (*ApduTransceiveRawFunction_t)(void *conn_ctx, U8 *pTx, U16 txLen, U8 *pRx, U32 *pRxLen);

U16 smCom_Init(ApduTransceiveFunction_t pTransceive, ApduTransceiveRawFunction_t pTransceiveRaw);
void smCom_DeInit(void);
U32 smCom_TransceiveRaw(void *conn_ctx, U8 *pTx, U16 txLen, U8 *pRx, U32 *pRxLen);

#ifdef __cplusplus
}
#endif
#endif
