/**
 * @file smComSerial.h
 * @author NXP Semiconductors
 * @version 1.0
 * @par License
 *
 * Copyright 2017,2020 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * @par Description
 *
 *****************************************************************************/

#ifndef _SCCOMSERIAL_H_
#define _SCCOMSERIAL_H_

#include "smCom.h"

#ifdef __cplusplus
extern "C" {
#endif

U32 smComVCom_Open(void **vcom_ctx, const char *pComPortString);
U32 smComVCom_Close(void *conn_ctx);
U32 smComVCom_Transceive(void *conn_ctx, apdu_t *pApdu);
U32 smComVCom_TransceiveRaw(void *conn_ctx, U8 *pTx, U16 txLen, U8 *pRx, U32 *pRxLen);

U32 smComVCom_SetState(void *conn_ctx);
U32 smComVCom_GetCip(void *conn_ctx, U8 *pCip, U16 *CipLen);

U32 smComVCom_GPIOInit(void *conn_ctx, U8 gpioPIN, U8 setInOutDIR);
U32 smComVCom_GPIOSet(void *conn_ctx, U8 gpioPIN);
U32 smComVCom_GPIOClear(void *conn_ctx, U8 gpioPIN);
U32 smComVCom_GPIOToggle(void *conn_ctx, U8 gpioPIN);
U32 smComVCom_GPIORead(void *conn_ctx, U8 gpioPIN, U8 *pRx, U32 *pRxLen);

#ifdef __cplusplus
}
#endif
#endif //_SCCOMSERIAL_H_
