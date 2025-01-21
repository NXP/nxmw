/**
 * @file smComSocket.h
 * @author NXP Semiconductors
 * @version 1.1
 * @par License
 * Copyright 2016,2017,2020 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * @par Description
 *
 *****************************************************************************/

#ifndef _SCCOMSOCKET_H_
#define _SCCOMSOCKET_H_

#include "smCom.h"

#ifdef __cplusplus
extern "C" {
#endif

#define IP_ADDR_MAX_LEN         50
#define	MTY_WAIT_FOR_CARD       0x00
#define	MTY_APDU_DATA           0x01
#define MYT_DEFAULT_NAD         0x00
#define MTY_LOCK                0x30
#define MTY_UNLOCK              0x31

U16 smComSocket_Close(void);
U16 smComSocket_Open(void** conn_ctx, U8 *pIpAddrString, U16 portNo, U8 *pCip, U16 *cipLen);
#if defined(_WIN32) && defined(TGT_A70CU)
U16 smComSocket_Init(U8 *pIpAddrString, U16 portNo, U8 *pCip, U16 *pCipLength, U16 maxCipLength);
#endif
U32 smComSocket_Transceive(void* conn_ctx, apdu_t *pApdu);
U32 smComSocket_TransceiveFD(int fd, apdu_t *pApdu);
U32 smComSocket_TransceiveRaw(void* conn_ctx, U8 *pTx, U16 txLen, U8 *pRx, U32 *pRxLen);
U32 smComSocket_TransceiveRawFD(int fd, U8 *pTx, U16 txLen, U8 *pRx, U32 *pRxLen);
U32 smComSocket_CloseFD(int fd);
U32 smComSocket_GetCIPFD(int fd, U8* pCip, U16* cipLen);
U32 smComSocket_LockChannelFD(int fd);
U32 smComSocket_UnlockChannelFD(int fd);

U32 smComSocket_LockChannel();
U32 smComSocket_UnlockChannel();
U32 smComSocket_GPIOInitFD(int fd, U8 gpioPIN, U8 setInOutDir);
U32 smComSocket_GPIOSetFD(int fd, U8 gpioPIN);
U32 smComSocket_GPIOClearFD(int fd, U8 gpioPIN);
U32 smComSocket_GPIOToggleFD(int fd, U8 gpioPIN);
U32 smComSocket_GPIOReadFD(int fd, U8 gpioPIN, U8 *pRx, U32 *pRxLen);
#ifdef __cplusplus
}
#endif
#endif //_SCCOMSOCKET_H_
