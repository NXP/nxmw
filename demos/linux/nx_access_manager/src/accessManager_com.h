/*
 * Copyright 2024 NXP
 * SPDX-License-Identifier: BSD-3-Clause
**/

#ifndef _ACCESS_MANAGER_COM_H_
#define _ACCESS_MANAGER_COM_H_

#include "sm_types.h"

#if defined(SSS_HAVE_SMCOM_PCSC) && (SSS_HAVE_SMCOM_PCSC)
#include "smComPCSC.h"
#endif
#if defined(SSS_HAVE_SMCOM_VCOM) && (SSS_HAVE_SMCOM_VCOM)
#include "smComSerial.h"
#endif
#if defined(SSS_HAVE_SMCOM_T1OI2C_GP1_0) && (SSS_HAVE_SMCOM_T1OI2C_GP1_0)
#include "smComT1oI2C.h"
#include "phNxpEse_Api.h"
#endif

#define MSG_SIZE 1024
#define MSG_HEADER_SIZE 4
#define TLV_HEADER_SIZE 4
#define MSG_SHORT_LENGTH_BYTES 1
#define MSG_EXTENDED_LENGTH_BYTES 3

typedef struct
{
    U16 param1;
    U16 param2;
    U32 appletVersion;
    U16 sbVersion;
} SmCommStateAm_t;

/* Function declarations */

uint16_t am_get_command_commMode(uint8_t cmdByte, nx_ev2_comm_mode_t *CommMode);

smStatus_t amTxRxAPDU(SeSession_t *pSessionCtx, U8 *cmd, U16 cmdLen, U8 *resp, U16 *respLen, nx_auth_type_t auth_type);

#endif // _ACCESS_MANAGER_COM_H_
