/*
*
* Copyright 2022-2023 NXP
* SPDX-License-Identifier: BSD-3-Clause
*/

#ifndef NX_SECURE_MSG_APIS_H_
#define NX_SECURE_MSG_APIS_H_

/* ************************************************************************** */
/* Includes                                                                   */
/* ************************************************************************** */
#include "nx_secure_msg_const.h"
#include "nx_apdu_tlv.h"

#ifdef __cplusplus
extern "C" {
#endif

#if SSS_HAVE_NX_TYPE

uint16_t nx_Decrypt_AES_EV2_ResponseAPDU(
    pSeSession_t session_ctx, uint8_t cmdByte, uint8_t *rspBuf, size_t *pRspBufLen, void *options);

uint16_t nx_get_command_commMode(uint8_t cmdByte, nx_ev2_comm_mode_t *CommMode);

sss_status_t nx_AES_EV2_Encrypt_CommandAPDU(
    pSeSession_t session_ctx, uint8_t *cmdData, size_t cmdDataLen, uint8_t *encCmdData, size_t *encCmdDataLen);

sss_status_t nx_AES_EV2_MAC_CommandAPDU(pSeSession_t session_ctx,
    uint8_t cmdByte,
    uint8_t *cmdHeader,
    size_t cmdHeaderLen,
    uint8_t *cmdData,
    size_t dataLen,
    uint8_t *txBuf,
    size_t *ptxBufLen);

sss_status_t nx_AES_EV2_Plain_CommandAPDU(pSeSession_t session_ctx,
    uint8_t *cmdHeader,
    size_t cmdHeaderLen,
    uint8_t *cmdData,
    size_t dataLen,
    uint8_t *txBuf,
    size_t *ptxBufLen);

void nx_AES_EV2_CommandAPDU_log(
    uint8_t cmdByte, uint8_t *cmdHeader, size_t cmdHeaderLen, uint8_t *cmdData, size_t cmdDataLen);

#endif //#if SSS_HAVE_NX_TYPE

#ifdef __cplusplus
} /* extern "c"*/
#endif

#endif /* NX_SECURE_MSG_APIS_H_ */
