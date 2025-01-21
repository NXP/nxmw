/* Copyright 2023 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __USB_C_RESPONDER_HELPERS_H__
#define __USB_C_RESPONDER_HELPERS_H__

#include "nx_apdu_tlv.h"

sss_status_t getSha256Hash(
    sss_session_t *pSession, const uint8_t *pInput, size_t inputLen, uint8_t *pOutput, size_t *pOutputLen);
sss_status_t swapRandS(uint8_t *data, size_t dataLen);
smStatus_t EcSignatureToRandS(uint8_t *signature, size_t *sigLen);
smStatus_t getPopulatedSlots(sss_session_t *pSession, uint8_t *pSlotsPopulated);
sss_status_t generateRandom(sss_session_t *pSession, uint8_t *pBuf, size_t bufLen);

#endif // __USB_C_RESPONDER_HELPERS_H__
