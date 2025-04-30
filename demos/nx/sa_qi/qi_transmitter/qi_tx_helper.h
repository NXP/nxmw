/* Copyright 2023 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __SA_QI_TX_HELPERS_PORT_H__
#define __SA_QI_TX_HELPERS_PORT_H__

#include "nx_apdu_tlv.h"

smStatus_t getSha256Hash(
    sss_session_t *session_ctx, const uint8_t *pInput, size_t inputLen, uint8_t *pOutput, size_t *pOutputLen);
smStatus_t EcSignatureToRandS(uint8_t *signature, size_t *sigLen);
smStatus_t getPopulatedSlots(uint8_t *pSlotsPopulated);
smStatus_t readObjectWithChunking(
    uint32_t certChainId, uint16_t offset, uint16_t bytesToRead, uint8_t *pData, size_t *pdataLen);
smStatus_t getManufacturerCertificateLength(uint32_t certChainId, uint16_t *N_MC);

smStatus_t ReadSize(uint32_t certChainId, uint16_t *objectSize);
smStatus_t ReadObject(uint32_t certChainId, uint16_t offsetMC, uint16_t Length, uint8_t *pData, size_t *readSize);

#define readCertificateChain readObjectWithChunking

typedef struct sa_qi_credentials
{
    uint8_t *qi_certificate_chain;
    uint16_t qi_certificate_chain_len;
    uint8_t *qi_ec_priv_key;
    uint16_t qi_ec_priv_key_len;
} sa_qi_credentials_t;
#endif // __SA_QI_TX_HELPERS_PORT_H__
