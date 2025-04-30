/* Copyright 2023-2024 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __SA_QI_NX_H__
#define __SA_QI_NX_H__

#include "ex_sss_boot.h"
#include "fsl_sss_nx_apis.h"
#include "fsl_sss_util_asn1_der.h"
#include "sa_qi_common.h"
#include "nxLog_msg.h"
#include "mbedtls/asn1.h"

extern ex_sss_boot_ctx_t gex_qi_auth_ctx;

extern uint8_t qi_rootca_cert[];
extern size_t qi_rootca_cert_len;

extern sss_session_t *pgSssSession;
extern sss_key_store_t *pgKeyStore;

int nx_getRandomNonce(uint8_t *nonce, size_t *pNonceLen);
void nx_parseCertGetPublicKey(uint8_t *pCert, size_t certLen, uint8_t *pPucPublicKey, size_t *pucPublicKeylen);
int nx_VerifyCertificateChain(
    uint8_t *response_buffer, size_t response_size, uint16_t pucCertOffset, uint16_t manufacturerCertLenOffset);
int nx_VerifyChallenge(uint8_t *pPublicKey,
    size_t publicKeyLen,
    uint8_t *pCertificateChainHash,
    uint8_t *pChallengeRequest,
    uint8_t *pChallengeResponse);
int nx_getDigest(uint8_t *pInput, size_t inputLen, uint8_t *pOutput, size_t *pOutputLen);
int parseCertGetTBS(uint8_t *pCert, size_t certLen, uint8_t *pgetTbs, size_t *pTbslen);
void parseCertGetSignature(uint8_t *pCert, size_t certLen, uint8_t *pSignature, size_t *pSignaturelen);
sss_status_t nxVerifySignature(
    uint8_t *publicKey, size_t publicKeyLen, uint8_t *input, size_t inputLen, uint8_t *signature, size_t signatureLen);
int nxVerifyChallenge(uint8_t *pPublicKey,
    size_t publicKeyLen,
    uint8_t *pCertificateChainHash,
    uint8_t *pChallengeRequest,
    uint8_t *pChallengeResponse);

void getPublicKeyFromSlot(uint8_t slot_id, uint8_t *pPublicKey, size_t *pPublicKeyLen);

#endif