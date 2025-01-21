/* Copyright 2023 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __USB_C_INITIATOR_PORT_H__
#define __USB_C_INITIATOR_PORT_H__

#include "ex_sss_boot.h"
#include "fsl_sss_nx_apis.h"
#include "fsl_sss_util_asn1_der.h"
#include "nxLog_msg.h"

#if SSS_HAVE_HOSTCRYPTO_MBEDTLS
#include "mbedtls/asn1.h"
#endif

extern ex_sss_boot_ctx_t gex_usb_c_auth_ctx;

int port_getRandomNonce(uint8_t *nonce, size_t *pNonceLen);
void port_parseCertGetPublicKey(uint8_t *pCert, size_t certLen, uint8_t *pPucPublicKey, size_t *pucPublicKeylen);
int port_parseCertificatesGetLeafCert(uint8_t *pCerts, size_t certsLen, uint8_t **pLeafCert, size_t *leafCertLen);
int port_hostVerifyCertificates(uint8_t *certificates, size_t certificates_size);
int port_hostVerifyChallenge(
    uint8_t *pPublicKey, size_t publicKeyLen, uint8_t *pChallengeRequest, uint8_t *pChallengeResponse);
int port_getSha256Hash(const uint8_t *pInput, size_t inputLen, uint8_t *pOutput, size_t *pOutputLen);

#endif // __USB_C_INITIATOR_PORT_H__