/*
 *
 * Copyright 2023-2024 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <limits.h>
#include "fsl_sss_api.h"
#include "nx_apdu_tlv.h"
#include "qi_transmitter.h"
#include "qi_tx_helper.h"
#include "qi_tx_port.h"

#include "nxLog_msg.h"

#if defined(SSS_USE_FTR_FILE)
#include "fsl_sss_ftr.h"
#else
#include "fsl_sss_ftr_default.h"
#endif

#if SSS_HAVE_HOSTCRYPTO_MBEDTLS
#include "fsl_sss_mbedtls_apis.h"
#endif

#if SSS_HAVE_HOSTCRYPTO_OPENSSL
#include "fsl_sss_openssl_apis.h"
#endif

uint8_t qi_ec_priv_key[]   = QI_EC_PRIV_KEY_TX;
uint8_t qi_ec_priv_key_len = sizeof(qi_ec_priv_key);

extern sss_session_t *pghostSession;
extern sss_key_store_t *pghostKeyStore;

void powerTransmitterSendCommand(
    const uint8_t *pCmdBuffer, const size_t cmdBufferLen, uint8_t *pResponseBuffer, size_t *pResponseBufferLen)
{
    qi_error_code_t errorCode = kQiErrorUnspecified;
    uint8_t errorData         = 0;

    if ((NULL == pResponseBuffer) || (NULL == pResponseBufferLen)) {
        LOG_E("Invalid input parameter");
        return;
    }
    if (NULL == pCmdBuffer) {
        LOG_E("Invalid input parameter");
        errorCode = kQiErrorInvalidRequest;
        goto error;
    }
    if (cmdBufferLen < 1) {
        LOG_E("Command too small");
        errorCode = kQiErrorInvalidRequest;
        goto error;
    }
    if ((pCmdBuffer[0] & 0xF0) != (AUTH_PROTOCOL_VERSION << 4)) {
        errorCode = kQiErrorUnsupportedProtocol;
        errorData = AUTH_PROTOCOL_VERSION;
        goto error;
    }
    if ((pCmdBuffer[0] & QI_COMMAND_MASK) == kQiCommandGetDigests) {
        LOG_D("GetCertificateChainDigest");
        GetCertificateChainDigest(pCmdBuffer, cmdBufferLen, pResponseBuffer, pResponseBufferLen);
    }
    else if ((pCmdBuffer[0] & QI_COMMAND_MASK) == kQiCommandGetCertificate) {
        LOG_D("ReadCertificates");
        ReadCertificates(pCmdBuffer, cmdBufferLen, pResponseBuffer, pResponseBufferLen);
    }
    else if ((pCmdBuffer[0] & QI_COMMAND_MASK) == kQiCommandChallenge) {
        LOG_D("Authenticate");
        Authenticate(pCmdBuffer, cmdBufferLen, pResponseBuffer, pResponseBufferLen);
    }
    else {
        LOG_E("Invalid command");
        errorCode = kQiErrorInvalidRequest;
        goto error;
    }

    return;

error:
    if (*pResponseBufferLen < 1) {
        // Cannot set response buffer with error code and data
    }
    else {
        pResponseBuffer[0]  = (uint8_t)(AUTH_PROTOCOL_VERSION << 4) | (uint8_t)(kQiResponseError);
        pResponseBuffer[1]  = (uint8_t)(errorCode);
        pResponseBuffer[2]  = (uint8_t)(errorData);
        *pResponseBufferLen = 3;
    }
}

/* doc:start:qi-GetCertificateChainDigest */
void GetCertificateChainDigest(const uint8_t *pGetDigestRequest,
    const size_t getDigestRequestLen,
    uint8_t *pDigestResponse,
    size_t *pDigestResponseLen)
{
    smStatus_t retStatus = SM_NOT_OK;
    uint32_t certChainId = 0;
    uint16_t objectSize  = 0;
    size_t readSize      = 0;
    uint8_t *pData       = NULL;
    uint8_t *pDigestPtr  = NULL;

    qi_error_code_t errorCode  = kQiErrorUnspecified;
    uint8_t authMsgHeader      = 0;
    uint8_t requestedSlotMask  = 0;
    uint8_t slotsPopulated     = 0x00;
    uint8_t slotsReturned      = 0x00;
    uint8_t slotsReturnedCount = 0;

    if ((NULL == pGetDigestRequest) || (NULL == pDigestResponse) || (NULL == pDigestResponseLen)) {
        LOG_E("Null buffer");
        errorCode = kQiErrorInvalidRequest;
        goto error;
    }

    authMsgHeader = pGetDigestRequest[0];

    if (getDigestRequestLen != GET_DIGESTS_CMD_LEN) {
        LOG_E("Invalid request length");
        errorCode = kQiErrorInvalidRequest;
        goto error;
    }

    requestedSlotMask = pGetDigestRequest[1] & 0x0F;

    /* Invalid slot requested */
    if (requestedSlotMask == 0) {
        errorCode = kQiErrorInvalidRequest;
        LOG_E("No slot requested");
        goto error;
    }

    /* Get all populated slots */
    retStatus = getPopulatedSlots(&slotsPopulated);
    if (SM_OK != retStatus) {
        errorCode = kQiErrorUnspecified;
        LOG_E("Failed to retrieve populated slots");
        goto error;
    }

    /* Is Slot 0 empty? - Return error as slot 0 must always be populated */
    if (1 != (slotsPopulated & 0x01)) {
        errorCode = kQiErrorUnspecified;
        goto error;
    }

    /* We will return slots which were requested AND are provisioned */
    slotsReturned = requestedSlotMask & slotsPopulated;
    pDigestPtr    = &pDigestResponse[2];

    /* Validate response buffer size */
    for (size_t i = 0; i < MAX_SLOTS; i++) {
        if ((slotsReturned) & (0x01 << i)) {
            slotsReturnedCount++;
        }
    }
    if (*pDigestResponseLen < (size_t)((slotsReturnedCount * DIGEST_SIZE_BYTES) + 2)) {
        /* Response buffer size too less */
        errorCode = kQiErrorUnspecified;
        goto error;
    }

    pData = (uint8_t *)SSS_MALLOC(slotsReturnedCount * DIGEST_SIZE_BYTES);
    if (NULL == pData) {
        errorCode = kQiErrorUnspecified;
        goto error;
    }

    for (uint32_t i = 0; i < MAX_SLOTS; i++) {
        if ((slotsReturned) & (0x01 << i)) {
            certChainId = (uint32_t)QI_SLOT_ID_TO_CERT_ID(i);
            /* Read size of object to allocate necessary memory
             * so that we can read the complete object */

            retStatus = ReadSize(certChainId, &objectSize);
            if (retStatus != SM_OK) {
                errorCode = kQiErrorUnspecified;
                LOG_E("Failed ReadSize");
                goto error;
            }

            /* Size of binary object cannot be less than Digest size */
            if (objectSize < DIGEST_SIZE_BYTES) {
                errorCode = kQiErrorUnspecified;
                goto error;
            }
            readSize = DIGEST_SIZE_BYTES;
            //Read Digest from given Certificate chain ID
            retStatus = ReadObject(certChainId, 0x00, DIGEST_SIZE_BYTES, pData, &readSize);
            if (retStatus != SM_OK) {
                errorCode = kQiErrorUnspecified;
                LOG_E("Failed ReadDigest");
                goto error;
            }

            memcpy(pDigestPtr, pData, DIGEST_SIZE_BYTES);
            pDigestPtr += DIGEST_SIZE_BYTES;
        }
    }

    /* Successfully filled all digests - fill response buffer header now */
    pDigestResponse[0] = (uint8_t)((authMsgHeader & 0xF0) + kQiResponseDigest);
    pDigestResponse[1] =
        (uint8_t)(((slotsPopulated & SLOTS_POPULATED_MASK) << 4) + (slotsReturned & SLOTS_RETURNED_MASK));
    *pDigestResponseLen = (slotsReturnedCount * DIGEST_SIZE_BYTES) + 2;

    if (NULL != pData) {
        SSS_FREE(pData);
    }

    return;

error:
    if (NULL != pData) {
        SSS_FREE(pData);
    }
    if (pDigestResponse) {
        pDigestResponse[0] = (uint8_t)(authMsgHeader & 0xF0) + (uint8_t)(kQiResponseError);
        pDigestResponse[1] = (uint8_t)(errorCode);
        pDigestResponse[2] = 0x00;
        if (NULL != pDigestResponseLen) {
            *pDigestResponseLen = 3;
        }
        else {
            LOG_E("pDigestResponse supplied, but pDigestResponseLen pointer is NULL");
        }
    }
}
/* doc:end:qi-GetCertificateChainDigest */

/* doc:start:qi-ReadCertificates */
void ReadCertificates(const uint8_t *pGetCertificateRequest,
    const size_t getCertificateRequestLen,
    uint8_t *pCertificateResponse,
    size_t *pCertificateResponseLen)
{
    smStatus_t retStatus = SM_NOT_OK;
    uint16_t objectSize  = 0;
    uint32_t certChainId = 0;
    size_t readSize      = 0;
    uint8_t *pData       = NULL;

    qi_error_code_t errorCode   = kQiErrorUnspecified;
    uint8_t authMsgHeader       = 0;
    uint8_t requestedslots      = 0;
    uint8_t certificateOffsetA8 = 0;
    uint8_t certificateOffset70 = 0;
    uint8_t certificateLengthA8 = 0;
    uint8_t certificateLength70 = 0;
    uint16_t certificateOffset  = 0;
    uint16_t certificatelength  = 0;
    /* Offset first DIGEST bytes to skip certificate chain hash */
    uint16_t offset      = (uint16_t)DIGEST_SIZE_BYTES;
    uint16_t N_MC        = 0;
    uint16_t bytesToRead = 0;

    if ((NULL == pGetCertificateRequest) || (NULL == pCertificateResponse) || (NULL == pCertificateResponseLen)) {
        LOG_E("Null buffer");
        errorCode = kQiErrorInvalidRequest;
        goto error;
    }

    authMsgHeader = pGetCertificateRequest[0];

    if (getCertificateRequestLen != GET_CERTIFICATE_CMD_LEN) {
        LOG_E("Invalid request length");
        errorCode = kQiErrorInvalidRequest;
        goto error;
    }

    requestedslots      = pGetCertificateRequest[1] & 0x03;
    certificateOffsetA8 = (pGetCertificateRequest[1] & 0xE0) >> 5;
    certificateOffset70 = pGetCertificateRequest[2];
    certificateLengthA8 = (pGetCertificateRequest[1] & 0x1C) >> 2;
    certificateLength70 = pGetCertificateRequest[3];
    certificateOffset   = certificateOffsetA8 * 256 + certificateOffset70;
    certificatelength   = certificateLengthA8 * 256 + certificateLength70;

    certChainId = (uint32_t)QI_SLOT_ID_TO_CERT_ID(requestedslots);

    retStatus = ReadSize(certChainId, &objectSize);
    if (retStatus != SM_OK) {
        errorCode = kQiErrorUnspecified;
        LOG_E("ReadSize failed");
        goto error;
    }

    /* Read length of manufacturer certificate to determine the offset for PUC */

    retStatus = getManufacturerCertificateLength(certChainId, &N_MC);
    if (retStatus != SM_OK) {
        LOG_E("Failed to read manufacturer certificate length");
        errorCode = kQiErrorUnspecified;
        goto error;
    }

    if (certificateOffset >= MAXIMUM_CERT_OFFSET) {
        if ((UINT16_MAX - offset - N_MC - certificateOffset) < (2 + DIGEST_SIZE_BYTES - MAXIMUM_CERT_OFFSET)) {
            errorCode = kQiErrorInvalidRequest;
            goto error;
        }
        LOG_D("Read PUC");
        /* N_RH is length of root Hash Certificate and
         * N_MC is length of Manufacturer Certificate
         */
        offset += 2 /* Length of length field */
                  /* Length of RootHash */
                  + DIGEST_SIZE_BYTES
                  /* Length of Manufacturer certificate */
                  + N_MC
                  /* Offset from Product Unit Certificate */
                  + certificateOffset - MAXIMUM_CERT_OFFSET;
    }
    else {
        offset += certificateOffset;
    }

    /* Calculate actual bytes to read */
    if (certificatelength == 0) {
        if (objectSize < offset) {
            errorCode = kQiErrorInvalidRequest;
            goto error;
        }
        bytesToRead = objectSize - offset;
    }
    else {
        bytesToRead = certificatelength;
    }

    if (bytesToRead == 0) {
        /* Cannot read 0 bytes */
        errorCode = kQiErrorInvalidRequest;
        goto error;
    }

    /* Bytes to read cannot exceed the total object size */
    if ((offset + bytesToRead) > objectSize) {
        errorCode = kQiErrorInvalidRequest;
        goto error;
    }

    readSize = bytesToRead;
    pData    = (uint8_t *)SSS_MALLOC(bytesToRead * sizeof(uint8_t));
    if (NULL == pData) {
        errorCode = kQiErrorUnspecified;
        goto error;
    }

    if (*pCertificateResponseLen < (size_t)(bytesToRead + 1)) {
        LOG_E("Insufficient buffer");
        errorCode = kQiErrorUnspecified;
        goto error;
    }

    /* Read certificate chain */

    retStatus = readCertificateChain(certChainId, offset, bytesToRead, pData, &readSize);
    if (retStatus != SM_OK) {
        errorCode = kQiErrorUnspecified;
        LOG_E("ReadDigest Failed");
        goto error;
    }
    LOG_MAU8_D("ReadCertificate object", pData, readSize);

    /* Copy the data read out to response buffer */
    memcpy(&pCertificateResponse[1], pData, readSize);
    if (NULL != pData) {
        SSS_FREE(pData);
    }

    pCertificateResponse[0]  = (uint8_t)(authMsgHeader & 0xF0) + (uint8_t)(kQiResponseCertificate);
    *pCertificateResponseLen = (bytesToRead) + 1;

    return;

error:
    if (pData) {
        SSS_FREE(pData);
    }
    if (pCertificateResponse) {
        pCertificateResponse[0] = (uint8_t)(authMsgHeader & 0xF0) + (uint8_t)(kQiResponseError);
        pCertificateResponse[1] = (uint8_t)(errorCode);
        pCertificateResponse[2] = 0x00;
        if (NULL != pCertificateResponseLen) {
            *pCertificateResponseLen = 3;
        }
        else {
            LOG_E("pCertificateResponse supplied, but pCertificateResponseLen pointer is NULL");
        }
    }
}
/* doc:end:qi-ReadCertificates */

/* doc:start:qi-Authenticate */
void Authenticate(const uint8_t *pChallengeRequest,
    const size_t challengeRequestLen,
    uint8_t *pChallengeAuthResponse,
    size_t *pChallengeAuthResponseLen)
{
    smStatus_t retStatus                     = SM_NOT_OK;
    uint16_t objectSize                      = 0;
    uint8_t *pTbsAuthPtr                     = NULL;
    size_t readSize                          = 0;
    uint8_t certChainHash[DIGEST_SIZE_BYTES] = {0};
    uint8_t hash[DIGEST_SIZE_BYTES]          = {0};
    size_t hashLen                           = sizeof(hash);

    uint8_t authMsgHeader                = 0;
    uint8_t requestedSlot                = 0;
    uint8_t slotsPopulated               = 0x00;
    uint8_t tbsAuth[TBSAUTH_MAX_SIZE]    = {0};
    size_t tbsAuthlen                    = sizeof(tbsAuth);
    uint8_t signature[MAX_SIGNATURE_LEN] = {0};
    size_t sigLen                        = sizeof(signature);
    qi_error_code_t errorCode            = kQiErrorUnspecified;
    uint32_t certChainId                 = 0;
    uint32_t keyId                       = 0;
    size_t keylen                        = KEY_BIT_LENGTH / 8;

    sss_asymmetric_t signCtx         = {0};
    sss_status_t sss_status          = kStatus_SSS_Fail;
    sss_object_t hostPublicKeyObject = {0};

    if ((NULL == pChallengeRequest) || (NULL == pChallengeAuthResponse) || (NULL == pChallengeAuthResponseLen)) {
        LOG_E("Null buffer");
        errorCode = kQiErrorInvalidRequest;
        goto error;
    }

    authMsgHeader = pChallengeRequest[0];

    if (challengeRequestLen != CHALLENGE_CMD_LEN) {
        LOG_E("Invalid request length");
        errorCode = kQiErrorInvalidRequest;
        goto error;
    }

    requestedSlot = pChallengeRequest[1] & 0x03;
    certChainId   = (uint32_t)QI_SLOT_ID_TO_CERT_ID(requestedSlot);
    keyId         = (uint32_t)QI_SLOT_ID_TO_KEY_ID(requestedSlot);

    if (*pChallengeAuthResponseLen < CHALLENGE_AUTH_RESPONSE_LEN) {
        LOG_E("Insufficient buffer");
        errorCode = kQiErrorUnspecified;
        goto error;
    }

    retStatus = getPopulatedSlots(&slotsPopulated);
    if (SM_OK != retStatus) {
        errorCode = kQiErrorUnspecified;
        LOG_E("Failed to retrieve populated slots");
        goto error;
    }

    if (1 != (slotsPopulated & 0x01)) {
        /* Slot 0 is empty */
        errorCode = kQiErrorUnspecified;
        goto error;
    }
    /* Check if the requested slot is populated */
    if (1 != ((1 << requestedSlot) & slotsPopulated)) {
        errorCode = kQiErrorInvalidRequest;
        LOG_E("Requested slot not populated");
        goto error;
    }

    retStatus = ReadSize(certChainId, &objectSize);
    if (retStatus != SM_OK) {
        errorCode = kQiErrorUnspecified;
        LOG_E("ReadSize Failed");
        goto error;
    }

    /* Certificate chain size cannot be less than DIGEST_SIZE_BYTES */
    if (objectSize < DIGEST_SIZE_BYTES) {
        errorCode = kQiErrorUnspecified;
        goto error;
    }

    /* Read Certificate chain hash value */
    pTbsAuthPtr = &tbsAuth[1];
    readSize    = DIGEST_SIZE_BYTES;
    retStatus   = ReadObject(certChainId, 0, DIGEST_SIZE_BYTES, certChainHash, &readSize);
    if (retStatus != SM_OK) {
        errorCode = kQiErrorUnspecified;
        LOG_E("ReadObject Failed");
        goto error;
    }
    memcpy(pTbsAuthPtr, certChainHash, DIGEST_SIZE_BYTES);

    /* Copy Challenge request to TBS Auth */
    pTbsAuthPtr = &tbsAuth[TBSAUTH_CHALLENGE_REQ_OFFSET];
    memcpy(pTbsAuthPtr, pChallengeRequest, challengeRequestLen);

    pChallengeAuthResponse[0] = (uint8_t)((authMsgHeader & 0xF0) + kQiResponseChallengeAuth);
    pChallengeAuthResponse[1] = (uint8_t)((AUTH_PROTOCOL_VERSION << 4) + (slotsPopulated & SLOTS_POPULATED_MASK));
    pChallengeAuthResponse[2] = (uint8_t)(certChainHash[DIGEST_SIZE_BYTES - 1]);

    tbsAuth[0] = CHALLENGE_AUTH_RESPONSE_PREFIX; // ASCII representation of A
    memcpy(&tbsAuth[TBSAUTH_CHALLENGE_AUTH_RESP_OFFSET], pChallengeAuthResponse, 3);

    /* Calculate SHA256 of TBSAuth for signature */
    retStatus = getSha256Hash(pghostSession, tbsAuth, tbsAuthlen, hash, &hashLen);
    if (retStatus != SM_OK) {
        LOG_E("Failed getSha256Hash");
        errorCode = kQiErrorUnspecified;
        goto error;
    }

    /* Calculate signature */
    sss_status = sss_host_key_object_init(&hostPublicKeyObject, pghostKeyStore);
    if (kStatus_SSS_Success != sss_status) {
        LOG_E("sss_host_key_object_init Failed");
        errorCode = kQiErrorUnspecified;
        goto error;
    }

    sss_status = sss_host_key_object_allocate_handle(
        &hostPublicKeyObject, keyId, kSSS_KeyPart_Pair, kSSS_CipherType_EC_NIST_P, keylen, kKeyObject_Mode_Transient);
    if (kStatus_SSS_Success != sss_status) {
        LOG_E("sss_host_key_object_allocate_handle Failed");
        errorCode = kQiErrorUnspecified;
        goto error;
    }

    sss_status = sss_host_key_store_set_key(
        pghostKeyStore, &hostPublicKeyObject, qi_ec_priv_key, qi_ec_priv_key_len, KEY_BIT_LENGTH, NULL, 0);
    if (kStatus_SSS_Success != sss_status) {
        LOG_E("sss_host_key_store_set_key Failed");
        errorCode = kQiErrorUnspecified;
        goto error;
    }

    sss_status = sss_host_asymmetric_context_init(
        &signCtx, pghostSession, &hostPublicKeyObject, kAlgorithm_SSS_ECDSA_SHA256, kMode_SSS_Sign);
    if (sss_status != kStatus_SSS_Success) {
        LOG_E(" sss_host_asymmetric_context_init Failed...");
        errorCode = kQiErrorUnspecified;
        goto error;
    }

    sss_status = sss_host_asymmetric_sign_digest(&signCtx, hash, hashLen, &signature[0], &sigLen);
    if (kStatus_SSS_Success != sss_status) {
        LOG_E("sss_host_asymmetric_sign_digest Failed");
        errorCode = kQiErrorUnspecified;
        goto error;
    }

    /* Extract R and S values from signature */
    retStatus = EcSignatureToRandS(signature, &sigLen);
    if (retStatus != SM_OK) {
        LOG_E(" EcSignatureToRandS Failed...");
        errorCode = kQiErrorUnspecified;
        goto error;
    }
    *pChallengeAuthResponseLen = (sigLen) + 3;
    memcpy(&pChallengeAuthResponse[3], signature, sigLen);

    if (signCtx.session != NULL) {
        sss_host_asymmetric_context_free(&signCtx);
    }
    if (hostPublicKeyObject.keyStore != NULL) {
        sss_host_key_object_free(&hostPublicKeyObject);
    }

    return;

error:
    if (signCtx.session != NULL) {
        sss_host_asymmetric_context_free(&signCtx);
    }
    if (hostPublicKeyObject.keyStore != NULL) {
        sss_host_key_object_free(&hostPublicKeyObject);
    }
    if (pChallengeAuthResponse) {
        pChallengeAuthResponse[0] = (uint8_t)(authMsgHeader & 0xF0) + (uint8_t)(kQiResponseError);
        pChallengeAuthResponse[1] = (uint8_t)(errorCode);
        pChallengeAuthResponse[2] = 0x00;
        if (NULL != pChallengeAuthResponseLen) {
            *pChallengeAuthResponseLen = 3;
        }
        else {
            LOG_E("pChallengeAuthResponse supplied, but pChallengeAuthResponseLen pointer is NULL");
        }
    }
}
/* doc:end:qi-Authenticate */
