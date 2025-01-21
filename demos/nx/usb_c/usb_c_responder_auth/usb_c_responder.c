/*
 *
 * Copyright 2023-2024 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <nx_apdu_tlv.h>
#include "usb_c_responder.h"
#include "usb_c_responder_helpers.h"
#include "usb_c_responder_port.h"

#include "nxLog_msg.h"
#include <nx_apdu.h>
#include <nx_enums.h>

extern sss_session_t *pgSssSession;
extern sss_key_store_t *pgKeyStore;

void responderSendCommand(
    const uint8_t *pCmdBuffer, const size_t cmdBufferLen, uint8_t *pResponseBuffer, size_t *pResponseBufferLen)
{
    usb_c_error_code_t errorCode     = kUSBcErrorUnspecified;
    uint8_t errorData                = 0;
    usb_c_msg_header_t *msg_request  = NULL;
    usb_c_msg_header_t *msg_response = NULL;

    msg_request  = (usb_c_msg_header_t *)pCmdBuffer;
    msg_response = (usb_c_msg_header_t *)pResponseBuffer;

    if ((NULL == pCmdBuffer) || (NULL == pResponseBuffer) || (NULL == pResponseBufferLen)) {
        LOG_E("Null buffer");
        errorCode = kUSBcErrorInvalidRequest;
        goto error;
    }

    if (cmdBufferLen < sizeof(usb_c_msg_header_t)) {
        LOG_E("Command too small");
        errorCode = kUSBcErrorInvalidRequest;
        goto error;
    }
    if (msg_request->protocolVersion != AUTH_PROTOCOL_VERSION) {
        errorCode = kUSBcErrorUnsupportedProtocol;
        errorData = AUTH_PROTOCOL_VERSION;
        goto error;
    }
    if (msg_request->messageType == kUSBcCommandGetDigests) {
        LOG_D("GetCertificateChainDigest");
        GetCertificateChainDigest(pCmdBuffer, cmdBufferLen, pResponseBuffer, pResponseBufferLen);
    }
    else if (msg_request->messageType == kUSBcCommandGetCertificate) {
        LOG_D("ReadCertificates");
        ReadCertificates(pCmdBuffer, cmdBufferLen, pResponseBuffer, pResponseBufferLen);
    }
    else if (msg_request->messageType == kUSBcCommandChallenge) {
        LOG_D("Authenticate");
        Authenticate(pCmdBuffer, cmdBufferLen, pResponseBuffer, pResponseBufferLen);
    }
    else {
        LOG_E("Invalid command");
        errorCode = kUSBcErrorInvalidRequest;
        goto error;
    }

    return;

error:
    if ((pResponseBuffer) && (pResponseBufferLen)) {
        if (*pResponseBufferLen >= sizeof(usb_c_msg_header_t)) {
            msg_response->protocolVersion = (uint8_t)(AUTH_PROTOCOL_VERSION);
            msg_response->messageType     = (uint8_t)(kUSBcResponseError);
            msg_response->param1          = (uint8_t)(errorCode);
            msg_response->param2          = (uint8_t)(errorData);
            *pResponseBufferLen           = sizeof(usb_c_msg_header_t);
        }
        else {
            *pResponseBufferLen = 0;
        }
    }
}

/* doc:start:usb_c-GetCertificateChainDigest */
void GetCertificateChainDigest(const uint8_t *pGetDigestRequest,
    const size_t getDigestRequestLen,
    uint8_t *pDigestResponse,
    size_t *pDigestResponseLen)
{
    smStatus_t sm_status                   = SM_NOT_OK;
    uint8_t certChainFileId                = 0;
    size_t readSize                        = 0;
    uint8_t *pData                         = NULL;
    uint8_t *pDigestPtr                    = NULL;
    usb_c_error_code_t errorCode           = kUSBcErrorUnspecified;
    uint8_t slotsPopulated                 = 0x00;
    uint8_t slotsReturnedCount             = 0;
    usb_c_digests_request_t *msg_request   = NULL;
    usb_c_digests_response_t *msg_response = NULL;
    sss_session_t *pSession                = pgSssSession;
    Nx_FILEType_t certChainFileType        = 0;
    uint8_t certChainFileOption = NX_FILE_OPTION_SDM_DISBALED | NX_FILE_OPTION_DEFERRED_DISABLED | Nx_CommMode_Plain;
    Nx_AccessCondition_t certChainFileReadAccessCondition      = Nx_AccessCondition_No_Access;
    Nx_AccessCondition_t certChainFileWriteAccessCondition     = Nx_AccessCondition_No_Access;
    Nx_AccessCondition_t certChainFileReadWriteAccessCondition = Nx_AccessCondition_No_Access;
    Nx_AccessCondition_t certChainFileChangeAccessCondition    = Nx_AccessCondition_No_Access;
    size_t certChainFileSize                                   = 0;

    msg_request  = (usb_c_digests_request_t *)pGetDigestRequest;
    msg_response = (usb_c_digests_response_t *)pDigestResponse;

    if ((NULL == pGetDigestRequest) || (NULL == pDigestResponse) || (NULL == pDigestResponseLen)) {
        LOG_E("Null buffer");
        errorCode = kUSBcErrorInvalidRequest;
        goto error;
    }

    if (getDigestRequestLen != GET_DIGESTS_CMD_LEN) {
        LOG_E("Invalid request length");
        errorCode = kUSBcErrorInvalidRequest;
        goto error;
    }

    /* Get all populated slots */
    sm_status = getPopulatedSlots(pSession, &slotsPopulated);
    if (SM_OK != sm_status) {
        errorCode = kUSBcErrorUnspecified;
        LOG_E("Failed to retrieve populated slots");
        goto error;
    }

    /* Is Slot 0 empty? - Return error as slot 0 must always be populated */
    // A product shall not act as an Authentication Responder unless it contains a Certificate Chain in Slot 0.
    if (!(slotsPopulated & 0x01)) {
        errorCode = kUSBcErrorUnspecified;
        goto error;
    }

    /* We will return slots which were requested AND are provisioned */
    pDigestPtr = msg_response->payload;

    /* Validate response buffer size */
    for (size_t i = 0; i < MAX_SLOTS; i++) {
        if ((slotsPopulated) & (0x01 << i)) {
            slotsReturnedCount++;
        }
    }
    if (*pDigestResponseLen < (size_t)((slotsReturnedCount * DIGEST_SIZE_BYTES) + sizeof(msg_response->header))) {
        /* Response buffer size too less */
        errorCode = kUSBcErrorUnspecified;
        goto error;
    }

    pData = (uint8_t *)SSS_MALLOC(DIGEST_SIZE_BYTES);
    if (NULL == pData) {
        errorCode = kUSBcErrorUnspecified;
        goto error;
    }

    for (size_t i = 0; i < MAX_SLOTS; i++) {
        if ((slotsPopulated) & (0x01 << i)) {
            certChainFileId = (uint8_t)(USB_C_SLOT_ID_TO_CERT_FILE_ID(i));

            /* Read size of object to allocate necessary memory
             * so that we can read the complete object */
            sm_status = nx_GetFileSettings(&((sss_nx_session_t *)pSession)->s_ctx,
                certChainFileId,
                &certChainFileType,
                &certChainFileOption,
                &certChainFileReadAccessCondition,
                &certChainFileWriteAccessCondition,
                &certChainFileReadWriteAccessCondition,
                &certChainFileChangeAccessCondition,
                &certChainFileSize,
                NULL);
            if (sm_status != SM_OK) {
                LOG_E("Get file setting failed!!!");
                goto error;
            }

            /* Size of binary object cannot be less than Digest size */
            if (certChainFileSize < DIGEST_SIZE_BYTES) {
                errorCode = kUSBcErrorUnspecified;
                goto error;
            }
            readSize = DIGEST_SIZE_BYTES;

            sm_status = nx_ReadData(&((sss_nx_session_t *)pSession)->s_ctx,
                certChainFileId,
                0,
                DIGEST_SIZE_BYTES,
                pData,
                &readSize,
                Nx_CommMode_NA);
            if (sm_status != SM_OK) {
                LOG_E("Read file failed!!!");
                goto error;
            }

            memcpy(pDigestPtr, pData, DIGEST_SIZE_BYTES);
            pDigestPtr += DIGEST_SIZE_BYTES;
        }
    }

    /* Successfully filled all digests - fill response buffer header now */
    msg_response->header.protocolVersion = msg_request->header.protocolVersion;
    msg_response->header.messageType     = (uint8_t)(kUSBcResponseDigest);
    msg_response->header.param1          = (uint8_t)(CHALLENGE_RESPONSE_CAPABILITIES);
    msg_response->header.param2          = (uint8_t)(slotsPopulated);
    *pDigestResponseLen                  = (slotsReturnedCount * DIGEST_SIZE_BYTES) + sizeof(msg_response->header);

    if (NULL != pData) {
        SSS_FREE(pData);
    }

    return;

error:
    if (NULL != pData) {
        SSS_FREE(pData);
    }
    /*Free the file context*/
    // sss_file_context_free(&file);
    if ((pDigestResponse) && (pDigestResponseLen)) {
        if (*pDigestResponseLen >= sizeof(msg_response->header)) {
            msg_response->header.protocolVersion = msg_request->header.protocolVersion;
            msg_response->header.messageType     = (uint8_t)(kUSBcResponseError);
            msg_response->header.param1          = (uint8_t)(errorCode);
            msg_response->header.param2          = (uint8_t)(0x00);
            *pDigestResponseLen                  = sizeof(msg_response->header);
        }
        else {
            *pDigestResponseLen = 0;
        }
    }
}
/* doc:end:usb_c-GetCertificateChainDigest */

/* doc:start:usb_c-ReadCertificates */
void ReadCertificates(const uint8_t *pGetCertificateRequest,
    const size_t getCertificateRequestLen,
    uint8_t *pCertificateResponse,
    size_t *pCertificateResponseLen)
{
    smStatus_t sm_status    = SM_NOT_OK;
    size_t objectSize       = 0;
    uint8_t certChainFileId = 0;
    size_t readSize         = 0;
    uint8_t *pData          = NULL;

    usb_c_error_code_t errorCode = kUSBcErrorUnspecified;
    uint8_t requestedslots       = 0;
    uint16_t certificateOffset   = 0;
    uint16_t certificatelength   = 0;
    /* Offset first DIGEST bytes to skip certificate chain hash */
    uint16_t offset                     = (uint16_t)DIGEST_SIZE_BYTES;
    size_t bytesToRead                  = 0;
    usb_c_cert_request_t *msg_request   = NULL;
    usb_c_cert_response_t *msg_response = NULL;
    sss_session_t *pSession             = pgSssSession;
    uint8_t fileNo                      = 0;
    uint8_t i                           = 0;
    uint8_t fIDList[32]                 = {0};
    size_t fIDListLen                   = sizeof(fIDList);
    bool fileExist                      = false;
    Nx_FILEType_t certChainFileType     = 0;
    uint8_t certChainFileOption = NX_FILE_OPTION_SDM_DISBALED | NX_FILE_OPTION_DEFERRED_DISABLED | Nx_CommMode_Plain;
    Nx_AccessCondition_t certChainFileReadAccessCondition      = Nx_AccessCondition_No_Access;
    Nx_AccessCondition_t certChainFileWriteAccessCondition     = Nx_AccessCondition_No_Access;
    Nx_AccessCondition_t certChainFileReadWriteAccessCondition = Nx_AccessCondition_No_Access;
    Nx_AccessCondition_t certChainFileChangeAccessCondition    = Nx_AccessCondition_No_Access;
    size_t certChainFileSize                                   = 0;

    msg_request  = (usb_c_cert_request_t *)pGetCertificateRequest;
    msg_response = (usb_c_cert_response_t *)pCertificateResponse;

    if (NULL == pGetCertificateRequest || NULL == pCertificateResponse || NULL == pCertificateResponseLen) {
        LOG_E("Null buffer");
        errorCode = kUSBcErrorInvalidRequest;
        goto error;
    }

    if (getCertificateRequestLen != GET_CERTIFICATE_CMD_LEN) {
        LOG_E("Invalid request length");
        errorCode = kUSBcErrorInvalidRequest;
        goto error;
    }

    requestedslots = msg_request->header.param1;

    if (requestedslots > MAX_SLOTS - 1) {
        errorCode = kUSBcErrorInvalidRequest;
        LOG_E("Invalid slot id");
        goto error;
    }

    certificateOffset = (uint16_t)(msg_request->offset[1] << 8);
    certificateOffset |= msg_request->offset[0];
    certificatelength = (uint16_t)(msg_request->length[1] << 8);
    certificatelength |= msg_request->length[0];
    certChainFileId = (uint8_t)(USB_C_SLOT_ID_TO_CERT_FILE_ID(requestedslots));
    fileNo          = certChainFileId;
    sm_status       = nx_GetFileIDs(&((sss_nx_session_t *)pSession)->s_ctx, fIDList, &fIDListLen);
    if (sm_status != SM_OK) {
        errorCode = kUSBcErrorUnspecified;
        goto error;
    }

    for (i = 0; i < fIDListLen; i++) {
        if (fileNo == fIDList[i]) {
            fileExist = true;
            break;
        }
    }

    if (!(fileExist)) {
        errorCode = kUSBcErrorUnspecified;
        goto error;
    }
    // Get file setting (length, etc)
    sm_status = nx_GetFileSettings(&((sss_nx_session_t *)pSession)->s_ctx,
        certChainFileId,
        &certChainFileType,
        &certChainFileOption,
        &certChainFileReadAccessCondition,
        &certChainFileWriteAccessCondition,
        &certChainFileReadWriteAccessCondition,
        &certChainFileChangeAccessCondition,
        &certChainFileSize,
        NULL);
    if (sm_status != SM_OK) {
        errorCode = kUSBcErrorUnspecified;
        LOG_E("Get file setting failed!!!");
        goto error;
    }

    offset += certificateOffset;
    objectSize = certChainFileSize;

    if (objectSize < offset) {
        /* Cannot read from offset larger than file size */
        errorCode = kUSBcErrorInvalidRequest;
        goto error;
    }

    /* Calculate actual bytes to read */
    if (certificatelength == 0) {
        bytesToRead = objectSize - offset;
    }
    else {
        bytesToRead = certificatelength;
    }

    if (bytesToRead == 0) {
        /* Cannot read 0 bytes */
        errorCode = kUSBcErrorInvalidRequest;
        goto error;
    }

    /* Bytes to read cannot exceed the total object size */
    if (((size_t)(offset + bytesToRead)) > objectSize) {
        errorCode = kUSBcErrorInvalidRequest;
        goto error;
    }

    readSize = bytesToRead;
    pData    = (uint8_t *)SSS_MALLOC(bytesToRead * sizeof(uint8_t));
    if (!pData) {
        errorCode = kUSBcErrorUnspecified;
        goto error;
    }

    if (*pCertificateResponseLen < (size_t)(bytesToRead + sizeof(usb_c_msg_header_t))) {
        LOG_E("Insufficient buffer");
        errorCode = kUSBcErrorUnspecified;
        goto error;
    }

    /* Read certificate chain */
    sm_status = nx_ReadData(
        &((sss_nx_session_t *)pSession)->s_ctx, certChainFileId, offset, bytesToRead, pData, &readSize, Nx_CommMode_NA);
    if (sm_status != SM_OK) {
        errorCode = kUSBcErrorUnspecified;
        LOG_E("Read certificate file failed!!!");
        goto error;
    }
    LOG_MAU8_D("ReadCertificate object", pData, readSize);

    msg_response->header.protocolVersion = msg_request->header.protocolVersion;
    msg_response->header.messageType     = kUSBcResponseCertificate;
    msg_response->header.param1          = msg_request->header.param1;
    msg_response->header.param2          = 0x00;

    /* Copy the data read out to response buffer */
    memcpy(msg_response->certChain, pData, readSize);
    if (NULL != pData) {
        SSS_FREE(pData);
    }

    *pCertificateResponseLen = (bytesToRead) + sizeof(msg_response->header);

    return;

error:
    if (NULL != pData) {
        SSS_FREE(pData);
    }

    if ((pCertificateResponse) && (pCertificateResponseLen)) {
        if (*pCertificateResponseLen >= sizeof(msg_response->header)) {
            msg_response->header.protocolVersion = msg_request->header.protocolVersion;
            msg_response->header.messageType     = (uint8_t)(kUSBcResponseError);
            msg_response->header.param1          = (uint8_t)(errorCode);
            msg_response->header.param2          = (uint8_t)(0x00);
            *pCertificateResponseLen             = sizeof(msg_response->header);
        }
        else {
            *pCertificateResponseLen = 0;
        }
    }
}
/* doc:end:usb_c-ReadCertificates */

/* doc:start:usb_c-Authenticate */
void Authenticate(const uint8_t *pChallengeRequest,
    const size_t challengeRequestLen,
    uint8_t *pChallengeAuthResponse,
    size_t *pChallengeAuthResponseLen)
{
    sss_status_t status                                    = kStatus_SSS_Fail;
    smStatus_t retStatus                                   = SM_NOT_OK;
    size_t readSize                                        = 0;
    sss_session_t *pSession                                = pgSssSession;
    sss_key_store_t *pKeystore                             = pgKeyStore;
    uint8_t certChainHash[DIGEST_SIZE_BYTES]               = {0};
    uint8_t hash[DIGEST_SIZE_BYTES]                        = {0};
    size_t hashLen                                         = sizeof(hash);
    uint8_t requestedSlot                                  = 0;
    uint8_t slotsPopulated                                 = 0x00;
    uint8_t msgContent[MSG_CONTENT_FOR_SIGNATURE_MAX_SIZE] = {0};
    uint8_t signature[MAX_SIGNATURE_LEN]                   = {0};
    size_t sigLen                                          = sizeof(signature);
    usb_c_error_code_t errorCode                           = kUSBcErrorUnspecified;
    uint32_t keyId                                         = 0;
    usb_c_challenge_request_t *msg_request                 = NULL;
    usb_c_challenge_response_t *msg_response               = NULL;
    usb_c_msg_for_signature_t *msg_content                 = NULL;
    uint8_t certChainFileId                                = 0;
    size_t contextHashLen                                  = DIGEST_SIZE_BYTES;
    uint8_t productInfo[]                                  = PRODUCT_SPECIFIC_CONTEXT;
    size_t productInfoLen                                  = sizeof(productInfo);
    sss_object_t leafKeyPair                               = {0};
    sss_asymmetric_t asymm_ctx                             = {0};
    Nx_FILEType_t certChainFileType                        = 0;
    uint8_t certChainFileOption = NX_FILE_OPTION_SDM_DISBALED | NX_FILE_OPTION_DEFERRED_DISABLED | Nx_CommMode_Plain;
    Nx_AccessCondition_t certChainFileReadAccessCondition      = Nx_AccessCondition_No_Access;
    Nx_AccessCondition_t certChainFileWriteAccessCondition     = Nx_AccessCondition_No_Access;
    Nx_AccessCondition_t certChainFileReadWriteAccessCondition = Nx_AccessCondition_No_Access;
    Nx_AccessCondition_t certChainFileChangeAccessCondition    = Nx_AccessCondition_No_Access;
    size_t certChainFileSize                                   = 0;

    msg_request  = (usb_c_challenge_request_t *)pChallengeRequest;
    msg_response = (usb_c_challenge_response_t *)pChallengeAuthResponse;
    msg_content  = (usb_c_msg_for_signature_t *)msgContent;

    if (NULL == pChallengeRequest || NULL == pChallengeAuthResponse || NULL == pChallengeAuthResponseLen) {
        LOG_E("Null buffer");
        errorCode = kUSBcErrorInvalidRequest;
        goto error;
    }

    if (challengeRequestLen != CHALLENGE_CMD_LEN) {
        LOG_E("Invalid request length");
        errorCode = kUSBcErrorInvalidRequest;
        goto error;
    }

    requestedSlot = msg_request->header.param1;

    if (requestedSlot > MAX_SLOTS - 1) {
        errorCode = kUSBcErrorInvalidRequest;
        LOG_E("Invalid slot id");
        goto error;
    }

    certChainFileId = (uint8_t)(USB_C_SLOT_ID_TO_CERT_FILE_ID(requestedSlot));
    keyId           = (uint32_t)USB_C_SLOT_ID_TO_KEY_ID(requestedSlot);

    if (*pChallengeAuthResponseLen < CHALLENGE_AUTH_RESPONSE_LEN) {
        LOG_E("Insufficient buffer");
        errorCode = kUSBcErrorUnspecified;
        goto error;
    }

    retStatus = getPopulatedSlots(pSession, &slotsPopulated);
    if (SM_OK != retStatus) {
        errorCode = kUSBcErrorUnspecified;
        LOG_E("Failed to retrieve populated slots");
        goto error;
    }

    if (!(slotsPopulated & 0x01)) {
        /* Slot 0 is empty */
        errorCode = kUSBcErrorUnspecified;
        goto error;
    }
    /* Check if the requested slot is populated */
    if (!((1 << requestedSlot) & slotsPopulated)) {
        errorCode = kUSBcErrorInvalidRequest;
        LOG_E("Requested slot not populated");
        goto error;
    }

    /* Get the size of certificate chain file */
    retStatus = nx_GetFileSettings(&((sss_nx_session_t *)pSession)->s_ctx,
        certChainFileId,
        &certChainFileType,
        &certChainFileOption,
        &certChainFileReadAccessCondition,
        &certChainFileWriteAccessCondition,
        &certChainFileReadWriteAccessCondition,
        &certChainFileChangeAccessCondition,
        &certChainFileSize,
        NULL);
    if (retStatus != SM_OK) {
        LOG_E("Get file setting failed!!!");
        goto error;
    }

    /* Size of binary object cannot be less than Digest size */
    if (certChainFileSize < DIGEST_SIZE_BYTES) {
        errorCode = kUSBcErrorUnspecified;
        goto error;
    }
    readSize = DIGEST_SIZE_BYTES;

    // Read digest from the file.
    retStatus = nx_ReadData(&((sss_nx_session_t *)pSession)->s_ctx,
        certChainFileId,
        0,
        DIGEST_SIZE_BYTES,
        certChainHash,
        &readSize,
        Nx_CommMode_NA);
    if (retStatus != SM_OK) {
        LOG_E("Read file failed!!!");
        goto error;
    }

    msg_response->header.protocolVersion = msg_request->header.protocolVersion;
    msg_response->header.messageType     = kUSBcResponseChallenge;
    msg_response->header.param1          = msg_request->header.param1;
    msg_response->header.param2          = (uint8_t)(slotsPopulated);
    msg_response->minProtocolVersion     = CHALLENGE_RESPONSE_MIN_VERSION;
    msg_response->maxProtocolVersion     = CHALLENGE_RESPONSE_MAX_VERSION;
    msg_response->capabilities           = CHALLENGE_RESPONSE_CAPABILITIES;
    msg_response->orgName                = CHALLENGE_RESPONSE_ORG_NAME_USB_IF;
    memcpy(msg_response->certChainHash, certChainHash, DIGEST_SIZE_BYTES);
    status = generateRandom(pSession, msg_response->salt, sizeof(msg_response->salt));
    if (kStatus_SSS_Success != status) {
        errorCode = kUSBcErrorUnspecified;
        LOG_E("Failed to get salt");
        goto error;
    }

    status = getSha256Hash(pSession, productInfo, productInfoLen, msg_response->contextHash, &contextHashLen);
    if (kStatus_SSS_Success != status) {
        errorCode = kUSBcErrorUnspecified;
        LOG_E("Failed to get context hash");
        goto error;
    }

    // Contruct CHALLENGE_AUTH Response message
    memcpy(&(msg_content->reqMsg), pChallengeRequest, challengeRequestLen);
    memcpy(&(msg_content->respMsg), msg_response, sizeof(msg_content->respMsg));

    /* Calculate SHA256 of message content for signature */
    status = getSha256Hash(pSession, (uint8_t *)msg_content, sizeof(usb_c_msg_for_signature_t), hash, &hashLen);
    if (status != kStatus_SSS_Success) {
        errorCode = kUSBcErrorUnspecified;
        LOG_E("Failed getSha256Hash");
        goto error;
    }

    /* Generating keypair */
    status = sss_key_object_init(&leafKeyPair, pKeystore);
    if (status != kStatus_SSS_Success) {
        errorCode = kUSBcErrorUnspecified;
        LOG_E("sss_key_object_init Failed!!!");
        goto error;
    }

    status = sss_key_object_get_handle(&leafKeyPair, kSSS_CipherType_EC_NIST_P, keyId);
    if (status != kStatus_SSS_Success) {
        errorCode = kUSBcErrorUnspecified;
        LOG_E("sss_key_object_init Failed!!!");
        goto error;
    }

    /* Init asymm context */
    status =
        sss_asymmetric_context_init(&asymm_ctx, pSession, &leafKeyPair, kAlgorithm_SSS_ECDSA_SHA256, kMode_SSS_Sign);
    if (status != kStatus_SSS_Success) {
        errorCode = kUSBcErrorUnspecified;
        LOG_E("sss_asymmetric_context_init Failed!!!");
        goto error;
    }

    /* Calculate signature */
    status = sss_asymmetric_sign_digest(&asymm_ctx, hash, hashLen, signature, &sigLen);
    if (status != kStatus_SSS_Success) {
        errorCode = kUSBcErrorUnspecified;
        LOG_E("sss_asymmetric_sign_one_go Failed!!!");
        goto error;
    }

    /* Extract R and S values from signature */
    retStatus = EcSignatureToRandS(signature, &sigLen);
    if (retStatus != SM_OK) {
        LOG_E("EcSignatureToRandS Failed...");
        errorCode = kUSBcErrorUnspecified;
        goto error;
    }

    if (sigLen != 64) {
        errorCode = kUSBcErrorUnspecified;
        LOG_E("Invalid signature length!!!");
        goto error;
    }

    status = swapRandS(signature, sigLen / 2);
    if (status != kStatus_SSS_Success) {
        errorCode = kUSBcErrorUnspecified;
        LOG_E("swapRandS Failed!!!");
        goto error;
    }

    status = swapRandS(&(signature[32]), sigLen / 2);
    if (status != kStatus_SSS_Success) {
        errorCode = kUSBcErrorUnspecified;
        LOG_E("swapRandS Failed!!!");
        goto error;
    }

    memcpy(msg_response->signature, signature, sigLen);
    *pChallengeAuthResponseLen = sizeof(usb_c_challenge_response_t);

    return;

error:
    if (asymm_ctx.session != NULL) {
        sss_asymmetric_context_free(&asymm_ctx);
    }
    if (leafKeyPair.keyStore != NULL) {
        sss_key_object_free(&leafKeyPair);
    }
    if ((pChallengeAuthResponse) && (pChallengeAuthResponseLen)) {
        if (*pChallengeAuthResponseLen >= sizeof(msg_response->header)) {
            msg_response->header.protocolVersion = msg_request->header.protocolVersion;
            msg_response->header.messageType     = (uint8_t)(kUSBcResponseError);
            msg_response->header.param1          = (uint8_t)(errorCode);
            msg_response->header.param2          = (uint8_t)(0x00);
            *pChallengeAuthResponseLen           = sizeof(msg_response->header);
        }
        else {
            *pChallengeAuthResponseLen = 0;
        }
    }
}
/* doc:end:usb_c-Authenticate */
