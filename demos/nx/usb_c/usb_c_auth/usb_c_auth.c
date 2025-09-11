/*
 *
 * Copyright 2023-2025 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "usb_c_auth.h"

#define EX_SLOT_ID 0x01

static int sendCommandGetDigests_RetrieveHashForSlot(uint8_t *pHash);
static int sendCommandGetCertificate_RetrivePublicKeyVerifyHash(
    uint8_t *pPublicKey, size_t *pPublicKeyLen, uint8_t *pHash);
static int sendCommandChallenge_VerifySignature(uint8_t *pPublicKey, size_t publicKeyLen);

sss_status_t ex_sss_entry(ex_sss_boot_ctx_t *pCtx)
{
    sss_status_t status = kStatus_SSS_Fail;

    uint8_t digest[DIGEST_SIZE_BYTES] = {0};
    uint8_t publicKey[80]             = {0};
    size_t publicKeyLen               = sizeof(publicKey);

    if (0 != sendCommandGetDigests_RetrieveHashForSlot(digest)) {
        LOG_E("GetDigests failed");
        goto exit;
    }
    LOG_MAU8_I("Retrieved digest", digest, sizeof(digest));
    if (0 != sendCommandGetCertificate_RetrivePublicKeyVerifyHash(publicKey, &publicKeyLen, digest)) {
        LOG_E("GetCertificate failed");
        goto exit;
    }
    LOG_MAU8_I("Retrieved Leaf certificate public key", publicKey, publicKeyLen);
    if (0 != sendCommandChallenge_VerifySignature(publicKey, publicKeyLen)) {
        LOG_E("Challenge failed");
        goto exit;
    }

    status = kStatus_SSS_Success;
exit:
    if (kStatus_SSS_Success == status) {
        LOG_I("usb_c_auth Example Success !!!...");
    }
    else {
        LOG_E("usb_c_auth Example Failed !!!...");
    }
    return status;
}

static int sendCommandGetDigests_RetrieveHashForSlot(uint8_t *pHash)
{
    int ret                                           = -1;
    uint8_t cmd_buffer[MAX_CMD_SIZE_GET_DIGESTS]      = {0};
    size_t cmd_size                                   = sizeof(cmd_buffer);
    uint8_t response_buffer[MAX_RSP_SIZE_GET_DIGESTS] = {0};
    size_t response_size                              = sizeof(response_buffer);
    uint8_t slot_id                                   = EX_SLOT_ID;
    uint8_t required_slot_id_mask                     = (1 << EX_SLOT_ID);
    uint8_t hash_response_offset                      = 0;
    uint8_t slots_populated                           = 0x00;
    usb_c_digests_request_t *auth_request             = (usb_c_digests_request_t *)cmd_buffer;
    usb_c_digests_response_t *auth_response           = NULL;

    if (NULL == pHash) {
        goto exit;
    }

    LOG_I("Send command GET_DIGESTS");
    /* Create command buffer for GET_DIGESTS command */
    auth_request->header.protocolVersion = AUTH_PROTOCOL_VERSION;
    auth_request->header.messageType     = kUSBcCommandGetDigests;
    auth_request->header.param1          = 0;
    auth_request->header.param2          = 0;

    /* Send GET_DIGESTS command */
    LOG_MAU8_D("GET_DIGESTS >", cmd_buffer, cmd_size);
    responderSendCommand(cmd_buffer, cmd_size, response_buffer, &response_size);
    LOG_MAU8_D("DIGESTS <", response_buffer, response_size);
    auth_response = (usb_c_digests_response_t *)response_buffer;
    if ((auth_response->header.protocolVersion != AUTH_PROTOCOL_VERSION) &&
        (auth_response->header.protocolVersion != kUSBcResponseDigest) &&
        (auth_response->header.param1 != CHALLENGE_RESPONSE_CAPABILITIES)) {
        LOG_E("sendCommandGetDigests Failed");
        goto exit;
    }
    if ((required_slot_id_mask & (auth_response->header.param2)) != required_slot_id_mask) {
        LOG_E("sendCommandGetDigests Failed: Required slot not populated");
        goto exit;
    }

    slots_populated = auth_response->header.param2;
    for (size_t i = 0; i < MAX_SLOTS; i++) {
        if (i == slot_id) {
            break;
        }
        if ((slots_populated) & (0x01 << i)) {
            hash_response_offset += DIGEST_SIZE_BYTES;
        }
    }

    memcpy(pHash, &auth_response->payload[hash_response_offset], DIGEST_SIZE_BYTES);
    ret = 0;

exit:
    return ret;
}

static int sendCommandGetCertificate_RetrivePublicKeyVerifyHash(
    uint8_t *pPublicKey, size_t *pPublicKeyLen, uint8_t *pHash)
{
    int ret                                                             = -1;
    uint8_t cmd_buffer[MAX_CMD_SIZE_GET_CERTIFICATE]                    = {0};
    size_t cmd_size                                                     = sizeof(cmd_buffer);
    uint8_t response_buffer[AUTH_MSG_HEADER_SIZE + MAX_CERT_CHAIN_SIZE] = {0};
    size_t response_size                                                = sizeof(response_buffer);
    uint8_t calculated_digest[DIGEST_SIZE_BYTES]                        = {0};
    size_t calculated_digest_size                                       = sizeof(calculated_digest);
    uint8_t leafCertPublicKey[71]                                       = {0};
    size_t leafCertPublicKeylen                                         = sizeof(leafCertPublicKey);
    uint16_t offset                                                     = 0;
    uint16_t length                                                     = 0;
    uint8_t slot_id                                                     = EX_SLOT_ID;
    size_t certificateChainLength                                       = 0;
    usb_c_cert_request_t *auth_request                                  = (usb_c_cert_request_t *)cmd_buffer;
    usb_c_cert_response_t *auth_response                                = (usb_c_cert_response_t *)response_buffer;
    usb_c_cert_chain_t *cert_chain                                      = NULL;
    uint8_t *pLeafCert                                                  = NULL;
    size_t leafCertLen                                                  = 0;

    LOG_I("Send command GET_CERTIFICATE");

    if (NULL == pHash) {
        goto exit;
    }

    /* Create command buffer for GET_CERTIFICATE command */
    auth_request->header.protocolVersion = AUTH_PROTOCOL_VERSION;
    auth_request->header.messageType     = kUSBcCommandGetCertificate;
    auth_request->header.param1          = slot_id;
    auth_request->header.param2          = 0x00;
    auth_request->offset[0]              = (uint8_t)(offset & 0x00FF);
    auth_request->offset[1]              = (uint8_t)((offset & 0xFF00) >> 8);
    auth_request->length[0]              = (uint8_t)(length & 0x00FF);
    auth_request->length[1]              = (uint8_t)((length & 0xFF00) >> 8);

    /* Send GET_CERTIFICATE command */
    LOG_MAU8_D("GET_CERTIFICATE >", cmd_buffer, cmd_size);
    responderSendCommand(cmd_buffer, cmd_size, response_buffer, &response_size);
    LOG_MAU8_D("CERTIFICATE <", response_buffer, response_size);
    if ((auth_response->header.protocolVersion != AUTH_PROTOCOL_VERSION) ||
        (auth_response->header.messageType != kUSBcResponseCertificate)) {
        LOG_E("sendCommandGetCertificate Failed");
        goto exit;
    }

    cert_chain             = (usb_c_cert_chain_t *)(auth_response->certChain);
    certificateChainLength = cert_chain->length[0];
    certificateChainLength |= (size_t)((cert_chain->length[1] << 8));

    if (0 != port_getSha256Hash(
                 auth_response->certChain, certificateChainLength, calculated_digest, &calculated_digest_size)) {
        LOG_W("Could not calculate SHA256 on host");
        goto exit;
    }

    if (memcmp(calculated_digest, pHash, DIGEST_SIZE_BYTES)) {
        LOG_E("SHA256 of certificate chain mismatch");
        goto exit;
    }
    else {
        LOG_I("Certificate chain digest successfully verified");
    }

    if (certificateChainLength <= 36) {
        LOG_E("No avaible certificates");
        goto exit;
    }

    if (0 != port_parseCertificatesGetLeafCert(
                 cert_chain->certificates, certificateChainLength - 36, &pLeafCert, &leafCertLen)) {
        LOG_W("Get Leaf Certificate from certificate chain failed");
    };

    LOG_MAU8_I("Retrieved Leaf Certificate", (pLeafCert), leafCertLen);

    port_parseCertGetPublicKey(pLeafCert, leafCertLen, leafCertPublicKey, &leafCertPublicKeylen);

    if (leafCertPublicKeylen > COMPRESSED_KEY_SIZE) {
        /* Uncompressed key */
        if ((NULL == pPublicKey) || (NULL == pPublicKeyLen)) {
            goto exit;
        }
        *pPublicKey = 0x04;
        memcpy(pPublicKey + 1, leafCertPublicKey, leafCertPublicKeylen);
        *pPublicKeyLen = leafCertPublicKeylen + 1;
    }
    else {
        /* Compressed key */
        LOG_E("Don't support compressed key");
        goto exit;
    }

    if (0 != port_hostVerifyCertificates(cert_chain->certificates, certificateChainLength - 36)) {
        LOG_W("Certificate chain verification failed");
    }
    else {
        LOG_I("Certificate chain successfully verified");
    }

    ret = 0;

exit:
    return ret;
}

static int sendCommandChallenge_VerifySignature(uint8_t *pPublicKey, size_t publicKeyLen)
{
    uint8_t cmd_buffer[MAX_CMD_SIZE_CHALLENGE]      = {0};
    size_t cmd_size                                 = sizeof(cmd_buffer);
    uint8_t response_buffer[MAX_RSP_SIZE_CHALLENGE] = {0};
    size_t response_size                            = sizeof(response_buffer);
    uint8_t slot_id                                 = EX_SLOT_ID;
    uint8_t nonce[NONCE_LEN]                        = {0};
    size_t nonce_length                             = sizeof(nonce);
    usb_c_challenge_request_t *auth_request         = (usb_c_challenge_request_t *)cmd_buffer;
    usb_c_challenge_response_t *auth_response       = (usb_c_challenge_response_t *)response_buffer;

    LOG_I("Send command CHALLENGE");

    if (0 != port_getRandomNonce(nonce, &nonce_length)) {
        LOG_W("Could not generate random nonce on host");
        memset(nonce, 0, sizeof(nonce));
    }

    /* Create command buffer for CHALLENGE command */
    auth_request->header.protocolVersion = AUTH_PROTOCOL_VERSION;
    auth_request->header.messageType     = kUSBcCommandChallenge;
    auth_request->header.param1          = slot_id;
    auth_request->header.param2          = 0;
    memcpy(auth_request->nonce, nonce, sizeof(nonce));

    /* Send CHALLENGE command */
    LOG_MAU8_D("CHALLENGE >", cmd_buffer, cmd_size);
    responderSendCommand(cmd_buffer, cmd_size, response_buffer, &response_size);
    LOG_MAU8_D("CHALLENGE_AUTH <", response_buffer, response_size);

    if ((auth_response->header.protocolVersion != AUTH_PROTOCOL_VERSION) ||
        (auth_response->header.messageType != kUSBcResponseChallenge)) {
        LOG_E("sendCommandChallenge Failed");
        return -1;
    }

    LOG_MAU8_I("Challenge Signature", (auth_response->signature), RAW_SIGNATURE_SIZE_BYTES);

    if (0 != port_hostVerifyChallenge(pPublicKey, publicKeyLen, cmd_buffer, response_buffer)) {
        LOG_E("Failed to verify signature");
        return -1;
    }

    return 0;
}
