/* Copyright 2023 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __USB_C_RESPONDER__
#define __USB_C_RESPONDER__

#include <stdint.h>
#include <stdlib.h>
#include "usb_c_common.h"
#include "usb_c_responder_port.h"

#define AUTH_PROTOCOL_VERSION 0x1

#define READ_ID_LIST_MAX_OBJECTS 256
#define READ_ID_LIST_SIZE READ_ID_LIST_MAX_OBJECTS * 4
#define MSG_CONTENT_FOR_SIGNATURE_MAX_SIZE 140
#define TBSAUTH_CHALLENGE_REQ_OFFSET 33
#define TBSAUTH_CHALLENGE_AUTH_RESP_OFFSET 51
#define CHALLENGE_AUTH_RESPONSE_PREFIX 0x41
#define MAX_SIGNATURE_LEN 80
#define CHALLENGE_AUTH_RESPONSE_LEN sizeof(usb_c_challenge_response_t)
#define GET_DIGESTS_CMD_LEN sizeof(usb_c_digests_request_t)
#define GET_CERTIFICATE_CMD_LEN 8
#define CHALLENGE_CMD_LEN 36

#define CHALLENGE_RESPONSE_MIN_VERSION 0x01
#define CHALLENGE_RESPONSE_MAX_VERSION 0x01
#define CHALLENGE_RESPONSE_CAPABILITIES 0x01
#define CHALLENGE_RESPONSE_ORG_NAME_USB_IF 0x00

#define PRODUCT_SPECIFIC_CONTEXT                                                                                    \
    {                                                                                                               \
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,                     \
    }

typedef enum
{
    kUSBcCommandGetDigests     = 0x81,
    kUSBcCommandGetCertificate = 0x82,
    kUSBcCommandChallenge      = 0x83,
} usb_c_command_type_t;

typedef enum
{
    kUSBcResponseDigest      = 0x1,
    kUSBcResponseCertificate = 0x2,
    kUSBcResponseChallenge   = 0x3,
    kUSBcResponseError       = 0x7F,
} usb_c_response_type_t;

typedef enum
{
    kUSBcErrorNone = 0x0,
    kUSBcErrorInvalidRequest,
    kUSBcErrorUnsupportedProtocol,
    kUSBcErrorBusy,
    kUSBcErrorUnspecified,
} usb_c_error_code_t;

void responderSendCommand(
    const uint8_t *pCmdBuffer, const size_t cmdBufferLen, uint8_t *pResponseBuffer, size_t *pResponseBufferLen);

void GetCertificateChainDigest(const uint8_t *pGetDigestRequest,
    const size_t getDigestRequestLen,
    uint8_t *pDigestResponse,
    size_t *pDigestResponseLen);

void ReadCertificates(const uint8_t *pGetCertificateRequest,
    const size_t getCertificateRequestLen,
    uint8_t *pCertificateResponse,
    size_t *pCertificateResponseLen);

void Authenticate(const uint8_t *pChallengeRequest,
    const size_t challengeRequestLen,
    uint8_t *pChallengeAuthResponse,
    size_t *pChallengeAuthResponseLen);

#endif // __USB_C_RESPONDER__
