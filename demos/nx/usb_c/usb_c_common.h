/* Copyright 2023-2024 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __USB_C_COMMON_H__
#define __USB_C_COMMON_H__

#if SSS_HAVE_LOG_VERBOSE
#define NX_LOG_ENABLE_APP_DEBUG 1
#endif // SSS_HAVE_LOG_VERBOSE

#define USB_C_PROVISIONING_KEY_ID_OFFSET 0x0
#define USB_C_PROVISIONING_CERT_FILE_ID_OFFSET 0x10
#define USB_C_PROVISIONING_CERT_ISO_FILE_ID_OFFSET 0x1000
#define MAX_SLOTS 0x5

#define RAW_SIGNATURE_SIZE_BYTES 64
#define NONCE_LEN 32
#define MAX_CERT_CHAIN_DEPTH 20
/*
 * USB_C provisioning Key IDs are defined as USB_C_PROVISIONING_ID_BASE + SlotNumber
 * Where,
 *     USB_C_PROVISIONING_KEY_ID_OFFSET is 0x0
 *     SlotNumber is the slot for which provisioning needs to be done
 */
#define USB_C_SLOT_ID_TO_KEY_ID(SLOT_ID) USB_C_PROVISIONING_KEY_ID_OFFSET + SLOT_ID
#define USB_C_SLOT_ID_TO_CERT_FILE_ID(SLOT_ID) USB_C_PROVISIONING_CERT_FILE_ID_OFFSET + SLOT_ID
#define USB_C_SLOT_ID_TO_CERT_ISO_FILE_ID(SLOT_ID) USB_C_PROVISIONING_CERT_ISO_FILE_ID_OFFSET + SLOT_ID

#define DIGEST_SIZE_BYTES 32

#pragma pack(push)
#pragma pack(1)

typedef struct
{
    uint8_t protocolVersion;
    uint8_t messageType;
    uint8_t param1;
    uint8_t param2;
} usb_c_msg_header_t;

typedef struct
{
    usb_c_msg_header_t header;
} usb_c_digests_request_t;

typedef struct
{
    usb_c_msg_header_t header;
    uint8_t payload[1]; // Start point of digest field. Doesn't mean the digest field length is 1 byte.
} usb_c_digests_response_t;

typedef struct
{
    usb_c_msg_header_t header;
    uint8_t offset[2];
    uint8_t length[2];
} usb_c_cert_request_t;

typedef struct
{
    usb_c_msg_header_t header;
    uint8_t certChain
        [1]; // Start point of certificate chain field. Doesn't mean the certificate chain field length is 1 byte.
} usb_c_cert_response_t;

typedef struct
{
    uint8_t length[2];
    uint8_t reserve[2];
    uint8_t rootHash[32];
    uint8_t certificates[1]; // Start point of certificates field. Doesn't mean the certificates field length is 1 byte.
} usb_c_cert_chain_t;

typedef struct
{
    usb_c_msg_header_t header;
    uint8_t nonce[32];
} usb_c_challenge_request_t;

typedef struct
{
    usb_c_msg_header_t header;
    uint8_t minProtocolVersion;
    uint8_t maxProtocolVersion;
    uint8_t capabilities;
    uint8_t orgName;
    uint8_t certChainHash[32];
    uint8_t salt[32];
    uint8_t contextHash[32];
    uint8_t signature[64];
} usb_c_challenge_response_t;

typedef struct
{
    usb_c_msg_header_t header;
    uint8_t minProtocolVersion;
    uint8_t maxProtocolVersion;
    uint8_t capabilities;
    uint8_t orgName;
    uint8_t certChainHash[32];
    uint8_t salt[32];
    uint8_t contextHash[32];
} usb_c_challenge_response_wo_sign_t;

typedef struct
{
    usb_c_challenge_request_t reqMsg;
    usb_c_challenge_response_wo_sign_t respMsg;
} usb_c_msg_for_signature_t;

#pragma pack(pop)

#endif // __USB_C_COMMON_H__