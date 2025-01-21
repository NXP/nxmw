/* Copyright 2023 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __USB_C_AUTH_H__
#define __USB_C_AUTH_H__

#include "usb_c_responder.h"
#include "usb_c_responder_helpers.h"
#include "usb_c_initiator_helper_port.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>

#define MAX_CMD_SIZE_GET_DIGESTS 4
#define MAX_RSP_SIZE_GET_DIGESTS 4 + (32 /* Digest size */ * MAX_SLOTS /* Total slots */)

#define MAX_CMD_SIZE_GET_CERTIFICATE 8
#define MAX_CMD_SIZE_CHALLENGE (4 + 32) // Header + 32 bytes random
#define MAX_RSP_SIZE_CHALLENGE 168
#define TBS_AUTH_BUFFER_SIZE \
    1 + 32 /* Digest Size */ + MAX_CMD_SIZE_CHALLENGE + 3 /* First 3 bytes of Challenge response */

#define UNCOMPRESSED_KEY_SIZE 64
#define COMPRESSED_KEY_SIZE 32
#define MAX_MANUFACTURER_CERT_SIZE 0x200
#define MAX_PROD_CERT_SIZE 0x200
#define ROOT_CERT_SIZE 32 /* Only hash of Root cert will be stored */
#define CERT_CHAIN_HASH_SIZE 32

#define AUTH_MSG_HEADER_SIZE 4
#define MAX_CERT_CHAIN_SIZE 4096

extern sss_session_t *pgSssSession;
extern uint8_t usb_c_rootca_cert[];
extern size_t usb_c_rootca_cert_len;

#endif // __USB_C_AUTH_H__
