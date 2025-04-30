/*
 * Copyright 2024 NXP
 * SPDX-License-Identifier: BSD-3-Clause
**/

#include "sm_types.h"
#include "ex_sss_boot.h"

#define AM_LOCK_UNLOCK_SUPPORT

#define SERVERPORT 8040

// General Message Format
//
// [MTY]:[NAD]:[LNH]:[LNL]:[D0]:...[Dn]
// MTY: Message Type
#define MTY_WAIT_FOR_CARD 0x00
#define MTY_APDU_DATA 0x01
// #define	MTY_STATUS              0x02
// #define	MTY_ERROR_MSG           0x03
// #define	MTY_TERMINAL_INFO       0x04
// #define	MTY_INITIALIZATION_DATA 0x05
// #define	MTY_INFORMATION_TEXT    0x06
// #define	MTY_DEBUG_INFORMATION   0x07

#define MTY_IDX 0
#define NAD_IDX 1
#define LNH_IDX 2
#define LNL_IDX 3
#define DATA_START_IDX 4

// Additionally defined
// Lock/Unlock command: Reserve/Release access to node to calling client
#define MTY_LOCK 0x30
#define MTY_UNLOCK 0x31
// Development commands
#define MTY_SET_UINT32 0x40
#define MTY_GET_UINT32 0x41
// Default Node Address
#define MYT_DEFAULT_NAD 0x00
// Close command
#define MTY_CLOSE 0x03
// Quit command
#define MTY_QUIT 0x50

/* Access manager reserved commands - start */
// For future use
#define RESERVED_ID1 0x60
#define RESERVED_ID2 0x61
#define RESERVED_ID3 0x62
#define RESERVED_ID4 0x63

#define RESERVED_ID5 0x70
#define RESERVED_ID6 0x71
#define RESERVED_ID7 0x72
#define RESERVED_ID8 0x73
/* Access manager reserved commands - end */

#define MCS_OK 0
#define MCS_SOCKET_FAILURE 2
#define MCS_MSG_MISMATCH 3

#define AM_OK 0x0000
#define AM_NOT_OK 0x3000
#define AM_ARG_FAIL 0x6000
#define EX_SSS_BOOT_SSS_PORT "EX_SSS_BOOT_SSS_PORT"

typedef struct
{
    sss_session_t session;
    sss_key_store_t ks;
    sss_session_t host_session;
    sss_key_store_t host_ks;
} am_sss_boot_ctx_t;

int amPackageApduResponse(
    U8 messageType, U8 nodeAddress, U8 *payload, U16 payloadLen, U8 *targetBuf, U16 *targetBufLen);
void amResetTransactionBuffers(
    uint8_t *rcvBuf, uint8_t *respBuf, uint16_t *respBufLen, uint8_t *sndBuf, uint16_t *sndBufLen);
int amParseCmdLineArgs(int argc, char **argv, bool *requestAnyAddressBinding);
void showAccessManagerHelp();
sss_status_t amSessionOpen(
    int argc, char **argv, ex_sss_boot_ctx_t *pboot_ctx, nx_auth_type_t auth_type, char *portName);
void amSessionClose(ex_sss_boot_ctx_t *pboot_ctx);
void amGetPortName(int argc, char **argv, char **portname);

#define UNIX_SOCKET_FILE "/var/run/am"

#define ENSURE_RECV_BYTES_OR_CLOSE_CONN_AND_CONTINUE(nByte, cl)                                           \
    if (nByte == 0) {                                                                                     \
        /* if select marks descriptor as ready, but no data can be read the connection has been closed */ \
        LOG_I("Received 0 bytes from client %d (Message Header Phase).\n", cl->sock);                     \
        close(cl->sock);                                                                                  \
        cl->sock = -1; /* mark client for deletion */                                                     \
        cl       = cl->next;                                                                              \
        continue;                                                                                         \
    }                                                                                                     \
    else if (nByte == -1) {                                                                               \
        LOG_E("Error on reading: errno: %s.\n", strerror(errno));                                         \
        cl->sock = -1; /* mark client for deletion */                                                     \
        cl       = cl->next;                                                                              \
        continue;                                                                                         \
    }                                                                                                     \
    else if (nByte < MSG_HEADER_SIZE) {                                                                   \
        LOG_E("Expected to handle a header of size 2. Actual size = %d.", nByte);                         \
        close(cl->sock);                                                                                  \
        cl->sock = -1; /* mark client for deletion */                                                     \
        cl       = cl->next;                                                                              \
        continue;                                                                                         \
    }
