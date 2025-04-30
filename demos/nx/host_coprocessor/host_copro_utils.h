/* Copyright 2025 NXP
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef HOST_COPRO_UTILS_H_
#define HOST_COPRO_UTILS_H_
#include <stdint.h>
#include <stddef.h>

#define NX_HOST_COPRO_MSG_START 0xB0
#define NX_HOST_COPRO_MSG_START2 0x00
// Message Session OK
#define NX_HOST_COPRO_MSG_SESSION_OK 0xB4

#define NX_HOST_COPRO_FREEMEM (0x6E)
#define NX_MAX_BUF_SIZE_CMD (1024)
#define NX_MAX_BUF_SIZE_RSP (1024)

int hcp_get_u8buf(uint8_t *buf, size_t *pBufIndex, const size_t bufLen, uint8_t *rsp, size_t rspLen);
int hcp_set_u8buf(uint8_t **buf, size_t *bufLen, const uint8_t *cmd, size_t cmdLen);
int hcp_set_U8(uint8_t **buf, size_t *bufLen, uint8_t value);
#endif // HOST_COPRO_UTILS_H_