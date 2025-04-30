/*
 *
 * Copyright 2025 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "host_copro_utils.h"
#include "nxLog_msg.h"
#include "nxEnsure.h"

/* ************************************************************************** */
/* Local Defines                                                              */
/* ************************************************************************** */

/* ************************************************************************** */
/* Public Functions                                                           */
/* ************************************************************************** */

int hcp_set_u8buf(uint8_t **buf, size_t *bufLen, const uint8_t *cmd, size_t cmdLen)
{
    int retVal               = 1;
    uint8_t *pBuf            = NULL;
    const size_t size_of_tlv = cmdLen;

    ENSURE_OR_GO_CLEANUP(NULL != buf);
    ENSURE_OR_GO_CLEANUP(NULL != *buf);
    ENSURE_OR_GO_CLEANUP(NULL != bufLen);
    ENSURE_OR_GO_CLEANUP(NULL != cmd);

    pBuf = *buf;
    if ((SIZE_MAX - (*bufLen)) < size_of_tlv) {
        goto cleanup;
    }

    if (((*bufLen) + size_of_tlv) > NX_MAX_BUF_SIZE_CMD) {
        LOG_E("Not enough buffer");
        goto cleanup;
    }
    if ((cmdLen > 0) && (cmd != NULL)) {
        while (cmdLen-- > 0) {
            *pBuf++ = *cmd++;
        }
    }

    *bufLen += size_of_tlv;
    *buf   = pBuf;
    retVal = 0;
cleanup:
    return retVal;
}

//ISO 7816-4 Annex D.
//          |---------|tag------------------|-------------------|
// before: buf       pBufIndex                              bufLen
// after:  buf                           pBufIndex          bufLen
int hcp_get_u8buf(uint8_t *buf, size_t *pBufIndex, const size_t bufLen, uint8_t *rsp, size_t rspLen)
{
    int retVal    = 1;
    uint8_t *pBuf = NULL;

    ENSURE_OR_GO_CLEANUP(NULL != buf)
    ENSURE_OR_GO_CLEANUP(NULL != pBufIndex)
    ENSURE_OR_GO_CLEANUP(NULL != rsp)

    pBuf = buf + (*pBufIndex);
    ENSURE_OR_GO_CLEANUP((SIZE_MAX - (*pBufIndex)) >= rspLen);
    ENSURE_OR_GO_CLEANUP(((*pBufIndex) + rspLen) <= NX_MAX_BUF_SIZE_RSP)

    *pBufIndex += rspLen;
    if ((*pBufIndex) > bufLen) {
        goto cleanup;
    }

    while (rspLen-- > 0) {
        *rsp++ = *pBuf++;
    }
    retVal = 0;
cleanup:
    return retVal;
}

//          |------------|------------|----------------|
// Before  start   buf(bufLen)                        Max
// After                          buf(bufLen)
int hcp_set_U8(uint8_t **buf, size_t *bufLen, uint8_t value)
{
    int retVal                 = 1;
    uint8_t *pBuf              = NULL;
    const size_t size_of_value = 1;

    ENSURE_OR_GO_CLEANUP(NULL != buf)
    ENSURE_OR_GO_CLEANUP(NULL != *buf)
    ENSURE_OR_GO_CLEANUP(NULL != bufLen)

    pBuf = *buf;
    if ((SIZE_MAX - (*bufLen)) < size_of_value) {
        goto cleanup;
    }
    if (((*bufLen) + size_of_value) > NX_MAX_BUF_SIZE_CMD) {
        goto cleanup;
    }
    *pBuf++ = value;
    *buf    = pBuf;
    *bufLen += size_of_value;
    retVal = 0;
cleanup:
    return retVal;
}