/*
 *
 * Copyright 2022-2024 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 */

#if defined(SSS_USE_FTR_FILE)
#include "fsl_sss_ftr.h"
#else
#include "fsl_sss_ftr_default.h"
#endif

#include <string.h>
#include <limits.h>
#include "nxLog_msg.h"
#include "nx_secure_msg_apis.h"
#include "nxEnsure.h"

//          |------------|------------|----------------|
// Before  start   buf(bufLen)                        Max
// After                          buf(bufLen)
int set_U8(uint8_t **buf, size_t *bufLen, uint8_t value, size_t max_buf_size)
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
    if (((*bufLen) + size_of_value) > max_buf_size) {
        goto cleanup;
    }
    *pBuf++ = value;
    *buf    = pBuf;
    *bufLen += size_of_value;
    retVal = 0;
cleanup:
    return retVal;
}

int set_U16_LSB(uint8_t **buf, size_t *bufLen, uint16_t value, size_t max_buf_size)
{
    int retVal                 = 1;
    uint8_t *pBuf              = NULL;
    const size_t size_of_value = 2;

    ENSURE_OR_GO_CLEANUP(NULL != buf)
    ENSURE_OR_GO_CLEANUP(NULL != *buf)
    ENSURE_OR_GO_CLEANUP(NULL != bufLen)

    pBuf = *buf;
    if ((SIZE_MAX - (*bufLen)) < size_of_value) {
        goto cleanup;
    }

    if (((*bufLen) + size_of_value) > max_buf_size) {
        goto cleanup;
    }
    *pBuf++ = (uint8_t)((value >> 0 * 8) & 0xFF);
    *pBuf++ = (uint8_t)((value >> 1 * 8) & 0xFF);
    *buf    = pBuf;
    *bufLen += size_of_value;
    retVal = 0;
cleanup:
    return retVal;
}

int set_U24_LSB(uint8_t **buf, size_t *bufLen, size_t value, size_t max_buf_size)
{
    int retVal                 = 1;
    uint8_t *pBuf              = NULL;
    const size_t size_of_value = 3;

    ENSURE_OR_GO_CLEANUP(NULL != buf)
    ENSURE_OR_GO_CLEANUP(NULL != *buf)
    ENSURE_OR_GO_CLEANUP(NULL != bufLen)

    pBuf = *buf;
    if ((SIZE_MAX - (*bufLen)) < size_of_value) {
        goto cleanup;
    }

    if (((*bufLen) + size_of_value) > max_buf_size) {
        goto cleanup;
    }
    *pBuf++ = (uint8_t)((value >> 0 * 8) & 0xFF);
    *pBuf++ = (uint8_t)((value >> 1 * 8) & 0xFF);
    *pBuf++ = (uint8_t)((value >> 2 * 8) & 0xFF);
    *buf    = pBuf;
    *bufLen += size_of_value;
    retVal = 0;
cleanup:
    return retVal;
}

int get_U24_LSB(uint8_t *buf, size_t *pBufIndex, const size_t bufLen, uint32_t *pRsp)
{
    int retVal                 = 1;
    uint8_t *pBuf              = NULL;
    const size_t size_of_value = 3;

    ENSURE_OR_GO_CLEANUP(NULL != buf)
    ENSURE_OR_GO_CLEANUP(NULL != pBufIndex)
    ENSURE_OR_GO_CLEANUP(NULL != pRsp)

    pBuf = buf + (*pBufIndex);

    if (bufLen < size_of_value) {
        goto cleanup;
    }
    if ((*pBufIndex) > (bufLen - size_of_value)) {
        goto cleanup;
    }
    *pRsp = (*pBuf++);
    *pRsp |= (*pBuf++) << 8;
    *pRsp |= (*pBuf++) << 16;
    *pBufIndex += (1 + 1 + 1);
    retVal = 0;
cleanup:
    return retVal;
}

int get_U32_LSB(uint8_t *buf, size_t *pBufIndex, const size_t bufLen, uint32_t *pRsp)
{
    int retVal                 = 1;
    uint8_t *pBuf              = NULL;
    const size_t size_of_value = 4;

    ENSURE_OR_GO_CLEANUP(NULL != buf)
    ENSURE_OR_GO_CLEANUP(NULL != pBufIndex)
    ENSURE_OR_GO_CLEANUP(NULL != pRsp)

    pBuf = buf + (*pBufIndex);

    if (bufLen < size_of_value) {
        goto cleanup;
    }
    if ((*pBufIndex) > (bufLen - size_of_value)) {
        goto cleanup;
    }
    *pRsp = (*pBuf++);
    *pRsp |= (*pBuf++) << 8;
    *pRsp |= (*pBuf++) << 16;
    *pRsp |= (*pBuf++) << 24;
    *pBufIndex += size_of_value;
    retVal = 0;
cleanup:
    return retVal;
}

int set_U32_LSB(uint8_t **buf, size_t *bufLen, size_t value, size_t max_buf_size)
{
    int retVal               = 1;
    uint8_t *pBuf            = NULL;
    const size_t size_of_tlv = 4;

    ENSURE_OR_GO_CLEANUP(NULL != buf)
    ENSURE_OR_GO_CLEANUP(NULL != *buf)
    ENSURE_OR_GO_CLEANUP(NULL != bufLen)

    pBuf = *buf;
    if ((SIZE_MAX - (*bufLen)) < size_of_tlv) {
        goto cleanup;
    }
    if (((*bufLen) + size_of_tlv) > max_buf_size) {
        goto cleanup;
    }
    *pBuf++ = (uint8_t)((value >> 0 * 8) & 0xFF);
    *pBuf++ = (uint8_t)((value >> 1 * 8) & 0xFF);
    *pBuf++ = (uint8_t)((value >> 2 * 8) & 0xFF);
    *pBuf++ = (uint8_t)((value >> 3 * 8) & 0xFF);
    *buf    = pBuf;
    *bufLen += size_of_tlv;
    retVal = 0;
cleanup:
    return retVal;
}

int tlvSet_U8(uint8_t **buf, size_t *bufLen, NX_TAG_t tag, uint8_t value, size_t max_buf_size)
{
    int retVal               = 1;
    uint8_t *pBuf            = NULL;
    const size_t size_of_tlv = 1 + 1 + 1;

    ENSURE_OR_GO_CLEANUP(NULL != buf)
    ENSURE_OR_GO_CLEANUP(NULL != *buf)
    ENSURE_OR_GO_CLEANUP(NULL != bufLen)

    pBuf = *buf;
    if ((SIZE_MAX - (*bufLen)) < size_of_tlv) {
        goto cleanup;
    }
    if (((*bufLen) + size_of_tlv) > max_buf_size) {
        goto cleanup;
    }
    *pBuf++ = (uint8_t)tag;
    *pBuf++ = 1;
    *pBuf++ = value;
    *buf    = pBuf;
    *bufLen += size_of_tlv;
    retVal = 0;
cleanup:
    return retVal;
}

//          |---------|------------------|-------------------|
// before:          buf, bufLen                             Max
//          |---------|tag---------------|-------------------|
// after:                             buf, bufLen           Max
int tlvSet_u8buf(uint8_t **buf, size_t *bufLen, NX_TAG_t tag, const uint8_t *cmd, size_t cmdLen, size_t max_buf_size)
{
    int retVal    = 1;
    uint8_t *pBuf = NULL;

    /* if < 0x7F
    *    len = 1 byte
    * elif if < 0xFF
    *    '0x81' + len == 2 Bytes
    * elif if < 0xFFFF
    *    '0x82' + len_msb + len_lsb == 3 Bytes
    */
    const size_t size_of_length = (cmdLen <= 0x7f ? 1 : (cmdLen <= 0xFf ? 2 : 3));
    ENSURE_OR_GO_CLEANUP(SIZE_MAX - (1 + size_of_length) >= cmdLen);
    const size_t size_of_tlv = 1 + size_of_length + cmdLen;

    ENSURE_OR_GO_CLEANUP(NULL != buf)
    ENSURE_OR_GO_CLEANUP(NULL != *buf)
    ENSURE_OR_GO_CLEANUP(NULL != bufLen)
    ENSURE_OR_GO_CLEANUP(NULL != cmd)

    pBuf = *buf;
    if ((SIZE_MAX - (*bufLen)) < size_of_tlv) {
        goto cleanup;
    }
    if (((*bufLen) + size_of_tlv) > max_buf_size) {
        LOG_E("Not enough buffer");
        goto cleanup;
    }
    *pBuf++ = (uint8_t)tag;

    if (cmdLen <= 0x7Fu) {
        *pBuf++ = (uint8_t)cmdLen;
    }
    else if (cmdLen <= 0xFFu) {
        *pBuf++ = (uint8_t)(0x80 /* Extended */ | 0x01 /* Additional Length */);
        *pBuf++ = (uint8_t)((cmdLen >> 0 * 8) & 0xFF);
    }
    else if (cmdLen <= 0xFFFFu) {
        *pBuf++ = (uint8_t)(0x80 /* Extended */ | 0x02 /* Additional Length */);
        *pBuf++ = (uint8_t)((cmdLen >> 1 * 8) & 0xFF);
        *pBuf++ = (uint8_t)((cmdLen >> 0 * 8) & 0xFF);
    }
    else {
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

int set_u8buf(uint8_t **buf, size_t *bufLen, const uint8_t *cmd, size_t cmdLen, size_t max_buf_size)
{
    int retVal               = 1;
    uint8_t *pBuf            = NULL;
    const size_t size_of_tlv = cmdLen;

    ENSURE_OR_GO_CLEANUP(NULL != buf)
    ENSURE_OR_GO_CLEANUP(NULL != *buf)
    ENSURE_OR_GO_CLEANUP(NULL != bufLen)
    ENSURE_OR_GO_CLEANUP(NULL != cmd)

    pBuf = *buf;
    if ((SIZE_MAX - (*bufLen)) < size_of_tlv) {
        goto cleanup;
    }

    if (((*bufLen) + size_of_tlv) > max_buf_size) {
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

int get_U8(uint8_t *buf, size_t *pBufIndex, const size_t bufLen, uint8_t *pRsp)
{
    int retVal                 = 1;
    uint8_t *pBuf              = NULL;
    const size_t size_of_value = 1;

    ENSURE_OR_GO_CLEANUP(NULL != buf)
    ENSURE_OR_GO_CLEANUP(NULL != pBufIndex)
    ENSURE_OR_GO_CLEANUP(NULL != pRsp)

    pBuf = buf + (*pBufIndex);

    if (bufLen < size_of_value) {
        goto cleanup;
    }
    if ((*pBufIndex) > (bufLen - size_of_value)) {
        goto cleanup;
    }

    *pRsp = *pBuf++;
    *pBufIndex += (1);
    retVal = 0;
cleanup:
    return retVal;
}

int get_U16_LSB(uint8_t *buf, size_t *pBufIndex, const size_t bufLen, uint16_t *pRsp)
{
    int retVal                 = 1;
    uint8_t *pBuf              = NULL;
    const size_t size_of_value = 2;

    ENSURE_OR_GO_CLEANUP(NULL != buf)
    ENSURE_OR_GO_CLEANUP(NULL != pBufIndex)
    ENSURE_OR_GO_CLEANUP(NULL != pRsp)

    pBuf = buf + (*pBufIndex);

    if (bufLen < size_of_value) {
        goto cleanup;
    }
    if ((*pBufIndex) > (bufLen - size_of_value)) {
        goto cleanup;
    }

    *pRsp = (*pBuf++);
    *pRsp |= (*pBuf++) << 8;
    *pBufIndex += (1 + 1);
    retVal = 0;
cleanup:
    return retVal;
}

//ISO 7816-4 Annex D.
//          |---------|tag------------------|-------------------|
// before: buf       pBufIndex                              bufLen
// after:  buf                           pBufIndex          bufLen
int get_u8buf(uint8_t *buf, size_t *pBufIndex, const size_t bufLen, uint8_t *rsp, size_t rspLen)
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

//          |---------|tag------------------|-------------------|
// before: buf       pBufIndex                              bufLen
// after:  buf                           pBufIndex          bufLen
int tlvGet_U8(uint8_t *buf, size_t *pBufIndex, const size_t bufLen, NX_TAG_t tag, uint8_t *pRsp)
{
    int retVal    = 1;
    uint8_t *pBuf = NULL;

    uint8_t got_tag = 0;
    size_t rspLen   = 0;

    ENSURE_OR_GO_CLEANUP(NULL != buf)
    ENSURE_OR_GO_CLEANUP(NULL != pBufIndex)
    ENSURE_OR_GO_CLEANUP(NULL != pRsp)

    pBuf = buf + (*pBufIndex);
    ENSURE_OR_GO_CLEANUP(UINT8_MAX > (*pBuf));

    if (bufLen < 3) {
        goto cleanup;
    }
    if ((*pBufIndex) > (bufLen - 3)) {
        goto cleanup;
    }

    got_tag = *pBuf++;
    if (got_tag != tag) {
        goto cleanup;
    }
    rspLen = *pBuf++;
    if (rspLen > 1) {
        goto cleanup;
    }
    *pRsp = *pBuf++;
    *pBufIndex += (1 + 1 + (rspLen));
    retVal = 0;
cleanup:
    return retVal;
}

//ISO 7816-4 Annex D.
//          |---------|tag------------------|-------------------|
// before: buf       pBufIndex                              bufLen
// after:  buf                           pBufIndex          bufLen
int tlvGet_u8buf(uint8_t *buf, size_t *pBufIndex, const size_t bufLen, NX_TAG_t tag, uint8_t *rsp, size_t *pRspLen)
{
    int retVal         = 1;
    uint8_t *pBuf      = NULL;
    uint8_t got_tag    = 0;
    size_t extendedLen = 0;
    size_t rspLen      = 0;

    ENSURE_OR_GO_CLEANUP(NULL != buf)
    ENSURE_OR_GO_CLEANUP(NULL != pBufIndex)
    ENSURE_OR_GO_CLEANUP(NULL != rsp)
    ENSURE_OR_GO_CLEANUP(NULL != pRspLen)

    pBuf    = buf + (*pBufIndex);
    got_tag = *pBuf++;

    if ((*pBufIndex) > bufLen) {
        goto cleanup;
    }

    if (got_tag != tag) {
        goto cleanup;
    }
    rspLen = *pBuf++;

    if (rspLen <= 0x7FU) {
        extendedLen = rspLen;
        *pBufIndex += (1 + 1);
    }
    else if (rspLen == 0x81) {
        extendedLen = *pBuf++;
        *pBufIndex += (1 + 1 + 1);
    }
    else if (rspLen == 0x82) {
        extendedLen = *pBuf++;
        extendedLen = (extendedLen << 8) | *pBuf++;
        *pBufIndex += (1 + 1 + 2);
    }
    else {
        goto cleanup;
    }

    if (extendedLen > *pRspLen) {
        goto cleanup;
    }
    if (extendedLen > bufLen) {
        goto cleanup;
    }

    *pRspLen = extendedLen;
    *pBufIndex += extendedLen;
    while (extendedLen-- > 0) {
        *rsp++ = *pBuf++;
    }
    retVal = 0;
cleanup:
    if (retVal != 0) {
        if (pRspLen != NULL) {
            *pRspLen = 0;
        }
    }
    return retVal;
}

//ISO 7816-4 Annex D.
// Similar to tlvGet_u8buf() but only return pointer to value without data copy.
// buf: buffer start pointer
// buflen: buffer length
// pBufIndex: Offset of the buffer to be processed. Pointer to next tag as output.
// tag: Tag to be process.
// rsp: return value field pointer
// pRspLen: value field length
int tlvGet_u8bufPointer(
    uint8_t *buf, size_t *pBufIndex, const size_t bufLen, NX_TAG_t tag, uint8_t **rsp, size_t *pRspLen)
{
    int retVal         = 1;
    uint8_t *pBuf      = NULL;
    uint8_t got_tag    = 0;
    size_t extendedLen = 0;
    size_t rspLen      = 0;

    ENSURE_OR_GO_CLEANUP(NULL != buf)
    ENSURE_OR_GO_CLEANUP(NULL != pBufIndex)
    ENSURE_OR_GO_CLEANUP(NULL != rsp)
    ENSURE_OR_GO_CLEANUP(NULL != pRspLen)

    pBuf    = buf + (*pBufIndex);
    got_tag = *pBuf++;
    if ((*pBufIndex) > bufLen) {
        goto cleanup;
    }

    if (got_tag != tag) {
        goto cleanup;
    }
    rspLen = *pBuf++;

    if (rspLen <= 0x7FU) {
        extendedLen = rspLen;
        *pBufIndex += (1 + 1);
    }
    else if (rspLen == 0x81) {
        extendedLen = *pBuf++;
        *pBufIndex += (1 + 1 + 1);
    }
    else if (rspLen == 0x82) {
        extendedLen = *pBuf++;
        extendedLen = (extendedLen << 8) | *pBuf++;
        *pBufIndex += (1 + 1 + 2);
    }
    else {
        goto cleanup;
    }

    if (extendedLen > bufLen) {
        goto cleanup;
    }

    *pRspLen = extendedLen;
    *pBufIndex += extendedLen;

    *rsp = pBuf;

    retVal = 0;
cleanup:
    if (retVal != 0) {
        if (pRspLen != NULL) {
            *pRspLen = 0;
        }
    }
    return retVal;
}

int tlvGet_ValueIndex(uint8_t *buf, size_t *pBufIndex, const size_t bufLen, NX_TAG_t tag)
{
    int retVal         = 1;
    uint8_t *pBuf      = NULL;
    uint8_t got_tag    = 0;
    size_t extendedLen = 0;
    size_t rspLen      = 0;

    ENSURE_OR_GO_CLEANUP(NULL != buf)
    ENSURE_OR_GO_CLEANUP(NULL != pBufIndex)

    pBuf    = buf + (*pBufIndex);
    got_tag = *pBuf++;
    if ((*pBufIndex) > bufLen) {
        goto cleanup;
    }

    if (got_tag != tag) {
        goto cleanup;
    }
    rspLen = *pBuf++;

    if (rspLen <= 0x7FU) {
        extendedLen = rspLen;
        *pBufIndex += (1 + 1);
    }
    else if (rspLen == 0x81) {
        extendedLen = *pBuf++;
        *pBufIndex += (1 + 1 + 1);
    }
    else if (rspLen == 0x82) {
        extendedLen = *pBuf++;
        extendedLen = (extendedLen << 8) | *pBuf++;
        *pBufIndex += (1 + 1 + 2);
    }
    else {
        goto cleanup;
    }

    if (extendedLen > bufLen) {
        goto cleanup;
    }

    retVal = 0;
cleanup:
    return retVal;
}

smStatus_t DoAPDUTx_s_Case3(SeSession_t *pSessionCtx,
    const tlvHeader_t *hdr,
    uint8_t *cmdHeader,
    size_t cmdHeaderLen,
    uint8_t *cmdData,
    size_t cmdDataLen,
    void *options)
{
    smStatus_t apduStatus                  = SM_NOT_OK;
    uint8_t rxBuf[NX_MAX_BUF_SIZE_RSP + 2] = {0};
    size_t rxBufLen                        = sizeof(rxBuf);

    ENSURE_OR_GO_EXIT(NULL != pSessionCtx)

    if (pSessionCtx->fp_TXn == NULL) {
        apduStatus = SM_NOT_OK;
    }
    else {
        apduStatus = pSessionCtx->fp_TXn(
            pSessionCtx, hdr, cmdHeader, cmdHeaderLen, cmdData, cmdDataLen, rxBuf, &rxBufLen, 0, 0, options);
    }

exit:
    return apduStatus;
}

smStatus_t DoAPDUTxRx_s_Case4(SeSession_t *pSessionCtx,
    const tlvHeader_t *hdr,
    uint8_t *cmdHeader,
    size_t cmdHeaderLen,
    uint8_t *cmdData,
    size_t cmdDataLen,
    uint8_t *rspBuf,
    size_t *pRspBufLen,
    void *options)
{
    smStatus_t apduStatus = SM_NOT_OK;

    ENSURE_OR_GO_EXIT(NULL != pSessionCtx)

    if (pSessionCtx->fp_TXn == NULL) {
        apduStatus = SM_NOT_OK;
    }
    else {
        apduStatus = pSessionCtx->fp_TXn(
            pSessionCtx, hdr, cmdHeader, cmdHeaderLen, cmdData, cmdDataLen, rspBuf, pRspBufLen, 1, 0, options);
    }

exit:
    return apduStatus;
}

smStatus_t DoAPDUTxRx_s_Case4_ext(SeSession_t *pSessionCtx,
    const tlvHeader_t *hdr,
    uint8_t *cmdHeader,
    size_t cmdHeaderLen,
    uint8_t *cmdData,
    size_t cmdDataLen,
    uint8_t *rspBuf,
    size_t *pRspBufLen,
    void *options)
{
    smStatus_t apduStatus = SM_NOT_OK;

    ENSURE_OR_GO_EXIT(NULL != pSessionCtx)

    if (pSessionCtx->fp_TXn == NULL) {
        apduStatus = SM_NOT_OK;
    }
    else {
        apduStatus = pSessionCtx->fp_TXn(
            pSessionCtx, hdr, cmdHeader, cmdHeaderLen, cmdData, cmdDataLen, rspBuf, pRspBufLen, 1, 1, options);
    }

exit:
    return apduStatus;
}

#if SSS_HAVE_SMCOM_JRCP_V1_AM
/*
 *  APDU Structure for sending to access manager:
 *  hdr(4)---LenAPDU(1/3)---cmdHdrLen(2)---cmdHdr(cmdHdrLen)---cmdDataLen(2)--cmdData(cmdDataLen)---hasLeByte(1)---extendedLenByte(1)---hasLe(0-3)
 *
 *  This is required as in plain session, once the APDU is transformed, there is no way of distinguishing
 *  cmdHeader and cmdData. This function sends hdr separately. lenAPDU and hasLe is appended by txn function (called
 *  after transform function call).
 *
 *  txBuf:
 *  cmdHdrLen(2)---cmdHdr(cmdHdrLen)---cmdDataLen(2)--cmdData(cmdDataLen)---hasLeByte(1)---extendedLenByte(1)
**/
smStatus_t nx_Transform_jrcpv1_am(struct SeSession *pSession,
    const tlvHeader_t *hdr,
    uint8_t *cmdHeader,
    const size_t cmdHeaderLen,
    uint8_t *cmdDataBuf,
    const size_t cmdDataBufLen,
    tlvHeader_t *out_hdr,
    uint8_t *txBuf,
    size_t *ptxBufLen,
    uint8_t hasLe,
    uint8_t isExtended,
    void *options)
{
    size_t i             = 0;
    smStatus_t retStatus = SM_NOT_OK;

    LOG_D("FN: %s", __FUNCTION__);

    out_hdr->hdr[0] = hdr->hdr[0];
    out_hdr->hdr[1] = hdr->hdr[1];
    out_hdr->hdr[2] = hdr->hdr[2];
    out_hdr->hdr[3] = hdr->hdr[3];

    //cmdApduBufLen = 2 + cmdHeaderLen + 2 + cmdDataBufLen;
    ENSURE_OR_GO_EXIT(NULL != hdr)
    ENSURE_OR_GO_EXIT(NULL != out_hdr)
    ENSURE_OR_GO_EXIT(NULL != txBuf)
    ENSURE_OR_GO_EXIT(NULL != ptxBufLen)
    ENSURE_OR_GO_EXIT(*ptxBufLen >= 2                   // 2 bytes of cmdHeader length
                                        + cmdHeaderLen  // cmdHeader
                                        + 2             // 2 bytes of cmdData length
                                        + cmdDataBufLen // cmdDataBuf
                                        + 2             // 1 byte hasLe + 1 byte isExtended
    )

    // Copy cmdHeader
    if (cmdHeader == NULL || cmdHeaderLen == 0) {
        txBuf[i++] = 0;
        txBuf[i++] = 0;
    }
    else {
        txBuf[i++] = (uint8_t)((cmdHeaderLen >> 8) & 0x00FF);
        txBuf[i++] = (uint8_t)(cmdHeaderLen & 0x00FF);
        memcpy(&txBuf[i], cmdHeader, cmdHeaderLen);
        i += cmdHeaderLen;
    }

    // Copy cmdDataBuf
    if (cmdDataBuf == NULL || cmdDataBufLen == 0) {
        txBuf[i++] = 0;
        txBuf[i++] = 0;
    }
    else {
        txBuf[i++] = (uint8_t)((cmdDataBufLen >> 8) & 0x00FF);
        txBuf[i++] = (uint8_t)(cmdDataBufLen & 0x00FF);
        memcpy(&txBuf[i], cmdDataBuf, cmdDataBufLen);
        i += cmdDataBufLen;
    }

    // Copy hasLe and isExtended
    txBuf[i++] = hasLe;
    txBuf[i++] = isExtended;

    *ptxBufLen = i;
    retStatus  = SM_OK;

    LOG_AU8_D(out_hdr->hdr, sizeof(tlvHeader_t));
    LOG_AU8_D(cmdHeader, cmdHeaderLen);
    LOG_AU8_D(cmdDataBuf, cmdDataBufLen);
    LOG_D("hasLe: %d", hasLe);
    LOG_D("isExtended: %d", isExtended);

exit:
    return retStatus;
}
#endif
smStatus_t nx_Transform(struct SeSession *pSession,
    const tlvHeader_t *hdr,
    uint8_t *cmdHeader,
    const size_t cmdHeaderLen,
    uint8_t *cmdDataBuf,
    const size_t cmdDataBufLen,
    tlvHeader_t *out_hdr,
    uint8_t *txBuf,
    size_t *ptxBufLen,
    uint8_t hasLe,
    uint8_t isExtended,
    void *options)
{
    size_t i             = 0;
    smStatus_t retStatus = SM_NOT_OK;
    //size_t cmdApduBufLen = 0;

    out_hdr->hdr[0] = hdr->hdr[0];
    out_hdr->hdr[1] = hdr->hdr[1];
    out_hdr->hdr[2] = hdr->hdr[2];
    out_hdr->hdr[3] = hdr->hdr[3];

    //cmdApduBufLen = cmdHeaderLen + cmdDataBufLen;
    ENSURE_OR_GO_EXIT(NULL != hdr)
    ENSURE_OR_GO_EXIT(NULL != out_hdr)
    ENSURE_OR_GO_EXIT(NULL != txBuf)
    ENSURE_OR_GO_EXIT(NULL != ptxBufLen)
    ENSURE_OR_GO_EXIT((SIZE_MAX - cmdHeaderLen) > cmdDataBufLen)
    ENSURE_OR_GO_EXIT(cmdHeaderLen + cmdDataBufLen <= NX_MAX_BUF_SIZE_CMD)

    if (cmdHeaderLen > 0) {
        ENSURE_OR_GO_EXIT(NULL != cmdHeader)
        memcpy(&txBuf[i], cmdHeader, cmdHeaderLen);
        i += cmdHeaderLen;
    }

    if (cmdDataBufLen > 0) {
        ENSURE_OR_GO_EXIT(NULL != cmdDataBuf)
        ENSURE_OR_GO_EXIT(i <= NX_MAX_BUF_SIZE_CMD)
        memcpy(&txBuf[i], cmdDataBuf, cmdDataBufLen);
        i += cmdDataBufLen;
    }

    *ptxBufLen = i;
    retStatus  = SM_OK;

exit:
    return retStatus;
}

#if SSS_HAVE_NX_TYPE
/**
 * @brief         Decode AES-256 CCM secure channel R-APDU.
 *
 *                WRAP R-APDU
 *                <encrpted ISO APDU Response> <WRAP APDU SW>
 *                ISO APDU Response
 *                <RespData> 91 YY
 *                1. GEt <encrpted ISO APDU Response>
 *                2. Decrypt <encrpted ISO APDU Response>
 *
 * @param         pSessionCtx           SE session
 * @param         cmd_cmacLen           Unused.
 * @param[out]    rsp                   Decrypted ISO APDU R-APDU.
 * @param[out]    rspLength             Decrypted ISO APDU R-APDU length.
 * @param         hasLe                 Unused.
 *
 * @return        Status.
 */
smStatus_t nx_DeCrypt(struct SeSession *pSessionCtx,
    size_t cmd_cmacLen,
    uint8_t cmd,
    uint8_t *rsp,
    size_t *rspLength,
    uint8_t hasLe,
    void *options)
{
    U16 rv = SM_NOT_OK;
#if SSS_HAVE_AUTH_SIGMA_I_VERIFIER || SSS_HAVE_AUTH_SIGMA_I_PROVER || SSS_HAVE_AUTH_SYMM_AUTH || \
    SSS_HAVE_ALL_AUTH_CODE_ENABLED
    size_t decRspLen = 0;
#endif

    ENSURE_OR_GO_EXIT(NULL != pSessionCtx)
    ENSURE_OR_GO_EXIT(NULL != rsp)
    ENSURE_OR_GO_EXIT(NULL != rspLength)

    LOG_D("FN: %s", __FUNCTION__);
    LOG_MAU8_D(" Input:rspBuf", rsp, *rspLength);

    if (*rspLength >= 2) {
        if ((rsp[(*rspLength) - 2] << 8 | rsp[(*rspLength) - 1]) > UINT16_MAX) {
            goto exit;
        }
        rv = rsp[(*rspLength) - 2] << 8 | rsp[(*rspLength) - 1];

        if ((rv == SM_OK || rv == SM_OK_ALT) &&
            ((pSessionCtx->authType == knx_AuthType_SIGMA_I_Verifier) ||
                (pSessionCtx->authType == knx_AuthType_SIGMA_I_Prover)) &&
            (pSessionCtx->ctx.pdynSigICtx != NULL)) {
#if SSS_HAVE_AUTH_SIGMA_I_VERIFIER || SSS_HAVE_AUTH_SIGMA_I_PROVER || SSS_HAVE_ALL_AUTH_CODE_ENABLED
            if ((pSessionCtx->ctx.pdynSigICtx->selectedSecureTunnelType == knx_SecureSymmType_AES128_NTAG) ||
                (pSessionCtx->ctx.pdynSigICtx->selectedSecureTunnelType == knx_SecureSymmType_AES256_NTAG)) {
                decRspLen = *rspLength;
                rv        = nx_Decrypt_AES_EV2_ResponseAPDU(pSessionCtx, cmd, rsp, &decRspLen, options);
            }
            else {
                LOG_E("FN: %s. Unknown secure tunneling type", __FUNCTION__);
            }
            *rspLength = decRspLen;
#else
            LOG_E("Wrong Authenication option selected. Rebuild the library with correct AUTH option");
            return SM_NOT_OK;
#endif
        }
        else if ((rv == SM_OK || rv == SM_OK_ALT) && (pSessionCtx->authType == knx_AuthType_SYMM_AUTH) &&
                 (pSessionCtx->ctx.pdynSymmAuthCtx != NULL)) {
#if SSS_HAVE_AUTH_SYMM_AUTH || SSS_HAVE_ALL_AUTH_CODE_ENABLED
            if ((cmd == NX_INS_CHANGE_KEY) && (*rspLength == 2)) {
                rv = SM_OK;
                goto exit;
            }
            decRspLen = *rspLength;
            rv        = nx_Decrypt_AES_EV2_ResponseAPDU(pSessionCtx, cmd, rsp, &decRspLen, options);

            *rspLength = decRspLen;
#else
            LOG_E("Wrong Authenication option selected. Rebuild the library with correct AUTH option");
            return SM_NOT_OK;
#endif
        }
        else {
            goto exit;
        }
    }

exit:
    return rv;
}

#if ((defined(SSS_HAVE_HOSTCRYPTO_ANY) && (SSS_HAVE_HOSTCRYPTO_ANY)) &&                \
     ((defined(SSS_HAVE_AUTH_SIGMA_I_VERIFIER) && (SSS_HAVE_AUTH_SIGMA_I_VERIFIER)) || \
         (defined(SSS_HAVE_AUTH_SIGMA_I_PROVER) && (SSS_HAVE_AUTH_SIGMA_I_PROVER)) ||  \
         (defined(SSS_HAVE_AUTH_SYMM_AUTH) && (SSS_HAVE_AUTH_SYMM_AUTH)) ||            \
         (defined(SSS_HAVE_ALL_AUTH_CODE_ENABLED) && (SSS_HAVE_ALL_AUTH_CODE_ENABLED))))

smStatus_t nx_Transform_AES_EV2(struct SeSession *pSession,
    const tlvHeader_t *hdr,
    uint8_t *cmdHeader,
    const size_t cmdHeaderLen,
    uint8_t *cmdData,
    const size_t cmdDataLen,
    tlvHeader_t *outhdr,
    uint8_t *txBuf,
    size_t *ptxBufLen,
    uint8_t hasLe,
    uint8_t isExtended,
    void *options)
{
    smStatus_t apduStatus                   = SM_NOT_OK;
    uint32_t status                         = SCP_FAIL;
    sss_status_t sss_status                 = kStatus_SSS_Fail;
    uint8_t encCmdData[NX_MAX_BUF_SIZE_CMD] = {0};
    size_t encCmdDataLen                    = sizeof(encCmdData);

    uint8_t cmdByte                 = 0;
    nx_ev2_comm_mode_t CommMode     = 0xFF; //TODO init value for CommMode
    uint8_t *pMacData               = NULL;
    size_t macDataLen               = 0;
    nx_ev2_comm_mode_t *preCommMode = (nx_ev2_comm_mode_t *)options; // Pre-configured CommMode.

    ENSURE_OR_GO_CLEANUP(NULL != pSession)
    ENSURE_OR_GO_CLEANUP((NULL != pSession->ctx.pdynSigICtx) || (NULL != pSession->ctx.pdynSymmAuthCtx))
    ENSURE_OR_GO_CLEANUP(NULL != hdr)

    memcpy(outhdr, hdr, sizeof(*hdr));

    cmdByte = (uint8_t)hdr->hdr[1];

    nx_AES_EV2_CommandAPDU_log(cmdByte, cmdHeader, cmdHeaderLen, cmdData, cmdDataLen);

    if (preCommMode == NULL) {
        status = nx_get_command_commMode(cmdByte, &CommMode);
        ENSURE_OR_GO_CLEANUP(status == SCP_OK);
    }
    else {
        CommMode = *preCommMode;
    }

    pMacData   = cmdData;
    macDataLen = cmdDataLen;

    if ((CommMode == EV2_CommMode_FULL) && (cmdDataLen > 0)) {
        sss_status = nx_AES_EV2_Encrypt_CommandAPDU(pSession, cmdData, cmdDataLen, encCmdData, &encCmdDataLen);
        ENSURE_OR_GO_CLEANUP(sss_status == kStatus_SSS_Success);

        pMacData   = encCmdData;
        macDataLen = encCmdDataLen;
    }

    if (CommMode == EV2_CommMode_FULL || CommMode == EV2_CommMode_MAC) {
        sss_status = nx_AES_EV2_MAC_CommandAPDU(
            pSession, cmdByte, cmdHeader, cmdHeaderLen, pMacData, macDataLen, txBuf, ptxBufLen);
        ENSURE_OR_GO_CLEANUP(sss_status == kStatus_SSS_Success);
        // additinal frame not required to increment command counter
        if (cmdByte != NX_INS_ADDITIONAL_FRAME_REQ) {
            if (pSession->authType == knx_AuthType_SIGMA_I_Verifier ||
                pSession->authType == knx_AuthType_SIGMA_I_Prover) {
                ENSURE_OR_GO_CLEANUP(NULL != pSession->ctx.pdynSigICtx);
                LOG_D("Command counter = 0x%02x", pSession->ctx.pdynSigICtx->CmdCtr);
                pSession->ctx.pdynSigICtx->CmdCtr += 1; //command counter incremented after mac authentication
            }
            else if (pSession->authType == knx_AuthType_SYMM_AUTH) {
                ENSURE_OR_GO_CLEANUP(NULL != pSession->ctx.pdynSymmAuthCtx);
                LOG_D("Command counter = 0x%02x", pSession->ctx.pdynSymmAuthCtx->CmdCtr);
                pSession->ctx.pdynSymmAuthCtx->CmdCtr += 1; //command counter incremented after mac authentication
            }
        }
    }

    if (CommMode == EV2_CommMode_PLAIN) {
        sss_status =
            nx_AES_EV2_Plain_CommandAPDU(pSession, cmdHeader, cmdHeaderLen, cmdData, cmdDataLen, txBuf, ptxBufLen);
        ENSURE_OR_GO_CLEANUP(sss_status == kStatus_SSS_Success);
        // additinal frame not required to increment command counter
        if (cmdByte != NX_INS_ADDITIONAL_FRAME_REQ) {
            if (pSession->authType == knx_AuthType_SIGMA_I_Verifier ||
                pSession->authType == knx_AuthType_SIGMA_I_Prover) {
                ENSURE_OR_GO_CLEANUP(NULL != pSession->ctx.pdynSigICtx);
                LOG_D("Command counter = 0x%02x", pSession->ctx.pdynSigICtx->CmdCtr);
                pSession->ctx.pdynSigICtx->CmdCtr += 1; //command counter incremented
            }
            else if (pSession->authType == knx_AuthType_SYMM_AUTH) {
                ENSURE_OR_GO_CLEANUP(NULL != pSession->ctx.pdynSymmAuthCtx);
                LOG_D("Command counter = 0x%02x", pSession->ctx.pdynSymmAuthCtx->CmdCtr);
                pSession->ctx.pdynSymmAuthCtx->CmdCtr += 1; //command counter incremented
            }
        }
    }
    apduStatus = SM_OK;

cleanup:
    return apduStatus;
}
#endif //SSS_HAVE_HOSTCRYPTO_ANY && (either of one authentication)

#endif // SSS_HAVE_NX_TYPE
