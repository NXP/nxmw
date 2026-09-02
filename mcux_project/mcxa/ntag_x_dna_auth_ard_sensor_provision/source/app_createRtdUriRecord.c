/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/* ************************************************************************** */
/* Includes                                                                   */
/* ************************************************************************** */
#include "app_ndef_record.h"

/* ************************************************************************** */
/* Public Functions                                                           */
/* ************************************************************************** */

/**
 * @brief Creates an NFC Forum Well-Known Type (RTD-URI) NDEF Record.
 *
 * Encodes a URI string into an NDEF RTD-URI record and writes it into the
 * provided output buffer. Short Record (SR) mode is automatically selected
 * for payloads smaller than 256 bytes.
 *
 * @param[in]  msg_begin        Set to 1 if this is the first record (MB bit).
 * @param[in]  msg_end          Set to 1 if this is the last record (ME bit).
 * @param[in]  url              Null-terminated URI string (without prefix).
 * @param[in]  uriId            URI Identifier Code (e.g. URI_ID_HTTPS).
 * @param[out] outBuffer        Buffer to write the encoded NDEF record into.
 * @param[in]  outBufferOffset  Start offset within outBuffer.
 * @param[in]  outBufferSize    Total size of outBuffer.
 *
 * @return Number of bytes written, or -1 on error.
 */
int32_t createRtdUriRecord(
    uint8_t msg_begin,
    uint8_t msg_end,
    const char *url,
    UriIdentifier_t uriId,
    uint8_t *outBuffer,
    uint32_t outBufferOffset,
    size_t outBufferSize)
{
    int32_t idx = 0;

    /* Validate input parameters */
    if ((url == NULL) || (outBuffer == NULL))
    {
        LOG_E("createRtdUriRecord: Invalid input parameter");
        idx = -1;
        goto exit;
    }

    uint32_t urlLen     = (uint32_t)strlen(url);
    uint32_t payloadLen = 1u + urlLen; /* 1 byte URI Identifier Code + URI string */

    /* Determine if Short Record (SR) bit must be set (payload < 256 bytes) */
    uint8_t useShortRecord = (payloadLen < 256u) ? 1u : 0u;

    /*
     * Calculate required output buffer size:
     *   1 byte  - NDEF header
     *   1 byte  - Type Length
     *   1 or 4  - Payload Length (SR or normal)
     *   1 byte  - Type field ('U')
     *   n bytes - Payload (URI ID + URI string)
     */
    uint32_t requiredSize = 1u + 1u + (useShortRecord ? 1u : 4u) + 1u + payloadLen;

    /* Verify the record fits within the available buffer space after offset */
    if ((outBufferOffset + requiredSize) > (uint32_t)outBufferSize)
    {
        LOG_E("createRtdUriRecord: Output buffer too small (required=%u, available=%u)",
              requiredSize, (uint32_t)outBufferSize - outBufferOffset);
        idx = -1;
        goto exit;
    }

    /*
     * Build NDEF Record Header byte:
     *   Bit 7: MB  - Message Begin
     *   Bit 6: ME  - Message End
     *   Bit 5: CF  - Chunk Flag (always 0)
     *   Bit 4: SR  - Short Record
     *   Bit 3: IL  - ID Length present (always 0)
     *   Bit 2-0: TNF - Type Name Format
     */
    uint8_t header = 0u;
    header |= (msg_begin ? (1u << 7u) : 0u); /* MB flag */
    header |= (msg_end   ? (1u << 6u) : 0u); /* ME flag */
    header |= (useShortRecord ? (1u << 4u) : 0u); /* SR flag */
    header |= TNF_WELL_KNOWN; /* TNF = 0x01 */

    outBuffer[outBufferOffset + (uint32_t)idx] = header;
    idx++;

    /* Type Length: always 1 byte for RTD-URI ('U') */
    outBuffer[outBufferOffset + (uint32_t)idx] = 0x01u;
    idx++;

    /* Payload Length field */
    if (useShortRecord)
    {
        /* SR=1: single byte payload length */
        outBuffer[outBufferOffset + (uint32_t)idx] = (uint8_t)payloadLen;
        idx++;
    }
    else
    {
        /* SR=0: 4-byte big-endian payload length */
        outBuffer[outBufferOffset + (uint32_t)idx] = (uint8_t)((payloadLen >> 24u) & 0xFFu);
        idx++;
        outBuffer[outBufferOffset + (uint32_t)idx] = (uint8_t)((payloadLen >> 16u) & 0xFFu);
        idx++;
        outBuffer[outBufferOffset + (uint32_t)idx] = (uint8_t)((payloadLen >> 8u) & 0xFFu);
        idx++;
        outBuffer[outBufferOffset + (uint32_t)idx] = (uint8_t)((payloadLen >> 0u) & 0xFFu);
        idx++;
    }

    /* Type field: 'U' for RTD-URI */
    outBuffer[outBufferOffset + (uint32_t)idx] = RTD_URI;
    idx++;

    /* Payload: URI Identifier Code followed by URI string bytes */
    outBuffer[outBufferOffset + (uint32_t)idx] = (uint8_t)uriId;
    idx++;
    memcpy(&outBuffer[outBufferOffset + (uint32_t)idx], url, urlLen);
    idx += (int32_t)urlLen;

exit:
    return idx; /* Number of bytes written, or -1 on error */
}
