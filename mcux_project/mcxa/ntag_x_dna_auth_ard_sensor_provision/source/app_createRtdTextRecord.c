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
 * @brief Creates an NFC Forum RTD Text NDEF Record.
 *
 * Encodes a text string into an NDEF RTD-Text record and writes it into the
 * provided output buffer. Short Record (SR) mode is automatically selected
 * for payloads smaller than 256 bytes.
 *
 * @param[in]  msg_begin        Set to 1 if this is the first record (MB bit).
 * @param[in]  msg_end          Set to 1 if this is the last record (ME bit).
 * @param[in]  text             Null-terminated text string to encode.
 * @param[in]  encoding         Text encoding: TEXT_UTF8 or TEXT_UTF16BE.
 * @param[in]  languageCode     Null-terminated IANA language code (e.g. "en", "de").
 * @param[out] outBuffer        Buffer to write the encoded NDEF record into.
 * @param[in]  outBufferOffset  Start offset within outBuffer.
 * @param[in]  outBufferSize    Total size of outBuffer.
 *
 * @return Number of bytes written, or -1 on error.
 */
int16_t createRtdTextRecord(
    uint8_t msg_begin,
    uint8_t msg_end,
    const char *text,
    TextEncoding_t encoding,
    const char *languageCode,
    uint8_t *outBuffer,
    uint32_t outBufferOffset,
    size_t outBufferSize)
{
    int16_t idx = 0;

    /* Validate input parameters */
    if ((text == NULL) || (languageCode == NULL) || (outBuffer == NULL))
    {
        LOG_E("createRtdTextRecord: Invalid input parameter");
        idx = -1;
        goto exit;
    }

    uint8_t  languageCodeLen = (uint8_t)strlen(languageCode);
    uint32_t textLen         = (uint32_t)strlen(text);

    /*
     * Payload structure:
     *   1 byte  - Status byte (encoding + language code length)
     *   n bytes - Language code
     *   m bytes - Text string
     */
    uint32_t payloadLen = 1u + (uint32_t)languageCodeLen + textLen;

    /* Determine if Short Record (SR) bit must be set (payload < 256 bytes) */
    uint8_t useShortRecord = (payloadLen < 256u) ? 1u : 0u;

    /*
     * Calculate required output buffer size:
     *   1 byte  - NDEF header
     *   1 byte  - Type Length
     *   1 or 4  - Payload Length (SR or normal)
     *   1 byte  - Type field ('T')
     *   n bytes - Payload (status byte + language code + text)
     */
    uint32_t requiredSize = 1u + 1u + (useShortRecord ? 1u : 4u) + 1u + payloadLen;

    /* Verify the record fits within the available buffer space after offset */
    if ((outBufferOffset + requiredSize) > (uint32_t)outBufferSize)
    {
        LOG_E("createRtdTextRecord: Output buffer too small (required=%u, available=%u)",
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
    header |= (msg_begin      ? (1u << 7u) : 0u); /* MB flag */
    header |= (msg_end        ? (1u << 6u) : 0u); /* ME flag */
    header |= (useShortRecord ? (1u << 4u) : 0u); /* SR flag */
    header |= TNF_WELL_KNOWN;                      /* TNF = 0x01 */

    outBuffer[outBufferOffset + (uint32_t)idx] = header;
    idx++;

    /* Type Length: always 1 byte for RTD-Text ('T') */
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

    /* Type field: 'T' for RTD-Text */
    outBuffer[outBufferOffset + (uint32_t)idx] = RTD_TEXT;
    idx++;

    /*
     * Payload status byte:
     *   Bit 7:   Encoding flag (0 = UTF-8, 1 = UTF-16BE)
     *   Bit 6:   RFU, must be zero
     *   Bit 5-0: Language code length (IANA code, max 63 bytes)
     */
    uint8_t payloadStatusByte = languageCodeLen & 0x3Fu;
    if (encoding == TEXT_UTF16BE)
    {
        payloadStatusByte |= 0x80u; /* Set UTF-16BE flag */
    }
    outBuffer[outBufferOffset + (uint32_t)idx] = payloadStatusByte;
    idx++;

    /* Language code */
    memcpy(&outBuffer[outBufferOffset + (uint32_t)idx], languageCode, languageCodeLen);
    idx += (int16_t)languageCodeLen;

    /* Text payload */
    memcpy(&outBuffer[outBufferOffset + (uint32_t)idx], text, textLen);
    idx += (int16_t)textLen;

exit:
    return idx; /* Number of bytes written, or -1 on error */
}
