/*
 * Copyright 2025 NXP
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/* ************************************************************************** */
/* Includes                                                                   */
/* ************************************************************************** */
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <limits.h>
#include <fsl_sss_types.h>
#include <nxLog_msg.h>

#ifndef NX_CREATERTDURIRECORD_H_
#define NX_CREATERTDURIRECORD_H_

/* ************************************************************************** */
/* Defines                                                                    */
/* ************************************************************************** */

/** RTD Type field value for URI record */
#define RTD_URI  'U'

/** RTD Type field value for Text record */
#define RTD_TEXT 'T'

/** NDEF Message Begin flag: set on first record in message */
#define NDEF_MB_TRUE  1
#define NDEF_MB_FALSE 0

/** NDEF Message End flag: set on last record in message */
#define NDEF_ME_TRUE  1
#define NDEF_ME_FALSE 0

/* ************************************************************************** */
/* Enumerations                                                               */
/* ************************************************************************** */

/**
 * @brief NDEF Type Name Format (TNF) values.
 *
 * Defines the structure of the record type field as per NFC Forum
 * NDEF specification.
 */
typedef enum _TNF_t
{
	TNF_EMPTY        = 0x00, /**< Empty record                          */
	TNF_WELL_KNOWN   = 0x01, /**< NFC Forum Well Known Type             */
	TNF_MIME_MEDIA   = 0x02, /**< MIME Media Type (RFC 2046)            */
	TNF_ABSOLUTE_URI = 0x03, /**< Absolute URI (RFC 3986)               */
	TNF_EXTERNAL_TYPE= 0x04, /**< NFC Forum External Type               */
	TNF_UNKNOWN      = 0x05, /**< Unknown type                          */
	TNF_UNCHANGED    = 0x06, /**< Unchanged (used in chunked records)   */
	TNF_RESERVED     = 0x07  /**< Reserved                              */
} TNF_t;

/**
 * @brief URI Identifier Codes as defined by NFC Forum RTD-URI specification.
 *
 * These codes represent common URI prefix strings that are abbreviated
 * in the NDEF payload to save space.
 */
typedef enum _UriIdentifier_t
{
	URI_ID_HTTP_WWW  = 0x01, /**< Abbreviation for "http://www."  */
	URI_ID_HTTPS_WWW = 0x02, /**< Abbreviation for "https://www." */
	URI_ID_HTTP      = 0x03, /**< Abbreviation for "http://"      */
	URI_ID_HTTPS     = 0x04  /**< Abbreviation for "https://"     */
} UriIdentifier_t;

/**
 * @brief Text encoding options for RTD Text records.
 */
typedef enum
{
	TEXT_UTF8   = 0, /**< UTF-8 encoding (bit 7 = 0)              */
	TEXT_UTF16BE = 1 /**< UTF-16 Big Endian encoding (bit 7 = 1)  */
} TextEncoding_t;

/* ************************************************************************** */
/* Function Prototypes                                                        */
/* ************************************************************************** */

/**
 * @brief Creates an NFC Forum Well-Known Type (RTD-URI) NDEF Record.
 *
 * This function encodes a URI string into an NDEF RTD-URI record and writes it
 * into the provided output buffer. It automatically selects Short Record (SR)
 * mode for payloads smaller than 256 bytes and uses a 4-byte payload length
 * field for larger records, as required by the NFC Forum NDEF specification.
 *
 * The generated record has the structure:
 *   - NDEF Record Header (MB, ME, SR, TNF)
 *   - Type Length (always 1 for RTD-URI)
 *   - Payload Length (1 byte if SR=1, otherwise 4 bytes)
 *   - Type Field ('U')
 *   - Payload:
 *        [0]    URI Identifier Code (prefix abbreviation)
 *        [1..n] URI string bytes
 *
 * @param[in]  msg_begin        Set to 1 if this record is the first in the NDEF
 *                              message (MB bit). Set to 0 otherwise.
 * @param[in]  msg_end          Set to 1 if this record is the last in the NDEF
 *                              message (ME bit). Set to 0 otherwise.
 * @param[in]  url              Null-terminated URI string (must NOT include the
 *                              prefix specified by uriId).
 * @param[in]  uriId            URI Identifier Code (e.g. URI_ID_HTTPS = "https://").
 * @param[out] outBuffer        Buffer into which the encoded NDEF record is written.
 * @param[in]  outBufferOffset  Start offset within outBuffer.
 * @param[in]  outBufferSize    Total size of outBuffer in bytes.
 *
 * @return int32_t
 *         - >= 0 : Number of bytes written to the output buffer.
 *         -   -1 : Invalid input or output buffer too small.
 *
 * @note The caller is responsible for constructing a full NDEF message by
 *       chaining multiple records. URI payload must be ASCII/UTF-8 encoded.
 */
int32_t createRtdUriRecord(
	uint8_t msg_begin,
	uint8_t msg_end,
	const char *url,
	UriIdentifier_t uriId,
	uint8_t *outBuffer,
	uint32_t outBufferOffset,
	size_t outBufferSize);

/**
 * @brief Creates an NFC Forum RTD Text NDEF Record.
 *
 * This function builds a Well-Known Type "T" (Text) NDEF record and writes
 * it into the provided buffer. It correctly formats the NDEF header, type
 * field, and payload according to the NFC Forum Text Record Type Definition.
 *
 * Short Record (SR) mode is automatically selected when payload length < 256
 * bytes. For larger payloads, SR is cleared and the payload length is encoded
 * as a 4-byte big-endian integer.
 *
 * @param[in]  msg_begin        Set to 1 if this is the first record (MB flag).
 * @param[in]  msg_end          Set to 1 if this is the last record (ME flag).
 * @param[in]  text             Pointer to the text payload (null-terminated UTF-8,
 *                              or raw UTF-16BE bytes).
 * @param[in]  encoding         Text encoding: TEXT_UTF8 or TEXT_UTF16BE.
 * @param[in]  languageCode     Null-terminated IANA language code (e.g. "en", "de").
 * @param[out] outBuffer        Buffer into which the generated NDEF record is written.
 * @param[in]  outBufferOffset  Starting offset inside outBuffer.
 * @param[in]  outBufferSize    Number of bytes available in outBuffer.
 *
 * @return int16_t
 *         - >= 0 : Number of bytes written to the output buffer.
 *         -   -1 : Invalid input or output buffer too small.
 *
 * @note The language code must be ASCII and is limited to 6 bits (0-63 bytes).
 *       UTF-16 text must already be encoded in BE format by the caller.
 */
int16_t createRtdTextRecord(
	uint8_t msg_begin,
	uint8_t msg_end,
	const char *text,
	TextEncoding_t encoding,
	const char *languageCode,
	uint8_t *outBuffer,
	uint32_t outBufferOffset,
	size_t outBufferSize);

#endif /* NX_CREATERTDURIRECORD_H_ */
