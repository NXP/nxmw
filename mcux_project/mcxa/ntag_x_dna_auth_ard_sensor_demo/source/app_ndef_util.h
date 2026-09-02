/*
 * Copyright 2025 NXP
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <limits.h>
#include <fsl_sss_types.h>


#ifndef NX_NDEF_UTIL_H_
#define NX_NDEF_UTIL_H_



#define APP_NDEF_UTIL_TOKEN_PARSE_FAILED -1


/**
 * @brief Searches an NDEF payload buffer for a specific variable-length pattern.
 *
 * This function scans a byte buffer for a sequence of bytes derived from the
 * supplied C-string pattern. The entire pattern string (excluding the null
 * terminator) is used for matching.
 *
 * If the sequence is found, the function returns the starting index within
 * the buffer.
 *
 * @param[in] buf       Pointer to the input byte buffer to be searched. Must not be NULL.
 * @param[in] buf_len   Length of the buffer in bytes.
 * @param[in] pattern   Null-terminated C-string pattern to search for. Must not be NULL.
 *
 * @return int32_t
 *         - >= 0 : Index of the first occurrence of the pattern.
 *         -   -1 : Pattern not found or invalid input parameters.
 *
 * @note Performs a simple linear search. No wildcard or case-insensitive matching.
 */
int32_t getNdefDataOffset(const uint8_t* buf, size_t buf_len, const char* pattern);




#endif /* NX_NDEF_UTIL_H_ */
