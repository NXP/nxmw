/*
 * Copyright 2025 NXP
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/* ************************************************************************** */
/* Includes                                                                   */
/* ************************************************************************** */
#include "app_ndef_util.h"

/* ************************************************************************** */
/* Public Functions                                                           */
/* ************************************************************************** */

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
int32_t getNdefDataOffset(const uint8_t *buf,
    size_t buf_len,
    const char *pattern)
{
    size_t pattern_len;
    size_t last;

    /* Validate input parameters */
    if ((buf == NULL) || (pattern == NULL))
    {
        return APP_NDEF_UTIL_TOKEN_PARSE_FAILED;
    }

    /* Get pattern length */
    pattern_len = strlen(pattern);

    /* Reject empty pattern */
    if (pattern_len == 0U)
    {
        return APP_NDEF_UTIL_TOKEN_PARSE_FAILED;
    }

    /* Check if buffer is large enough to contain the pattern */
    if (buf_len < pattern_len)
    {
        return APP_NDEF_UTIL_TOKEN_PARSE_FAILED;
    }

    /* Ensure buffer length does not exceed the int32_t return value range */
    if (buf_len > (size_t)INT32_MAX)
    {
        return APP_NDEF_UTIL_TOKEN_PARSE_FAILED;
    }

    /* Calculate the last valid starting position for pattern matching */
    last = buf_len - pattern_len;

    /* Linear search: scan buffer for pattern match */
    for (size_t i = 0U; i <= last; i++)
    {
        size_t j;

        /* Compare pattern byte by byte at current position */
        for (j = 0U; j < pattern_len; j++)
        {
            if (buf[i + j] != (uint8_t)(unsigned char)pattern[j])
            {
                break; /* Mismatch: try next starting position */
            }
        }

        /* Full pattern matched at position i */
        if (j == pattern_len)
        {
            return (int32_t)i;
        }
    }

    /* Pattern not found in buffer */
    return APP_NDEF_UTIL_TOKEN_PARSE_FAILED;
}
