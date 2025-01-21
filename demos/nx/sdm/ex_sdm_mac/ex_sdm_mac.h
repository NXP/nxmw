/* Copyright 2024 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __EX_SDM_MAC_H__
#define __EX_SDM_MAC_H__

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>

#include "ex_sdm_common.h"

#define EX_SSS_SDM_PICCDATA_LENGTH 0x20

#define EX_SSS_SDM_ENCRYPTED_ASCII_PLACEHOLDER_MAX_LEN 128
/* clang-format off */
#define EX_SSS_SDM_PICCDATA_IV_VALUE                                                                   \
    {                                                                                                  \
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 \
    }

#define EX_SSS_SDM_TAG_OFFSET_IN_PICCDATA 0x0
#define EX_SSS_SDM_PICCDATA_TAG_VCUID_LENGTH_MASK 0x0F
#define EX_SSS_SDM_PICCDATA_TAG_SDMREACTR_MASK 0x40
#define EX_SSS_SDM_PICCDATA_TAG_VCUID_MASK 0x80
#define EX_SSS_SDM_PICCDATA_TAG_VCUID_ENABLE (1 << 7)
#define EX_SSS_SDM_PICCDATA_TAG_SDMREACTR_ENABLE (1 << 6)
#define EX_SSS_SDM_VCUID_OFFSET_IN_PICCDATA 0x1
#define EX_SSS_SDM_10BYTE_VCUID_LENGTH_IN_PICCDATA 0x0A
#define EX_SSS_SDM_7BYTE_VCUID_LENGTH_IN_PICCDATA 0x07
#define EX_SSS_SDM_VCUID_MAX_LENGTH_IN_PICCDATA 0x0A
#define EX_SSS_SDM_SDMREADCTR_OFFSET_IN_PICCDATA_10BYTE_UID 0x0B
#define EX_SSS_SDM_SDMREADCTR_OFFSET_IN_PICCDATA_7BYTE_UID 0x08
#define EX_SSS_SDM_IV_DATA_LENGTH 0x10
#define EX_SSS_SDM_SV_CONSTANT_BYTES_LEN 0x06
#define EX_SSS_SDM_SV_BUF_MAX_LEN 0x20
#define EX_SSS_SDM_READ_CNTR_LEN 0x03
#define EX_SSS_SDM_ZERO_PADDING_LEN 0x0D
#define EX_SSS_SDM_ZERO_PADDING_BYTE 0x00
#define EX_SSS_SDM_AES_KEY_BIT_LEN_128 128
#define EX_SSS_SDM_AES_KEY_BIT_LEN_256 256

#define EX_SSS_SDM_SDMMACLength 0x10

/* clang-format on */
#endif // __EX_SDM_MAC_H__
