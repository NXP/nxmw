/* Copyright 2024 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __EX_SDM_FILE_READ_H__
#define __EX_SDM_FILE_READ_H__

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

#define EX_SSS_SDM_SDMSignatureLength 0x80

#define EX_SSS_SDM_ECC_PUBLIC_KEY                                                                       \
    {                                                                                                   \
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x08, 0x2A, \
        0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,                                     \
        0x04, 0x4A, 0x76, 0x93, 0x0B, 0xA3, 0x50, 0xC8, 0x59, 0x3D, 0x1B, 0xCB, 0x82, 0x59, 0xAA, 0x09, \
        0x78, 0xC2, 0xD2, 0x0E, 0x5E, 0xB2, 0xA6, 0xBE, 0xFB, 0x06, 0xA3, 0x9A, 0x36, 0x92, 0xDE, 0x4A, \
        0xE0, 0xAB, 0x68, 0x57, 0x0A, 0x2E, 0x3E, 0x36, 0xFF, 0xA0, 0xEE, 0xBD, 0x5A, 0x21, 0x87, 0xFE, \
        0x31, 0xC5, 0xD4, 0x74, 0x4D, 0x1F, 0x62, 0xA7, 0xCE, 0x52, 0x9E, 0x07, 0x47, 0x8B, 0x63, 0xB1, \
        0xAD,                                                                                           \
    }
/* clang-format on */
#endif // __EX_SDM_FILE_READ_H__
