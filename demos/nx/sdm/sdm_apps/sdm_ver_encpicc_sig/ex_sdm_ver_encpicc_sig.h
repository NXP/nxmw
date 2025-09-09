/* Copyright 2025 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __EX_SDM_VER_ENCPICC_SIG_H__
#define __EX_SDM_VER_ENCPICC_SIG_H__

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>

#define EX_SSS_SDM_PICCDATA_OFFSET 0x20
#define EX_SSS_SDM_GPIOStatusOffset 0x68
#define EX_SSS_SDM_SDMENCOffset 0x60
#define EX_SSS_SDM_SDMENCLength 0x20
#define EX_SSS_SDM_SDMMACOffset 0x43
#define EX_SSS_SDM_SDMMACInputOffset 0x1B
#define EX_SSS_SDM_PICCDATA_LENGTH 0x20
#define COMPRESSED_KEY_SIZE 32
#define EX_SSS_SDM_ENCRYPTED_ASCII_PLACEHOLDER_MAX_LEN 128
#define EX_SSS_SDM_NDEF_FILE_SIZE 256
#define EX_SSS_SDM_NDEF_FILE_NUMBER 0x02
#define EX_SSS_SDM_7BYTE_VCUID_LENGTH 0x07

#endif // __EX_SDM_VER_ENCPICC_SIG_H__
