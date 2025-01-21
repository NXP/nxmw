/* Copyright 2023 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __EX_SDM_COMMON_H__
#define __EX_SDM_COMMON_H__

#define EX_SSS_SDM_PICCDATA_OFFSET 0x20
#define EX_SSS_SDM_GPIOStatusOffset 0x68
#define EX_SSS_SDM_SDMENCOffset 0x60
#define EX_SSS_SDM_SDMENCLength 0x20
#define EX_SSS_SDM_SDMMACOffset 0x80
#define EX_SSS_SDM_SDMMACInputOffset 0x10

#define EX_SSS_SDM_NDEF_FILE_NUMBER 0x02
#define EX_SSS_SDM_NDEF_FILE_SIZE 256
/* clang-format off */
#define EX_SSS_SDM_NEW_AES_KEY                                                                          \
    {                                                                                                   \
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
    }
/* clang-format on */
#define EX_SSS_SDM_META_READ_AES_KEY EX_SSS_SDM_NEW_AES_KEY
#define EX_SSS_SDM_FILE_READ_AES_KEY EX_SSS_SDM_NEW_AES_KEY

#define EX_SSS_SDM_ECC_CURVE_TYPE kSSS_CipherType_EC_NIST_P

#endif // __EX_SDM_COMMON_H__
