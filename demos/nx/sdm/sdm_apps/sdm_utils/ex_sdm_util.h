/* Copyright 2025 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __EX_SDM_UTIL_H__
#define __EX_SDM_UTIL_H__

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>

#include "ex_sss_boot.h"
#include "fsl_sss_api.h"

#ifndef MAKE_TEST_ID
#define MAKE_TEST_ID(ID) (0xEF000000u + ID)
#endif /* MAKE_TEST_ID */

#define COMPRESSED_KEY_SIZE 32
#define KEY_BIT_LENGTH 256
#define NIST_256_HEADER_LEN 26
#define PUBKEY_LEN_MAX 256

#define EX_SSS_SDM_SDMSignatureLength 0x80
#define EX_SSS_SDM_ENCRYPTED_ASCII_PLACEHOLDER_MAX_LEN 128

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

/* clang-format off */
#define EX_SSS_SDM_NEW_AES_KEY                                                                          \
    {                                                                                                   \
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
    }
/* clang-format on */
#define EX_SSS_SDM_META_READ_AES_KEY EX_SSS_SDM_NEW_AES_KEY
#define EX_SSS_SDM_FILE_READ_AES_KEY EX_SSS_SDM_NEW_AES_KEY

/* clang-format off */
#define EX_SSS_SDM_PICCDATA_IV_VALUE                                                                   \
    {                                                                                                  \
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 \
    }
/* clang-format on */

#define EX_SSS_SDM_ECC_CURVE_TYPE kSSS_CipherType_EC_NIST_P

void parseCertGetPublicKey(uint8_t *pCert, size_t certLen, uint8_t *pPucPublicKey, size_t *pucPublicKeylen);
int sdm_ascii_to_hex(uint8_t *asciiBuf, size_t asciiBufLen, uint8_t *hexBuf, size_t *hexBufLen);
sss_status_t sdm_decrypt_picc_data(
    ex_sss_boot_ctx_t *pCtx, uint8_t *encData, size_t encDataLen, uint8_t *outPlainData, size_t *outPlainDataLen);
sss_status_t sdm_verify_data_signature(ex_sss_boot_ctx_t *pCtx,
    uint8_t *plainData,
    size_t plainDataLen,
    uint8_t *pubKey,
    size_t pubKeyLen,
    uint8_t *signData,
    size_t signDataLen);
int set_secp256r1nist_header(uint8_t *pbKey, size_t *pbKeyByteLen);
#endif //__EX_SDM_UTIL_H__