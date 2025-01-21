/*
*
* Copyright 2018-2020, 2023-2024 NXP
* SPDX-License-Identifier: BSD-3-Clause
*/

#ifndef FSL_SSS_UTIL_ASN1_DER_H
#define FSL_SSS_UTIL_ASN1_DER_H

#if defined(SSS_USE_FTR_FILE)
#include "fsl_sss_ftr.h"
#else
#include "fsl_sss_ftr_default.h"
#endif

#include "fsl_sss_api.h"

/* ************************************************************************** */
/* Defines                                                                    */
/* ************************************************************************** */
#define ASN_TAG_INT 0x02
#define ASN_TAG_SEQUENCE 0x30
#define ASN_TAG_BITSTRING 0x03
#define ASN_TAG_OCTETSTRING 0x04
#define ASN_TAG_OBJ_IDF 0x06
#define ASN_TAG_CNT_SPECIFIC 0xA1
#define ASN_TAG_CNT_SPECIFIC_PRIMITIVE 0x80
#define ASN_TAG_CRL_EXTENSIONS 0xA0

#define SSS_UTIL_ASN1_BOOLEAN 0x01
#define SSS_UTIL_ASN1_INTEGER 0x02
#define SSS_UTIL_ASN1_BIT_STRING 0x03
#define SSS_UTIL_ASN1_OCTET_STRING 0x04
#define SSS_UTIL_ASN1_NULL 0x05
#define SSS_UTIL_ASN1_OID 0x06
#define SSS_UTIL_ASN1_ENUMERATED 0x0A
#define SSS_UTIL_ASN1_UTF8_STRING 0x0C
#define SSS_UTIL_ASN1_SEQUENCE 0x10
#define SSS_UTIL_ASN1_SET 0x11
#define SSS_UTIL_ASN1_PRINTABLE_STRING 0x13
#define SSS_UTIL_ASN1_T61_STRING 0x14
#define SSS_UTIL_ASN1_IA5_STRING 0x16
#define SSS_UTIL_ASN1_UTC_TIME 0x17
#define SSS_UTIL_ASN1_GENERALIZED_TIME 0x18
#define SSS_UTIL_ASN1_UNIVERSAL_STRING 0x1C
#define SSS_UTIL_ASN1_BMP_STRING 0x1E
#define SSS_UTIL_ASN1_PRIMITIVE 0x00
#define SSS_UTIL_ASN1_CONSTRUCTED 0x20
#define SSS_UTIL_ASN1_CONTEXT_SPECIFIC 0x80

extern const uint8_t gecc_der_header_nist256[];
extern const uint8_t gecc_der_header_bp256[];
extern const size_t der_ecc_nistp256_header_len;
extern const size_t der_ecc_bp256_header_len;

/* ************************************************************************** */
/* Functions                                                                  */
/* ************************************************************************** */

#define IS_VALID_TAG(x)                                                                             \
    (x == ASN_TAG_SEQUENCE || x == ASN_TAG_OBJ_IDF || x == ASN_TAG_BITSTRING || x == ASN_TAG_INT || \
        x == ASN_TAG_OCTETSTRING || x == ASN_TAG_CNT_SPECIFIC || x == ASN_TAG_CRL_EXTENSIONS) ?     \
        1 :                                                                                         \
        0

int sss_util_asn1_get_len(unsigned char **p, const unsigned char *end, size_t *len);

int sss_util_asn1_get_tag(unsigned char **p, const unsigned char *end, size_t *len, int tag);

#endif // FSL_SSS_UTIL_ASN1_DER_H
