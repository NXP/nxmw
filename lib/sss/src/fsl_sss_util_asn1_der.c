/*
*
* Copyright 2022-2024 NXP
* SPDX-License-Identifier: BSD-3-Clause
*/

#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include "fsl_sss_util_asn1_der.h"
#include "nxEnsure.h"
#include "nxLog_msg.h"

#define IS_VALID_RFC8410_TAG(x)                                                                     \
    (x == ASN_TAG_SEQUENCE || x == ASN_TAG_OBJ_IDF || x == ASN_TAG_BITSTRING || x == ASN_TAG_INT || \
        x == ASN_TAG_OCTETSTRING || x == ASN_TAG_CNT_SPECIFIC || x == ASN_TAG_CRL_EXTENSIONS ||     \
        x == (ASN_TAG_CNT_SPECIFIC_PRIMITIVE | 0x01)) ?                                             \
        1 :                                                                                         \
        0

/* ECC Header */

/* clang-format off */
const uint8_t gecc_der_header_nist256[] = {
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86,  \
    0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x08, 0x2A,  \
    0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x03,  \
    0x42, 0x00,  \
};

const uint8_t gecc_der_header_bp256[] = {
    0x30, 0x5a, 0x30, 0x14, 0x06, 0x07, 0x2a, 0x86, \
    0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x09, 0x2b, \
    0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07, \
    0x03, 0x42, 0x00, \
};

/* clang-format on */

size_t const der_ecc_nistp256_header_len = sizeof(gecc_der_header_nist256);
size_t const der_ecc_bp256_header_len    = sizeof(gecc_der_header_bp256);

int sss_util_asn1_get_len(unsigned char **p, const unsigned char *end, size_t *len)
{
    if ((p == NULL) || (*p == NULL) || (len == NULL)) {
        return -1;
    }

    if ((end - *p) < 1)
        return (-1);

    if ((**p & 0x80) == 0)
        *len = *(*p)++;
    else {
        switch (**p & 0x7F) {
        case 1:
            if ((end - *p) < 2)
                return (-1);

            *len = (*p)[1];
            (*p) += 2;
            break;

        case 2:
            if ((end - *p) < 3)
                return (-1);

            *len = ((size_t)(*p)[1] << 8) | (*p)[2];
            (*p) += 3;
            break;

        case 3:
            if ((end - *p) < 4)
                return (-1);

            *len = ((size_t)(*p)[1] << 16) | ((size_t)(*p)[2] << 8) | (*p)[3];
            (*p) += 4;
            break;

        case 4:
            if ((end - *p) < 5)
                return (-1);

            *len = ((size_t)(*p)[1] << 24) | ((size_t)(*p)[2] << 16) | ((size_t)(*p)[3] << 8) | (*p)[4];
            (*p) += 5;
            break;

        default:
            return (-1);
        }
    }

    if (*len > (size_t)(end - *p))
        return (-1);

    return (0);
}

/**
 * @brief         Get value field address and length of a specified tag.
 *
 *         |-tag-len-value----------------------|
 * Before  ^p                                   ^end
 * After             ^p                         ^end, len = len field = end - p;
 */
int sss_util_asn1_get_tag(unsigned char **p, const unsigned char *end, size_t *len, int tag)
{
    if ((p == NULL) || (*p == NULL)) {
        return -1;
    }
    else {
        if ((end - *p) < 1)
            return (-1);

        if (**p != tag)
            return (-1);

        (*p)++;

        return (sss_util_asn1_get_len(p, end, len));
    }
}