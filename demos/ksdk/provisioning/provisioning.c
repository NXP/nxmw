/* Copyright 2024 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "provisioning.h"
#include "ex_sss_boot.h"
#include "nxLog_msg.h"

static ex_sss_boot_ctx_t gex_sss_provisioning_ctx;

#define EX_SSS_BOOT_PCONTEXT (&gex_sss_provisioning_ctx)
#define EX_SSS_BOOT_EXPOSE_ARGC_ARGV 0

/* ************************************************************************** */
/* Include "main()" with the platform specific startup code for NXMW examples */
/* which will call ex_sss_entry()                                             */
/* ************************************************************************** */
#include <ex_sss_main_inc.h>

int ex_util_asn1_get_ec_pair_key_index(const uint8_t *input,
    size_t inLen,
    uint8_t *pubkeyIndex,
    size_t *publicKeyLen,
    uint8_t *prvkeyIndex,
    size_t *privateKeyLen)
{
    size_t i      = 0;
    size_t taglen = 0;
    int tag       = 0;
    int ret       = -1;

    ENSURE_OR_GO_EXIT(input != NULL);
    ENSURE_OR_GO_EXIT(pubkeyIndex != NULL);
    ENSURE_OR_GO_EXIT(publicKeyLen != NULL);
    ENSURE_OR_GO_EXIT(prvkeyIndex != NULL);
    ENSURE_OR_GO_EXIT(privateKeyLen != NULL);

    for (;;) {
        ENSURE_OR_GO_EXIT(i < inLen);
        tag = input[i++];
        if (IS_VALID_TAG(tag)) {
            ENSURE_OR_GO_EXIT(i < inLen);
            taglen = input[i++];
            if (taglen == 0x81) {
                ENSURE_OR_GO_EXIT(i < inLen);
                taglen = input[i];
                i      = i + 1;
            }
            else if (taglen == 0x82) {
                ENSURE_OR_GO_EXIT(i < (inLen - 1));
                taglen = input[i] | input[i + 1] << 8;
                i      = i + 2;
            }

            if (taglen > inLen) {
                goto exit;
            }

            if (tag == ASN_TAG_OCTETSTRING) {
                ENSURE_OR_GO_EXIT((UINT_MAX - i) >= taglen);
                if (i + taglen == inLen) {
                    continue;
                }
                else {
                    *prvkeyIndex   = (uint8_t)i;
                    *privateKeyLen = taglen;
                }
            }

            if (tag == ASN_TAG_BITSTRING) {
                *pubkeyIndex  = (uint8_t)i;
                *publicKeyLen = taglen;
                ENSURE_OR_GO_EXIT(i < inLen);
                if (input[i] == 0x00 || input[i] == 0x01) {
                    ENSURE_OR_GO_EXIT((UINT8_MAX - 1) >= (*pubkeyIndex));
                    *pubkeyIndex  = *pubkeyIndex + 1;
                    *publicKeyLen = *publicKeyLen - 1;
                }
                break;
            }
            ENSURE_OR_GO_EXIT((UINT_MAX - i) >= taglen);
            if (i + taglen == inLen) {
                continue;
            }
            else {
                i = i + taglen;
            }
        }
        else {
            goto exit;
        }
    }

    ENSURE_OR_GO_EXIT((*pubkeyIndex) < inLen);
    ENSURE_OR_GO_EXIT((UINT_MAX - (*pubkeyIndex)) >= (*publicKeyLen));
    ENSURE_OR_GO_EXIT(((*pubkeyIndex) + (*publicKeyLen)) <= inLen);
    ENSURE_OR_GO_EXIT((*prvkeyIndex) < inLen);
    ENSURE_OR_GO_EXIT((UINT_MAX - (*prvkeyIndex)) >= (*privateKeyLen));
    ENSURE_OR_GO_EXIT(((*prvkeyIndex) + (*privateKeyLen)) <= inLen);
    ret = 0;

exit:
    return ret;
}