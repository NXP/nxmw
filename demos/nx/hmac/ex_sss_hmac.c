/*
 *
 * Copyright 2023-2024 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 */

/* ************************************************************************** */
/* Includes                                                                   */
/* ************************************************************************** */
#include "ex_sss_boot.h"
#include "nxEnsure.h"
#include "nxLog_msg.h"

/* ************************************************************************** */
/* Local Defines                                                              */
/* ************************************************************************** */
#define HMAC_LEN_BYTES 32
#define HMAC_KEY_LEN 16

/* ************************************************************************** */
/* Structures and Typedefs                                                    */
/* ************************************************************************** */

/* ************************************************************************** */
/* Global Variables                                                           */
/* ************************************************************************** */

static ex_sss_boot_ctx_t gex_sss_hmac_boot_ctx;

/* ************************************************************************** */
/* Static function declarations                                               */
/* ************************************************************************** */

/* ************************************************************************** */
/* Private Functions                                                          */
/* ************************************************************************** */

/* ************************************************************************** */
/* Public Functions                                                           */
/* ************************************************************************** */

#define EX_SSS_BOOT_PCONTEXT (&gex_sss_hmac_boot_ctx)
#define EX_SSS_BOOT_EXPOSE_ARGC_ARGV 0

/* ************************************************************************** */
/* Include "main()" with the platform specific startup code for NX            */
/* MW examples which will call ex_sss_entry()                                 */
/* ************************************************************************** */
#include <ex_sss_main_inc.h>

sss_status_t ex_sss_entry(ex_sss_boot_ctx_t *pCtx)
{
    sss_status_t status                = kStatus_SSS_Fail;
    sss_algorithm_t algorithm          = kAlgorithm_SSS_HMAC_SHA256;
    sss_mode_t mode                    = kMode_SSS_Mac;
    uint8_t input[]                    = "HelloWorld";
    size_t inputLen                    = strlen((const char *)input);
    uint8_t hmacOutput[HMAC_LEN_BYTES] = {0};
    size_t hmacOutputLen               = sizeof(hmacOutput);
    sss_mac_t ctx_hmac                 = {0};
    sss_object_t hmacKeyObj            = {0};
    uint32_t keyId                     = 0x12; /* must be in range: '0x10' - '0x17' */
    const sss_policy_u aeskeyPolicy    = {.type = KPolicy_ChgAESKey,
        .policy                              = {.chgAesKey = {
                       .hkdfEnabled        = 0,
                       .hmacEnabled        = 1,
                       .aeadEncIntEnabled  = 0,
                       .aeadEncEnabled     = 0,
                       .aeadDecEnabled     = 0,
                       .ecb_cbc_EncEnabled = 0,
                       .ecb_cbc_DecEnabled = 0,
                       .macSignEnabled     = 0,
                       .macVerifyEnabled   = 0,
                   }}};
    sss_policy_t aeskeyPolicyList      = {.nPolicies = 1, .policies = {&aeskeyPolicy}};
    /* clang-format off */
    uint8_t hmacKey[HMAC_KEY_LEN] = { 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x48, 0x65, 0x6c,
                                      0x6c, 0x6f, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x48 };

    uint8_t expectedVal[HMAC_LEN_BYTES] = { 0x68, 0x7a, 0x26, 0x95, 0x49, 0x67, 0x9d, 0x6e,
                                            0xfa, 0x11, 0x19, 0x5e, 0x96, 0xcb, 0xba, 0xc2,
                                            0x6b, 0x50, 0xa5, 0x09, 0x10, 0x8a, 0xd1, 0x48,
                                            0xb5, 0xfc, 0xa0, 0x94, 0x2c, 0xbd, 0x10, 0x21 };
    /* clang-format on */

    ENSURE_OR_GO_CLEANUP(NULL != pCtx)

    LOG_I("Running HMAC (SHA256) Example ex_sss_hmac.c");

    status = sss_key_object_init(&hmacKeyObj, &pCtx->ks);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_key_object_allocate_handle(
        &hmacKeyObj, keyId, kSSS_KeyPart_Default, kSSS_CipherType_AES, HMAC_KEY_LEN, kKeyObject_Mode_Persistent);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_key_store_set_key(
        &pCtx->ks, &hmacKeyObj, hmacKey, HMAC_KEY_LEN, (HMAC_KEY_LEN * 8), &aeskeyPolicyList, sizeof(aeskeyPolicyList));
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_mac_context_init(&ctx_hmac, &pCtx->session, &hmacKeyObj, algorithm, mode);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    LOG_I("Do HMAC");
    LOG_MAU8_I("input", input, inputLen);
    LOG_MAU8_I("hmac key", hmacKey, HMAC_KEY_LEN);
    status = sss_mac_one_go(&ctx_hmac, input, inputLen, hmacOutput, &hmacOutputLen);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    if (0 != memcmp(hmacOutput, expectedVal, HMAC_LEN_BYTES)) {
        status = kStatus_SSS_Fail;
    }
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
    LOG_I("HMAC (SHA256) successful !!!");
    LOG_MAU8_I("hmac", hmacOutput, hmacOutputLen);
cleanup:
    if (kStatus_SSS_Success == status) {
        LOG_I("ex_sss_hmac Example Success !!!...");
    }
    else {
        LOG_E("ex_sss_hmac Example Failed !!!...");
    }
    if (ctx_hmac.session != NULL) {
        sss_mac_context_free(&ctx_hmac);
    }
    if (hmacKeyObj.keyStore != NULL) {
        sss_key_object_free(&hmacKeyObj);
    }
    return status;
}
