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
#define HKDF_MAX_SALT 32
#define SYM_KEY_MAX 16
#define HKDF_INFO_LEN 80

/* ************************************************************************** */
/* Structures and Typedefs                                                    */
/* ************************************************************************** */

/* ************************************************************************** */
/* Global Variables                                                           */
/* ************************************************************************** */

/* clang-format on */

static ex_sss_boot_ctx_t gex_sss_hkdf_boot_ctx;

/* ************************************************************************** */
/* Static function declarations                                               */
/* ************************************************************************** */

/* ************************************************************************** */
/* Private Functions                                                          */
/* ************************************************************************** */

/* ************************************************************************** */
/* Public Functions                                                           */
/* ************************************************************************** */

#define EX_SSS_BOOT_PCONTEXT (&gex_sss_hkdf_boot_ctx)
#define EX_SSS_BOOT_EXPOSE_ARGC_ARGV 0

/* ************************************************************************** */
/* Include "main()" with the platform specific startup code for NX            */
/* MW examples which will call ex_sss_entry()                                 */
/* ************************************************************************** */
#include <ex_sss_main_inc.h>

sss_status_t ex_sss_entry(ex_sss_boot_ctx_t *pCtx)
{
    sss_status_t status       = kStatus_SSS_Fail;
    sss_derive_key_t ctx_derv = {0};
    /* HKDF Extract and Expand*/
    sss_algorithm_t algorithm = kAlgorithm_SSS_SHA256;
    sss_mode_t mode           = kMode_SSS_HKDF_ExtractExpand;
    uint32_t aes_keyId        = 0x12; /* must be in range: 0x10 to 0x17 */
    uint32_t salt_keyId       = __LINE__;
    uint32_t drv_keyId        = __LINE__;
    int i                     = -1;
    uint32_t hmacKey_len      = SYM_KEY_MAX;
    uint16_t deriveDataLen    = 128;
    uint8_t hkdfKey[128]      = {0};
    size_t hkdfKeyLen         = sizeof(hkdfKey);
    /* clang-format off */
    const uint8_t hmacRef[SYM_KEY_MAX] = { 0xDB, 0xFE, 0xE9, 0xE3, 0xB2, 0x76, 0x15, 0x4D,
                                           0x67, 0xF9, 0xD8, 0x4C, 0xB9, 0x35, 0x54, 0x56 };
    static uint8_t salt[HKDF_MAX_SALT] = { 0xAA, 0x1A, 0x2A, 0xE3, 0xB2, 0x76, 0x15, 0x4D,
                                           0x67, 0xF9, 0xD8, 0x4C, 0xB9, 0x35, 0x54, 0x56,
                                           0xBB, 0x1B, 0x2B, 0x03, 0x04, 0x05, 0x06, 0x07,
                                           0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
    /* clang-format on */

    sss_object_t aesKeyObject     = {0};
    sss_object_t saltObject       = {0};
    sss_object_t derivedKeyObject = {0};

    const sss_policy_u aeskeyPolicy = {.type = KPolicy_ChgAESKey,
        .policy                              = {.chgAesKey = {
                       .hkdfEnabled        = 1,
                       .hmacEnabled        = 0,
                       .aeadEncIntEnabled  = 0,
                       .aeadEncEnabled     = 0,
                       .aeadDecEnabled     = 0,
                       .ecb_cbc_EncEnabled = 0,
                       .ecb_cbc_DecEnabled = 0,
                       .macSignEnabled     = 0,
                       .macVerifyEnabled   = 0,
                   }}};
    sss_policy_t aeskeyPolicyList   = {.nPolicies = 1, .policies = {&aeskeyPolicy}};

    LOG_I("Running HMAC Key Derivation Function Example ex_sss_hkdf.c");

    uint8_t info[HKDF_INFO_LEN] = {0};
    uint8_t infoLen             = sizeof(info);
    for (i = 0; i < HKDF_INFO_LEN; i++) {
        info[i] = (uint8_t)i;
    }
    ENSURE_OR_GO_CLEANUP(NULL != pCtx)

    /* Set IKM */
    status = sss_key_object_init(&aesKeyObject, &pCtx->ks);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_key_object_allocate_handle(
        &aesKeyObject, aes_keyId, kSSS_KeyPart_Default, kSSS_CipherType_AES, SYM_KEY_MAX, kKeyObject_Mode_Persistent);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_key_store_set_key(
        &pCtx->ks, &aesKeyObject, hmacRef, hmacKey_len, hmacKey_len * 8, &aeskeyPolicyList, sizeof(aeskeyPolicyList));
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    /* Create Salt object */
    status = sss_key_object_init(&saltObject, &pCtx->host_ks);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_key_object_allocate_handle(
        &saltObject, salt_keyId, kSSS_KeyPart_Default, kSSS_CipherType_AES, HKDF_MAX_SALT, kKeyObject_Mode_Transient);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_key_store_set_key(&pCtx->host_ks, &saltObject, salt, HKDF_MAX_SALT, (HKDF_MAX_SALT * 8), NULL, 0);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    /* Create Derived key object (to hold HKDF output) */
    status = sss_key_object_init(&derivedKeyObject, &pCtx->host_ks);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_key_object_allocate_handle(&derivedKeyObject,
        drv_keyId,
        kSSS_KeyPart_Default,
        kSSS_CipherType_AES,
        deriveDataLen,
        kKeyObject_Mode_Persistent);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    /* Note:
           Set mode to kMode_SSS_HKDF_ExpandOnly to request only the Expand phase
           of the HKDF to be calculated.
     */
    status = sss_derive_key_context_init(&ctx_derv, &pCtx->session, &aesKeyObject, algorithm, mode);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    LOG_I("Do Key Derivation");
    LOG_MAU8_I("salt", salt, HKDF_MAX_SALT);
    LOG_MAU8_I("info", info, infoLen);

    status = sss_derive_key_one_go(&ctx_derv, &saltObject, info, infoLen, &derivedKeyObject, deriveDataLen);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    /* Get the HKDF key */
    status = sss_key_store_get_key(derivedKeyObject.keyStore, &derivedKeyObject, hkdfKey, &hkdfKeyLen, NULL);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    LOG_I("Key Derivation successful !!!");
    LOG_MAU8_I("hkdfOutput", hkdfKey, hkdfKeyLen);

cleanup:
    if (kStatus_SSS_Success == status) {
        LOG_I("ex_sss_hkdf Example Success !!!...");
    }
    else {
        LOG_E("ex_sss_hkdf Example Failed !!!...");
    }

    if (aesKeyObject.keyStore != NULL) {
        sss_key_object_free(&aesKeyObject);
    }
    if (saltObject.keyStore != NULL) {
        sss_key_object_free(&saltObject);
    }
    if (derivedKeyObject.keyStore != NULL) {
        sss_key_object_free(&derivedKeyObject);
    }
    if (ctx_derv.session != NULL) {
        sss_derive_key_context_free(&ctx_derv);
    }

    return status;
}
