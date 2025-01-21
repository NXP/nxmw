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
#include <string.h>
#include "nx_apdu.h"
#include "fsl_sss_nx_auth_types.h"

/* ************************************************************************** */
/* Local Defines                                                              */
/* ************************************************************************** */
#define EX_UPDATE_OLD_AESKEY EX_SYMM_AUTH_AES128_KEY
#define EX_UPDATE_OLD_AESKEY_LEN EX_SYMM_AUTH_AES128_KEY_SIZE
#define EX_UPDATE_NEW_AESKEY EX_SYMM_AUTH_AES256_KEY
#define EX_UPDATE_NEW_AESKEY_LEN EX_SYMM_AUTH_AES256_KEY_SIZE

#define EX_UPDATE_KEY_ID 0
/* ************************************************************************** */
/* Structures and Typedefs                                                    */
/* ************************************************************************** */

/* ************************************************************************** */
/* Global Variables                                                           */
/* ************************************************************************** */

static ex_sss_boot_ctx_t gex_sss_update_key_boot_ctx;

/* ************************************************************************** */
/* Static function declarations                                               */
/* ************************************************************************** */

/* ************************************************************************** */
/* Private Functions                                                          */
/* ************************************************************************** */

/* ************************************************************************** */
/* Public Functions                                                           */
/* ************************************************************************** */

#define EX_SSS_BOOT_PCONTEXT (&gex_sss_update_key_boot_ctx)
#define EX_SSS_BOOT_EXPOSE_ARGC_ARGV 0

#include <ex_sss_main_inc.h>

sss_status_t ex_sss_entry(ex_sss_boot_ctx_t *pCtx)
{
    sss_status_t status           = kStatus_SSS_Fail;
    uint32_t keyId                = EX_UPDATE_KEY_ID;
    uint8_t key[32]               = EX_UPDATE_NEW_AESKEY;
    size_t keyLen                 = EX_UPDATE_NEW_AESKEY_LEN;
    size_t keyBitLen              = EX_UPDATE_NEW_AESKEY_LEN * 8;
    sss_object_t keyObject        = {0};
    sss_policy_u aeskeyPolicy     = {.type = KPolicy_ChgAESKey,
        .policy                        = {.chgAesKey = {
                       .oldKey    = EX_UPDATE_OLD_AESKEY,
                       .oldKeyLen = EX_UPDATE_OLD_AESKEY_LEN,
                   }}};
    sss_policy_t aeskeyPolicyList = {.nPolicies = 1, .policies = {&aeskeyPolicy}};

    status = sss_key_object_init(&keyObject, &pCtx->ks);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    LOG_MAU8_I("Old AES Key", aeskeyPolicy.policy.chgAesKey.oldKey, aeskeyPolicy.policy.chgAesKey.oldKeyLen);
    status = sss_key_object_allocate_handle(
        &keyObject, keyId, kSSS_KeyPart_Default, kSSS_CipherType_AES, keyLen, kKeyObject_Mode_Persistent);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    LOG_MAU8_I("New AES Key", key, keyLen);
    status = sss_key_store_set_key(
        &pCtx->ks, &keyObject, &key[0], keyLen, keyBitLen, &aeskeyPolicyList, sizeof(aeskeyPolicyList));
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
    LOG_I("Successfully injected AES key into Nx");

cleanup:

    if (kStatus_SSS_Success == status) {
        LOG_I("ex_sss_update_key Example Success !!!...");
    }
    else {
        LOG_E("ex_sss_update_key Example Failed !!!...");
    }
    if (keyObject.keyStore != NULL) {
        sss_key_object_free(&keyObject);
    }

    return status;
}
