/*
 *
 * Copyright 2022, 2024 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 */

/* ************************************************************************** */
/* Includes                                                                   */
/* ************************************************************************** */
#include <string.h>
#include "ex_sss_boot.h"
#include "fsl_sss_nx_auth_types.h"
#include "fsl_sss_nx_auth_keys.h"
#include "diversify_key_perso.h"
#include "nxEnsure.h"
#include "nxLog_msg.h"
#include "nx_apdu.h"
#include "nx_enums.h"

/* ************************************************************************** */
/* Local Defines                                                              */
/* ************************************************************************** */
#define AES128_KEY_LEN 16
#define AES256_KEY_LEN 32
#define AES128_DIVERSIFY_INPUT_CONSTANT_BYTE 0x01
#define AES256_DIVERSIFY_INPUT_D1_CONSTANT_BYTE 0x41
#define AES256_DIVERSIFY_INPUT_D2_CONSTANT_BYTE 0x42
#define DIVERSIFY_INPUT_CONSTANT_BYTE_LEN 1
#define DIVERSIFY_INPUT_SIZE 32
#define DIVERSIFY_INPUT_PAD_BYTE 0x80
#define DIVERSIFY_KEY_LEN 16
#define BLOCK_SIZE 16
#define MASTER_KEY_MAX_LEN 32

/* ************************************************************************** */
/* Structures and Typedefs                                                    */
/* ************************************************************************** */

/* ************************************************************************** */
/* Global Variables                                                           */
/* ************************************************************************** */

static ex_sss_boot_ctx_t gex_sss_diversifykeyperso_boot_ctx;

/* ************************************************************************** */
/* Static function declarations                                               */
/* ************************************************************************** */
static void addPaddingDiversifyInput(uint8_t *diversifyInput, size_t diversifyInputBufSize, size_t *diversifyInputLen);
/* ************************************************************************** */
/* Private Functions                                                          */
/* ************************************************************************** */

/* ************************************************************************** */
/* Public Functions                                                           */
/* ************************************************************************** */

#define EX_SSS_BOOT_PCONTEXT (&gex_sss_diversifykeyperso_boot_ctx)
#define EX_SSS_BOOT_EXPOSE_ARGC_ARGV 0

#ifndef MAKE_TEST_ID
#define MAKE_TEST_ID(ID) (0xEF000000u + ID)
#endif /* MAKE_TEST_ID */

#include <ex_sss_main_inc.h>

sss_status_t ex_sss_entry(ex_sss_boot_ctx_t *pCtx)
{
    sss_status_t status                  = kStatus_SSS_Fail;
    sss_algorithm_t algorithm            = kAlgorithm_SSS_CMAC_AES;
    sss_mode_t mode                      = kMode_SSS_Mac;
    sss_mac_t macCtx                     = {0};
    sss_object_t diversifyKeyObj         = {0};
    sss_object_t masterKeyObj            = {0};
    static nx_connect_ctx_t *pConnectCtx = NULL;
    static nx_connect_ctx_t nx_open_ctx  = {0};
    pConnectCtx                          = &nx_open_ctx;
    sss_key_part_t keyPart               = kSSS_KeyPart_Default;
    sss_cipher_type_t cipherType         = kSSS_CipherType_AES;
    uint32_t keyId                       = MAKE_TEST_ID(__LINE__);

    uint8_t diversifyInput[DIVERSIFY_INPUT_SIZE]  = {0};
    size_t diversifyInputLen                      = 0;
    uint8_t aes128DiversifyKey[DIVERSIFY_KEY_LEN] = {0};
    size_t aes128DiversifyKeyLen                  = sizeof(aes128DiversifyKey);
    uint8_t aes128OldKeyBuf[AES128_KEY_LEN]       = EX_AES128_KEYID_1_OLD_KEY;
    uint8_t aes256OldKeyBuf[AES256_KEY_LEN]       = EX_AES256_KEYID_1_OLD_KEY;
    uint8_t masterKey[MASTER_KEY_MAX_LEN]         = {0};
    size_t masterKeyLen                           = 0;
    uint8_t uidBufDefault[EX_DIVERSIFY_UID_LEN]   = EX_DIVERSIFY_INPUT_UID;
    size_t uidBufDefaultLen                       = sizeof(uidBufDefault);
    uint8_t aidBufDefault[EX_DIVERSIFY_AID_LEN]   = EX_DIVERSIFY_INPUT_AID;
    size_t aidBufDefaultLen                       = sizeof(aidBufDefault);
    uint8_t sidBufDefault[EX_DIVERSIFY_SID_LEN]   = EX_DIVERSIFY_INPUT_SID;
    size_t sidBufDefaultLen                       = sizeof(sidBufDefault);

    pConnectCtx->auth = pCtx->nx_open_ctx.auth;

    /* clang-format off */
    uint8_t appkeyId = NX_KEY_MGMT_APP_KEY_ID_1;
    sss_policy_u changeAesKey = {.type = KPolicy_ChgAESKey,
        .policy                              = {.chgAesKey = {
                       .hkdfEnabled        = 0,
                       .hmacEnabled        = 0,
                       .aeadEncIntEnabled  = 0,
                       .aeadEncEnabled     = 0,
                       .aeadDecEnabled     = 0,
                       .ecb_cbc_EncEnabled = 0,
                       .ecb_cbc_DecEnabled = 0,
                       .macSignEnabled     = 0,
                       .macVerifyEnabled   = 0,
                       .oldKey             = {0},
                       .oldKeyLen          = 0,
                   }}};
    sss_policy_t changeAesKeyPolicyList   = {.nPolicies = 1, .policies = {&changeAesKey}};

    /* clang-format on */
#if defined(EX_SSS_D_KEY_INPUT_FILE_PATH)
    uint8_t uidBuf_fs[EX_DIVERSIFY_UID_LEN] = {0};
    size_t uidBufLen_fs                     = sizeof(uidBuf_fs);
    uint8_t aidBuf_fs[EX_DIVERSIFY_AID_LEN] = {0};
    size_t aidBufLen_fs                     = sizeof(aidBuf_fs);
    uint8_t sidBuf_fs[EX_DIVERSIFY_SID_LEN] = {0};
    size_t sidBufLen_fs                     = sizeof(sidBuf_fs);
    status                                  = ex_sss_util_get_dkeyinput_from_fs(
        &uidBuf_fs[0], uidBufLen_fs, &aidBuf_fs[0], aidBufLen_fs, &sidBuf_fs[0], sidBufLen_fs);
    if (status == kStatus_SSS_Success) {
        memcpy(uidBufDefault, uidBuf_fs, uidBufLen_fs);
        uidBufDefaultLen = uidBufLen_fs;
        memcpy(aidBufDefault, aidBuf_fs, aidBufLen_fs);
        aidBufDefaultLen = aidBufLen_fs;
        memcpy(sidBufDefault, sidBuf_fs, sidBufLen_fs);
        sidBufDefaultLen = sidBufLen_fs;
    }
#endif // EX_SSS_D_KEY_INPUT_FILE_PATH

    diversifyInputLen = DIVERSIFY_INPUT_CONSTANT_BYTE_LEN;
    memcpy(diversifyInput + diversifyInputLen, uidBufDefault, uidBufDefaultLen);
    diversifyInputLen += uidBufDefaultLen;
    LOG_MAU8_I("uid", uidBufDefault, uidBufDefaultLen);
    memcpy(diversifyInput + diversifyInputLen, aidBufDefault, aidBufDefaultLen);
    diversifyInputLen += aidBufDefaultLen;
    LOG_MAU8_I("aid", aidBufDefault, aidBufDefaultLen);
    memcpy(diversifyInput + diversifyInputLen, sidBufDefault, sidBufDefaultLen);
    diversifyInputLen += sidBufDefaultLen;
    LOG_MAU8_I("sid", sidBufDefault, sidBufDefaultLen);

    if (diversifyInputLen < BLOCK_SIZE) {
        addPaddingDiversifyInput(&diversifyInput[0], sizeof(diversifyInput), &diversifyInputLen);
    }

    if (pConnectCtx->auth.authType == knx_AuthType_SYMM_AUTH) {
        if (pConnectCtx->auth.ctx.symmAuth.static_ctx.appKeySize == AES128_KEY_LEN) {
            uint8_t aes128masterKeyDefault[EX_SYMM_AUTH_AES128_KEY_SIZE] = EX_SYMM_AUTH_AES128_KEY;
            size_t aes128masterKeyDefaultLen                             = EX_SYMM_AUTH_AES128_KEY_SIZE;
#ifdef EX_SSS_APPKEY_FILE_PATH
            uint8_t aes128masterKey_fs[EX_SYMM_AUTH_AES128_KEY_SIZE] = {0};
            size_t aes128masterKeyLen_fs                             = 0;
            status                                                   = nx_util_get_app_keys_from_fs(
                &aes128masterKey_fs[0], sizeof(aes128masterKey_fs), &aes128masterKeyLen_fs);
            if (status == kStatus_SSS_Success) {
                memcpy(aes128masterKeyDefault, aes128masterKey_fs, aes128masterKeyLen_fs);
                aes128masterKeyDefaultLen = aes128masterKeyLen_fs;
            }
            if (aes128masterKeyDefaultLen != EX_SYMM_AUTH_AES128_KEY_SIZE) {
                LOG_E("Invalid keysize");
                status = kStatus_SSS_Fail;
                goto cleanup;
            }
#endif // EX_SSS_APPKEY_FILE_PATH,
            memcpy(masterKey, aes128masterKeyDefault, aes128masterKeyDefaultLen);
            masterKeyLen = aes128masterKeyDefaultLen;
        }
        else if (pConnectCtx->auth.ctx.symmAuth.static_ctx.appKeySize == AES256_KEY_LEN) {
            uint8_t aes256masterKeyDefault[EX_SYMM_AUTH_AES256_KEY_SIZE] = EX_SYMM_AUTH_AES256_KEY;
            size_t aes256masterKeyDefaultLen                             = EX_SYMM_AUTH_AES256_KEY_SIZE;
#ifdef EX_SSS_APPKEY_FILE_PATH
            uint8_t aes256masterKey_fs[EX_SYMM_AUTH_AES256_KEY_SIZE] = {0};
            size_t aes256masterKeyLen_fs                             = 0;

            status = nx_util_get_app_keys_from_fs(
                &aes256masterKey_fs[0], sizeof(aes256masterKey_fs), &aes256masterKeyLen_fs);
            if (status == kStatus_SSS_Success) {
                memcpy(aes256masterKeyDefault, aes256masterKey_fs, aes256masterKeyLen_fs);
                aes256masterKeyDefaultLen = aes256masterKeyLen_fs;
            }
            if (aes256masterKeyDefaultLen != EX_SYMM_AUTH_AES256_KEY_SIZE) {
                LOG_E("Invalid keysize");
                status = kStatus_SSS_Fail;
                goto cleanup;
            }
#endif // EX_SSS_APPKEY_FILE_PATH
            memcpy(masterKey, aes256masterKeyDefault, aes256masterKeyDefaultLen);
            masterKeyLen = aes256masterKeyDefaultLen;
        }
    }
    else if ((pConnectCtx->auth.authType == knx_AuthType_SIGMA_I_Verifier) ||
             (pConnectCtx->auth.authType == knx_AuthType_SIGMA_I_Prover)) {
        uint8_t masterKeyBufDefault[MASTER_KEY_MAX_LEN] = EX_SIGMA_I_AUTH_DEFAULT_AESKEY;
        size_t masterKeyBufDefaultLen                   = EX_SIGMA_I_AUTH_DEFAULT_AESKEY_LEN;
#ifdef EX_SSS_APPKEY_FILE_PATH
        uint8_t masterKeyBuf_fs[MASTER_KEY_MAX_LEN] = {0};
        size_t masterKeyBufLen_fs                   = 0;

        status = nx_util_get_app_keys_from_fs(&masterKeyBuf_fs[0], sizeof(masterKeyBuf_fs), &masterKeyBufLen_fs);
        if (status == kStatus_SSS_Success) {
            memcpy(masterKeyBufDefault, masterKeyBuf_fs, masterKeyBufLen_fs);
            masterKeyBufDefaultLen = masterKeyBufLen_fs;
        }
        if ((masterKeyBufDefaultLen != EX_SYMM_AUTH_AES128_KEY_SIZE) &&
            (masterKeyBufDefaultLen != EX_SYMM_AUTH_AES256_KEY_SIZE)) {
            LOG_E("Invalid keysize");
            status = kStatus_SSS_Fail;
            goto cleanup;
        }
#endif // EX_SSS_APPKEY_FILE_PATH
        memcpy(masterKey, masterKeyBufDefault, masterKeyBufDefaultLen);
        masterKeyLen = masterKeyBufDefaultLen;
    }
    else {
        LOG_E("Invalid authType");
        status = kStatus_SSS_Fail;
        goto cleanup;
    }

    if ((masterKeyLen == AES128_KEY_LEN) || (masterKeyLen == AES256_KEY_LEN)) {
        status = sss_key_object_init(&masterKeyObj, &pCtx->host_ks);
        ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

        status = sss_key_object_allocate_handle(
            &masterKeyObj, keyId, kSSS_KeyPart_Default, kSSS_CipherType_AES, masterKeyLen, kKeyObject_Mode_Persistent);
        ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

        status =
            sss_key_store_set_key(&pCtx->host_ks, &masterKeyObj, masterKey, masterKeyLen, (masterKeyLen * 8), NULL, 0);
        ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
        LOG_MAU8_I("masterKey", masterKey, masterKeyLen);
    }

    if (masterKeyLen == AES128_KEY_LEN) {
        diversifyInput[0] = AES128_DIVERSIFY_INPUT_CONSTANT_BYTE;
        memcpy(changeAesKey.policy.chgAesKey.oldKey, aes128OldKeyBuf, sizeof(aes128OldKeyBuf));
        changeAesKey.policy.chgAesKey.oldKeyLen = sizeof(aes128OldKeyBuf);

        status = sss_mac_context_init(&macCtx, &pCtx->host_session, &masterKeyObj, algorithm, mode);
        ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

        status = sss_mac_one_go(&macCtx, diversifyInput, diversifyInputLen, aes128DiversifyKey, &aes128DiversifyKeyLen);
        ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

        if (macCtx.session != NULL) {
            sss_mac_context_free(&macCtx);
        }

        status = sss_key_object_init(&diversifyKeyObj, &pCtx->ks);
        ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

        status = sss_key_object_allocate_handle(
            &diversifyKeyObj, appkeyId, keyPart, cipherType, aes128DiversifyKeyLen, kKeyObject_Mode_Persistent);
        ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

        LOG_MAU8_I("diversifyKey", aes128DiversifyKey, aes128DiversifyKeyLen);
        status = sss_key_store_set_key(&pCtx->ks,
            &diversifyKeyObj,
            aes128DiversifyKey,
            aes128DiversifyKeyLen,
            (aes128DiversifyKeyLen * 8),
            &changeAesKeyPolicyList,
            sizeof(changeAesKeyPolicyList));
        ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
        LOG_I("successfully set diversifyKey into Nx");
    }
    else if (masterKeyLen == AES256_KEY_LEN) {
        uint8_t diversifyInputD1[DIVERSIFY_INPUT_SIZE] = {0};
        uint8_t diversifyInputD2[DIVERSIFY_INPUT_SIZE] = {0};
        uint8_t aes256DiversifyKey[AES256_KEY_LEN]     = {0};
        size_t aes256DiversifyKeyLen                   = 0;
        uint8_t diversifyKeyA[DIVERSIFY_KEY_LEN]       = {0};
        size_t diversifyKeyALen                        = sizeof(diversifyKeyA);
        uint8_t diversifyKeyB[DIVERSIFY_KEY_LEN]       = {0};
        size_t diversifyKeyBLen                        = sizeof(diversifyKeyB);

        memcpy(diversifyInputD1, diversifyInput, DIVERSIFY_INPUT_SIZE);
        diversifyInputD1[0] = AES256_DIVERSIFY_INPUT_D1_CONSTANT_BYTE;

        memcpy(changeAesKey.policy.chgAesKey.oldKey, aes256OldKeyBuf, sizeof(aes256OldKeyBuf));
        changeAesKey.policy.chgAesKey.oldKeyLen = sizeof(aes256OldKeyBuf);

        status = sss_mac_context_init(&macCtx, &pCtx->host_session, &masterKeyObj, algorithm, mode);
        ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

        status = sss_mac_one_go(&macCtx, diversifyInputD1, diversifyInputLen, diversifyKeyA, &diversifyKeyALen);
        ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

        memcpy(diversifyInputD2, diversifyInput, DIVERSIFY_INPUT_SIZE);
        diversifyInputD2[0] = AES256_DIVERSIFY_INPUT_D2_CONSTANT_BYTE;
        status = sss_mac_one_go(&macCtx, diversifyInputD2, diversifyInputLen, diversifyKeyB, &diversifyKeyBLen);
        ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

        if (macCtx.session != NULL) {
            sss_mac_context_free(&macCtx);
        }

        memcpy(aes256DiversifyKey, diversifyKeyA, diversifyKeyALen);
        aes256DiversifyKeyLen = diversifyKeyALen;
        memcpy(aes256DiversifyKey + aes256DiversifyKeyLen, diversifyKeyB, diversifyKeyBLen);
        aes256DiversifyKeyLen += diversifyKeyBLen;
        status = sss_key_object_init(&diversifyKeyObj, &pCtx->ks);
        ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

        status = sss_key_object_allocate_handle(
            &diversifyKeyObj, appkeyId, keyPart, cipherType, aes256DiversifyKeyLen, kKeyObject_Mode_Persistent);
        ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
        LOG_MAU8_I("diversifyKey", aes256DiversifyKey, aes256DiversifyKeyLen);
        status = sss_key_store_set_key(&pCtx->ks,
            &diversifyKeyObj,
            aes256DiversifyKey,
            aes256DiversifyKeyLen,
            (aes256DiversifyKeyLen * 8),
            &changeAesKeyPolicyList,
            sizeof(changeAesKeyPolicyList));
        ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
        LOG_I("successfully set diversifyKey into Nx");
    }

cleanup:

    if (masterKeyObj.keyStore != NULL) {
        sss_key_object_free(&masterKeyObj);
    }
    if (diversifyKeyObj.keyStore != NULL) {
        sss_key_object_free(&diversifyKeyObj);
    }
    if (macCtx.session != NULL) {
        sss_mac_context_free(&macCtx);
    }
    if (kStatus_SSS_Success == status) {
        LOG_I("ex_diversify_key_perso Example Success !!!...");
    }
    else {
        LOG_E("ex_diversify_key_perso Example Failed !!!...");
    }
    return status;
}

static void addPaddingDiversifyInput(uint8_t *diversifyInput, size_t diversifyInputBufSize, size_t *diversifyInputLen)
{
    uint16_t zeroBytesToPad = 0;
    ENSURE_OR_GO_EXIT((UINT_MAX - EX_DIVERSIFY_INPUT_PAD_BYTE_SIZE) > (*diversifyInputLen));

    zeroBytesToPad = (EX_DIVERSIFY_INPUT_SIZE -
                         ((*diversifyInputLen + EX_DIVERSIFY_INPUT_PAD_BYTE_SIZE) % EX_DIVERSIFY_INPUT_SIZE)) %
                     EX_DIVERSIFY_INPUT_SIZE;

    ENSURE_OR_GO_EXIT(diversifyInputLen != NULL);
    ENSURE_OR_GO_EXIT(diversifyInput != NULL);
    ENSURE_OR_GO_EXIT((UINT_MAX - 1) > (*diversifyInputLen));
    ENSURE_OR_GO_EXIT(*diversifyInputLen < EX_DIVERSIFY_INPUT_SIZE); // supports only 32Byte padding
    ENSURE_OR_GO_EXIT(zeroBytesToPad + (*diversifyInputLen) <= diversifyInputBufSize);

    // pad and adjust the length of the diversify key input data
    diversifyInput[(*diversifyInputLen)] = EX_DIVERSIFY_INPUT_PAD_BYTE;
    *diversifyInputLen += EX_DIVERSIFY_INPUT_PAD_BYTE_SIZE;
    ENSURE_OR_GO_EXIT((UINT_MAX - (*diversifyInputLen)) > zeroBytesToPad);
    memset(&diversifyInput[(*diversifyInputLen)], 0x00, zeroBytesToPad);

exit:
    return;
}