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
#include "fsl_sss_nx_auth_types.h"

/* ************************************************************************** */
/* Local Defines                                                              */
/* ************************************************************************** */
#define AES128_KEY_LEN 16
#define AES_KEY_ID 0x10

/* ************************************************************************** */
/* Structures and Typedefs                                                    */
/* ************************************************************************** */

/* ************************************************************************** */
/* Global Variables                                                           */
/* ************************************************************************** */
static ex_sss_boot_ctx_t gex_sss_ecc_boot_ctx;

/* ************************************************************************** */
/* Static function declarations                                               */
/* ************************************************************************** */

/* ************************************************************************** */
/* Private Functions                                                          */
/* ************************************************************************** */

/* ************************************************************************** */
/* Public Functions                                                           */
/* ************************************************************************** */

#define EX_SSS_BOOT_PCONTEXT (&gex_sss_ecc_boot_ctx)
#define EX_SSS_BOOT_EXPOSE_ARGC_ARGV 0

#include <ex_sss_main_inc.h>

sss_status_t ex_sss_entry(ex_sss_boot_ctx_t *pCtx)
{
    sss_status_t status = kStatus_SSS_Fail;
    sss_algorithm_t algorithm;
    sss_mode_t mode;
    sss_key_part_t keyPart;
    sss_cipher_type_t cipherType;

    /* clang-format off */
    uint8_t srcData[16]            = {0x48 ,0x45 ,0x4c ,0x4c ,0x4f ,0x48 ,0x45 ,0x4c ,0x4c ,0x4f ,0x48 ,0x45 ,0x4c ,0x4c ,0x4f ,0x31}; /*HELLOHELLOHELLO1*/
    size_t srcDataLen              = sizeof(srcData);
    uint8_t aesKey[AES128_KEY_LEN] = {0x48 ,0x45 ,0x4c ,0x4c ,0x4f ,0x48 ,0x45 ,0x4c ,0x4c ,0x4f ,0x48 ,0x45 ,0x4c ,0x4c ,0x4f ,0x31}; /*HELLOHELLOHELLO1*/
    size_t aesKeyLen               = AES128_KEY_LEN;
    uint8_t expectedEncData[16]    = {0x32, 0xA6, 0x04, 0x88, 0xC5, 0xB3, 0xFF, 0x40, 0x50, 0xAF, 0x56, 0xA5, 0x68, 0xAE, 0xD1, 0x05};
    size_t expectedEncDataLen      = sizeof(expectedEncData);
    uint8_t encData[16]            = {0};
    size_t encDataLen              = sizeof(encData);
    uint8_t decData[16]            = {0};
    size_t decDataLen              = sizeof(decData);
    uint8_t icv[16]                = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    size_t icvLen                  = sizeof(icv);
    uint32_t keyId                 = AES_KEY_ID;
    size_t keyByteLenMax           = AES128_KEY_LEN;
#if SSS_HAVE_NX_TYPE
    sss_policy_u aeskeyPolicy      = {.type = KPolicy_ChgAESKey,
        .policy                              = {.chgAesKey = {
                                                    .hkdfEnabled        = 0,
                                                    .hmacEnabled        = 0,
                                                    .aeadEncIntEnabled  = 0,
                                                    .aeadEncEnabled     = 0,
                                                    .aeadDecEnabled     = 0,
                                                    .ecb_cbc_EncEnabled = 1,
                                                    .ecb_cbc_DecEnabled = 1,
                                                    .macSignEnabled     = 0,
                                                    .macVerifyEnabled   = 0,
                   }}};
    sss_policy_t aeskeyPolicyList   = {.nPolicies = 1, .policies = {&aeskeyPolicy}};
#endif // SSS_HAVE_NX_TYPE
    sss_object_t keyObject = { 0 };
    sss_symmetric_t ctx_symm_encrypt = { 0 };
    sss_symmetric_t ctx_symm_decrypt = { 0 };
    /* clang-format on */

    algorithm  = kAlgorithm_SSS_AES_CBC;
    keyPart    = kSSS_KeyPart_Default;
    cipherType = kSSS_CipherType_AES;
    mode       = kMode_SSS_Encrypt;

    LOG_I("Running AES Symmetric Example ex_sss_symmetric.c");

    /* Pre-requisite for encryption Part*/
    status = sss_key_object_init(&keyObject, &pCtx->ks);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_key_object_allocate_handle(
        &keyObject, keyId, keyPart, cipherType, keyByteLenMax, kKeyObject_Mode_Persistent);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

#if SSS_HAVE_NX_TYPE
    status = sss_key_store_set_key(
        &pCtx->ks, &keyObject, aesKey, aesKeyLen, aesKeyLen * 8, &aeskeyPolicyList, sizeof(aeskeyPolicyList));
#else
    status = sss_key_store_set_key(&pCtx->ks, &keyObject, aesKey, aesKeyLen, aesKeyLen * 8, NULL, 0);
#endif // SSS_HAVE_NX_TYPE
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_symmetric_context_init(&ctx_symm_encrypt, &pCtx->session, &keyObject, algorithm, mode);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    LOG_I("Do Encryption");
    /* reset iv */
    memset(icv, 0, icvLen);
    LOG_MAU8_I("icv", icv, icvLen);
    LOG_MAU8_I("srcData", srcData, icvLen);

    /*Do Encryption*/
    status = sss_cipher_one_go(&ctx_symm_encrypt, icv, icvLen, srcData, encData, encDataLen);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    if (0 != memcmp(encData, expectedEncData, expectedEncDataLen)) {
        status = kStatus_SSS_Fail;
    }
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    if (ctx_symm_encrypt.session != NULL) {
        sss_symmetric_context_free(&ctx_symm_encrypt);
    }

    LOG_I("Encryption successful !!!");
    LOG_MAU8_I("Encrypted data", encData, encDataLen);

    algorithm  = kAlgorithm_SSS_AES_CBC;
    keyPart    = kSSS_KeyPart_Default;
    cipherType = kSSS_CipherType_AES;
    mode       = kMode_SSS_Decrypt;

    status = sss_symmetric_context_init(&ctx_symm_decrypt, &pCtx->session, &keyObject, algorithm, mode);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    LOG_I("Do Decryption");

    LOG_MAU8_I("icv", icv, icvLen);
    LOG_MAU8_I("Encrypted data", encData, encDataLen);

    status = sss_cipher_one_go(&ctx_symm_decrypt, icv, icvLen, encData, decData, decDataLen);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    if (0 != memcmp(decData, srcData, srcDataLen)) {
        status = kStatus_SSS_Fail;
    }
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    LOG_I("Decryption successful !!!");
    LOG_MAU8_I("Decrypted data", decData, decDataLen);

cleanup:
    if (kStatus_SSS_Success == status) {
        LOG_I("ex_sss_symmetric Example Success !!!...");
    }
    else {
        LOG_E("ex_sss_symmetric Example Failed !!!...");
    }
    if (ctx_symm_encrypt.session != NULL) {
        sss_symmetric_context_free(&ctx_symm_encrypt);
    }
    if (ctx_symm_decrypt.session != NULL) {
        sss_symmetric_context_free(&ctx_symm_decrypt);
    }
    if (keyObject.keyStore != NULL) {
        sss_key_object_free(&keyObject);
    }
    return status;
}