/*
 *
 * Copyright 2022-2024 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 */

/* ************************************************************************** */
/* Includes                                                                   */
/* ************************************************************************** */
#include "ex_sss_boot.h"
#include "nxEnsure.h"
#include "nxLog_msg.h"
#if defined(SSS_HAVE_HOST_PCWINDOWS) && (SSS_HAVE_HOST_PCWINDOWS) || \
    defined(SSS_HAVE_HOST_PCLINUX64) && (SSS_HAVE_HOST_PCLINUX64) || \
    defined(SSS_HAVE_HOST_RASPBIAN) && (SSS_HAVE_HOST_RASPBIAN)
#include <stdio.h>
#endif // File sytsem based hosts
/* ************************************************************************** */
/* Local Defines                                                              */
/* ************************************************************************** */
#define EC_KEY_BIT_LEN 256
#define PUBKEY_LEN_MAX 92
#define PUBKEY_FILE "public_key.der"

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
    /* clang-format off */
    uint8_t digest[32]  = {1, 2, 3, 4, 5, 6, 7, 8, 9, };
    /* clang-format on */
    size_t digestLen            = sizeof(digest);
    uint8_t signature[256]      = {0};
    size_t signatureLen         = sizeof(signature);
    sss_asymmetric_t ctx_asymm  = {0};
    sss_asymmetric_t ctx_verify = {0};
    uint32_t keyId              = 2;
    sss_object_t keyObject      = {0};
#if SSS_HAVE_NX_TYPE
    const sss_policy_u keyGenPolicy = {.type = KPolicy_GenECKey,
        .policy                              = {.genEcKey = {
                       .freezeKUCLimit        = 0,
                       .cardUnilateralEnabled = 0,
                       .sdmEnabled            = 1,
                       .sigmaiEnabled         = 0,
                       .ecdhEnabled           = 0,
                       .eccSignEnabled        = 1,
                       .writeCommMode         = kCommMode_SSS_Full,
                       .writeAccessCond       = Nx_AccessCondition_Auth_Required_0x0,
                       .kucLimit              = 0,
                       .userCommMode          = kCommMode_SSS_NA,
                   }}};
    sss_policy_t ec_key_policy      = {.nPolicies = 1, .policies = {&keyGenPolicy}};
#endif

    ENSURE_OR_GO_CLEANUP(NULL != pCtx)

    LOG_I("Running Elliptic Curve Cryptography Example ex_sss_ecc.c");

    /* Pre-requisite for Signing Part*/
    status = sss_key_object_init(&keyObject, &pCtx->ks);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_key_object_allocate_handle(
        &keyObject, keyId, kSSS_KeyPart_Pair, kSSS_CipherType_EC_NIST_P, 256, kKeyObject_Mode_Persistent);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

#if SSS_HAVE_NX_TYPE
    status = sss_key_store_generate_key(&pCtx->ks, &keyObject, 256, &ec_key_policy);
#else
    status = sss_key_store_generate_key(&pCtx->ks, &keyObject, 256, NULL);
#endif
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    /* Storing the generated public key in a file for file system based hosts, i.. */
#if defined(SSS_HAVE_HOST_PCWINDOWS) && (SSS_HAVE_HOST_PCWINDOWS) || \
    defined(SSS_HAVE_HOST_PCLINUX64) && (SSS_HAVE_HOST_PCLINUX64) || \
    defined(SSS_HAVE_HOST_RASPBIAN) && (SSS_HAVE_HOST_RASPBIAN)
    {
        uint8_t publicKey[PUBKEY_LEN_MAX] = {0};
        size_t publicKeyLen               = sizeof(publicKey);
        size_t publicKeyBitLen            = 0;
        FILE *pPubKeyFile                 = NULL;
        size_t numBytesWritten            = 0;

        /* Extracting the public key */
        status = sss_key_store_get_key(&pCtx->ks, &keyObject, publicKey, &publicKeyLen, &publicKeyBitLen);
        ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

        /* Writing the public key in DER format in public_key.der */
        pPubKeyFile = fopen(PUBKEY_FILE, "w");
        if (NULL == pPubKeyFile) {
            LOG_W("Unable to open a file to store the public key");
        }
        else {
            numBytesWritten = fwrite(publicKey, sizeof(uint8_t), publicKeyLen, pPubKeyFile);
            if (numBytesWritten != publicKeyLen) {
                LOG_W("Failed to write public key into the file");
            }
            else {
                LOG_I("Storing the generated public key in %s (in the directory where this demo is run from)",
                    PUBKEY_FILE);
            }
            if (0 != fclose(pPubKeyFile)) {
                LOG_W("Failed to close the file handle");
            }
        }
    }
#endif // File system based hosts

    /* Do Signing */
    status = sss_asymmetric_context_init(
        &ctx_asymm, &pCtx->session, &keyObject, kAlgorithm_SSS_ECDSA_SHA256, kMode_SSS_Sign);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
    LOG_I("Do Signing");
    LOG_MAU8_I("digest", digest, digestLen);
    status = sss_asymmetric_sign_digest(&ctx_asymm, digest, digestLen, signature, &signatureLen);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
    LOG_MAU8_I("signature", signature, signatureLen);
    LOG_I("Signing Successful !!!");

    if (ctx_asymm.session != NULL) {
        sss_asymmetric_context_free(&ctx_asymm);
    }

    /* Do Verification */
    status = sss_asymmetric_context_init(
        &ctx_verify, &pCtx->session, &keyObject, kAlgorithm_SSS_ECDSA_SHA256, kMode_SSS_Verify);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
    LOG_I("Do Verification");
    LOG_MAU8_I("digest", digest, digestLen);
    LOG_MAU8_I("signature", signature, signatureLen);
    status = sss_asymmetric_verify_digest(&ctx_verify, digest, digestLen, signature, signatureLen);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
    LOG_I("Verification Successful !!!");

cleanup:
    if (kStatus_SSS_Success == status) {
        LOG_I("ex_sss_ecc Example Success !!!...");
    }
    else {
        LOG_E("ex_sss_ecc Example Failed !!!...");
    }
    if (ctx_asymm.session != NULL) {
        sss_asymmetric_context_free(&ctx_asymm);
    }
    if (ctx_verify.session != NULL) {
        sss_asymmetric_context_free(&ctx_verify);
    }
    if (keyObject.keyStore != NULL) {
        sss_key_object_free(&keyObject);
    }

    return status;
}