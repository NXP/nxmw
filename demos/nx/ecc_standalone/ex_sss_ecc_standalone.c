/*
 *
 * Copyright 2024-2025 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 */

/* ************************************************************************** */
/* Includes                                                                   */
/* ************************************************************************** */
#include "fsl_sss_api.h"
#include "fsl_sss_nx_auth.h"
#include "nx_apdu.h"
#include "nxLog_msg.h"
#include "nxEnsure.h"
#include "platform.h"

/* ************************************************************************** */
/* Local Defines                                                              */
/* ************************************************************************** */
#define EC_KEY_BIT_LEN 256

/* ************************************************************************** */
/* Structures and Typedefs                                                    */
/* ************************************************************************** */

/* ************************************************************************** */
/* Global Variables                                                           */
/* ************************************************************************** */

/* ************************************************************************** */
/* Static function declarations                                               */
/* ************************************************************************** */

/* ************************************************************************** */
/* Private Functions                                                          */
/* ************************************************************************** */

/* ************************************************************************** */
/* Public Functions                                                           */
/* ************************************************************************** */

void ex_free_conn_ctx(nx_connect_ctx_t *pConnectCtx)
{
    /* Free the key objects generated in connection context during session open */
    nx_auth_symm_static_ctx_t *static_ctx = &pConnectCtx->auth.ctx.symmAuth.static_ctx;
    nx_auth_symm_dynamic_ctx_t *dyn_ctx   = &pConnectCtx->auth.ctx.symmAuth.dyn_ctx;
    sss_host_key_object_free(&static_ctx->appKey);
    sss_host_key_object_free(&dyn_ctx->k_e2);
    sss_host_key_object_free(&dyn_ctx->k_m2);
}

int main()
{
    sss_status_t status          = kStatus_SSS_Fail;
    nx_connect_ctx_t connectCtx  = {0};
    sss_session_t hostSession    = {0};
    sss_session_t seSession      = {0};
    sss_key_store_t hostKeyStore = {0};
    sss_key_store_t seKeyStore   = {0};

    /* clang-format off */
    uint8_t digest[32]  = {1, 2, 3, 4, 5, 6, 7, 8, 9, };
    /* clang-format on */
    size_t digestLen                = sizeof(digest);
    uint8_t signature[256]          = {0};
    size_t signatureLen             = sizeof(signature);
    sss_asymmetric_t ctx_asymm      = {0};
    sss_asymmetric_t ctx_verify     = {0};
    uint32_t keyId                  = 2;
    sss_object_t keyObject          = {0};
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

    connectCtx.connType = kType_SE_Conn_Type_T1oI2C;
    connectCtx.portName = NULL;

    /* Initialize the board */
    platform_boot_direct();
    platform_init_hardware();

    /* Set the parameters for Symmetric session */
    status =
        nx_init_conn_context_symm_auth(&connectCtx, knx_AuthType_SYMM_AUTH, knx_SecureSymmType_AES128_NTAG, 0, true);
    ENSURE_OR_GO_CLEANUP(kStatus_SSS_Success == status);

    status = nx_prepare_host_for_auth(&hostSession, &hostKeyStore, &connectCtx);
    ENSURE_OR_GO_CLEANUP(kStatus_SSS_Success == status);

    /* Open a Symmetric session */
    status = sss_session_open(&seSession, kType_SSS_SE_NX, 0, kSSS_ConnectionType_Encrypted, &connectCtx);
    ENSURE_OR_GO_CLEANUP(kStatus_SSS_Success == status);

    /* Initialize keystore */
    status = sss_key_store_context_init(&seKeyStore, &seSession);
    ENSURE_OR_GO_CLEANUP(kStatus_SSS_Success == status);

    /* Allocate keystore */
    status = sss_key_store_allocate(&seKeyStore, __LINE__);
    ENSURE_OR_GO_CLEANUP(kStatus_SSS_Success == status);

    LOG_I("Running Elliptic Curve Cryptography Example ex_sss_ecc_standalone.c");

    /* Pre-requisite for Signing Part*/
    status = sss_key_object_init(&keyObject, &seKeyStore);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_key_object_allocate_handle(
        &keyObject, keyId, kSSS_KeyPart_Pair, kSSS_CipherType_EC_NIST_P, EC_KEY_BIT_LEN, kKeyObject_Mode_Persistent);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_key_store_generate_key(&seKeyStore, &keyObject, EC_KEY_BIT_LEN, &ec_key_policy);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    if (seKeyStore.session != NULL) {
        sss_key_store_context_free(&seKeyStore);
    }

    /* Do Signing */
    status =
        sss_asymmetric_context_init(&ctx_asymm, &seSession, &keyObject, kAlgorithm_SSS_ECDSA_SHA256, kMode_SSS_Sign);
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
    status =
        sss_asymmetric_context_init(&ctx_verify, &seSession, &keyObject, kAlgorithm_SSS_ECDSA_SHA256, kMode_SSS_Verify);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
    LOG_I("Do Verification");
    LOG_MAU8_I("digest", digest, digestLen);
    LOG_MAU8_I("signature", signature, signatureLen);
    status = sss_asymmetric_verify_digest(&ctx_verify, digest, digestLen, signature, signatureLen);
    LOG_I("Verification Successful !!!");

cleanup:
    if (kStatus_SSS_Success == status) {
        LOG_I("ECC-Standalone Example Success !!!...");
        platform_success_indicator();
    }
    else {
        LOG_E("ECC-Standalone Example Failed !!!...");
        platform_failure_indicator();
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
    if (seKeyStore.session != NULL) {
        sss_key_store_context_free(&seKeyStore);
    }
    sss_session_close(&seSession);
    ex_free_conn_ctx(&connectCtx);
    memset(&connectCtx, 0, sizeof(connectCtx));
    sss_host_key_store_context_free(&hostKeyStore);
    sss_host_session_close(&hostSession);
    return 0;
}
