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
#include <string.h>

/* ************************************************************************** */
/* Local Defines                                                              */
/* ************************************************************************** */

/* ************************************************************************** */
/* Structures and Typedefs                                                    */
/* ************************************************************************** */

/* ************************************************************************** */
/* Global Variables                                                           */
/* ************************************************************************** */

static ex_sss_boot_ctx_t gex_sss_ecdh_boot_ctx;

/* ************************************************************************** */
/* Static function declarations                                               */
/* ************************************************************************** */

/* ************************************************************************** */
/* Private Functions                                                          */
/* ************************************************************************** */

/* ************************************************************************** */
/* Public Functions                                                           */
/* ************************************************************************** */

#define EX_SSS_BOOT_PCONTEXT (&gex_sss_ecdh_boot_ctx)
#define EX_SSS_BOOT_EXPOSE_ARGC_ARGV 0

#include <ex_sss_main_inc.h>

#ifndef MAKE_TEST_ID
#define MAKE_TEST_ID(ID) (0xEF000000u + ID)
#endif /* MAKE_TEST_ID */

/* clang-format off */
uint8_t otherParty_publicKey[]  = {
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86,
    0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03,
    0x42, 0x00, 0x04, 0xb0, 0x62, 0x84, 0x30, 0xf3,
    0x42, 0xa0, 0x6a, 0x15, 0xf0, 0x4c, 0x61, 0xef,
    0xb4, 0x47, 0x45, 0x9a, 0x0c, 0x43, 0xd9, 0xa9,
    0x31, 0x4f, 0x09, 0xaa, 0xe6, 0x52, 0x0c, 0x63,
    0xc8, 0x63, 0x8f, 0xe5, 0x9f, 0x8f, 0xa5, 0x03,
    0x4b, 0x4b, 0xab, 0x01, 0x6e, 0x1f, 0x86, 0x6f,
    0x06, 0xc4, 0x47, 0x89, 0xe2, 0x8e, 0x49, 0x1a,
    0xaf, 0x63, 0x24, 0x30, 0xbe, 0x40, 0x91, 0xfe,
    0x90, 0x98, 0x70};
/* clang-format on */

#define EX_SSS_ECDH_ICV_DATA_LEN 16
#define EX_SSS_ECDH_ICV_DATA                                                                            \
    {                                                                                                   \
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
    }
#define EX_SSS_ECDH_INPUT_DATA_LEN 32
#define EX_SSS_ECDH_INPUT_DATA                                                                                      \
    {                                                                                                               \
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, \
            0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,                     \
    }

static sss_status_t ex_ecdh_static_keypair_export_sharedsecret(ex_sss_boot_ctx_t *pCtx)
{
    sss_status_t status                            = kStatus_SSS_Fail;
    sss_algorithm_t algorithm                      = kAlgorithm_SSS_ECDH;
    sss_mode_t mode                                = kMode_SSS_ComputeSharedSecret;
    sss_object_t keyPair                           = {0};
    uint32_t keyPairKeyId                          = 0x03;
    sss_object_t pubKeyObject                      = {0};
    sss_derive_key_t ctx_derive_key                = {0};
    sss_object_t ecdhKeyObject                     = {0};
    uint8_t ecdhKey[32]                            = {0};
    size_t ecdhKeyLen                              = sizeof(ecdhKey);
    size_t ecdhKeyBitLen                           = 0;
    sss_symmetric_t ctx_symm                       = {0};
    uint8_t icv_data[EX_SSS_ECDH_ICV_DATA_LEN]     = EX_SSS_ECDH_ICV_DATA;
    size_t icv_len                                 = sizeof(icv_data);
    uint8_t input_data[EX_SSS_ECDH_INPUT_DATA_LEN] = EX_SSS_ECDH_INPUT_DATA;
    size_t input_len                               = sizeof(input_data);
    uint8_t enc_data[EX_SSS_ECDH_INPUT_DATA_LEN]   = {0};

#if SSS_HAVE_NX_TYPE
    sss_policy_u keyGenPolicy  = {.type = KPolicy_GenECKey,
        .policy                        = {.genEcKey = {
                       .freezeKUCLimit        = 0,
                       .cardUnilateralEnabled = 0,
                       .sdmEnabled            = 0,
                       .sigmaiEnabled         = 0,
                       .ecdhEnabled           = 1,
                       .eccSignEnabled        = 0,
                       .writeCommMode         = kCommMode_SSS_Full,
                       .writeAccessCond       = Nx_AccessCondition_Auth_Required_0x1,
                       .kucLimit              = 0,
                       .userCommMode          = kCommMode_SSS_NA,
                   }}};
    sss_policy_t ec_key_policy = {.nPolicies = 1, .policies = {&keyGenPolicy}};
    pSeSession_t session_ctx   = NULL;

    ENSURE_OR_GO_CLEANUP(NULL != pCtx);
    session_ctx = &((sss_nx_session_t *)(&pCtx->session))->s_ctx;

    if (session_ctx->authType == knx_AuthType_SYMM_AUTH) {
        if (session_ctx->ctx.pdynSymmAuthCtx != NULL) {
            LOG_W("writeAccessCond (in keyGenPolicy variable) value is overwritten");
            keyGenPolicy.policy.genEcKey.writeAccessCond = session_ctx->ctx.pdynSymmAuthCtx->keyNo;
        }
        else {
            LOG_E("Invalid symm auth context !!!");
        }
    }

#if defined(SSS_HAVE_SMCOM_JRCP_V1_AM) && (SSS_HAVE_SMCOM_JRCP_V1_AM)
    if (session_ctx->authType == knx_AuthType_None) {
        LOG_W("writeAccessCond (in keyGenPolicy variable) value is overwritten");
        keyGenPolicy.policy.genEcKey.writeAccessCond = Nx_AccessCondition_Auth_Required_0x0;
    }
#endif
#endif

    /*
     * Create keypair on the NX Secure Authenticator
     */
    status = sss_key_object_init(&keyPair, &pCtx->ks);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_key_object_allocate_handle(
        &keyPair, keyPairKeyId, kSSS_KeyPart_Pair, kSSS_CipherType_EC_NIST_P, 256, kKeyObject_Mode_Persistent);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

#if SSS_HAVE_NX_TYPE
    // Generate Key pair at slot 0x03 in nx Secure Authenticator
    status = sss_key_store_generate_key(&pCtx->ks, &keyPair, 256, &ec_key_policy);
#else
    // Generate Key pair at slot 0x03 in nx Secure Authenticator
    status = sss_key_store_generate_key(&pCtx->ks, &keyPair, 256, NULL);
#endif
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    LOG_I("ECDH own Keypair %d", keyPairKeyId);

    /*
     * Store the pre-cooked other party public key on the host (Openssl or Mbedtls).
     */
    status = sss_key_object_init(&pubKeyObject, &pCtx->host_ks);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_key_object_allocate_handle(&pubKeyObject,
        MAKE_TEST_ID(__LINE__),
        kSSS_KeyPart_Public,
        kSSS_CipherType_EC_NIST_P,
        256,
        kKeyObject_Mode_Persistent);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

#if SSS_HAVE_NX_TYPE
    status = sss_key_store_set_key(&pCtx->host_ks,
        &pubKeyObject,
        otherParty_publicKey,
        sizeof(otherParty_publicKey),
        sizeof(otherParty_publicKey) * 8,
        &ec_key_policy,
        sizeof(ec_key_policy));
#else
    status = sss_key_store_set_key(&pCtx->host_ks,
        &pubKeyObject,
        otherParty_publicKey,
        sizeof(otherParty_publicKey),
        sizeof(otherParty_publicKey) * 8,
        NULL,
        0);
#endif
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    LOG_MAU8_I("ECDH peer public Key", otherParty_publicKey, sizeof(otherParty_publicKey));

    /*
     * Generate shared secret using nx Secure Authenticator.
     * Steps ==>
     * 1. Create derive key context.
     * 2. Create a key object
     *      Option 1 - key object on host (Openssl or Mbedtls) to hold the shared secret data (implemented below)
     *      Option 2 - key object on nx Secure Authenticator with valid transient / static buffer slot id (ciphet type = kSSS_CipherType_BufferSlots)
     *          Valid slot numbers:
     *          0x80 - 0x87 (Transient buffer slots. Each slot of 16 bytes.)
     *          0xC0 - 0xCF (Static buffer slots. Each slot of 16 bytes.)
     * 3. Call derive key api (sss_derive_key_dh_one_go)
     */

    status = sss_derive_key_context_init(&ctx_derive_key, &pCtx->session, &keyPair, algorithm, mode);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_key_object_init(&ecdhKeyObject, &pCtx->host_ks);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_key_object_allocate_handle(&ecdhKeyObject,
        MAKE_TEST_ID(__LINE__),
        kSSS_KeyPart_Default,
        kSSS_CipherType_AES,
        32,
        kKeyObject_Mode_Transient);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_derive_key_dh_one_go(&ctx_derive_key, &pubKeyObject, &ecdhKeyObject);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    if (pubKeyObject.keyStore != NULL) {
        sss_key_object_free(&pubKeyObject);
    }

    /*
     * Get the shared secret from host key object (Openssl or Mbedtls).
     */
    status = sss_key_store_get_key(&pCtx->host_ks, &ecdhKeyObject, ecdhKey, &ecdhKeyLen, &ecdhKeyBitLen);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    LOG_I("ECDH successful !!!");
    LOG_MAU8_I("ECDH derive Key", ecdhKey, ecdhKeyLen);

    /*
     * Do AES CBC encyption with ECDH shared secret on host.
     */
    algorithm = kAlgorithm_SSS_AES_CBC;
    mode      = kMode_SSS_Encrypt;

    status = sss_symmetric_context_init(&ctx_symm, &pCtx->host_session, &ecdhKeyObject, algorithm, mode);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_cipher_one_go(&ctx_symm, icv_data, icv_len, input_data, enc_data, input_len);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    LOG_MAU8_I("Plain text data:\n ", input_data, input_len);
    LOG_MAU8_I("IV data:\n ", icv_data, icv_len);
    LOG_MAU8_I("Encrypted data with ECDH derive key:\n ", enc_data, input_len);

cleanup:
    if (kStatus_SSS_Success == status) {
        LOG_I("ex_sss_ecdh Example Success !!!...");
    }
    else {
        LOG_E("ex_sss_ecdh Example Failed !!!...");
    }
    if (ctx_symm.session != NULL) {
        sss_symmetric_context_free(&ctx_symm);
    }
    if (keyPair.keyStore != NULL) {
        sss_key_object_free(&keyPair);
    }
    if (pubKeyObject.keyStore != NULL) {
        sss_key_object_free(&pubKeyObject);
    }
    if (ctx_derive_key.session != NULL) {
        sss_derive_key_context_free(&ctx_derive_key);
    }
    if (ecdhKeyObject.keyStore != NULL) {
        sss_key_object_free(&ecdhKeyObject);
    }

    return status;
}

#if SSS_HAVE_NX_TYPE
static sss_status_t ex_ecdh_static_keypair_internal_sharedsecret(ex_sss_boot_ctx_t *pCtx)
{
    sss_status_t status                            = kStatus_SSS_Fail;
    sss_algorithm_t algorithm                      = kAlgorithm_SSS_ECDH;
    sss_mode_t mode                                = kMode_SSS_ComputeSharedSecret;
    sss_object_t keyPair                           = {0};
    uint32_t keyPairKeyId                          = 0x04;
    sss_object_t pubKeyObject                      = {0};
    sss_derive_key_t ctx_derive_key                = {0};
    sss_object_t ecdhKeyObject                     = {0};
    sss_symmetric_t ctx_symm                       = {0};
    uint8_t icv_data[EX_SSS_ECDH_ICV_DATA_LEN]     = EX_SSS_ECDH_ICV_DATA;
    size_t icv_len                                 = sizeof(icv_data);
    uint8_t input_data[EX_SSS_ECDH_INPUT_DATA_LEN] = EX_SSS_ECDH_INPUT_DATA;
    size_t input_len                               = sizeof(input_data);
    uint8_t enc_data[EX_SSS_ECDH_INPUT_DATA_LEN]   = {0};
    uint32_t intSharedSecretId                     = kSE_CryptoDataSrc_TB0;

    sss_policy_u keyGenPolicy  = {.type = KPolicy_GenECKey,
        .policy                        = {.genEcKey = {
                       .freezeKUCLimit        = 0,
                       .cardUnilateralEnabled = 0,
                       .sdmEnabled            = 0,
                       .sigmaiEnabled         = 0,
                       .ecdhEnabled           = 1,
                       .eccSignEnabled        = 0,
                       .writeCommMode         = kCommMode_SSS_Full,
                       .writeAccessCond       = Nx_AccessCondition_Auth_Required_0x1,
                       .kucLimit              = 0,
                       .userCommMode          = kCommMode_SSS_NA,
                   }}};
    sss_policy_t ec_key_policy = {.nPolicies = 1, .policies = {&keyGenPolicy}};
    pSeSession_t session_ctx   = NULL;

    ENSURE_OR_GO_CLEANUP(NULL != pCtx)
    session_ctx = &((sss_nx_session_t *)(&pCtx->session))->s_ctx;
    // This part of code not mandtory to user, this code used to make re-running the example possible.
    if (session_ctx->authType == knx_AuthType_SYMM_AUTH) {
        if (session_ctx->ctx.pdynSymmAuthCtx != NULL) {
            LOG_W("writeAccessCond (in keyGenPolicy variable) value is overwritten");
            keyGenPolicy.policy.genEcKey.writeAccessCond = session_ctx->ctx.pdynSymmAuthCtx->keyNo;
        }
        else {
            LOG_E("Invalid symm auth context !!!");
        }
    }

#if defined(SSS_HAVE_SMCOM_JRCP_V1_AM) && (SSS_HAVE_SMCOM_JRCP_V1_AM)
    if (session_ctx->authType == knx_AuthType_None) {
        LOG_W("writeAccessCond (in keyGenPolicy variable) value is overwritten");
        keyGenPolicy.policy.genEcKey.writeAccessCond = Nx_AccessCondition_Auth_Required_0x0;
    }
#endif

    /*
     * Create keypair on the NX Secure Authenticator
     */
    status = sss_key_object_init(&keyPair, &pCtx->ks);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_key_object_allocate_handle(
        &keyPair, keyPairKeyId, kSSS_KeyPart_Pair, kSSS_CipherType_EC_NIST_P, 256, kKeyObject_Mode_Persistent);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    // Generate Key pair at slot 0x03 in nx Secure Authenticator
    status = sss_key_store_generate_key(&pCtx->ks, &keyPair, 256, &ec_key_policy);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    LOG_I("ECDH own Keypair %d", keyPairKeyId);

    /*
     * Store the pre-cooked other party public key on the host (Openssl or Mbedtls).
     */
    status = sss_key_object_init(&pubKeyObject, &pCtx->host_ks);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_key_object_allocate_handle(&pubKeyObject,
        MAKE_TEST_ID(__LINE__),
        kSSS_KeyPart_Public,
        kSSS_CipherType_EC_NIST_P,
        256,
        kKeyObject_Mode_Persistent);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_key_store_set_key(&pCtx->host_ks,
        &pubKeyObject,
        otherParty_publicKey,
        sizeof(otherParty_publicKey),
        sizeof(otherParty_publicKey) * 8,
        &ec_key_policy,
        sizeof(ec_key_policy));
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    LOG_MAU8_I("ECDH peer public Key", otherParty_publicKey, sizeof(otherParty_publicKey));

    /*
     * Generate shared secret using nx Secure Authenticator.
     * Steps ==>
     * 1. Create derive key context.
     * 2. Create a key object
     *      Option 1 - key object on host (Openssl or Mbedtls) to hold the shared secret data
     *      Option 2 - key object on nx Secure Authenticator with valid transient / static buffer slot id (ciphet type = kSSS_CipherType_BufferSlots)
     *          Valid slot numbers:
     *          0x80 - 0x87 (Transient buffer slots. Each slot of 16 bytes.)    (implemented below)
     *          0xC0 - 0xCF (Static buffer slots. Each slot of 16 bytes.)
     * 3. Call derive key api (sss_derive_key_dh_one_go)
     */

    status = sss_derive_key_context_init(&ctx_derive_key, &pCtx->session, &keyPair, algorithm, mode);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_key_object_init(&ecdhKeyObject, &pCtx->ks);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_key_object_allocate_handle(
        &ecdhKeyObject, intSharedSecretId, kSSS_KeyPart_Default, kSSS_CipherType_BufferSlots, 32, kKeyObject_Mode_None);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_derive_key_dh_one_go(&ctx_derive_key, &pubKeyObject, &ecdhKeyObject);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    LOG_I("ECDH successful !!!");

    /*
     * Do AES CBC encyption with ECDH shared secret in SE internal buffer.
     */
    algorithm = kAlgorithm_SSS_AES_CBC;
    mode      = kMode_SSS_Encrypt;
    memset(enc_data, 0, sizeof(enc_data));

    status = sss_symmetric_context_init(&ctx_symm, &pCtx->session, &ecdhKeyObject, algorithm, mode);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_cipher_one_go(&ctx_symm, icv_data, icv_len, input_data, enc_data, input_len);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    LOG_MAU8_I("Plain text data:\n ", input_data, input_len);
    LOG_MAU8_I("IV data:\n ", icv_data, icv_len);
    LOG_MAU8_I("Encrypted data with internal derive key :\n ", enc_data, input_len);

cleanup:
    if (kStatus_SSS_Success == status) {
        LOG_I("ex_sss_ecdh Example Success !!!...");
    }
    else {
        LOG_E("ex_sss_ecdh Example Failed !!!...");
    }
    if (ctx_symm.session != NULL) {
        sss_symmetric_context_free(&ctx_symm);
    }
    if (keyPair.keyStore != NULL) {
        sss_key_object_free(&keyPair);
    }
    if (pubKeyObject.keyStore != NULL) {
        sss_key_object_free(&pubKeyObject);
    }
    if (ctx_derive_key.session != NULL) {
        sss_derive_key_context_free(&ctx_derive_key);
    }
    if (ecdhKeyObject.keyStore != NULL) {
        sss_key_object_free(&ecdhKeyObject);
    }

    return status;
}

static sss_status_t ex_ecdh_ephem_keypair_export_sharedsecret(ex_sss_boot_ctx_t *pCtx)
{
    sss_status_t status                            = kStatus_SSS_Fail;
    sss_algorithm_t algorithm                      = kAlgorithm_SSS_ECDH;
    sss_mode_t mode                                = kMode_SSS_ComputeSharedSecret;
    sss_object_t keyPair                           = {0};
    uint32_t keyPairKeyId                          = NX_KEY_ID_EPHEM_NISTP256;
    sss_object_t pubKeyObject                      = {0};
    sss_derive_key_t ctx_derive_key                = {0};
    sss_object_t ecdhKeyObject                     = {0};
    uint8_t ecdhKey[32]                            = {0};
    size_t ecdhKeyLen                              = sizeof(ecdhKey);
    size_t ecdhKeyBitLen                           = 0;
    sss_symmetric_t ctx_symm                       = {0};
    uint8_t icv_data[EX_SSS_ECDH_ICV_DATA_LEN]     = EX_SSS_ECDH_ICV_DATA;
    size_t icv_len                                 = sizeof(icv_data);
    uint8_t input_data[EX_SSS_ECDH_INPUT_DATA_LEN] = EX_SSS_ECDH_INPUT_DATA;
    size_t input_len                               = sizeof(input_data);
    uint8_t enc_data[EX_SSS_ECDH_INPUT_DATA_LEN]   = {0};

    sss_policy_u keyGenPolicy  = {.type = KPolicy_GenECKey,
        .policy                        = {.genEcKey = {
                       .freezeKUCLimit        = 0,
                       .cardUnilateralEnabled = 0,
                       .sdmEnabled            = 0,
                       .sigmaiEnabled         = 0,
                       .ecdhEnabled           = 1,
                       .eccSignEnabled        = 0,
                       .writeCommMode         = kCommMode_SSS_Full,
                       .writeAccessCond       = Nx_AccessCondition_Auth_Required_0x1,
                       .kucLimit              = 0,
                       .userCommMode          = kCommMode_SSS_NA,
                   }}};
    sss_policy_t ec_key_policy = {.nPolicies = 1, .policies = {&keyGenPolicy}};
    pSeSession_t session_ctx   = NULL;

    ENSURE_OR_GO_CLEANUP(NULL != pCtx)
    session_ctx = &((sss_nx_session_t *)(&pCtx->session))->s_ctx;

    if (session_ctx->authType == knx_AuthType_SYMM_AUTH) {
        if (session_ctx->ctx.pdynSymmAuthCtx != NULL) {
            LOG_W("writeAccessCond (in keyGenPolicy variable) value is overwritten");
            keyGenPolicy.policy.genEcKey.writeAccessCond = session_ctx->ctx.pdynSymmAuthCtx->keyNo;
        }
        else {
            LOG_E("Invalid symm auth context !!!");
        }
    }

#if defined(SSS_HAVE_SMCOM_JRCP_V1_AM) && (SSS_HAVE_SMCOM_JRCP_V1_AM)
    if (session_ctx->authType == knx_AuthType_None) {
        LOG_W("writeAccessCond (in keyGenPolicy variable) value is overwritten");
        keyGenPolicy.policy.genEcKey.writeAccessCond = Nx_AccessCondition_Auth_Required_0x0;
    }
#endif

    /*
     * Create keypair on the NX Secure Authenticator
     */
    status = sss_key_object_init(&keyPair, &pCtx->ks);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_key_object_allocate_handle(
        &keyPair, keyPairKeyId, kSSS_KeyPart_Pair, kSSS_CipherType_EC_NIST_P, 256, kKeyObject_Mode_Transient);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    // Generate Key pair at slot 0xFE (Ephermeral key NIST-P 256) in nx Secure Authenticator
    status = sss_key_store_generate_key(&pCtx->ks, &keyPair, 256, &ec_key_policy);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    LOG_I("ECDH own Keypair %d", keyPairKeyId);

    /*
     * Store the pre-cooked other party public key on the host (Openssl or Mbedtls).
     */
    status = sss_key_object_init(&pubKeyObject, &pCtx->host_ks);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_key_object_allocate_handle(&pubKeyObject,
        MAKE_TEST_ID(__LINE__),
        kSSS_KeyPart_Public,
        kSSS_CipherType_EC_NIST_P,
        256,
        kKeyObject_Mode_Persistent);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_key_store_set_key(&pCtx->host_ks,
        &pubKeyObject,
        otherParty_publicKey,
        sizeof(otherParty_publicKey),
        sizeof(otherParty_publicKey) * 8,
        &ec_key_policy,
        sizeof(ec_key_policy));
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    LOG_MAU8_I("ECDH peer public Key", otherParty_publicKey, sizeof(otherParty_publicKey));

    /*
     * Generate shared secret using nx Secure Authenticator.
     * Steps ==>
     * 1. Create derive key context.
     * 2. Create a key object
     *      Option 1 - key object on host (Openssl or Mbedtls) to hold the shared secret data (implemented below)
     *      Option 2 - key object on nx Secure Authenticator with valid transient / static buffer slot id (ciphet type = kSSS_CipherType_BufferSlots)
     *          Valid slot numbers:
     *          0x80 - 0x87 (Transient buffer slots. Each slot of 16 bytes.)
     *          0xC0 - 0xCF (Static buffer slots. Each slot of 16 bytes.)
     * 3. Call derive key api (sss_derive_key_dh_one_go)
     */

    status = sss_derive_key_context_init(&ctx_derive_key, &pCtx->session, &keyPair, algorithm, mode);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_key_object_init(&ecdhKeyObject, &pCtx->host_ks);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_key_object_allocate_handle(&ecdhKeyObject,
        MAKE_TEST_ID(__LINE__),
        kSSS_KeyPart_Default,
        kSSS_CipherType_AES,
        32,
        kKeyObject_Mode_Transient);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_derive_key_dh_one_go(&ctx_derive_key, &pubKeyObject, &ecdhKeyObject);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    /*
     * Get the shared secret from host key object (Openssl or Mbedtls).
     */
    status = sss_key_store_get_key(&pCtx->host_ks, &ecdhKeyObject, ecdhKey, &ecdhKeyLen, &ecdhKeyBitLen);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    LOG_I("ECDH successful !!!");
    LOG_MAU8_I("ECDH derive Key", ecdhKey, ecdhKeyLen);

    /*
     * Do AES CBC encyption with ECDH shared secret on host.
     */
    algorithm = kAlgorithm_SSS_AES_CBC;
    mode      = kMode_SSS_Encrypt;

    status = sss_symmetric_context_init(&ctx_symm, &pCtx->host_session, &ecdhKeyObject, algorithm, mode);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_cipher_one_go(&ctx_symm, icv_data, icv_len, input_data, enc_data, input_len);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    LOG_MAU8_I("Plain text data:\n ", input_data, input_len);
    LOG_MAU8_I("IV data:\n ", icv_data, icv_len);
    LOG_MAU8_I("Encrypted data with ECDH derive key:\n ", enc_data, input_len);

cleanup:
    if (kStatus_SSS_Success == status) {
        LOG_I("ex_sss_ecdh Example Success !!!...");
    }
    else {
        LOG_E("ex_sss_ecdh Example Failed !!!...");
    }
    if (ctx_symm.session != NULL) {
        sss_symmetric_context_free(&ctx_symm);
    }
    if (keyPair.keyStore != NULL) {
        sss_key_object_free(&keyPair);
    }
    if (pubKeyObject.keyStore != NULL) {
        sss_key_object_free(&pubKeyObject);
    }
    if (ctx_derive_key.session != NULL) {
        sss_derive_key_context_free(&ctx_derive_key);
    }
    if (ecdhKeyObject.keyStore != NULL) {
        sss_key_object_free(&ecdhKeyObject);
    }

    return status;
}

static sss_status_t ex_ecdh_ephem_keypair_internal_sharedsecret(ex_sss_boot_ctx_t *pCtx)
{
    sss_status_t status                            = kStatus_SSS_Fail;
    sss_algorithm_t algorithm                      = kAlgorithm_SSS_ECDH;
    sss_mode_t mode                                = kMode_SSS_ComputeSharedSecret;
    sss_object_t keyPair                           = {0};
    uint32_t keyPairKeyId                          = NX_KEY_ID_EPHEM_NISTP256;
    sss_object_t pubKeyObject                      = {0};
    sss_derive_key_t ctx_derive_key                = {0};
    sss_object_t ecdhKeyObject                     = {0};
    sss_symmetric_t ctx_symm                       = {0};
    uint8_t icv_data[EX_SSS_ECDH_ICV_DATA_LEN]     = EX_SSS_ECDH_ICV_DATA;
    size_t icv_len                                 = sizeof(icv_data);
    uint8_t input_data[EX_SSS_ECDH_INPUT_DATA_LEN] = EX_SSS_ECDH_INPUT_DATA;
    size_t input_len                               = sizeof(input_data);
    uint8_t enc_data[EX_SSS_ECDH_INPUT_DATA_LEN]   = {0};
    uint32_t intSharedSecretId                     = kSE_CryptoDataSrc_TB0;

    sss_policy_u keyGenPolicy  = {.type = KPolicy_GenECKey,
        .policy                        = {.genEcKey = {
                       .freezeKUCLimit        = 0,
                       .cardUnilateralEnabled = 0,
                       .sdmEnabled            = 0,
                       .sigmaiEnabled         = 0,
                       .ecdhEnabled           = 1,
                       .eccSignEnabled        = 0,
                       .writeCommMode         = kCommMode_SSS_Full,
                       .writeAccessCond       = Nx_AccessCondition_Auth_Required_0x1,
                       .kucLimit              = 0,
                       .userCommMode          = kCommMode_SSS_NA,
                   }}};
    sss_policy_t ec_key_policy = {.nPolicies = 1, .policies = {&keyGenPolicy}};
    pSeSession_t session_ctx   = NULL;

    ENSURE_OR_GO_CLEANUP(NULL != pCtx)
    session_ctx = &((sss_nx_session_t *)(&pCtx->session))->s_ctx;

    if (session_ctx->authType == knx_AuthType_SYMM_AUTH) {
        if (session_ctx->ctx.pdynSymmAuthCtx != NULL) {
            LOG_W("writeAccessCond (in keyGenPolicy variable) value is overwritten");
            keyGenPolicy.policy.genEcKey.writeAccessCond = session_ctx->ctx.pdynSymmAuthCtx->keyNo;
        }
        else {
            LOG_E("Invalid symm auth context !!!");
        }
    }

#if defined(SSS_HAVE_SMCOM_JRCP_V1_AM) && (SSS_HAVE_SMCOM_JRCP_V1_AM)
    if (session_ctx->authType == knx_AuthType_None) {
        LOG_W("writeAccessCond (in keyGenPolicy variable) value is overwritten");
        keyGenPolicy.policy.genEcKey.writeAccessCond = Nx_AccessCondition_Auth_Required_0x0;
    }
#endif

    /*
     * Create keypair on the NX Secure Authenticator
     */
    status = sss_key_object_init(&keyPair, &pCtx->ks);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_key_object_allocate_handle(
        &keyPair, keyPairKeyId, kSSS_KeyPart_Pair, kSSS_CipherType_EC_NIST_P, 256, kKeyObject_Mode_Transient);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    // Generate Key pair at slot 0xFE (Ephermeral key NIST-P 256) in nx Secure Authenticator
    status = sss_key_store_generate_key(&pCtx->ks, &keyPair, 256, &ec_key_policy);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    LOG_I("ECDH own Keypair %d", keyPairKeyId);

    /*
     * Store the pre-cooked other party public key on the host (Openssl or Mbedtls).
     */
    status = sss_key_object_init(&pubKeyObject, &pCtx->host_ks);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_key_object_allocate_handle(&pubKeyObject,
        MAKE_TEST_ID(__LINE__),
        kSSS_KeyPart_Public,
        kSSS_CipherType_EC_NIST_P,
        256,
        kKeyObject_Mode_Persistent);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_key_store_set_key(&pCtx->host_ks,
        &pubKeyObject,
        otherParty_publicKey,
        sizeof(otherParty_publicKey),
        sizeof(otherParty_publicKey) * 8,
        &ec_key_policy,
        sizeof(ec_key_policy));
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    LOG_MAU8_I("ECDH peer public Key", otherParty_publicKey, sizeof(otherParty_publicKey));

    /*
     * Generate shared secret using nx Secure Authenticator.
     * Steps ==>
     * 1. Create derive key context.
     * 2. Create a key object
     *      Option 1 - key object on host (Openssl or Mbedtls) to hold the shared secret data
     *      Option 2 - key object on nx Secure Authenticator with valid transient / static buffer slot id (ciphet type = kSSS_CipherType_BufferSlots)
     *          Valid slot numbers:
     *          0x80 - 0x87 (Transient buffer slots. Each slot of 16 bytes.)    (implemented below)
     *          0xC0 - 0xCF (Static buffer slots. Each slot of 16 bytes.)
     * 3. Call derive key api (sss_derive_key_dh_one_go)
     */

    status = sss_derive_key_context_init(&ctx_derive_key, &pCtx->session, &keyPair, algorithm, mode);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_key_object_init(&ecdhKeyObject, &pCtx->ks);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_key_object_allocate_handle(
        &ecdhKeyObject, intSharedSecretId, kSSS_KeyPart_Default, kSSS_CipherType_BufferSlots, 32, kKeyObject_Mode_None);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_derive_key_dh_one_go(&ctx_derive_key, &pubKeyObject, &ecdhKeyObject);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    LOG_I("ECDH successful !!!");

    /*
     * Do AES CBC encyption with ECDH shared secret in SE internal buffer.
     */
    algorithm = kAlgorithm_SSS_AES_CBC;
    mode      = kMode_SSS_Encrypt;
    memset(enc_data, 0, sizeof(enc_data));

    status = sss_symmetric_context_init(&ctx_symm, &pCtx->session, &ecdhKeyObject, algorithm, mode);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_cipher_one_go(&ctx_symm, icv_data, icv_len, input_data, enc_data, input_len);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    LOG_MAU8_I("Plain text data:\n ", input_data, input_len);
    LOG_MAU8_I("IV data:\n ", icv_data, icv_len);
    LOG_MAU8_I("Encrypted data with internal derive key :\n ", enc_data, input_len);

cleanup:
    if (kStatus_SSS_Success == status) {
        LOG_I("ex_sss_ecdh Example Success !!!...");
    }
    else {
        LOG_E("ex_sss_ecdh Example Failed !!!...");
    }
    if (ctx_symm.session != NULL) {
        sss_symmetric_context_free(&ctx_symm);
    }
    if (keyPair.keyStore != NULL) {
        sss_key_object_free(&keyPair);
    }
    if (pubKeyObject.keyStore != NULL) {
        sss_key_object_free(&pubKeyObject);
    }
    if (ctx_derive_key.session != NULL) {
        sss_derive_key_context_free(&ctx_derive_key);
    }
    if (ecdhKeyObject.keyStore != NULL) {
        sss_key_object_free(&ecdhKeyObject);
    }

    return status;
}
#endif

sss_status_t ex_sss_entry(ex_sss_boot_ctx_t *pCtx)
{
    sss_status_t status = kStatus_SSS_Fail;

    LOG_I("\n");
    LOG_I("ECDH with static keypair. Export shared secrect to keyobject.");
    status = ex_ecdh_static_keypair_export_sharedsecret(pCtx);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

#if SSS_HAVE_NX_TYPE
    LOG_I("\n");
    LOG_I("ECDH with static keypair. Store shared secrect to internal buffer.");
    status = ex_ecdh_static_keypair_internal_sharedsecret(pCtx);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    LOG_I("\n");
    LOG_I("ECDH with ephemeral keypair. Export shared secrect to keyobject.");
    status = ex_ecdh_ephem_keypair_export_sharedsecret(pCtx);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    LOG_I("\n");
    LOG_I("ECDH with ephemeral keypair. Store shared secrect to internal buffer.");
    status = ex_ecdh_ephem_keypair_internal_sharedsecret(pCtx);
#endif

cleanup:
    return status;
}
