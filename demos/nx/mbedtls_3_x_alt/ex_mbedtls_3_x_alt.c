/*
 *
 * Copyright 2025 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 */

/* ************************************************************************** */
/* Includes                                                                   */
/* ************************************************************************** */
#include "ex_sss_boot.h"
#include "nxEnsure.h"
#include "nxLog_msg.h"
#include "ex_mbedtls_3_x_alt.h"

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/mbedtls_config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif
/* ************************************************************************** */
/* Local Defines                                                              */
/* ************************************************************************** */
#define EX_SSS_BOOT_PCONTEXT (&gex_mbedtks3x_alt_boot_ctx)
#define EX_SSS_BOOT_EXPOSE_ARGC_ARGV 0
#define KEY_BIT_LENGTH 256

/* ************************************************************************** */
/* Structures and Typedefs                                                    */
/* ************************************************************************** */

/* ************************************************************************** */
/* Global Variables                                                           */
/* ************************************************************************** */
static ex_sss_boot_ctx_t gex_mbedtks3x_alt_boot_ctx;

/* ************************************************************************** */
/* Static function declarations                                               */
/* ************************************************************************** */

/* ************************************************************************** */
/* Private Functions                                                          */
/* ************************************************************************** */

/* ************************************************************************** */
/* Public Functions                                                           */
/* ************************************************************************** */
#ifdef MBEDTLS_ECDSA_SIGN_ALT
void sss_mbedtls_set_keystore_ecdsa_sign(sss_key_store_t *ssskeystore);
#endif
#ifdef MBEDTLS_ECDSA_VERIFY_ALT
void sss_mbedtls_set_keystore_ecdsa_verify(sss_key_store_t *ssskeystore);
#endif
void sss_mbedtls_set_keystore_rng(sss_key_store_t *ssskeystore);
#if defined(MBEDTLS_AES_ENCRYPT_ALT) || defined(MBEDTLS_AES_DECRYPT_ALT)
void sss_mbedtls_set_keystore_aes(sss_key_store_t *ssskeystore);
#endif
#ifdef MBEDTLS_ECDH_COMPUTE_SHARED_ALT
void sss_mbedtls_set_keystore_ecdh(sss_key_store_t *ssskeystore);
#endif

#include <ex_sss_main_inc.h>

#define AES128_KEY_LEN 16
#define AES128_CBC_ICV_LEN 16
#define INPUT_DATA_LEN_MAX 64

/** Length of BRAINPOOL 256 header */
#define NX_BRAINPOOL_256_PUB_HEADER_LEN 27
#define NX_BP_REFKEY_KEYID_OFFET 26
/** Length of NIST-P (SECP 256 R1) header */
#define NX_NIST_256_PUB_HEADER_LEN 26
#define NX_NISTP_REFKEY_KEYID_OFFET 54

/* Generate refernce for keyid and cipher type */
#ifdef MBEDTLS_ECDH_COMPUTE_SHARED_ALT

/*
* Function to create the reference key
* Pass the public key without header (65 bytes for nist-256),
*/
static int generate_reference_key(uint8_t *publickey,
    size_t publickeyLen,
    uint32_t keyId,
    sss_cipher_type_t cipherType,
    uint8_t *refkeybuf,
    size_t *refkeylen)
{
    const uint8_t nist256_key_template[] = {
        0x30,
        0x81,
        0x87,
        0x02,
        0x01,
        0x00,
        0x30,
        0x13,
        0x06,
        0x07,
        0x2A,
        0x86,
        0x48,
        0xCE,
        0x3D,
        0x02,
        0x01,
        0x06,
        0x08,
        0x2A,
        0x86,
        0x48,
        0xCE,
        0x3D,
        0x03,
        0x01,
        0x07,
        0x04,
        0x6D,
        0x30,
        0x6B,
        0x02,
        0x01,
        0x01,
        0x04,
        0x20,
        0x10,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x02,
        0xA5,
        0xA6,
        0xB5,
        0xB6,
        0xA5,
        0xA6,
        0xB5,
        0xB6,
        0x00,
        0x00,
        0xA1,
        0x44,
        0x03,
        0x42,
        0x00,
    };
    const uint8_t bp256_key_template[] = {

        0x30,
        0x78,
        0x02,
        0x01,
        0x01,
        0x04,
        0x20,
        0x10,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x02,
        0xA5,
        0xA6,
        0xB5,
        0xB6,
        0xA5,
        0xA6,
        0xB5,
        0xB6,
        0x10,
        0x00,
        0xA0,
        0x0B,
        0x06,
        0x09,
        0x2B,
        0x24,
        0x03,
        0x03,
        0x02,
        0x08,
        0x01,
        0x01,
        0x07,
        0xA1,
        0x44,
        0x03,
        0x42,
        0x00,
    };
    uint8_t refkey_id_offset = 0;

    if (publickey == NULL || refkeybuf == NULL || refkeylen == NULL) {
        return 1;
    }

    if (cipherType == kSSS_CipherType_EC_NIST_P) {
        *refkeylen       = sizeof(nist256_key_template);
        refkey_id_offset = NX_NISTP_REFKEY_KEYID_OFFET;
        memcpy(&refkeybuf[0], nist256_key_template, sizeof(nist256_key_template));
        refkeybuf[refkey_id_offset++] = (keyId & 0xFF000000) >> 24;
        refkeybuf[refkey_id_offset++] = (keyId & 0xFF0000) >> 16;
        refkeybuf[refkey_id_offset++] = (keyId & 0xFF00) >> 8;
        refkeybuf[refkey_id_offset++] = (keyId & 0xFF);

        memcpy(&refkeybuf[*refkeylen], &publickey[0], publickeyLen);
        *refkeylen += publickeyLen;
    }
    else if (cipherType == kSSS_CipherType_EC_BRAINPOOL) {
        *refkeylen       = sizeof(bp256_key_template);
        refkey_id_offset = NX_BP_REFKEY_KEYID_OFFET;
        memcpy(&refkeybuf[0], bp256_key_template, sizeof(bp256_key_template));
        refkeybuf[refkey_id_offset++] = (keyId & 0xFF000000) >> 24;
        refkeybuf[refkey_id_offset++] = (keyId & 0xFF0000) >> 16;
        refkeybuf[refkey_id_offset++] = (keyId & 0xFF00) >> 8;
        refkeybuf[refkey_id_offset++] = (keyId & 0xFF);
        memcpy(&refkeybuf[*refkeylen], &publickey[0], publickeyLen);
        *refkeylen += publickeyLen;
    }
    else {
        LOG_E("Invalid cipher type");
        return 1;
    }

    LOG_MAU8_I("refbuf", refkeybuf, *refkeylen);

    return 0;
}
#endif

#ifdef MBEDTLS_ECDSA_SIGN_ALT
sss_status_t ex_mbedtls3x_ecdsa_sign(ex_sss_boot_ctx_t *pCtx)
{
    sss_status_t status          = kStatus_SSS_Success;
    sss_object_t keyPairSE       = {0};
    sss_object_t refKey_host     = {0};
    sss_object_t keyPair_host    = {0};
    sss_asymmetric_t ctx_asymm   = {0};
    sss_cipher_type_t cipherType = kSSS_CipherType_EC_NIST_P;
    uint32_t keyid           = 0x02;
    uint8_t signature[256]     = {0};
    size_t signatureLen        = sizeof(signature);
    uint8_t digest[32] = "Hello World";
    size_t digestLen   = sizeof(digest);
    const sss_policy_u eccKeyGenPolicy = {.type = KPolicy_GenECKey,
        .policy                                 = {.genEcKey = {
                       .freezeKUCLimit        = 0,
                       .cardUnilateralEnabled = 0,
                       .sdmEnabled            = 0,
                       .eccSignEnabled        = 1,
                       .ecdhEnabled           = 0,
                       .sigmaiEnabled         = 0,
                       .writeCommMode         = kCommMode_FULL,
                       .writeAccessCond       = Nx_AccessCondition_Free_Access,
                       .kucLimit              = 0,
                       .userCommMode          = kCommMode_SSS_NA,
                   }}};
    sss_policy_t ec_key_policy         = {.nPolicies = 1, .policies = {&eccKeyGenPolicy}};

    ENSURE_OR_GO_CLEANUP(NULL != pCtx)

    LOG_I("Injecting actual keyPair on Host");

    status = sss_key_object_init(&keyPair_host, &pCtx->host_ks);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_key_object_allocate_handle(
        &keyPair_host, __LINE__, kSSS_KeyPart_Pair, cipherType, nist256_keyPairData_len, kKeyObject_Mode_Transient);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_key_store_set_key(
        &pCtx->host_ks, &keyPair_host, nist256_keyPairData, nist256_keyPairData_len, KEY_BIT_LENGTH, NULL, 0);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    LOG_I("Sign using SSS API");
    /* Sign using Mbedtls ALT.. Should rollback to host API */
    status = sss_asymmetric_context_init(
        &ctx_asymm, &pCtx->host_session, &keyPair_host, kAlgorithm_SSS_ECDSA_SHA256, kMode_SSS_Sign);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_asymmetric_sign_digest(&ctx_asymm, digest, digestLen, signature, &signatureLen);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    sss_asymmetric_context_free(&ctx_asymm);

    LOG_I("Injecting actual key in Secure Authenticator");
    status = sss_key_object_init(&keyPairSE, &pCtx->ks);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_key_object_allocate_handle(
        &keyPairSE, keyid, kSSS_KeyPart_Private, cipherType, nist256_privatekeyData_len, kKeyObject_Mode_Persistent);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_key_store_set_key(&pCtx->ks,
        &keyPairSE,
        nist256_privatekeyData,
        nist256_privatekeyData_len,
        KEY_BIT_LENGTH,
        &ec_key_policy,
        sizeof(ec_key_policy));
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    LOG_I("Injecting reference key (for key id 0x02) on Host");
    status = sss_key_object_init(&refKey_host, &pCtx->host_ks);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_key_object_allocate_handle(
        &refKey_host, __LINE__, kSSS_KeyPart_Pair, cipherType, nist256_keyPair_refKey_len, kKeyObject_Mode_Transient);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_key_store_set_key(
        &pCtx->host_ks, &refKey_host, nist256_keyPair_refKey, nist256_keyPair_refKey_len, KEY_BIT_LENGTH, NULL, 0);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    LOG_I("Sign using SSS API");
    /* Sign using Mbedtls ALT.. Should use SE for Sign */
    status = sss_asymmetric_context_init(
        &ctx_asymm, &pCtx->host_session, &refKey_host, kAlgorithm_SSS_ECDSA_SHA256, kMode_SSS_Sign);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    signatureLen = sizeof(signature); //reinitialize signture buffer length
    status       = sss_asymmetric_sign_digest(&ctx_asymm, digest, digestLen, signature, &signatureLen);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

cleanup:

    if (ctx_asymm.session != NULL) {
        sss_asymmetric_context_free(&ctx_asymm);
    }
    if (keyPair_host.keyStore != NULL) {
        sss_key_object_free(&keyPair_host);
    }
    if (keyPairSE.keyStore != NULL) {
        sss_key_object_free(&keyPairSE);
    }
    if (refKey_host.keyStore != NULL) {
        sss_key_object_free(&refKey_host);
    }
    return status;
}
#endif

#if (defined(SSS_HAVE_AUTH_SYMM_AUTH) && (SSS_HAVE_AUTH_SYMM_AUTH == 1)) || \
    (defined(SSS_HAVE_AUTH_NONE) && (SSS_HAVE_AUTH_NONE == 1))
#ifdef MBEDTLS_ECDSA_VERIFY_ALT
sss_status_t ex_mbedtls3x_ecdsa_verify(ex_sss_boot_ctx_t *pCtx)
{
    sss_status_t status                = kStatus_SSS_Success;
    sss_object_t keyPair_SE            = {0};
    sss_object_t pubKey_host           = {0};
    sss_asymmetric_t ctx_asymm         = {0};
    sss_cipher_type_t cipherType       = kSSS_CipherType_EC_NIST_P;
    uint32_t keyid                     = 0x02;
    uint8_t se_signature[256]          = {0};
    size_t se_signatureLen             = sizeof(se_signature);
    uint8_t digest[32]                 = "Hello World";
    size_t digestLen                   = sizeof(digest);
    const sss_policy_u eccKeyGenPolicy = {.type = KPolicy_GenECKey,
        .policy                                 = {.genEcKey = {
                       .freezeKUCLimit        = 0,
                       .cardUnilateralEnabled = 0,
                       .sdmEnabled            = 0,
                       .eccSignEnabled        = 1,
                       .ecdhEnabled           = 0,
                       .sigmaiEnabled         = 0,
                       .writeCommMode         = kCommMode_FULL,
                       .writeAccessCond       = Nx_AccessCondition_Free_Access,
                       .kucLimit              = 0,
                       .userCommMode          = kCommMode_SSS_NA,
                   }}};
    sss_policy_t ec_key_policy         = {.nPolicies = 1, .policies = {&eccKeyGenPolicy}};

    ENSURE_OR_GO_CLEANUP(NULL != pCtx)

    LOG_I("Injecting actual key in Secure Authenticator");

    status = sss_key_object_init(&keyPair_SE, &pCtx->ks);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_key_object_allocate_handle(
        &keyPair_SE, keyid, kSSS_KeyPart_Private, cipherType, nist256_privatekeyData_len, kKeyObject_Mode_Persistent);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_key_store_set_key(&pCtx->ks,
        &keyPair_SE,
        nist256_privatekeyData,
        nist256_privatekeyData_len,
        KEY_BIT_LENGTH,
        &ec_key_policy,
        sizeof(ec_key_policy));
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    LOG_I("Sign using NX SA using SSS API");
    /* Sign using Secure Authenticator */
    status = sss_asymmetric_context_init(
        &ctx_asymm, &pCtx->session, &keyPair_SE, kAlgorithm_SSS_ECDSA_SHA256, kMode_SSS_Sign);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_asymmetric_sign_digest(&ctx_asymm, digest, digestLen, se_signature, &se_signatureLen);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    sss_asymmetric_context_free(&ctx_asymm);

    LOG_I("Injecting public key on Host");

    status = sss_key_object_init(&pubKey_host, &pCtx->host_ks);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_key_object_allocate_handle(
        &pubKey_host, __LINE__, kSSS_KeyPart_Public, cipherType, nist256_PubKey_len, kKeyObject_Mode_Transient);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_key_store_set_key(
        &pCtx->host_ks, &pubKey_host, nist256_PubKey, nist256_PubKey_len, KEY_BIT_LENGTH, NULL, 0);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    LOG_I("Verify using SSS API");
    /* Verify using Mbedtls ALT.. Should use SE for Verify */
    status = sss_asymmetric_context_init(
        &ctx_asymm, &pCtx->host_session, &pubKey_host, kAlgorithm_SSS_ECDSA_SHA256, kMode_SSS_Verify);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_asymmetric_verify_digest(&ctx_asymm, digest, digestLen, se_signature, se_signatureLen);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

cleanup:

    if (ctx_asymm.session != NULL) {
        sss_asymmetric_context_free(&ctx_asymm);
    }
    if (keyPair_SE.keyStore != NULL) {
        sss_key_object_free(&keyPair_SE);
    }
    if (pubKey_host.keyStore != NULL) {
        sss_key_object_free(&pubKey_host);
    }
    return status;
}
#endif
#endif

sss_status_t ex_mbedtls3x_rng_gen(ex_sss_boot_ctx_t *pCtx)
{
    sss_status_t status       = kStatus_SSS_Fail;
    sss_rng_context_t ctx_rng = {0};
    uint8_t rndData[32]       = {0};
    size_t rndDataLen         = sizeof(rndData);
    status                    = sss_rng_context_init(&ctx_rng, &pCtx->host_session /* Session */);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_rng_get_random(&ctx_rng, rndData, rndDataLen);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

cleanup:
    if (ctx_rng.session != NULL) {
        sss_rng_context_free(&ctx_rng);
    }
    return status;
}

#if defined(SSS_HAVE_AUTH_NONE) && (SSS_HAVE_AUTH_NONE == 1)
sss_status_t ex_mbedtls3x_ebc(ex_sss_boot_ctx_t *pCtx)
{
    sss_status_t status          = kStatus_SSS_Fail;
    sss_algorithm_t algorithm    = kAlgorithm_SSS_AES_ECB;
    sss_key_part_t keyPart       = kSSS_KeyPart_Default;
    sss_cipher_type_t cipherType = kSSS_CipherType_AES;
    sss_mode_t mode              = kMode_SSS_Encrypt;
    sss_object_t host_keyobject  = {0};

    /* clang-format off */
    uint8_t aes_key_data[AES128_KEY_LEN] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c, };
    /* clang-format on */
    /* clang-format off */
    uint8_t icv_data[AES128_CBC_ICV_LEN] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, };
    /* clang-format on */
    size_t icv_len = AES128_CBC_ICV_LEN;
    /* clang-format off */
    uint8_t input_data[]                 = {0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
                                            0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
                                            0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
                                            0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10, };
    /* clang-format on */
    size_t input_len                     = sizeof(input_data);
    uint8_t enc_data[INPUT_DATA_LEN_MAX] = {0};
    uint8_t dec_data[INPUT_DATA_LEN_MAX] = {0};
    size_t dec_data_len                  = input_len;
    sss_symmetric_t ctx_symm             = {0};
    sss_symmetric_t ctx_2symm            = {0};

    /* Do Encryption */

    status = sss_key_object_init(&host_keyobject, &pCtx->host_ks);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_key_object_allocate_handle(
        &host_keyobject, __LINE__, keyPart, cipherType, sizeof(aes_key_data), kKeyObject_Mode_Persistent);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_key_store_set_key(
        &pCtx->host_ks, &host_keyobject, aes_key_data, sizeof(aes_key_data), (sizeof(aes_key_data) * 8), NULL, 0);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    LOG_MAU8_D("Plain text:\n", input_data, input_len);

    status = sss_symmetric_context_init(&ctx_symm, &pCtx->host_session, &host_keyobject, algorithm, mode);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_cipher_one_go(&ctx_symm, icv_data, icv_len, input_data, enc_data, input_len);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    LOG_MAU8_D("ECB encrypted data:\n ", enc_data, input_len);

    sss_symmetric_context_free(&ctx_symm);

    /* Do Decryption */
    mode   = kMode_SSS_Decrypt;
    status = sss_symmetric_context_init(&ctx_2symm, &pCtx->host_session, &host_keyobject, algorithm, mode);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_cipher_one_go(&ctx_2symm, icv_data, icv_len, enc_data, dec_data, dec_data_len);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
    sss_symmetric_context_free(&ctx_2symm);

    LOG_MAU8_D("ECB decrypted data:\n ", dec_data, dec_data_len);

#if defined(MBEDTLS_AES_ENCRYPT_ALT) || defined(MBEDTLS_AES_DECRYPT_ALT)
    sss_mbedtls_set_keystore_aes(&pCtx->ks);
#endif

    mode = kMode_SSS_Encrypt;
    LOG_MAU8_D("Plain text:\n", input_data, input_len);
    status = sss_symmetric_context_init(&ctx_symm, &pCtx->host_session, &host_keyobject, algorithm, mode);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_cipher_one_go(&ctx_symm, icv_data, icv_len, input_data, enc_data, input_len);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    LOG_MAU8_D("ECB encrypted data:\n ", enc_data, input_len);
    sss_symmetric_context_free(&ctx_symm);

    /* Do Decryption */
    mode   = kMode_SSS_Decrypt;
    status = sss_symmetric_context_init(&ctx_2symm, &pCtx->host_session, &host_keyobject, algorithm, mode);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_cipher_one_go(&ctx_2symm, icv_data, icv_len, enc_data, dec_data, dec_data_len);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    LOG_MAU8_D("ECB decrypted data:\n ", dec_data, dec_data_len);

    if (0 != memcmp(dec_data, input_data, input_len)) {
        LOG_E("Decrypted data not match with plain data");
    }

cleanup:

    if (ctx_symm.session != NULL) {
        sss_symmetric_context_free(&ctx_symm);
    }
    if (ctx_2symm.session != NULL) {
        sss_symmetric_context_free(&ctx_2symm);
    }
    if (host_keyobject.keyStore != NULL) {
        sss_key_object_free(&host_keyobject);
    }
    return status;
}

sss_status_t ex_mbedtls3x_cbc(ex_sss_boot_ctx_t *pCtx)
{
    sss_status_t status          = kStatus_SSS_Fail;
    sss_algorithm_t algorithm    = kAlgorithm_SSS_AES_CBC;
    sss_key_part_t keyPart       = kSSS_KeyPart_Default;
    sss_cipher_type_t cipherType = kSSS_CipherType_AES;
    sss_mode_t mode              = kMode_SSS_Encrypt;
    /* clang-format off */
    uint8_t aes_key_data[AES128_KEY_LEN]    = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c, };
    uint8_t icv_data[AES128_CBC_ICV_LEN]    = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, };
    size_t icv_len                          = AES128_CBC_ICV_LEN;
    uint8_t input_data[]                    = {0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
                                                0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51, };
    /* clang-format on */
    size_t input_len                     = sizeof(input_data);
    uint8_t enc_data[INPUT_DATA_LEN_MAX] = {0};
    size_t enc_data_len                  = input_len;
    uint8_t dec_data[INPUT_DATA_LEN_MAX] = {0};
    size_t dec_data_len                  = input_len;
    sss_symmetric_t ctx_symm             = {0};
    sss_symmetric_t ctx_2symm            = {0};
    sss_object_t host_keyobject          = {0};

    status = sss_key_object_init(&host_keyobject, &pCtx->host_ks);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_key_object_allocate_handle(
        &host_keyobject, __LINE__, keyPart, cipherType, sizeof(aes_key_data), kKeyObject_Mode_Persistent);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_key_store_set_key(
        &pCtx->host_ks, &host_keyobject, aes_key_data, sizeof(aes_key_data), (sizeof(aes_key_data) * 8), NULL, 0);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    LOG_MAU8_D("Plain text:\n", input_data, input_len);

    status = sss_symmetric_context_init(&ctx_symm, &pCtx->host_session, &host_keyobject, algorithm, mode);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_cipher_one_go(&ctx_symm, icv_data, icv_len, input_data, enc_data, enc_data_len);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    LOG_MAU8_D("CBC encrypted data:\n ", enc_data, enc_data_len);

    sss_symmetric_context_free(&ctx_symm);

    /* Do Decryption on NX (SE) */
    mode = kMode_SSS_Decrypt;
    /* This Function will Init,Allocate and Set key in keystore */
    status = sss_symmetric_context_init(&ctx_2symm, &pCtx->host_session, &host_keyobject, algorithm, mode);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_cipher_one_go(&ctx_2symm, icv_data, icv_len, enc_data, dec_data, dec_data_len);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
    sss_symmetric_context_free(&ctx_2symm);

    LOG_MAU8_D("CBC decrypted data:\n ", dec_data, dec_data_len);

#if defined(MBEDTLS_AES_ENCRYPT_ALT) || defined(MBEDTLS_AES_DECRYPT_ALT)
    sss_mbedtls_set_keystore_aes(&pCtx->ks);
#endif

    mode = kMode_SSS_Encrypt;
    LOG_MAU8_D("Plain text:\n", input_data, input_len);
    status = sss_symmetric_context_init(&ctx_symm, &pCtx->host_session, &host_keyobject, algorithm, mode);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_cipher_one_go(&ctx_symm, icv_data, icv_len, input_data, enc_data, enc_data_len);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    LOG_MAU8_D("CBC encrypted data:\n ", enc_data, enc_data_len);
    sss_symmetric_context_free(&ctx_symm);

    /* Do Decryption on NX (SE) */
    mode = kMode_SSS_Decrypt;
    /* This Function will Init,Allocate and Set key in keystore */
    status = sss_symmetric_context_init(&ctx_2symm, &pCtx->host_session, &host_keyobject, algorithm, mode);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_cipher_one_go(&ctx_2symm, icv_data, icv_len, enc_data, dec_data, dec_data_len);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    LOG_MAU8_D("CBC decrypted data:\n ", dec_data, dec_data_len);

    if (0 != memcmp(dec_data, input_data, input_len)) {
        LOG_E("decrypted data not match with plain data");
    }

cleanup:
    if (ctx_symm.session != NULL) {
        sss_symmetric_context_free(&ctx_symm);
    }
    if (ctx_2symm.session != NULL) {
        sss_symmetric_context_free(&ctx_2symm);
    }
    if (host_keyobject.keyStore != NULL) {
        sss_key_object_free(&host_keyobject);
    }

    return status;
}

sss_status_t ex_mbedtls3x_cmac(ex_sss_boot_ctx_t *pCtx)
{
    sss_status_t status          = kStatus_SSS_Fail;
    uint32_t algorithm           = kAlgorithm_SSS_CMAC_AES;
    sss_mode_t mode              = kMode_SSS_Mac;
    sss_key_part_t keyPart       = kSSS_KeyPart_Default;
    sss_cipher_type_t cipherType = kSSS_CipherType_AES;
    /* clang-format off */
    uint8_t outdata[128]                    = {0};
    size_t outdatLen = sizeof(outdata);
    /* clang-format on */
    memset(outdata, 0x00, outdatLen);
    sss_mac_t ctx_mac           = {0};
    sss_mac_t ctx_2mac          = {0};
    sss_object_t host_keyobject = {0};
    /* Generate MAC on NX */
    uint8_t srcData[]      = {0x00,
        0x01,
        0x02,
        0x03,
        0x04,
        0x05,
        0x06,
        0x07,
        0x08,
        0x09,
        0x0A,
        0x0B,
        0x0C,
        0x0D,
        0x0E,
        0x0F,
        0x00,
        0x01,
        0x02,
        0x03,
        0x04,
        0x05,
        0x06,
        0x07,
        0x08,
        0x09,
        0x0A,
        0x0B,
        0x0C,
        0x0D,
        0x0E,
        0x0F};
    uint8_t aes_key_data[] = {0x00,
        0x01,
        0x02,
        0x03,
        0x04,
        0x05,
        0x06,
        0x07,
        0x08,
        0x09,
        0x0A,
        0x0B,
        0x0C,
        0x0D,
        0x0E,
        0x0F,
        0x00,
        0x01,
        0x02,
        0x03,
        0x04,
        0x05,
        0x06,
        0x07,
        0x08,
        0x09,
        0x0A,
        0x0B,
        0x0C,
        0x0D,
        0x0E,
        0x0F};
    /* clang-format on */

    status = sss_key_object_init(&host_keyobject, &pCtx->host_ks);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_key_object_allocate_handle(
        &host_keyobject, __LINE__, keyPart, cipherType, sizeof(aes_key_data), kKeyObject_Mode_Persistent);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_key_store_set_key(
        &pCtx->host_ks, &host_keyobject, aes_key_data, sizeof(aes_key_data), (sizeof(aes_key_data) * 8), NULL, 0);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    mode = kMode_SSS_Mac;
    LOG_MAU8_D("Plain text:\n", srcData, sizeof(srcData));
    status = sss_mac_context_init(&ctx_mac, &pCtx->host_session, &host_keyobject, algorithm, mode);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
    status = sss_mac_init(&ctx_mac);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_mac_update(&ctx_mac, &srcData[0], 8);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_mac_update(&ctx_mac, &srcData[8], sizeof(srcData) - 8);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_mac_finish(&ctx_mac, outdata, &outdatLen);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
    sss_mac_context_free(&ctx_mac);

    LOG_MAU8_D("MAC sign:\n", outdata, outdatLen);

    /* Validate MAC */
    mode   = kMode_SSS_Mac_Validate;
    status = sss_mac_context_init(&ctx_2mac, &pCtx->host_session, &host_keyobject, algorithm, mode);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_mac_init(&ctx_2mac);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_mac_update(&ctx_2mac, &srcData[0], 8);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_mac_update(&ctx_2mac, &srcData[8], sizeof(srcData) - 8);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_mac_finish(&ctx_2mac, outdata, &outdatLen);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
    sss_mac_context_free(&ctx_2mac);

    LOG_MAU8_D("MAC Verify:\n", outdata, outdatLen);

#if defined(MBEDTLS_AES_ENCRYPT_ALT) || defined(MBEDTLS_AES_DECRYPT_ALT)
    sss_mbedtls_set_keystore_aes(&pCtx->ks);
#endif

    mode   = kMode_SSS_Mac;
    status = sss_mac_context_init(&ctx_mac, &pCtx->host_session, &host_keyobject, algorithm, mode);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    LOG_MAU8_D("Plain Data:\n", srcData, sizeof(srcData));
    status = sss_mac_init(&ctx_mac);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_mac_update(&ctx_mac, &srcData[0], 8);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_mac_update(&ctx_mac, &srcData[8], sizeof(srcData) - 8);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_mac_finish(&ctx_mac, outdata, &outdatLen);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
    sss_mac_context_free(&ctx_mac);

    LOG_MAU8_D("MAC sign:\n", outdata, outdatLen);

    /* Validate MAC on CP */
    mode   = kMode_SSS_Mac_Validate;
    status = sss_mac_context_init(&ctx_2mac, &pCtx->host_session, &host_keyobject, algorithm, mode);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_mac_init(&ctx_2mac);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_mac_update(&ctx_2mac, &srcData[0], 8);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_mac_update(&ctx_2mac, &srcData[8], sizeof(srcData) - 8);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_mac_finish(&ctx_2mac, outdata, &outdatLen);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
    LOG_MAU8_D("MAC Verify:\n", outdata, outdatLen);

cleanup:
    if (ctx_mac.session != NULL) {
        sss_mac_context_free(&ctx_mac);
    }
    if (ctx_2mac.session != NULL) {
        sss_mac_context_free(&ctx_2mac);
    }
    if (host_keyobject.keyStore != NULL) {
        sss_key_object_free(&host_keyobject);
    }

    return status;
}
#endif

#if defined(MBEDTLS_ECDH_COMPUTE_SHARED_ALT)
sss_status_t ex_mbedtls3x_ecdh(ex_sss_boot_ctx_t *pCtx)
{
    sss_status_t status             = kStatus_SSS_Success;
    sss_object_t keyPairSE          = {0};
    sss_object_t keyPairHost        = {0};
    sss_object_t OtherPartyPubkey   = {0};
    uint32_t keyid                  = NX_KEY_ID_EPHEM_NISTP256;
    sss_derive_key_t ctx_derive_key = {0};
    sss_object_t deriveKey          = {0};
    uint8_t ecdhKey[128]            = {0};
    size_t ecdhKeyLen               = sizeof(ecdhKey);
    size_t ecdhKeyBitLen            = sizeof(ecdhKey) * 8;
    sss_cipher_type_t cipherType    = kSSS_CipherType_EC_NIST_P;
    size_t keyLen                   = KEY_BIT_LENGTH;
    uint8_t ret                     = 1;
    uint8_t refkeybuf[250]          = {0};
    size_t refkeylen                = sizeof(refkeybuf);

    const uint8_t otherPartyPublicKeyBuf[] = {0x30,
        0x59,
        0x30,
        0x13,
        0x06,
        0x07,
        0x2A,
        0x86,
        0x48,
        0xCE,
        0x3D,
        0x02,
        0x01,
        0x06,
        0x08,
        0x2A,
        0x86,
        0x48,
        0xCE,
        0x3D,
        0x03,
        0x01,
        0x07,
        0x03,
        0x42,
        0x00,
        0x04,
        0xED,
        0xA7,
        0xE9,
        0x0B,
        0xF9,
        0x20,
        0xCF,
        0xFB,
        0x9D,
        0xF6,
        0xDB,
        0xCE,
        0xF7,
        0x20,
        0xE1,
        0x23,
        0x8B,
        0x3C,
        0xEE,
        0x84,
        0x86,
        0xD2,
        0x50,
        0xE4,
        0xDF,
        0x30,
        0x11,
        0x50,
        0x1A,
        0x15,
        0x08,
        0xA6,
        0x2E,
        0xD7,
        0x49,
        0x52,
        0x78,
        0x63,
        0x6E,
        0x61,
        0xE8,
        0x5F,
        0xED,
        0xB0,
        0x6D,
        0x87,
        0x92,
        0x0A,
        0x04,
        0x19,
        0x14,
        0xFE,
        0x76,
        0x63,
        0x55,
        0xDF,
        0xBD,
        0x68,
        0x61,
        0x59,
        0x31,
        0x8E,
        0x68,
        0x7C};
    size_t otherPartyPublicKeyBuf_len      = sizeof(otherPartyPublicKeyBuf);

    const sss_policy_u eccKeyGenPolicy = {.type = KPolicy_GenECKey,
        .policy                                 = {.genEcKey = {
                       .freezeKUCLimit        = 0,
                       .cardUnilateralEnabled = 0,
                       .sdmEnabled            = 0,
                       .eccSignEnabled        = 0,
                       .ecdhEnabled           = 1,
                       .sigmaiEnabled         = 0,
                       .writeCommMode         = kCommMode_FULL,
                       .writeAccessCond       = Nx_AccessCondition_Free_Access,
                       .kucLimit              = 0,
                       .userCommMode          = kCommMode_SSS_NA,
                   }}};
    sss_policy_t ec_key_policy         = {.nPolicies = 1, .policies = {&eccKeyGenPolicy}};

    LOG_I("Injecting actual key in Secure Authenticator");
    status = sss_key_object_init(&keyPairSE, &pCtx->ks);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_key_object_allocate_handle(
        &keyPairSE, keyid, kSSS_KeyPart_Pair, cipherType, nist256_privatekeyData_len, kKeyObject_Mode_Transient);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_key_store_generate_key(&pCtx->ks, &keyPairSE, 256, &ec_key_policy);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    /*
        We cannot get the piblic key of Ephemeral key from NX SA...
        So pass a dummy public key  (other party public key in this case) to create a reference key for now.
        Passing 0s will not help, as the reference key becomes invalid and we will not be able to set it in NX SA.
    */
    ret = generate_reference_key((uint8_t *)&otherPartyPublicKeyBuf[NX_NIST_256_PUB_HEADER_LEN],
        otherPartyPublicKeyBuf_len - NX_NIST_256_PUB_HEADER_LEN,
        keyid,
        cipherType,
        &refkeybuf[0],
        &refkeylen);
    ENSURE_OR_GO_CLEANUP(ret == 0);

    LOG_I("Injecting reference key on Host");
    status = sss_key_object_init(&keyPairHost, &pCtx->host_ks);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_key_object_allocate_handle(
        &keyPairHost, __LINE__, kSSS_KeyPart_Pair, cipherType, refkeylen, kKeyObject_Mode_Transient);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_key_store_set_key(&pCtx->host_ks, &keyPairHost, &refkeybuf[0], refkeylen, keyLen, NULL, 0);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    LOG_I("Injecting Public key on Host");
    status = sss_key_object_init(&OtherPartyPubkey, &pCtx->host_ks);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_key_object_allocate_handle(
        &OtherPartyPubkey, __LINE__, kSSS_KeyPart_Public, cipherType, nist256_PubKey_len, kKeyObject_Mode_Transient);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_key_store_set_key(
        &pCtx->host_ks, &OtherPartyPubkey, otherPartyPublicKeyBuf, otherPartyPublicKeyBuf_len, keyLen, NULL, 0);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    LOG_I("ECDH using SSS API");
    status = sss_key_object_init(&deriveKey, &pCtx->host_ks);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_key_object_allocate_handle(
        &deriveKey, __LINE__, kSSS_KeyPart_Default, kSSS_CipherType_AES, 128, kKeyObject_Mode_Transient);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_derive_key_context_init(
        &ctx_derive_key, &pCtx->host_session, &keyPairHost, kAlgorithm_SSS_ECDH, kMode_SSS_ComputeSharedSecret);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_derive_key_dh_one_go(&ctx_derive_key, &OtherPartyPubkey, &deriveKey);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_key_store_get_key(&pCtx->host_ks, &deriveKey, ecdhKey, &ecdhKeyLen, &ecdhKeyBitLen);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
    LOG_MAU8_I("ECDH derive Key", ecdhKey, ecdhKeyLen);

cleanup:

    if (ctx_derive_key.session != NULL) {
        sss_derive_key_context_free(&ctx_derive_key);
    }
    if (keyPairSE.keyStore != NULL) {
        sss_key_object_free(&keyPairSE);
    }
    if (keyPairHost.keyStore != NULL) {
        sss_key_object_free(&keyPairHost);
    }
    if (OtherPartyPubkey.keyStore != NULL) {
        sss_key_object_free(&OtherPartyPubkey);
    }
    if (deriveKey.keyStore != NULL) {
        sss_key_object_free(&deriveKey);
    }
    return status;
}
#endif

sss_status_t ex_sss_entry(ex_sss_boot_ctx_t *pCtx)
{
    sss_status_t status = kStatus_SSS_Success;
    sss_status_t ex_status = kStatus_SSS_Success;

#ifdef MBEDTLS_ECDSA_SIGN_ALT
    LOG_I("\n\n");
    LOG_I("******** Testing ECDSA Sign ALT ******** ");
    sss_mbedtls_set_keystore_ecdsa_sign(&pCtx->ks);
    status = ex_mbedtls3x_ecdsa_sign(pCtx);
    if (status == kStatus_SSS_Success) {
        LOG_I("ex_mbedtls3x_ecdsa_sign Success");
    }
    else {
        ex_status = kStatus_SSS_Fail;
        LOG_I("ex_mbedtls3x_ecdsa_sign Failed");
    }
    sss_mbedtls_set_keystore_ecdsa_sign(NULL);
    LOG_I("\n\n");
#endif

    /*
        Alt ECDSA Verify works with symmetric authentication.
        If Authentication = None, change the access and commMode mode.
        Alt ECDSA Verify does not with sigma-i-auth.
    */
#if (defined(SSS_HAVE_AUTH_SYMM_AUTH) && (SSS_HAVE_AUTH_SYMM_AUTH == 1)) || \
    (defined(SSS_HAVE_AUTH_NONE) && (SSS_HAVE_AUTH_NONE == 1))
#ifdef MBEDTLS_ECDSA_VERIFY_ALT
    LOG_I("******** Testing ECDSA Verify ALT ******** ");
    sss_mbedtls_set_keystore_ecdsa_verify(&pCtx->ks);
    status = ex_mbedtls3x_ecdsa_verify(pCtx);
    if (status == kStatus_SSS_Success) {
        LOG_I("ex_mbedtls3x_ecdsa_verify Success");
    }
    else {
        ex_status = kStatus_SSS_Fail;
        LOG_I("ex_mbedtls3x_ecdsa_verify Failed");
    }
    sss_mbedtls_set_keystore_ecdsa_verify(NULL);
    LOG_I("\n\n");
#endif
#endif

    /*
        If Authentication = None, change the access and commMode mode.
    */
    LOG_I("******** Testing RNG ALT ******** ");
    sss_mbedtls_set_keystore_rng(&pCtx->ks);
    status = ex_mbedtls3x_rng_gen(pCtx);
    if (status == kStatus_SSS_Success) {
        LOG_I("ex_mbedtls3x_rng_gen Success");
    }
    else {
        ex_status = kStatus_SSS_Fail;
        LOG_I("ex_mbedtls3x_rng_gen Failed");
    }
    sss_mbedtls_set_keystore_rng(NULL);
    LOG_I("\n\n");

    /*
        If Authentication = None, change the access and commMode mode.
    */
#ifdef MBEDTLS_ECDH_COMPUTE_SHARED_ALT
    LOG_I("******** Testing ECDH ALT ******** ");
    sss_mbedtls_set_keystore_ecdh(&pCtx->ks);
    status = ex_mbedtls3x_ecdh(pCtx);
    if (status == kStatus_SSS_Success) {
        LOG_I("ex_mbedtls3x_ecdh Success");
    }
    else {
        ex_status = kStatus_SSS_Fail;
        LOG_I("ex_mbedtls3x_ecdh Failed");
    }
    sss_mbedtls_set_keystore_ecdh(NULL);
    LOG_I("\n\n");
#endif

    /*
        AES mbedtls alt supported only with auth mode none.
        For all Authentication modes, during secure tunnling we have the dependence over aes cipher and mac.
    */
#if defined(SSS_HAVE_AUTH_NONE) && (SSS_HAVE_AUTH_NONE == 1)
#if defined(MBEDTLS_AES_ENCRYPT_ALT) || defined(MBEDTLS_AES_DECRYPT_ALT)

    LOG_I("******** Testing AES ECB ALT ******** ");
    status = ex_mbedtls3x_ebc(pCtx);
    if (status == kStatus_SSS_Success) {
        LOG_I("ex_mbedtls3x_ebc Success");
    }
    else {
        ex_status = kStatus_SSS_Fail;
        LOG_I("ex_mbedtls3x_ebc Failed");
    }
    sss_mbedtls_set_keystore_aes(NULL);
    LOG_I("\n\n");

    LOG_I("******** Testing AES CBC ALT ******** ");
    status = ex_mbedtls3x_cbc(pCtx);
    if (status == kStatus_SSS_Success) {
        LOG_I("ex_mbedtls3x_cbc Success");
    }
    else {
        ex_status = kStatus_SSS_Fail;
        LOG_I("ex_mbedtls3x_cbc Failed");
    }
    sss_mbedtls_set_keystore_aes(NULL);
    LOG_I("\n\n");

    LOG_I("******** Testing AES CMAC ALT ******** ");
    status = ex_mbedtls3x_cmac(pCtx);
    if (status == kStatus_SSS_Success) {
        LOG_I("ex_mbedtls3x_cmac Success");
    }
    else {
        ex_status = kStatus_SSS_Fail;
        LOG_I("ex_mbedtls3x_cmac Failed");
    }
    sss_mbedtls_set_keystore_aes(NULL);
    LOG_I("\n\n");
#endif
#endif
    if (ex_status == kStatus_SSS_Success) {
        LOG_I("ex_mbedtls_3_x_alt Example Success !!!...");
    }
    else {
        LOG_I("ex_mbedtls_3_x_alt Example Failed !!!...");
    }
    return status;
}
