/* Copyright 2023-2024 NXP
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "psa_alt.h"

#include <nxLog_msg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#include "psa/crypto.h"
#include "psa/crypto_se_driver.h"
#include "psa/crypto_types.h"
#include "psa/crypto_values.h"
#include "psa_alt_utils.h"
#include "psa_crypto_storage.h"
#include "sss_psa_alt.h"
#include "psa/crypto_extra.h"

psa_status_t psa_alt_driver_init(psa_drv_se_context_t *drv_context, void *persistent_data, psa_key_lifetime_t lifetime)
{
    psa_status_t psa_status = PSA_ERROR_GENERIC_ERROR;
    LOG_I("Initializing driver");
    sss_status_t status = kStatus_SSS_Fail;
    status              = sss_psa_alt_session_open();
    if (status == kStatus_SSS_Success) {
        psa_status = PSA_SUCCESS;
    }
    return psa_status;
}

psa_status_t psa_alt_allocate_key(psa_drv_se_context_t *drv_context,
    void *persistent_data,
    const psa_key_attributes_t *attributes,
    psa_key_creation_method_t method,
    psa_key_slot_number_t *key_slot)
{
    psa_status_t psa_status     = PSA_ERROR_GENERIC_ERROR;
    psa_key_id_t key_id         = psa_get_key_id(attributes);
    psa_key_type_t psa_key_type = psa_get_key_type(attributes);
    /* Return the keyID used by App.
     * We will manage masking in implementation
     */
    *key_slot = (uint64_t)(key_id);
    /* Mask App keyID to the keyID actually to be used.
     * We only need to use OBJECT_ID mask here.
     * ITS mask can be checked while creation/storing
     * object file
     */
    key_id = PSA_KEY_ID_TO_ALT_OBJECT_ID(key_id);

    psa_status = sss_check_if_object_exists(key_id, psa_key_type);
    if (psa_status == PSA_ERROR_DOES_NOT_EXIST) {
        psa_status = PSA_SUCCESS;
    }
    else if (psa_status == PSA_SUCCESS) {
        // psa_status = PSA_ERROR_ALREADY_EXISTS;
    }
    return psa_status;
}

psa_status_t psa_alt_import_key(psa_drv_se_context_t *drv_context,
    psa_key_slot_number_t key_slot,
    const psa_key_attributes_t *attributes,
    const uint8_t *data,
    size_t data_length,
    size_t *bits)
{
    psa_status_t psa_status      = PSA_ERROR_GENERIC_ERROR;
    sss_status_t sss_status      = kStatus_SSS_Fail;
    uint32_t se_key_id           = (uint32_t)PSA_KEY_ID_TO_ALT_OBJECT_ID(key_slot);
    psa_key_type_t psa_key_type  = psa_get_key_type(attributes);
    size_t key_size              = psa_get_key_bits(attributes);
    sss_cipher_type_t sss_cipher = kSSS_CipherType_NONE;
    sss_key_part_t sss_key_part  = kSSS_KeyPart_NONE;
    sss_policy_t *policyList     = NULL;
    size_t policyListLen         = 0;

    psa_status = sss_check_if_object_exists(se_key_id, psa_key_type);
    if (psa_status == PSA_SUCCESS) {
        // return PSA_ERROR_ALREADY_EXISTS;
    }

    sss_policy_u commonPolicy     = {.type = KPolicy_ChgAESKey,
        .policy                        = {.chgAesKey = {
                       .hkdfEnabled        = 0,
                       .hmacEnabled        = 0,
                       .aeadEncIntEnabled  = 0,
                       .aeadDecEnabled     = 0,
                       .aeadEncEnabled     = 0,
                       .ecb_cbc_EncEnabled = 0,
                       .ecb_cbc_DecEnabled = 0,
                       .macSignEnabled     = 0,
                       .macVerifyEnabled   = 0,
                   }}};
    sss_policy_t commonPolicyList = {.nPolicies = 1, .policies = {&commonPolicy}};

    if (psa_key_type == PSA_KEY_TYPE_AES) {
        commonPolicy.policy.chgAesKey.hkdfEnabled        = 0;
        commonPolicy.policy.chgAesKey.hmacEnabled        = 0;
        commonPolicy.policy.chgAesKey.aeadEncIntEnabled  = 1;
        commonPolicy.policy.chgAesKey.aeadDecEnabled     = 1;
        commonPolicy.policy.chgAesKey.aeadEncEnabled     = 1;
        commonPolicy.policy.chgAesKey.ecb_cbc_EncEnabled = 1;
        commonPolicy.policy.chgAesKey.ecb_cbc_DecEnabled = 1;
        commonPolicy.policy.chgAesKey.macSignEnabled     = 0;
        commonPolicy.policy.chgAesKey.macVerifyEnabled   = 0;
    }
    else if (psa_key_type == PSA_KEY_TYPE_HMAC) {
        commonPolicy.policy.chgAesKey.hkdfEnabled        = 0;
        commonPolicy.policy.chgAesKey.hmacEnabled        = 1;
        commonPolicy.policy.chgAesKey.aeadEncIntEnabled  = 0;
        commonPolicy.policy.chgAesKey.aeadDecEnabled     = 0;
        commonPolicy.policy.chgAesKey.aeadEncEnabled     = 0;
        commonPolicy.policy.chgAesKey.ecb_cbc_EncEnabled = 0;
        commonPolicy.policy.chgAesKey.ecb_cbc_DecEnabled = 0;
        commonPolicy.policy.chgAesKey.macSignEnabled     = 0;
        commonPolicy.policy.chgAesKey.macVerifyEnabled   = 0;
    }

    policyList    = &(commonPolicyList);
    policyListLen = sizeof(commonPolicyList);

    psa_status = psa_key_type_to_sss_cipher(psa_key_type, &sss_cipher, &sss_key_part);
    if (psa_status != PSA_SUCCESS) {
        LOG_E("Incorrect attributes %d", __LINE__);
        return psa_status;
    }
    else if (sss_key_part == kSSS_KeyPart_Public) {
        /* TODO: Implement a KeyStore which will save the Public keys. */
        LOG_E("Public Key Import Not supported. ", __LINE__);
        return PSA_ERROR_NOT_SUPPORTED;
    }

    *bits = key_size;

    uint8_t formatted_data[512] = {0};
    size_t formatted_data_len   = sizeof(formatted_data);

    memcpy(formatted_data, data, data_length);
    formatted_data_len = data_length;

    if (key_size != 0 && key_size != *bits) {
        if (sss_key_part == kSSS_KeyPart_Default) {
            /* Only specific lengths are supported.
             * If some other value is passed, the argument is invalid
             */
            return PSA_ERROR_INVALID_ARGUMENT;
        }
        else {
            /* Different bit sizes can be supported but we
             * don't support the passed bit size
             */
            return PSA_ERROR_NOT_SUPPORTED;
        }
    }

    if (psa_key_type == PSA_KEY_TYPE_AES) {
        sss_status = sss_psa_alt_import_key(
            se_key_id, formatted_data, formatted_data_len, *bits, sss_key_part, sss_cipher, policyList, policyListLen);
    }
    else if (psa_key_type == PSA_KEY_TYPE_HMAC) {
        sss_status = sss_psa_alt_import_key(
            se_key_id, formatted_data, formatted_data_len, *bits, sss_key_part, sss_cipher, policyList, policyListLen);
    }
    else if (sss_key_part == kSSS_KeyPart_Public || sss_key_part == kSSS_KeyPart_Pair) {
        sss_status = sss_psa_alt_import_key(
            se_key_id, formatted_data, formatted_data_len, *bits, sss_key_part, sss_cipher, NULL, 0);
    }

    if (sss_status != kStatus_SSS_Success) {
        return PSA_ERROR_HARDWARE_FAILURE;
    }

    return PSA_SUCCESS;
}

psa_status_t psa_alt_generate_key(psa_drv_se_context_t *drv_context,
    psa_key_slot_number_t key_slot,
    const psa_key_attributes_t *attributes,
    uint8_t *pubkey,
    size_t pubkey_size,
    size_t *pubkey_length)
{
    LOG_D("%s", __FUNCTION__);
    psa_status_t psa_status = PSA_ERROR_GENERIC_ERROR;
    sss_status_t sss_status = kStatus_SSS_Fail;
    uint32_t se_key_id      = (uint32_t)PSA_KEY_ID_TO_ALT_OBJECT_ID(key_slot);

    psa_status = sss_check_if_object_exists(se_key_id, attributes->private_type);
    if (psa_status == PSA_SUCCESS) {
        //return PSA_ERROR_ALREADY_EXISTS;
    }

    psa_key_type_t psa_key_type   = psa_get_key_type(attributes);
    size_t key_size               = psa_get_key_bits(attributes);
    sss_cipher_type_t sss_cipher  = kSSS_CipherType_NONE;
    sss_key_part_t sss_key_part   = kSSS_KeyPart_NONE;
    uint8_t *key                  = NULL;
    size_t keyLen                 = 0;
    sss_policy_u aeskeyPolicy     = {.type = KPolicy_ChgAESKey,
        .policy                        = {.chgAesKey = {
                       .hkdfEnabled        = 0,
                       .hmacEnabled        = 0,
                       .aeadEncIntEnabled  = 0,
                       .aeadEncEnabled     = 0,
                       .aeadDecEnabled     = 0,
                       .ecb_cbc_EncEnabled = 0,
                       .ecb_cbc_DecEnabled = 0,
                       .macSignEnabled     = 0,
                       .macVerifyEnabled   = 0,
                   }}};
    sss_policy_t aeskeyPolicyList = {.nPolicies = 1, .policies = {&aeskeyPolicy}};

    if (psa_key_type == PSA_KEY_TYPE_AES) {
        aeskeyPolicy.policy.chgAesKey.hkdfEnabled        = 0;
        aeskeyPolicy.policy.chgAesKey.hmacEnabled        = 0;
        aeskeyPolicy.policy.chgAesKey.aeadEncIntEnabled  = 1;
        aeskeyPolicy.policy.chgAesKey.aeadDecEnabled     = 1;
        aeskeyPolicy.policy.chgAesKey.aeadEncEnabled     = 1;
        aeskeyPolicy.policy.chgAesKey.ecb_cbc_EncEnabled = 1;
        aeskeyPolicy.policy.chgAesKey.ecb_cbc_DecEnabled = 1;
        aeskeyPolicy.policy.chgAesKey.macSignEnabled     = 0;
        aeskeyPolicy.policy.chgAesKey.macVerifyEnabled   = 0;
    }
    else if (psa_key_type == PSA_KEY_TYPE_HMAC) {
        aeskeyPolicy.policy.chgAesKey.hkdfEnabled        = 0;
        aeskeyPolicy.policy.chgAesKey.hmacEnabled        = 1;
        aeskeyPolicy.policy.chgAesKey.aeadEncIntEnabled  = 0;
        aeskeyPolicy.policy.chgAesKey.aeadDecEnabled     = 0;
        aeskeyPolicy.policy.chgAesKey.aeadEncEnabled     = 0;
        aeskeyPolicy.policy.chgAesKey.ecb_cbc_EncEnabled = 0;
        aeskeyPolicy.policy.chgAesKey.ecb_cbc_DecEnabled = 0;
        aeskeyPolicy.policy.chgAesKey.macSignEnabled     = 0;
        aeskeyPolicy.policy.chgAesKey.macVerifyEnabled   = 0;
    }

    psa_status = psa_key_type_to_sss_cipher(psa_key_type, &sss_cipher, &sss_key_part);
    if (psa_status != PSA_SUCCESS) {
        LOG_E("Incorrect attributes %d", __LINE__);
        return psa_status;
    }

    if (sss_key_part == kSSS_KeyPart_Public) {
        LOG_E("Cannot generate public key");
        return PSA_ERROR_NOT_SUPPORTED;
    }

    psa_status = sss_cipher_validate_key_size(sss_cipher, key_size);
    if (psa_status != PSA_SUCCESS) {
        LOG_E("Unsupported key size");
        return psa_status;
    }

    if (sss_key_part != kSSS_KeyPart_Default) {
        sss_status = sss_psa_alt_generate_key(se_key_id, key_size, sss_key_part, sss_cipher);
        if (sss_status != kStatus_SSS_Success) {
            LOG_E("Key generation failed");
            return PSA_ERROR_HARDWARE_FAILURE;
        }
        else {
            return PSA_SUCCESS;
        }
    }
    else {
        key    = (uint8_t *)SSS_MALLOC(sizeof(uint8_t) * (key_size / 8));
        keyLen = key_size / 8;
        goto generate_random;
    }

generate_random:
    psa_status = psa_generate_random_symmetric_key(key, &keyLen, key_size / 8);
    if (psa_status != PSA_SUCCESS) {
        if (key) {
            SSS_FREE(key);
        }
        return psa_status;
    }
    sss_status = sss_psa_alt_import_key(
        se_key_id, key, keyLen, keyLen * 8, sss_key_part, sss_cipher, &aeskeyPolicyList, sizeof(aeskeyPolicyList));
    if (key) {
        SSS_FREE(key);
    }
    if (sss_status != kStatus_SSS_Success) {
        LOG_E("Key generation failed");
        return PSA_ERROR_HARDWARE_FAILURE;
    }

    return PSA_SUCCESS;
}

psa_status_t psa_alt_asymmetric_sign_digest(psa_drv_se_context_t *drv_context,
    psa_key_slot_number_t key_slot,
    psa_algorithm_t alg,
    const uint8_t *p_hash,
    size_t hash_length,
    uint8_t *p_signature,
    size_t signature_size,
    size_t *p_signature_length)
{
    psa_status_t psa_status = PSA_ERROR_GENERIC_ERROR;
    sss_status_t sss_status = kStatus_SSS_Fail;
    uint32_t se_key_id      = (uint32_t)PSA_KEY_ID_TO_ALT_OBJECT_ID(key_slot);

    psa_status = sss_check_if_object_exists(se_key_id, 0);
    if (psa_status != PSA_SUCCESS) {
        return PSA_ERROR_DOES_NOT_EXIST;
    }

    sss_algorithm_t sss_algorithm = kAlgorithm_None;
    psa_status                    = psa_algorithm_to_sss_algorithm(alg, &sss_algorithm);
    if (psa_status != PSA_SUCCESS) {
        return psa_status;
    }

    psa_status = validate_sign_input_data(se_key_id, alg, p_hash, hash_length);
    if (psa_status != PSA_SUCCESS) {
        return psa_status;
    }

    psa_status = nx_sign_check_input_len(hash_length, sss_algorithm);
    if (psa_status != PSA_SUCCESS) {
        return psa_status;
    }

    uint8_t *pHash = (uint8_t *)SSS_MALLOC(sizeof(uint8_t) * hash_length);
    if (pHash == NULL) {
        return PSA_ERROR_INSUFFICIENT_MEMORY;
    }
    memset(pHash, 0, hash_length);
    memcpy(pHash, p_hash, hash_length);

    uint8_t signature[512] = {0};
    size_t sig_len         = sizeof(signature);

    sss_status = sss_psa_alt_asymmetric_sign_digest(se_key_id, sss_algorithm, pHash, hash_length, signature, &sig_len);

    if (pHash) {
        SSS_FREE(pHash);
    }

    if (sss_status != kStatus_SSS_Success) {
        *p_signature_length = 0;
        return PSA_ERROR_HARDWARE_FAILURE;
    }
    if (PSA_ALG_IS_RANDOMIZED_ECDSA(alg)) {
        if (0 != EcSignatureToRandS(signature, &sig_len)) {
            *p_signature_length = 0;
            return PSA_ERROR_DATA_CORRUPT;
        }
    }
    if (signature_size < sig_len) {
        *p_signature_length = 0;
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    memcpy(p_signature, signature, sig_len);
    *p_signature_length = sig_len;

    return PSA_SUCCESS;
}

psa_status_t psa_alt_aead_encrypt(psa_drv_se_context_t *drv_context,
    psa_key_slot_number_t key_slot,
    psa_algorithm_t alg,
    const uint8_t *nonce,
    size_t nonce_length,
    const uint8_t *additional_data,
    size_t additional_data_length,
    const uint8_t *plaintext,
    size_t plaintext_length,
    uint8_t *ciphertext,
    size_t ciphertext_size,
    size_t *ciphertext_length)
{
    psa_status_t psa_status = PSA_ERROR_GENERIC_ERROR;
    sss_status_t sss_status = kStatus_SSS_Fail;
    uint32_t se_key_id      = (uint32_t)PSA_KEY_ID_TO_ALT_OBJECT_ID(key_slot);

    sss_algorithm_t sss_algorithm = kAlgorithm_None;
    psa_status                    = psa_algorithm_to_sss_algorithm(alg, &sss_algorithm);
    if (psa_status != PSA_SUCCESS) {
        return psa_status;
    }

    uint8_t tag[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    size_t tagLen   = sizeof(tag);

    if ((ciphertext_size < tagLen) || (ciphertext_size - tagLen) < plaintext_length) {
        LOG_E("Not Enough Buffer to Store Ciphertext and Tag");
    }

    ciphertext_size = plaintext_length;

    sss_status = sss_psa_alt_aead_encrypt(se_key_id,
        sss_algorithm,
        nonce,
        nonce_length,
        additional_data,
        additional_data_length,
        plaintext,
        plaintext_length,
        ciphertext,
        ciphertext_size,
        ciphertext_length,
        tag,
        tagLen);

    if (sss_status != kStatus_SSS_Success) {
        return psa_status;
    }

    memcpy(ciphertext + plaintext_length, tag, tagLen);
    *ciphertext_length = plaintext_length + tagLen;

    return PSA_SUCCESS;
}

psa_status_t psa_alt_aead_decrypt(psa_drv_se_context_t *drv_context,
    psa_key_slot_number_t key_slot,
    psa_algorithm_t alg,
    const uint8_t *nonce,
    size_t nonce_length,
    const uint8_t *additional_data,
    size_t additional_data_length,
    const uint8_t *ciphertext,
    size_t ciphertext_length,
    uint8_t *plaintext,
    size_t plaintext_size,
    size_t *plaintext_length)
{
    psa_status_t psa_status = PSA_ERROR_GENERIC_ERROR;
    sss_status_t sss_status = kStatus_SSS_Fail;
    uint32_t se_key_id      = (uint32_t)PSA_KEY_ID_TO_ALT_OBJECT_ID(key_slot);

    sss_algorithm_t sss_algorithm = kAlgorithm_None;
    psa_status                    = psa_algorithm_to_sss_algorithm(alg, &sss_algorithm);
    if (psa_status != PSA_SUCCESS) {
        return psa_status;
    }

    sss_status = sss_psa_alt_aead_decrypt(se_key_id,
        sss_algorithm,
        nonce,
        nonce_length,
        additional_data,
        additional_data_length,
        ciphertext,
        ciphertext_length,
        plaintext,
        plaintext_size,
        plaintext_length);

    if (sss_status != kStatus_SSS_Success) {
        return psa_status;
    }

    return PSA_SUCCESS;
}

psa_status_t psa_alt_mac_compute(psa_drv_se_context_t *drv_context,
    const uint8_t *input,
    size_t input_length,
    psa_key_slot_number_t key_slot,
    psa_algorithm_t alg,
    uint8_t *mac,
    size_t mac_size,
    size_t *mac_length)
{
    psa_status_t psa_status = PSA_ERROR_STORAGE_FAILURE;
    sss_status_t sss_status = kStatus_SSS_Fail;
    uint32_t se_key_id      = (uint32_t)PSA_KEY_ID_TO_ALT_OBJECT_ID(key_slot);
    size_t rsp_mac_length   = mac_size;

    sss_algorithm_t sss_algorithm = kAlgorithm_None;
    psa_status                    = psa_algorithm_to_sss_algorithm(alg, &sss_algorithm);
    if (psa_status != PSA_SUCCESS) {
        return psa_status;
    }

    sss_status = sss_psa_alt_mac_compute(se_key_id, sss_algorithm, input, input_length, mac, &rsp_mac_length);
    if (sss_status != kStatus_SSS_Success) {
        psa_status = PSA_ERROR_STORAGE_FAILURE;
        return psa_status;
    }

    *mac_length = rsp_mac_length;

    return PSA_SUCCESS;
}

psa_status_t psa_alt_mac_setup(psa_drv_se_context_t *drv_context,
    psa_mac_operation_t *op_context,
    psa_key_slot_number_t key_slot,
    psa_algorithm_t algorithm)
{
    psa_status_t psa_status = PSA_ERROR_STORAGE_FAILURE;
    sss_status_t sss_status = kStatus_SSS_Fail;

    op_context->private_ctx.mbedtls_ctx.private_alg = algorithm;
    op_context->private_id                          = key_slot;

    uint32_t se_key_id            = (uint32_t)PSA_KEY_ID_TO_ALT_OBJECT_ID(key_slot);
    sss_algorithm_t sss_algorithm = kAlgorithm_None;
    sss_mode_t mode               = 0;
    psa_status                    = psa_algorithm_to_sss_algorithm(algorithm, &sss_algorithm);
    if (psa_status != PSA_SUCCESS) {
        return psa_status;
    }
    if (op_context->private_is_sign == 1) {
        mode = kMode_SSS_Mac;
    }
    else {
        mode = kMode_SSS_Mac_Validate;
    }
    sss_status = sss_psa_alt_mac_setup(se_key_id, sss_algorithm, mode);
    if (sss_status != kStatus_SSS_Success) {
        psa_status = PSA_ERROR_STORAGE_FAILURE;
        return psa_status;
    }

    return PSA_SUCCESS;
}

psa_status_t psa_alt_mac_update(psa_mac_operation_t *op_context, const uint8_t *p_input, size_t input_length)
{
    psa_status_t psa_status = PSA_ERROR_STORAGE_FAILURE;
    sss_status_t sss_status = kStatus_SSS_Fail;
    uint32_t se_key_id      = (uint32_t)PSA_KEY_ID_TO_ALT_OBJECT_ID(op_context->private_id);
    psa_algorithm_t alg     = op_context->private_ctx.mbedtls_ctx.private_alg;
    sss_mode_t mode         = 0;

    sss_algorithm_t sss_algorithm = kAlgorithm_None;
    psa_status                    = psa_algorithm_to_sss_algorithm(alg, &sss_algorithm);
    if (psa_status != PSA_SUCCESS) {
        return psa_status;
    }

    if (op_context->private_is_sign == 1) {
        mode = kMode_SSS_Mac;
    }
    else {
        mode = kMode_SSS_Mac_Validate;
    }
    sss_status = sss_psa_alt_mac_update(se_key_id, sss_algorithm, p_input, input_length, mode);
    if (sss_status != kStatus_SSS_Success) {
        psa_status = PSA_ERROR_STORAGE_FAILURE;
        return psa_status;
    }

    return PSA_SUCCESS;
}

psa_status_t psa_alt_mac_finish(psa_mac_operation_t *op_context, uint8_t *p_mac, size_t mac_size, size_t *p_mac_length)
{
    psa_status_t psa_status = PSA_ERROR_STORAGE_FAILURE;
    sss_status_t sss_status = kStatus_SSS_Fail;
    uint32_t se_key_id      = (uint32_t)PSA_KEY_ID_TO_ALT_OBJECT_ID(op_context->private_id);
    psa_algorithm_t alg     = op_context->private_ctx.mbedtls_ctx.private_alg;
    sss_mode_t mode         = 0;
    size_t rsp_mac_len      = mac_size;

    sss_algorithm_t sss_algorithm = kAlgorithm_None;
    psa_status                    = psa_algorithm_to_sss_algorithm(alg, &sss_algorithm);
    if (psa_status != PSA_SUCCESS) {
        return psa_status;
    }

    if (op_context->private_is_sign == 1) {
        mode = kMode_SSS_Mac;
    }
    else {
        mode = kMode_SSS_Mac_Validate;
    }
    sss_status = sss_psa_alt_mac_finish(se_key_id, sss_algorithm, p_mac, mac_size, &rsp_mac_len, mode);
    if (sss_status != kStatus_SSS_Success) {
        psa_status = PSA_ERROR_STORAGE_FAILURE;
        return psa_status;
    }

    return PSA_SUCCESS;
}

psa_status_t psa_alt_mac_abort(psa_mac_operation_t *op_context)
{
    if (op_context != NULL) {
        memset(op_context, 0, sizeof(psa_cipher_operation_t));
    }
    return PSA_SUCCESS;
}

psa_status_t psa_alt_cipher_setup(psa_drv_se_context_t *drv_context,
    psa_cipher_operation_t *op_context,
    psa_key_slot_number_t key_slot,
    psa_algorithm_t algorithm,
    psa_encrypt_or_decrypt_t direction)
{
    op_context->private_ctx.mbedtls_ctx.private_alg = algorithm;
    op_context->private_id                          = (uint32_t)PSA_KEY_ID_TO_ALT_OBJECT_ID(key_slot);
    op_context->private_ctx.mbedtls_ctx.private_ctx.private_cipher.private_operation = (mbedtls_operation_t)direction;

    if (algorithm == PSA_ALG_ECB_NO_PADDING) {
        op_context->private_iv_required = 1;
    }

    return PSA_SUCCESS;
}

psa_status_t psa_alt_cipher_set_iv(psa_cipher_operation_t *op_context, const uint8_t *p_iv, size_t iv_length)
{
    psa_status_t psa_status = PSA_ERROR_STORAGE_FAILURE;
    sss_status_t sss_status = kStatus_SSS_Fail;
    uint32_t se_key_id      = (uint32_t)PSA_KEY_ID_TO_ALT_OBJECT_ID(op_context->private_id);
    psa_algorithm_t alg     = op_context->private_ctx.mbedtls_ctx.private_alg;
    sss_mode_t mode         = 0;

    sss_algorithm_t sss_algorithm = kAlgorithm_None;
    psa_status                    = psa_algorithm_to_sss_algorithm(alg, &sss_algorithm);
    if (psa_status != PSA_SUCCESS) {
        return psa_status;
    }

    if (op_context->private_ctx.mbedtls_ctx.private_ctx.private_cipher.private_operation ==
        (mbedtls_operation_t)PSA_CRYPTO_DRIVER_ENCRYPT) {
        mode = kMode_SSS_Encrypt;
    }
    else if (op_context->private_ctx.mbedtls_ctx.private_ctx.private_cipher.private_operation ==
             (mbedtls_operation_t)PSA_CRYPTO_DRIVER_DECRYPT) {
        mode = kMode_SSS_Decrypt;
    }
    if (sss_algorithm == kAlgorithm_SSS_AES_CBC) {
        sss_status = sss_psa_alt_cipher_set_iv(se_key_id, sss_algorithm, p_iv, iv_length, mode);
    }
    else if (sss_algorithm == kAlgorithm_SSS_AES_ECB) {
        sss_status = sss_psa_alt_cipher_set_iv(se_key_id, sss_algorithm, NULL, 0, mode);
    }
    if (sss_status != kStatus_SSS_Success) {
        psa_status = PSA_ERROR_STORAGE_FAILURE;
        return psa_status;
    }

    return PSA_SUCCESS;
}

psa_status_t psa_alt_cipher_update(psa_cipher_operation_t *op_context,
    const uint8_t *p_input,
    size_t input_size,
    uint8_t *p_output,
    size_t output_size,
    size_t *p_output_length)
{
    psa_status_t psa_status = PSA_ERROR_STORAGE_FAILURE;
    sss_status_t sss_status = kStatus_SSS_Fail;
    uint32_t se_key_id      = (uint32_t)PSA_KEY_ID_TO_ALT_OBJECT_ID(op_context->private_id);
    psa_algorithm_t alg     = op_context->private_ctx.mbedtls_ctx.private_alg;
    sss_mode_t mode         = 0;
    size_t rsp_enc_length   = output_size;

    sss_algorithm_t sss_algorithm = kAlgorithm_None;
    psa_status                    = psa_algorithm_to_sss_algorithm(alg, &sss_algorithm);
    if (psa_status != PSA_SUCCESS) {
        return psa_status;
    }

    if (op_context->private_ctx.mbedtls_ctx.private_ctx.private_cipher.private_operation ==
        (mbedtls_operation_t)PSA_CRYPTO_DRIVER_ENCRYPT) {
        mode = kMode_SSS_Encrypt;
    }
    else if (op_context->private_ctx.mbedtls_ctx.private_ctx.private_cipher.private_operation ==
             (mbedtls_operation_t)PSA_CRYPTO_DRIVER_DECRYPT) {
        mode = kMode_SSS_Decrypt;
    }

    sss_status = sss_psa_alt_cipher_update(
        se_key_id, sss_algorithm, p_input, input_size, p_output, output_size, &rsp_enc_length, mode);
    if (sss_status != kStatus_SSS_Success) {
        psa_status = PSA_ERROR_STORAGE_FAILURE;
        return psa_status;
    }
    *p_output_length = rsp_enc_length;

    return PSA_SUCCESS;
}

psa_status_t psa_alt_cipher_finish(
    psa_cipher_operation_t *op_context, uint8_t *p_output, size_t output_size, size_t *p_output_length)
{
    psa_status_t psa_status = PSA_ERROR_STORAGE_FAILURE;
    sss_status_t sss_status = kStatus_SSS_Fail;
    uint32_t se_key_id      = (uint32_t)PSA_KEY_ID_TO_ALT_OBJECT_ID(op_context->private_id);
    psa_algorithm_t alg     = op_context->private_ctx.mbedtls_ctx.private_alg;
    sss_mode_t mode         = 0;
    size_t rsp_enc_length   = output_size;

    sss_algorithm_t sss_algorithm = kAlgorithm_None;
    psa_status                    = psa_algorithm_to_sss_algorithm(alg, &sss_algorithm);
    if (psa_status != PSA_SUCCESS) {
        return psa_status;
    }

    if (op_context->private_ctx.mbedtls_ctx.private_ctx.private_cipher.private_operation ==
        (mbedtls_operation_t)PSA_CRYPTO_DRIVER_ENCRYPT) {
        mode = kMode_SSS_Encrypt;
    }
    else if (op_context->private_ctx.mbedtls_ctx.private_ctx.private_cipher.private_operation ==
             (mbedtls_operation_t)PSA_CRYPTO_DRIVER_DECRYPT) {
        mode = kMode_SSS_Decrypt;
    }

    sss_status =
        sss_psa_alt_cipher_finish(se_key_id, sss_algorithm, NULL, 0, p_output, output_size, &rsp_enc_length, mode);
    if (sss_status != kStatus_SSS_Success) {
        psa_status = PSA_ERROR_STORAGE_FAILURE;
        return psa_status;
    }

    *p_output_length = rsp_enc_length;

    return PSA_SUCCESS;
}
psa_status_t psa_alt_cipher_abort(psa_cipher_operation_t *op_context)
{
    if (op_context != NULL) {
        memset(op_context, 0, sizeof(psa_cipher_operation_t));
    }

    return PSA_SUCCESS;
}

psa_status_t psa_alt_cipher_ecb(psa_drv_se_context_t *drv_context,
    psa_key_slot_number_t key_slot,
    psa_algorithm_t algorithm,
    psa_encrypt_or_decrypt_t direction,
    const uint8_t *p_input,
    size_t input_size,
    uint8_t *p_output,
    size_t output_size)
{
    psa_status_t psa_status = PSA_ERROR_GENERIC_ERROR;
    sss_status_t sss_status = kStatus_SSS_Fail;
    uint32_t se_key_id      = (uint32_t)PSA_KEY_ID_TO_ALT_OBJECT_ID(key_slot);
    sss_mode_t mode         = 0;

    sss_algorithm_t sss_algorithm = kAlgorithm_None;
    psa_status                    = psa_algorithm_to_sss_algorithm(algorithm, &sss_algorithm);
    if (psa_status != PSA_SUCCESS) {
        return psa_status;
    }

    if (direction == PSA_CRYPTO_DRIVER_ENCRYPT) {
        mode = kMode_SSS_Encrypt;
    }
    else if (direction == PSA_CRYPTO_DRIVER_DECRYPT) {
        mode = kMode_SSS_Decrypt;
    }

    sss_status = sss_psa_alt_ecb_one_go(se_key_id, sss_algorithm, p_input, input_size, p_output, output_size, mode);
    if (sss_status != kStatus_SSS_Success) {
        psa_status = PSA_ERROR_STORAGE_FAILURE;
        return psa_status;
    }

    return PSA_SUCCESS;
}
