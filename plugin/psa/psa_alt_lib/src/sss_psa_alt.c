/* Copyright 2023-2024 NXP
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <string.h>

#include "sss_psa_alt.h"

#include <nxLog_msg.h>

#include "ex_sss_ports.h"
#include "ex_sss_boot.h"
#include "nxEnsure.h"

ex_sss_boot_ctx_t gPsaAltBootCtx;

/* Session Open from driver->p_init API */
sss_status_t sss_psa_alt_session_open()
{
    sss_status_t status = kStatus_SSS_Fail;
    char *portName;

    status = ex_sss_boot_connectstring(0, NULL, &portName);
    ENSURE_OR_GO_EXIT(kStatus_SSS_Success == status);

    ex_sss_session_close(&gPsaAltBootCtx);

    status = ex_sss_boot_open(&gPsaAltBootCtx, portName);
    ENSURE_OR_GO_EXIT(kStatus_SSS_Success == status);

    status = ex_sss_key_store_and_object_init(&gPsaAltBootCtx);
    ENSURE_OR_GO_EXIT(kStatus_SSS_Success == status);

exit:
#if defined(_MSC_VER)
    if (portName) {
        char *dummy_portName = NULL;
        size_t dummy_sz      = 0;
        _dupenv_s(&dummy_portName, &dummy_sz, EX_SSS_BOOT_SSS_PORT);
        if (NULL != dummy_portName) {
            free(dummy_portName);
            free(portName);
        }
    }
#endif // _MSC_VER
    return status;
}

sss_status_t sss_psa_alt_generate_key(
    uint32_t keyId, size_t keyBitLen, sss_key_part_t keyPart, sss_cipher_type_t cipherType)
{
    sss_status_t status     = kStatus_SSS_Fail;
    sss_object_t sss_object = {0};

    status = sss_key_object_init(&sss_object, &gPsaAltBootCtx.ks);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);
    status = sss_key_object_allocate_handle(&sss_object, keyId, keyPart, cipherType, 0, kKeyObject_Mode_Persistent);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);
    status = sss_key_store_generate_key(&gPsaAltBootCtx.ks, &sss_object, keyBitLen, NULL);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

exit:
    return status;
}

sss_status_t sss_psa_alt_import_key(uint32_t keyId,
    const uint8_t *data,
    size_t dataLen,
    size_t keyBitLen,
    sss_key_part_t keyPart,
    sss_cipher_type_t cipherType,
    void *options,
    size_t optionsLen)
{
    sss_status_t status     = kStatus_SSS_Fail;
    sss_object_t sss_object = {0};

    status = sss_key_object_init(&sss_object, &gPsaAltBootCtx.ks);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);
    status = sss_key_object_allocate_handle(
        &sss_object, keyId, keyPart, cipherType, (keyBitLen / 8), kKeyObject_Mode_Persistent);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);
    status = sss_key_store_set_key(&gPsaAltBootCtx.ks, &sss_object, data, dataLen, keyBitLen, options, sizeof(options));
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

exit:
    return status;
}

sss_status_t sss_psa_alt_asymmetric_sign_digest(const uint32_t keyId,
    sss_algorithm_t sss_algorithm,
    uint8_t *digest,
    size_t digestLen,
    uint8_t *signature,
    size_t *signatureLen)
{
    sss_status_t status        = kStatus_SSS_Fail;
    sss_object_t sss_object    = {0};
    sss_asymmetric_t asymm_ctx = {0};

    status = sss_key_object_init(&sss_object, &gPsaAltBootCtx.ks);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);
    status = sss_key_object_get_handle(&sss_object, kSSS_CipherType_EC_NIST_P, keyId);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    status =
        sss_asymmetric_context_init(&asymm_ctx, &gPsaAltBootCtx.session, &sss_object, sss_algorithm, kMode_SSS_Sign);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);
    status = sss_asymmetric_sign_digest(&asymm_ctx, digest, digestLen, signature, signatureLen);

exit:
    if (asymm_ctx.session != NULL) {
        sss_asymmetric_context_free(&asymm_ctx);
    }
    if (sss_object.keyStore != NULL) {
        sss_key_object_free(&sss_object);
    }
    return status;
}

sss_status_t sss_psa_alt_aead_encrypt(const uint32_t keyId,
    sss_algorithm_t algorithm,
    const uint8_t *nonce,
    size_t nonce_length,
    const uint8_t *additional_data,
    size_t additional_data_length,
    const uint8_t *plaintext,
    size_t plaintext_length,
    uint8_t *ciphertext,
    size_t ciphertext_size,
    size_t *ciphertext_length,
    uint8_t *tag,
    size_t tagLen)
{
    sss_status_t status     = kStatus_SSS_Fail;
    sss_object_t sss_object = {0};
    sss_aead_t aead_ctx     = {0};
    sss_mode_t mode         = kMode_SSS_Encrypt;

    status = sss_key_object_init(&sss_object, &gPsaAltBootCtx.ks);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    status = sss_key_object_get_handle(&sss_object, kSSS_CipherType_AES, keyId);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    status = sss_aead_context_init(&aead_ctx, &gPsaAltBootCtx.session, &sss_object, algorithm, mode);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    status = sss_aead_one_go(&aead_ctx,
        plaintext,
        ciphertext,
        ciphertext_size,
        (uint8_t *)nonce,
        nonce_length,
        additional_data,
        additional_data_length,
        tag,
        &tagLen);

    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

exit:
    if (sss_object.keyStore != NULL) {
        sss_key_object_free(&sss_object);
    }
    if (aead_ctx.session != NULL) {
        sss_aead_context_free(&aead_ctx);
    }

    return status;
}

sss_status_t sss_psa_alt_aead_decrypt(const uint32_t keyId,
    sss_algorithm_t algorithm,
    const uint8_t *nonce,
    size_t nonce_length,
    const uint8_t *additional_data,
    size_t additional_data_length,
    const uint8_t *ciphertext,
    size_t ciphertext_length,
    uint8_t *plaintext,
    size_t paintext_size,
    size_t *plaintext_length)
{
    sss_status_t status     = kStatus_SSS_Fail;
    sss_object_t sss_object = {0};
    sss_aead_t aead_ctx     = {0};
    sss_mode_t mode         = kMode_SSS_Decrypt;

    uint8_t tag[16] = {0};
    size_t tagLen   = sizeof(tag);

    memcpy(tag, ciphertext + paintext_size, tagLen);

    status = sss_key_object_init(&sss_object, &gPsaAltBootCtx.ks);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    status = sss_key_object_get_handle(&sss_object, kSSS_CipherType_AES, keyId);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    status = sss_aead_context_init(&aead_ctx, &gPsaAltBootCtx.session, &sss_object, algorithm, mode);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    status = sss_aead_one_go(&aead_ctx,
        ciphertext,
        plaintext,
        paintext_size,
        (uint8_t *)nonce,
        nonce_length,
        additional_data,
        additional_data_length,
        tag,
        &tagLen);

    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    *plaintext_length = ciphertext_length - tagLen;

exit:
    if (sss_object.keyStore != NULL) {
        sss_key_object_free(&sss_object);
    }
    if (aead_ctx.session != NULL) {
        sss_aead_context_free(&aead_ctx);
    }
    return status;
}

sss_status_t sss_psa_alt_mac_compute(const uint32_t keyId,
    sss_algorithm_t sss_algorithm,
    const uint8_t *input,
    size_t input_length,
    uint8_t *mac,
    size_t *mac_length)
{
    sss_status_t status     = kStatus_SSS_Fail;
    sss_object_t sss_object = {0};
    sss_mac_t mac_ctx       = {0};

    sss_mode_t mode = kMode_SSS_Mac;

    status = sss_key_object_init(&sss_object, &gPsaAltBootCtx.ks);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    status = sss_key_object_get_handle(&sss_object, kSSS_CipherType_AES, keyId);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    status = sss_mac_context_init(&mac_ctx, &gPsaAltBootCtx.session, &sss_object, sss_algorithm, mode);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    status = sss_mac_one_go(&mac_ctx, input, input_length, mac, mac_length);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

exit:
    if (sss_object.keyStore != NULL) {
        sss_key_object_free(&sss_object);
    }
    if (mac_ctx.session != NULL) {
        sss_mac_context_free(&mac_ctx);
    }
    return status;
}

sss_status_t sss_psa_alt_mac_setup(const uint32_t keyId, sss_algorithm_t sss_algorithm, sss_mode_t mode)
{
    sss_status_t status     = kStatus_SSS_Fail;
    sss_object_t sss_object = {0};
    sss_mac_t mac_ctx       = {0};

    status = sss_key_object_init(&sss_object, &gPsaAltBootCtx.ks);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    status = sss_key_object_get_handle(&sss_object, kSSS_CipherType_AES, keyId);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    status = sss_mac_context_init(&mac_ctx, &gPsaAltBootCtx.session, &sss_object, sss_algorithm, mode);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    status = sss_mac_init(&mac_ctx);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

exit:
    if (sss_object.keyStore != NULL) {
        sss_key_object_free(&sss_object);
    }
    if (mac_ctx.session != NULL) {
        sss_mac_context_free(&mac_ctx);
    }
    return status;
}

sss_status_t sss_psa_alt_mac_update(
    const uint32_t keyId, sss_algorithm_t sss_algorithm, const uint8_t *p_input, size_t input_length, sss_mode_t mode)
{
    sss_status_t status     = kStatus_SSS_Fail;
    sss_object_t sss_object = {0};
    sss_mac_t mac_ctx       = {0};

    status = sss_key_object_init(&sss_object, &gPsaAltBootCtx.ks);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    status = sss_key_object_get_handle(&sss_object, kSSS_CipherType_AES, keyId);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    status = sss_mac_context_init(&mac_ctx, &gPsaAltBootCtx.session, &sss_object, sss_algorithm, mode);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    status = sss_mac_update(&mac_ctx, p_input, input_length);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

exit:
    if (sss_object.keyStore != NULL) {
        sss_key_object_free(&sss_object);
    }
    if (mac_ctx.session != NULL) {
        sss_mac_context_free(&mac_ctx);
    }
    return status;
}

sss_status_t sss_psa_alt_mac_finish(const uint32_t keyId,
    sss_algorithm_t sss_algorithm,
    uint8_t *p_mac,
    size_t mac_size,
    size_t *p_mac_length,
    sss_mode_t mode)
{
    sss_status_t status     = kStatus_SSS_Fail;
    sss_object_t sss_object = {0};
    sss_mac_t mac_ctx       = {0};

    status = sss_key_object_init(&sss_object, &gPsaAltBootCtx.ks);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    status = sss_key_object_get_handle(&sss_object, kSSS_CipherType_AES, keyId);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    status = sss_mac_context_init(&mac_ctx, &gPsaAltBootCtx.session, &sss_object, sss_algorithm, mode);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    status = sss_mac_finish(&mac_ctx, p_mac, p_mac_length);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

exit:
    if (sss_object.keyStore != NULL) {
        sss_key_object_free(&sss_object);
    }
    if (mac_ctx.session != NULL) {
        sss_mac_context_free(&mac_ctx);
    }
    return status;
}

sss_status_t sss_psa_alt_cipher_set_iv(
    const uint32_t keyId, sss_algorithm_t sss_algorithm, const uint8_t *p_iv, size_t iv_length, sss_mode_t mode)
{
    sss_status_t status        = kStatus_SSS_Fail;
    sss_object_t sss_object    = {0};
    sss_symmetric_t cipher_ctx = {0};

    status = sss_key_object_init(&sss_object, &gPsaAltBootCtx.ks);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    status = sss_key_object_get_handle(&sss_object, kSSS_CipherType_AES, keyId);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    status = sss_symmetric_context_init(&cipher_ctx, &gPsaAltBootCtx.session, &sss_object, sss_algorithm, mode);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    status = sss_cipher_init(&cipher_ctx, (uint8_t *)p_iv, iv_length);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

exit:
    if (sss_object.keyStore != NULL) {
        sss_key_object_free(&sss_object);
    }
    if (cipher_ctx.session != NULL) {
        sss_symmetric_context_free(&cipher_ctx);
    }
    return status;
}

sss_status_t sss_psa_alt_cipher_update(const uint32_t keyId,
    sss_algorithm_t sss_algorithm,
    const uint8_t *p_input,
    size_t input_size,
    uint8_t *p_output,
    size_t output_size,
    size_t *p_output_length,
    sss_mode_t mode)
{
    sss_status_t status        = kStatus_SSS_Fail;
    sss_object_t sss_object    = {0};
    sss_symmetric_t cipher_ctx = {0};

    status = sss_key_object_init(&sss_object, &gPsaAltBootCtx.ks);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    status = sss_key_object_get_handle(&sss_object, kSSS_CipherType_AES, keyId);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    status = sss_symmetric_context_init(&cipher_ctx, &gPsaAltBootCtx.session, &sss_object, sss_algorithm, mode);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    status = sss_cipher_update(&cipher_ctx, (uint8_t *)p_input, input_size, p_output, &output_size);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

exit:
    if (sss_object.keyStore != NULL) {
        sss_key_object_free(&sss_object);
    }
    if (cipher_ctx.session != NULL) {
        sss_symmetric_context_free(&cipher_ctx);
    }
    return status;
}

sss_status_t sss_psa_alt_cipher_finish(const uint32_t keyId,
    sss_algorithm_t sss_algorithm,
    const uint8_t *p_input,
    size_t input_size,
    uint8_t *p_output,
    size_t output_size,
    size_t *p_output_length,
    sss_mode_t mode)
{
    sss_status_t status        = kStatus_SSS_Fail;
    sss_object_t sss_object    = {0};
    sss_symmetric_t cipher_ctx = {0};

    status = sss_key_object_init(&sss_object, &gPsaAltBootCtx.ks);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    status = sss_key_object_get_handle(&sss_object, kSSS_CipherType_AES, keyId);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    status = sss_symmetric_context_init(&cipher_ctx, &gPsaAltBootCtx.session, &sss_object, sss_algorithm, mode);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    status = sss_cipher_finish(&cipher_ctx, (uint8_t *)p_input, input_size, p_output, &output_size);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

exit:
    if (sss_object.keyStore != NULL) {
        sss_key_object_free(&sss_object);
    }
    if (cipher_ctx.session != NULL) {
        sss_symmetric_context_free(&cipher_ctx);
    }
    return status;
}

sss_status_t sss_psa_alt_ecb_one_go(const uint32_t keyId,
    sss_algorithm_t algorithm,
    const uint8_t *p_input,
    size_t input_size,
    uint8_t *p_output,
    size_t output_size,
    sss_mode_t mode)
{
    sss_status_t status        = kStatus_SSS_Fail;
    sss_object_t sss_object    = {0};
    sss_symmetric_t cipher_ctx = {0};

    status = sss_key_object_init(&sss_object, &gPsaAltBootCtx.ks);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    status = sss_key_object_get_handle(&sss_object, kSSS_CipherType_AES, keyId);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    status = sss_symmetric_context_init(&cipher_ctx, &gPsaAltBootCtx.session, &sss_object, algorithm, mode);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    status = sss_cipher_one_go(&cipher_ctx, NULL, 0, p_input, p_output, output_size);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

exit:
    if (sss_object.keyStore != NULL) {
        sss_key_object_free(&sss_object);
    }
    if (cipher_ctx.session != NULL) {
        sss_symmetric_context_free(&cipher_ctx);
    }
    return status;
}