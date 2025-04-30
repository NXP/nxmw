/* Copyright 2023-2024 NXP
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef _SSS_PSA_ALT_H_
#define _SSS_PSA_ALT_H_

#include <fsl_sss_api.h>

/* Session Open from driver->p_init API */
sss_status_t sss_psa_alt_session_open(void);

sss_status_t sss_psa_alt_generate_key(
    uint32_t keyId, size_t keyBitLen, sss_key_part_t keyPart, sss_cipher_type_t cipherType);

sss_status_t sss_psa_alt_import_key(uint32_t keyId,
    const uint8_t *data,
    size_t dataLen,
    size_t keyBitLen,
    sss_key_part_t keyPart,
    sss_cipher_type_t cipherType,
    void *options,
    size_t optionsLen);

sss_status_t sss_psa_alt_asymmetric_sign_digest(const uint32_t keyId,
    sss_algorithm_t sss_algorithm,
    uint8_t *digest,
    size_t digestLen,
    uint8_t *signature,
    size_t *signatureLen);

sss_status_t sss_psa_alt_asymmetric_verify_digest(const uint32_t keyId,
    sss_algorithm_t sss_algorithm,
    uint8_t *digest,
    size_t digestLen,
    uint8_t *signature,
    size_t signatureLen);

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
    size_t tagLen);

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
    size_t *plaintext_length);

sss_status_t sss_psa_alt_mac_compute(const uint32_t keyId,
    sss_algorithm_t sss_algorithm,
    const uint8_t *input,
    size_t input_length,
    uint8_t *mac,
    size_t *mac_length);

sss_status_t sss_psa_alt_mac_setup(const uint32_t keyId, sss_algorithm_t sss_algorithm, sss_mode_t mode);

sss_status_t sss_psa_alt_mac_update(
    const uint32_t keyId, sss_algorithm_t sss_algorithm, const uint8_t *p_input, size_t input_length, sss_mode_t mode);

sss_status_t sss_psa_alt_mac_finish(const uint32_t keyId,
    sss_algorithm_t sss_algorithm,
    uint8_t *p_mac,
    size_t mac_size,
    size_t *p_mac_length,
    sss_mode_t mode);

sss_status_t sss_psa_alt_cipher_set_iv(
    const uint32_t keyId, sss_algorithm_t sss_algorithm, const uint8_t *p_iv, size_t iv_length, sss_mode_t mode);

sss_status_t sss_psa_alt_cipher_update(const uint32_t keyId,
    sss_algorithm_t algorithm,
    const uint8_t *p_input,
    size_t input_size,
    uint8_t *p_output,
    size_t output_size,
    size_t *p_output_length,
    sss_mode_t mode);

sss_status_t sss_psa_alt_cipher_finish(const uint32_t keyId,
    sss_algorithm_t sss_algorithm,
    const uint8_t *p_input,
    size_t input_size,
    uint8_t *p_output,
    size_t output_size,
    size_t *p_output_length,
    sss_mode_t mode);

sss_status_t sss_psa_alt_ecb_one_go(const uint32_t keyId,
    sss_algorithm_t algorithm,
    const uint8_t *p_input,
    size_t input_size,
    uint8_t *p_output,
    size_t output_size,
    sss_mode_t mode);
#endif //_SSS_PSA_ALT_H_
