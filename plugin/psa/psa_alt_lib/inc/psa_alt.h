/* Copyright 2023-2024 NXP
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef _PSA_ALT_H_
#define _PSA_ALT_H_

#include "psa/crypto.h"
#include "psa/crypto_se_driver.h"
#include "psa/crypto_types.h"
#include "psa/crypto_values.h"
#include "psa_crypto_its.h"
#include "psa_crypto_se.h"

/************************************************************************
 * Definitions
 ************************************************************************/

/* PSA_CRYPTO_SE_DRIVER_ITS_UID_BASE = 0xfffffe00 */

/* Driver keystore file is defined as File Permissions (32-bit)
 * (PSA_CRYPTO_SE_DRIVER_ITS_UID_BASE (32-bit) + lifetime)
 */

#define PSA_ALT_NX_LOCATION 1
#define PSA_ALT_NX_LIFETIME (PSA_ALT_NX_LOCATION << 8)
#define PSA_ALT_LIFETIME_FILE 0x1FFFFFFF

/* Transaction file : PSA_CRYPTO_ITS_TRANSACTION_UID = 0xffffff74 */
#define PSA_ALT_TRANSACTION_FILE 0x1FFFFFFE

/** Use of Internal KeyIDs
 *  0x2xxxxxxx -> Object files
 *  0x3xxxxxxx -> Secure Objects
 *
 *  KeyID and slotID can be used inter-changeably by the app.
 *  App can specify whether to store object file in SE or flash.
 *
 *  Slot number (Application keyID) ranges
 *  0x00000001 - 0x0FFFFFFF -> Require Flash storage for object files.
 *  0x10000000 - 0x1FFFFFFF -> Require SE storage for object files.
 *
 *  If bit 28 of the keyID sent by app is 1, we will use SE to store
 *  object files. Otherwise, we will use flash to store object files.
 *  Most significant nibble is still masked out - effective keyID is
 *  28-bit.
 */

/**
 *  Note - Since we have effective keyID of 28-bits, we can use
 *  4 most significant bits as flags if required.
 *
 *  PSA library also internally checks the keyID. According to PSA,
 *  the application keyID range is from 0x00000001 - 0x3fffffff.
 *  So, if application passes a keyID greater that 0x3fffffff, it fails.
 *  There is an option for vendor keyID which can be in range
 *  0x40000000 - 0x7fffffff. But this is only used in psa_open_key.
 *  While creating a new key, vendor keyID is not checked.
 *
 *  So, we can use only 2 flags, for bit-28 and bit-29.
 */

#define PSA_ALT_OBJECT_FILE_START 0x20000000
#define PSA_ALT_OBJECT_FILE_MASK 0xF0000000
#define PSA_ALT_OBJECT_FILE_END 0x2FFFFFFF

//#define PSA_ALT_OBJECT_START 0x30000000
#define PSA_ALT_OBJECT_START 0x0

#define PSA_ALT_OBJECT_END 0x3FFFFFFF

#define PSA_ALT_ITS_SE_FLAG ((0x1) << 28)
#define PSA_ALT_ITS_SE_MASK PSA_ALT_ITS_SE_FLAG

#define PSA_KEY_ID_TO_ALT_OBJECT_ID(id) ((id & (~PSA_ALT_OBJECT_FILE_MASK)) | PSA_ALT_OBJECT_START)
#define PSA_KEY_ID_TO_ITS_KEY_ID(id) ((id & (~PSA_ALT_OBJECT_FILE_MASK)) | PSA_ALT_OBJECT_FILE_START)

#define PSA_KEY_ID_NEEDS_ITS_FLASH(id) (!((uint32_t)(id & PSA_ALT_ITS_SE_MASK)))
#define PSA_KEY_ID_NEEDS_ITS_SE(id) (((uint32_t)(id & PSA_ALT_ITS_SE_MASK)))

#define EXPORT_MAX_DATA_KEY_BUFLEN 2048

/** The driver initialization function.
 *
 *  Refer to mbed-crypto\include\psa\crypto_se_driver.h
 */
psa_status_t psa_alt_driver_init(psa_drv_se_context_t *drv_context, void *persistent_data, psa_key_lifetime_t lifetime);

/** psa_drv_se_key_management_t APIs */

/** Function that allocates a slot for a key.
 *  Refer to mbed-crypto\include\psa\crypto_se_driver.h
 */
psa_status_t psa_alt_allocate_key(psa_drv_se_context_t *drv_context,
    void *persistent_data,
    const psa_key_attributes_t *attributes,
    psa_key_creation_method_t method,
    psa_key_slot_number_t *key_slot);

/** Function that performs a key import operation
 *  Refer to mbed-crypto\include\psa\crypto_se_driver.h
 */
psa_status_t psa_alt_import_key(psa_drv_se_context_t *drv_context,
    psa_key_slot_number_t key_slot,
    const psa_key_attributes_t *attributes,
    const uint8_t *data,
    size_t data_length,
    size_t *bits);

/** Function that performs a generation
 *  Refer to mbed-crypto\include\psa\crypto_se_driver.h
 */
psa_status_t psa_alt_generate_key(psa_drv_se_context_t *drv_context,
    psa_key_slot_number_t key_slot,
    const psa_key_attributes_t *attributes,
    uint8_t *pubkey,
    size_t pubkey_size,
    size_t *pubkey_length);

/**
 * A function that signs a hash or short message with a private key in
 * a Secure Authenticator
 * Refer to mbed-crypto\include\psa\crypto_se_driver.h
 */

psa_status_t psa_alt_asymmetric_sign_digest(psa_drv_se_context_t *drv_context,
    psa_key_slot_number_t key_slot,
    psa_algorithm_t alg,
    const uint8_t *p_hash,
    size_t hash_length,
    uint8_t *p_signature,
    size_t signature_size,
    size_t *p_signature_length);

/**
 * A function that performs aead encrypt in a Secure Authenticator
 * Refer to mbed-crypto\include\psa\crypto_se_driver.h
 */
psa_status_t psa_alt_aead_encrypt(psa_drv_se_context_t *drv_context,
    psa_key_slot_number_t key_buffer,
    psa_algorithm_t alg,
    const uint8_t *nonce,
    size_t nonce_length,
    const uint8_t *additional_data,
    size_t additional_data_length,
    const uint8_t *plaintext,
    size_t plaintext_length,
    uint8_t *ciphertext,
    size_t ciphertext_size,
    size_t *ciphertext_length);
/**
 * A function that performs aead decrypt in a Secure Authenticator
 * Refer to mbed-crypto\include\psa\crypto_se_driver.h
 */
psa_status_t psa_alt_aead_decrypt(psa_drv_se_context_t *drv_context,
    psa_key_slot_number_t key_buffer,
    psa_algorithm_t alg,
    const uint8_t *nonce,
    size_t nonce_length,
    const uint8_t *additional_data,
    size_t additional_data_length,
    const uint8_t *ciphertext,
    size_t ciphertext_length,
    uint8_t *plaintext,
    size_t plaintext_size,
    size_t *plaintext_length);

/**
 * A function that performs mac in a Secure Authenticator
 * Refer to mbed-crypto\include\psa\crypto_se_driver.h
 */
psa_status_t psa_alt_mac_compute(psa_drv_se_context_t *drv_context,
    const uint8_t *input,
    size_t input_length,
    psa_key_slot_number_t key_slot,
    psa_algorithm_t alg,
    uint8_t *mac,
    size_t mac_size,
    size_t *mac_length);

/** A function that provides the mac setup function for a
 *  Secure Authenticator driver
 *  Refer to mbed-crypto\include\psa\crypto_se_driver.h
 */
psa_status_t psa_alt_mac_setup(psa_drv_se_context_t *drv_context,
    psa_mac_operation_t *op_context,
    psa_key_slot_number_t key_slot,
    psa_algorithm_t algorithm);

/** A function that continues a previously started Secure Authenticator mac
 *  operation
 *  Refer to mbed-crypto\include\psa\crypto_se_driver.h
 */
psa_status_t psa_alt_mac_update(psa_mac_operation_t *op_context, const uint8_t *p_input, size_t input_length);

/** A function that finishes a previously started Secure Authenticator mac
 *  operation
 *  Refer to mbed-crypto\include\psa\crypto_se_driver.h
 */
psa_status_t psa_alt_mac_finish(psa_mac_operation_t *op_context, uint8_t *p_mac, size_t mac_size, size_t *p_mac_length);

/** A function that aborts a previously started Secure Authenticator mac
 *  operation
 *  Refer to mbed-crypto\include\psa\crypto_se_driver.h
 */
psa_status_t psa_alt_mac_abort(psa_mac_operation_t *op_context);

/** A function that provides the cipher setup function for a
 *  Secure Authenticator driver
 *  Refer to mbed-crypto\include\psa\crypto_se_driver.h
 */
psa_status_t psa_alt_cipher_setup(psa_drv_se_context_t *drv_context,
    psa_cipher_operation_t *op_context,
    psa_key_slot_number_t key_slot,
    psa_algorithm_t algorithm,
    psa_encrypt_or_decrypt_t direction);

/** A function that sets the initialization vector (if
 *  necessary) for an Secure Authenticator cipher operation
 *  Refer to mbed-crypto\include\psa\crypto_se_driver.h
 */
psa_status_t psa_alt_cipher_set_iv(psa_cipher_operation_t *op_context, const uint8_t *p_iv, size_t iv_length);

/** A function that continues a previously started Secure Authenticator cipher
 *  operation
 *  Refer to mbed-crypto\include\psa\crypto_se_driver.h
 */
psa_status_t psa_alt_cipher_update(psa_cipher_operation_t *op_context,
    const uint8_t *p_input,
    size_t input_size,
    uint8_t *p_output,
    size_t output_size,
    size_t *p_output_length);

/** A function that finishes a previously started Secure Authenticator cipher
 *  operation
 *  Refer to mbed-crypto\include\psa\crypto_se_driver.h
 */
psa_status_t psa_alt_cipher_finish(
    psa_cipher_operation_t *op_context, uint8_t *p_output, size_t output_size, size_t *p_output_length);

/** A function that aborts a previously started Secure Authenticator cipher
 *  operation
 *  Refer to mbed-crypto\include\psa\crypto_se_driver.h
 */
psa_status_t psa_alt_cipher_abort(psa_cipher_operation_t *op_context);

/**
 * A function that performs ecb enc/dec in one go in a Secure Authenticator
 * Refer to mbed-crypto\include\psa\crypto_se_driver.h
 */
psa_status_t psa_alt_cipher_ecb(psa_drv_se_context_t *drv_context,
    psa_key_slot_number_t key_slot,
    psa_algorithm_t algorithm,
    psa_encrypt_or_decrypt_t direction,
    const uint8_t *p_input,
    size_t input_size,
    uint8_t *p_output,
    size_t output_size);

psa_status_t psa_alt_store_flash_its_file(psa_storage_uid_t uid, uint8_t *data, size_t dataLen);

psa_status_t psa_alt_read_flash_its_file(psa_storage_uid_t uid, uint8_t *data, size_t *dataLen);

psa_status_t psa_alt_remove_flash_its_file(psa_storage_uid_t uid);

#endif //_PSA_ALT_H_
