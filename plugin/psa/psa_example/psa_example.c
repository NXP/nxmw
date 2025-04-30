/* Copyright 2023-2025 NXP
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <stdio.h>
#include <string.h>

#include "ex_sss_boot.h"
#include "psa/crypto.h"
#include "psa/crypto_types.h"
#include "psa/crypto_values.h"
#include "psa_alt.h"
#include "psa/crypto_se_driver.h"

#include "platform.h"
#if defined(SSS_HAVE_HOST_LPCXPRESSO55S) && (SSS_HAVE_HOST_LPCXPRESSO55S == 1)
#include "psa_alt_flash.h"
#endif

#include "nxEnsure.h"
#include "nxLog_msg.h"
psa_status_t psa_ecc_sign();
psa_status_t psa_generate_aes_key();
psa_status_t psa_aead_encrypt_decrypt();
psa_status_t psa_mac_and_verify();
psa_status_t psa_cipher_encrypt_decrypt_multistep();
psa_status_t psa_ecb_enc_dec_one_go();
psa_status_t psa_mac_multistep();

int main(int argc, const char *argv[])
{
    psa_status_t status         = PSA_SUCCESS;
    psa_key_location_t location = PSA_ALT_NX_LOCATION;
    psa_drv_se_t driver;

    /* Key management driver APIs for PSA */
    psa_drv_se_key_management_t key_mgmt_drv;
    psa_drv_se_asymmetric_t asymm_drv;
    psa_drv_se_aead_t aead_drv;
    psa_drv_se_mac_t mac_drv;
    psa_drv_se_cipher_t cipher_drv;
    memset(&key_mgmt_drv, 0, sizeof(psa_drv_se_key_management_t));
    memset(&asymm_drv, 0, sizeof(psa_drv_se_asymmetric_t));
    memset(&aead_drv, 0, sizeof(psa_drv_se_aead_t));
    memset(&mac_drv, 0, sizeof(psa_drv_se_mac_t));
    memset(&cipher_drv, 0, sizeof(psa_drv_se_cipher_t));
    key_mgmt_drv.private_p_generate = &psa_alt_generate_key;
    key_mgmt_drv.private_p_allocate = &psa_alt_allocate_key;
    key_mgmt_drv.private_p_import   = &psa_alt_import_key;
    asymm_drv.private_p_sign        = &psa_alt_asymmetric_sign_digest;
    aead_drv.private_p_encrypt      = &psa_alt_aead_encrypt;
    aead_drv.private_p_decrypt      = &psa_alt_aead_decrypt;
    mac_drv.private_p_mac           = &psa_alt_mac_compute;
    mac_drv.private_p_setup         = (psa_drv_se_mac_setup_t)&psa_alt_mac_setup;
    mac_drv.private_p_update        = (psa_drv_se_mac_update_t)&psa_alt_mac_update;
    mac_drv.private_p_finish        = (psa_drv_se_mac_finish_t)&psa_alt_mac_finish;
    mac_drv.private_p_abort         = (psa_drv_se_mac_abort_t)&psa_alt_mac_abort;
    cipher_drv.private_p_setup      = (psa_drv_se_cipher_setup_t)&psa_alt_cipher_setup;
    cipher_drv.private_p_set_iv     = (psa_drv_se_cipher_set_iv_t)&psa_alt_cipher_set_iv;
    cipher_drv.private_p_update     = (psa_drv_se_cipher_update_t)&psa_alt_cipher_update;
    cipher_drv.private_p_finish     = (psa_drv_se_cipher_finish_t)&psa_alt_cipher_finish;
    cipher_drv.private_p_abort      = (psa_drv_se_cipher_abort_t)&psa_alt_cipher_abort;
    cipher_drv.private_p_ecb        = &psa_alt_cipher_ecb;

#if (defined(SSS_HAVE_HOST_EMBEDDED) && (SSS_HAVE_HOST_EMBEDDED))
    platform_boot_direct();
    platform_init_hardware();
#endif

#if defined(SSS_HAVE_HOST_LPCXPRESSO55S) && (SSS_HAVE_HOST_LPCXPRESSO55S == 1)
    psa_flash_ks_init(true);
#endif

    memset(&driver, 0, sizeof(driver));
    driver.private_hal_version = PSA_DRV_SE_HAL_VERSION;

    /* Assign function pointers to SE driver
     * SE Driver has components for different operations:
     *      key_management driver,
     *      cipher driver,
     *      mac driver,
     *      asymmetric driver, etc.
     */

    driver.private_key_management = &key_mgmt_drv;
    driver.private_asymmetric     = &asymm_drv;
    driver.private_aead           = &aead_drv;
    driver.private_mac            = &mac_drv;
    driver.private_cipher         = &cipher_drv;
    driver.private_p_init         = &psa_alt_driver_init;

    /* First register SE Driver so that it is initialized in psa_crypto_init before performing any operation
     * Maximum of 4 drivers can be registered
     */
    status = psa_register_se_driver(location, &driver);
    ENSURE_OR_GO_EXIT(status == PSA_SUCCESS);

    status = psa_crypto_init();
    ENSURE_OR_GO_EXIT(status == PSA_SUCCESS);

    status = psa_ecc_sign();
    ENSURE_OR_GO_EXIT(status == PSA_SUCCESS);

    status = psa_generate_aes_key();
    ENSURE_OR_GO_EXIT(status == PSA_SUCCESS);

    status = psa_aead_encrypt_decrypt();
    ENSURE_OR_GO_EXIT(status == PSA_SUCCESS);

    status = psa_mac_and_verify();
    ENSURE_OR_GO_EXIT(status == PSA_SUCCESS);

    status = psa_cipher_encrypt_decrypt_multistep();
    ENSURE_OR_GO_EXIT(status == PSA_SUCCESS);

    status = psa_ecb_enc_dec_one_go();
    ENSURE_OR_GO_EXIT(status == PSA_SUCCESS);

    status = psa_mac_multistep();
    ENSURE_OR_GO_EXIT(status == PSA_SUCCESS);

exit:

    if (status == PSA_SUCCESS) {
        LOG_I("PSA Example Success !!!...");
        return 0;
    }
    else {
        LOG_E("PSA Example Failed !!!...");
        return 1;
    }
}

psa_status_t psa_ecc_sign()
{
    psa_status_t status         = PSA_SUCCESS;
    psa_key_lifetime_t lifetime = PSA_ALT_NX_LIFETIME + PSA_KEY_PERSISTENCE_DEFAULT;
    const psa_algorithm_t alg   = PSA_ALG_ECDSA(PSA_ALG_ANY_HASH);
    psa_key_id_t key_id         = 0x03;
    size_t key_bits             = 256;
    psa_key_handle_t key_handle = 0;
    uint8_t hash[32]            = {1};
    size_t hashLen              = sizeof(hash);

    /* Sign example */
    uint8_t signature[256] = {0};
    size_t sigLen          = sizeof(signature);

    LOG_I("Running ECC Sign using PSA apis.");

    /* attributes will contain all details about type of operation to be performed, driver (lifetime) to be used, algorithm, flags, etc */
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_EXPORT | PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_VERIFY_HASH);
    psa_set_key_algorithm(&attributes, alg);
    psa_set_key_type(&attributes,
        PSA_KEY_TYPE_ECC_KEY_PAIR(
            PSA_ECC_FAMILY_SECP_R1)); /*To generate brainpool curve type use PSA_ECC_FAMILY_BRAINPOOL_P_R1*/
    psa_set_key_bits(&attributes, key_bits);
    psa_set_key_lifetime(&attributes, lifetime);
    psa_set_key_id(&attributes, key_id);

    status = psa_generate_key(&attributes, &key_handle);
    ENSURE_OR_GO_EXIT(status == PSA_SUCCESS);

    status =
        psa_sign_hash(key_handle, PSA_ALG_ECDSA(PSA_ALG_SHA_256), hash, hashLen, signature, sizeof(signature), &sigLen);
    LOG_AU8_I(signature, sigLen);
    LOG_I("ECC Sign Passed Successfully\n");

exit:
    return status;
}

psa_status_t psa_generate_aes_key()
{
    psa_status_t status           = PSA_SUCCESS;
    psa_key_lifetime_t lifetime   = PSA_ALT_NX_LIFETIME + PSA_KEY_PERSISTENCE_DEFAULT;
    const psa_algorithm_t aes_alg = PSA_ALG_CCM;
    size_t aes_key_bits           = 256;
    psa_key_id_t aes_key_id       = 0x15;
    psa_key_id_t mac_key_id       = 0x16;
    psa_key_handle_t key_handle   = 0;

    LOG_I("Running  AES and HMAC key generation using PSA apis.");

    /* attributes will contain all details about type of operation to be performed, driver (lifetime) to be used, algorithm, flags, etc */
    psa_key_attributes_t aes_attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_attributes_t mac_attributes = PSA_KEY_ATTRIBUTES_INIT;

    psa_set_key_usage_flags(&aes_attributes, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&aes_attributes, aes_alg);
    psa_set_key_type(&aes_attributes, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&aes_attributes, aes_key_bits);
    psa_set_key_lifetime(&aes_attributes, lifetime);
    psa_set_key_id(&aes_attributes, aes_key_id);

    // Generate AES key
    status = psa_generate_key(&aes_attributes, &key_handle);
    ENSURE_OR_GO_EXIT(status == PSA_SUCCESS);

    psa_set_key_usage_flags(&mac_attributes,
        PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_VERIFY_HASH | PSA_KEY_USAGE_SIGN_MESSAGE |
            PSA_KEY_USAGE_VERIFY_MESSAGE);
    psa_set_key_algorithm(&mac_attributes, PSA_ALG_HMAC(PSA_ALG_SHA_256));
    psa_set_key_type(&mac_attributes, PSA_KEY_TYPE_HMAC);
    psa_set_key_bits(&mac_attributes, aes_key_bits);
    psa_set_key_lifetime(&mac_attributes, lifetime);
    psa_set_key_id(&mac_attributes, mac_key_id);

    // Generate HMAC key
    status = psa_generate_key(&mac_attributes, &key_handle);
    ENSURE_OR_GO_EXIT(status == PSA_SUCCESS);

    LOG_I("Generate AES and HMAC key Passed Successfully\n");

exit:
    return status;
}

psa_status_t psa_aead_encrypt_decrypt()
{
    psa_status_t status         = PSA_SUCCESS;
    psa_key_lifetime_t lifetime = PSA_ALT_NX_LIFETIME + PSA_KEY_PERSISTENCE_DEFAULT;
    /*AEAD ENCRYPT AND DECRYPT EXAMPLE*/

    const psa_algorithm_t aes_alg = PSA_ALG_CCM;
    size_t aes_key_bits           = 256;
    psa_key_id_t aes_key_id       = 0x10;

    LOG_I("Running  AES Encrypt/Decrypt using PSA apis.");

    static const uint8_t key[] = {
        0x31,
        0x4a,
        0x20,
        0x2f,
        0x83,
        0x6f,
        0x9f,
        0x25,
        0x7e,
        0x22,
        0xd8,
        0xc1,
        0x17,
        0x57,
        0x83,
        0x2a,
        0xe5,
        0x13,
        0x1d,
        0x35,
        0x7a,
        0x72,
        0xdf,
        0x88,
        0xf3,
        0xef,
        0xf0,
        0xff,
        0xce,
        0xe0,
        0xda,
        0x4e,
    };

    /* attributes will contain all details about type of operation to be performed, driver (lifetime) to be used, algorithm, flags, etc */
    psa_key_attributes_t aes_attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_usage_flags(&aes_attributes, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&aes_attributes, aes_alg);
    psa_set_key_type(&aes_attributes, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&aes_attributes, aes_key_bits);
    psa_set_key_lifetime(&aes_attributes, lifetime);
    psa_set_key_id(&aes_attributes, aes_key_id);

    uint8_t nonce[13] = {
        0xa5,
        0x44,
        0x21,
        0x8d,
        0xad,
        0xd3,
        0xc1,
        0x05,
        0x83,
        0xdb,
        0x49,
        0xcf,
        0x39,
    };
    size_t nonceLen = sizeof(nonce);
    uint8_t aad[]   = {
        0x3c,
        0x0e,
        0x28,
        0x15,
        0xd3,
        0x7d,
        0x84,
        0x4f,
        0x7a,
        0xc2,
        0x40,
        0xba,
        0x9d,
        0x6e,
        0x3a,
        0x0b,
        0x2a,
        0x86,
        0xf7,
        0x06,
        0xe8,
        0x85,
        0x95,
        0x9e,
        0x09,
        0xa1,
        0x00,
        0x5e,
        0x02,
        0x4f,
        0x69,
        0x07,
    };
    size_t aadLen                  = sizeof(aad);
    const uint8_t inputsrcData[24] = {
        0xe8,
        0xde,
        0x97,
        0x0f,
        0x6e,
        0xe8,
        0xe8,
        0x0e,
        0xde,
        0x93,
        0x35,
        0x81,
        0xb5,
        0xbc,
        0xf4,
        0xd8,
        0x37,
        0xe2,
        0xb7,
        0x2b,
        0xaa,
        0x8b,
        0x00,
        0xc3,
    };
    size_t srcDataLen = sizeof(inputsrcData);

    uint8_t expectedData[24]  = {0};
    size_t expected_data_size = sizeof(expectedData);
    size_t expected_data_len  = 0;

    uint8_t cipherData[100] = {0};
    size_t cipherDataSize   = sizeof(cipherData);
    size_t cipherDataLen    = 0;

    status = psa_import_key(&aes_attributes, key, sizeof(key), &aes_key_id);
    ENSURE_OR_GO_EXIT(status == PSA_SUCCESS);

    status = psa_aead_encrypt(aes_key_id,
        PSA_ALG_CCM,
        nonce,
        nonceLen,
        aad,
        aadLen,
        inputsrcData,
        srcDataLen,
        cipherData,
        cipherDataSize,
        &cipherDataLen);
    ENSURE_OR_GO_EXIT(status == PSA_SUCCESS);

    LOG_MAU8_I("Cipher text", cipherData, cipherDataLen);

    status = psa_aead_decrypt(aes_key_id,
        PSA_ALG_CCM,
        nonce,
        nonceLen,
        aad,
        aadLen,
        (const uint8_t *)cipherData,
        cipherDataLen,
        expectedData,
        expected_data_size,
        &expected_data_len);
    ENSURE_OR_GO_EXIT(status == PSA_SUCCESS);

    LOG_MAU8_I("Plain Text", expectedData, expected_data_len);

    LOG_I("AEAD Encrypt/Decrypt Passed Successfully\n");

exit:
    return status;
}

psa_status_t psa_mac_and_verify()
{
    psa_status_t status         = PSA_SUCCESS;
    psa_key_lifetime_t lifetime = PSA_ALT_NX_LIFETIME + PSA_KEY_PERSISTENCE_DEFAULT;
    /*MAC EXAMPLE*/
    psa_key_id_t mac_key_id = 0x11;
    size_t aes_key_bits     = 128;
    uint8_t outdata[128]    = {0};
    size_t outdatLen        = sizeof(outdata);
    uint8_t cmac_message[]  = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a};

    LOG_I("Running MAC Compute and Verify using PSA apis.");

    psa_key_attributes_t mac_attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_usage_flags(&mac_attributes,
        PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_VERIFY_HASH | PSA_KEY_USAGE_SIGN_MESSAGE |
            PSA_KEY_USAGE_VERIFY_MESSAGE);
    psa_set_key_algorithm(&mac_attributes, PSA_ALG_HMAC(PSA_ALG_SHA_256));
    psa_set_key_type(&mac_attributes, PSA_KEY_TYPE_HMAC);
    psa_set_key_bits(&mac_attributes, aes_key_bits);
    psa_set_key_lifetime(&mac_attributes, lifetime);
    psa_set_key_id(&mac_attributes, mac_key_id);

    uint8_t mac_key[] = {
        0x26,
        0x51,
        0x1f,
        0xb5,
        0x1f,
        0xcf,
        0xa7,
        0x5c,
        0xb4,
        0xb4,
        0x4d,
        0xa7,
        0x5a,
        0x6e,
        0x5a,
        0x0e,
    };

    status = psa_import_key(&mac_attributes, mac_key, sizeof(mac_key), &mac_key_id);
    ENSURE_OR_GO_EXIT(status == PSA_SUCCESS);

    status = psa_mac_compute(mac_key_id,
        PSA_ALG_HMAC(PSA_ALG_SHA_256),
        cmac_message,
        sizeof(cmac_message),
        outdata,
        PSA_MAC_MAX_SIZE,
        &outdatLen);
    ENSURE_OR_GO_EXIT(status == PSA_SUCCESS);

    LOG_MAU8_I("Hmac", outdata, outdatLen);

    status = psa_mac_verify(
        mac_key_id, PSA_ALG_HMAC(PSA_ALG_SHA_256), cmac_message, sizeof(cmac_message), outdata, outdatLen);
    ENSURE_OR_GO_EXIT(status == PSA_SUCCESS);

    LOG_MAU8_I("Hmac verify", outdata, outdatLen);

    LOG_I("HMAC Passed Successfully\n");
exit:
    return status;
}

psa_status_t psa_mac_multistep()
{
    psa_status_t status         = PSA_SUCCESS;
    psa_key_lifetime_t lifetime = PSA_ALT_NX_LIFETIME + PSA_KEY_PERSISTENCE_DEFAULT;
    /*MAC EXAMPLE*/
    psa_key_id_t mac_key_id = 0x14;
    size_t aes_key_bits     = 128;
    uint8_t outdata[32]     = {0};
    size_t outdatLen        = sizeof(outdata);
    uint8_t hmac_message[]  = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a};

    LOG_I("Running Multi-step HMAC sign/verify using PSA apis.");

    psa_key_attributes_t mac_attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_mac_operation_t operation       = PSA_MAC_OPERATION_INIT;
    psa_set_key_usage_flags(&mac_attributes,
        PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_VERIFY_HASH | PSA_KEY_USAGE_SIGN_MESSAGE |
            PSA_KEY_USAGE_VERIFY_MESSAGE);
    psa_set_key_algorithm(&mac_attributes, PSA_ALG_HMAC(PSA_ALG_SHA_256));
    psa_set_key_type(&mac_attributes, PSA_KEY_TYPE_HMAC);
    psa_set_key_bits(&mac_attributes, aes_key_bits);
    psa_set_key_lifetime(&mac_attributes, lifetime);
    psa_set_key_id(&mac_attributes, mac_key_id);

    uint8_t mac_key[] = {
        0x26,
        0x51,
        0x1f,
        0xb5,
        0x1f,
        0xcf,
        0xa7,
        0x5c,
        0xb4,
        0xb4,
        0x4d,
        0xa7,
        0x5a,
        0x6e,
        0x5a,
        0x0e,
    };

    status = psa_import_key(&mac_attributes, mac_key, sizeof(mac_key), &mac_key_id);
    ENSURE_OR_GO_EXIT(status == PSA_SUCCESS);

    status = psa_mac_sign_setup(&operation, mac_key_id, PSA_ALG_HMAC(PSA_ALG_SHA_256));
    ENSURE_OR_GO_EXIT(status == PSA_SUCCESS);

    status = psa_mac_update(&operation, hmac_message, sizeof(hmac_message));
    ENSURE_OR_GO_EXIT(status == PSA_SUCCESS);

    status = psa_mac_sign_finish(&operation, outdata, outdatLen, &outdatLen);
    ENSURE_OR_GO_EXIT(status == PSA_SUCCESS);

    /*Mac Verify*/
    psa_mac_operation_t verify_operation = PSA_MAC_OPERATION_INIT;

    status = psa_mac_verify_setup(&verify_operation, mac_key_id, PSA_ALG_HMAC(PSA_ALG_SHA_256));
    ENSURE_OR_GO_EXIT(status == PSA_SUCCESS);

    status = psa_mac_update(&verify_operation, hmac_message, sizeof(hmac_message));
    ENSURE_OR_GO_EXIT(status == PSA_SUCCESS);

    status = psa_mac_verify_finish(&verify_operation, outdata, outdatLen);
    ENSURE_OR_GO_EXIT(status == PSA_SUCCESS);

    status = psa_mac_abort(&operation);
    ENSURE_OR_GO_EXIT(status == PSA_SUCCESS);

    LOG_MAU8_I("MAC", outdata, outdatLen);
    LOG_I("Multi-step Hmac sign/verify passed successfully\n");
exit:
    return status;
}

psa_status_t psa_cipher_encrypt_decrypt_multistep()
{
    psa_status_t status         = PSA_SUCCESS;
    psa_key_lifetime_t lifetime = PSA_ALT_NX_LIFETIME + PSA_KEY_PERSISTENCE_DEFAULT;

    /*CIPHER EXAMPLE*/
    psa_key_attributes_t cipher_attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_algorithm_t cipher_alg             = PSA_ALG_ECB_NO_PADDING;

    LOG_I("Running Multi-step Encrypt Decrypt using PSA apis.");

    uint8_t aes_key_data[] = {
        0x2b,
        0x7e,
        0x15,
        0x16,
        0x28,
        0xae,
        0xd2,
        0xa6,
        0xab,
        0xf7,
        0x15,
        0x88,
        0x09,
        0xcf,
        0x4f,
        0x3c,
    };

    uint8_t input_data[] = {
        0x6b,
        0xc1,
        0xbe,
        0xe2,
        0x2e,
        0x40,
        0x9f,
        0x96,
        0xe9,
        0x3d,
        0x7e,
        0x11,
        0x73,
        0x93,
        0x17,
        0x2a,
        0xae,
        0x2d,
        0x8a,
        0x57,
        0x1e,
        0x03,
        0xac,
        0x9c,
        0x9e,
        0xb7,
        0x6f,
        0xac,
        0x45,
        0xaf,
        0x8e,
        0x51,
        0x30,
        0xc8,
        0x1c,
        0x46,
        0xa3,
        0x5c,
        0xe4,
        0x11,
        0xe5,
        0xfb,
        0xc1,
        0x19,
        0x1a,
        0x0a,
        0x52,
        0xef,
        0xf6,
        0x9f,
        0x24,
        0x45,
        0xdf,
        0x4f,
        0x9b,
        0x17,
        0xad,
        0x2b,
        0x41,
        0x7b,
        0xe6,
        0x6c,
        0x37,
        0x10,
    };
    size_t input_size = sizeof(input_data);
    uint8_t iv[16];
    size_t iv_len;
    psa_key_id_t cipher_key_id       = 0x12;
    psa_cipher_operation_t operation = PSA_CIPHER_OPERATION_INIT;
    uint8_t enc_data[64]             = {0};
    size_t enc_data_size             = input_size;
    size_t enc_data_len              = 0;

    uint8_t dec_data[64]   = {0};
    size_t dec_data_size   = sizeof(dec_data);
    size_t dec_data_length = 0;

    psa_set_key_usage_flags(&cipher_attributes, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&cipher_attributes, cipher_alg);
    psa_set_key_type(&cipher_attributes, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&cipher_attributes, 128);
    psa_set_key_lifetime(&cipher_attributes, lifetime);
    psa_set_key_id(&cipher_attributes, cipher_key_id);

    status = psa_import_key(&cipher_attributes, aes_key_data, sizeof(aes_key_data), &cipher_key_id);
    ENSURE_OR_GO_EXIT(status == PSA_SUCCESS);

    /*Encrypt*/
    status = psa_cipher_encrypt_setup(&operation, cipher_key_id, cipher_alg);
    ENSURE_OR_GO_EXIT(status == PSA_SUCCESS);

    status = psa_cipher_generate_iv(&operation, iv, sizeof(iv), &iv_len);
    ENSURE_OR_GO_EXIT(status == PSA_SUCCESS);

    status = psa_cipher_update(&operation, input_data, input_size, (enc_data), enc_data_size, &enc_data_len);
    ENSURE_OR_GO_EXIT(status == PSA_SUCCESS);

    status = psa_cipher_finish(&operation, (enc_data + 48), enc_data_size - 48, &enc_data_len);
    ENSURE_OR_GO_EXIT(status == PSA_SUCCESS);

    LOG_MAU8_I("Encrypted Data", enc_data, enc_data_size);

    /*Decrypt*/
    status = psa_cipher_decrypt_setup(&operation, cipher_key_id, cipher_alg);
    ENSURE_OR_GO_EXIT(status == PSA_SUCCESS);

    status = psa_cipher_set_iv(&operation, iv, iv_len);
    ENSURE_OR_GO_EXIT(status == PSA_SUCCESS);

    status = psa_cipher_update(&operation, (enc_data), enc_data_len, (dec_data), dec_data_size, &dec_data_length);
    ENSURE_OR_GO_EXIT(status == PSA_SUCCESS);

    status = psa_cipher_finish(&operation, dec_data + 48, dec_data_size - 48, &dec_data_length);
    ENSURE_OR_GO_EXIT(status == PSA_SUCCESS);

    LOG_MAU8_I("Decrypted Data", dec_data, dec_data_size);

    status = psa_cipher_abort(&operation);
    ENSURE_OR_GO_EXIT(status == PSA_SUCCESS);

    LOG_I("Multi-step Encrypt Decrypt passed successfully\n");

exit:
    return status;
}

psa_status_t psa_ecb_enc_dec_one_go()
{
    psa_status_t status                    = PSA_SUCCESS;
    psa_key_lifetime_t lifetime            = PSA_ALT_NX_LIFETIME + PSA_KEY_PERSISTENCE_DEFAULT;
    psa_key_attributes_t cipher_attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_algorithm_t cipher_alg             = PSA_ALG_ECB_NO_PADDING;

    LOG_I("Running ECB Oneshot Encrypt/Decrypt using PSA apis.");

    uint8_t aes_key_data[] = {
        0x2b,
        0x7e,
        0x15,
        0x16,
        0x28,
        0xae,
        0xd2,
        0xa6,
        0xab,
        0xf7,
        0x15,
        0x88,
        0x09,
        0xcf,
        0x4f,
        0x3c,
    };

    uint8_t input_data[] = {
        0x6b,
        0xc1,
        0xbe,
        0xe2,
        0x2e,
        0x40,
        0x9f,
        0x96,
        0xe9,
        0x3d,
        0x7e,
        0x11,
        0x73,
        0x93,
        0x17,
        0x2a,
        0xae,
        0x2d,
        0x8a,
        0x57,
        0x1e,
        0x03,
        0xac,
        0x9c,
        0x9e,
        0xb7,
        0x6f,
        0xac,
        0x45,
        0xaf,
        0x8e,
        0x51,
        0x30,
        0xc8,
        0x1c,
        0x46,
        0xa3,
        0x5c,
        0xe4,
        0x11,
        0xe5,
        0xfb,
        0xc1,
        0x19,
        0x1a,
        0x0a,
        0x52,
        0xef,
        0xf6,
        0x9f,
        0x24,
        0x45,
        0xdf,
        0x4f,
        0x9b,
        0x17,
        0xad,
        0x2b,
        0x41,
        0x7b,
        0xe6,
        0x6c,
        0x37,
        0x10,
    };
    size_t input_size          = sizeof(input_data);
    psa_key_id_t cipher_key_id = 0x13;

    uint8_t enc_data[64] = {0};
    size_t enc_data_size = input_size;
    size_t enc_data_len  = 0;

    uint8_t dec_data[64]   = {0};
    size_t dec_data_size   = sizeof(dec_data);
    size_t dec_data_length = 0;

    psa_set_key_usage_flags(&cipher_attributes, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&cipher_attributes, cipher_alg);
    psa_set_key_type(&cipher_attributes, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&cipher_attributes, 128);
    psa_set_key_lifetime(&cipher_attributes, lifetime);
    psa_set_key_id(&cipher_attributes, cipher_key_id);

    status = psa_import_key(&cipher_attributes, aes_key_data, sizeof(aes_key_data), &cipher_key_id);
    ENSURE_OR_GO_EXIT(status == PSA_SUCCESS);

    status = psa_cipher_encrypt(
        cipher_key_id, PSA_ALG_ECB_NO_PADDING, input_data, input_size, enc_data, enc_data_size, &enc_data_len);
    ENSURE_OR_GO_EXIT(status == PSA_SUCCESS);

    LOG_MAU8_I("Encrypted Data", enc_data, enc_data_size);

    status = psa_cipher_decrypt(
        cipher_key_id, PSA_ALG_ECB_NO_PADDING, enc_data, enc_data_size, dec_data, dec_data_size, &dec_data_length);
    ENSURE_OR_GO_EXIT(status == PSA_SUCCESS);

    LOG_MAU8_I("Decrypted Data", dec_data, dec_data_size);

    LOG_I("ECB Oneshot Encrypt Decrypt passed successfully\n");

exit:
    return status;
}