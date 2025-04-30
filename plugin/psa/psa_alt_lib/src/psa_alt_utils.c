/* Copyright 2023-2024 NXP
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "psa_alt_utils.h"

#include <stdio.h>
#include <string.h>
#include <limits.h>

#include "ex_sss_boot.h"

#include "fsl_sss_api.h"
#include "fsl_sss_nx_apis.h"
#include "fsl_sss_nx_types.h"
#include "fsl_sss_util_asn1_der.h"

#include "mbedtls/oid.h"
#include "mbedtls/pk.h"
#include "nxEnsure.h"
#include "nxLog_msg.h"
#include "psa/crypto.h"
#include "psa/crypto_se_driver.h"
#include "psa/crypto_types.h"
#include "psa/crypto_values.h"
#include "psa_alt.h"
#include "psa_crypto_se.h"
#include "nx_apdu.h"
#include "sss_psa_alt.h"

extern ex_sss_boot_ctx_t gPsaAltBootCtx;

/************************************************************************
 * Definitions
 ************************************************************************/
static psa_status_t psa_ecc_curve_to_sss_cipher(const psa_ecc_family_t ecc_curve, sss_cipher_type_t *sss_cipher);

static psa_status_t psa_algorithm_to_ecdsa_sign_algorithm(
    const psa_algorithm_t psa_algorithm, sss_algorithm_t *sss_algorithm);

static psa_status_t psa_algorithm_to_aead_enc_algorithm(
    const psa_algorithm_t psa_algorithm, sss_algorithm_t *sss_algorithm);

static psa_status_t psa_algorithm_to_sss_hmac_algorithm(
    const psa_algorithm_t psa_algorithm, sss_algorithm_t *sss_algorithm);

static psa_status_t psa_algorithm_to_sss_cipher_algorithm(
    const psa_algorithm_t psa_algorithm, sss_algorithm_t *sss_algorithm);

psa_status_t sss_check_if_object_exists(uint32_t key_id, psa_key_type_t keyType)
{
    sss_status_t sss_status = kStatus_SSS_Fail;
    psa_status_t psa_status = PSA_ERROR_GENERIC_ERROR;
    sss_object_t sss_object = {0};
    sss_status              = sss_key_object_init(&sss_object, &gPsaAltBootCtx.ks);
    ENSURE_OR_GO_EXIT(sss_status == kStatus_SSS_Success);

    if (keyType == PSA_KEY_TYPE_AES || keyType == PSA_KEY_TYPE_HMAC) {
        sss_status = sss_key_object_get_handle(&sss_object, kSSS_CipherType_AES, key_id);
    }
    else {
        sss_status = sss_key_object_get_handle(&sss_object, kSSS_CipherType_EC_NIST_P, key_id);
    }

    if (sss_status != kStatus_SSS_Success) {
        psa_status = PSA_ERROR_DOES_NOT_EXIST;
    }
    else {
        psa_status = PSA_SUCCESS;
    }

exit:
    if (sss_object.keyStore != NULL) {
        sss_key_object_free(&sss_object);
    }
    return psa_status;
}

psa_status_t sss_cipher_validate_key_size(const sss_cipher_type_t sss_cipher, size_t key_size)
{
    psa_status_t psa_status = PSA_SUCCESS;
    if (sss_cipher == kSSS_CipherType_EC_NIST_P) {
        if ((key_size != 192) && (key_size != 224) && (key_size != 256) && (key_size != 384) && (key_size != 521)) {
            LOG_E("Key Size not supported");
            psa_status = PSA_ERROR_NOT_SUPPORTED;
        }
    }
    else if (sss_cipher == kSSS_CipherType_EC_BRAINPOOL) {
        if ((key_size != 256) && (key_size != 384) && (key_size != 512)) {
            LOG_E("Key Size not supported");
            psa_status = PSA_ERROR_NOT_SUPPORTED;
        }
    }
    else if (sss_cipher == kSSS_CipherType_AES) {
        if ((key_size != 128) && (key_size != 192) && (key_size != 256)) {
            LOG_E("Key Size not supported");
            psa_status = PSA_ERROR_INVALID_ARGUMENT;
        }
    }
    else if (sss_cipher == kSSS_CipherType_HMAC) {
        if (key_size > (256 /* Max byte key supported */ * 8)) {
            LOG_E("Key Size not supported");
            psa_status = PSA_ERROR_NOT_SUPPORTED;
        }
    }

    return psa_status;
}

psa_status_t psa_key_type_to_sss_cipher(
    psa_key_type_t psa_key_type, sss_cipher_type_t *sss_cipher, sss_key_part_t *sss_key_part)
{
    psa_status_t psa_status = PSA_ERROR_NOT_SUPPORTED;

    if (PSA_KEY_TYPE_IS_ECC_KEY_PAIR(psa_key_type)) {
        psa_ecc_family_t ecc_curve = PSA_KEY_TYPE_ECC_GET_FAMILY(psa_key_type);
        psa_status                 = psa_ecc_curve_to_sss_cipher(ecc_curve, sss_cipher);
        if (psa_status != PSA_SUCCESS) {
            goto exit;
        }
        *sss_key_part = kSSS_KeyPart_Pair;
        psa_status    = PSA_SUCCESS;
    }
    else if (PSA_KEY_TYPE_IS_ECC_PUBLIC_KEY(psa_key_type)) {
        psa_ecc_family_t ecc_curve = PSA_KEY_TYPE_ECC_GET_FAMILY(psa_key_type);
        psa_status                 = psa_ecc_curve_to_sss_cipher(ecc_curve, sss_cipher);
        if (psa_status != PSA_SUCCESS) {
            goto exit;
        }
        *sss_key_part = kSSS_KeyPart_Public;
        psa_status    = PSA_SUCCESS;
    }
    else if (psa_key_type == PSA_KEY_TYPE_AES) {
        *sss_cipher   = kSSS_CipherType_AES;
        *sss_key_part = kSSS_KeyPart_Default;
        psa_status    = PSA_SUCCESS;
    }
    else if (psa_key_type == PSA_KEY_TYPE_HMAC) {
        *sss_cipher   = kSSS_CipherType_AES;
        *sss_key_part = kSSS_KeyPart_Default;
        psa_status    = PSA_SUCCESS;
    }

exit:
    return psa_status;
}

psa_status_t psa_generate_random_symmetric_key(uint8_t *key, size_t *bufferLen, const size_t keyLen)
{
    psa_status_t psa_status = PSA_ERROR_GENERIC_ERROR;
    sss_status_t sss_status = kStatus_SSS_Fail;
    sss_rng_context_t rng_ctx;

    if (*bufferLen < keyLen) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    sss_status = sss_rng_context_init(&rng_ctx, &gPsaAltBootCtx.session);
    ENSURE_OR_GO_EXIT(sss_status == kStatus_SSS_Success);
    sss_status = sss_rng_get_random(&rng_ctx, key, keyLen);
    ENSURE_OR_GO_EXIT(sss_status == kStatus_SSS_Success);
    *bufferLen = keyLen;
    psa_status = PSA_SUCCESS;

exit:
    return psa_status;
}

psa_status_t psa_algorithm_to_sss_algorithm(const psa_algorithm_t psa_algorithm, sss_algorithm_t *sss_algorithm)
{
    psa_status_t psa_status = PSA_ERROR_NOT_SUPPORTED;

    if (PSA_ALG_IS_RANDOMIZED_ECDSA(psa_algorithm)) {
        psa_status = psa_algorithm_to_ecdsa_sign_algorithm(psa_algorithm, sss_algorithm);
    }
    else if (PSA_ALG_IS_AEAD(psa_algorithm)) {
        psa_status = psa_algorithm_to_aead_enc_algorithm(psa_algorithm, sss_algorithm);
    }
    else if (PSA_ALG_IS_MAC(psa_algorithm)) {
        psa_status = psa_algorithm_to_sss_hmac_algorithm(psa_algorithm, sss_algorithm);
    }
    else if (PSA_ALG_IS_CIPHER(psa_algorithm)) {
        psa_status = psa_algorithm_to_sss_cipher_algorithm(psa_algorithm, sss_algorithm);
    }

    return psa_status;
}

static psa_status_t psa_algorithm_to_ecdsa_sign_algorithm(
    const psa_algorithm_t psa_algorithm, sss_algorithm_t *sss_algorithm)
{
    psa_status_t psa_status        = PSA_ERROR_GENERIC_ERROR;
    psa_algorithm_t hash_algorithm = psa_algorithm & PSA_ALG_HASH_MASK;
    switch (hash_algorithm) {
    /** SHA2-256 */
    case (PSA_ALG_SHA_256 & PSA_ALG_HASH_MASK):
        *sss_algorithm = kAlgorithm_SSS_ECDSA_SHA256;
        psa_status     = PSA_SUCCESS;
        break;
    /** SHA2-384 */
    case (PSA_ALG_SHA_384 & PSA_ALG_HASH_MASK):
        *sss_algorithm = kAlgorithm_SSS_ECDSA_SHA384;
        psa_status     = PSA_SUCCESS;
        break;
    default:
        psa_status = PSA_ERROR_NOT_SUPPORTED;
    }
    return psa_status;
}

static psa_status_t psa_algorithm_to_aead_enc_algorithm(
    const psa_algorithm_t psa_algorithm, sss_algorithm_t *sss_algorithm)
{
    psa_status_t psa_status = PSA_ERROR_GENERIC_ERROR;
    switch (psa_algorithm) {
    /** SHA1 */
    case (PSA_ALG_CCM):
        *sss_algorithm = kAlgorithm_SSS_AES_CCM;
        psa_status     = PSA_SUCCESS;
        break;
    /** SHA2-224 */
    case (PSA_ALG_GCM):
        *sss_algorithm = kAlgorithm_SSS_AES_GCM;
        psa_status     = PSA_SUCCESS;
        break;
    default:
        psa_status = PSA_ERROR_NOT_SUPPORTED;
    }
    return psa_status;
}

static psa_status_t psa_algorithm_to_sss_hmac_algorithm(
    const psa_algorithm_t psa_algorithm, sss_algorithm_t *sss_algorithm)
{
    psa_status_t psa_status        = PSA_ERROR_GENERIC_ERROR;
    psa_algorithm_t hash_algorithm = psa_algorithm & PSA_ALG_HASH_MASK;
    switch (hash_algorithm) {
    /** SHA2-256 */
    case (PSA_ALG_SHA_256 & PSA_ALG_HASH_MASK):
        *sss_algorithm = kAlgorithm_SSS_HMAC_SHA256;
        psa_status     = PSA_SUCCESS;
        break;
    /** SHA2-384 */
    case (PSA_ALG_SHA_384 & PSA_ALG_HASH_MASK):
        *sss_algorithm = kAlgorithm_SSS_HMAC_SHA384;
        psa_status     = PSA_SUCCESS;
        break;
    default:
        psa_status = PSA_ERROR_NOT_SUPPORTED;
    }
    return psa_status;
}

static psa_status_t psa_algorithm_to_sss_cipher_algorithm(
    const psa_algorithm_t psa_algorithm, sss_algorithm_t *sss_algorithm)
{
    psa_status_t psa_status = PSA_ERROR_GENERIC_ERROR;
    switch (psa_algorithm) {
    /** SHA2-256 */
    case (PSA_ALG_CBC_NO_PADDING):
        *sss_algorithm = kAlgorithm_SSS_AES_CBC;
        psa_status     = PSA_SUCCESS;
        break;
    /** SHA2-384 */
    case (PSA_ALG_ECB_NO_PADDING):
        *sss_algorithm = kAlgorithm_SSS_AES_ECB;
        psa_status     = PSA_SUCCESS;
        break;
    default:
        psa_status = PSA_ERROR_NOT_SUPPORTED;
    }
    return psa_status;
}

static psa_status_t psa_ecc_curve_to_sss_cipher(const psa_ecc_family_t ecc_curve, sss_cipher_type_t *sss_cipher)
{
    psa_status_t psa_status = PSA_SUCCESS;
    switch (ecc_curve) {
    case PSA_ECC_FAMILY_SECP_R1:
        *sss_cipher = kSSS_CipherType_EC_NIST_P;
        break;
    case PSA_ECC_FAMILY_BRAINPOOL_P_R1:
        *sss_cipher = kSSS_CipherType_EC_BRAINPOOL;
        break;
    default:
        LOG_E("Curve not supported");
        psa_status = PSA_ERROR_NOT_SUPPORTED;
    }
    return psa_status;
}

psa_status_t validate_sign_input_data(
    uint32_t key_id, const psa_algorithm_t psa_algorithm, const uint8_t *input, size_t data_len)
{
    psa_status_t psa_status = PSA_ERROR_INVALID_ARGUMENT;
    sss_status_t sss_status = kStatus_SSS_Fail;
    sss_object_t sss_object = {0};

    sss_status = sss_key_object_init(&sss_object, &gPsaAltBootCtx.ks);
    ENSURE_OR_GO_EXIT(sss_status == kStatus_SSS_Success);
    sss_status = sss_key_object_get_handle(&sss_object, kSSS_CipherType_EC_NIST_P, key_id);
    ENSURE_OR_GO_EXIT(sss_status == kStatus_SSS_Success);

    if (PSA_ALG_IS_RANDOMIZED_ECDSA(psa_algorithm)) {
        psa_status = PSA_SUCCESS;
    }

exit:
    if (sss_object.keyStore != NULL) {
        sss_key_object_free(&sss_object);
    }
    return psa_status;
}

/* add psa_ prefix */
int EcSignatureToRandS(uint8_t *signature, size_t *sigLen)
{
    int result         = 1;
    uint8_t rands[128] = {0};
    int index          = 0;
    size_t i           = 0;
    size_t len         = 0;
    if (signature[index++] != 0x30) {
        goto exit;
    }
    if (signature[index++] != (*sigLen - 2)) {
        goto exit;
    }
    if (signature[index++] != 0x02) {
        goto exit;
    }

    /* Parse length, skip initial 0x00 byte if present */
    len = signature[index++];
    if (len & 0x01) {
        len--;
        index++;
    }

    /* Copy R component*/
    for (i = 0; i < len; i++) {
        rands[i] = signature[index++];
    }

    if (signature[index++] != 0x02) {
        goto exit;
    }

    /* Parse length, skip initial 0x00 byte if present */
    len = signature[index++];
    if (len & 0x01) {
        len--;
        index++;
    }

    /* Copy S component*/
    len = len + i;
    for (; i < len; i++) {
        rands[i] = signature[index++];
    }

    /* Copy to output buffer and update length */
    memcpy(&signature[0], &rands[0], i);
    *sigLen = i;

    result = 0;

exit:
    return result;
}

psa_status_t nx_sign_check_input_len(size_t inLen, sss_algorithm_t sss_algorithm)
{
    psa_status_t retval = PSA_ERROR_INVALID_ARGUMENT;

    switch (sss_algorithm) {
    case kAlgorithm_SSS_SHA256:
    case kAlgorithm_SSS_ECDSA_SHA256:
        retval = (inLen == 32) ? PSA_SUCCESS : PSA_ERROR_INVALID_ARGUMENT;
        break;
    case kAlgorithm_SSS_SHA384:
    case kAlgorithm_SSS_ECDSA_SHA384:
        retval = (inLen == 48) ? PSA_SUCCESS : PSA_ERROR_INVALID_ARGUMENT;
        break;
    default:
        LOG_E("Unknown algorithm");
        retval = PSA_ERROR_INVALID_ARGUMENT;
    }
    return retval;
}