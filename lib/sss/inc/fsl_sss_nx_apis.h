/*
 *
 * Copyright 2022-2023 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 */

/** @file */

#ifndef FSL_SSS_NX_APIS_H
#define FSL_SSS_NX_APIS_H

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#if defined(SSS_USE_FTR_FILE)
#include "fsl_sss_ftr.h"
#else
#include "fsl_sss_ftr_default.h"
#endif

#if SSS_HAVE_NX_TYPE
#include "fsl_sss_nx_types.h"

/* ************************************************************************** */
/* Functions                                                                  */
/* ************************************************************************** */

/**
 * @addtogroup sss_nx_session
 * @{
 */

/** @copydoc sss_nx_session_open
 *
 */
sss_status_t sss_nx_session_open(sss_nx_session_t *session,
    sss_type_t subsystem,
    uint32_t application_id,
    sss_connection_type_t connection_type,
    void *connectionData);

/** @copydoc sss_nx_session_close
 *
 */
sss_status_t sss_nx_session_close(sss_nx_session_t *session);

/*! @} */ /* end of : sss_nx_session */

/** @copydoc sss_nx_key_store_context_init
 *
 */
sss_status_t sss_nx_key_store_context_init(sss_nx_key_store_t *keyStore, sss_nx_session_t *session);

/** @copydoc sss_nx_key_store_allocate
 *
 */
sss_status_t sss_nx_key_store_allocate(sss_nx_key_store_t *keyStore, uint32_t keyStoreId);

/** @copydoc sss_nx_key_store_set_key
 *
 */
sss_status_t sss_nx_key_store_set_key(sss_nx_key_store_t *keyStore,
    sss_nx_object_t *keyObject,
    const uint8_t *key,
    size_t keyLen,
    size_t keyBitLen,
    void *options,
    size_t optionsLen);

/** @copydoc sss_nx_key_store_generate_key
 *
 */
sss_status_t sss_nx_key_store_generate_key(
    sss_nx_key_store_t *keyStore, sss_nx_object_t *keyObject, size_t keyBitLen, void *options);

/** @copydoc sss_nx_key_store_get_key
 *
 */
sss_status_t sss_nx_key_store_get_key(
    sss_nx_key_store_t *keyStore, sss_nx_object_t *keyObject, uint8_t *data, size_t *dataLen, size_t *pKeyBitLen);

/** @copydoc sss_nx_key_store_context_free
 *
 */
void sss_nx_key_store_context_free(sss_nx_key_store_t *keyStore);

/**
 * @addtogroup sss_key_object
 * @{
 */
/** @copydoc sss_nx_key_object_init
 *
 */
sss_status_t sss_nx_key_object_init(sss_nx_object_t *keyObject, sss_nx_key_store_t *keyStore);

/** @copydoc sss_nx_key_object_allocate_handle
 *
 */
sss_status_t sss_nx_key_object_allocate_handle(sss_nx_object_t *keyObject,
    uint32_t keyId,
    sss_key_part_t key_part,
    sss_cipher_type_t cipherType,
    size_t keyByteLenMax,
    uint32_t options);

/** @copydoc sss_nx_key_object_get_handle
 *
 */
sss_status_t sss_nx_key_object_get_handle(sss_nx_object_t *keyObject, sss_cipher_type_t cipherType, uint32_t keyId);

/** @copydoc sss_nx_key_object_free
 *
 */
void sss_nx_key_object_free(sss_nx_object_t *keyObject);

/*! @} */ /* end of : sss_key_object */

/**
 * @addtogroup sss_nx_keyderive
 * @{
 */
/** @copydoc sss_nx_derive_key_context_init
 *
 */
sss_status_t sss_nx_derive_key_context_init(sss_nx_derive_key_t *context,
    sss_nx_session_t *session,
    sss_nx_object_t *keyObject,
    sss_algorithm_t algorithm,
    sss_mode_t mode);

/** @copydoc sss_nx_derive_key_context_free
 *
 */
void sss_nx_derive_key_context_free(sss_nx_derive_key_t *context);

/*! @} */ /* end of : sss_nx_keyderive */

/** @copydoc sss_nx_asymmetric_context_init
 *
 */
sss_status_t sss_nx_asymmetric_context_init(sss_nx_asymmetric_t *context,
    sss_nx_session_t *session,
    sss_nx_object_t *keyObject,
    sss_algorithm_t algorithm,
    sss_mode_t mode);

/** @copydoc sss_nx_asymmetric_sign_digest
 *
 */
sss_status_t sss_nx_asymmetric_sign_digest(
    sss_nx_asymmetric_t *context, uint8_t *digest, size_t digestLen, uint8_t *signature, size_t *signatureLen);

/** @copydoc sss_nx_asymmetric_verify_digest
 *
 */
sss_status_t sss_nx_asymmetric_verify_digest(
    sss_nx_asymmetric_t *context, uint8_t *digest, size_t digestLen, uint8_t *signature, size_t signatureLen);

/** @copydoc sss_nx_asymmetric_sign_one_go
 *
 */
sss_status_t sss_nx_asymmetric_sign_one_go(
    sss_nx_asymmetric_t *context, uint8_t *srcData, size_t srcLen, uint8_t *signature, size_t *signatureLen);

/** @copydoc sss_nx_asymmetric_sign_init
 *
 */
sss_status_t sss_nx_asymmetric_sign_init(sss_nx_asymmetric_t *context, uint8_t *srcData, size_t srcLen);

/** @copydoc sss_nx_asymmetric_sign_update
 *
 */
sss_status_t sss_nx_asymmetric_sign_update(sss_nx_asymmetric_t *context, uint8_t *srcData, size_t srcLen);

/** @copydoc sss_nx_asymmetric_sign_finish
 *
 */
sss_status_t sss_nx_asymmetric_sign_finish(
    sss_nx_asymmetric_t *context, uint8_t *srcData, size_t srcLen, uint8_t *signature, size_t *signatureLen);

/** @copydoc sss_nx_asymmetric_verify_one_go
 *
 */
sss_status_t sss_nx_asymmetric_verify_one_go(
    sss_nx_asymmetric_t *context, uint8_t *srcData, size_t srcLen, uint8_t *signature, size_t signatureLen);

/** @copydoc sss_nx_asymmetric_verify_init
 *
 */
sss_status_t sss_nx_asymmetric_verify_init(sss_nx_asymmetric_t *context, uint8_t *srcData, size_t srcLen);

/** @copydoc sss_nx_asymmetric_verify_update
 *
 */
sss_status_t sss_nx_asymmetric_verify_update(sss_nx_asymmetric_t *context, uint8_t *srcData, size_t srcLen);

/** @copydoc sss_nx_asymmetric_verify_finish
 *
 */

sss_status_t sss_nx_asymmetric_verify_finish(
    sss_nx_asymmetric_t *context, uint8_t *srcData, size_t srcLen, uint8_t *signature, size_t signatureLen);

/** @copydoc sss_nx_asymmetric_context_free
 *
 */
void sss_nx_asymmetric_context_free(sss_nx_asymmetric_t *context);

/** @copydoc sss_nx_symmetric_context_init
 *
 */
sss_status_t sss_nx_symmetric_context_init(sss_nx_symmetric_t *context,
    sss_nx_session_t *session,
    sss_nx_object_t *keyObject,
    sss_algorithm_t algorithm,
    sss_mode_t mode);

/** @copydoc sss_nx_cipher_one_go
 *
 */
sss_status_t sss_nx_cipher_one_go(
    sss_nx_symmetric_t *context, uint8_t *iv, size_t ivLen, const uint8_t *srcData, uint8_t *destData, size_t dataLen);

/** @copydoc sss_nx_cipher_init
 *
 */
sss_status_t sss_nx_cipher_init(sss_nx_symmetric_t *context, uint8_t *iv, size_t ivLen);

/** @copydoc sss_nx_cipher_update
 *
 */
sss_status_t sss_nx_cipher_update(
    sss_nx_symmetric_t *context, const uint8_t *srcData, size_t srcLen, uint8_t *destData, size_t *destLen);

/** @copydoc sss_nx_cipher_finish
 *
 */
sss_status_t sss_nx_cipher_finish(
    sss_nx_symmetric_t *context, const uint8_t *srcData, size_t srcLen, uint8_t *destData, size_t *destLen);

/** @copydoc sss_nx_symmetric_context_free
 *
 */
void sss_nx_symmetric_context_free(sss_nx_symmetric_t *context);

/** @copydoc sss_nx_aead_context_init
 *
 */
sss_status_t sss_nx_aead_context_init(sss_nx_aead_t *context,
    sss_nx_session_t *session,
    sss_nx_object_t *keyObject,
    sss_algorithm_t algorithm,
    sss_mode_t mode);

/** @copydoc sss_nx_aead_one_go
 *
 */
sss_status_t sss_nx_aead_one_go(sss_nx_aead_t *context,
    const uint8_t *srcData,
    uint8_t *destData,
    size_t size,
    uint8_t *nonce,
    size_t nonceLen,
    const uint8_t *aad,
    size_t aadLen,
    uint8_t *tag,
    size_t *tagLen);

/** @copydoc sss_nx_aead_init
 *
 */
sss_status_t sss_nx_aead_init(
    sss_nx_aead_t *context, uint8_t *nonce, size_t nonceLen, size_t tagLen, size_t aadLen, size_t payloadLen);

/** @copydoc sss_nx_aead_update_aad
 *
 */
sss_status_t sss_nx_aead_update_aad(sss_nx_aead_t *context, const uint8_t *aadData, size_t aadDataLen);

/** @copydoc sss_nx_aead_update
 *
 */
sss_status_t sss_nx_aead_update(
    sss_nx_aead_t *context, const uint8_t *srcData, size_t srcLen, uint8_t *destData, size_t *destLen);

/** @copydoc sss_nx_aead_finish
 *
 */
sss_status_t sss_nx_aead_finish(sss_nx_aead_t *context,
    const uint8_t *srcData,
    size_t srcLen,
    uint8_t *destData,
    size_t *destLen,
    uint8_t *tag,
    size_t *tagLen);

/** @copydoc sss_nx_aead_context_free
 *
 */
void sss_nx_aead_context_free(sss_nx_aead_t *context);

/** @copydoc sss_nx_digest_context_init
 *
 */
sss_status_t sss_nx_digest_context_init(
    sss_nx_digest_t *context, sss_nx_session_t *session, sss_algorithm_t algorithm, sss_mode_t mode);

/** @copydoc sss_nx_digest_one_go
 *
 */
sss_status_t sss_nx_digest_one_go(
    sss_nx_digest_t *context, const uint8_t *message, size_t messageLen, uint8_t *digest, size_t *digestLen);

/** @copydoc sss_nx_digest_init
 *
 */
sss_status_t sss_nx_digest_init(sss_nx_digest_t *context);

/** @copydoc sss_nx_digest_update
 *
 */
sss_status_t sss_nx_digest_update(sss_nx_digest_t *context, const uint8_t *message, size_t messageLen);

/** @copydoc sss_nx_digest_finish
 *
 */
sss_status_t sss_nx_digest_finish(sss_nx_digest_t *context, uint8_t *digest, size_t *digestLen);

/** @copydoc sss_nx_digest_context_free
 *
 */
void sss_nx_digest_context_free(sss_nx_digest_t *context);

/**
 * @addtogroup sss_nx_rng
 * @{
 */

/** @copydoc sss_nx_rng_context_init
 *
 */
sss_status_t sss_nx_rng_context_init(sss_nx_rng_context_t *context, sss_nx_session_t *session);

/** @copydoc sss_nx_rng_get_random
 *
 */
sss_status_t sss_nx_rng_get_random(sss_nx_rng_context_t *context, uint8_t *randomData, size_t randomDataLen);

/** @copydoc sss_nx_rng_context_free
 *
 */
sss_status_t sss_nx_rng_context_free(sss_nx_rng_context_t *context);

/*! @} */ /* end of : sss_nx_rng */

/**
 * @addtogroup sss_nx_mac
 * @{
 */

/** @copydoc sss_mac_context_init
 *
 */
sss_status_t sss_nx_mac_context_init(sss_nx_mac_t *context,
    sss_nx_session_t *session,
    sss_nx_object_t *keyObject,
    sss_algorithm_t algorithm,
    sss_mode_t mode);

/** @copydoc sss_mac_one_go
 *
 */
sss_status_t sss_nx_mac_one_go(
    sss_nx_mac_t *context, const uint8_t *message, size_t messageLen, uint8_t *mac, size_t *macLen);

/** @copydoc sss_mac_init
 *
 */
sss_status_t sss_nx_mac_init(sss_nx_mac_t *context);

/** @copydoc sss_mac_update
 *
 */
sss_status_t sss_nx_mac_update(sss_nx_mac_t *context, const uint8_t *message, size_t messageLen);

/** @copydoc sss_mac_finish
 *
 */
sss_status_t sss_nx_mac_finish(sss_nx_mac_t *context, uint8_t *mac, size_t *macLen);

/** @copydoc sss_mac_context_free
 *
 */
void sss_nx_mac_context_free(sss_nx_mac_t *context);

/*! @} */ /* end of : sss_nx_mac */

sss_status_t sss_nx_derive_key_dh_one_go(
    sss_nx_derive_key_t *context, sss_nx_object_t *otherPartyKeyObject, sss_nx_object_t *derivedKeyObject);

sss_status_t sss_nx_derive_key_dh_two_step_part1(sss_nx_derive_key_t *context);

sss_status_t sss_nx_derive_key_dh_two_step_part2(
    sss_nx_derive_key_t *context, sss_nx_object_t *otherPartyKeyObject, sss_nx_object_t *derivedKeyObject);

sss_status_t sss_nx_derive_key_one_go(sss_nx_derive_key_t *context,
    sss_object_t *saltKeyObject,
    const uint8_t *info,
    size_t infoLen,
    sss_object_t *derivedKeyObject,
    uint16_t deriveDataLen);

sss_status_t sss_nx_key_object_get_key_version(
    sss_nx_session_t *session, sss_nx_object_t *keyObject, uint8_t *keyVersion);

int util_replace_substring(
    char *string, char *oldSubstring, char *newSubstring, char *outputString, size_t outputStringSize);

sss_status_t sss_util_encode_asn1_signature(
    uint8_t *signatureAsn1, size_t *signatureLenAsn1, uint8_t *rawSignature, size_t rawSignatureLen);
sss_status_t sss_util_decode_asn1_signature(
    uint8_t *rawSignature, size_t *rawSignatureLen, uint8_t *signature, size_t signatureLen);

#if (SSS_HAVE_SSS == 1)
/* Direct Call : session */
#define sss_session_open(session, subsystem, application_id, connection_type, connectionData) \
    sss_nx_session_open(                                                                      \
        ((sss_nx_session_t *)session), (subsystem), (application_id), (connection_type), (connectionData))
#define sss_session_close(session) sss_nx_session_close(((sss_nx_session_t *)session))
#define sss_key_object_init(keyObject, keyStore) \
    sss_nx_key_object_init(((sss_nx_object_t *)keyObject), ((sss_nx_key_store_t *)keyStore))
#define sss_key_object_allocate_handle(keyObject, keyId, keyPart, cipherType, keyByteLenMax, options) \
    sss_nx_key_object_allocate_handle(                                                                \
        ((sss_nx_object_t *)keyObject), (keyId), (keyPart), (cipherType), (keyByteLenMax), (options))
#define sss_key_object_get_handle(keyObject, cipherType, keyId) \
    sss_nx_key_object_get_handle(((sss_nx_object_t *)keyObject), (cipherType), (keyId))
#define sss_key_object_set_eccgfp_group(keyObject, group) \
    sss_nx_key_object_set_eccgfp_group(((sss_nx_object_t *)keyObject), (group))
#define sss_key_object_free(keyObject) sss_nx_key_object_free(((sss_nx_object_t *)keyObject))
/* Direct Call : keyderive */
#define sss_derive_key_context_init(context, session, keyObject, algorithm, mode) \
    sss_nx_derive_key_context_init(((sss_nx_derive_key_t *)context),              \
        ((sss_nx_session_t *)session),                                            \
        ((sss_nx_object_t *)keyObject),                                           \
        (algorithm),                                                              \
        (mode))
#define sss_derive_key_one_go(context, saltKeyObject, info, infoLen, derivedKeyObject, deriveDataLen) \
    sss_nx_derive_key_one_go(                                                                         \
        ((sss_nx_derive_key_t *)context), (saltKeyObject), (info), (infoLen), (derivedKeyObject), (deriveDataLen))
#define sss_derive_key_dh_one_go(context, otherPartyKeyObject, derivedKeyObject) \
    sss_nx_derive_key_dh_one_go(((sss_nx_derive_key_t *)context),                \
        ((sss_nx_object_t *)otherPartyKeyObject),                                \
        ((sss_nx_object_t *)derivedKeyObject))
#define sss_derive_key_dh_two_step_part1(context) sss_nx_derive_key_dh_two_step_part1(((sss_nx_derive_key_t *)context))
#define sss_derive_key_dh_two_step_part2(context, otherPartyKeyObject, derivedKeyObject) \
    sss_nx_derive_key_dh_two_step_part2(((sss_nx_derive_key_t *)context),                \
        ((sss_nx_object_t *)otherPartyKeyObject),                                        \
        ((sss_nx_object_t *)derivedKeyObject))
#define sss_derive_key_context_free(context) sss_nx_derive_key_context_free(((sss_nx_derive_key_t *)context))
/* Direct Call : keystore */
#define sss_key_store_context_init(keyStore, session) \
    sss_nx_key_store_context_init(((sss_nx_key_store_t *)keyStore), ((sss_nx_session_t *)session))
#define sss_key_store_allocate(keyStore, keyStoreId) \
    sss_nx_key_store_allocate(((sss_nx_key_store_t *)keyStore), (keyStoreId))
#define sss_key_store_set_key(keyStore, keyObject, data, dataLen, keyBitLen, options, optionsLen) \
    sss_nx_key_store_set_key(((sss_nx_key_store_t *)keyStore),                                    \
        ((sss_nx_object_t *)keyObject),                                                           \
        (data),                                                                                   \
        (dataLen),                                                                                \
        (keyBitLen),                                                                              \
        (options),                                                                                \
        (optionsLen))
#define sss_key_store_generate_key(keyStore, keyObject, keyBitLen, options) \
    sss_nx_key_store_generate_key(                                          \
        ((sss_nx_key_store_t *)keyStore), ((sss_nx_object_t *)keyObject), (keyBitLen), (options))
#define sss_key_store_get_key(keyStore, keyObject, data, dataLen, pKeyBitLen) \
    sss_nx_key_store_get_key(                                                 \
        ((sss_nx_key_store_t *)keyStore), ((sss_nx_object_t *)keyObject), (data), (dataLen), (pKeyBitLen))
#define sss_key_store_context_free(keyStore) sss_nx_key_store_context_free(((sss_nx_key_store_t *)keyStore))
/* Direct Call : asym */
#define sss_asymmetric_context_init(context, session, keyObject, algorithm, mode) \
    sss_nx_asymmetric_context_init(((sss_nx_asymmetric_t *)context),              \
        ((sss_nx_session_t *)session),                                            \
        ((sss_nx_object_t *)keyObject),                                           \
        (algorithm),                                                              \
        (mode))
#define sss_asymmetric_sign_digest(context, digest, digestLen, signature, signatureLen) \
    sss_nx_asymmetric_sign_digest(((sss_nx_asymmetric_t *)context), (digest), (digestLen), (signature), (signatureLen))
#define sss_asymmetric_verify_digest(context, digest, digestLen, signature, signatureLen) \
    sss_nx_asymmetric_verify_digest(                                                      \
        ((sss_nx_asymmetric_t *)context), (digest), (digestLen), (signature), (signatureLen))
#define sss_asymmetric_context_free(context) sss_nx_asymmetric_context_free(((sss_nx_asymmetric_t *)context))
#define sss_asymmetric_sign_one_go(context, srcData, srcLen, signature, signatureLen) \
    sss_nx_asymmetric_sign_one_go(((sss_nx_asymmetric_t *)context), (srcData), (srcLen), (signature), (signatureLen))
#define sss_asymmetric_verify_one_go(context, srcData, srcLen, signature, signatureLen) \
    sss_nx_asymmetric_verify_one_go(((sss_nx_asymmetric_t *)context), (srcData), (srcLen), (signature), (signatureLen))
#define sss_asymmetric_sign_init(context, srcData, srcLen) \
    sss_nx_asymmetric_sign_init(((sss_nx_asymmetric_t *)context), (srcData), (srcLen))
#define sss_asymmetric_sign_update(context, srcData, srcLen) \
    sss_nx_asymmetric_sign_update(((sss_nx_asymmetric_t *)context), (srcData), (srcLen))
#define sss_asymmetric_sign_finish(context, srcData, srcLen, signature, signatureLen) \
    sss_nx_asymmetric_sign_finish(((sss_nx_asymmetric_t *)context), (srcData), (srcLen), (signature), (signatureLen))
#define sss_asymmetric_verify_init(context, srcData, srcLen) \
    sss_nx_asymmetric_verify_init(((sss_nx_asymmetric_t *)context), (srcData), (srcLen))
#define sss_asymmetric_verify_update(context, srcData, srcLen) \
    sss_nx_asymmetric_verify_update(((sss_nx_asymmetric_t *)context), (srcData), (srcLen))
#define sss_asymmetric_verify_finish(context, srcData, srcLen, signature, signatureLen) \
    sss_nx_asymmetric_verify_finish(((sss_nx_asymmetric_t *)context), (srcData), (srcLen), (signature), (signatureLen))
/* Direct Call : symm */
#define sss_symmetric_context_init(context, session, keyObject, algorithm, mode) \
    sss_nx_symmetric_context_init(((sss_nx_symmetric_t *)context),               \
        ((sss_nx_session_t *)session),                                           \
        ((sss_nx_object_t *)keyObject),                                          \
        (algorithm),                                                             \
        (mode))
#define sss_cipher_one_go(context, iv, ivLen, srcData, destData, dataLen) \
    sss_nx_cipher_one_go(((sss_nx_symmetric_t *)context), (iv), (ivLen), (srcData), (destData), (dataLen))
#define sss_cipher_init(context, iv, ivLen) sss_nx_cipher_init(((sss_nx_symmetric_t *)context), (iv), (ivLen))
#define sss_cipher_update(context, srcData, srcLen, destData, destLen) \
    sss_nx_cipher_update(((sss_nx_symmetric_t *)context), (srcData), (srcLen), (destData), (destLen))
#define sss_cipher_finish(context, srcData, srcLen, destData, destLen) \
    sss_nx_cipher_finish(((sss_nx_symmetric_t *)context), (srcData), (srcLen), (destData), (destLen))
#define sss_symmetric_context_free(context) sss_nx_symmetric_context_free(((sss_nx_symmetric_t *)context))
/* Direct Call : aead */
#define sss_aead_context_init(context, session, keyObject, algorithm, mode) \
    sss_nx_aead_context_init(((sss_nx_aead_t *)context),                    \
        ((sss_nx_session_t *)session),                                      \
        ((sss_nx_object_t *)keyObject),                                     \
        (algorithm),                                                        \
        (mode))
#define sss_aead_one_go(context, srcData, destData, size, nonce, nonceLen, aad, aadLen, tag, tagLen) \
    sss_nx_aead_one_go(((sss_nx_aead_t *)context),                                                   \
        (srcData),                                                                                   \
        (destData),                                                                                  \
        (size),                                                                                      \
        (nonce),                                                                                     \
        (nonceLen),                                                                                  \
        (aad),                                                                                       \
        (aadLen),                                                                                    \
        (tag),                                                                                       \
        (tagLen))
#define sss_aead_init(context, nonce, nonceLen, tagLen, aadLen, payloadLen) \
    sss_nx_aead_init(((sss_nx_aead_t *)context), (nonce), (nonceLen), (tagLen), (aadLen), (payloadLen))
#define sss_aead_update_aad(context, aadData, aadDataLen) \
    sss_nx_aead_update_aad(((sss_nx_aead_t *)context), (aadData), (aadDataLen))
#define sss_aead_update(context, srcData, srcLen, destData, destLen) \
    sss_nx_aead_update(((sss_nx_aead_t *)context), (srcData), (srcLen), (destData), (destLen))
#define sss_aead_finish(context, srcData, srcLen, destData, destLen, tag, tagLen) \
    sss_nx_aead_finish(((sss_nx_aead_t *)context), (srcData), (srcLen), (destData), (destLen), (tag), (tagLen))
#define sss_aead_context_free(context) sss_nx_aead_context_free(((sss_nx_aead_t *)context))
/* Direct Call : mac */
#define sss_mac_context_init(context, session, keyObject, algorithm, mode) \
    sss_nx_mac_context_init(                                               \
        ((sss_nx_mac_t *)context), ((sss_nx_session_t *)session), ((sss_nx_object_t *)keyObject), (algorithm), (mode))
#define sss_mac_one_go(context, message, messageLen, mac, macLen) \
    sss_nx_mac_one_go(((sss_nx_mac_t *)context), (message), (messageLen), (mac), (macLen))
#define sss_mac_init(context) sss_nx_mac_init(((sss_nx_mac_t *)context))
#define sss_mac_update(context, message, messageLen) \
    sss_nx_mac_update(((sss_nx_mac_t *)context), (message), (messageLen))
#define sss_mac_finish(context, mac, macLen) sss_nx_mac_finish(((sss_nx_mac_t *)context), (mac), (macLen))
#define sss_mac_context_free(context) sss_nx_mac_context_free(((sss_nx_mac_t *)context))
/* Direct Call : md */
#define sss_digest_context_init(context, session, algorithm, mode) \
    sss_nx_digest_context_init(((sss_nx_digest_t *)context), ((sss_nx_session_t *)session), (algorithm), (mode))
#define sss_digest_one_go(context, message, messageLen, digest, digestLen) \
    sss_nx_digest_one_go(((sss_nx_digest_t *)context), (message), (messageLen), (digest), (digestLen))
#define sss_digest_init(context) sss_nx_digest_init(((sss_nx_digest_t *)context))
#define sss_digest_update(context, message, messageLen) \
    sss_nx_digest_update(((sss_nx_digest_t *)context), (message), (messageLen))
#define sss_digest_finish(context, digest, digestLen) \
    sss_nx_digest_finish(((sss_nx_digest_t *)context), (digest), (digestLen))
#define sss_digest_context_free(context) sss_nx_digest_context_free(((sss_nx_digest_t *)context))
/* Direct Call : rng */
#define sss_rng_context_init(context, session) \
    sss_nx_rng_context_init(((sss_nx_rng_context_t *)context), ((sss_nx_session_t *)session))
#define sss_rng_get_random(context, random_data, dataLen) \
    sss_nx_rng_get_random(((sss_nx_rng_context_t *)context), (random_data), (dataLen))
#define sss_rng_context_free(context) sss_nx_rng_context_free(((sss_nx_rng_context_t *)context))
#endif // SSS_HAVE_SSS == 1

#endif /* SSS_HAVE_NX_TYPE */
#ifdef __cplusplus
} // extern "C"
#endif /* __cplusplus */

#endif /* FSL_SSS_NX_APIS_H */
