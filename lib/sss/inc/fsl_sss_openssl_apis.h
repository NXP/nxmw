/*
 *
 * Copyright 2018-2020 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef FSL_SSS_OPENSSL_APIS_H
#define FSL_SSS_OPENSSL_APIS_H

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#if defined(SSS_USE_FTR_FILE)
#include "fsl_sss_ftr.h"
#else
#include "fsl_sss_ftr_default.h"
#endif

#if SSS_HAVE_HOSTCRYPTO_OPENSSL
#include "fsl_sss_openssl_types.h"

/* ************************************************************************** */
/* Functions                                                                  */
/* ************************************************************************** */
/**
 * @addtogroup sss_openssl_session
 * @{
 */
/** @copydoc sss_session_open
 *
 */
sss_status_t sss_openssl_session_open(sss_openssl_session_t *session,
    sss_type_t subsystem,
    uint32_t application_id,
    sss_connection_type_t connection_type,
    void *connectionData);

/** @copydoc sss_session_close
 *
 */
sss_status_t sss_openssl_session_close(sss_openssl_session_t *session);

/*! @} */ /* end of : sss_openssl_session */

/**
 * @addtogroup sss_openssl_keyobj
 * @{
 */
/** @copydoc sss_key_object_init
 *
 */
sss_status_t sss_openssl_key_object_init(sss_openssl_object_t *keyObject, sss_openssl_key_store_t *keyStore);

/** @copydoc sss_key_object_allocate_handle
 *
 */
sss_status_t sss_openssl_key_object_allocate_handle(sss_openssl_object_t *keyObject,
    uint32_t keyId,
    sss_key_part_t keyPart,
    sss_cipher_type_t cipherType,
    size_t keyByteLenMax,
    uint32_t options);

/** @copydoc sss_key_object_get_handle
 *
 */
sss_status_t sss_openssl_key_object_get_handle(sss_openssl_object_t *keyObject, uint32_t keyId);

/** @copydoc sss_key_object_free
 *
 */
void sss_openssl_key_object_free(sss_openssl_object_t *keyObject);

/*! @} */ /* end of : sss_openssl_keyobj */

/**
 * @addtogroup sss_openssl_keyderive
 * @{
 */
/** @copydoc sss_derive_key_context_init
 *
 */
sss_status_t sss_openssl_derive_key_context_init(sss_openssl_derive_key_t *context,
    sss_openssl_session_t *session,
    sss_openssl_object_t *keyObject,
    sss_algorithm_t algorithm,
    sss_mode_t mode);

/** @copydoc sss_derive_key_one_go
*
*/
sss_status_t sss_openssl_derive_key_one_go(sss_openssl_derive_key_t *context,
    sss_object_t *saltObject,
    const uint8_t *info,
    size_t infoLen,
    sss_object_t *derivedKeyObject,
    uint16_t deriveDataLen);

/** @copydoc sss_derive_key_dh_one_go
*
*/
sss_status_t sss_openssl_derive_key_dh_one_go(sss_openssl_derive_key_t *context,
    sss_openssl_object_t *otherPartyKeyObject,
    sss_openssl_object_t *derivedKeyObject);

/** @copydoc sss_derive_key_dh_two_step_part1
*
*/
sss_status_t sss_openssl_derive_key_dh_two_step_part1(sss_openssl_derive_key_t *context);

/** @copydoc sss_derive_key_dh_two_step_part2
*
*/
sss_status_t sss_openssl_derive_key_dh_two_step_part2(sss_openssl_derive_key_t *context,
    sss_openssl_object_t *otherPartyKeyObject,
    sss_openssl_object_t *derivedKeyObject);

/** @copydoc sss_derive_key_dh
 *
 */
sss_status_t sss_openssl_derive_key_dh(sss_openssl_derive_key_t *context,
    sss_openssl_object_t *otherPartyKeyObject,
    sss_openssl_object_t *derivedKeyObject);

/** @copydoc sss_derive_key_context_free
 *
 */
void sss_openssl_derive_key_context_free(sss_openssl_derive_key_t *context);

/*! @} */ /* end of : sss_openssl_keyderive */

/**
 * @addtogroup sss_openssl_keystore
 * @{
 */
/** @copydoc sss_key_store_context_init
 *
 */
sss_status_t sss_openssl_key_store_context_init(sss_openssl_key_store_t *keyStore, sss_openssl_session_t *session);

/** @copydoc sss_key_store_allocate
 *
 */
sss_status_t sss_openssl_key_store_allocate(sss_openssl_key_store_t *keyStore, uint32_t keyStoreId);

/** @copydoc sss_key_store_set_key
 *
 */
sss_status_t sss_openssl_key_store_set_key(sss_openssl_key_store_t *keyStore,
    sss_openssl_object_t *keyObject,
    const uint8_t *data,
    size_t dataLen,
    size_t keyBitLen,
    void *options,
    size_t optionsLen);

/** @copydoc sss_key_store_generate_key
 *
 */
sss_status_t sss_openssl_key_store_generate_key(
    sss_openssl_key_store_t *keyStore, sss_openssl_object_t *keyObject, size_t keyBitLen, void *options);

/** @copydoc sss_key_store_get_key
 *
 */
sss_status_t sss_openssl_key_store_get_key(sss_openssl_key_store_t *keyStore,
    sss_openssl_object_t *keyObject,
    uint8_t *data,
    size_t *dataLen,
    size_t *pKeyBitLen);

/** @copydoc sss_key_store_erase_key
 *
 */
sss_status_t sss_openssl_key_store_erase_key(sss_openssl_key_store_t *keyStore, sss_openssl_object_t *keyObject);

/** @copydoc sss_key_store_context_free
 *
 */
void sss_openssl_key_store_context_free(sss_openssl_key_store_t *keyStore);

/*! @} */ /* end of : sss_openssl_keystore */

/**
 * @addtogroup sss_openssl_asym
 * @{
 */
/** @copydoc sss_asymmetric_context_init
 *
 */
sss_status_t sss_openssl_asymmetric_context_init(sss_openssl_asymmetric_t *context,
    sss_openssl_session_t *session,
    sss_openssl_object_t *keyObject,
    sss_algorithm_t algorithm,
    sss_mode_t mode);

/** @copydoc sss_asymmetric_sign_digest
 *
 */
sss_status_t sss_openssl_asymmetric_sign_digest(
    sss_openssl_asymmetric_t *context, uint8_t *digest, size_t digestLen, uint8_t *signature, size_t *signatureLen);

/** @copydoc sss_asymmetric_verify_digest
 *
 */
sss_status_t sss_openssl_asymmetric_verify_digest(
    sss_openssl_asymmetric_t *context, uint8_t *digest, size_t digestLen, uint8_t *signature, size_t signatureLen);

/** @copydoc sss_openssl_asymmetric_sign_one_go
 *
 */
sss_status_t sss_openssl_asymmetric_sign_one_go(
    sss_openssl_asymmetric_t *context, uint8_t *srcData, size_t srcLen, uint8_t *signature, size_t *signatureLen);

/** @copydoc sss_openssl_asymmetric_sign_init
 *
 */
sss_status_t sss_openssl_asymmetric_sign_init(sss_openssl_asymmetric_t *context, uint8_t *srcData, size_t srcLen);

/** @copydoc sss_openssl_asymmetric_sign_update
 *
 */
sss_status_t sss_openssl_asymmetric_sign_update(sss_openssl_asymmetric_t *context, uint8_t *srcData, size_t srcLen);

/** @copydoc sss_openssl_asymmetric_sign_finish
 *
 */
sss_status_t sss_openssl_asymmetric_sign_finish(
    sss_openssl_asymmetric_t *context, uint8_t *srcData, size_t srcLen, uint8_t *signature, size_t *signatureLen);

/** @copydoc sss_openssl_asymmetric_verify_one_go
 *
 */
sss_status_t sss_openssl_asymmetric_verify_one_go(
    sss_openssl_asymmetric_t *context, uint8_t *srcData, size_t srcLen, uint8_t *signature, size_t signatureLen);

/** @copydoc sss_openssl_asymmetric_verify_init
 *
 */
sss_status_t sss_openssl_asymmetric_verify_init(sss_openssl_asymmetric_t *context, uint8_t *srcData, size_t srcLen);

/** @copydoc sss_openssl_asymmetric_verify_update
 *
 */
sss_status_t sss_openssl_asymmetric_verify_update(sss_openssl_asymmetric_t *context, uint8_t *srcData, size_t srcLen);

/** @copydoc sss_openssl_asymmetric_verify_finish
 *
 */
sss_status_t sss_openssl_asymmetric_verify_finish(
    sss_openssl_asymmetric_t *context, uint8_t *srcData, size_t srcLen, uint8_t *signature, size_t signatureLen);

/** @copydoc sss_asymmetric_context_free
 *
 */
void sss_openssl_asymmetric_context_free(sss_openssl_asymmetric_t *context);

/*! @} */ /* end of : sss_openssl_asym */

/**
 * @addtogroup sss_openssl_symm
 * @{
 */
/** @copydoc sss_symmetric_context_init
 *
 */
sss_status_t sss_openssl_symmetric_context_init(sss_openssl_symmetric_t *context,
    sss_openssl_session_t *session,
    sss_openssl_object_t *keyObject,
    sss_algorithm_t algorithm,
    sss_mode_t mode);

/** @copydoc sss_cipher_one_go
 *
 */
sss_status_t sss_openssl_cipher_one_go(sss_openssl_symmetric_t *context,
    uint8_t *iv,
    size_t ivLen,
    const uint8_t *srcData,
    uint8_t *destData,
    size_t dataLen);

/** @copydoc sss_cipher_init
 *
 */
sss_status_t sss_openssl_cipher_init(sss_openssl_symmetric_t *context, uint8_t *iv, size_t ivLen);

/** @copydoc sss_cipher_update
 *
 */
sss_status_t sss_openssl_cipher_update(
    sss_openssl_symmetric_t *context, const uint8_t *srcData, size_t srcLen, uint8_t *destData, size_t *destLen);

/** @copydoc sss_cipher_finish
 *
 */
sss_status_t sss_openssl_cipher_finish(
    sss_openssl_symmetric_t *context, const uint8_t *srcData, size_t srcLen, uint8_t *destData, size_t *destLen);

/** @copydoc sss_symmetric_context_free
 *
 */
void sss_openssl_symmetric_context_free(sss_openssl_symmetric_t *context);

/*! @} */ /* end of : sss_openssl_symm */

/**
 * @addtogroup sss_openssl_aead
 * @{
 */
/** @copydoc sss_aead_context_init
 *
 */
sss_status_t sss_openssl_aead_context_init(sss_openssl_aead_t *context,
    sss_openssl_session_t *session,
    sss_openssl_object_t *keyObject,
    sss_algorithm_t algorithm,
    sss_mode_t mode);

/** @copydoc sss_aead_one_go
 *
 */
sss_status_t sss_openssl_aead_one_go(sss_openssl_aead_t *context,
    const uint8_t *srcData,
    uint8_t *destData,
    size_t size,
    uint8_t *nonce,
    size_t nonceLen,
    const uint8_t *aad,
    size_t aadLen,
    uint8_t *tag,
    size_t *tagLen);

/** @copydoc sss_aead_init
 *
 */
sss_status_t sss_openssl_aead_init(
    sss_openssl_aead_t *context, uint8_t *nonce, size_t nonceLen, size_t tagLen, size_t aadLen, size_t payloadLen);

/** @copydoc sss_aead_update_aad
 *
 */
sss_status_t sss_openssl_aead_update_aad(sss_openssl_aead_t *context, const uint8_t *aadData, size_t aadDataLen);

/** @copydoc sss_aead_update
 *
 */
sss_status_t sss_openssl_aead_update(
    sss_openssl_aead_t *context, const uint8_t *srcData, size_t srcLen, uint8_t *destData, size_t *destLen);

/** @copydoc sss_aead_finish
 *
 */
sss_status_t sss_openssl_aead_finish(sss_openssl_aead_t *context,
    const uint8_t *srcData,
    size_t srcLen,
    uint8_t *destData,
    size_t *destLen,
    uint8_t *tag,
    size_t *tagLen);

/** @copydoc sss_aead_context_free
 *
 */
void sss_openssl_aead_context_free(sss_openssl_aead_t *context);

/*! @} */ /* end of : sss_openssl_aead */

/**
 * @addtogroup sss_openssl_mac
 * @{
 */
/** @copydoc sss_mac_context_init
 *
 */
sss_status_t sss_openssl_mac_context_init(sss_openssl_mac_t *context,
    sss_openssl_session_t *session,
    sss_openssl_object_t *keyObject,
    sss_algorithm_t algorithm,
    sss_mode_t mode);

/** @copydoc sss_mac_one_go
 *
 */
sss_status_t sss_openssl_mac_one_go(
    sss_openssl_mac_t *context, const uint8_t *message, size_t messageLen, uint8_t *mac, size_t *macLen);

/** @copydoc sss_mac_init
 *
 */
sss_status_t sss_openssl_mac_init(sss_openssl_mac_t *context);

/** @copydoc sss_mac_update
 *
 */
sss_status_t sss_openssl_mac_update(sss_openssl_mac_t *context, const uint8_t *message, size_t messageLen);

/** @copydoc sss_mac_finish
 *
 */
sss_status_t sss_openssl_mac_finish(sss_openssl_mac_t *context, uint8_t *mac, size_t *macLen);

/** @copydoc sss_mac_context_free
 *
 */
void sss_openssl_mac_context_free(sss_openssl_mac_t *context);

/*! @} */ /* end of : sss_openssl_mac */

/**
 * @addtogroup sss_openssl_md
 * @{
 */
/** @copydoc sss_digest_context_init
 *
 */
sss_status_t sss_openssl_digest_context_init(
    sss_openssl_digest_t *context, sss_openssl_session_t *session, sss_algorithm_t algorithm, sss_mode_t mode);

/** @copydoc sss_digest_one_go
 *
 */
sss_status_t sss_openssl_digest_one_go(
    sss_openssl_digest_t *context, const uint8_t *message, size_t messageLen, uint8_t *digest, size_t *digestLen);

/** @copydoc sss_digest_init
 *
 */
sss_status_t sss_openssl_digest_init(sss_openssl_digest_t *context);

/** @copydoc sss_digest_update
 *
 */
sss_status_t sss_openssl_digest_update(sss_openssl_digest_t *context, const uint8_t *message, size_t messageLen);

/** @copydoc sss_digest_finish
 *
 */
sss_status_t sss_openssl_digest_finish(sss_openssl_digest_t *context, uint8_t *digest, size_t *digestLen);

/** @copydoc sss_digest_context_free
 *
 */
void sss_openssl_digest_context_free(sss_openssl_digest_t *context);

/*! @} */ /* end of : sss_openssl_md */

/**
 * @addtogroup sss_openssl_rng
 * @{
 */
/** @copydoc sss_rng_context_init
 *
 */
sss_status_t sss_openssl_rng_context_init(sss_openssl_rng_context_t *context, sss_openssl_session_t *session);

/** @copydoc sss_rng_get_random
 *
 */
sss_status_t sss_openssl_rng_get_random(sss_openssl_rng_context_t *context, uint8_t *random_data, size_t dataLen);

/** @copydoc sss_rng_context_free
 *
 */
sss_status_t sss_openssl_rng_context_free(sss_openssl_rng_context_t *context);

/*! @} */ /* end of : sss_openssl_rng */

/* clang-format off */
#   if (SSS_HAVE_SSS == 1)
        /* Direct Call : session */
#       define sss_session_open(session,subsystem,application_id,connection_type,connectionData) \
            sss_openssl_session_open(((sss_openssl_session_t * ) session),(subsystem),(application_id),(connection_type),(connectionData))
#       define sss_session_close(session) \
            sss_openssl_session_close(((sss_openssl_session_t * ) session))
#       define sss_key_object_init(keyObject,keyStore) \
            sss_openssl_key_object_init(((sss_openssl_object_t * ) keyObject),((sss_openssl_key_store_t * ) keyStore))
#       define sss_key_object_allocate_handle(keyObject,keyId,keyPart,cipherType,keyByteLenMax,options) \
            sss_openssl_key_object_allocate_handle(((sss_openssl_object_t * ) keyObject),(keyId),(keyPart),(cipherType),(keyByteLenMax),(options))
#       define sss_key_object_get_handle(keyObject,cipherType,keyId) \
            sss_openssl_key_object_get_handle(((sss_openssl_object_t * ) keyObject),(keyId))
#       define sss_key_object_set_eccgfp_group(keyObject,group) \
            sss_openssl_key_object_set_eccgfp_group(((sss_openssl_object_t * ) keyObject),(group))
#       define sss_key_object_free(keyObject) \
            sss_openssl_key_object_free(((sss_openssl_object_t * ) keyObject))
        /* Direct Call : keyderive */
#       define sss_derive_key_context_init(context,session,keyObject,algorithm,mode) \
            sss_openssl_derive_key_context_init(((sss_openssl_derive_key_t * ) context),((sss_openssl_session_t * ) session),((sss_openssl_object_t * ) keyObject),(algorithm),(mode))
#       define sss_derive_key_one_go(context,saltObject,info,infoLen,derivedKeyObject,deriveDataLen) \
            sss_openssl_derive_key_one_go(((sss_openssl_derive_key_t * ) context),(saltObject),(info),(infoLen),(derivedKeyObject),(deriveDataLen))
#       define sss_derive_key_dh_one_go(context,otherPartyKeyObject,derivedKeyObject) \
            sss_openssl_derive_key_dh_one_go(((sss_openssl_derive_key_t * ) context),((sss_openssl_object_t * ) otherPartyKeyObject),((sss_openssl_object_t * ) derivedKeyObject))
#       define sss_derive_key_dh_two_step_part1(context) \
            sss_openssl_derive_key_dh_two_step_part1((sss_openssl_derive_key_t * ) context)
#       define sss_derive_key_dh_two_step_part2(context,otherPartyKeyObject,derivedKeyObject) \
            sss_openssl_derive_key_dh_two_step_part2(((sss_openssl_derive_key_t * ) context),((sss_openssl_object_t * ) otherPartyKeyObject),((sss_openssl_object_t * ) derivedKeyObject))
#       define sss_derive_key_dh(context,otherPartyKeyObject,derivedKeyObject) \
            sss_openssl_derive_key_dh(((sss_openssl_derive_key_t * ) context),((sss_openssl_object_t * ) otherPartyKeyObject),((sss_openssl_object_t * ) derivedKeyObject))
#       define sss_derive_key_context_free(context) \
            sss_openssl_derive_key_context_free(((sss_openssl_derive_key_t * ) context))
        /* Direct Call : keystore */
#       define sss_key_store_context_init(keyStore,session) \
            sss_openssl_key_store_context_init(((sss_openssl_key_store_t * ) keyStore),((sss_openssl_session_t * ) session))
#       define sss_key_store_allocate(keyStore,keyStoreId) \
            sss_openssl_key_store_allocate(((sss_openssl_key_store_t * ) keyStore),(keyStoreId))
#       define sss_key_store_set_key(keyStore,keyObject,data,dataLen,keyBitLen,options,optionsLen) \
            sss_openssl_key_store_set_key(((sss_openssl_key_store_t * ) keyStore),((sss_openssl_object_t * ) keyObject),(data),(dataLen),(keyBitLen),(options),(optionsLen))
#       define sss_key_store_generate_key(keyStore,keyObject,keyBitLen,options) \
            sss_openssl_key_store_generate_key(((sss_openssl_key_store_t * ) keyStore),((sss_openssl_object_t * ) keyObject),(keyBitLen),(options))
#       define sss_key_store_get_key(keyStore,keyObject,data,dataLen,pKeyBitLen) \
            sss_openssl_key_store_get_key(((sss_openssl_key_store_t * ) keyStore),((sss_openssl_object_t * ) keyObject),(data),(dataLen),(pKeyBitLen))
#       define sss_key_store_erase_key(keyStore,keyObject) \
            sss_openssl_key_store_erase_key(((sss_openssl_key_store_t * ) keyStore),((sss_openssl_object_t * ) keyObject))
#       define sss_key_store_context_free(keyStore) \
            sss_openssl_key_store_context_free(((sss_openssl_key_store_t * ) keyStore))
        /* Direct Call : asym */
#       define sss_asymmetric_context_init(context,session,keyObject,algorithm,mode) \
            sss_openssl_asymmetric_context_init(((sss_openssl_asymmetric_t * ) context),((sss_openssl_session_t * ) session),((sss_openssl_object_t * ) keyObject),(algorithm),(mode))
#       define sss_asymmetric_sign_digest(context,digest,digestLen,signature,signatureLen) \
            sss_openssl_asymmetric_sign_digest(((sss_openssl_asymmetric_t * ) context),(digest),(digestLen),(signature),(signatureLen))
#       define sss_asymmetric_verify_digest(context,digest,digestLen,signature,signatureLen) \
            sss_openssl_asymmetric_verify_digest(((sss_openssl_asymmetric_t * ) context),(digest),(digestLen),(signature),(signatureLen))
#       define sss_asymmetric_context_free(context) \
            sss_openssl_asymmetric_context_free(((sss_openssl_asymmetric_t * ) context))
#       define sss_asymmetric_sign_one_go(context,srcData,srcLen,signature,signatureLen) \
            sss_openssl_asymmetric_sign_one_go(((sss_openssl_asymmetric_t * ) context),(srcData),(srcLen),(signature),(signatureLen))
#       define sss_asymmetric_verify_one_go(context,srcData,srcLen,signature,signatureLen) \
            sss_openssl_asymmetric_verify_one_go(((sss_openssl_asymmetric_t * ) context),(srcData),(srcLen),(signature),(signatureLen))
#       define sss_asymmetric_sign_init(context,srcData,srcLen) \
            sss_openssl_asymmetric_sign_init(((sss_openssl_asymmetric_t * ) context),(srcData),(srcLen))
#       define sss_asymmetric_sign_update(context,srcData,srcLen) \
            sss_openssl_asymmetric_sign_update(((sss_openssl_asymmetric_t * ) context),(srcData),(srcLen))
#       define sss_asymmetric_sign_finish(context,srcData,srcLen,signature,signatureLen) \
            sss_openssl_asymmetric_sign_finish(((sss_openssl_asymmetric_t * ) context),(srcData),(srcLen),(signature),(signatureLen))
#       define sss_asymmetric_verify_init(context,srcData,srcLen) \
            sss_openssl_asymmetric_verify_init(((sss_openssl_asymmetric_t * ) context),(srcData),(srcLen))
#       define sss_asymmetric_verify_update(context,srcData,srcLen) \
            sss_openssl_asymmetric_verify_update(((sss_openssl_asymmetric_t * ) context),(srcData),(srcLen))
#       define sss_asymmetric_verify_finish(context,srcData,srcLen,signature,signatureLen) \
            sss_openssl_asymmetric_verify_finish(((sss_openssl_asymmetric_t * ) context),(srcData),(srcLen),(signature),(signatureLen))

        /* Direct Call : symm */
#       define sss_symmetric_context_init(context,session,keyObject,algorithm,mode) \
            sss_openssl_symmetric_context_init(((sss_openssl_symmetric_t * ) context),((sss_openssl_session_t * ) session),((sss_openssl_object_t * ) keyObject),(algorithm),(mode))
#       define sss_cipher_one_go(context,iv,ivLen,srcData,destData,dataLen) \
            sss_openssl_cipher_one_go(((sss_openssl_symmetric_t * ) context),(iv),(ivLen),(srcData),(destData),(dataLen))
#       define sss_cipher_init(context,iv,ivLen) \
            sss_openssl_cipher_init(((sss_openssl_symmetric_t * ) context),(iv),(ivLen))
#       define sss_cipher_update(context,srcData,srcLen,destData,destLen) \
            sss_openssl_cipher_update(((sss_openssl_symmetric_t * ) context),(srcData),(srcLen),(destData),(destLen))
#       define sss_cipher_finish(context,srcData,srcLen,destData,destLen) \
            sss_openssl_cipher_finish(((sss_openssl_symmetric_t * ) context),(srcData),(srcLen),(destData),(destLen))
#       define sss_symmetric_context_free(context) \
            sss_openssl_symmetric_context_free(((sss_openssl_symmetric_t * ) context))
        /* Direct Call : aead */
#       define sss_aead_context_init(context,session,keyObject,algorithm,mode) \
            sss_openssl_aead_context_init(((sss_openssl_aead_t * ) context),((sss_openssl_session_t * ) session),((sss_openssl_object_t * ) keyObject),(algorithm),(mode))
#       define sss_aead_one_go(context,srcData,destData,size,nonce,nonceLen,aad,aadLen,tag,tagLen) \
            sss_openssl_aead_one_go(((sss_openssl_aead_t * ) context),(srcData),(destData),(size),(nonce),(nonceLen),(aad),(aadLen),(tag),(tagLen))
#       define sss_aead_init(context,nonce,nonceLen,tagLen,aadLen,payloadLen) \
            sss_openssl_aead_init(((sss_openssl_aead_t * ) context),(nonce),(nonceLen),(tagLen),(aadLen),(payloadLen))
#       define sss_aead_update_aad(context,aadData,aadDataLen) \
            sss_openssl_aead_update_aad(((sss_openssl_aead_t * ) context),(aadData),(aadDataLen))
#       define sss_aead_update(context,srcData,srcLen,destData,destLen) \
            sss_openssl_aead_update(((sss_openssl_aead_t * ) context),(srcData),(srcLen),(destData),(destLen))
#       define sss_aead_finish(context,srcData,srcLen,destData,destLen,tag,tagLen) \
            sss_openssl_aead_finish(((sss_openssl_aead_t * ) context),(srcData),(srcLen),(destData),(destLen),(tag),(tagLen))
#       define sss_aead_context_free(context) \
            sss_openssl_aead_context_free(((sss_openssl_aead_t * ) context))
        /* Direct Call : mac */
#       define sss_mac_context_init(context,session,keyObject,algorithm,mode) \
            sss_openssl_mac_context_init(((sss_openssl_mac_t * ) context),((sss_openssl_session_t * ) session),((sss_openssl_object_t * ) keyObject),(algorithm),(mode))
#       define sss_mac_one_go(context,message,messageLen,mac,macLen) \
            sss_openssl_mac_one_go(((sss_openssl_mac_t * ) context),(message),(messageLen),(mac),(macLen))
#       define sss_mac_init(context) \
            sss_openssl_mac_init(((sss_openssl_mac_t * ) context))
#       define sss_mac_update(context,message,messageLen) \
            sss_openssl_mac_update(((sss_openssl_mac_t * ) context),(message),(messageLen))
#       define sss_mac_finish(context,mac,macLen) \
            sss_openssl_mac_finish(((sss_openssl_mac_t * ) context),(mac),(macLen))
#       define sss_mac_context_free(context) \
            sss_openssl_mac_context_free(((sss_openssl_mac_t * ) context))
        /* Direct Call : md */
#       define sss_digest_context_init(context,session,algorithm,mode) \
            sss_openssl_digest_context_init(((sss_openssl_digest_t * ) context),((sss_openssl_session_t * ) session),(algorithm),(mode))
#       define sss_digest_one_go(context,message,messageLen,digest,digestLen) \
            sss_openssl_digest_one_go(((sss_openssl_digest_t * ) context),(message),(messageLen),(digest),(digestLen))
#       define sss_digest_init(context) \
            sss_openssl_digest_init(((sss_openssl_digest_t * ) context))
#       define sss_digest_update(context,message,messageLen) \
            sss_openssl_digest_update(((sss_openssl_digest_t * ) context),(message),(messageLen))
#       define sss_digest_finish(context,digest,digestLen) \
            sss_openssl_digest_finish(((sss_openssl_digest_t * ) context),(digest),(digestLen))
#       define sss_digest_context_free(context) \
            sss_openssl_digest_context_free(((sss_openssl_digest_t * ) context))
        /* Direct Call : rng */
#       define sss_rng_context_init(context,session) \
            sss_openssl_rng_context_init(((sss_openssl_rng_context_t * ) context),((sss_openssl_session_t * ) session))
#       define sss_rng_get_random(context,random_data,dataLen) \
            sss_openssl_rng_get_random(((sss_openssl_rng_context_t * ) context),(random_data),(dataLen))
#       define sss_rng_context_free(context) \
            sss_openssl_rng_context_free(((sss_openssl_rng_context_t * ) context))
        /* Direct Call : mgmt */
#   endif /* (SSS_HAVE_SSS == 1) */
#   if (SSS_HAVE_HOSTCRYPTO_MBEDTLS == 0)
        /* Host Call : session */
#       define sss_host_session_open(session,subsystem,application_id,connection_type,connectionData) \
            sss_openssl_session_open(((sss_openssl_session_t * ) session),(subsystem),(application_id),(connection_type),(connectionData))
#       define sss_host_session_close(session) \
            sss_openssl_session_close(((sss_openssl_session_t * ) session))
#       define sss_host_key_object_init(keyObject,keyStore) \
            sss_openssl_key_object_init(((sss_openssl_object_t * ) keyObject),((sss_openssl_key_store_t * ) keyStore))
#       define sss_host_key_object_allocate_handle(keyObject,keyId,keyPart,cipherType,keyByteLenMax,options) \
            sss_openssl_key_object_allocate_handle(((sss_openssl_object_t * ) keyObject),(keyId),(keyPart),(cipherType),(keyByteLenMax),(options))
#       define sss_host_key_object_get_handle(keyObject,keyId) \
            sss_openssl_key_object_get_handle(((sss_openssl_object_t * ) keyObject),(keyId))
#       define sss_host_key_object_set_eccgfp_group(keyObject,group) \
            sss_openssl_key_object_set_eccgfp_group(((sss_openssl_object_t * ) keyObject),(group))
#       define sss_host_key_object_free(keyObject) \
            sss_openssl_key_object_free(((sss_openssl_object_t * ) keyObject))
        /* Host Call : keyderive */
#       define sss_host_derive_key_context_init(context,session,keyObject,algorithm,mode) \
            sss_openssl_derive_key_context_init(((sss_openssl_derive_key_t * ) context),((sss_openssl_session_t * ) session),((sss_openssl_object_t * ) keyObject),(algorithm),(mode))
#       define sss_host_derive_key_dh(context,otherPartyKeyObject,derivedKeyObject) \
            sss_openssl_derive_key_dh(((sss_openssl_derive_key_t * ) context),((sss_openssl_object_t * ) otherPartyKeyObject),((sss_openssl_object_t * ) derivedKeyObject))
#       define sss_host_derive_key_context_free(context) \
            sss_openssl_derive_key_context_free(((sss_openssl_derive_key_t * ) context))
        /* Host Call : keystore */
#       define sss_host_key_store_context_init(keyStore,session) \
            sss_openssl_key_store_context_init(((sss_openssl_key_store_t * ) keyStore),((sss_openssl_session_t * ) session))
#       define sss_host_key_store_allocate(keyStore,keyStoreId) \
            sss_openssl_key_store_allocate(((sss_openssl_key_store_t * ) keyStore),(keyStoreId))
#       define sss_host_key_store_set_key(keyStore,keyObject,data,dataLen,keyBitLen,options,optionsLen) \
            sss_openssl_key_store_set_key(((sss_openssl_key_store_t * ) keyStore),((sss_openssl_object_t * ) keyObject),(data),(dataLen),(keyBitLen),(options),(optionsLen))
#       define sss_host_key_store_generate_key(keyStore,keyObject,keyBitLen,options) \
            sss_openssl_key_store_generate_key(((sss_openssl_key_store_t * ) keyStore),((sss_openssl_object_t * ) keyObject),(keyBitLen),(options))
#       define sss_host_key_store_get_key(keyStore,keyObject,data,dataLen,pKeyBitLen) \
            sss_openssl_key_store_get_key(((sss_openssl_key_store_t * ) keyStore),((sss_openssl_object_t * ) keyObject),(data),(dataLen),(pKeyBitLen))
#       define sss_host_key_store_erase_key(keyStore,keyObject) \
            sss_openssl_key_store_erase_key(((sss_openssl_key_store_t * ) keyStore),((sss_openssl_object_t * ) keyObject))
#       define sss_host_key_store_context_free(keyStore) \
            sss_openssl_key_store_context_free(((sss_openssl_key_store_t * ) keyStore))
        /* Host Call : asym */
#       define sss_host_asymmetric_context_init(context,session,keyObject,algorithm,mode) \
            sss_openssl_asymmetric_context_init(((sss_openssl_asymmetric_t * ) context),((sss_openssl_session_t * ) session),((sss_openssl_object_t * ) keyObject),(algorithm),(mode))
#       define sss_host_asymmetric_sign_digest(context,digest,digestLen,signature,signatureLen) \
            sss_openssl_asymmetric_sign_digest(((sss_openssl_asymmetric_t * ) context),(digest),(digestLen),(signature),(signatureLen))
#       define sss_host_asymmetric_verify_digest(context,digest,digestLen,signature,signatureLen) \
            sss_openssl_asymmetric_verify_digest(((sss_openssl_asymmetric_t * ) context),(digest),(digestLen),(signature),(signatureLen))
#       define sss_host_asymmetric_context_free(context) \
            sss_openssl_asymmetric_context_free(((sss_openssl_asymmetric_t * ) context))
        /* Host Call : symm */
#       define sss_host_symmetric_context_init(context,session,keyObject,algorithm,mode) \
            sss_openssl_symmetric_context_init(((sss_openssl_symmetric_t * ) context),((sss_openssl_session_t * ) session),((sss_openssl_object_t * ) keyObject),(algorithm),(mode))
#       define sss_host_cipher_one_go(context,iv,ivLen,srcData,destData,dataLen) \
            sss_openssl_cipher_one_go(((sss_openssl_symmetric_t * ) context),(iv),(ivLen),(srcData),(destData),(dataLen))
#       define sss_host_cipher_init(context,iv,ivLen) \
            sss_openssl_cipher_init(((sss_openssl_symmetric_t * ) context),(iv),(ivLen))
#       define sss_host_cipher_update(context,srcData,srcLen,destData,destLen) \
            sss_openssl_cipher_update(((sss_openssl_symmetric_t * ) context),(srcData),(srcLen),(destData),(destLen))
#       define sss_host_cipher_finish(context,srcData,srcLen,destData,destLen) \
            sss_openssl_cipher_finish(((sss_openssl_symmetric_t * ) context),(srcData),(srcLen),(destData),(destLen))
#       define sss_host_symmetric_context_free(context) \
            sss_openssl_symmetric_context_free(((sss_openssl_symmetric_t * ) context))
        /* Host Call : aead */
#       define sss_host_aead_context_init(context,session,keyObject,algorithm,mode) \
            sss_openssl_aead_context_init(((sss_openssl_aead_t * ) context),((sss_openssl_session_t * ) session),((sss_openssl_object_t * ) keyObject),(algorithm),(mode))
#       define sss_host_aead_one_go(context,srcData,destData,size,nonce,nonceLen,aad,aadLen,tag,tagLen) \
            sss_openssl_aead_one_go(((sss_openssl_aead_t * ) context),(srcData),(destData),(size),(nonce),(nonceLen),(aad),(aadLen),(tag),(tagLen))
#       define sss_host_aead_init(context,nonce,nonceLen,tagLen,aadLen,payloadLen) \
            sss_openssl_aead_init(((sss_openssl_aead_t * ) context),(nonce),(nonceLen),(tagLen),(aadLen),(payloadLen))
#       define sss_host_aead_update_aad(context,aadData,aadDataLen) \
            sss_openssl_aead_update_aad(((sss_openssl_aead_t * ) context),(aadData),(aadDataLen))
#       define sss_host_aead_update(context,srcData,srcLen,destData,destLen) \
            sss_openssl_aead_update(((sss_openssl_aead_t * ) context),(srcData),(srcLen),(destData),(destLen))
#       define sss_host_aead_finish(context,srcData,srcLen,destData,destLen,tag,tagLen) \
            sss_openssl_aead_finish(((sss_openssl_aead_t * ) context),(srcData),(srcLen),(destData),(destLen),(tag),(tagLen))
#       define sss_host_aead_context_free(context) \
            sss_openssl_aead_context_free(((sss_openssl_aead_t * ) context))
        /* Host Call : mac */
#       define sss_host_mac_context_init(context,session,keyObject,algorithm,mode) \
            sss_openssl_mac_context_init(((sss_openssl_mac_t * ) context),((sss_openssl_session_t * ) session),((sss_openssl_object_t * ) keyObject),(algorithm),(mode))
#       define sss_host_mac_one_go(context,message,messageLen,mac,macLen) \
            sss_openssl_mac_one_go(((sss_openssl_mac_t * ) context),(message),(messageLen),(mac),(macLen))
#       define sss_host_mac_init(context) \
            sss_openssl_mac_init(((sss_openssl_mac_t * ) context))
#       define sss_host_mac_update(context,message,messageLen) \
            sss_openssl_mac_update(((sss_openssl_mac_t * ) context),(message),(messageLen))
#       define sss_host_mac_finish(context,mac,macLen) \
            sss_openssl_mac_finish(((sss_openssl_mac_t * ) context),(mac),(macLen))
#       define sss_host_mac_context_free(context) \
            sss_openssl_mac_context_free(((sss_openssl_mac_t * ) context))
        /* Host Call : md */
#       define sss_host_digest_context_init(context,session,algorithm,mode) \
            sss_openssl_digest_context_init(((sss_openssl_digest_t * ) context),((sss_openssl_session_t * ) session),(algorithm),(mode))
#       define sss_host_digest_one_go(context,message,messageLen,digest,digestLen) \
            sss_openssl_digest_one_go(((sss_openssl_digest_t * ) context),(message),(messageLen),(digest),(digestLen))
#       define sss_host_digest_init(context) \
            sss_openssl_digest_init(((sss_openssl_digest_t * ) context))
#       define sss_host_digest_update(context,message,messageLen) \
            sss_openssl_digest_update(((sss_openssl_digest_t * ) context),(message),(messageLen))
#       define sss_host_digest_finish(context,digest,digestLen) \
            sss_openssl_digest_finish(((sss_openssl_digest_t * ) context),(digest),(digestLen))
#       define sss_host_digest_context_free(context) \
            sss_openssl_digest_context_free(((sss_openssl_digest_t * ) context))
        /* Host Call : rng */
#       define sss_host_rng_context_init(context,session) \
            sss_openssl_rng_context_init(((sss_openssl_rng_context_t * ) context),((sss_openssl_session_t * ) session))
#       define sss_host_rng_get_random(context,random_data,dataLen) \
            sss_openssl_rng_get_random(((sss_openssl_rng_context_t * ) context),(random_data),(dataLen))
#       define sss_host_rng_context_free(context) \
            sss_openssl_rng_context_free(((sss_openssl_rng_context_t * ) context))
#   endif /* (SSS_HAVE_SSS == 1) */
/* clang-format on */
#endif /* SSS_HAVE_HOSTCRYPTO_OPENSSL */
#ifdef __cplusplus
} // extern "C"
#endif /* __cplusplus */

#endif /* FSL_SSS_OPENSSL_APIS_H */
