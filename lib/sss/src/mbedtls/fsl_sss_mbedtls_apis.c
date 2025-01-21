/*
 *
 * Copyright 2018-2020, 2022-2024 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "fsl_sss_mbedtls_apis.h"

#define MBEDTLS_DO_LITTLE_ENDIAN

#if SSS_HAVE_HOSTCRYPTO_MBEDTLS

#include "mbedtls/version.h"
#include <stdlib.h>
#ifdef MBEDTLS_FS_IO
#include <memory.h>
#endif
#include <inttypes.h>
#include "mbedtls/aes.h"
#include "mbedtls/base64.h"
#include "mbedtls/cmac.h"
#include "mbedtls/des.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/md.h"
#include "nxEnsure.h"
#include "nxLog_msg.h"
#include "sm_types.h"
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include "fsl_sss_util_asn1_der.h"

#define MAX_KEY_OBJ_COUNT KS_N_ENTIRES
#define MAX_FILE_NAME_SIZE 255
#define MAX_SHARED_SECRET_DERIVED_DATA 255
#define BEGIN_PRIVATE "-----BEGIN PRIVATE KEY-----\n"
#define END_PRIVATE "\n-----END PRIVATE KEY-----"
#define BEGIN_PUBLIC "-----BEGIN PUBLIC KEY-----\n"
#define END_PUBLIC "\n-----END PUBLIC KEY-----"

#define NX_CIPHER_BLOCK_SIZE 16
#define NX_DES_BLOCK_SIZE (MBEDTLS_KEY_LENGTH_DES / 8)

/* ************************************************************************** */
/* Functions : Private sss mbedtls delceration                                */
/* ************************************************************************** */
static sss_status_t sss_mbedtls_drbg_seed(sss_mbedtls_session_t *pSession, const char *pers, size_t persLen);

#if SSS_HAVE_MBEDTLS_3_X
int mbedtls_entropy_func_3_X(void *data, unsigned char *output, size_t len);
#endif

static sss_status_t sss_mbedtls_generate_ecp_key(
    mbedtls_pk_context *pkey, sss_mbedtls_session_t *pSession, size_t keyBitLen, sss_cipher_type_t key_typ);

static sss_status_t sss_mbedtls_hkdf_extract(const mbedtls_md_info_t *md,
    const uint8_t *salt,
    size_t salt_len,
    const uint8_t *ikm,
    size_t ikm_len,
    uint8_t *prk);

static sss_status_t sss_mbedtls_hkdf_expand(const mbedtls_md_info_t *md,
    const uint8_t *prk,
    size_t prk_len,
    const uint8_t *info,
    size_t info_len,
    uint8_t *okm,
    size_t okm_len);

static sss_status_t sss_mbedtls_set_key(
    sss_mbedtls_object_t *keyObject, const uint8_t *data, size_t dataLen, size_t keyBitLen);

static sss_status_t sss_mbedtls_aead_ccm_finish(
    sss_mbedtls_aead_t *context, uint8_t *destData, size_t *destLen, uint8_t *tag, size_t *tagLen);
static sss_status_t sss_mbedtls_aead_ccm_update(sss_mbedtls_aead_t *context, const uint8_t *srcData, size_t srcLen);

/* ************************************************************************** */
/* Functions : sss_mbedtls_session                                            */
/* ************************************************************************** */

#ifndef MBEDTLS_CTR_DRBG_C
#error Need MBEDTLS_CTR_DRBG_C defined
#endif

sss_status_t sss_mbedtls_session_open(sss_mbedtls_session_t *session,
    sss_type_t subsystem,
    uint32_t application_id,
    sss_connection_type_t connection_type,
    void *connectionData)
{
    sss_status_t retval      = kStatus_SSS_InvalidArgument;
    static const char pers[] = "mbedtls_session";
    if (NULL == session) {
        LOG_E("session pointer invalid!");
        goto exit;
    }
    memset(session, 0, sizeof(*session));
    ENSURE_OR_GO_EXIT(connection_type == kSSS_ConnectionType_Plain);

#ifdef MBEDTLS_FS_IO
    if (connectionData == NULL) {
        /* Nothing */
    }
    else {
        const char *szRootPath = (const char *)connectionData;
        session->szRootPath    = szRootPath;
    }
#else
    if (connectionData != NULL) {
        /* Can't support connectionData  != NULL for mbedTLS without
        * MBEDTLS_FS_IO */
        retval = kStatus_SSS_InvalidArgument;
        goto exit;
    }
#endif
    retval            = kStatus_SSS_Fail;
    session->ctr_drbg = SSS_MALLOC(sizeof(*session->ctr_drbg));
    ENSURE_OR_GO_EXIT(session->ctr_drbg != NULL);

    session->entropy = SSS_MALLOC(sizeof(*session->entropy));
    ENSURE_OR_GO_EXIT(session->entropy != NULL);
    retval = kStatus_SSS_InvalidArgument;

    mbedtls_ctr_drbg_init((session->ctr_drbg));
    mbedtls_entropy_init((session->entropy));
    retval = sss_mbedtls_drbg_seed(session, pers, sizeof(pers) - 1);
    if (retval != kStatus_SSS_Success) {
        LOG_E("MbedTLS:DRBG Failed");
        goto exit;
    }
    /* Success */
    session->subsystem = subsystem;

exit:
    return retval;
}

sss_status_t sss_mbedtls_session_close(sss_mbedtls_session_t *session)
{
    sss_status_t retval = kStatus_SSS_Fail;

    ENSURE_OR_GO_EXIT(NULL != session)
    if (session->ctr_drbg != NULL) {
        SSS_FREE(session->ctr_drbg);
    }
    if (session->entropy != NULL) {
        SSS_FREE(session->entropy);
    }
    memset(session, 0, sizeof(*session));
    retval = kStatus_SSS_Success;

exit:
    return retval;
}

/* End: mbedtls_session */

/* ************************************************************************** */
/* Functions : sss_mbedtls_keyobj                                             */
/* ************************************************************************** */

sss_status_t sss_mbedtls_key_object_init(sss_mbedtls_object_t *keyObject, sss_mbedtls_key_store_t *keyStore)
{
    sss_status_t retval = kStatus_SSS_Fail;
    ENSURE_OR_GO_CLEANUP(NULL != keyObject);
    ENSURE_OR_GO_CLEANUP(NULL != keyStore);
    memset(keyObject, 0, sizeof(*keyObject));
    keyObject->keyStore = keyStore;
    retval              = kStatus_SSS_Success;
cleanup:
    return retval;
}

sss_status_t sss_mbedtls_key_object_allocate_handle(sss_mbedtls_object_t *keyObject,
    uint32_t keyId,
    sss_key_part_t key_part,
    sss_cipher_type_t cipherType,
    size_t keyByteLenMax,
    uint32_t options)
{
    sss_status_t retval = kStatus_SSS_Fail;
    ENSURE_OR_GO_CLEANUP(NULL != keyObject);
    ENSURE_OR_GO_CLEANUP(keyId != 0);
    ENSURE_OR_GO_CLEANUP(keyId != 0xFFFFFFFFu);
    ENSURE_OR_GO_CLEANUP(keyByteLenMax > 0);

#ifdef EX_SSS_OBJID_TEST_START
    if (keyId < EX_SSS_OBJID_TEST_START) {
        return kStatus_SSS_Fail;
    }
    if (keyId > EX_SSS_OBJID_TEST_END) {
        return kStatus_SSS_Fail;
    }
#endif

    if (options != kKeyObject_Mode_Persistent && options != kKeyObject_Mode_Transient) {
        LOG_E("sss_mbedtls_key_object_allocate_handle option invalid 0x%X", options);
        retval = kStatus_SSS_Fail;
        goto cleanup;
    }
    {
        /* to avoid error -Werror=type-limit */
        unsigned int uikey_part = ((unsigned int)key_part);
        if (uikey_part > UINT8_MAX) {
            LOG_E(" Only objectType 8 bits wide supported");
            retval = kStatus_SSS_Fail;
            goto cleanup;
        }
    }
#if defined(MBEDTLS_FS_IO) && ((defined(SSS_HAVE_HOST_PCWINDOWS) && (SSS_HAVE_HOST_PCWINDOWS)) ||    \
                                  (defined(SSS_HAVE_HOST_PCLINUX64) && (SSS_HAVE_HOST_PCLINUX64)) || \
                                  (defined(SSS_HAVE_HOST_RASPBIAN) && (SSS_HAVE_HOST_RASPBIAN)))
    if (options == kKeyObject_Mode_Persistent) {
        uint32_t i;
        sss_mbedtls_object_t **ks;
        ENSURE_OR_GO_CLEANUP(NULL != keyObject->keyStore);
        ENSURE_OR_GO_CLEANUP(keyObject->keyStore->max_object_count != 0);
        ENSURE_OR_GO_CLEANUP(keyByteLenMax <= UINT16_MAX);
        retval = ks_common_update_fat(
            keyObject->keyStore->keystore_shadow, keyId, key_part, cipherType, 0, 0, (uint16_t)keyByteLenMax);
        ENSURE_OR_GO_CLEANUP(retval == kStatus_SSS_Success);
        ks     = keyObject->keyStore->objects;
        retval = kStatus_SSS_Fail;
        for (i = 0; i < keyObject->keyStore->max_object_count; i++) {
            if (ks[i] == NULL) {
                ks[i]  = keyObject;
                retval = ks_mbedtls_key_object_create(keyObject, keyId, key_part, cipherType, keyByteLenMax, options);
                break;
            }
        }
    }
    else
#endif
    {
        retval = ks_mbedtls_key_object_create(keyObject, keyId, key_part, cipherType, keyByteLenMax, options);
    }
cleanup:
    return retval;
}

sss_status_t sss_mbedtls_key_object_get_handle(sss_mbedtls_object_t *keyObject, uint32_t keyId)
{
    sss_status_t retval = kStatus_SSS_Fail;
#if defined(MBEDTLS_FS_IO) && ((defined(SSS_HAVE_HOST_PCWINDOWS) && (SSS_HAVE_HOST_PCWINDOWS)) ||    \
                                  (defined(SSS_HAVE_HOST_PCLINUX64) && (SSS_HAVE_HOST_PCLINUX64)) || \
                                  (defined(SSS_HAVE_HOST_RASPBIAN) && (SSS_HAVE_HOST_RASPBIAN)))
    uint32_t i = 0;
    ENSURE_OR_GO_CLEANUP(NULL != keyObject);
    ENSURE_OR_GO_CLEANUP(NULL != keyObject->keyStore);
    retval = kStatus_SSS_Success;
    /* If key store already has loaded this and shared this - fail */
    for (i = 0; i < keyObject->keyStore->max_object_count; i++) {
        if (keyObject->keyStore->objects[i] != NULL && keyObject->keyStore->objects[i]->keyId == keyId) {
            /* Key Object already loaded and shared in another instance */
            LOG_E("KeyID 0x%X already loaded / shared", keyId);
            retval = kStatus_SSS_Fail;
            break;
        }
    }
    if (retval == kStatus_SSS_Success) {
        for (i = 0; i < keyObject->keyStore->max_object_count; i++) {
            if (keyObject->keyStore->objects[i] == NULL) {
                retval = ks_mbedtls_load_key(keyObject, keyObject->keyStore->keystore_shadow, keyId);
                if (retval == kStatus_SSS_Success) {
                    keyObject->keyStore->objects[i] = keyObject;
                }
                break;
            }
        }
    }
cleanup:
#endif
    return retval;
}

void sss_mbedtls_key_object_free(sss_mbedtls_object_t *keyObject)
{
    if (keyObject == NULL) {
        LOG_E("No keyObject to free!");
    }
    else {
#ifdef MBEDTLS_FS_IO
        if (keyObject->keyStore != NULL && keyObject->objectType != 0) {
            unsigned int i = 0;
            for (i = 0; i < keyObject->keyStore->max_object_count; i++) {
                if (keyObject->keyStore->objects[i] == keyObject) {
                    keyObject->keyStore->objects[i] = NULL;
                    break;
                }
            }
        }
#endif
        if (keyObject->contents != NULL && keyObject->contents_must_free) {
            switch (keyObject->objectType) {
            case kSSS_KeyPart_Public:
            case kSSS_KeyPart_Pair:
            case kSSS_KeyPart_Private: {
                mbedtls_pk_context *pk;
                pk = (mbedtls_pk_context *)keyObject->contents;
                mbedtls_pk_free(pk);
                SSS_FREE(pk);
                break;
            }
            default:
                SSS_FREE(keyObject->contents);
            }
        }
        memset(keyObject, 0, sizeof(*keyObject));
    } /* if (keyObject != NULL) */
}

/* End: mbedtls_keyobj */

/* ************************************************************************** */
/* Functions : sss_mbedtls_keyderive                                          */
/* ************************************************************************** */

sss_status_t sss_mbedtls_derive_key_context_init(sss_mbedtls_derive_key_t *context,
    sss_mbedtls_session_t *session,
    sss_mbedtls_object_t *keyObject,
    sss_algorithm_t algorithm,
    sss_mode_t mode)
{
    sss_status_t retval = kStatus_SSS_Fail;
    ENSURE_OR_GO_CLEANUP(NULL != context);
    ENSURE_OR_GO_CLEANUP(NULL != session);
    ENSURE_OR_GO_CLEANUP(NULL != keyObject);
    ENSURE_OR_GO_CLEANUP(NULL != keyObject->contents);

    context->session   = session;
    context->keyObject = keyObject;
    context->algorithm = algorithm;
    context->mode      = mode;
    retval             = kStatus_SSS_Success;
cleanup:
    return retval;
}

sss_status_t sss_mbedtls_derive_key_dh(sss_mbedtls_derive_key_t *context,
    sss_mbedtls_object_t *otherPartyKeyObject,
    sss_mbedtls_object_t *derivedKeyObject)
{
    sss_status_t retval          = kStatus_SSS_Fail;
    int ret                      = -1;
    mbedtls_pk_context *pKeyPrv  = NULL;
    mbedtls_ecp_keypair *pEcpPrv = NULL;

#if defined(MBEDTLS_ECDH_C)
    mbedtls_pk_context *pKeyExt  = NULL;
    mbedtls_ecp_keypair *pEcpExt = NULL;
#endif
    size_t keyLen                              = 0;
    size_t sharedSecretLen                     = 0;
    size_t sharedSecretLen_Derived             = 0;
    const mbedtls_ecp_curve_info *p_curve_info = NULL;
    mbedtls_mpi rawSharedData                  = {0};

    ENSURE_OR_GO_EXIT(NULL != context);
    ENSURE_OR_GO_EXIT(NULL != context->keyObject);
    ENSURE_OR_GO_EXIT(NULL != context->keyObject->contents);
    ENSURE_OR_GO_EXIT(NULL != otherPartyKeyObject);
    ENSURE_OR_GO_EXIT(NULL != otherPartyKeyObject->contents);
    ENSURE_OR_GO_EXIT(NULL != derivedKeyObject);

    pKeyPrv = (mbedtls_pk_context *)context->keyObject->contents;
    pEcpPrv = mbedtls_pk_ec(*pKeyPrv);
    ENSURE_OR_GO_EXIT(NULL != pEcpPrv);

#if defined(MBEDTLS_ECDH_C)
    pKeyExt = (mbedtls_pk_context *)otherPartyKeyObject->contents;
    pEcpExt = mbedtls_pk_ec(*pKeyExt);
    ENSURE_OR_GO_EXIT(NULL != pEcpExt);
#endif

    mbedtls_mpi_init(&rawSharedData);

/* Compute the size of the shared secret */
#if SSS_HAVE_MBEDTLS_3_X
    p_curve_info = mbedtls_ecp_curve_info_from_grp_id(pEcpPrv->private_grp.id);
#else
    p_curve_info = mbedtls_ecp_curve_info_from_grp_id(pEcpPrv->grp.id);
#endif
    if (p_curve_info != NULL) {
        keyLen = (size_t)(((p_curve_info->bit_size + 7)) / 8);
    }
    else {
        goto exit;
    }

    sharedSecretLen = (size_t)(keyLen);
#if defined(MBEDTLS_ECDH_C)
#if SSS_HAVE_MBEDTLS_3_X
    ret = mbedtls_ecdh_compute_shared(&pEcpPrv->private_grp,
        &rawSharedData,
        &(pEcpExt->private_Q),
        &(pEcpPrv->private_d),
        mbedtls_ctr_drbg_random,
        context->session->ctr_drbg);
#else
    ret = mbedtls_ecdh_compute_shared(&pEcpPrv->grp,
        &rawSharedData,
        &(pEcpExt->Q),
        &(pEcpPrv->d),
        mbedtls_ctr_drbg_random,
        context->session->ctr_drbg);
#endif
#endif
    if (ret != 0) {
        LOG_E("mbedtls_ecdh_compute_shared returned -0x%04x", -ret);
        goto exit;
    }
    sharedSecretLen_Derived = mbedtls_mpi_size(&rawSharedData);
    if (sharedSecretLen_Derived > sharedSecretLen) {
        LOG_E("Failed: Incorrect shared key length");
        mbedtls_mpi_free(&rawSharedData);
        goto exit;
    }

    derivedKeyObject->contents_size = keyLen;
    ret = mbedtls_mpi_write_binary(&rawSharedData, derivedKeyObject->contents, derivedKeyObject->contents_size);
    if (ret != 0) {
        LOG_E("Failed: unable to write shared key");
        goto exit;
    }
    mbedtls_mpi_free(&rawSharedData);
    retval = kStatus_SSS_Success;
exit:
    return retval;
}

sss_status_t sss_mbedtls_derive_key_dh_two_step_part1(sss_mbedtls_derive_key_t *context)
{
    sss_status_t status      = kStatus_SSS_Fail;
    mbedtls_pk_context *pkey = NULL;

    ENSURE_OR_GO_EXIT(NULL != context)
    ENSURE_OR_GO_EXIT(NULL != context->keyObject)

    /* Retrieving the underlying pkey structure from sss object */
    pkey = (mbedtls_pk_context *)context->keyObject->contents;
    ENSURE_OR_GO_EXIT(NULL != pkey)

/* Ensure that there is no pkey context already present */
#if SSS_HAVE_MBEDTLS_3_X
    if ((NULL == pkey->private_pk_info) && (NULL == pkey->private_pk_ctx)) {
        status = sss_mbedtls_key_store_generate_key(context->keyObject->keyStore, context->keyObject, 256, NULL);
    }
#else
    if ((NULL == pkey->pk_info) && (NULL == pkey->pk_ctx)) {
        status = sss_mbedtls_key_store_generate_key(context->keyObject->keyStore, context->keyObject, 256, NULL);
    }
#endif
    else {
        LOG_E("A keypair already exists in this derive-key context");
    }
exit:
    return status;
}

sss_status_t sss_mbedtls_derive_key_dh_two_step_part2(sss_mbedtls_derive_key_t *context,
    sss_mbedtls_object_t *otherPartyKeyObject,
    sss_mbedtls_object_t *derivedKeyObject)
{
    return sss_mbedtls_derive_key_dh(context, otherPartyKeyObject, derivedKeyObject);
}

void sss_mbedtls_derive_key_context_free(sss_mbedtls_derive_key_t *context)
{
    if (NULL == context) {
        LOG_E("No context to free!");
    }
    else {
        memset(context, 0, sizeof(*context));
    }
}

/* End: mbedtls_keyderive */

/* ************************************************************************** */
/* Functions : sss_mbedtls_keystore                                           */
/* ************************************************************************** */

sss_status_t sss_mbedtls_key_store_context_init(sss_mbedtls_key_store_t *keyStore, sss_mbedtls_session_t *session)
{
    sss_status_t retval = kStatus_SSS_Fail;
    ENSURE_OR_GO_CLEANUP(NULL != keyStore);
    ENSURE_OR_GO_CLEANUP(NULL != session);

    memset(keyStore, 0, sizeof(*keyStore));
    keyStore->session = session;
    retval            = kStatus_SSS_Success;
cleanup:
    return retval;
}

sss_status_t sss_mbedtls_key_store_allocate(sss_mbedtls_key_store_t *keyStore, uint32_t keyStoreId)
{
    sss_status_t retval = kStatus_SSS_Fail;
    ENSURE_OR_GO_CLEANUP(NULL != keyStore);
    ENSURE_OR_GO_CLEANUP(NULL != keyStore->session);

#if defined(MBEDTLS_FS_IO) && ((defined(SSS_HAVE_HOST_PCWINDOWS) && (SSS_HAVE_HOST_PCWINDOWS)) ||    \
                                  (defined(SSS_HAVE_HOST_PCLINUX64) && (SSS_HAVE_HOST_PCLINUX64)) || \
                                  (defined(SSS_HAVE_HOST_RASPBIAN) && (SSS_HAVE_HOST_RASPBIAN)))
    /* This function is called once per session so keystore
    object and shadow objects Should be equal to Null */
    ENSURE_OR_GO_CLEANUP(keyStore->objects == NULL);
    ENSURE_OR_GO_CLEANUP(keyStore->keystore_shadow == NULL);

    keyStore->max_object_count = MAX_KEY_OBJ_COUNT;
    keyStore->objects = (sss_mbedtls_object_t **)SSS_MALLOC(MAX_KEY_OBJ_COUNT * sizeof(sss_mbedtls_object_t *));
    ENSURE_OR_GO_CLEANUP(keyStore->objects != NULL);
    memset(keyStore->objects, 0, (MAX_KEY_OBJ_COUNT * sizeof(sss_mbedtls_object_t *)));
    ks_sw_fat_allocate(&keyStore->keystore_shadow);
    if (NULL != keyStore->session->szRootPath) {
        retval = ks_sw_fat_load(keyStore->session->szRootPath, keyStore->keystore_shadow);
    }
    else {
        /*No keystore shadow to be loaded*/
    }
    retval = kStatus_SSS_Success;

#else
    retval = kStatus_SSS_Success;
#endif
cleanup:
    return retval;
}

sss_status_t sss_mbedtls_key_store_set_key(sss_mbedtls_key_store_t *keyStore,
    sss_mbedtls_object_t *keyObject,
    const uint8_t *data,
    size_t dataLen,
    size_t keyBitLen,
    void *options,
    size_t optionsLen)
{
    sss_status_t retval = kStatus_SSS_Fail;
    ENSURE_OR_GO_CLEANUP(NULL != keyObject);
    ENSURE_OR_GO_CLEANUP(NULL != keyObject->contents);

    ENSURE_OR_GO_CLEANUP((keyObject->accessRights & kAccessPermission_SSS_Write));
    retval = sss_mbedtls_set_key(keyObject, data, dataLen, keyBitLen);
cleanup:
    return retval;
}

sss_status_t sss_mbedtls_key_store_generate_key(
    sss_mbedtls_key_store_t *keyStore, sss_mbedtls_object_t *keyObject, size_t keyBitLen, void *options)
{
    sss_status_t retval       = kStatus_SSS_Fail;
    sss_mbedtls_session_t *pS = NULL;
    mbedtls_pk_context *pkey  = NULL;
    ENSURE_OR_GO_CLEANUP(NULL != keyStore);
    ENSURE_OR_GO_CLEANUP(NULL != keyObject);
    ENSURE_OR_GO_CLEANUP(NULL != keyObject->contents); /* Must be allocated in allocate handle */

    pS = keyStore->session;

    pkey = (mbedtls_pk_context *)keyObject->contents;
    if (keyObject->objectType != kSSS_KeyPart_Pair) {
        goto cleanup;
    }

    mbedtls_pk_init(pkey);
    switch (keyObject->cipherType) {
    case kSSS_CipherType_EC_NIST_P:
    case kSSS_CipherType_EC_BRAINPOOL:
        retval = sss_mbedtls_generate_ecp_key(pkey, pS, keyBitLen, (sss_cipher_type_t)(keyObject->cipherType));
        break;
    default:
        break;
    }
cleanup:
    return retval;
}

sss_status_t sss_mbedtls_key_store_get_key(sss_mbedtls_key_store_t *keyStore,
    sss_mbedtls_object_t *keyObject,
    uint8_t *data,
    size_t *dataLen,
    size_t *pKeyBitLen)
{
    sss_status_t retval    = kStatus_SSS_Fail;
    mbedtls_pk_context *pk = NULL;
    int ret                = -1;
    uint8_t output[1600]   = {0};
    unsigned char *c       = output;

    ENSURE_OR_GO_CLEANUP(NULL != keyObject);
    ENSURE_OR_GO_CLEANUP(0 != (keyObject->accessRights & kAccessPermission_SSS_Read));
    ENSURE_OR_GO_CLEANUP(NULL != data);
    ENSURE_OR_GO_CLEANUP(0 != dataLen);

    switch (keyObject->objectType) {
    case kSSS_KeyPart_Default:
        ENSURE_OR_GO_CLEANUP(*dataLen >= keyObject->contents_size);
        memcpy(data, keyObject->contents, keyObject->contents_size);
        *dataLen = keyObject->contents_size;
        if (pKeyBitLen != NULL) {
            *pKeyBitLen = keyObject->contents_size * 8;
        }
        retval = kStatus_SSS_Success;
        break;
    case kSSS_KeyPart_Public:
    case kSSS_KeyPart_Pair:
        pk = (mbedtls_pk_context *)keyObject->contents;
        {
            ret = mbedtls_pk_write_pubkey_der(pk, output, sizeof(output));
            if (ret > 0) {
                if ((*dataLen) >= (size_t)ret) {
                    if (pKeyBitLen != NULL) {
                        *pKeyBitLen = mbedtls_pk_get_bitlen(pk);
                    }
                    *dataLen = ret;
                    /* Data is put at end, so copy it to front of output buffer */
                    c = output + sizeof(output) - ret;
                    memcpy(data, c, ret);
                    retval = kStatus_SSS_Success;
                }
            }
        }
        break;
    default:
        break;
    }
cleanup:
    return retval;
}

sss_status_t sss_mbedtls_key_store_erase_key(sss_mbedtls_key_store_t *keyStore, sss_mbedtls_object_t *keyObject)
{
    sss_status_t retval = kStatus_SSS_Fail;
    ENSURE_OR_GO_EXIT(NULL != keyStore);
    ENSURE_OR_GO_EXIT(NULL != keyObject);
    ENSURE_OR_GO_EXIT(NULL != keyObject->keyStore);

    ENSURE_OR_GO_EXIT((keyObject->accessRights & kAccessPermission_SSS_Delete));

    if (keyObject->keyMode == kKeyObject_Mode_Persistent) {
#if defined(MBEDTLS_FS_IO) && ((defined(SSS_HAVE_HOST_PCWINDOWS) && (SSS_HAVE_HOST_PCWINDOWS)) ||    \
                                  (defined(SSS_HAVE_HOST_PCLINUX64) && (SSS_HAVE_HOST_PCLINUX64)) || \
                                  (defined(SSS_HAVE_HOST_RASPBIAN) && (SSS_HAVE_HOST_RASPBIAN)))
        unsigned int i = 0;
        /* first check if key exists delete key from shadow KS*/
        retval = ks_common_remove_fat(keyObject->keyStore->keystore_shadow, keyObject->keyId);
        ENSURE_OR_GO_CLEANUP(retval == kStatus_SSS_Success);

        /* Update shadow keystore in file system*/
        retval = ks_mbedtls_fat_update(keyObject->keyStore);
        ENSURE_OR_GO_CLEANUP(retval == kStatus_SSS_Success);

        /*Clear key object from file*/
        retval = ks_mbedtls_remove_key(keyObject);

        for (i = 0; i < keyObject->keyStore->max_object_count; i++) {
            if (keyObject->keyStore->objects[i] == keyObject) {
                keyObject->keyStore->objects[i] = NULL;
                break;
            }
        }
#endif
    }
    else {
        retval = kStatus_SSS_Success;
    }

#if defined(MBEDTLS_FS_IO) && ((defined(SSS_HAVE_HOST_PCWINDOWS) && (SSS_HAVE_HOST_PCWINDOWS)) ||    \
                                  (defined(SSS_HAVE_HOST_PCLINUX64) && (SSS_HAVE_HOST_PCLINUX64)) || \
                                  (defined(SSS_HAVE_HOST_RASPBIAN) && (SSS_HAVE_HOST_RASPBIAN)))
cleanup:
#endif
exit:
    return retval;
}

void sss_mbedtls_key_store_context_free(sss_mbedtls_key_store_t *keyStore)
{
#if defined(MBEDTLS_FS_IO) && ((defined(SSS_HAVE_HOST_PCWINDOWS) && (SSS_HAVE_HOST_PCWINDOWS)) ||    \
                                  (defined(SSS_HAVE_HOST_PCLINUX64) && (SSS_HAVE_HOST_PCLINUX64)) || \
                                  (defined(SSS_HAVE_HOST_RASPBIAN) && (SSS_HAVE_HOST_RASPBIAN)))
    if (NULL != keyStore->objects) {
        uint32_t i;
        for (i = 0; i < keyStore->max_object_count; i++) {
            if (keyStore->objects[i] != NULL) {
                keyStore->objects[i] = NULL;
            }
        }
        SSS_FREE(keyStore->objects);
        keyStore->objects = NULL;
    }
    if (NULL != keyStore->keystore_shadow) {
        ks_sw_fat_free(keyStore->keystore_shadow);
    }
#endif
    memset(keyStore, 0, sizeof(*keyStore));
}

/* End: mbedtls_keystore */

/* ************************************************************************** */
/* Functions : sss_mbedtls_asym                                               */
/* ************************************************************************** */

sss_status_t sss_mbedtls_asymmetric_context_init(sss_mbedtls_asymmetric_t *context,
    sss_mbedtls_session_t *session,
    sss_mbedtls_object_t *keyObject,
    sss_algorithm_t algorithm,
    sss_mode_t mode)
{
    sss_status_t retval = kStatus_SSS_Fail;
    ENSURE_OR_GO_CLEANUP(NULL != context);
    ENSURE_OR_GO_CLEANUP(NULL != keyObject);
    ENSURE_OR_GO_CLEANUP(NULL != keyObject->keyStore);
    ENSURE_OR_GO_CLEANUP(NULL != keyObject->keyStore->session);
    ENSURE_OR_GO_CLEANUP(keyObject->keyStore->session->subsystem == kType_SSS_mbedTLS);

    context->session   = session;
    context->keyObject = keyObject;
    context->algorithm = algorithm;
    context->mode      = mode;
    retval             = kStatus_SSS_Success;
cleanup:
    return retval;
}

static mbedtls_md_type_t sss_mbedtls_set_padding_get_hash(sss_algorithm_t algorithm)
{
    mbedtls_md_type_t md_alg = MBEDTLS_MD_NONE;
    switch (algorithm) {
    case kAlgorithm_SSS_ECDSA_SHA256:
    case kAlgorithm_SSS_SHA256: {
        md_alg = MBEDTLS_MD_SHA256;
    } break;
    default:
        md_alg = MBEDTLS_MD_NONE;
        break;
    }
    return md_alg;
}

sss_status_t sss_mbedtls_asymmetric_sign_digest(
    sss_mbedtls_asymmetric_t *context, uint8_t *digest, size_t digestLen, uint8_t *signature, size_t *signatureLen)
{
    sss_status_t retval       = kStatus_SSS_Fail;
    int ret                   = 1;
    mbedtls_md_type_t md_alg  = MBEDTLS_MD_NONE;
    sss_mbedtls_session_t *pS = NULL;
    mbedtls_pk_context *pKey  = NULL;

    ENSURE_OR_GO_EXIT(NULL != context)
    ENSURE_OR_GO_EXIT(NULL != context->keyObject)
    ENSURE_OR_GO_EXIT(0 != (context->keyObject->accessRights & kAccessPermission_SSS_Use));

    pS   = context->session;
    pKey = (mbedtls_pk_context *)context->keyObject->contents;

    md_alg = sss_mbedtls_set_padding_get_hash(context->algorithm);

#if SSS_HAVE_MBEDTLS_3_X
    ret = mbedtls_pk_sign(
        pKey, md_alg, digest, digestLen, signature, *signatureLen, signatureLen, mbedtls_ctr_drbg_random, pS->ctr_drbg);
#else
    ret = mbedtls_pk_sign(
        pKey, md_alg, digest, digestLen, signature, signatureLen, mbedtls_ctr_drbg_random, pS->ctr_drbg);
#endif
    ENSURE_OR_GO_EXIT(ret == 0);

    retval = kStatus_SSS_Success;
exit:
    return retval;
}

sss_status_t sss_mbedtls_asymmetric_verify_digest(
    sss_mbedtls_asymmetric_t *context, uint8_t *digest, size_t digestLen, uint8_t *signature, size_t signatureLen)
{
    sss_status_t retval      = kStatus_SSS_Fail;
    int ret                  = 1;
    mbedtls_md_type_t md_alg = MBEDTLS_MD_NONE;
    mbedtls_pk_context *pKey = NULL;

    ENSURE_OR_GO_EXIT(NULL != context)
    ENSURE_OR_GO_EXIT(NULL != context->keyObject)
    ENSURE_OR_GO_EXIT(0 != (context->keyObject->accessRights & kAccessPermission_SSS_Use));

    pKey = (mbedtls_pk_context *)context->keyObject->contents;

    md_alg = sss_mbedtls_set_padding_get_hash(context->algorithm);

    ret = mbedtls_pk_verify(pKey, md_alg, digest, digestLen, signature, signatureLen);

    ENSURE_OR_GO_EXIT(ret == 0);

    retval = kStatus_SSS_Success;
exit:
    return retval;
}

sss_status_t sss_mbedtls_asymmetric_sign_one_go(
    sss_mbedtls_asymmetric_t *context, uint8_t *srcData, size_t srcLen, uint8_t *signature, size_t *signatureLen)
{
    sss_status_t retval       = kStatus_SSS_Fail;
    int ret                   = 1;
    mbedtls_md_type_t md_alg  = MBEDTLS_MD_NONE;
    sss_mbedtls_session_t *pS = NULL;
    mbedtls_pk_context *pKey  = NULL;
    size_t srcLenTemp         = srcLen;
    size_t templen            = 0;
    size_t offset             = 0;
    sss_status_t status;
    sss_mbedtls_digest_t digestCtx = {0};
    uint8_t digest[64 /* SHA512*/] = {0};
    size_t digestLen               = sizeof(digest);
    sss_algorithm_t algorithm      = kAlgorithm_SSS_SHA256;

    ENSURE_OR_GO_EXIT(NULL != context)
    ENSURE_OR_GO_EXIT(NULL != context->keyObject)
    ENSURE_OR_GO_EXIT(0 != (context->keyObject->accessRights & kAccessPermission_SSS_Use));
    ENSURE_OR_GO_EXIT(srcData != NULL);
    ENSURE_OR_GO_EXIT(signature != NULL);
    ENSURE_OR_GO_EXIT(signatureLen != NULL);
    ENSURE_OR_GO_EXIT(srcLen > 0);

    pS   = context->session;
    pKey = (mbedtls_pk_context *)context->keyObject->contents;

    md_alg = sss_mbedtls_set_padding_get_hash(context->algorithm);

    { /* Calculate hash */

        switch (context->algorithm) {
        case kAlgorithm_SSS_ECDSA_SHA256: {
            algorithm = kAlgorithm_SSS_SHA256;
        } break;
        default:
            algorithm = kAlgorithm_SSS_SHA256;
            break;
        }

        status = sss_mbedtls_digest_context_init(&digestCtx, context->session, algorithm, kMode_SSS_Digest);
        ENSURE_OR_GO_EXIT(kStatus_SSS_Success == status);

        status = sss_mbedtls_digest_init(&digestCtx);
        ENSURE_OR_GO_EXIT(kStatus_SSS_Success == status);

        while (srcLenTemp > 0) {
            templen = (srcLenTemp > 512) ? 512 : srcLenTemp;

            status = sss_mbedtls_digest_update(&digestCtx, srcData + offset, templen);
            ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

            srcLenTemp = srcLenTemp - templen;
            ENSURE_OR_GO_EXIT((UINT_MAX - offset) >= templen);
            offset = offset + templen;
        }

        status = sss_mbedtls_digest_finish(&digestCtx, &digest[0], &digestLen);
        ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);
    }

#if SSS_HAVE_MBEDTLS_3_X
    ret = mbedtls_pk_sign(
        pKey, md_alg, digest, digestLen, signature, *signatureLen, signatureLen, mbedtls_ctr_drbg_random, pS->ctr_drbg);
#else
    ret = mbedtls_pk_sign(
        pKey, md_alg, digest, digestLen, signature, signatureLen, mbedtls_ctr_drbg_random, pS->ctr_drbg);
#endif
    ENSURE_OR_GO_EXIT(ret == 0);

    retval = kStatus_SSS_Success;
exit:
    if (digestCtx.session != NULL) {
        sss_mbedtls_digest_context_free(&digestCtx);
    }
    return retval;
}

sss_status_t sss_mbedtls_asymmetric_sign_init(sss_mbedtls_asymmetric_t *context, uint8_t *srcData, size_t srcLen)
{
    sss_status_t retval       = kStatus_SSS_Fail;
    sss_algorithm_t algorithm = kAlgorithm_SSS_SHA256;

    ENSURE_OR_GO_EXIT(NULL != context);

    switch (context->algorithm) {
    case kAlgorithm_SSS_ECDSA_SHA256: {
        algorithm = kAlgorithm_SSS_SHA256;
    } break;
    default:
        algorithm = kAlgorithm_SSS_SHA256;
        break;
    }

    retval = sss_mbedtls_digest_context_init(&context->digestCtx, context->session, algorithm, kMode_SSS_Digest);
    ENSURE_OR_GO_EXIT(kStatus_SSS_Success == retval);

    retval = sss_mbedtls_digest_init(&context->digestCtx);
    ENSURE_OR_GO_EXIT(kStatus_SSS_Success == retval);

    if ((NULL != srcData) && (srcLen > 0)) {
        retval = sss_mbedtls_digest_update(&context->digestCtx, srcData, srcLen);
        ENSURE_OR_GO_EXIT(kStatus_SSS_Success == retval);
    }

exit:
    if (retval != kStatus_SSS_Success) {
        if (context != NULL) {
            if (context->digestCtx.session != NULL) {
                sss_mbedtls_digest_context_free(&context->digestCtx);
            }
        }
    }
    return retval;
}

sss_status_t sss_mbedtls_asymmetric_sign_update(sss_mbedtls_asymmetric_t *context, uint8_t *srcData, size_t srcLen)
{
    sss_status_t retval = kStatus_SSS_Fail;

    ENSURE_OR_GO_EXIT(NULL != context);
    ENSURE_OR_GO_EXIT(srcData != NULL);
    ENSURE_OR_GO_EXIT(srcLen > 0);

    retval = sss_mbedtls_digest_update(&context->digestCtx, srcData, srcLen);

exit:
    if (retval != kStatus_SSS_Success) {
        if (context != NULL) {
            if (context->digestCtx.session != NULL) {
                sss_mbedtls_digest_context_free(&context->digestCtx);
            }
        }
    }
    return retval;
}

sss_status_t sss_mbedtls_asymmetric_sign_finish(
    sss_mbedtls_asymmetric_t *context, uint8_t *srcData, size_t srcLen, uint8_t *signature, size_t *signatureLen)
{
    sss_status_t retval                = kStatus_SSS_Fail;
    uint8_t digest[64 /* MAX-SHA512*/] = {0};
    size_t digestLen                   = sizeof(digest);

    ENSURE_OR_GO_EXIT(NULL != context);
    ENSURE_OR_GO_EXIT(signature != NULL);
    ENSURE_OR_GO_EXIT(signatureLen != NULL);

    if ((NULL != srcData) && (srcLen > 0)) {
        retval = sss_mbedtls_digest_update(&context->digestCtx, srcData, srcLen);
        ENSURE_OR_GO_EXIT(kStatus_SSS_Success == retval);
    }

    retval = sss_mbedtls_digest_finish(&context->digestCtx, &digest[0], &digestLen);
    ENSURE_OR_GO_EXIT(retval == kStatus_SSS_Success);

    retval = sss_mbedtls_asymmetric_sign_digest(context, digest, digestLen, signature, signatureLen);

exit:
    if (context != NULL) {
        if (context->digestCtx.session != NULL) {
            sss_mbedtls_digest_context_free(&context->digestCtx);
        }
    }
    return retval;
}

sss_status_t sss_mbedtls_asymmetric_verify_one_go(
    sss_mbedtls_asymmetric_t *context, uint8_t *srcData, size_t srcLen, uint8_t *signature, size_t signatureLen)
{
    sss_status_t retval      = kStatus_SSS_Fail;
    int ret                  = 1;
    mbedtls_md_type_t md_alg = MBEDTLS_MD_NONE;
    mbedtls_pk_context *pKey;
    size_t srcLenTemp = srcLen;
    size_t templen    = 0;
    size_t offset     = 0;
    sss_status_t status;
    sss_mbedtls_digest_t digestCtx = {0};
    uint8_t digest[64 /* SHA512*/] = {0};
    size_t digestLen               = sizeof(digest);
    sss_algorithm_t algorithm      = kAlgorithm_SSS_SHA256;

    ENSURE_OR_GO_EXIT(context != NULL);
    ENSURE_OR_GO_EXIT(context->keyObject != NULL);
    ENSURE_OR_GO_EXIT((context->keyObject->accessRights & kAccessPermission_SSS_Use));
    ENSURE_OR_GO_EXIT(srcData != NULL);
    ENSURE_OR_GO_EXIT(signature != NULL);
    ENSURE_OR_GO_EXIT(srcLen > 0);

    pKey   = (mbedtls_pk_context *)context->keyObject->contents;
    md_alg = sss_mbedtls_set_padding_get_hash(context->algorithm);

    { /* Calculate hash */

        switch (context->algorithm) {
        case kAlgorithm_SSS_ECDSA_SHA256: {
            algorithm = kAlgorithm_SSS_SHA256;
        } break;
        default:
            algorithm = kAlgorithm_SSS_SHA256;
            break;
        }

        status = sss_mbedtls_digest_context_init(&digestCtx, context->session, algorithm, kMode_SSS_Digest);
        ENSURE_OR_GO_EXIT(kStatus_SSS_Success == status);

        status = sss_mbedtls_digest_init(&digestCtx);
        ENSURE_OR_GO_EXIT(kStatus_SSS_Success == status);

        while (srcLenTemp > 0) {
            templen = (srcLenTemp > 512) ? 512 : srcLenTemp;

            status = sss_mbedtls_digest_update(&digestCtx, srcData + offset, templen);
            ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

            srcLenTemp = srcLenTemp - templen;
            ENSURE_OR_GO_EXIT((UINT_MAX - offset) >= templen);
            offset = offset + templen;
        }

        status = sss_mbedtls_digest_finish(&digestCtx, &digest[0], &digestLen);
        ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);
    }

    ret = mbedtls_pk_verify(pKey, md_alg, digest, digestLen, signature, signatureLen);
    ENSURE_OR_GO_EXIT(ret == 0);

    retval = kStatus_SSS_Success;
exit:
    if (digestCtx.session != NULL) {
        sss_mbedtls_digest_context_free(&digestCtx);
    }
    return retval;
}

sss_status_t sss_mbedtls_asymmetric_verify_init(sss_mbedtls_asymmetric_t *context, uint8_t *srcData, size_t srcLen)
{
    sss_status_t retval       = kStatus_SSS_Fail;
    sss_algorithm_t algorithm = kAlgorithm_SSS_SHA256;

    ENSURE_OR_GO_EXIT(NULL != context);

    switch (context->algorithm) {
    case kAlgorithm_SSS_ECDSA_SHA256: {
        algorithm = kAlgorithm_SSS_SHA256;
    } break;
    default:
        algorithm = kAlgorithm_SSS_SHA256;
        break;
    }

    retval = sss_mbedtls_digest_context_init(&context->digestCtx, context->session, algorithm, kMode_SSS_Digest);
    ENSURE_OR_GO_EXIT(kStatus_SSS_Success == retval);

    retval = sss_mbedtls_digest_init(&context->digestCtx);
    ENSURE_OR_GO_EXIT(kStatus_SSS_Success == retval);

    if ((NULL != srcData) && (srcLen > 0)) {
        retval = sss_mbedtls_digest_update(&context->digestCtx, srcData, srcLen);
        ENSURE_OR_GO_EXIT(kStatus_SSS_Success == retval);
    }

exit:
    if (retval != kStatus_SSS_Success) {
        if (context != NULL) {
            if (context->digestCtx.session != NULL) {
                sss_mbedtls_digest_context_free(&context->digestCtx);
            }
        }
    }
    return retval;
}

sss_status_t sss_mbedtls_asymmetric_verify_update(sss_mbedtls_asymmetric_t *context, uint8_t *srcData, size_t srcLen)
{
    sss_status_t retval = kStatus_SSS_Fail;

    ENSURE_OR_GO_EXIT(NULL != context);
    ENSURE_OR_GO_EXIT(srcData != NULL);
    ENSURE_OR_GO_EXIT(srcLen > 0);

    retval = sss_mbedtls_digest_update(&context->digestCtx, srcData, srcLen);

exit:
    if (retval != kStatus_SSS_Success) {
        if (context != NULL) {
            if (context->digestCtx.session != NULL) {
                sss_mbedtls_digest_context_free(&context->digestCtx);
            }
        }
    }
    return retval;
}

sss_status_t sss_mbedtls_asymmetric_verify_finish(
    sss_mbedtls_asymmetric_t *context, uint8_t *srcData, size_t srcLen, uint8_t *signature, size_t signatureLen)
{
    sss_status_t retval            = kStatus_SSS_Fail;
    uint8_t digest[64 /* SHA512*/] = {0};
    size_t digestLen               = sizeof(digest);

    ENSURE_OR_GO_EXIT(NULL != context);
    ENSURE_OR_GO_EXIT(signature != NULL);

    if ((NULL != srcData) && (srcLen > 0)) {
        retval = sss_mbedtls_digest_update(&context->digestCtx, srcData, srcLen);
        ENSURE_OR_GO_EXIT(kStatus_SSS_Success == retval);
    }

    retval = sss_mbedtls_digest_finish(&context->digestCtx, &digest[0], &digestLen);
    ENSURE_OR_GO_EXIT(retval == kStatus_SSS_Success);

    retval = sss_mbedtls_asymmetric_verify_digest(context, digest, digestLen, signature, signatureLen);
    ENSURE_OR_GO_EXIT(retval == kStatus_SSS_Success);

exit:
    if (context != NULL) {
        if (context->digestCtx.session != NULL) {
            sss_mbedtls_digest_context_free(&context->digestCtx);
        }
    }
    return retval;
}

void sss_mbedtls_asymmetric_context_free(sss_mbedtls_asymmetric_t *context)
{
    if (NULL == context) {
        LOG_E("No context to free!");
    }
    else {
        memset(context, 0, sizeof(*context));
    }
}

/* End: mbedtls_asym */

/* ************************************************************************** */
/* Functions : sss_mbedtls_symm                                               */
/* ************************************************************************** */

sss_status_t sss_mbedtls_symmetric_context_init(sss_mbedtls_symmetric_t *context,
    sss_mbedtls_session_t *session,
    sss_mbedtls_object_t *keyObject,
    sss_algorithm_t algorithm,
    sss_mode_t mode)
{
    sss_status_t retval = kStatus_SSS_Fail;

    ENSURE_OR_GO_EXIT(NULL != context)
    context->session   = session;
    context->keyObject = keyObject;
    context->algorithm = algorithm;
    context->mode      = mode;
    retval             = kStatus_SSS_Success;
exit:
    return retval;
}

sss_status_t sss_mbedtls_cipher_one_go(sss_mbedtls_symmetric_t *context,
    uint8_t *iv,
    size_t ivLen,
    const uint8_t *srcData,
    uint8_t *destData,
    size_t dataLen)
{
    sss_status_t retval         = kStatus_SSS_Fail;
    mbedtls_aes_context aes_ctx = {0};
    int mbedtls_ret             = 1; /* Fail by default */
    size_t i                    = 0;
    uint8_t iv_copy[16]         = {0};

    ENSURE_OR_GO_EXIT(NULL != context)

    /* Use the copy of IV, as it gets overwritten in the mbedtls_aes_crypt_* functions */
    if (context->algorithm == kAlgorithm_SSS_AES_CBC) {
        ENSURE_OR_GO_EXIT((NULL != iv) && (0 != ivLen));
        memcpy(iv_copy, iv, ivLen);
    }

    switch (context->algorithm) {
    case kAlgorithm_SSS_AES_ECB:
    case kAlgorithm_SSS_AES_CBC:
        mbedtls_aes_init(&aes_ctx);
        if (context->mode == kMode_SSS_Encrypt) {
            mbedtls_ret = mbedtls_aes_setkey_enc(
                &aes_ctx, context->keyObject->contents, (unsigned int)(context->keyObject->contents_size * 8));
        }
        else if (context->mode == kMode_SSS_Decrypt) {
            mbedtls_ret = mbedtls_aes_setkey_dec(
                &aes_ctx, context->keyObject->contents, (unsigned int)(context->keyObject->contents_size * 8));
        }
        else {
            LOG_E("Invalid mode for AES!");
            goto exit;
        }
        break;
    default:
        goto exit;
    }

    ENSURE_OR_GO_EXIT(mbedtls_ret == 0);

    mbedtls_ret = 1;
    if (context->mode == kMode_SSS_Encrypt) {
        switch (context->algorithm) {
        case kAlgorithm_SSS_AES_ECB:
            if (dataLen > NX_CIPHER_BLOCK_SIZE) {
                while (i < dataLen) {
                    mbedtls_ret = mbedtls_aes_crypt_ecb(&aes_ctx, MBEDTLS_AES_ENCRYPT, srcData + i, destData + i);
                    ENSURE_OR_GO_EXIT(i <= SIZE_MAX - NX_CIPHER_BLOCK_SIZE)
                    i += NX_CIPHER_BLOCK_SIZE;
                }
            }
            else {
                mbedtls_ret = mbedtls_aes_crypt_ecb(&aes_ctx, MBEDTLS_AES_ENCRYPT, srcData, destData);
            }
            break;
        case kAlgorithm_SSS_AES_CBC:
            mbedtls_ret = mbedtls_aes_crypt_cbc(&aes_ctx, MBEDTLS_AES_ENCRYPT, dataLen, iv_copy, srcData, destData);
            break;
        default:
            break;
        }
    }
    else if (context->mode == kMode_SSS_Decrypt) {
        switch (context->algorithm) {
        case kAlgorithm_SSS_AES_CBC:
            mbedtls_ret = mbedtls_aes_crypt_cbc(&aes_ctx, MBEDTLS_AES_DECRYPT, dataLen, iv_copy, srcData, destData);
            break;
        case kAlgorithm_SSS_AES_ECB:
            if (dataLen > NX_CIPHER_BLOCK_SIZE) {
                while (i < dataLen) {
                    mbedtls_ret = mbedtls_aes_crypt_ecb(&aes_ctx, MBEDTLS_AES_DECRYPT, srcData + i, destData + i);
                    ENSURE_OR_GO_EXIT(i <= SIZE_MAX - NX_CIPHER_BLOCK_SIZE)
                    i += NX_CIPHER_BLOCK_SIZE;
                }
            }
            else {
                mbedtls_ret = mbedtls_aes_crypt_ecb(&aes_ctx, MBEDTLS_AES_DECRYPT, srcData, destData);
            }
            break;
        default:
            break;
        }
    }
    else {
        goto exit;
    }

    ENSURE_OR_GO_EXIT(mbedtls_ret == 0);

    mbedtls_ret = 1;
    switch (context->algorithm) {
    case kAlgorithm_SSS_AES_ECB:
    case kAlgorithm_SSS_AES_CBC:
        mbedtls_aes_free(&aes_ctx);
        break;
    default:
        goto exit;
    }

    retval = kStatus_SSS_Success;
exit:
    return retval;
}

sss_status_t sss_mbedtls_cipher_init(sss_mbedtls_symmetric_t *context, uint8_t *iv, size_t ivLen)
{
    sss_status_t retval                      = kStatus_SSS_Fail;
    const mbedtls_cipher_info_t *cipher_info = NULL;
    mbedtls_cipher_type_t cipher_type        = MBEDTLS_CIPHER_NONE;

    ENSURE_OR_GO_EXIT(context != NULL);
    ENSURE_OR_GO_EXIT(context->keyObject != NULL);
    ENSURE_OR_GO_EXIT((context->keyObject->contents_size * 8) <= INT_MAX);

    context->cipher_ctx = (mbedtls_cipher_context_t *)SSS_MALLOC(sizeof(mbedtls_cipher_context_t));
    ENSURE_OR_GO_EXIT(context->cipher_ctx != NULL);

    if (context->algorithm == kAlgorithm_SSS_AES_ECB) {
        switch (context->keyObject->keyBitLen) {
        case 128:
            cipher_type = MBEDTLS_CIPHER_AES_128_ECB;
            break;
        case 256:
            cipher_type = MBEDTLS_CIPHER_AES_256_ECB;
            break;
        default:
            goto exit;
            break;
        }
    }
    else if (context->algorithm == kAlgorithm_SSS_AES_CBC) {
        switch (context->keyObject->keyBitLen) {
        case 128:
            cipher_type = MBEDTLS_CIPHER_AES_128_CBC;
            break;
        case 256:
            cipher_type = MBEDTLS_CIPHER_AES_256_CBC;
            break;
        default:
            goto exit;
            break;
        }
    }
    else {
        retval = kStatus_SSS_InvalidArgument;
        goto exit;
    }

    if (cipher_type != MBEDTLS_CIPHER_NONE) {
        cipher_info = mbedtls_cipher_info_from_type(cipher_type);
    }

    mbedtls_cipher_init(context->cipher_ctx);

    if (0 == mbedtls_cipher_setup(context->cipher_ctx, cipher_info)) {
        if (context->mode == kMode_SSS_Encrypt) {
            if (0 != mbedtls_cipher_setkey(context->cipher_ctx,
                         context->keyObject->contents,
                         (unsigned int)(context->keyObject->contents_size * 8),
                         MBEDTLS_ENCRYPT)) {
                goto exit;
            }
        }
        else if (context->mode == kMode_SSS_Decrypt) {
            if (0 != mbedtls_cipher_setkey(context->cipher_ctx,
                         context->keyObject->contents,
                         (unsigned int)(context->keyObject->contents_size * 8),
                         MBEDTLS_DECRYPT)) {
                goto exit;
            }
        }
        else {
            LOG_E("Invalid mode for AES!");
            retval = kStatus_SSS_InvalidArgument;
            goto exit;
        }

        if (0 != mbedtls_cipher_set_iv(context->cipher_ctx, iv, ivLen)) {
            goto exit;
        }
        if (0 != mbedtls_cipher_reset(context->cipher_ctx)) {
            goto exit;
        }
    }
    else {
        LOG_E("sss_mbedtls_cipher_init: mbedtls_cipher_setup failed!");
        goto exit;
    }
    retval = kStatus_SSS_Success;

exit:
    if (kStatus_SSS_Success != retval && NULL != context) {
        SSS_FREE(context->cipher_ctx);
    }
    return retval;
}

sss_status_t sss_mbedtls_cipher_update(
    sss_mbedtls_symmetric_t *context, const uint8_t *srcData, size_t srcLen, uint8_t *destData, size_t *destLen)
{
    sss_status_t retval                     = kStatus_SSS_Fail;
    uint8_t inputData[NX_CIPHER_BLOCK_SIZE] = {
        0,
    };
    size_t inputData_len   = 0;
    size_t src_offset      = 0;
    size_t output_offset   = 0;
    size_t outBuffSize     = 0;
    size_t blockoutLen     = 0;
    int retMbedtlsVal      = 1;
    size_t cipherBlockSize = NX_CIPHER_BLOCK_SIZE;

    ENSURE_OR_GO_EXIT(NULL != destLen);
    outBuffSize = *destLen;

    ENSURE_OR_GO_EXIT(NULL != context);
    ENSURE_OR_GO_EXIT(NULL != srcData);
    ENSURE_OR_GO_EXIT((SIZE_MAX - context->cache_data_len) >= srcLen);

    if ((context->cache_data_len + srcLen) < cipherBlockSize) {
        /* Insufficinet data to process . Cache the data */
        memcpy((context->cache_data + context->cache_data_len), srcData, srcLen);
        context->cache_data_len = context->cache_data_len + srcLen;
        *destLen                = 0;
        return kStatus_SSS_Success;
    }
    else {
        /* Concatenate the unprocessed and current input data*/
        memcpy(inputData, context->cache_data, context->cache_data_len);
        inputData_len = context->cache_data_len;
        memcpy((inputData + inputData_len), srcData, (cipherBlockSize - context->cache_data_len));
        inputData_len += (cipherBlockSize - context->cache_data_len);
        src_offset += (cipherBlockSize - context->cache_data_len);
        context->cache_data_len = 0;

        blockoutLen = outBuffSize;
        ENSURE_OR_GO_EXIT(blockoutLen >= inputData_len);
        retMbedtlsVal = mbedtls_cipher_update(
            context->cipher_ctx, inputData, inputData_len, (destData + output_offset), &blockoutLen);
        ENSURE_OR_GO_EXIT(retMbedtlsVal == 0);

        ENSURE_OR_GO_EXIT((outBuffSize >= blockoutLen));
        ENSURE_OR_GO_EXIT((SIZE_MAX - output_offset) >= blockoutLen);
        outBuffSize -= blockoutLen;
        output_offset += blockoutLen;

        ENSURE_OR_GO_EXIT(srcLen >= src_offset);
        while (srcLen - src_offset >= cipherBlockSize) {
            memcpy(inputData, (srcData + src_offset), cipherBlockSize);
            src_offset += cipherBlockSize;

            blockoutLen   = outBuffSize;
            inputData_len = cipherBlockSize;
            ENSURE_OR_GO_EXIT(blockoutLen >= inputData_len);
            retMbedtlsVal = mbedtls_cipher_update(
                context->cipher_ctx, inputData, inputData_len, (destData + output_offset), &blockoutLen);
            ENSURE_OR_GO_EXIT(retMbedtlsVal == 0);

            ENSURE_OR_GO_EXIT((outBuffSize >= blockoutLen));
            ENSURE_OR_GO_EXIT((SIZE_MAX - output_offset) >= blockoutLen);
            outBuffSize -= blockoutLen;
            output_offset += blockoutLen;
        }

        *destLen = output_offset;

        /* Copy unprocessed data to cache */
        if ((srcLen - src_offset) > 0) {
            memcpy(context->cache_data, (srcData + src_offset), (srcLen - src_offset));
            context->cache_data_len = (srcLen - src_offset);
        }
    }

    retval = kStatus_SSS_Success;
exit:
    if ((kStatus_SSS_Success != retval) && (NULL != destLen)) {
        *destLen = 0;
    }
    return retval;
}

sss_status_t sss_mbedtls_cipher_finish(
    sss_mbedtls_symmetric_t *context, const uint8_t *srcData, size_t srcLen, uint8_t *destData, size_t *destLen)
{
    sss_status_t retval                               = kStatus_SSS_Fail;
    uint8_t srcdata_updated[2 * NX_CIPHER_BLOCK_SIZE] = {
        0,
    };
    size_t srcdata_updated_len = 0;
    size_t outBuffSize         = 0;
    size_t blockoutLen         = 0;
    size_t output_offset       = 0;
    int retMbedtlsVal          = 1;
    uint8_t temp[16]           = {
        0,
    };
    size_t temp_len        = sizeof(temp);
    size_t cipherBlockSize = NX_CIPHER_BLOCK_SIZE;

    ENSURE_OR_GO_EXIT(NULL != destLen);
    outBuffSize = *destLen;

    ENSURE_OR_GO_EXIT(NULL != context);

    if (srcLen > cipherBlockSize) {
        LOG_E("srcLen cannot be greater than %d bytes. Call update function ", cipherBlockSize);
        *destLen = 0;
        goto exit;
    }

    if (context->cache_data_len != 0) {
        ENSURE_OR_GO_EXIT(context->cache_data_len <= sizeof(srcdata_updated));
        memcpy(srcdata_updated, context->cache_data, context->cache_data_len);
        srcdata_updated_len     = context->cache_data_len;
        context->cache_data_len = 0;
    }
    if (srcLen != 0) {
        ENSURE_OR_GO_EXIT(srcdata_updated_len <= (SIZE_MAX - srcLen));
        ENSURE_OR_GO_EXIT(srcLen + srcdata_updated_len <= sizeof(srcdata_updated));
        memcpy((srcdata_updated + srcdata_updated_len), srcData, srcLen);
        srcdata_updated_len += srcLen;
    }

    /* Align buffer to cipherBlockSize */
    if (srcdata_updated_len > 0 && (srcdata_updated_len % cipherBlockSize != 0)) {
        srcdata_updated_len = srcdata_updated_len + (cipherBlockSize - (srcdata_updated_len % cipherBlockSize));
    }

    if (*destLen < srcdata_updated_len) {
        LOG_E("Output buffer not sufficient");
        goto exit;
    }

    *destLen = 0;

    if (srcdata_updated_len > 0) {
        blockoutLen = outBuffSize;
        ENSURE_OR_GO_EXIT(blockoutLen >= cipherBlockSize);
        retMbedtlsVal = mbedtls_cipher_update(
            context->cipher_ctx, srcdata_updated, cipherBlockSize, (destData + output_offset), &blockoutLen);
        ENSURE_OR_GO_EXIT(retMbedtlsVal == 0);
        *destLen = blockoutLen;
        outBuffSize -= blockoutLen;
        output_offset += blockoutLen;
    }

    if (srcdata_updated_len > cipherBlockSize) {
        blockoutLen = outBuffSize;
        ENSURE_OR_GO_EXIT(blockoutLen >= cipherBlockSize);
        retMbedtlsVal = mbedtls_cipher_update(context->cipher_ctx,
            srcdata_updated + cipherBlockSize,
            cipherBlockSize,
            destData + output_offset,
            &blockoutLen);
        ENSURE_OR_GO_EXIT(retMbedtlsVal == 0);
        ENSURE_OR_GO_EXIT((SIZE_MAX - (*destLen)) >= blockoutLen);
        *destLen += blockoutLen;
        ENSURE_OR_GO_EXIT((outBuffSize >= blockoutLen));
        ENSURE_OR_GO_EXIT((SIZE_MAX - output_offset) >= blockoutLen);
        outBuffSize -= blockoutLen;
        output_offset += blockoutLen;
    }

    /*
    * For decrypt operation, on passing 16 bytes of buffer data to mbedtls_cipher_update, data is cached
    * and in next updated call it is processed.
    * So call another update api with zero dummy data
    *
    * NOTE- This workaround is required only for CBC mode.
    */
    if ((context->mode == kMode_SSS_Decrypt) && (context->algorithm == kAlgorithm_SSS_AES_CBC)) {
        blockoutLen = outBuffSize;
        mbedtls_cipher_update(context->cipher_ctx, temp, temp_len, destData + output_offset, &blockoutLen);
        ENSURE_OR_GO_EXIT((SIZE_MAX - (*destLen)) >= blockoutLen);
        *destLen += blockoutLen;
    }

    mbedtls_cipher_finish(context->cipher_ctx, temp, &temp_len);

    retval = kStatus_SSS_Success;
exit:
    return retval;
}

void sss_mbedtls_symmetric_context_free(sss_mbedtls_symmetric_t *context)
{
    if (NULL == context) {
        LOG_E("No context to free!");
    }
    else {
        if (NULL != context->cipher_ctx) {
            mbedtls_cipher_free(context->cipher_ctx);
            memset(context->cipher_ctx, 0, sizeof(*(context->cipher_ctx)));
            SSS_FREE(context->cipher_ctx);
        }
        memset(context, 0, sizeof(*context));
    }
}

/* End: mbedtls_symm */

/* ************************************************************************** */
/* Functions : sss_mbedtls_aead                                               */
/* ************************************************************************** */

sss_status_t sss_mbedtls_aead_context_init(sss_mbedtls_aead_t *context,
    sss_mbedtls_session_t *session,
    sss_mbedtls_object_t *keyObject,
    sss_algorithm_t algorithm,
    sss_mode_t mode)
{
    sss_status_t retval = kStatus_SSS_Fail;
    ENSURE_OR_GO_CLEANUP(NULL != context);
    ENSURE_OR_GO_CLEANUP(NULL != session);
    ENSURE_OR_GO_CLEANUP(NULL != keyObject);

    context->session   = session;
    context->keyObject = keyObject;
    context->algorithm = algorithm;
    context->mode      = mode;

    if (algorithm == kAlgorithm_SSS_AES_GCM) {
        context->gcm_ctx = (mbedtls_gcm_context *)SSS_MALLOC(sizeof(mbedtls_gcm_context));
        ENSURE_OR_GO_CLEANUP(context->gcm_ctx);
    }
    else if (algorithm == kAlgorithm_SSS_AES_CCM) {
        context->ccm_ctx = (mbedtls_ccm_context *)SSS_MALLOC(sizeof(mbedtls_ccm_context));
        ENSURE_OR_GO_CLEANUP(context->ccm_ctx);
    }
    else {
        LOG_E("Improper Algorithm passed!");
        goto cleanup;
    }
    context->pCcm_aad  = NULL;
    context->pCcm_data = NULL;
    context->pNonce    = NULL;
    retval             = kStatus_SSS_Success;
cleanup:
    if ((kStatus_SSS_Success != retval) && (context != NULL)) {
        if (context->gcm_ctx != NULL) {
            SSS_FREE(context->gcm_ctx);
        }
        if (context->ccm_ctx != NULL) {
            SSS_FREE(context->ccm_ctx);
        }
    }
    return retval;
}

sss_status_t sss_mbedtls_aead_one_go(sss_mbedtls_aead_t *context,
    const uint8_t *srcData,
    uint8_t *destData,
    size_t size,
    uint8_t *nonce,
    size_t nonceLen,
    const uint8_t *aad,
    size_t aadLen,
    uint8_t *tag,
    size_t *tagLen)
{
    sss_status_t retval = kStatus_SSS_Fail;

    ENSURE_OR_GO_CLEANUP(NULL != tagLen)
    size_t destLen = size;
    /* Call the multi-step SSS APIs to achieve one-go functionality. */

    /* Set the nonce, nonceLen, aadLen, size (srcData length) */
    retval = sss_mbedtls_aead_init(context, nonce, nonceLen, *tagLen, aadLen, size);
    ENSURE_OR_GO_CLEANUP(kStatus_SSS_Success == retval);

    /* Set the AAD data, if any */
    if ((NULL != aad) && (aadLen > 0)) {
        retval = sss_mbedtls_aead_update_aad(context, aad, aadLen);
        ENSURE_OR_GO_CLEANUP(kStatus_SSS_Success == retval);
    }

    /* Set the srcData */
    retval = sss_mbedtls_aead_update(context, srcData, size, destData, &destLen);
    ENSURE_OR_GO_CLEANUP(kStatus_SSS_Success == retval);

    /* Finish operation- here the srcData is passed as NULL,           */
    /* as we pass all the srcData in the sss_mbedtls_aead_update call. */
    retval = sss_mbedtls_aead_finish(context,
        NULL,
        0,
        destData + destLen, /* To process the leftover cached data */
        &destLen,
        tag,
        tagLen);
cleanup:
    return retval;
}

sss_status_t sss_mbedtls_aead_init(
    sss_mbedtls_aead_t *context, uint8_t *nonce, size_t nonceLen, size_t tagLen, size_t aadLen, size_t payloadLen)
{
    sss_status_t retval = kStatus_SSS_Fail;
    int ret             = 1;

    ENSURE_OR_GO_CLEANUP(NULL != context);
    ENSURE_OR_GO_CLEANUP(NULL != nonce);

    /* Save the nonce and its length in context */
    context->pNonce           = nonce;
    context->nonceLen         = nonceLen;
    context->ccm_aadLen       = aadLen;
    context->ccm_dataTotalLen = payloadLen;
    if (context->algorithm == kAlgorithm_SSS_AES_CCM) {
        if (0 != context->ccm_dataTotalLen) {
            context->pCcm_data = SSS_MALLOC(payloadLen);
            if (NULL != context->pCcm_data) {
                memset(context->pCcm_data, 0, payloadLen);
                context->ccm_dataoffset = 0;
            }
            else {
                LOG_E("malloc failed");
                goto cleanup;
            }
        }
    }
    context->cache_data_len = 0;
    memset(context->cache_data, 0x00, sizeof(context->cache_data));

    if (context->algorithm == kAlgorithm_SSS_AES_GCM) {
        /* Initialize gcm context */
        mbedtls_gcm_init(context->gcm_ctx);

        /* Set key to the context */
        ENSURE_OR_GO_CLEANUP(NULL != context->keyObject);
        ret = mbedtls_gcm_setkey(context->gcm_ctx,
            MBEDTLS_CIPHER_ID_AES,
            context->keyObject->contents,
            (unsigned int)(context->keyObject->contents_size * 8));
        ENSURE_OR_GO_CLEANUP(ret == 0);
    }
    else if (context->algorithm == kAlgorithm_SSS_AES_CCM) {
        /* Initialize ccm context */
        mbedtls_ccm_init(context->ccm_ctx);
        /* Set key to the context */
        ret = mbedtls_ccm_setkey(context->ccm_ctx,
            MBEDTLS_CIPHER_ID_AES,
            context->keyObject->contents,
            (unsigned int)(context->keyObject->contents_size * 8));
        ENSURE_OR_GO_CLEANUP(ret == 0);
    }
    else {
        LOG_E("Invalid algorithm for AEAD!");
        goto cleanup;
    }

    retval = kStatus_SSS_Success;

cleanup:
    return retval;
}

sss_status_t sss_mbedtls_aead_update_aad(sss_mbedtls_aead_t *context, const uint8_t *aadData, size_t aadDataLen)
{
    sss_status_t retval = kStatus_SSS_Fail;
    int ret             = 1;
    int mode            = 0;

    ENSURE_OR_GO_CLEANUP(NULL != context);

    if (context->mode == kMode_SSS_Encrypt) {
        mode = MBEDTLS_GCM_ENCRYPT;
    }
    else if (context->mode == kMode_SSS_Decrypt) {
        mode = MBEDTLS_GCM_DECRYPT;
    }
    else {
        LOG_E("Invalid mode for AEAD!");
        goto cleanup;
    }

    if (aadDataLen > 0) {
        ENSURE_OR_GO_CLEANUP(NULL != aadData);
    }
    if (context->algorithm == kAlgorithm_SSS_AES_GCM) {
/* Add aad Data */
#if SSS_HAVE_MBEDTLS_3_X
        ret = mbedtls_gcm_starts(context->gcm_ctx, mode, context->pNonce, context->nonceLen);
        ENSURE_OR_GO_CLEANUP(ret == 0);
        ret = mbedtls_gcm_update_ad(context->gcm_ctx, (unsigned char *)aadData, aadDataLen);
#else
        ret = mbedtls_gcm_starts(context->gcm_ctx, mode, context->pNonce, context->nonceLen, aadData, aadDataLen);
#endif
        ENSURE_OR_GO_CLEANUP(ret == 0);
    }
    else if (context->algorithm == kAlgorithm_SSS_AES_CCM) {
        context->pCcm_aad   = aadData;
        context->ccm_aadLen = aadDataLen;
    }
    else {
        LOG_E("Invalid algorithm for AEAD!");
        goto cleanup;
    }
    retval = kStatus_SSS_Success;

cleanup:
    return retval;
}

sss_status_t sss_mbedtls_aead_update(
    sss_mbedtls_aead_t *context, const uint8_t *srcData, size_t srcLen, uint8_t *destData, size_t *destLen)
{
    sss_status_t retval                     = kStatus_SSS_Fail;
    uint8_t inputData[NX_CIPHER_BLOCK_SIZE] = {
        0,
    };
    size_t inputData_len = 0;
    size_t src_offset    = 0;
    size_t output_offset = 0;
    size_t outBuffSize   = 0;
    size_t blockoutLen   = 0;
#if SSS_HAVE_MBEDTLS_3_X
    size_t outputLen = 0;
#endif
    int ret = 1;

    ENSURE_OR_GO_CLEANUP(NULL != destLen)
    outBuffSize = *destLen;

    ENSURE_OR_GO_CLEANUP(NULL != context)
    if (context->algorithm == kAlgorithm_SSS_AES_CCM) {
        if ((srcData != NULL) && (srcLen > 0)) {
            retval = sss_mbedtls_aead_ccm_update(context, srcData, srcLen);
            ENSURE_OR_GO_CLEANUP(retval == kStatus_SSS_Success);
        }
        *destLen = 0;
    }
    else if (context->algorithm == kAlgorithm_SSS_AES_GCM) {
        ENSURE_OR_GO_CLEANUP((SIZE_MAX - context->cache_data_len) >= srcLen);
        if ((context->cache_data_len + srcLen) < NX_CIPHER_BLOCK_SIZE) {
            /* Insufficinet data to process . Cache the data */
            memcpy((context->cache_data + context->cache_data_len), srcData, srcLen);
            context->cache_data_len = context->cache_data_len + srcLen;
            *destLen                = 0;
            return kStatus_SSS_Success;
        }
        else {
            /* Concatenate the unprocessed and current input data*/
            memcpy(inputData, context->cache_data, context->cache_data_len);
            inputData_len = context->cache_data_len;
            memcpy((inputData + inputData_len), srcData, (NX_CIPHER_BLOCK_SIZE - context->cache_data_len));
            ENSURE_OR_GO_CLEANUP(UINT_MAX >= (inputData_len + NX_CIPHER_BLOCK_SIZE - context->cache_data_len));
            inputData_len += (NX_CIPHER_BLOCK_SIZE - context->cache_data_len);
            src_offset += (NX_CIPHER_BLOCK_SIZE - context->cache_data_len);
            blockoutLen = outBuffSize;

/* Add Source Data */
#if SSS_HAVE_MBEDTLS_3_X
            outputLen = *destLen - output_offset;
            ret       = mbedtls_gcm_update(
                context->gcm_ctx, inputData, inputData_len, (destData + output_offset), outputLen, &outputLen);
#else
            ret = mbedtls_gcm_update(context->gcm_ctx, inputData_len, inputData, (destData + output_offset));
#endif
            ENSURE_OR_GO_CLEANUP(ret == 0);

            blockoutLen = inputData_len;
            ENSURE_OR_GO_CLEANUP(outBuffSize >= blockoutLen);
            outBuffSize -= blockoutLen;
            output_offset += blockoutLen;

            ENSURE_OR_GO_CLEANUP(srcLen >= src_offset);
            while (srcLen - src_offset >= NX_CIPHER_BLOCK_SIZE) {
                memcpy(inputData, (srcData + src_offset), NX_CIPHER_BLOCK_SIZE);
                src_offset += NX_CIPHER_BLOCK_SIZE;

                blockoutLen = outBuffSize;

/* Add Source Data */
#if SSS_HAVE_MBEDTLS_3_X
                ENSURE_OR_GO_CLEANUP(*destLen >= output_offset);
                outputLen = *destLen - output_offset;
                ret       = mbedtls_gcm_update(
                    context->gcm_ctx, inputData, inputData_len, (destData + output_offset), outputLen, &outputLen);
#else
                ret = mbedtls_gcm_update(context->gcm_ctx, inputData_len, inputData, (destData + output_offset));
#endif
                ENSURE_OR_GO_CLEANUP(ret == 0);
                blockoutLen = inputData_len;
                outBuffSize -= blockoutLen;
                output_offset += blockoutLen;
            }
            *destLen = output_offset;
            /* Copy unprocessed data to cache */
            memcpy(context->cache_data, (srcData + src_offset), (srcLen - src_offset));
            context->cache_data_len = (srcLen - src_offset);
        }
    }
    else {
        LOG_E("Invalid algorithm for AEAD!");
        goto cleanup;
    }
    retval = kStatus_SSS_Success;
cleanup:
    if ((kStatus_SSS_Success != retval) && (NULL != destLen)) {
        *destLen = 0;
    }
    return retval;
}

static sss_status_t sss_mbedtls_aead_ccm_update(sss_mbedtls_aead_t *context, const uint8_t *srcData, size_t srcLen)
{
    sss_status_t retval = kStatus_SSS_Fail;
    ENSURE_OR_GO_CLEANUP(NULL != context);
    ENSURE_OR_GO_CLEANUP((SIZE_MAX - context->ccm_dataoffset) >= srcLen);
    if ((context->ccm_dataoffset + srcLen) <= (context->ccm_dataTotalLen)) {
        memcpy(context->pCcm_data + context->ccm_dataoffset, srcData, srcLen);
        context->ccm_dataoffset = context->ccm_dataoffset + srcLen;
        retval                  = kStatus_SSS_Success;
    }
    else {
        /*Free the allocated memory in init*/
        if (context->pCcm_data != NULL) {
            SSS_FREE(context->pCcm_data);
            context->pCcm_data = NULL;
        }
    }
cleanup:
    return retval;
}

sss_status_t sss_mbedtls_aead_finish(sss_mbedtls_aead_t *context,
    const uint8_t *srcData,
    size_t srcLen,
    uint8_t *destData,
    size_t *destLen,
    uint8_t *tag,
    size_t *tagLen)
{
    sss_status_t retval                               = kStatus_SSS_Fail;
    size_t stagLen                                    = 0;
    int ret                                           = 1;
    uint8_t srcdata_updated[2 * NX_CIPHER_BLOCK_SIZE] = {
        0,
    };
    size_t srcdata_updated_len = 0;
    uint8_t *pTag              = NULL;
#if SSS_HAVE_MBEDTLS_3_X
    size_t totalDestLen = 0;
    size_t outDestLen   = 0;
#endif
    ENSURE_OR_GO_EXIT(NULL != context);
    if (srcLen > 0) {
        ENSURE_OR_GO_EXIT(NULL != srcData);
    }
    ENSURE_OR_GO_EXIT(NULL != destData);
    ENSURE_OR_GO_EXIT(NULL != tag);
    ENSURE_OR_GO_EXIT(NULL != tagLen);

    stagLen = *tagLen;

    if (context->algorithm == kAlgorithm_SSS_AES_CCM) { /* Check if finish has got source data */
        if ((srcData != NULL) && (srcLen > 0)) {
            retval = sss_mbedtls_aead_ccm_update(context, srcData, srcLen);
            ENSURE_OR_GO_EXIT(retval == kStatus_SSS_Success);
        }
        retval = sss_mbedtls_aead_ccm_finish(context, destData, destLen, tag, tagLen);
        ENSURE_OR_GO_EXIT(retval == kStatus_SSS_Success);
    }
    else if (context->algorithm == kAlgorithm_SSS_AES_GCM) {
        if (srcLen > NX_CIPHER_BLOCK_SIZE) {
            LOG_E("srcLen cannot be greater than 16 bytes. Call update function ");
            *destLen = 0;
            goto exit;
        }

        if (context->cache_data_len != 0) {
            memcpy(srcdata_updated, context->cache_data, context->cache_data_len);
            srcdata_updated_len = context->cache_data_len;
        }

        if (srcLen != 0) {
            memcpy((srcdata_updated + srcdata_updated_len), srcData, srcLen);
            ENSURE_OR_GO_EXIT((UINT_MAX - srcLen) >= srcdata_updated_len);
            srcdata_updated_len += srcLen;
        }

/* Add Source Data */
#if SSS_HAVE_MBEDTLS_3_X
        if (destLen != NULL) {
            totalDestLen = *destLen;
        }
        outDestLen = 0;
        ret        = mbedtls_gcm_update(
            context->gcm_ctx, srcdata_updated, srcdata_updated_len, destData, totalDestLen, &outDestLen);
        if (totalDestLen < outDestLen) {
            goto exit;
        }
        totalDestLen = totalDestLen - outDestLen;
        if (destLen != NULL) {
            *destLen = outDestLen;
        }
#else
        ret = mbedtls_gcm_update(context->gcm_ctx, srcdata_updated_len, srcdata_updated, destData);
        if (destLen != NULL) {
            *destLen = srcdata_updated_len;
        }
#endif
        ENSURE_OR_GO_EXIT(ret == 0);

        pTag = (uint8_t *)SSS_MALLOC(*tagLen);
        ENSURE_OR_GO_EXIT(NULL != pTag);
        memset(pTag, 0, *tagLen);

/* Get Tag for Enc*/
#if SSS_HAVE_MBEDTLS_3_X
        outDestLen = 0;
        ret        = mbedtls_gcm_finish(context->gcm_ctx, destData, totalDestLen, &outDestLen, pTag, stagLen);
        if (destLen != NULL) {
            ENSURE_OR_GO_EXIT(*destLen <= SIZE_MAX - outDestLen);
            *destLen += outDestLen;
        }
#else
        ret = mbedtls_gcm_finish(context->gcm_ctx, pTag, stagLen);
#endif
        ENSURE_OR_GO_EXIT(ret == 0);
        if (context->mode == kMode_SSS_Encrypt) {
            memcpy(tag, pTag, stagLen);
        }
        else if (context->mode == kMode_SSS_Decrypt) {
            if (0 != memcmp(pTag, tag, stagLen)) {
                goto exit;
            }
        }
        else {
            LOG_E("Invalid mode for AEAD!");
            goto exit;
        }

        *tagLen = stagLen;
    }
    else {
        LOG_E("Invalid algorithm for AEAD!");
        goto exit;
    }
    retval = kStatus_SSS_Success;

exit:
    if (pTag) {
        SSS_FREE(pTag);
    }
    return retval;
}

static sss_status_t sss_mbedtls_aead_ccm_finish(
    sss_mbedtls_aead_t *context, uint8_t *destData, size_t *destLen, uint8_t *tag, size_t *tagLen)
{
    sss_status_t retval = kStatus_SSS_Fail;
    size_t stagLen      = 0;
    int ret             = 1;

    ENSURE_OR_GO_EXIT(NULL != tagLen)
    ENSURE_OR_GO_EXIT(NULL != destLen)
    stagLen = *tagLen;
    /* Check the mode and perform requested operation */
    if (context->mode == kMode_SSS_Encrypt) {
        ret = mbedtls_ccm_encrypt_and_tag(context->ccm_ctx,
            context->ccm_dataTotalLen,
            context->pNonce,
            context->nonceLen,
            context->pCcm_aad,
            context->ccm_aadLen,
            context->pCcm_data,
            destData,
            tag,
            stagLen);
    }
    else if (context->mode == kMode_SSS_Decrypt) {
        ret = mbedtls_ccm_auth_decrypt(context->ccm_ctx,
            context->ccm_dataTotalLen,
            context->pNonce,
            context->nonceLen,
            context->pCcm_aad,
            context->ccm_aadLen,
            context->pCcm_data,
            destData,
            tag,
            stagLen);
    }
    else {
        LOG_E("Invalid mode for AEAD!");
        goto exit;
    }
    ENSURE_OR_GO_EXIT(ret == 0);
    *destLen = context->ccm_dataTotalLen;
    retval   = kStatus_SSS_Success;

exit:
    return retval;
}

void sss_mbedtls_aead_context_free(sss_mbedtls_aead_t *context)
{
    if (context != NULL) {
        if (context->algorithm == kAlgorithm_SSS_AES_GCM) {
            if (context->gcm_ctx != NULL) {
                mbedtls_gcm_free(context->gcm_ctx);
                SSS_FREE(context->gcm_ctx);
            }
        }
        else if (context->algorithm == kAlgorithm_SSS_AES_CCM) {
            if (context->ccm_ctx != NULL) {
                mbedtls_ccm_free(context->ccm_ctx);
                SSS_FREE(context->ccm_ctx);
                if (context->pCcm_data != NULL) {
                    SSS_FREE(context->pCcm_data);
                    context->pCcm_data = NULL;
                }
            }
        }
        else {
            LOG_E("Invalid algorithm for AEAD!");
        }
        if (context->pCcm_aad != NULL) {
            context->pCcm_aad = NULL;
        }
        if (context->pNonce != NULL) {
            context->pNonce = NULL;
        }
        memset(context, 0, sizeof(*context));
    }
}

/* End: mbedtls_aead */

/* ************************************************************************** */
/* Functions : sss_mbedtls_mac                                               */
/* ************************************************************************** */
sss_status_t sss_mbedtls_mac_context_init(sss_mbedtls_mac_t *context,
    sss_mbedtls_session_t *session,
    sss_mbedtls_object_t *keyObject,
    sss_algorithm_t algorithm,
    sss_mode_t mode)
{
    sss_status_t status = kStatus_SSS_Fail;
    ENSURE_OR_GO_CLEANUP(NULL != context);
    ENSURE_OR_GO_CLEANUP(NULL != session);
    ENSURE_OR_GO_CLEANUP(NULL != keyObject);

    context->session    = session;
    context->keyObject  = keyObject;
    context->algorithm  = algorithm;
    context->mode       = mode;
    context->cipher_ctx = NULL;

    if (algorithm == kAlgorithm_SSS_CMAC_AES) {
        context->cipher_ctx = (mbedtls_cipher_context_t *)SSS_CALLOC(1, sizeof(mbedtls_cipher_context_t));
        ENSURE_OR_GO_CLEANUP(context->cipher_ctx);
    }
    if (algorithm == kAlgorithm_SSS_HMAC_SHA256 || algorithm == kAlgorithm_SSS_HMAC_SHA384) {
        context->HmacCtx = (mbedtls_md_context_t *)SSS_CALLOC(1, sizeof(mbedtls_md_context_t));
        ENSURE_OR_GO_CLEANUP(context->HmacCtx);
    }
    else {
        /*No special context to be allocated for other algorithm*/
    }
    status = kStatus_SSS_Success;
cleanup:
    return status;
}

sss_status_t sss_mbedtls_mac_one_go(
    sss_mbedtls_mac_t *context, const uint8_t *message, size_t messageLen, uint8_t *mac, size_t *macLen)
{
    sss_status_t status                      = kStatus_SSS_Fail;
    int ret                                  = 1;
    const mbedtls_cipher_info_t *cipher_info = NULL;
    const mbedtls_md_info_t *md_info         = NULL;
    uint8_t *key                             = NULL;
    size_t keylen                            = 0;

    ENSURE_OR_GO_CLEANUP(NULL != context);
    ENSURE_OR_GO_CLEANUP(NULL != context->keyObject);
    ENSURE_OR_GO_CLEANUP(NULL != context->keyObject->contents);
    ENSURE_OR_GO_CLEANUP(NULL != macLen);
    key    = context->keyObject->contents;
    keylen = context->keyObject->contents_size;

    if (context->algorithm == kAlgorithm_SSS_CMAC_AES) {
        mbedtls_cipher_type_t cipher_type = MBEDTLS_CIPHER_NONE;

        switch (keylen * 8) {
        case 128:
            cipher_type = MBEDTLS_CIPHER_AES_128_ECB;
            break;
        case 256:
            cipher_type = MBEDTLS_CIPHER_AES_256_ECB;
            break;
        default:
            LOG_E("key bit not supported");
            goto cleanup;
        }

        cipher_info = mbedtls_cipher_info_from_type(cipher_type);
        if (cipher_info != NULL) {
            mbedtls_cipher_init(context->cipher_ctx);
            ret = mbedtls_cipher_setup(context->cipher_ctx, cipher_info);
            if (ret == 0) {
#ifdef MBEDTLS_CMAC_C
                ret = 1;
                ret = mbedtls_cipher_cmac_starts(context->cipher_ctx, key, (keylen * 8));
                if (ret == 0) {
                    ret = 1;
                    ret = mbedtls_cipher_cmac_update(context->cipher_ctx, message, messageLen);
                    if (ret == 0) {
                        if (context->mode == kMode_SSS_Mac) {
                            ret = 1;
                            ret = mbedtls_cipher_cmac_finish(context->cipher_ctx, mac);
                            if (ret == 0) {
#if SSS_HAVE_MBEDTLS_3_X
                                *macLen = context->cipher_ctx->private_cipher_info->private_block_size;
#else
                                *macLen = context->cipher_ctx->cipher_info->block_size;
#endif
                                status = kStatus_SSS_Success;
                            }
                        }
                        else if (context->mode == kMode_SSS_Mac_Validate) {
                            /* validate MAC*/
                            uint8_t macLocal[64] = {
                                0,
                            };
                            size_t macLocalLen = 0;
                            status             = kStatus_SSS_Fail;
                            ret                = 1;
                            ret                = mbedtls_cipher_cmac_finish(context->cipher_ctx, macLocal);
                            if (ret == 0) {
#if SSS_HAVE_MBEDTLS_3_X
                                macLocalLen = context->cipher_ctx->private_cipher_info->private_block_size;
#else
                                macLocalLen = context->cipher_ctx->cipher_info->block_size;
#endif
                                if (macLocalLen == *macLen) {
                                    if (0 == memcmp(macLocal, mac, macLocalLen)) {
                                        status = kStatus_SSS_Success;
                                    }
                                }
                            }
                        }
                        else {
                            LOG_E("Unknown mode");
                            status = kStatus_SSS_Fail;
                        }
                    }
                }
#endif
            }
        }
    }
    else if (context->algorithm == kAlgorithm_SSS_HMAC_SHA256 || context->algorithm == kAlgorithm_SSS_HMAC_SHA384) {
        /*For HMAC any Key length is supported*/
        switch (context->algorithm) {
        case kAlgorithm_SSS_HMAC_SHA256:
            md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
            break;
        case kAlgorithm_SSS_HMAC_SHA384:
            md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA384);
            break;
        default:
            LOG_E("Invalid HMAC algorithm");
            status = kStatus_SSS_Fail;
            goto cleanup;
        }

        if (md_info != NULL) {
            if (context->mode == kMode_SSS_Mac) {
                ret = mbedtls_md_hmac(md_info, key, keylen, message, messageLen, mac);
                if (ret == 0) {
                    *macLen = mbedtls_md_get_size(md_info);
                    status  = kStatus_SSS_Success;
                }
            }
            else if (context->mode == kMode_SSS_Mac_Validate) {
                /* validate MAC*/
                uint8_t macLocal[64] = {
                    0,
                };
                size_t macLocalLen = sizeof(macLocal);
                status             = kStatus_SSS_Fail;
                ret                = mbedtls_md_hmac(md_info, key, keylen, message, messageLen, macLocal);
                if (ret == 0) {
                    macLocalLen = mbedtls_md_get_size(md_info);
                    if (macLocalLen == *macLen) {
                        if (!memcmp(macLocal, mac, macLocalLen)) {
                            status = kStatus_SSS_Success;
                        }
                    }
                }
            }
            else {
                LOG_E("Unknown mode");
                status = kStatus_SSS_Fail;
            }
        }
    }
    else {
        LOG_E("Invalid algorithm type");
    }
cleanup:
    return status;
}

sss_status_t sss_mbedtls_mac_init(sss_mbedtls_mac_t *context)
{
    sss_status_t status               = kStatus_SSS_Fail;
    int ret                           = 1;
    uint8_t *key                      = NULL;
    size_t keylen                     = 0;
    mbedtls_cipher_type_t cipher_type = MBEDTLS_CIPHER_NONE;

    ENSURE_OR_GO_CLEANUP(NULL != context);
    ENSURE_OR_GO_CLEANUP(NULL != context->keyObject);
    ENSURE_OR_GO_CLEANUP(NULL != context->keyObject->contents);
    key    = context->keyObject->contents;
    keylen = context->keyObject->contents_size;

    if (context->algorithm == kAlgorithm_SSS_CMAC_AES) {
        const mbedtls_cipher_info_t *cipher_info = NULL;

        switch (context->keyObject->keyBitLen) {
        case 128:
            cipher_type = MBEDTLS_CIPHER_AES_128_ECB;
            break;
        case 256:
            cipher_type = MBEDTLS_CIPHER_AES_256_ECB;
            break;
        default:
            LOG_E("key bit not supported");
            goto cleanup;
        }

        if (cipher_type != MBEDTLS_CIPHER_NONE) {
            cipher_info = mbedtls_cipher_info_from_type(cipher_type);
        }

        if (cipher_info != NULL) {
            mbedtls_cipher_init(context->cipher_ctx);
            ret = 1;
            ret = mbedtls_cipher_setup(context->cipher_ctx, cipher_info);
            if (ret == 0) {
#ifdef MBEDTLS_CMAC_C
                ret = 1;
                ret = mbedtls_cipher_cmac_starts(context->cipher_ctx, key, (keylen * 8));
#endif
                if (ret == 0) {
                    status = kStatus_SSS_Success;
                }
            }
        }
    }
    else if (context->algorithm == kAlgorithm_SSS_HMAC_SHA256 || context->algorithm == kAlgorithm_SSS_HMAC_SHA384) {
        /* for HMAC any key length is supported */

        const mbedtls_md_info_t *md_info = NULL;
        mbedtls_md_context_t *hmac_ctx;
        hmac_ctx = context->HmacCtx;
        mbedtls_md_init(hmac_ctx);

        switch (context->algorithm) {
        case kAlgorithm_SSS_HMAC_SHA256:
            md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
            break;
        case kAlgorithm_SSS_HMAC_SHA384:
            md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA384);
            break;
        default:
            status = kStatus_SSS_Fail;
            goto cleanup;
        }

        if (md_info != NULL) {
            /* Below, third parameter '1' indicates that HMAC is to be setup*/
            ret = 1;
            ret = mbedtls_md_setup(hmac_ctx, md_info, 1);
            if (ret == 0) {
                ret = 1;
                ret = mbedtls_md_hmac_starts(hmac_ctx, key, (keylen));

                if (ret == 0) {
                    status = kStatus_SSS_Success;
                }
            }
        }
    }
    else {
        LOG_E("invalid algorithm mode for sss_mbedtls_mac_context_init ");
    }

cleanup:
    return status;
}

sss_status_t sss_mbedtls_mac_update(sss_mbedtls_mac_t *context, const uint8_t *message, size_t messageLen)
{
    int ret             = 1;
    sss_status_t status = kStatus_SSS_InvalidArgument;
    ENSURE_OR_GO_EXIT(message != NULL);
    ENSURE_OR_GO_EXIT(context != NULL);

    status = kStatus_SSS_Fail;
    LOG_AU8_D(message, messageLen);
    if (context->algorithm == kAlgorithm_SSS_CMAC_AES) {
#ifdef MBEDTLS_CMAC_C
        mbedtls_cipher_context_t *ctx;
        ctx = context->cipher_ctx;
        ret = mbedtls_cipher_cmac_update(ctx, message, messageLen);
#endif
        if (ret == 0) {
            status = kStatus_SSS_Success;
        }
    }
    else if (context->algorithm == kAlgorithm_SSS_HMAC_SHA256 || context->algorithm == kAlgorithm_SSS_HMAC_SHA384) {
        mbedtls_md_context_t *hmac_ctx;
        hmac_ctx = context->HmacCtx;
        ret      = mbedtls_md_hmac_update(hmac_ctx, message, messageLen);

        if (ret == 0) {
            status = kStatus_SSS_Success;
        }
    }
    else {
        LOG_E("invalid algorithm mode for sss_mbedtls_mac_update");
    }
exit:
    return status;
}

sss_status_t sss_mbedtls_mac_finish(sss_mbedtls_mac_t *context, uint8_t *mac, size_t *macLen)
{
    int ret             = 1;
    sss_status_t status = kStatus_SSS_Fail;

    ENSURE_OR_GO_EXIT(NULL != context);
    ENSURE_OR_GO_EXIT(NULL != mac);
    ENSURE_OR_GO_EXIT(NULL != macLen);

    if (context->algorithm == kAlgorithm_SSS_CMAC_AES) {
        mbedtls_cipher_context_t *ctx;
        ctx = context->cipher_ctx;

        if (context->mode == kMode_SSS_Mac) {
#ifdef MBEDTLS_CMAC_C
            ret = mbedtls_cipher_cmac_finish(ctx, mac);
#endif
            if (ret == 0) {
#if SSS_HAVE_MBEDTLS_3_X
                *macLen = ctx->private_cipher_info->private_block_size;
#else
                *macLen = ctx->cipher_info->block_size;
#endif
                status = kStatus_SSS_Success;
            }
        }
        else if (context->mode == kMode_SSS_Mac_Validate) {
            /* validate MAC*/
            uint8_t macLocal[64] = {
                0,
            };
            size_t macLocalLen;
            status = kStatus_SSS_Fail;
#ifdef MBEDTLS_CMAC_C
            ret = mbedtls_cipher_cmac_finish(ctx, macLocal);
#endif
            if (ret == 0) {
#if SSS_HAVE_MBEDTLS_3_X
                macLocalLen = ctx->private_cipher_info->private_block_size;
#else
                macLocalLen = ctx->cipher_info->block_size;
#endif
                if (macLocalLen == *macLen) {
                    if (0 == memcmp(macLocal, mac, macLocalLen)) {
                        status = kStatus_SSS_Success;
                    }
                }
            }
        }
        else {
            LOG_E("Unknown mode");
            status = kStatus_SSS_Fail;
        }
    }
    else if (context->algorithm == kAlgorithm_SSS_HMAC_SHA256 || context->algorithm == kAlgorithm_SSS_HMAC_SHA384) {
        mbedtls_md_context_t *hmacctx;
        hmacctx = context->HmacCtx;

        if (context->mode == kMode_SSS_Mac) {
            ret = mbedtls_md_hmac_finish(hmacctx, mac);
            if (ret == 0) {
#if SSS_HAVE_MBEDTLS_3_X
                *macLen = mbedtls_md_get_size(hmacctx->private_md_info);
#else
                *macLen = mbedtls_md_get_size(hmacctx->md_info);
#endif
                status = kStatus_SSS_Success;
            }
        }
        else if (context->mode == kMode_SSS_Mac_Validate) {
            /* validate MAC*/
            uint8_t macLocal[64] = {
                0,
            };
            size_t macLocalLen = sizeof(macLocal);
            status             = kStatus_SSS_Fail;
            ret                = mbedtls_md_hmac_finish(hmacctx, macLocal);
            if (ret == 0) {
#if SSS_HAVE_MBEDTLS_3_X
                macLocalLen = mbedtls_md_get_size(hmacctx->private_md_info);
#else
                macLocalLen = mbedtls_md_get_size(hmacctx->md_info);
#endif
                if (macLocalLen == *macLen) {
                    if (!memcmp(macLocal, mac, macLocalLen)) {
                        status = kStatus_SSS_Success;
                    }
                }
            }
        }
        else {
            LOG_E("Unknown mode");
            status = kStatus_SSS_Fail;
        }
    }
    else {
        LOG_E("Invalid algorithm type for sss_mbedtls_mac_finish");
    }
exit:
    return status;
}

void sss_mbedtls_mac_context_free(sss_mbedtls_mac_t *context)
{
    if (context == NULL) {
        LOG_E("No context to free!");
    }
    else {
        if (context->cipher_ctx != NULL) {
            mbedtls_cipher_free(context->cipher_ctx);
            SSS_FREE(context->cipher_ctx);
        }
        if (context->algorithm == kAlgorithm_SSS_HMAC_SHA256 || context->algorithm == kAlgorithm_SSS_HMAC_SHA384) {
            mbedtls_md_free(context->HmacCtx);
            SSS_FREE(context->HmacCtx);
        }
        memset(context, 0, sizeof(*context));
    }
}

/* ************************************************************************** */
/* Functions : sss_mbedtls_md                                                 */
/* ************************************************************************** */

sss_status_t sss_mbedtls_digest_context_init(
    sss_mbedtls_digest_t *context, sss_mbedtls_session_t *session, sss_algorithm_t algorithm, sss_mode_t mode)
{
    sss_status_t retval = kStatus_SSS_Fail;
    ENSURE_OR_GO_CLEANUP(NULL != context);
    memset(context, 0, sizeof(*context));
    context->session   = session;
    context->algorithm = algorithm;
    context->mode      = mode;
    retval             = kStatus_SSS_Success;
cleanup:
    return retval;
}

sss_status_t sss_mbedtls_digest_one_go(
    sss_mbedtls_digest_t *context, const uint8_t *message, size_t messageLen, uint8_t *digest, size_t *digestLen)
{
    sss_status_t retval             = kStatus_SSS_Fail;
    int ret                         = 1;
    const mbedtls_md_info_t *mdinfo = NULL;
    mbedtls_md_type_t md_type       = MBEDTLS_MD_NONE;

    ENSURE_OR_GO_EXIT(NULL != context)
    ENSURE_OR_GO_EXIT(NULL != digestLen)
    switch (context->algorithm) {
    case kAlgorithm_SSS_SHA256:
        md_type    = MBEDTLS_MD_SHA256;
        *digestLen = 32;
        break;
    case kAlgorithm_SSS_SHA384:
        md_type    = MBEDTLS_MD_SHA384;
        *digestLen = 48;
        break;
    default: {
        LOG_E("Algorithm mode not suported");
        goto exit;
    }
    }

    mdinfo = mbedtls_md_info_from_type(md_type);

    ret = mbedtls_md(mdinfo, message, messageLen, digest);

    if (ret != 0) {
        LOG_E("mbedtls_md failed");
        *digestLen = 0;
        goto exit;
    }

    retval = kStatus_SSS_Success;
exit:
    return retval;
}

sss_status_t sss_mbedtls_digest_init(sss_mbedtls_digest_t *context)
{
    sss_status_t retval             = kStatus_SSS_Fail;
    const mbedtls_md_info_t *mdinfo = NULL;
    mbedtls_md_type_t md_type       = MBEDTLS_MD_NONE;
    int ret                         = 1;

    ENSURE_OR_GO_EXIT(NULL != context)
    mbedtls_md_init(&context->md_ctx);

    switch (context->algorithm) {
    case kAlgorithm_SSS_SHA256:
        md_type = MBEDTLS_MD_SHA256;
        break;
    case kAlgorithm_SSS_SHA384:
        md_type = MBEDTLS_MD_SHA384;
        break;
    default:
        LOG_E("Algorithm mode not suported");
        goto exit;
    }

    mdinfo = mbedtls_md_info_from_type(md_type);

#if SSS_HAVE_MBEDTLS_3_X
    ret = mbedtls_md_setup(&context->md_ctx, mdinfo, 0);
#else
    ret = mbedtls_md_init_ctx(&context->md_ctx, mdinfo);
#endif
    ENSURE_OR_GO_EXIT(ret == 0);

    ret = 1;
    ret = mbedtls_md_starts(&context->md_ctx);
    ENSURE_OR_GO_EXIT(ret == 0);

    retval = kStatus_SSS_Success;
exit:
    return retval;
}

sss_status_t sss_mbedtls_digest_update(sss_mbedtls_digest_t *context, const uint8_t *message, size_t messageLen)
{
    sss_status_t retval = kStatus_SSS_Fail;
    int ret             = 1;

    ENSURE_OR_GO_EXIT(NULL != context);

    ret = mbedtls_md_update(&context->md_ctx, message, messageLen);
    ENSURE_OR_GO_EXIT(ret == 0);

    retval = kStatus_SSS_Success;
exit:
    return retval;
}

sss_status_t sss_mbedtls_digest_finish(sss_mbedtls_digest_t *context, uint8_t *digest, size_t *digestLen)
{
    sss_status_t retval = kStatus_SSS_Fail;
    int ret             = 1;

    ENSURE_OR_GO_EXIT(NULL != context)
    ENSURE_OR_GO_EXIT(NULL != digestLen)
    switch (context->algorithm) {
    case kAlgorithm_SSS_SHA256:
        *digestLen = 32;
        break;
    case kAlgorithm_SSS_SHA384:
        *digestLen = 48;
        break;
    default: {
        LOG_E("Algorithm mode not suported");
        goto exit;
    }
    }

    ret = mbedtls_md_finish(&context->md_ctx, digest);
    if (ret != 0) {
        LOG_E("mbedtls_md_update failed");
        *digestLen = 0;
        goto exit;
    }

    retval = kStatus_SSS_Success;
exit:
    return retval;
}

void sss_mbedtls_digest_context_free(sss_mbedtls_digest_t *context)
{
    if (context == NULL) {
        LOG_E("No context to free!");
    }
    else {
        mbedtls_md_free(&context->md_ctx);
        memset(context, 0, sizeof(*context));
    }
}

/* End: mbedtls_md */

/* ************************************************************************** */
/* Functions : sss_mbedtls_rng                                                */
/* ************************************************************************** */

sss_status_t sss_mbedtls_rng_context_init(sss_mbedtls_rng_context_t *context, sss_mbedtls_session_t *session)
{
    sss_status_t retval = kStatus_SSS_Fail;

    ENSURE_OR_GO_EXIT(NULL != context);
    ENSURE_OR_GO_EXIT(NULL != session);

    context->session = session;

    if (session->ctr_drbg == NULL) {
        session->ctr_drbg = SSS_MALLOC(sizeof(*session->ctr_drbg));
        ENSURE_OR_GO_EXIT(session->ctr_drbg != NULL);
        mbedtls_ctr_drbg_init((session->ctr_drbg));
    }

    if (session->entropy == NULL) {
        session->entropy = SSS_MALLOC(sizeof(*session->entropy));
        ENSURE_OR_GO_EXIT(session->entropy != NULL);
        mbedtls_entropy_init((session->entropy));
    }

    retval = kStatus_SSS_Success;
exit:
    return retval;
}

sss_status_t sss_mbedtls_rng_get_random(sss_mbedtls_rng_context_t *context, uint8_t *random_data, size_t dataLen)
{
    sss_status_t retval = kStatus_SSS_Fail;
    size_t chunk        = 0;
    size_t offset       = 0;
    int ret             = 1;

    ENSURE_OR_GO_EXIT(NULL != context)
    ENSURE_OR_GO_EXIT(NULL != context->session)

    if (dataLen > 0) {
        ENSURE_OR_GO_EXIT(NULL != random_data);
    }

    while (dataLen > 0) {
        if (dataLen > MBEDTLS_CTR_DRBG_MAX_REQUEST) {
            chunk = MBEDTLS_CTR_DRBG_MAX_REQUEST;
        }
        else {
            chunk = dataLen;
        }

        ret = mbedtls_ctr_drbg_random(context->session->ctr_drbg, (random_data + offset), chunk);
        ENSURE_OR_GO_EXIT(ret == 0);
        ENSURE_OR_GO_EXIT((UINT_MAX - offset) >= chunk);
        offset += chunk;
        dataLen -= chunk;
    }

    retval = kStatus_SSS_Success;
exit:
    return retval;
}

sss_status_t sss_mbedtls_rng_context_free(sss_mbedtls_rng_context_t *context)
{
    sss_status_t retval = kStatus_SSS_Fail;
    if (NULL == context) {
        LOG_E("No context to free!");
        goto exit;
    }
    else {
        memset(context, 0, sizeof(*context));
    }
    retval = kStatus_SSS_Success;
exit:
    return retval;
}

/* End: mbedtls_rng */

/* ************************************************************************** */
/* Functions : Private sss mbedtls functions                                  */
/* ************************************************************************** */

// FIXME: Handle data/dataLen
static sss_status_t sss_mbedtls_set_key(
    sss_mbedtls_object_t *keyObject, const uint8_t *data, size_t dataLen, size_t keyBitLen)
{
    sss_status_t retval  = kStatus_SSS_Fail;
    size_t base64_olen   = 0;
    int ret              = 1;
    char pem_format[512] = {0};

    ENSURE_OR_GO_EXIT(NULL != keyObject)
    switch (keyObject->objectType) {
    case kSSS_KeyPart_Default:
        ENSURE_OR_GO_EXIT(dataLen <= keyObject->contents_max_size);
        if (data != NULL) /* For empty certificate */
            memcpy(keyObject->contents, data, dataLen);
        keyObject->contents_size = dataLen;
        keyObject->keyBitLen     = keyBitLen;
        retval                   = kStatus_SSS_Success;
        break;
    case kSSS_KeyPart_Private:
    case kSSS_KeyPart_Pair: {
        mbedtls_pk_context *pk = (mbedtls_pk_context *)keyObject->contents;
#if SSS_HAVE_MBEDTLS_3_X
        ret = mbedtls_pk_parse_key(pk, data, dataLen, NULL, 0, NULL, NULL);
#else
        ret = mbedtls_pk_parse_key(pk, data, dataLen, NULL, 0);
#endif
        (ret == 0) ? (retval = kStatus_SSS_Success) : (retval = kStatus_SSS_Fail);
    } break;
    case kSSS_KeyPart_Public: {
        // Sizeof base64_format should be limited to sizeof(pem_format) minus BEGIN_PUBLIC and END_PUBLIC
        uint8_t base64_format[256] = {0};
        mbedtls_pk_context *pk     = (mbedtls_pk_context *)keyObject->contents;

        ret = mbedtls_base64_encode(base64_format, sizeof(base64_format), &base64_olen, data, dataLen);
        if (ret != 0) {
            goto exit;
        }
        if (SNPRINTF(pem_format, sizeof(pem_format), BEGIN_PUBLIC "%s" END_PUBLIC, base64_format) < 0) {
            retval = kStatus_SSS_Fail;
            goto exit;
        }

        ret = mbedtls_pk_parse_public_key(pk, (const uint8_t *)pem_format, strlen(pem_format) + 1);
        (ret == 0) ? (retval = kStatus_SSS_Success) : (retval = kStatus_SSS_Fail);
    } break;
    default:
        retval = kStatus_SSS_Fail;
        LOG_E("Key type not supported");
        break;
    }
exit:
    return retval;
}

#if SSS_HAVE_MBEDTLS_3_X
int mbedtls_entropy_func_3_X(void *data, unsigned char *output, size_t len)
{
    LOG_W(
        "mbedtls_entropy_func_3_X is a dummy implementation with hardcoded entropy. Mandatory to port it to the Micro "
        "Controller being used.");
    unsigned char buf[MBEDTLS_ENTROPY_BLOCK_SIZE] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
    if (len > MBEDTLS_ENTROPY_BLOCK_SIZE) {
        return MBEDTLS_ERR_ENTROPY_SOURCE_FAILED;
    }
    memcpy(output, buf, len);
    return 0;
}
#endif

static sss_status_t sss_mbedtls_drbg_seed(sss_mbedtls_session_t *pSession, const char *pers, size_t persLen)
{
    int ret             = 1;
    sss_status_t retval = kStatus_SSS_Fail;

#if (SSS_HAVE_HOST_FRDMK64F || SSS_HAVE_HOST_LPCXPRESSO55S) && SSS_HAVE_MBEDTLS_3_X
    ret = mbedtls_ctr_drbg_seed(
        pSession->ctr_drbg, &mbedtls_entropy_func_3_X, pSession->entropy, (const unsigned char *)pers, persLen);
#else
    ret = mbedtls_ctr_drbg_seed(
        pSession->ctr_drbg, &mbedtls_entropy_func, pSession->entropy, (const unsigned char *)pers, persLen);
#endif
    ENSURE_OR_GO_EXIT(ret == 0);
    retval = kStatus_SSS_Success;
exit:
    return (retval);
}

static mbedtls_ecp_group_id get_nist_p_group_id(size_t keyBitLen)
{
    mbedtls_ecp_group_id groupId = MBEDTLS_ECP_DP_NONE;
    switch (keyBitLen) {
    case 256:
        groupId = MBEDTLS_ECP_DP_SECP256R1;
        break;
    default:
        break;
    }
    return groupId;
}

static mbedtls_ecp_group_id get_bp_group_id(size_t keyBitLen)
{
    mbedtls_ecp_group_id groupId = MBEDTLS_ECP_DP_NONE;
    switch (keyBitLen) {
    case 256:
        groupId = MBEDTLS_ECP_DP_BP256R1;
        break;
    default:
        break;
    }
    return groupId;
}

static sss_status_t sss_mbedtls_generate_ecp_key(
    mbedtls_pk_context *pkey, sss_mbedtls_session_t *pSession, size_t keyBitLen, sss_cipher_type_t cipher_type)
{
    int ret                      = 1;
    sss_status_t retval          = kStatus_SSS_Fail;
    mbedtls_ecp_group_id groupId = MBEDTLS_ECP_DP_NONE;

    ret = mbedtls_pk_setup(pkey, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));
    ENSURE_OR_GO_EXIT(ret == 0);

    if (cipher_type == kSSS_CipherType_EC_NIST_P) {
        groupId = get_nist_p_group_id(keyBitLen);
    }
    else if (cipher_type == kSSS_CipherType_EC_BRAINPOOL) {
        groupId = get_bp_group_id(keyBitLen);
    }
    else {
        LOG_E(" sss_openssl_generate_ecp_key: Invalid key type ");
    }

    if (groupId != MBEDTLS_ECP_DP_NONE) {
        ret = mbedtls_ecp_gen_key(groupId, mbedtls_pk_ec(*pkey), mbedtls_ctr_drbg_random, pSession->ctr_drbg);
    }
    else {
        LOG_E(" Don't have support for this keyBitLen");
        ret = 1;
    }

    if (ret != 0) {
        LOG_E(" mbedtls_ecp_gen_key returned -0x%04x", -ret);
        goto exit;
    }
    retval = kStatus_SSS_Success;
exit:
    return retval;
}

static sss_status_t sss_mbedtls_hkdf_expand(const mbedtls_md_info_t *md,
    const uint8_t *prk,
    size_t prk_len,
    const uint8_t *info,
    size_t info_len,
    uint8_t *okm,
    size_t okm_len)
{
    size_t hash_len = 0;
    size_t N        = 0;
    size_t T_len = 0, where = 0, i;
    int ret                              = 1;
    mbedtls_md_context_t ctx             = {0};
    unsigned char T[MBEDTLS_MD_MAX_SIZE] = {0};
    sss_status_t retval                  = kStatus_SSS_Fail;

    if (okm == NULL) {
        retval = kStatus_SSS_InvalidArgument;
        goto exit;
    }

    hash_len = mbedtls_md_get_size(md);

    if (hash_len == 0) {
        goto exit;
    }

    if (info == NULL) {
        info = (const unsigned char *)"";
    }

    N = okm_len / hash_len;

    if (N >= UINT_MAX) {
        goto exit;
    }
    if ((okm_len % hash_len) != 0) {
        N++;
    }

    if (N > 255) {
        retval = kStatus_SSS_InvalidArgument;
        goto exit;
    }

    mbedtls_md_init(&ctx);

    if ((ret = mbedtls_md_setup(&ctx, md, 1)) != 0) {
        mbedtls_md_free(&ctx);
        goto exit;
    }

    /* Section 2.3. */
    for (i = 1; i <= N; i++) {
        unsigned char c = (unsigned char)i;

        ret = mbedtls_md_hmac_starts(&ctx, prk, prk_len) || mbedtls_md_hmac_update(&ctx, T, T_len) ||
              mbedtls_md_hmac_update(&ctx, info, info_len) ||
              /* The constant concatenated to the end of each T(n) is a single
            octet. */
              mbedtls_md_hmac_update(&ctx, &c, 1) || mbedtls_md_hmac_finish(&ctx, T);

        if (ret != 0) {
            mbedtls_md_free(&ctx);
            goto exit;
        }

        memcpy(okm + where, T, (i != N) ? hash_len : (okm_len - where));
        where += hash_len;
        T_len = hash_len;
    }

    mbedtls_md_free(&ctx);
    retval = kStatus_SSS_Success;
exit:
    return retval;
}

static sss_status_t sss_mbedtls_hkdf_extract(
    const mbedtls_md_info_t *md, const uint8_t *salt, size_t salt_len, const uint8_t *ikm, size_t ikm_len, uint8_t *prk)
{
    int hash_len                                 = 0;
    int ret                                      = 1;
    unsigned char null_salt[MBEDTLS_MD_MAX_SIZE] = {'\0'};
    sss_status_t retval                          = kStatus_SSS_Fail;

    hash_len = mbedtls_md_get_size(md);

    if (salt == NULL) {
        salt     = null_salt;
        salt_len = hash_len;
    }

    ret = mbedtls_md_hmac(md, salt, salt_len, ikm, ikm_len, prk);
    if (ret != 0) {
        goto exit;
    }
    retval = kStatus_SSS_Success;
exit:
    return retval;
}

// In HKDF Expand only mode PRK is unbounded, we set a maximum of 256 byte
// RFC5869 Section 2.3
#define HKDF_PRK_MAX 256
sss_status_t sss_mbedtls_derive_key_one_go(sss_mbedtls_derive_key_t *context,
    sss_object_t *saltObject,
    const uint8_t *info,
    size_t infoLen,
    sss_object_t *derivedKeyObject,
    uint16_t deriveDataLen)
{
    sss_status_t retval         = kStatus_SSS_Fail;
    const mbedtls_md_info_t *md = NULL;
    uint8_t *secret             = NULL;
    size_t secretLen            = 0;
    uint8_t prk[HKDF_PRK_MAX]   = {
        0,
    };
    size_t prk_len           = 0;
    mbedtls_md_type_t md_alg = MBEDTLS_MD_NONE;
    uint8_t *salt            = NULL;
    size_t adjustedSaltLen   = 0;
    uint8_t *hkdfOutput      = NULL;

    ENSURE_OR_GO_EXIT(NULL != context)
    ENSURE_OR_GO_EXIT(NULL != context->keyObject)
    ENSURE_OR_GO_EXIT(NULL != derivedKeyObject);
    ENSURE_OR_GO_EXIT(kType_SSS_mbedTLS == derivedKeyObject->keyStore->session->subsystem);

    secret     = context->keyObject->contents;
    secretLen  = context->keyObject->contents_size;
    hkdfOutput = ((sss_mbedtls_object_t *)derivedKeyObject)->contents;

    if (((sss_mbedtls_object_t *)derivedKeyObject)->contents_max_size < deriveDataLen) {
        LOG_E("derivedKeyObject data buffer is small!");
        return kStatus_SSS_Fail;
    }

    if (saltObject != NULL) {
        if (saltObject->keyStore->session->subsystem == kType_SSS_mbedTLS) {
            salt            = ((sss_mbedtls_object_t *)saltObject)->contents;
            adjustedSaltLen = ((sss_mbedtls_object_t *)saltObject)->contents_size;
        }
        else {
            LOG_E("saltKeyObject should be from host crypto");
        }
    }

    if (context->mode == kMode_SSS_HKDF_ExpandOnly) {
        adjustedSaltLen = 0;
    }

    switch (context->algorithm) {
    case kAlgorithm_SSS_SHA256:
    case kAlgorithm_SSS_HMAC_SHA256:
        md_alg = MBEDTLS_MD_SHA256;
        break;
    case kAlgorithm_SSS_SHA384:
    case kAlgorithm_SSS_HMAC_SHA384:
        md_alg = MBEDTLS_MD_SHA384;
        break;
    default:
        goto exit;
    }

    md = mbedtls_md_info_from_type(md_alg);

    if (adjustedSaltLen == 0) {
        /* Copy key as is */
        if (HKDF_PRK_MAX >= secretLen) {
            memcpy(prk, secret, secretLen);
            prk_len = secretLen;
        }
        else {
            LOG_E("HKDF Expand only (mbedTLS implementation): buffer too small");
            goto exit;
        }
    }
    else {
        retval  = sss_mbedtls_hkdf_extract(md, salt, adjustedSaltLen, secret, secretLen, prk);
        prk_len = mbedtls_md_get_size(md);
        if (retval != kStatus_SSS_Success) {
            goto exit;
        }
    }

    retval = sss_mbedtls_hkdf_expand(md, prk, prk_len, info, infoLen, hkdfOutput, deriveDataLen);
    if (retval == kStatus_SSS_Success) {
        ((sss_mbedtls_object_t *)derivedKeyObject)->contents_size = deriveDataLen;
    }

exit:
    return retval;
}

/* Low level implementation for sss_mbedtls_key_object_allocate_handle */
sss_status_t ks_mbedtls_key_object_create(sss_mbedtls_object_t *keyObject,
    uint32_t keyId,
    sss_key_part_t keyPart,
    sss_cipher_type_t cipherType,
    size_t keyByteLenMax,
    uint32_t keyMode)
{
    size_t size         = 0;
    sss_status_t retval = kStatus_SSS_Fail;
    ENSURE_OR_GO_CLEANUP(NULL != keyObject);

    keyObject->keyId              = keyId;
    keyObject->objectType         = keyPart;
    keyObject->cipherType         = cipherType;
    keyObject->contents_max_size  = keyByteLenMax;
    keyObject->contents_must_free = 1;
    keyObject->keyMode            = keyMode;
    /* Bitwise OR of all sss_access_permission. */
    keyObject->accessRights = kAccessPermission_SSS_All_Permission;
    switch (keyPart) {
    case kSSS_KeyPart_Default:
        size = keyByteLenMax;
        break;
    case kSSS_KeyPart_Pair:
    case kSSS_KeyPart_Private:
    case kSSS_KeyPart_Public:
        size = sizeof(mbedtls_pk_context);
        break;
    default:
        break;
    }
    if (size != 0) {
        keyObject->contents           = SSS_MALLOC(size);
        keyObject->contents_must_free = 1;
        ENSURE_OR_GO_CLEANUP(NULL != keyObject->contents);
        memset(keyObject->contents, 0, size);
        retval = kStatus_SSS_Success;
    }

cleanup:
    return retval;
}

#endif /* SSS_HAVE_HOSTCRYPTO_MBEDTLS */
