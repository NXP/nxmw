/*
 *
 * Copyright 2022-2023 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "fsl_sss_api.h"

#if defined(SSS_USE_FTR_FILE)
#include "fsl_sss_ftr.h"
#else
#include "fsl_sss_ftr_default.h"
#endif

#if SSS_HAVE_NX_TYPE
#include "fsl_sss_nx_apis.h"
#endif /* SSS_HAVE_NX_TYPE */

#if SSS_HAVE_HOSTCRYPTO_MBEDTLS
#include "fsl_sss_mbedtls_apis.h"
#endif /* SSS_HAVE_HOSTCRYPTO_MBEDTLS */

#if SSS_HAVE_HOSTCRYPTO_OPENSSL
#include "fsl_sss_openssl_apis.h"
#endif /* SSS_HAVE_HOSTCRYPTO_OPENSSL */

#include "nxLog_msg.h"

#if (SSS_HAVE_SSS > 1)

sss_status_t sss_session_open(sss_session_t *session,
    sss_type_t subsystem,
    uint32_t application_id,
    sss_connection_type_t connection_type,
    void *connectionData)
{
    if (NULL == session) {
        LOG_E("session pointer invalid!");
        return kStatus_SSS_Fail;
    }
    if (kType_SSS_Software == subsystem) {
#if SSS_HAVE_HOSTCRYPTO_OPENSSL
        /* if I have openSSL */
        subsystem = kType_SSS_OpenSSL;
#endif
#if SSS_HAVE_HOSTCRYPTO_MBEDTLS
        /* if I have mbed TLS */
        subsystem = kType_SSS_mbedTLS;
#endif
    }
    else if (kType_SSS_SecureElement == subsystem) {
#if SSS_HAVE_NX_TYPE
        subsystem = kType_SSS_SE_NX;
#endif
    }

#if SSS_HAVE_NX_TYPE
    if (SSS_SUBSYSTEM_TYPE_IS_NX(subsystem)) {
        sss_nx_session_t *nx_session = (sss_nx_session_t *)session;
        SSS_ASSERT(sizeof(*nx_session) <= sizeof(*session));
        return sss_nx_session_open(nx_session, subsystem, application_id, connection_type, connectionData);
    }
#endif /* SSS_HAVE_NX_TYPE */
#if SSS_HAVE_HOSTCRYPTO_MBEDTLS
    if (SSS_SUBSYSTEM_TYPE_IS_MBEDTLS(subsystem)) {
        sss_mbedtls_session_t *mbedtls_session = (sss_mbedtls_session_t *)session;
        SSS_ASSERT(sizeof(*mbedtls_session) <= sizeof(*session));
        return sss_mbedtls_session_open(mbedtls_session, subsystem, application_id, connection_type, connectionData);
    }
#endif /* SSS_HAVE_HOSTCRYPTO_MBEDTLS */
#if SSS_HAVE_HOSTCRYPTO_OPENSSL
    if (SSS_SUBSYSTEM_TYPE_IS_OPENSSL(subsystem)) {
        sss_openssl_session_t *openssl_session = (sss_openssl_session_t *)session;
        SSS_ASSERT(sizeof(*openssl_session) <= sizeof(*session));
        return sss_openssl_session_open(openssl_session, subsystem, application_id, connection_type, connectionData);
    }
#endif /* SSS_HAVE_HOSTCRYPTO_OPENSSL */
    return kStatus_SSS_InvalidArgument;
}

sss_status_t sss_session_close(sss_session_t *session)
{
#if SSS_HAVE_NX_TYPE
    if (SSS_SESSION_TYPE_IS_NX(session)) {
        sss_nx_session_t *nx_session = (sss_nx_session_t *)session;
        SSS_ASSERT(sizeof(*nx_session) <= sizeof(*session));
        return sss_nx_session_close(nx_session);
    }
#endif /* SSS_HAVE_NX_TYPE */
#if SSS_HAVE_HOSTCRYPTO_MBEDTLS
    if (SSS_SESSION_TYPE_IS_MBEDTLS(session)) {
        sss_mbedtls_session_t *mbedtls_session = (sss_mbedtls_session_t *)session;
        SSS_ASSERT(sizeof(*mbedtls_session) <= sizeof(*session));
        sss_mbedtls_session_close(mbedtls_session);
    }
#endif /* SSS_HAVE_HOSTCRYPTO_MBEDTLS */
#if SSS_HAVE_HOSTCRYPTO_OPENSSL
    if (SSS_SESSION_TYPE_IS_OPENSSL(session)) {
        sss_openssl_session_t *openssl_session = (sss_openssl_session_t *)session;
        SSS_ASSERT(sizeof(*openssl_session) <= sizeof(*session));
        sss_openssl_session_close(openssl_session);
    }
#endif /* SSS_HAVE_HOSTCRYPTO_OPENSSL */
    return kStatus_SSS_InvalidArgument;
}

sss_status_t sss_key_store_context_init(sss_key_store_t *keyStore, sss_session_t *session)
{
    if (NULL == keyStore) {
        LOG_E("keyStore pointer invalid!");
        return kStatus_SSS_Fail;
    }
#if SSS_HAVE_NX_TYPE
    if (SSS_SESSION_TYPE_IS_NX(session)) {
        sss_nx_key_store_t *nx_keyStore = (sss_nx_key_store_t *)keyStore;
        sss_nx_session_t *nx_session    = (sss_nx_session_t *)session;
        SSS_ASSERT(sizeof(*nx_keyStore) <= sizeof(*keyStore));
        SSS_ASSERT(sizeof(*nx_session) <= sizeof(*session));
        return sss_nx_key_store_context_init(nx_keyStore, nx_session);
    }
#endif /* SSS_HAVE_NX_TYPE */
#if SSS_HAVE_HOSTCRYPTO_MBEDTLS
    if (SSS_SESSION_TYPE_IS_MBEDTLS(session)) {
        sss_mbedtls_key_store_t *mbedtls_keyStore = (sss_mbedtls_key_store_t *)keyStore;
        sss_mbedtls_session_t *mbedtls_session    = (sss_mbedtls_session_t *)session;
        SSS_ASSERT(sizeof(*mbedtls_keyStore) <= sizeof(*keyStore));
        SSS_ASSERT(sizeof(*mbedtls_session) <= sizeof(*session));
        return sss_mbedtls_key_store_context_init(mbedtls_keyStore, mbedtls_session);
    }
#endif /* SSS_HAVE_HOSTCRYPTO_MBEDTLS */
#if SSS_HAVE_HOSTCRYPTO_OPENSSL
    if (SSS_SESSION_TYPE_IS_OPENSSL(session)) {
        sss_openssl_key_store_t *openssl_keyStore = (sss_openssl_key_store_t *)keyStore;
        sss_openssl_session_t *openssl_session    = (sss_openssl_session_t *)session;
        SSS_ASSERT(sizeof(*openssl_keyStore) <= sizeof(*keyStore));
        SSS_ASSERT(sizeof(*openssl_session) <= sizeof(*session));
        return sss_openssl_key_store_context_init(openssl_keyStore, openssl_session);
    }
#endif /* SSS_HAVE_HOSTCRYPTO_OPENSSL */
    return kStatus_SSS_InvalidArgument;
}

sss_status_t sss_key_store_allocate(sss_key_store_t *keyStore, uint32_t keyStoreId)
{
#if SSS_HAVE_NX_TYPE
    if (SSS_KEY_STORE_TYPE_IS_NX(keyStore)) {
        sss_nx_key_store_t *nx_keyStore = (sss_nx_key_store_t *)keyStore;
        SSS_ASSERT(sizeof(*nx_keyStore) <= sizeof(*keyStore));
        return sss_nx_key_store_allocate(nx_keyStore, keyStoreId);
    }
#endif /* SSS_HAVE_NX_TYPE */
#if SSS_HAVE_HOSTCRYPTO_MBEDTLS
    if (SSS_KEY_STORE_TYPE_IS_MBEDTLS(keyStore)) {
        sss_mbedtls_key_store_t *mbedtls_keyStore = (sss_mbedtls_key_store_t *)keyStore;
        SSS_ASSERT(sizeof(*mbedtls_keyStore) <= sizeof(*keyStore));
        return sss_mbedtls_key_store_allocate(mbedtls_keyStore, keyStoreId);
    }
#endif /* SSS_HAVE_HOSTCRYPTO_MBEDTLS */
#if SSS_HAVE_HOSTCRYPTO_OPENSSL
    if (SSS_KEY_STORE_TYPE_IS_OPENSSL(keyStore)) {
        sss_openssl_key_store_t *openssl_keyStore = (sss_openssl_key_store_t *)keyStore;
        SSS_ASSERT(sizeof(*openssl_keyStore) <= sizeof(*keyStore));
        return sss_openssl_key_store_allocate(openssl_keyStore, keyStoreId);
    }
#endif /* SSS_HAVE_HOSTCRYPTO_OPENSSL */
    return kStatus_SSS_InvalidArgument;
}

sss_status_t sss_key_store_set_key(sss_key_store_t *keyStore,
    sss_object_t *keyObject,
    const uint8_t *data,
    size_t dataLen,
    size_t keyBitLen,
    void *options,
    size_t optionsLen)
{
    if (NULL == keyObject) {
        LOG_E("keyObject pointer invalid!");
        return kStatus_SSS_Fail;
    }
#if SSS_HAVE_NX_TYPE
    if (SSS_KEY_STORE_TYPE_IS_NX(keyStore)) {
        sss_nx_key_store_t *nx_keyStore = (sss_nx_key_store_t *)keyStore;
        sss_nx_object_t *nx_keyObject   = (sss_nx_object_t *)keyObject;
        SSS_ASSERT(sizeof(*nx_keyStore) <= sizeof(*keyStore));
        SSS_ASSERT(sizeof(*nx_keyObject) <= sizeof(*keyObject));
        return sss_nx_key_store_set_key(nx_keyStore, nx_keyObject, data, dataLen, keyBitLen, options, optionsLen);
    }
#endif /* SSS_HAVE_NX_TYPE */
#if SSS_HAVE_HOSTCRYPTO_MBEDTLS
    if (SSS_KEY_STORE_TYPE_IS_MBEDTLS(keyStore)) {
        sss_mbedtls_key_store_t *mbedtls_keyStore = (sss_mbedtls_key_store_t *)keyStore;
        sss_mbedtls_object_t *mbedtls_keyObject   = (sss_mbedtls_object_t *)keyObject;
        SSS_ASSERT(sizeof(*mbedtls_keyStore) <= sizeof(*keyStore));
        SSS_ASSERT(sizeof(*mbedtls_keyObject) <= sizeof(*keyObject));
        return sss_mbedtls_key_store_set_key(
            mbedtls_keyStore, mbedtls_keyObject, data, dataLen, keyBitLen, options, optionsLen);
    }
#endif /* SSS_HAVE_HOSTCRYPTO_MBEDTLS */
#if SSS_HAVE_HOSTCRYPTO_OPENSSL
    if (SSS_KEY_STORE_TYPE_IS_OPENSSL(keyStore)) {
        sss_openssl_key_store_t *openssl_keyStore = (sss_openssl_key_store_t *)keyStore;
        sss_openssl_object_t *openssl_keyObject   = (sss_openssl_object_t *)keyObject;
        SSS_ASSERT(sizeof(*openssl_keyStore) <= sizeof(*keyStore));
        SSS_ASSERT(sizeof(*openssl_keyObject) <= sizeof(*keyObject));
        return sss_openssl_key_store_set_key(
            openssl_keyStore, openssl_keyObject, data, dataLen, keyBitLen, options, optionsLen);
    }
#endif /* SSS_HAVE_HOSTCRYPTO_OPENSSL */
    return kStatus_SSS_InvalidArgument;
}

sss_status_t sss_key_store_generate_key(
    sss_key_store_t *keyStore, sss_object_t *keyObject, size_t keyBitLen, void *options)
{
    if (NULL == keyObject) {
        LOG_E("keyObject pointer invalid!");
        return kStatus_SSS_Fail;
    }
#if SSS_HAVE_NX_TYPE
    if (SSS_KEY_STORE_TYPE_IS_NX(keyStore)) {
        sss_nx_key_store_t *nx_keyStore = (sss_nx_key_store_t *)keyStore;
        sss_nx_object_t *nx_keyObject   = (sss_nx_object_t *)keyObject;
        SSS_ASSERT(sizeof(*nx_keyStore) <= sizeof(*keyStore));
        SSS_ASSERT(sizeof(*nx_keyObject) <= sizeof(*keyObject));
        return sss_nx_key_store_generate_key(nx_keyStore, nx_keyObject, keyBitLen, options);
    }
#endif /* SSS_HAVE_NX_TYPE */
#if SSS_HAVE_HOSTCRYPTO_MBEDTLS
    if (SSS_KEY_STORE_TYPE_IS_MBEDTLS(keyStore)) {
        sss_mbedtls_key_store_t *mbedtls_keyStore = (sss_mbedtls_key_store_t *)keyStore;
        sss_mbedtls_object_t *mbedtls_keyObject   = (sss_mbedtls_object_t *)keyObject;
        SSS_ASSERT(sizeof(*mbedtls_keyStore) <= sizeof(*keyStore));
        SSS_ASSERT(sizeof(*mbedtls_keyObject) <= sizeof(*keyObject));
        return sss_mbedtls_key_store_generate_key(mbedtls_keyStore, mbedtls_keyObject, keyBitLen, options);
    }
#endif /* SSS_HAVE_HOSTCRYPTO_MBEDTLS */
#if SSS_HAVE_HOSTCRYPTO_OPENSSL
    if (SSS_KEY_STORE_TYPE_IS_OPENSSL(keyStore)) {
        sss_openssl_key_store_t *openssl_keyStore = (sss_openssl_key_store_t *)keyStore;
        sss_openssl_object_t *openssl_keyObject   = (sss_openssl_object_t *)keyObject;
        SSS_ASSERT(sizeof(*openssl_keyStore) <= sizeof(*keyStore));
        SSS_ASSERT(sizeof(*openssl_keyObject) <= sizeof(*keyObject));
        return sss_openssl_key_store_generate_key(openssl_keyStore, openssl_keyObject, keyBitLen, options);
    }
#endif /* SSS_HAVE_HOSTCRYPTO_OPENSSL */
    return kStatus_SSS_InvalidArgument;
}

sss_status_t sss_key_store_get_key(
    sss_key_store_t *keyStore, sss_object_t *keyObject, uint8_t *data, size_t *dataLen, size_t *pKeyBitLen)
{
    if (NULL == keyObject) {
        LOG_E("keyObject pointer invalid!");
        return kStatus_SSS_Fail;
    }
#if SSS_HAVE_NX_TYPE
    if (SSS_KEY_STORE_TYPE_IS_NX(keyStore)) {
        sss_nx_key_store_t *nx_keyStore = (sss_nx_key_store_t *)keyStore;
        sss_nx_object_t *nx_keyObject   = (sss_nx_object_t *)keyObject;
        SSS_ASSERT(sizeof(*nx_keyStore) <= sizeof(*keyStore));
        SSS_ASSERT(sizeof(*nx_keyObject) <= sizeof(*keyObject));
        return sss_nx_key_store_get_key(nx_keyStore, nx_keyObject, data, dataLen, pKeyBitLen);
    }
#endif /* SSS_HAVE_NX_TYPE */
#if SSS_HAVE_HOSTCRYPTO_MBEDTLS
    if (SSS_KEY_STORE_TYPE_IS_MBEDTLS(keyStore)) {
        sss_mbedtls_key_store_t *mbedtls_keyStore = (sss_mbedtls_key_store_t *)keyStore;
        sss_mbedtls_object_t *mbedtls_keyObject   = (sss_mbedtls_object_t *)keyObject;
        SSS_ASSERT(sizeof(*mbedtls_keyStore) <= sizeof(*keyStore));
        SSS_ASSERT(sizeof(*mbedtls_keyObject) <= sizeof(*keyObject));
        return sss_mbedtls_key_store_get_key(mbedtls_keyStore, mbedtls_keyObject, data, dataLen, pKeyBitLen);
    }
#endif /* SSS_HAVE_HOSTCRYPTO_MBEDTLS */
#if SSS_HAVE_HOSTCRYPTO_OPENSSL
    if (SSS_KEY_STORE_TYPE_IS_OPENSSL(keyStore)) {
        sss_openssl_key_store_t *openssl_keyStore = (sss_openssl_key_store_t *)keyStore;
        sss_openssl_object_t *openssl_keyObject   = (sss_openssl_object_t *)keyObject;
        SSS_ASSERT(sizeof(*openssl_keyStore) <= sizeof(*keyStore));
        SSS_ASSERT(sizeof(*openssl_keyObject) <= sizeof(*keyObject));
        return sss_openssl_key_store_get_key(openssl_keyStore, openssl_keyObject, data, dataLen, pKeyBitLen);
    }
#endif /* SSS_HAVE_HOSTCRYPTO_OPENSSL */
    return kStatus_SSS_InvalidArgument;
}

sss_status_t sss_key_store_erase_key(sss_key_store_t *keyStore, sss_object_t *keyObject)
{
    if (NULL == keyObject) {
        LOG_E("keyObject pointer invalid!");
        return kStatus_SSS_Fail;
    }
#if SSS_HAVE_NX_TYPE
    if (SSS_KEY_STORE_TYPE_IS_NX(keyStore)) {
        LOG_E("No erase key support!");
        return kStatus_SSS_Fail;
    }
#endif /* SSS_HAVE_NX_TYPE */
#if SSS_HAVE_HOSTCRYPTO_MBEDTLS
    if (SSS_KEY_STORE_TYPE_IS_MBEDTLS(keyStore)) {
        sss_mbedtls_key_store_t *mbedtls_keyStore = (sss_mbedtls_key_store_t *)keyStore;
        sss_mbedtls_object_t *mbedtls_keyObject   = (sss_mbedtls_object_t *)keyObject;
        SSS_ASSERT(sizeof(*mbedtls_keyStore) <= sizeof(*keyStore));
        SSS_ASSERT(sizeof(*mbedtls_keyObject) <= sizeof(*keyObject));
        return sss_mbedtls_key_store_erase_key(mbedtls_keyStore, mbedtls_keyObject);
    }
#endif /* SSS_HAVE_HOSTCRYPTO_MBEDTLS */
#if SSS_HAVE_HOSTCRYPTO_OPENSSL
    if (SSS_KEY_STORE_TYPE_IS_OPENSSL(keyStore)) {
        sss_openssl_key_store_t *openssl_keyStore = (sss_openssl_key_store_t *)keyStore;
        sss_openssl_object_t *openssl_keyObject   = (sss_openssl_object_t *)keyObject;
        SSS_ASSERT(sizeof(*openssl_keyStore) <= sizeof(*keyStore));
        SSS_ASSERT(sizeof(*openssl_keyObject) <= sizeof(*keyObject));
        return sss_openssl_key_store_erase_key(openssl_keyStore, openssl_keyObject);
    }
#endif /* SSS_HAVE_HOSTCRYPTO_OPENSSL */
    return kStatus_SSS_InvalidArgument;
}

void sss_key_store_context_free(sss_key_store_t *keyStore)
{
#if SSS_HAVE_NX_TYPE
    if (SSS_KEY_STORE_TYPE_IS_NX(keyStore)) {
        sss_nx_key_store_t *nx_keyStore = (sss_nx_key_store_t *)keyStore;
        SSS_ASSERT(sizeof(*nx_keyStore) <= sizeof(*keyStore));
        sss_nx_key_store_context_free(nx_keyStore);
    }
#endif /* SSS_HAVE_NX_TYPE */
#if SSS_HAVE_HOSTCRYPTO_MBEDTLS
    if (SSS_KEY_STORE_TYPE_IS_MBEDTLS(keyStore)) {
        sss_mbedtls_key_store_t *mbedtls_keyStore = (sss_mbedtls_key_store_t *)keyStore;
        SSS_ASSERT(sizeof(*mbedtls_keyStore) <= sizeof(*keyStore));
        sss_mbedtls_key_store_context_free(mbedtls_keyStore);
    }
#endif /* SSS_HAVE_HOSTCRYPTO_MBEDTLS */
#if SSS_HAVE_HOSTCRYPTO_OPENSSL
    if (SSS_KEY_STORE_TYPE_IS_OPENSSL(keyStore)) {
        sss_openssl_key_store_t *openssl_keyStore = (sss_openssl_key_store_t *)keyStore;
        SSS_ASSERT(sizeof(*openssl_keyStore) <= sizeof(*keyStore));
        sss_openssl_key_store_context_free(openssl_keyStore);
    }
#endif /* SSS_HAVE_HOSTCRYPTO_OPENSSL */
}

sss_status_t sss_key_object_init(sss_object_t *keyObject, sss_key_store_t *keyStore)
{
    if (NULL == keyObject) {
        LOG_E("keyObject pointer invalid!");
        return kStatus_SSS_Fail;
    }
#if SSS_HAVE_NX_TYPE
    if (SSS_KEY_STORE_TYPE_IS_NX(keyStore)) {
        sss_nx_object_t *nx_keyObject   = (sss_nx_object_t *)keyObject;
        sss_nx_key_store_t *nx_keyStore = (sss_nx_key_store_t *)keyStore;
        SSS_ASSERT(sizeof(*nx_keyObject) <= sizeof(*keyObject));
        SSS_ASSERT(sizeof(*nx_keyStore) <= sizeof(*keyStore));
        return sss_nx_key_object_init(nx_keyObject, nx_keyStore);
    }
#endif /* SSS_HAVE_NX_TYPE */
#if SSS_HAVE_HOSTCRYPTO_MBEDTLS
    if (SSS_KEY_STORE_TYPE_IS_MBEDTLS(keyStore)) {
        sss_mbedtls_object_t *mbedtls_keyObject   = (sss_mbedtls_object_t *)keyObject;
        sss_mbedtls_key_store_t *mbedtls_keyStore = (sss_mbedtls_key_store_t *)keyStore;
        SSS_ASSERT(sizeof(*mbedtls_keyObject) <= sizeof(*keyObject));
        SSS_ASSERT(sizeof(*mbedtls_keyStore) <= sizeof(*keyStore));
        return sss_mbedtls_key_object_init(mbedtls_keyObject, mbedtls_keyStore);
    }
#endif /* SSS_HAVE_HOSTCRYPTO_MBEDTLS */
#if SSS_HAVE_HOSTCRYPTO_OPENSSL
    if (SSS_KEY_STORE_TYPE_IS_OPENSSL(keyStore)) {
        sss_openssl_object_t *openssl_keyObject   = (sss_openssl_object_t *)keyObject;
        sss_openssl_key_store_t *openssl_keyStore = (sss_openssl_key_store_t *)keyStore;
        SSS_ASSERT(sizeof(*openssl_keyObject) <= sizeof(*keyObject));
        SSS_ASSERT(sizeof(*openssl_keyStore) <= sizeof(*keyStore));
        return sss_openssl_key_object_init(openssl_keyObject, openssl_keyStore);
    }
#endif /* SSS_HAVE_HOSTCRYPTO_OPENSSL */
    return kStatus_SSS_InvalidArgument;
}

sss_status_t sss_key_object_allocate_handle(sss_object_t *keyObject,
    uint32_t keyId,
    sss_key_part_t keyPart,
    sss_cipher_type_t cipherType,
    size_t keyByteLenMax,
    uint32_t options)
{
#if SSS_HAVE_NX_TYPE
    if (SSS_OBJECT_TYPE_IS_NX(keyObject)) {
        sss_nx_object_t *nx_keyObject = (sss_nx_object_t *)keyObject;
        SSS_ASSERT(sizeof(*nx_keyObject) <= sizeof(*keyObject));
        return sss_nx_key_object_allocate_handle(nx_keyObject, keyId, keyPart, cipherType, keyByteLenMax, options);
    }
#endif /* SSS_HAVE_NX_TYPE */
#if SSS_HAVE_HOSTCRYPTO_MBEDTLS
    if (SSS_OBJECT_TYPE_IS_MBEDTLS(keyObject)) {
        sss_mbedtls_object_t *mbedtls_keyObject = (sss_mbedtls_object_t *)keyObject;
        SSS_ASSERT(sizeof(*mbedtls_keyObject) <= sizeof(*keyObject));
        return sss_mbedtls_key_object_allocate_handle(
            mbedtls_keyObject, keyId, keyPart, cipherType, keyByteLenMax, options);
    }
#endif /* SSS_HAVE_HOSTCRYPTO_MBEDTLS */
#if SSS_HAVE_HOSTCRYPTO_OPENSSL
    if (SSS_OBJECT_TYPE_IS_OPENSSL(keyObject)) {
        sss_openssl_object_t *openssl_keyObject = (sss_openssl_object_t *)keyObject;
        SSS_ASSERT(sizeof(*openssl_keyObject) <= sizeof(*keyObject));
        return sss_openssl_key_object_allocate_handle(
            openssl_keyObject, keyId, keyPart, cipherType, keyByteLenMax, options);
    }
#endif /* SSS_HAVE_HOSTCRYPTO_OPENSSL */
    return kStatus_SSS_InvalidArgument;
}

sss_status_t sss_key_object_get_handle(sss_object_t *keyObject, sss_cipher_type_t cipherType, uint32_t keyId)
{
#if SSS_HAVE_NX_TYPE
    if (SSS_OBJECT_TYPE_IS_NX(keyObject)) {
        sss_nx_object_t *nx_keyObject = (sss_nx_object_t *)keyObject;
        SSS_ASSERT(sizeof(*nx_keyObject) <= sizeof(*keyObject));
        return sss_nx_key_object_get_handle(nx_keyObject, cipherType, keyId);
    }
#endif /* SSS_HAVE_NX_TYPE */
#if SSS_HAVE_HOSTCRYPTO_MBEDTLS
    if (SSS_OBJECT_TYPE_IS_MBEDTLS(keyObject)) {
        sss_mbedtls_object_t *mbedtls_keyObject = (sss_mbedtls_object_t *)keyObject;
        SSS_ASSERT(sizeof(*mbedtls_keyObject) <= sizeof(*keyObject));
        return sss_mbedtls_key_object_get_handle(mbedtls_keyObject, keyId);
    }
#endif /* SSS_HAVE_HOSTCRYPTO_MBEDTLS */
#if SSS_HAVE_HOSTCRYPTO_OPENSSL
    if (SSS_OBJECT_TYPE_IS_OPENSSL(keyObject)) {
        sss_openssl_object_t *openssl_keyObject = (sss_openssl_object_t *)keyObject;
        SSS_ASSERT(sizeof(*openssl_keyObject) <= sizeof(*keyObject));
        return sss_openssl_key_object_get_handle(openssl_keyObject, keyId);
    }
#endif /* SSS_HAVE_HOSTCRYPTO_OPENSSL */
    return kStatus_SSS_InvalidArgument;
}

void sss_key_object_free(sss_object_t *keyObject)
{
#if SSS_HAVE_NX_TYPE
    if (SSS_OBJECT_TYPE_IS_NX(keyObject)) {
        sss_nx_object_t *nx_keyObject = (sss_nx_object_t *)keyObject;
        SSS_ASSERT(sizeof(*nx_keyObject) <= sizeof(*keyObject));
        sss_nx_key_object_free(nx_keyObject);
    }
#endif /* SSS_HAVE_NX_TYPE */
#if SSS_HAVE_HOSTCRYPTO_MBEDTLS
    if (SSS_OBJECT_TYPE_IS_MBEDTLS(keyObject)) {
        sss_mbedtls_object_t *mbedtls_keyObject = (sss_mbedtls_object_t *)keyObject;
        SSS_ASSERT(sizeof(*mbedtls_keyObject) <= sizeof(*keyObject));
        sss_mbedtls_key_object_free(mbedtls_keyObject);
    }
#endif /* SSS_HAVE_HOSTCRYPTO_MBEDTLS */
#if SSS_HAVE_HOSTCRYPTO_OPENSSL
    if (SSS_OBJECT_TYPE_IS_OPENSSL(keyObject)) {
        sss_openssl_object_t *openssl_keyObject = (sss_openssl_object_t *)keyObject;
        SSS_ASSERT(sizeof(*openssl_keyObject) <= sizeof(*keyObject));
        sss_openssl_key_object_free(openssl_keyObject);
    }
#endif /* SSS_HAVE_HOSTCRYPTO_OPENSSL */
}

sss_status_t sss_derive_key_context_init(sss_derive_key_t *context,
    sss_session_t *session,
    sss_object_t *keyObject,
    sss_algorithm_t algorithm,
    sss_mode_t mode)
{
    if ((NULL == context) || (NULL == keyObject)) {
        LOG_E("context or keyObject pointer invalid!");
        return kStatus_SSS_Fail;
    }
#if SSS_HAVE_NX_TYPE
    if (SSS_SESSION_TYPE_IS_NX(session)) {
        sss_nx_derive_key_t *nx_context = (sss_nx_derive_key_t *)context;
        sss_nx_session_t *nx_session    = (sss_nx_session_t *)session;
        sss_nx_object_t *nx_keyObject   = (sss_nx_object_t *)keyObject;
        SSS_ASSERT(sizeof(*nx_context) <= sizeof(*context));
        SSS_ASSERT(sizeof(*nx_session) <= sizeof(*session));
        SSS_ASSERT(sizeof(*nx_keyObject) <= sizeof(*keyObject));
        return sss_nx_derive_key_context_init(nx_context, nx_session, nx_keyObject, algorithm, mode);
    }
#endif /* SSS_HAVE_NX_TYPE */
#if SSS_HAVE_HOSTCRYPTO_MBEDTLS
    if (SSS_SESSION_TYPE_IS_MBEDTLS(session)) {
        sss_mbedtls_derive_key_t *mbedtls_context = (sss_mbedtls_derive_key_t *)context;
        sss_mbedtls_session_t *mbedtls_session    = (sss_mbedtls_session_t *)session;
        sss_mbedtls_object_t *mbedtls_keyObject   = (sss_mbedtls_object_t *)keyObject;
        SSS_ASSERT(sizeof(*mbedtls_context) <= sizeof(*context));
        SSS_ASSERT(sizeof(*mbedtls_session) <= sizeof(*session));
        SSS_ASSERT(sizeof(*mbedtls_keyObject) <= sizeof(*keyObject));
        return sss_mbedtls_derive_key_context_init(
            mbedtls_context, mbedtls_session, mbedtls_keyObject, algorithm, mode);
    }
#endif /* SSS_HAVE_HOSTCRYPTO_MBEDTLS */
#if SSS_HAVE_HOSTCRYPTO_OPENSSL
    if (SSS_SESSION_TYPE_IS_OPENSSL(session)) {
        sss_openssl_derive_key_t *openssl_context = (sss_openssl_derive_key_t *)context;
        sss_openssl_session_t *openssl_session    = (sss_openssl_session_t *)session;
        sss_openssl_object_t *openssl_keyObject   = (sss_openssl_object_t *)keyObject;
        SSS_ASSERT(sizeof(*openssl_context) <= sizeof(*context));
        SSS_ASSERT(sizeof(*openssl_session) <= sizeof(*session));
        SSS_ASSERT(sizeof(*openssl_keyObject) <= sizeof(*keyObject));
        return sss_openssl_derive_key_context_init(
            openssl_context, openssl_session, openssl_keyObject, algorithm, mode);
    }
#endif /* SSS_HAVE_HOSTCRYPTO_OPENSSL */
    return kStatus_SSS_InvalidArgument;
}

sss_status_t sss_derive_key_dh_one_go(
    sss_derive_key_t *context, sss_object_t *otherPartyKeyObject, sss_object_t *derivedKeyObject)
{
    if ((NULL == otherPartyKeyObject) || (NULL == derivedKeyObject)) {
        LOG_E("otherPartyKeyObject or derivedKeyObject pointer invalid!");
        return kStatus_SSS_Fail;
    }
#if SSS_HAVE_NX_TYPE
    if (SSS_DERIVE_KEY_TYPE_IS_NX(context)) {
        sss_nx_derive_key_t *nx_context         = (sss_nx_derive_key_t *)context;
        sss_nx_object_t *nx_otherPartyKeyObject = (sss_nx_object_t *)otherPartyKeyObject;
        sss_nx_object_t *nx_derivedKeyObject    = (sss_nx_object_t *)derivedKeyObject;
        SSS_ASSERT(sizeof(*nx_context) <= sizeof(*context));
        SSS_ASSERT(sizeof(*nx_otherPartyKeyObject) <= sizeof(*otherPartyKeyObject));
        SSS_ASSERT(sizeof(*nx_derivedKeyObject) <= sizeof(*derivedKeyObject));
        return sss_nx_derive_key_dh_one_go(nx_context, nx_otherPartyKeyObject, nx_derivedKeyObject);
    }
#endif /* SSS_HAVE_NX_TYPE */
#if SSS_HAVE_HOSTCRYPTO_MBEDTLS
    if (SSS_DERIVE_KEY_TYPE_IS_MBEDTLS(context)) {
        sss_mbedtls_derive_key_t *mbedtls_context         = (sss_mbedtls_derive_key_t *)context;
        sss_mbedtls_object_t *mbedtls_otherPartyKeyObject = (sss_mbedtls_object_t *)otherPartyKeyObject;
        sss_mbedtls_object_t *mbedtls_derivedKeyObject    = (sss_mbedtls_object_t *)derivedKeyObject;
        SSS_ASSERT(sizeof(*mbedtls_context) <= sizeof(*context));
        SSS_ASSERT(sizeof(*mbedtls_otherPartyKeyObject) <= sizeof(*otherPartyKeyObject));
        SSS_ASSERT(sizeof(*mbedtls_derivedKeyObject) <= sizeof(*derivedKeyObject));
        return sss_mbedtls_derive_key_dh(mbedtls_context, mbedtls_otherPartyKeyObject, mbedtls_derivedKeyObject);
    }
#endif /* SSS_HAVE_HOSTCRYPTO_MBEDTLS */
#if SSS_HAVE_HOSTCRYPTO_OPENSSL
    if (SSS_DERIVE_KEY_TYPE_IS_OPENSSL(context)) {
        sss_openssl_derive_key_t *openssl_context         = (sss_openssl_derive_key_t *)context;
        sss_openssl_object_t *openssl_otherPartyKeyObject = (sss_openssl_object_t *)otherPartyKeyObject;
        sss_openssl_object_t *openssl_derivedKeyObject    = (sss_openssl_object_t *)derivedKeyObject;
        SSS_ASSERT(sizeof(*openssl_context) <= sizeof(*context));
        SSS_ASSERT(sizeof(*openssl_otherPartyKeyObject) <= sizeof(*otherPartyKeyObject));
        SSS_ASSERT(sizeof(*openssl_derivedKeyObject) <= sizeof(*derivedKeyObject));
        return sss_openssl_derive_key_dh(openssl_context, openssl_otherPartyKeyObject, openssl_derivedKeyObject);
    }
#endif /* SSS_HAVE_HOSTCRYPTO_OPENSSL */
    return kStatus_SSS_InvalidArgument;
}

sss_status_t sss_derive_key_dh_two_step_part1(sss_derive_key_t *context)
{
#if SSS_HAVE_NX_TYPE
    if (SSS_DERIVE_KEY_TYPE_IS_NX(context)) {
        sss_nx_derive_key_t *nx_context = (sss_nx_derive_key_t *)context;
        SSS_ASSERT(sizeof(*nx_context) <= sizeof(*context));
        return sss_nx_derive_key_dh_two_step_part1(nx_context);
    }
#endif /* SSS_HAVE_NX_TYPE */
#if SSS_HAVE_HOSTCRYPTO_MBEDTLS
    if (SSS_DERIVE_KEY_TYPE_IS_MBEDTLS(context)) {
        sss_mbedtls_derive_key_t *mbedtls_context = (sss_mbedtls_derive_key_t *)context;
        SSS_ASSERT(sizeof(*mbedtls_context) <= sizeof(*context));
        return sss_mbedtls_derive_key_dh_two_step_part1(mbedtls_context);
    }
#endif /* SSS_HAVE_HOSTCRYPTO_MBEDTLS */
#if SSS_HAVE_HOSTCRYPTO_OPENSSL
    if (SSS_DERIVE_KEY_TYPE_IS_OPENSSL(context)) {
        sss_openssl_derive_key_t *openssl_context = (sss_openssl_derive_key_t *)context;
        SSS_ASSERT(sizeof(*openssl_context) <= sizeof(*context));
        return sss_openssl_derive_key_dh_two_step_part1(openssl_context);
    }
#endif /* SSS_HAVE_HOSTCRYPTO_OPENSSL */
    return kStatus_SSS_InvalidArgument;
}

sss_status_t sss_derive_key_dh_two_step_part2(
    sss_derive_key_t *context, sss_object_t *otherPartyKeyObject, sss_object_t *derivedKeyObject)
{
    if ((NULL == otherPartyKeyObject) || (NULL == derivedKeyObject)) {
        LOG_E("otherPartyKeyObject or derivedKeyObject pointer invalid!");
        return kStatus_SSS_Fail;
    }
#if SSS_HAVE_NX_TYPE
    if (SSS_DERIVE_KEY_TYPE_IS_NX(context)) {
        sss_nx_derive_key_t *nx_context         = (sss_nx_derive_key_t *)context;
        sss_nx_object_t *nx_otherPartyKeyObject = (sss_nx_object_t *)otherPartyKeyObject;
        sss_nx_object_t *nx_derivedKeyObject    = (sss_nx_object_t *)derivedKeyObject;
        SSS_ASSERT(sizeof(*nx_context) <= sizeof(*context));
        SSS_ASSERT(sizeof(*nx_otherPartyKeyObject) <= sizeof(*otherPartyKeyObject));
        SSS_ASSERT(sizeof(*nx_derivedKeyObject) <= sizeof(*derivedKeyObject));
        return sss_nx_derive_key_dh_two_step_part2(nx_context, nx_otherPartyKeyObject, nx_derivedKeyObject);
    }
#endif /* SSS_HAVE_NX_TYPE */
#if SSS_HAVE_HOSTCRYPTO_MBEDTLS
    if (SSS_DERIVE_KEY_TYPE_IS_MBEDTLS(context)) {
        sss_mbedtls_derive_key_t *mbedtls_context         = (sss_mbedtls_derive_key_t *)context;
        sss_mbedtls_object_t *mbedtls_otherPartyKeyObject = (sss_mbedtls_object_t *)otherPartyKeyObject;
        sss_mbedtls_object_t *mbedtls_derivedKeyObject    = (sss_mbedtls_object_t *)derivedKeyObject;
        SSS_ASSERT(sizeof(*mbedtls_context) <= sizeof(*context));
        SSS_ASSERT(sizeof(*mbedtls_otherPartyKeyObject) <= sizeof(*otherPartyKeyObject));
        SSS_ASSERT(sizeof(*mbedtls_derivedKeyObject) <= sizeof(*derivedKeyObject));
        return sss_mbedtls_derive_key_dh_two_step_part2(
            mbedtls_context, mbedtls_otherPartyKeyObject, mbedtls_derivedKeyObject);
    }
#endif /* SSS_HAVE_HOSTCRYPTO_MBEDTLS */
#if SSS_HAVE_HOSTCRYPTO_OPENSSL
    if (SSS_DERIVE_KEY_TYPE_IS_OPENSSL(context)) {
        sss_openssl_derive_key_t *openssl_context         = (sss_openssl_derive_key_t *)context;
        sss_openssl_object_t *openssl_otherPartyKeyObject = (sss_openssl_object_t *)otherPartyKeyObject;
        sss_openssl_object_t *openssl_derivedKeyObject    = (sss_openssl_object_t *)derivedKeyObject;
        SSS_ASSERT(sizeof(*openssl_context) <= sizeof(*context));
        SSS_ASSERT(sizeof(*openssl_otherPartyKeyObject) <= sizeof(*otherPartyKeyObject));
        SSS_ASSERT(sizeof(*openssl_derivedKeyObject) <= sizeof(*derivedKeyObject));
        return sss_openssl_derive_key_dh_two_step_part2(
            openssl_context, openssl_otherPartyKeyObject, openssl_derivedKeyObject);
    }
#endif /* SSS_HAVE_HOSTCRYPTO_OPENSSL */
    return kStatus_SSS_InvalidArgument;
}

sss_status_t sss_derive_key_one_go(sss_derive_key_t *context,
    sss_object_t *saltObject,
    const uint8_t *info,
    size_t infoLen,
    sss_object_t *derivedKeyObject,
    uint16_t deriveDataLen)
{
#if SSS_HAVE_NX_TYPE
    if (SSS_DERIVE_KEY_TYPE_IS_NX(context)) {
        sss_nx_derive_key_t *nx_context = (sss_nx_derive_key_t *)context;
        SSS_ASSERT(sizeof(*nx_context) <= sizeof(*context));
        return sss_nx_derive_key_one_go(nx_context, saltObject, info, infoLen, derivedKeyObject, deriveDataLen);
    }
#endif /* SSS_HAVE_NX_TYPE */
#if SSS_HAVE_HOSTCRYPTO_MBEDTLS
    if (SSS_DERIVE_KEY_TYPE_IS_MBEDTLS(context)) {
        sss_mbedtls_derive_key_t *mbedtls_context = (sss_mbedtls_derive_key_t *)context;
        SSS_ASSERT(sizeof(*mbedtls_context) <= sizeof(*context));
        return sss_mbedtls_derive_key_one_go(
            mbedtls_context, saltObject, info, infoLen, derivedKeyObject, deriveDataLen);
    }
#endif /* SSS_HAVE_HOSTCRYPTO_MBEDTLS */
#if SSS_HAVE_HOSTCRYPTO_OPENSSL
    if (SSS_DERIVE_KEY_TYPE_IS_OPENSSL(context)) {
        sss_openssl_derive_key_t *openssl_context = (sss_openssl_derive_key_t *)context;
        SSS_ASSERT(sizeof(*openssl_context) <= sizeof(*context));
        return sss_openssl_derive_key_one_go(
            openssl_context, saltObject, info, infoLen, derivedKeyObject, deriveDataLen);
    }
#endif /* SSS_HAVE_HOSTCRYPTO_OPENSSL */
    return kStatus_SSS_InvalidArgument;
}

void sss_derive_key_context_free(sss_derive_key_t *context)
{
#if SSS_HAVE_NX_TYPE
    if (SSS_DERIVE_KEY_TYPE_IS_NX(context)) {
        sss_nx_derive_key_t *nx_context = (sss_nx_derive_key_t *)context;
        SSS_ASSERT(sizeof(*nx_context) <= sizeof(*context));
        sss_nx_derive_key_context_free(nx_context);
    }
#endif /* SSS_HAVE_NX_TYPE */
#if SSS_HAVE_HOSTCRYPTO_MBEDTLS
    if (SSS_DERIVE_KEY_TYPE_IS_MBEDTLS(context)) {
        sss_mbedtls_derive_key_t *mbedtls_context = (sss_mbedtls_derive_key_t *)context;
        SSS_ASSERT(sizeof(*mbedtls_context) <= sizeof(*context));
        sss_mbedtls_derive_key_context_free(mbedtls_context);
    }
#endif /* SSS_HAVE_HOSTCRYPTO_MBEDTLS */
#if SSS_HAVE_HOSTCRYPTO_OPENSSL
    if (SSS_DERIVE_KEY_TYPE_IS_OPENSSL(context)) {
        sss_openssl_derive_key_t *openssl_context = (sss_openssl_derive_key_t *)context;
        SSS_ASSERT(sizeof(*openssl_context) <= sizeof(*context));
        sss_openssl_derive_key_context_free(openssl_context);
    }
#endif /* SSS_HAVE_HOSTCRYPTO_OPENSSL */
}

sss_status_t sss_asymmetric_context_init(sss_asymmetric_t *context,
    sss_session_t *session,
    sss_object_t *keyObject,
    sss_algorithm_t algorithm,
    sss_mode_t mode)
{
    if ((NULL == context) || (NULL == keyObject)) {
        LOG_E("context or keyObject pointer invalid!");
        return kStatus_SSS_Fail;
    }
#if SSS_HAVE_NX_TYPE
    if (SSS_SESSION_TYPE_IS_NX(session)) {
        sss_nx_asymmetric_t *nx_context = (sss_nx_asymmetric_t *)context;
        sss_nx_session_t *nx_session    = (sss_nx_session_t *)session;
        sss_nx_object_t *nx_keyObject   = (sss_nx_object_t *)keyObject;
        SSS_ASSERT(sizeof(*nx_context) <= sizeof(*context));
        SSS_ASSERT(sizeof(*nx_session) <= sizeof(*session));
        SSS_ASSERT(sizeof(*nx_keyObject) <= sizeof(*keyObject));
        return sss_nx_asymmetric_context_init(nx_context, nx_session, nx_keyObject, algorithm, mode);
    }
#endif /* SSS_HAVE_NX_TYPE */
#if SSS_HAVE_HOSTCRYPTO_MBEDTLS
    if (SSS_SESSION_TYPE_IS_MBEDTLS(session)) {
        sss_mbedtls_asymmetric_t *mbedtls_context = (sss_mbedtls_asymmetric_t *)context;
        sss_mbedtls_session_t *mbedtls_session    = (sss_mbedtls_session_t *)session;
        sss_mbedtls_object_t *mbedtls_keyObject   = (sss_mbedtls_object_t *)keyObject;
        SSS_ASSERT(sizeof(*mbedtls_context) <= sizeof(*context));
        SSS_ASSERT(sizeof(*mbedtls_session) <= sizeof(*session));
        SSS_ASSERT(sizeof(*mbedtls_keyObject) <= sizeof(*keyObject));
        return sss_mbedtls_asymmetric_context_init(
            mbedtls_context, mbedtls_session, mbedtls_keyObject, algorithm, mode);
    }
#endif /* SSS_HAVE_HOSTCRYPTO_MBEDTLS */
#if SSS_HAVE_HOSTCRYPTO_OPENSSL
    if (SSS_SESSION_TYPE_IS_OPENSSL(session)) {
        sss_openssl_asymmetric_t *openssl_context = (sss_openssl_asymmetric_t *)context;
        sss_openssl_session_t *openssl_session    = (sss_openssl_session_t *)session;
        sss_openssl_object_t *openssl_keyObject   = (sss_openssl_object_t *)keyObject;
        SSS_ASSERT(sizeof(*openssl_context) <= sizeof(*context));
        SSS_ASSERT(sizeof(*openssl_session) <= sizeof(*session));
        SSS_ASSERT(sizeof(*openssl_keyObject) <= sizeof(*keyObject));
        return sss_openssl_asymmetric_context_init(
            openssl_context, openssl_session, openssl_keyObject, algorithm, mode);
    }
#endif /* SSS_HAVE_HOSTCRYPTO_OPENSSL */
    return kStatus_SSS_InvalidArgument;
}

sss_status_t sss_asymmetric_sign_digest(
    sss_asymmetric_t *context, uint8_t *digest, size_t digestLen, uint8_t *signature, size_t *signatureLen)
{
#if SSS_HAVE_NX_TYPE
    if (SSS_ASYMMETRIC_TYPE_IS_NX(context)) {
        sss_nx_asymmetric_t *nx_context = (sss_nx_asymmetric_t *)context;
        SSS_ASSERT(sizeof(*nx_context) <= sizeof(*context));
        return sss_nx_asymmetric_sign_digest(nx_context, digest, digestLen, signature, signatureLen);
    }
#endif /* SSS_HAVE_NX_TYPE */
#if SSS_HAVE_HOSTCRYPTO_MBEDTLS
    if (SSS_ASYMMETRIC_TYPE_IS_MBEDTLS(context)) {
        sss_mbedtls_asymmetric_t *mbedtls_context = (sss_mbedtls_asymmetric_t *)context;
        SSS_ASSERT(sizeof(*mbedtls_context) <= sizeof(*context));
        return sss_mbedtls_asymmetric_sign_digest(mbedtls_context, digest, digestLen, signature, signatureLen);
    }
#endif /* SSS_HAVE_HOSTCRYPTO_MBEDTLS */
#if SSS_HAVE_HOSTCRYPTO_OPENSSL
    if (SSS_ASYMMETRIC_TYPE_IS_OPENSSL(context)) {
        sss_openssl_asymmetric_t *openssl_context = (sss_openssl_asymmetric_t *)context;
        SSS_ASSERT(sizeof(*openssl_context) <= sizeof(*context));
        return sss_openssl_asymmetric_sign_digest(openssl_context, digest, digestLen, signature, signatureLen);
    }
#endif /* SSS_HAVE_HOSTCRYPTO_OPENSSL */
    return kStatus_SSS_InvalidArgument;
}

sss_status_t sss_asymmetric_verify_digest(
    sss_asymmetric_t *context, uint8_t *digest, size_t digestLen, uint8_t *signature, size_t signatureLen)
{
#if SSS_HAVE_NX_TYPE
    if (SSS_ASYMMETRIC_TYPE_IS_NX(context)) {
        sss_nx_asymmetric_t *nx_context = (sss_nx_asymmetric_t *)context;
        SSS_ASSERT(sizeof(*nx_context) <= sizeof(*context));
        return sss_nx_asymmetric_verify_digest(nx_context, digest, digestLen, signature, signatureLen);
    }
#endif /* SSS_HAVE_NX_TYPE */
#if SSS_HAVE_HOSTCRYPTO_MBEDTLS
    if (SSS_ASYMMETRIC_TYPE_IS_MBEDTLS(context)) {
        sss_mbedtls_asymmetric_t *mbedtls_context = (sss_mbedtls_asymmetric_t *)context;
        SSS_ASSERT(sizeof(*mbedtls_context) <= sizeof(*context));
        return sss_mbedtls_asymmetric_verify_digest(mbedtls_context, digest, digestLen, signature, signatureLen);
    }
#endif /* SSS_HAVE_HOSTCRYPTO_MBEDTLS */
#if SSS_HAVE_HOSTCRYPTO_OPENSSL
    if (SSS_ASYMMETRIC_TYPE_IS_OPENSSL(context)) {
        sss_openssl_asymmetric_t *openssl_context = (sss_openssl_asymmetric_t *)context;
        SSS_ASSERT(sizeof(*openssl_context) <= sizeof(*context));
        return sss_openssl_asymmetric_verify_digest(openssl_context, digest, digestLen, signature, signatureLen);
    }
#endif /* SSS_HAVE_HOSTCRYPTO_OPENSSL */
    return kStatus_SSS_InvalidArgument;
}

sss_status_t sss_asymmetric_sign_one_go(
    sss_asymmetric_t *context, uint8_t *srcData, size_t srcLen, uint8_t *signature, size_t *signatureLen)
{
#if SSS_HAVE_NX_TYPE
    if (SSS_ASYMMETRIC_TYPE_IS_NX(context)) {
        sss_nx_asymmetric_t *nx_context = (sss_nx_asymmetric_t *)context;
        SSS_ASSERT(sizeof(*nx_context) <= sizeof(*context));
        return sss_nx_asymmetric_sign_one_go(nx_context, srcData, srcLen, signature, signatureLen);
    }
#endif /* SSS_HAVE_NX_TYPE */
#if SSS_HAVE_HOSTCRYPTO_MBEDTLS
    if (SSS_ASYMMETRIC_TYPE_IS_MBEDTLS(context)) {
        sss_mbedtls_asymmetric_t *mbedtls_context = (sss_mbedtls_asymmetric_t *)context;
        SSS_ASSERT(sizeof(*mbedtls_context) <= sizeof(*context));
        return sss_mbedtls_asymmetric_sign_one_go(mbedtls_context, srcData, srcLen, signature, signatureLen);
    }
#endif /* SSS_HAVE_HOSTCRYPTO_MBEDTLS */
#if SSS_HAVE_HOSTCRYPTO_OPENSSL
    if (SSS_ASYMMETRIC_TYPE_IS_OPENSSL(context)) {
        sss_openssl_asymmetric_t *openssl_context = (sss_openssl_asymmetric_t *)context;
        SSS_ASSERT(sizeof(*openssl_context) <= sizeof(*context));
        return sss_openssl_asymmetric_sign_one_go(openssl_context, srcData, srcLen, signature, signatureLen);
    }
#endif /* SSS_HAVE_HOSTCRYPTO_OPENSSL */
    return kStatus_SSS_InvalidArgument;
}

sss_status_t sss_asymmetric_sign_init(sss_asymmetric_t *context, uint8_t *srcData, size_t srcLen)
{
#if SSS_HAVE_NX_TYPE
    if (SSS_ASYMMETRIC_TYPE_IS_NX(context)) {
        sss_nx_asymmetric_t *nx_context = (sss_nx_asymmetric_t *)context;
        SSS_ASSERT(sizeof(*nx_context) <= sizeof(*context));
        return sss_nx_asymmetric_sign_init(nx_context, srcData, srcLen);
    }
#endif /* SSS_HAVE_NX_TYPE */
#if SSS_HAVE_HOSTCRYPTO_MBEDTLS
    if (SSS_ASYMMETRIC_TYPE_IS_MBEDTLS(context)) {
        sss_mbedtls_asymmetric_t *mbedtls_context = (sss_mbedtls_asymmetric_t *)context;
        SSS_ASSERT(sizeof(*mbedtls_context) <= sizeof(*context));
        return sss_mbedtls_asymmetric_sign_init(mbedtls_context, srcData, srcLen);
    }
#endif /* SSS_HAVE_HOSTCRYPTO_MBEDTLS */
#if SSS_HAVE_HOSTCRYPTO_OPENSSL
    if (SSS_ASYMMETRIC_TYPE_IS_OPENSSL(context)) {
        sss_openssl_asymmetric_t *openssl_context = (sss_openssl_asymmetric_t *)context;
        SSS_ASSERT(sizeof(*openssl_context) <= sizeof(*context));
        return sss_openssl_asymmetric_sign_init(openssl_context, srcData, srcLen);
    }
#endif /* SSS_HAVE_HOSTCRYPTO_OPENSSL */
    return kStatus_SSS_InvalidArgument;
}

sss_status_t sss_asymmetric_sign_update(sss_asymmetric_t *context, uint8_t *srcData, size_t srcLen)
{
#if SSS_HAVE_NX_TYPE
    if (SSS_ASYMMETRIC_TYPE_IS_NX(context)) {
        sss_nx_asymmetric_t *nx_context = (sss_nx_asymmetric_t *)context;
        SSS_ASSERT(sizeof(*nx_context) <= sizeof(*context));
        return sss_nx_asymmetric_sign_update(nx_context, srcData, srcLen);
    }
#endif /* SSS_HAVE_NX_TYPE */
#if SSS_HAVE_HOSTCRYPTO_MBEDTLS
    if (SSS_ASYMMETRIC_TYPE_IS_MBEDTLS(context)) {
        sss_mbedtls_asymmetric_t *mbedtls_context = (sss_mbedtls_asymmetric_t *)context;
        SSS_ASSERT(sizeof(*mbedtls_context) <= sizeof(*context));
        return sss_mbedtls_asymmetric_sign_update(mbedtls_context, srcData, srcLen);
    }
#endif /* SSS_HAVE_HOSTCRYPTO_MBEDTLS */
#if SSS_HAVE_HOSTCRYPTO_OPENSSL
    if (SSS_ASYMMETRIC_TYPE_IS_OPENSSL(context)) {
        sss_openssl_asymmetric_t *openssl_context = (sss_openssl_asymmetric_t *)context;
        SSS_ASSERT(sizeof(*openssl_context) <= sizeof(*context));
        return sss_openssl_asymmetric_sign_update(openssl_context, srcData, srcLen);
    }
#endif /* SSS_HAVE_HOSTCRYPTO_OPENSSL */
    return kStatus_SSS_InvalidArgument;
}

sss_status_t sss_asymmetric_sign_finish(
    sss_asymmetric_t *context, uint8_t *srcData, size_t srcLen, uint8_t *signature, size_t *signatureLen)
{
#if SSS_HAVE_NX_TYPE
    if (SSS_ASYMMETRIC_TYPE_IS_NX(context)) {
        sss_nx_asymmetric_t *nx_context = (sss_nx_asymmetric_t *)context;
        SSS_ASSERT(sizeof(*nx_context) <= sizeof(*context));
        return sss_nx_asymmetric_sign_finish(nx_context, srcData, srcLen, signature, signatureLen);
    }
#endif /* SSS_HAVE_NX_TYPE */
#if SSS_HAVE_HOSTCRYPTO_MBEDTLS
    if (SSS_ASYMMETRIC_TYPE_IS_MBEDTLS(context)) {
        sss_mbedtls_asymmetric_t *mbedtls_context = (sss_mbedtls_asymmetric_t *)context;
        SSS_ASSERT(sizeof(*mbedtls_context) <= sizeof(*context));
        return sss_mbedtls_asymmetric_sign_finish(mbedtls_context, srcData, srcLen, signature, signatureLen);
    }
#endif /* SSS_HAVE_HOSTCRYPTO_MBEDTLS */
#if SSS_HAVE_HOSTCRYPTO_OPENSSL
    if (SSS_ASYMMETRIC_TYPE_IS_OPENSSL(context)) {
        sss_openssl_asymmetric_t *openssl_context = (sss_openssl_asymmetric_t *)context;
        SSS_ASSERT(sizeof(*openssl_context) <= sizeof(*context));
        return sss_openssl_asymmetric_sign_finish(openssl_context, srcData, srcLen, signature, signatureLen);
    }
#endif /* SSS_HAVE_HOSTCRYPTO_OPENSSL */
    return kStatus_SSS_InvalidArgument;
}

sss_status_t sss_asymmetric_verify_one_go(
    sss_asymmetric_t *context, uint8_t *srcData, size_t srcLen, uint8_t *signature, size_t signatureLen)
{
#if SSS_HAVE_NX_TYPE
    if (SSS_ASYMMETRIC_TYPE_IS_NX(context)) {
        sss_nx_asymmetric_t *nx_context = (sss_nx_asymmetric_t *)context;
        SSS_ASSERT(sizeof(*nx_context) <= sizeof(*context));
        return sss_nx_asymmetric_verify_one_go(nx_context, srcData, srcLen, signature, signatureLen);
    }
#endif /* SSS_HAVE_NX_TYPE */
#if SSS_HAVE_HOSTCRYPTO_MBEDTLS
    if (SSS_ASYMMETRIC_TYPE_IS_MBEDTLS(context)) {
        sss_mbedtls_asymmetric_t *mbedtls_context = (sss_mbedtls_asymmetric_t *)context;
        SSS_ASSERT(sizeof(*mbedtls_context) <= sizeof(*context));
        return sss_mbedtls_asymmetric_verify_one_go(mbedtls_context, srcData, srcLen, signature, signatureLen);
    }
#endif /* SSS_HAVE_HOSTCRYPTO_MBEDTLS */
#if SSS_HAVE_HOSTCRYPTO_OPENSSL
    if (SSS_ASYMMETRIC_TYPE_IS_OPENSSL(context)) {
        sss_openssl_asymmetric_t *openssl_context = (sss_openssl_asymmetric_t *)context;
        SSS_ASSERT(sizeof(*openssl_context) <= sizeof(*context));
        return sss_openssl_asymmetric_verify_one_go(openssl_context, srcData, srcLen, signature, signatureLen);
    }
#endif /* SSS_HAVE_HOSTCRYPTO_OPENSSL */
    return kStatus_SSS_InvalidArgument;
}

sss_status_t sss_asymmetric_verify_init(sss_asymmetric_t *context, uint8_t *srcData, size_t srcLen)
{
#if SSS_HAVE_NX_TYPE
    if (SSS_ASYMMETRIC_TYPE_IS_NX(context)) {
        sss_nx_asymmetric_t *nx_context = (sss_nx_asymmetric_t *)context;
        SSS_ASSERT(sizeof(*nx_context) <= sizeof(*context));
        return sss_nx_asymmetric_verify_init(nx_context, srcData, srcLen);
    }
#endif /* SSS_HAVE_NX_TYPE */

#if SSS_HAVE_HOSTCRYPTO_MBEDTLS
    if (SSS_ASYMMETRIC_TYPE_IS_MBEDTLS(context)) {
        sss_mbedtls_asymmetric_t *mbedtls_context = (sss_mbedtls_asymmetric_t *)context;
        SSS_ASSERT(sizeof(*mbedtls_context) <= sizeof(*context));
        return sss_mbedtls_asymmetric_verify_init(mbedtls_context, srcData, srcLen);
    }
#endif /* SSS_HAVE_HOSTCRYPTO_MBEDTLS */
#if SSS_HAVE_HOSTCRYPTO_OPENSSL
    if (SSS_ASYMMETRIC_TYPE_IS_OPENSSL(context)) {
        sss_openssl_asymmetric_t *openssl_context = (sss_openssl_asymmetric_t *)context;
        SSS_ASSERT(sizeof(*openssl_context) <= sizeof(*context));
        return sss_openssl_asymmetric_verify_init(openssl_context, srcData, srcLen);
    }
#endif /*SSS_HAVE_HOSTCRYPTO_OPENSSL */
    return kStatus_SSS_InvalidArgument;
}

sss_status_t sss_asymmetric_verify_update(sss_asymmetric_t *context, uint8_t *srcData, size_t srcLen)
{
#if SSS_HAVE_NX_TYPE
    if (SSS_ASYMMETRIC_TYPE_IS_NX(context)) {
        sss_nx_asymmetric_t *nx_context = (sss_nx_asymmetric_t *)context;
        SSS_ASSERT(sizeof(*nx_context) <= sizeof(*context));
        return sss_nx_asymmetric_verify_update(nx_context, srcData, srcLen);
    }
#endif /* SSS_HAVE_NX_TYPE */
#if SSS_HAVE_HOSTCRYPTO_MBEDTLS
    if (SSS_ASYMMETRIC_TYPE_IS_MBEDTLS(context)) {
        sss_mbedtls_asymmetric_t *mbedtls_context = (sss_mbedtls_asymmetric_t *)context;
        SSS_ASSERT(sizeof(*mbedtls_context) <= sizeof(*context));
        return sss_mbedtls_asymmetric_verify_update(mbedtls_context, srcData, srcLen);
    }
#endif /* SSS_HAVE_HOSTCRYPTO_MBEDTLS */
#if SSS_HAVE_HOSTCRYPTO_OPENSSL
    if (SSS_ASYMMETRIC_TYPE_IS_OPENSSL(context)) {
        sss_openssl_asymmetric_t *openssl_context = (sss_openssl_asymmetric_t *)context;
        SSS_ASSERT(sizeof(*openssl_context) <= sizeof(*context));
        return sss_openssl_asymmetric_verify_update(openssl_context, srcData, srcLen);
    }
#endif /* SSS_HAVE_HOSTCRYPTO_OPENSSL */
    return kStatus_SSS_InvalidArgument;
}

sss_status_t sss_asymmetric_verify_finish(
    sss_asymmetric_t *context, uint8_t *srcData, size_t srcLen, uint8_t *signature, size_t signatureLen)
{
#if SSS_HAVE_NX_TYPE
    if (SSS_ASYMMETRIC_TYPE_IS_NX(context)) {
        sss_nx_asymmetric_t *nx_context = (sss_nx_asymmetric_t *)context;
        SSS_ASSERT(sizeof(*nx_context) <= sizeof(*context));
        return sss_nx_asymmetric_verify_finish(nx_context, srcData, srcLen, signature, signatureLen);
    }
#endif /* SSS_HAVE_NX_TYPE */
#if SSS_HAVE_HOSTCRYPTO_MBEDTLS
    if (SSS_ASYMMETRIC_TYPE_IS_MBEDTLS(context)) {
        sss_mbedtls_asymmetric_t *mbedtls_context = (sss_mbedtls_asymmetric_t *)context;
        SSS_ASSERT(sizeof(*mbedtls_context) <= sizeof(*context));
        return sss_mbedtls_asymmetric_verify_finish(mbedtls_context, srcData, srcLen, signature, signatureLen);
    }
#endif /* SSS_HAVE_HOSTCRYPTO_MBEDTLS */
#if SSS_HAVE_HOSTCRYPTO_OPENSSL
    if (SSS_ASYMMETRIC_TYPE_IS_OPENSSL(context)) {
        sss_openssl_asymmetric_t *openssl_context = (sss_openssl_asymmetric_t *)context;
        SSS_ASSERT(sizeof(*openssl_context) <= sizeof(*context));
        return sss_openssl_asymmetric_verify_finish(openssl_context, srcData, srcLen, signature, signatureLen);
    }
#endif /* SSS_HAVE_HOSTCRYPTO_OPENSSL */
    return kStatus_SSS_InvalidArgument;
}

void sss_asymmetric_context_free(sss_asymmetric_t *context)
{
#if SSS_HAVE_NX_TYPE
    if (SSS_ASYMMETRIC_TYPE_IS_NX(context)) {
        sss_nx_asymmetric_t *nx_context = (sss_nx_asymmetric_t *)context;
        SSS_ASSERT(sizeof(*nx_context) <= sizeof(*context));
        sss_nx_asymmetric_context_free(nx_context);
    }
#endif /* SSS_HAVE_NX_TYPE */
#if SSS_HAVE_HOSTCRYPTO_MBEDTLS
    if (SSS_ASYMMETRIC_TYPE_IS_MBEDTLS(context)) {
        sss_mbedtls_asymmetric_t *mbedtls_context = (sss_mbedtls_asymmetric_t *)context;
        SSS_ASSERT(sizeof(*mbedtls_context) <= sizeof(*context));
        sss_mbedtls_asymmetric_context_free(mbedtls_context);
    }
#endif /* SSS_HAVE_HOSTCRYPTO_MBEDTLS */
#if SSS_HAVE_HOSTCRYPTO_OPENSSL
    if (SSS_ASYMMETRIC_TYPE_IS_OPENSSL(context)) {
        sss_openssl_asymmetric_t *openssl_context = (sss_openssl_asymmetric_t *)context;
        SSS_ASSERT(sizeof(*openssl_context) <= sizeof(*context));
        sss_openssl_asymmetric_context_free(openssl_context);
    }
#endif /* SSS_HAVE_HOSTCRYPTO_OPENSSL */
}

sss_status_t sss_symmetric_context_init(sss_symmetric_t *context,
    sss_session_t *session,
    sss_object_t *keyObject,
    sss_algorithm_t algorithm,
    sss_mode_t mode)
{
    if ((NULL == context) || (NULL == keyObject)) {
        LOG_E("context or keyObject pointer invalid!");
        return kStatus_SSS_Fail;
    }
    if (SSS_SESSION_TYPE_IS_NX(session)) {
        sss_nx_symmetric_t *nx_context = (sss_nx_symmetric_t *)context;
        sss_nx_session_t *nx_session   = (sss_nx_session_t *)session;
        sss_nx_object_t *nx_keyObject  = (sss_nx_object_t *)keyObject;
        SSS_ASSERT(sizeof(*nx_context) <= sizeof(*context));
        SSS_ASSERT(sizeof(*nx_session) <= sizeof(*session));
        SSS_ASSERT(sizeof(*nx_keyObject) <= sizeof(*keyObject));
        return sss_nx_symmetric_context_init(nx_context, nx_session, nx_keyObject, algorithm, mode);
    }
#if SSS_HAVE_HOSTCRYPTO_MBEDTLS
    if (SSS_SESSION_TYPE_IS_MBEDTLS(session)) {
        sss_mbedtls_symmetric_t *mbedtls_context = (sss_mbedtls_symmetric_t *)context;
        sss_mbedtls_session_t *mbedtls_session   = (sss_mbedtls_session_t *)session;
        sss_mbedtls_object_t *mbedtls_keyObject  = (sss_mbedtls_object_t *)keyObject;
        SSS_ASSERT(sizeof(*mbedtls_context) <= sizeof(*context));
        SSS_ASSERT(sizeof(*mbedtls_session) <= sizeof(*session));
        SSS_ASSERT(sizeof(*mbedtls_keyObject) <= sizeof(*keyObject));
        return sss_mbedtls_symmetric_context_init(mbedtls_context, mbedtls_session, mbedtls_keyObject, algorithm, mode);
    }
#endif /* SSS_HAVE_HOSTCRYPTO_MBEDTLS */
#if SSS_HAVE_HOSTCRYPTO_OPENSSL
    if (SSS_SESSION_TYPE_IS_OPENSSL(session)) {
        sss_openssl_symmetric_t *openssl_context = (sss_openssl_symmetric_t *)context;
        sss_openssl_session_t *openssl_session   = (sss_openssl_session_t *)session;
        sss_openssl_object_t *openssl_keyObject  = (sss_openssl_object_t *)keyObject;
        SSS_ASSERT(sizeof(*openssl_context) <= sizeof(*context));
        SSS_ASSERT(sizeof(*openssl_session) <= sizeof(*session));
        SSS_ASSERT(sizeof(*openssl_keyObject) <= sizeof(*keyObject));
        return sss_openssl_symmetric_context_init(openssl_context, openssl_session, openssl_keyObject, algorithm, mode);
    }
#endif /* SSS_HAVE_HOSTCRYPTO_OPENSSL */
    return kStatus_SSS_InvalidArgument;
}

sss_status_t sss_cipher_one_go(
    sss_symmetric_t *context, uint8_t *iv, size_t ivLen, const uint8_t *srcData, uint8_t *destData, size_t dataLen)
{
    LOG_D("FN: %s", __FUNCTION__);
    LOG_MAU8_D(" Input: IV", iv, ivLen);
    LOG_MAU8_D(" Input: srcData", srcData, dataLen);
    if (SSS_SYMMETRIC_TYPE_IS_NX(context)) {
        sss_nx_symmetric_t *nx_context = (sss_nx_symmetric_t *)context;
        SSS_ASSERT(sizeof(*nx_context) <= sizeof(*context));
        return sss_nx_cipher_one_go(nx_context, iv, ivLen, srcData, destData, dataLen);
    }
#if SSS_HAVE_HOSTCRYPTO_MBEDTLS
    if (SSS_SYMMETRIC_TYPE_IS_MBEDTLS(context)) {
        sss_mbedtls_symmetric_t *mbedtls_context = (sss_mbedtls_symmetric_t *)context;
        SSS_ASSERT(sizeof(*mbedtls_context) <= sizeof(*context));
        return sss_mbedtls_cipher_one_go(mbedtls_context, iv, ivLen, srcData, destData, dataLen);
    }
#endif /* SSS_HAVE_HOSTCRYPTO_MBEDTLS */
#if SSS_HAVE_HOSTCRYPTO_OPENSSL
    if (SSS_SYMMETRIC_TYPE_IS_OPENSSL(context)) {
        sss_openssl_symmetric_t *openssl_context = (sss_openssl_symmetric_t *)context;
        SSS_ASSERT(sizeof(*openssl_context) <= sizeof(*context));
        return sss_openssl_cipher_one_go(openssl_context, iv, ivLen, srcData, destData, dataLen);
    }
#endif /* SSS_HAVE_HOSTCRYPTO_OPENSSL */
    return kStatus_SSS_InvalidArgument;
}

sss_status_t sss_cipher_init(sss_symmetric_t *context, uint8_t *iv, size_t ivLen)
{
    if (SSS_SYMMETRIC_TYPE_IS_NX(context)) {
        sss_nx_symmetric_t *nx_context = (sss_nx_symmetric_t *)context;
        SSS_ASSERT(sizeof(*nx_context) <= sizeof(*context));
        return sss_nx_cipher_init(nx_context, iv, ivLen);
    }
#if SSS_HAVE_HOSTCRYPTO_MBEDTLS
    if (SSS_SYMMETRIC_TYPE_IS_MBEDTLS(context)) {
        sss_mbedtls_symmetric_t *mbedtls_context = (sss_mbedtls_symmetric_t *)context;
        SSS_ASSERT(sizeof(*mbedtls_context) <= sizeof(*context));
        return sss_mbedtls_cipher_init(mbedtls_context, iv, ivLen);
    }
#endif /* SSS_HAVE_HOSTCRYPTO_MBEDTLS */
#if SSS_HAVE_HOSTCRYPTO_OPENSSL
    if (SSS_SYMMETRIC_TYPE_IS_OPENSSL(context)) {
        sss_openssl_symmetric_t *openssl_context = (sss_openssl_symmetric_t *)context;
        SSS_ASSERT(sizeof(*openssl_context) <= sizeof(*context));
        return sss_openssl_cipher_init(openssl_context, iv, ivLen);
    }
#endif /* SSS_HAVE_HOSTCRYPTO_OPENSSL */
    return kStatus_SSS_InvalidArgument;
}

sss_status_t sss_cipher_update(
    sss_symmetric_t *context, const uint8_t *srcData, size_t srcLen, uint8_t *destData, size_t *destLen)
{
    if (SSS_SYMMETRIC_TYPE_IS_NX(context)) {
        sss_nx_symmetric_t *nx_context = (sss_nx_symmetric_t *)context;
        SSS_ASSERT(sizeof(*nx_context) <= sizeof(*context));
        return sss_nx_cipher_update(nx_context, srcData, srcLen, destData, destLen);
    }
#if SSS_HAVE_HOSTCRYPTO_MBEDTLS
    if (SSS_SYMMETRIC_TYPE_IS_MBEDTLS(context)) {
        sss_mbedtls_symmetric_t *mbedtls_context = (sss_mbedtls_symmetric_t *)context;
        SSS_ASSERT(sizeof(*mbedtls_context) <= sizeof(*context));
        return sss_mbedtls_cipher_update(mbedtls_context, srcData, srcLen, destData, destLen);
    }
#endif /* SSS_HAVE_HOSTCRYPTO_MBEDTLS */
#if SSS_HAVE_HOSTCRYPTO_OPENSSL
    if (SSS_SYMMETRIC_TYPE_IS_OPENSSL(context)) {
        sss_openssl_symmetric_t *openssl_context = (sss_openssl_symmetric_t *)context;
        SSS_ASSERT(sizeof(*openssl_context) <= sizeof(*context));
        return sss_openssl_cipher_update(openssl_context, srcData, srcLen, destData, destLen);
    }
#endif /* SSS_HAVE_HOSTCRYPTO_OPENSSL */
    return kStatus_SSS_InvalidArgument;
}

sss_status_t sss_cipher_finish(
    sss_symmetric_t *context, const uint8_t *srcData, size_t srcLen, uint8_t *destData, size_t *destLen)
{
    if (SSS_SYMMETRIC_TYPE_IS_NX(context)) {
        sss_nx_symmetric_t *nx_context = (sss_nx_symmetric_t *)context;
        SSS_ASSERT(sizeof(*nx_context) <= sizeof(*context));
        return sss_nx_cipher_finish(nx_context, srcData, srcLen, destData, destLen);
    }
#if SSS_HAVE_HOSTCRYPTO_MBEDTLS
    if (SSS_SYMMETRIC_TYPE_IS_MBEDTLS(context)) {
        sss_mbedtls_symmetric_t *mbedtls_context = (sss_mbedtls_symmetric_t *)context;
        SSS_ASSERT(sizeof(*mbedtls_context) <= sizeof(*context));
        return sss_mbedtls_cipher_finish(mbedtls_context, srcData, srcLen, destData, destLen);
    }
#endif /* SSS_HAVE_HOSTCRYPTO_MBEDTLS */
#if SSS_HAVE_HOSTCRYPTO_OPENSSL
    if (SSS_SYMMETRIC_TYPE_IS_OPENSSL(context)) {
        sss_openssl_symmetric_t *openssl_context = (sss_openssl_symmetric_t *)context;
        SSS_ASSERT(sizeof(*openssl_context) <= sizeof(*context));
        return sss_openssl_cipher_finish(openssl_context, srcData, srcLen, destData, destLen);
    }
#endif /* SSS_HAVE_HOSTCRYPTO_OPENSSL */
    return kStatus_SSS_InvalidArgument;
}

sss_status_t sss_aead_context_init(
    sss_aead_t *context, sss_session_t *session, sss_object_t *keyObject, sss_algorithm_t algorithm, sss_mode_t mode)
{
    if ((NULL == context) || (NULL == keyObject)) {
        LOG_E("context or keyObject pointer invalid!");
        return kStatus_SSS_Fail;
    }
    if (SSS_SESSION_TYPE_IS_NX(session)) {
        sss_nx_aead_t *nx_context     = (sss_nx_aead_t *)context;
        sss_nx_session_t *nx_session  = (sss_nx_session_t *)session;
        sss_nx_object_t *nx_keyObject = (sss_nx_object_t *)keyObject;
        SSS_ASSERT(sizeof(*nx_context) <= sizeof(*context));
        SSS_ASSERT(sizeof(*nx_session) <= sizeof(*session));
        SSS_ASSERT(sizeof(*nx_keyObject) <= sizeof(*keyObject));
        return sss_nx_aead_context_init(nx_context, nx_session, nx_keyObject, algorithm, mode);
    }
#if SSS_HAVE_HOSTCRYPTO_MBEDTLS
    if (SSS_SESSION_TYPE_IS_MBEDTLS(session)) {
        sss_mbedtls_aead_t *mbedtls_context     = (sss_mbedtls_aead_t *)context;
        sss_mbedtls_session_t *mbedtls_session  = (sss_mbedtls_session_t *)session;
        sss_mbedtls_object_t *mbedtls_keyObject = (sss_mbedtls_object_t *)keyObject;
        SSS_ASSERT(sizeof(*mbedtls_context) <= sizeof(*context));
        SSS_ASSERT(sizeof(*mbedtls_session) <= sizeof(*session));
        SSS_ASSERT(sizeof(*mbedtls_keyObject) <= sizeof(*keyObject));
        return sss_mbedtls_aead_context_init(mbedtls_context, mbedtls_session, mbedtls_keyObject, algorithm, mode);
    }
#endif /* SSS_HAVE_HOSTCRYPTO_MBEDTLS */
#if SSS_HAVE_HOSTCRYPTO_OPENSSL
    if (SSS_SESSION_TYPE_IS_OPENSSL(session)) {
        sss_openssl_aead_t *openssl_context     = (sss_openssl_aead_t *)context;
        sss_openssl_session_t *openssl_session  = (sss_openssl_session_t *)session;
        sss_openssl_object_t *openssl_keyObject = (sss_openssl_object_t *)keyObject;
        SSS_ASSERT(sizeof(*openssl_context) <= sizeof(*context));
        SSS_ASSERT(sizeof(*openssl_session) <= sizeof(*session));
        SSS_ASSERT(sizeof(*openssl_keyObject) <= sizeof(*keyObject));
        return sss_openssl_aead_context_init(openssl_context, openssl_session, openssl_keyObject, algorithm, mode);
    }
#endif /* SSS_HAVE_HOSTCRYPTO_OPENSSL */
    return kStatus_SSS_InvalidArgument;
}

sss_status_t sss_aead_one_go(sss_aead_t *context,
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
    if (SSS_SYMMETRIC_TYPE_IS_NX(context)) {
        sss_nx_aead_t *nx_context = (sss_nx_aead_t *)context;
        SSS_ASSERT(sizeof(*nx_context) <= sizeof(*context));
        return sss_nx_aead_one_go(nx_context, srcData, destData, size, nonce, nonceLen, aad, aadLen, tag, tagLen);
    }
#if SSS_HAVE_HOSTCRYPTO_MBEDTLS
    if (SSS_SYMMETRIC_TYPE_IS_MBEDTLS(context)) {
        sss_mbedtls_aead_t *mbedtls_context = (sss_mbedtls_aead_t *)context;
        SSS_ASSERT(sizeof(*mbedtls_context) <= sizeof(*context));
        return sss_mbedtls_aead_one_go(
            mbedtls_context, srcData, destData, size, nonce, nonceLen, aad, aadLen, tag, tagLen);
    }
#endif /* SSS_HAVE_HOSTCRYPTO_MBEDTLS */
#if SSS_HAVE_HOSTCRYPTO_OPENSSL
    if (SSS_SYMMETRIC_TYPE_IS_OPENSSL(context)) {
        sss_openssl_aead_t *openssl_context = (sss_openssl_aead_t *)context;
        SSS_ASSERT(sizeof(*openssl_context) <= sizeof(*context));
        return sss_openssl_aead_one_go(
            openssl_context, srcData, destData, size, nonce, nonceLen, aad, aadLen, tag, tagLen);
    }
#endif /* SSS_HAVE_HOSTCRYPTO_OPENSSL */
    return kStatus_SSS_InvalidArgument;
}

sss_status_t sss_aead_init(
    sss_aead_t *context, uint8_t *nonce, size_t nonceLen, size_t tagLen, size_t aadLen, size_t payloadLen)
{
    if (SSS_SYMMETRIC_TYPE_IS_NX(context)) {
        sss_nx_aead_t *nx_context = (sss_nx_aead_t *)context;
        SSS_ASSERT(sizeof(*nx_context) <= sizeof(*context));
        return sss_nx_aead_init(nx_context, nonce, nonceLen, tagLen, aadLen, payloadLen);
    }
#if SSS_HAVE_HOSTCRYPTO_MBEDTLS
    if (SSS_SYMMETRIC_TYPE_IS_MBEDTLS(context)) {
        sss_mbedtls_aead_t *mbedtls_context = (sss_mbedtls_aead_t *)context;
        SSS_ASSERT(sizeof(*mbedtls_context) <= sizeof(*context));
        return sss_mbedtls_aead_init(mbedtls_context, nonce, nonceLen, tagLen, aadLen, payloadLen);
    }
#endif /* SSS_HAVE_HOSTCRYPTO_MBEDTLS */
#if SSS_HAVE_HOSTCRYPTO_OPENSSL
    if (SSS_SYMMETRIC_TYPE_IS_OPENSSL(context)) {
        sss_openssl_aead_t *openssl_context = (sss_openssl_aead_t *)context;
        SSS_ASSERT(sizeof(*openssl_context) <= sizeof(*context));
        return sss_openssl_aead_init(openssl_context, nonce, nonceLen, tagLen, aadLen, payloadLen);
    }
#endif /* SSS_HAVE_HOSTCRYPTO_OPENSSL */
    return kStatus_SSS_InvalidArgument;
}

sss_status_t sss_aead_update_aad(sss_aead_t *context, const uint8_t *aadData, size_t aadDataLen)
{
    if (SSS_SYMMETRIC_TYPE_IS_NX(context)) {
        sss_nx_aead_t *nx_context = (sss_nx_aead_t *)context;
        SSS_ASSERT(sizeof(*nx_context) <= sizeof(*context));
        return sss_nx_aead_update_aad(nx_context, aadData, aadDataLen);
    }
#if SSS_HAVE_HOSTCRYPTO_MBEDTLS
    if (SSS_SYMMETRIC_TYPE_IS_MBEDTLS(context)) {
        sss_mbedtls_aead_t *mbedtls_context = (sss_mbedtls_aead_t *)context;
        SSS_ASSERT(sizeof(*mbedtls_context) <= sizeof(*context));
        return sss_mbedtls_aead_update_aad(mbedtls_context, aadData, aadDataLen);
    }
#endif /* SSS_HAVE_HOSTCRYPTO_MBEDTLS */
#if SSS_HAVE_HOSTCRYPTO_OPENSSL
    if (SSS_SYMMETRIC_TYPE_IS_OPENSSL(context)) {
        sss_openssl_aead_t *openssl_context = (sss_openssl_aead_t *)context;
        SSS_ASSERT(sizeof(*openssl_context) <= sizeof(*context));
        return sss_openssl_aead_update_aad(openssl_context, aadData, aadDataLen);
    }
#endif /* SSS_HAVE_HOSTCRYPTO_OPENSSL */
    return kStatus_SSS_InvalidArgument;
}

sss_status_t sss_aead_update(
    sss_aead_t *context, const uint8_t *srcData, size_t srcLen, uint8_t *destData, size_t *destLen)
{
    if (SSS_SYMMETRIC_TYPE_IS_NX(context)) {
        sss_nx_aead_t *nx_context = (sss_nx_aead_t *)context;
        SSS_ASSERT(sizeof(*nx_context) <= sizeof(*context));
        return sss_nx_aead_update(nx_context, srcData, srcLen, destData, destLen);
    }
#if SSS_HAVE_HOSTCRYPTO_MBEDTLS
    if (SSS_SYMMETRIC_TYPE_IS_MBEDTLS(context)) {
        sss_mbedtls_aead_t *mbedtls_context = (sss_mbedtls_aead_t *)context;
        SSS_ASSERT(sizeof(*mbedtls_context) <= sizeof(*context));
        return sss_mbedtls_aead_update(mbedtls_context, srcData, srcLen, destData, destLen);
    }
#endif /* SSS_HAVE_HOSTCRYPTO_MBEDTLS */
#if SSS_HAVE_HOSTCRYPTO_OPENSSL
    if (SSS_SYMMETRIC_TYPE_IS_OPENSSL(context)) {
        sss_openssl_aead_t *openssl_context = (sss_openssl_aead_t *)context;
        SSS_ASSERT(sizeof(*openssl_context) <= sizeof(*context));
        return sss_openssl_aead_update(openssl_context, srcData, srcLen, destData, destLen);
    }
#endif /* SSS_HAVE_HOSTCRYPTO_OPENSSL */
    return kStatus_SSS_InvalidArgument;
}

sss_status_t sss_aead_finish(sss_aead_t *context,
    const uint8_t *srcData,
    size_t srcLen,
    uint8_t *destData,
    size_t *destLen,
    uint8_t *tag,
    size_t *tagLen)
{
    if (SSS_SYMMETRIC_TYPE_IS_NX(context)) {
        sss_nx_aead_t *nx_context = (sss_nx_aead_t *)context;
        SSS_ASSERT(sizeof(*nx_context) <= sizeof(*context));
        return sss_nx_aead_finish(nx_context, srcData, srcLen, destData, destLen, tag, tagLen);
    }
#if SSS_HAVE_HOSTCRYPTO_MBEDTLS
    if (SSS_SYMMETRIC_TYPE_IS_MBEDTLS(context)) {
        sss_mbedtls_aead_t *mbedtls_context = (sss_mbedtls_aead_t *)context;
        SSS_ASSERT(sizeof(*mbedtls_context) <= sizeof(*context));
        return sss_mbedtls_aead_finish(mbedtls_context, srcData, srcLen, destData, destLen, tag, tagLen);
    }
#endif /* SSS_HAVE_HOSTCRYPTO_MBEDTLS */
#if SSS_HAVE_HOSTCRYPTO_OPENSSL
    if (SSS_SYMMETRIC_TYPE_IS_OPENSSL(context)) {
        sss_openssl_aead_t *openssl_context = (sss_openssl_aead_t *)context;
        SSS_ASSERT(sizeof(*openssl_context) <= sizeof(*context));
        return sss_openssl_aead_finish(openssl_context, srcData, srcLen, destData, destLen, tag, tagLen);
    }
#endif /* SSS_HAVE_HOSTCRYPTO_OPENSSL */
    return kStatus_SSS_InvalidArgument;
}

void sss_aead_context_free(sss_aead_t *context)
{
    LOG_D("FN: %s", __FUNCTION__);
    if (SSS_SYMMETRIC_TYPE_IS_NX(context)) {
        sss_nx_aead_t *nx_context = (sss_nx_aead_t *)context;
        SSS_ASSERT(sizeof(*nx_context) <= sizeof(*context));
        sss_nx_aead_context_free(nx_context);
    }
#if SSS_HAVE_HOSTCRYPTO_MBEDTLS
    if (SSS_SYMMETRIC_TYPE_IS_MBEDTLS(context)) {
        sss_mbedtls_aead_t *mbedtls_context = (sss_mbedtls_aead_t *)context;
        SSS_ASSERT(sizeof(*mbedtls_context) <= sizeof(*context));
        sss_mbedtls_aead_context_free(mbedtls_context);
    }
#endif /* SSS_HAVE_HOSTCRYPTO_MBEDTLS */
#if SSS_HAVE_HOSTCRYPTO_OPENSSL
    if (SSS_SYMMETRIC_TYPE_IS_OPENSSL(context)) {
        sss_openssl_aead_t *openssl_context = (sss_openssl_aead_t *)context;
        SSS_ASSERT(sizeof(*openssl_context) <= sizeof(*context));
        sss_openssl_aead_context_free(openssl_context);
    }
#endif /* SSS_HAVE_HOSTCRYPTO_OPENSSL */
}

void sss_symmetric_context_free(sss_symmetric_t *context)
{
    LOG_D("FN: %s", __FUNCTION__);
    if (SSS_SYMMETRIC_TYPE_IS_NX(context)) {
        sss_nx_symmetric_t *nx_context = (sss_nx_symmetric_t *)context;
        SSS_ASSERT(sizeof(*nx_context) <= sizeof(*context));
        sss_nx_symmetric_context_free(nx_context);
    }
#if SSS_HAVE_HOSTCRYPTO_MBEDTLS
    if (SSS_SYMMETRIC_TYPE_IS_MBEDTLS(context)) {
        sss_mbedtls_symmetric_t *mbedtls_context = (sss_mbedtls_symmetric_t *)context;
        SSS_ASSERT(sizeof(*mbedtls_context) <= sizeof(*context));
        sss_mbedtls_symmetric_context_free(mbedtls_context);
    }
#endif /* SSS_HAVE_HOSTCRYPTO_MBEDTLS */
#if SSS_HAVE_HOSTCRYPTO_OPENSSL
    if (SSS_SYMMETRIC_TYPE_IS_OPENSSL(context)) {
        sss_openssl_symmetric_t *openssl_context = (sss_openssl_symmetric_t *)context;
        SSS_ASSERT(sizeof(*openssl_context) <= sizeof(*context));
        sss_openssl_symmetric_context_free(openssl_context);
    }
#endif /* SSS_HAVE_HOSTCRYPTO_OPENSSL */
}

sss_status_t sss_digest_context_init(
    sss_digest_t *context, sss_session_t *session, sss_algorithm_t algorithm, sss_mode_t mode)
{
    if ((NULL == context)) {
        LOG_E("context pointer invalid!");
        return kStatus_SSS_Fail;
    }
#if SSS_HAVE_NX_TYPE
    if (SSS_SESSION_TYPE_IS_NX(session)) {
        sss_nx_digest_t *nx_context  = (sss_nx_digest_t *)context;
        sss_nx_session_t *nx_session = (sss_nx_session_t *)session;
        SSS_ASSERT(sizeof(*nx_context) <= sizeof(*context));
        SSS_ASSERT(sizeof(*nx_session) <= sizeof(*session));
        return sss_nx_digest_context_init(nx_context, nx_session, algorithm, mode);
    }
#endif /* SSS_HAVE_NX_TYPE */
#if SSS_HAVE_HOSTCRYPTO_MBEDTLS
    if (SSS_SESSION_TYPE_IS_MBEDTLS(session)) {
        sss_mbedtls_digest_t *mbedtls_context  = (sss_mbedtls_digest_t *)context;
        sss_mbedtls_session_t *mbedtls_session = (sss_mbedtls_session_t *)session;
        SSS_ASSERT(sizeof(*mbedtls_context) <= sizeof(*context));
        SSS_ASSERT(sizeof(*mbedtls_session) <= sizeof(*session));
        return sss_mbedtls_digest_context_init(mbedtls_context, mbedtls_session, algorithm, mode);
    }
#endif /* SSS_HAVE_HOSTCRYPTO_MBEDTLS */
#if SSS_HAVE_HOSTCRYPTO_OPENSSL
    if (SSS_SESSION_TYPE_IS_OPENSSL(session)) {
        sss_openssl_digest_t *openssl_context  = (sss_openssl_digest_t *)context;
        sss_openssl_session_t *openssl_session = (sss_openssl_session_t *)session;
        SSS_ASSERT(sizeof(*openssl_context) <= sizeof(*context));
        SSS_ASSERT(sizeof(*openssl_session) <= sizeof(*session));
        return sss_openssl_digest_context_init(openssl_context, openssl_session, algorithm, mode);
    }
#endif /* SSS_HAVE_HOSTCRYPTO_OPENSSL */
    return kStatus_SSS_InvalidArgument;
}

sss_status_t sss_digest_one_go(
    sss_digest_t *context, const uint8_t *message, size_t messageLen, uint8_t *digest, size_t *digestLen)
{
#if SSS_HAVE_NX_TYPE
    if (SSS_DIGEST_TYPE_IS_NX(context)) {
        sss_nx_digest_t *nx_context = (sss_nx_digest_t *)context;
        SSS_ASSERT(sizeof(*nx_context) <= sizeof(*context));
        return sss_nx_digest_one_go(nx_context, message, messageLen, digest, digestLen);
    }
#endif /* SSS_HAVE_NX_TYPE */
#if SSS_HAVE_HOSTCRYPTO_MBEDTLS
    if (SSS_DIGEST_TYPE_IS_MBEDTLS(context)) {
        sss_mbedtls_digest_t *mbedtls_context = (sss_mbedtls_digest_t *)context;
        SSS_ASSERT(sizeof(*mbedtls_context) <= sizeof(*context));
        return sss_mbedtls_digest_one_go(mbedtls_context, message, messageLen, digest, digestLen);
    }
#endif /* SSS_HAVE_HOSTCRYPTO_MBEDTLS */
#if SSS_HAVE_HOSTCRYPTO_OPENSSL
    if (SSS_DIGEST_TYPE_IS_OPENSSL(context)) {
        sss_openssl_digest_t *openssl_context = (sss_openssl_digest_t *)context;
        SSS_ASSERT(sizeof(*openssl_context) <= sizeof(*context));
        return sss_openssl_digest_one_go(openssl_context, message, messageLen, digest, digestLen);
    }
#endif /* SSS_HAVE_HOSTCRYPTO_OPENSSL */
    return kStatus_SSS_InvalidArgument;
}

sss_status_t sss_digest_init(sss_digest_t *context)
{
#if SSS_HAVE_NX_TYPE
    if (SSS_DIGEST_TYPE_IS_NX(context)) {
        sss_nx_digest_t *nx_context = (sss_nx_digest_t *)context;
        SSS_ASSERT(sizeof(*nx_context) <= sizeof(*context));
        return sss_nx_digest_init(nx_context);
    }
#endif /* SSS_HAVE_NX_TYPE */
#if SSS_HAVE_HOSTCRYPTO_MBEDTLS
    if (SSS_DIGEST_TYPE_IS_MBEDTLS(context)) {
        sss_mbedtls_digest_t *mbedtls_context = (sss_mbedtls_digest_t *)context;
        SSS_ASSERT(sizeof(*mbedtls_context) <= sizeof(*context));
        return sss_mbedtls_digest_init(mbedtls_context);
    }
#endif /* SSS_HAVE_HOSTCRYPTO_MBEDTLS */
#if SSS_HAVE_HOSTCRYPTO_OPENSSL
    if (SSS_DIGEST_TYPE_IS_OPENSSL(context)) {
        sss_openssl_digest_t *openssl_context = (sss_openssl_digest_t *)context;
        SSS_ASSERT(sizeof(*openssl_context) <= sizeof(*context));
        return sss_openssl_digest_init(openssl_context);
    }
#endif /* SSS_HAVE_HOSTCRYPTO_OPENSSL */
    return kStatus_SSS_InvalidArgument;
}

sss_status_t sss_digest_update(sss_digest_t *context, const uint8_t *message, size_t messageLen)
{
#if SSS_HAVE_NX_TYPE
    if (SSS_DIGEST_TYPE_IS_NX(context)) {
        sss_nx_digest_t *nx_context = (sss_nx_digest_t *)context;
        SSS_ASSERT(sizeof(*nx_context) <= sizeof(*context));
        return sss_nx_digest_update(nx_context, message, messageLen);
    }
#endif /* SSS_HAVE_NX_TYPE */
#if SSS_HAVE_HOSTCRYPTO_MBEDTLS
    if (SSS_DIGEST_TYPE_IS_MBEDTLS(context)) {
        sss_mbedtls_digest_t *mbedtls_context = (sss_mbedtls_digest_t *)context;
        SSS_ASSERT(sizeof(*mbedtls_context) <= sizeof(*context));
        return sss_mbedtls_digest_update(mbedtls_context, message, messageLen);
    }
#endif /* SSS_HAVE_HOSTCRYPTO_MBEDTLS */
#if SSS_HAVE_HOSTCRYPTO_OPENSSL
    if (SSS_DIGEST_TYPE_IS_OPENSSL(context)) {
        sss_openssl_digest_t *openssl_context = (sss_openssl_digest_t *)context;
        SSS_ASSERT(sizeof(*openssl_context) <= sizeof(*context));
        return sss_openssl_digest_update(openssl_context, message, messageLen);
    }
#endif /* SSS_HAVE_HOSTCRYPTO_OPENSSL */
    return kStatus_SSS_InvalidArgument;
}

sss_status_t sss_digest_finish(sss_digest_t *context, uint8_t *digest, size_t *digestLen)
{
#if SSS_HAVE_NX_TYPE
    if (SSS_DIGEST_TYPE_IS_NX(context)) {
        sss_nx_digest_t *nx_context = (sss_nx_digest_t *)context;
        SSS_ASSERT(sizeof(*nx_context) <= sizeof(*context));
        return sss_nx_digest_finish(nx_context, digest, digestLen);
    }
#endif /* SSS_HAVE_NX_TYPE */
#if SSS_HAVE_HOSTCRYPTO_MBEDTLS
    if (SSS_DIGEST_TYPE_IS_MBEDTLS(context)) {
        sss_mbedtls_digest_t *mbedtls_context = (sss_mbedtls_digest_t *)context;
        SSS_ASSERT(sizeof(*mbedtls_context) <= sizeof(*context));
        return sss_mbedtls_digest_finish(mbedtls_context, digest, digestLen);
    }
#endif /* SSS_HAVE_HOSTCRYPTO_MBEDTLS */
#if SSS_HAVE_HOSTCRYPTO_OPENSSL
    if (SSS_DIGEST_TYPE_IS_OPENSSL(context)) {
        sss_openssl_digest_t *openssl_context = (sss_openssl_digest_t *)context;
        SSS_ASSERT(sizeof(*openssl_context) <= sizeof(*context));
        return sss_openssl_digest_finish(openssl_context, digest, digestLen);
    }
#endif /* SSS_HAVE_HOSTCRYPTO_OPENSSL */
    return kStatus_SSS_InvalidArgument;
}

void sss_digest_context_free(sss_digest_t *context)
{
#if SSS_HAVE_NX_TYPE
    if (SSS_DIGEST_TYPE_IS_NX(context)) {
        sss_nx_digest_t *nx_context = (sss_nx_digest_t *)context;
        SSS_ASSERT(sizeof(*nx_context) <= sizeof(*context));
        sss_nx_digest_context_free(nx_context);
    }
#endif /* SSS_HAVE_NX_TYPE */
#if SSS_HAVE_HOSTCRYPTO_MBEDTLS
    if (SSS_DIGEST_TYPE_IS_MBEDTLS(context)) {
        sss_mbedtls_digest_t *mbedtls_context = (sss_mbedtls_digest_t *)context;
        SSS_ASSERT(sizeof(*mbedtls_context) <= sizeof(*context));
        sss_mbedtls_digest_context_free(mbedtls_context);
    }
#endif /* SSS_HAVE_HOSTCRYPTO_MBEDTLS */
#if SSS_HAVE_HOSTCRYPTO_OPENSSL
    if (SSS_DIGEST_TYPE_IS_OPENSSL(context)) {
        sss_openssl_digest_t *openssl_context = (sss_openssl_digest_t *)context;
        SSS_ASSERT(sizeof(*openssl_context) <= sizeof(*context));
        sss_openssl_digest_context_free(openssl_context);
    }
#endif /* SSS_HAVE_HOSTCRYPTO_OPENSSL */
}

sss_status_t sss_rng_context_init(sss_rng_context_t *context, sss_session_t *session)
{
    LOG_D("FN: %s", __FUNCTION__);
    if ((NULL == context)) {
        LOG_E("context pointer invalid!");
        return kStatus_SSS_Fail;
    }
#if SSS_HAVE_NX_TYPE
    if (SSS_SESSION_TYPE_IS_NX(session)) {
        sss_nx_rng_context_t *nx_context = (sss_nx_rng_context_t *)context;
        sss_nx_session_t *nx_session     = (sss_nx_session_t *)session;
        SSS_ASSERT(sizeof(*nx_context) <= sizeof(*context));
        SSS_ASSERT(sizeof(*nx_session) <= sizeof(*session));
        return sss_nx_rng_context_init(nx_context, nx_session);
    }
#endif /* SSS_HAVE_NX_TYPE */
#if SSS_HAVE_HOSTCRYPTO_MBEDTLS
    if (SSS_SESSION_TYPE_IS_MBEDTLS(session)) {
        sss_mbedtls_rng_context_t *mbedtls_context = (sss_mbedtls_rng_context_t *)context;
        sss_mbedtls_session_t *mbedtls_session     = (sss_mbedtls_session_t *)session;
        SSS_ASSERT(sizeof(*mbedtls_context) <= sizeof(*context));
        SSS_ASSERT(sizeof(*mbedtls_session) <= sizeof(*session));
        return sss_mbedtls_rng_context_init(mbedtls_context, mbedtls_session);
    }
#endif /* SSS_HAVE_HOSTCRYPTO_MBEDTLS */
#if SSS_HAVE_HOSTCRYPTO_OPENSSL
    if (SSS_SESSION_TYPE_IS_OPENSSL(session)) {
        sss_openssl_rng_context_t *openssl_context = (sss_openssl_rng_context_t *)context;
        sss_openssl_session_t *openssl_session     = (sss_openssl_session_t *)session;
        SSS_ASSERT(sizeof(*openssl_context) <= sizeof(*context));
        SSS_ASSERT(sizeof(*openssl_session) <= sizeof(*session));
        return sss_openssl_rng_context_init(openssl_context, openssl_session);
    }
#endif /* SSS_HAVE_HOSTCRYPTO_OPENSSL */
    return kStatus_SSS_InvalidArgument;
}

sss_status_t sss_rng_get_random(sss_rng_context_t *context, uint8_t *random_data, size_t dataLen)
{
    LOG_D("FN: %s", __FUNCTION__);
#if SSS_HAVE_NX_TYPE
    if (SSS_RNG_CONTEXT_TYPE_IS_NX(context)) {
        sss_nx_rng_context_t *nx_context = (sss_nx_rng_context_t *)context;
        SSS_ASSERT(sizeof(*nx_context) <= sizeof(*context));
        return sss_nx_rng_get_random(nx_context, random_data, dataLen);
    }
#endif /* SSS_HAVE_NX_TYPE */
#if SSS_HAVE_HOSTCRYPTO_MBEDTLS
    if (SSS_RNG_CONTEXT_TYPE_IS_MBEDTLS(context)) {
        sss_mbedtls_rng_context_t *mbedtls_context = (sss_mbedtls_rng_context_t *)context;
        SSS_ASSERT(sizeof(*mbedtls_context) <= sizeof(*context));
        return sss_mbedtls_rng_get_random(mbedtls_context, random_data, dataLen);
    }
#endif /* SSS_HAVE_HOSTCRYPTO_MBEDTLS */
#if SSS_HAVE_HOSTCRYPTO_OPENSSL
    if (SSS_RNG_CONTEXT_TYPE_IS_OPENSSL(context)) {
        sss_openssl_rng_context_t *openssl_context = (sss_openssl_rng_context_t *)context;
        SSS_ASSERT(sizeof(*openssl_context) <= sizeof(*context));
        return sss_openssl_rng_get_random(openssl_context, random_data, dataLen);
    }
#endif /* SSS_HAVE_HOSTCRYPTO_OPENSSL */
    return kStatus_SSS_InvalidArgument;
}

sss_status_t sss_rng_context_free(sss_rng_context_t *context)
{
    LOG_D("FN: %s", __FUNCTION__);
#if SSS_HAVE_NX_TYPE
    if (SSS_RNG_CONTEXT_TYPE_IS_NX(context)) {
        sss_nx_rng_context_t *nx_context = (sss_nx_rng_context_t *)context;
        SSS_ASSERT(sizeof(*nx_context) <= sizeof(*context));
        return sss_nx_rng_context_free(nx_context);
    }
#endif /* SSS_HAVE_NX_TYPE */
#if SSS_HAVE_HOSTCRYPTO_MBEDTLS
    if (SSS_RNG_CONTEXT_TYPE_IS_MBEDTLS(context)) {
        sss_mbedtls_rng_context_t *mbedtls_context = (sss_mbedtls_rng_context_t *)context;
        SSS_ASSERT(sizeof(*mbedtls_context) <= sizeof(*context));
        return sss_mbedtls_rng_context_free(mbedtls_context);
    }
#endif /* SSS_HAVE_HOSTCRYPTO_MBEDTLS */
#if SSS_HAVE_HOSTCRYPTO_OPENSSL
    if (SSS_RNG_CONTEXT_TYPE_IS_OPENSSL(context)) {
        sss_openssl_rng_context_t *openssl_context = (sss_openssl_rng_context_t *)context;
        SSS_ASSERT(sizeof(*openssl_context) <= sizeof(*context));
        return sss_openssl_rng_context_free(openssl_context);
    }
#endif /* SSS_HAVE_HOSTCRYPTO_OPENSSL */
    return kStatus_SSS_InvalidArgument;
}

sss_status_t sss_mac_context_init(
    sss_mac_t *context, sss_session_t *session, sss_object_t *keyObject, sss_algorithm_t algorithm, sss_mode_t mode)
{
    if ((NULL == context) || (NULL == keyObject)) {
        LOG_E("context or keyObject pointer invalid!");
        return kStatus_SSS_Fail;
    }
#if SSS_HAVE_NX_TYPE
    if (SSS_SESSION_TYPE_IS_NX(session)) {
        sss_nx_mac_t *nx_context      = (sss_nx_mac_t *)context;
        sss_nx_session_t *nx_session  = (sss_nx_session_t *)session;
        sss_nx_object_t *nx_keyObject = (sss_nx_object_t *)keyObject;
        SSS_ASSERT(sizeof(*nx_context) <= sizeof(*context));
        SSS_ASSERT(sizeof(*nx_session) <= sizeof(*session));
        SSS_ASSERT(sizeof(*nx_keyObject) <= sizeof(*keyObject));
        return sss_nx_mac_context_init(nx_context, nx_session, nx_keyObject, algorithm, mode);
    }
#endif /* SSS_HAVE_NX_TYPE */
#if SSS_HAVE_HOSTCRYPTO_MBEDTLS
    if (SSS_SESSION_TYPE_IS_MBEDTLS(session)) {
        sss_mbedtls_mac_t *mbedtls_context      = (sss_mbedtls_mac_t *)context;
        sss_mbedtls_session_t *mbedtls_session  = (sss_mbedtls_session_t *)session;
        sss_mbedtls_object_t *mbedtls_keyObject = (sss_mbedtls_object_t *)keyObject;
        SSS_ASSERT(sizeof(*mbedtls_context) <= sizeof(*context));
        SSS_ASSERT(sizeof(*mbedtls_session) <= sizeof(*session));
        SSS_ASSERT(sizeof(*mbedtls_keyObject) <= sizeof(*keyObject));
        return sss_mbedtls_mac_context_init(mbedtls_context, mbedtls_session, mbedtls_keyObject, algorithm, mode);
    }
#endif /* SSS_HAVE_HOSTCRYPTO_MBEDTLS */
#if SSS_HAVE_HOSTCRYPTO_OPENSSL
    if (SSS_SESSION_TYPE_IS_OPENSSL(session)) {
        sss_openssl_mac_t *openssl_context      = (sss_openssl_mac_t *)context;
        sss_openssl_session_t *openssl_session  = (sss_openssl_session_t *)session;
        sss_openssl_object_t *openssl_keyObject = (sss_openssl_object_t *)keyObject;
        SSS_ASSERT(sizeof(*openssl_context) <= sizeof(*context));
        SSS_ASSERT(sizeof(*openssl_session) <= sizeof(*session));
        SSS_ASSERT(sizeof(*openssl_keyObject) <= sizeof(*keyObject));
        return sss_openssl_mac_context_init(openssl_context, openssl_session, openssl_keyObject, algorithm, mode);
    }
#endif /* SSS_HAVE_HOSTCRYPTO_OPENSSL */
    return kStatus_SSS_InvalidArgument;
}

sss_status_t sss_mac_one_go(sss_mac_t *context, const uint8_t *message, size_t messageLen, uint8_t *mac, size_t *macLen)
{
#if SSS_HAVE_NX_TYPE
    if (SSS_MAC_TYPE_IS_NX(context)) {
        sss_nx_mac_t *nx_context = (sss_nx_mac_t *)context;
        SSS_ASSERT(sizeof(*nx_context) <= sizeof(*context));
        return sss_nx_mac_one_go(nx_context, message, messageLen, mac, macLen);
    }
#endif /* SSS_HAVE_NX_TYPE */
#if SSS_HAVE_HOSTCRYPTO_MBEDTLS
    if (SSS_MAC_TYPE_IS_MBEDTLS(context)) {
        sss_mbedtls_mac_t *mbedtls_context = (sss_mbedtls_mac_t *)context;
        SSS_ASSERT(sizeof(*mbedtls_context) <= sizeof(*context));
        return sss_mbedtls_mac_one_go(mbedtls_context, message, messageLen, mac, macLen);
    }
#endif /* SSS_HAVE_HOSTCRYPTO_MBEDTLS */
#if SSS_HAVE_HOSTCRYPTO_OPENSSL
    if (SSS_MAC_TYPE_IS_OPENSSL(context)) {
        sss_openssl_mac_t *openssl_context = (sss_openssl_mac_t *)context;
        SSS_ASSERT(sizeof(*openssl_context) <= sizeof(*context));
        return sss_openssl_mac_one_go(openssl_context, message, messageLen, mac, macLen);
    }
#endif /* SSS_HAVE_HOSTCRYPTO_OPENSSL */
    return kStatus_SSS_InvalidArgument;
}

sss_status_t sss_mac_init(sss_mac_t *context)
{
#if SSS_HAVE_NX_TYPE
    if (SSS_MAC_TYPE_IS_NX(context)) {
        sss_nx_mac_t *nx_context = (sss_nx_mac_t *)context;
        SSS_ASSERT(sizeof(*nx_context) <= sizeof(*context));
        return sss_nx_mac_init(nx_context);
    }
#endif /* SSS_HAVE_NX_TYPE */
#if SSS_HAVE_HOSTCRYPTO_MBEDTLS
    if (SSS_MAC_TYPE_IS_MBEDTLS(context)) {
        sss_mbedtls_mac_t *mbedtls_context = (sss_mbedtls_mac_t *)context;
        SSS_ASSERT(sizeof(*mbedtls_context) <= sizeof(*context));
        return sss_mbedtls_mac_init(mbedtls_context);
    }
#endif /* SSS_HAVE_HOSTCRYPTO_MBEDTLS */
#if SSS_HAVE_HOSTCRYPTO_OPENSSL
    if (SSS_MAC_TYPE_IS_OPENSSL(context)) {
        sss_openssl_mac_t *openssl_context = (sss_openssl_mac_t *)context;
        SSS_ASSERT(sizeof(*openssl_context) <= sizeof(*context));
        return sss_openssl_mac_init(openssl_context);
    }
#endif /* SSS_HAVE_HOSTCRYPTO_OPENSSL */
    return kStatus_SSS_InvalidArgument;
}

sss_status_t sss_mac_update(sss_mac_t *context, const uint8_t *message, size_t messageLen)
{
#if SSS_HAVE_NX_TYPE
    if (SSS_MAC_TYPE_IS_NX(context)) {
        sss_nx_mac_t *nx_context = (sss_nx_mac_t *)context;
        SSS_ASSERT(sizeof(*nx_context) <= sizeof(*context));
        return sss_nx_mac_update(nx_context, message, messageLen);
    }
#endif /* SSS_HAVE_NX_TYPE */
#if SSS_HAVE_HOSTCRYPTO_MBEDTLS
    if (SSS_MAC_TYPE_IS_MBEDTLS(context)) {
        sss_mbedtls_mac_t *mbedtls_context = (sss_mbedtls_mac_t *)context;
        SSS_ASSERT(sizeof(*mbedtls_context) <= sizeof(*context));
        return sss_mbedtls_mac_update(mbedtls_context, message, messageLen);
    }
#endif /* SSS_HAVE_HOSTCRYPTO_MBEDTLS */
#if SSS_HAVE_HOSTCRYPTO_OPENSSL
    if (SSS_MAC_TYPE_IS_OPENSSL(context)) {
        sss_openssl_mac_t *openssl_context = (sss_openssl_mac_t *)context;
        SSS_ASSERT(sizeof(*openssl_context) <= sizeof(*context));
        return sss_openssl_mac_update(openssl_context, message, messageLen);
    }
#endif /* SSS_HAVE_HOSTCRYPTO_OPENSSL */
    return kStatus_SSS_InvalidArgument;
}

sss_status_t sss_mac_finish(sss_mac_t *context, uint8_t *mac, size_t *macLen)
{
#if SSS_HAVE_NX_TYPE
    if (SSS_MAC_TYPE_IS_NX(context)) {
        sss_nx_mac_t *nx_context = (sss_nx_mac_t *)context;
        SSS_ASSERT(sizeof(*nx_context) <= sizeof(*context));
        return sss_nx_mac_finish(nx_context, mac, macLen);
    }
#endif /* SSS_HAVE_NX_TYPE */
#if SSS_HAVE_HOSTCRYPTO_MBEDTLS
    if (SSS_MAC_TYPE_IS_MBEDTLS(context)) {
        sss_mbedtls_mac_t *mbedtls_context = (sss_mbedtls_mac_t *)context;
        SSS_ASSERT(sizeof(*mbedtls_context) <= sizeof(*context));
        return sss_mbedtls_mac_finish(mbedtls_context, mac, macLen);
    }
#endif /* SSS_HAVE_HOSTCRYPTO_MBEDTLS */
#if SSS_HAVE_HOSTCRYPTO_OPENSSL
    if (SSS_MAC_TYPE_IS_OPENSSL(context)) {
        sss_openssl_mac_t *openssl_context = (sss_openssl_mac_t *)context;
        SSS_ASSERT(sizeof(*openssl_context) <= sizeof(*context));
        return sss_openssl_mac_finish(openssl_context, mac, macLen);
    }
#endif /* SSS_HAVE_HOSTCRYPTO_OPENSSL */
    return kStatus_SSS_InvalidArgument;
}

void sss_mac_context_free(sss_mac_t *context)
{
#if SSS_HAVE_NX_TYPE
    if (SSS_MAC_TYPE_IS_NX(context)) {
        sss_nx_mac_t *nx_context = (sss_nx_mac_t *)context;
        SSS_ASSERT(sizeof(*nx_context) <= sizeof(*context));
        sss_nx_mac_context_free(nx_context);
    }
#endif /* SSS_HAVE_NX_TYPE */
#if SSS_HAVE_HOSTCRYPTO_MBEDTLS
    if (SSS_MAC_TYPE_IS_MBEDTLS(context)) {
        sss_mbedtls_mac_t *mbedtls_context = (sss_mbedtls_mac_t *)context;
        SSS_ASSERT(sizeof(*mbedtls_context) <= sizeof(*context));
        sss_mbedtls_mac_context_free(mbedtls_context);
    }
#endif /* SSS_HAVE_HOSTCRYPTO_MBEDTLS */
#if SSS_HAVE_HOSTCRYPTO_OPENSSL
    if (SSS_MAC_TYPE_IS_OPENSSL(context)) {
        sss_openssl_mac_t *openssl_context = (sss_openssl_mac_t *)context;
        SSS_ASSERT(sizeof(*openssl_context) <= sizeof(*context));
        sss_openssl_mac_context_free(openssl_context);
    }
#endif /* SSS_HAVE_HOSTCRYPTO_OPENSSL */
}

#endif /* SSS_HAVE_SSS > 1 */
