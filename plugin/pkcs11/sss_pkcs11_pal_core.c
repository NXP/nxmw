/*
 * Amazon FreeRTOS PKCS#11 for NXP Secure element
 * Copyright (C) 2017 Amazon.com, Inc. or its affiliates.  All Rights Reserved.
 * Copyright 2024-2025 NXP
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 * the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 * IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * http://aws.amazon.com/freertos
 * http://www.FreeRTOS.org
 */

/* ********************** Include files ********************** */
#include "sss_pkcs11_pal.h"
#include <limits.h>

/* ********************** Constants ********************** */
#undef DEBUG_PKCS11_PAL
#define pkcs11SLOT_ID 1
#define PKCS11_MAX_DIGEST_INPUT_DATA 200
#define PKCS11_MAX_HMAC_INPUT_DATA 200
#define PKCS11_MAX_INPUT_DATA 200

/* ********************** Global variables ********************** */
int sessionCount         = 0;
bool cryptokiInitialized = false;
bool mutex_initialised   = false;


/**
 * @brief PKCS#11 interface functions implemented by this Cryptoki module.
 */
CK_FUNCTION_LIST prvP11FunctionList = {{CRYPTOKI_VERSION_MAJOR, CRYPTOKI_VERSION_MINOR},
    C_Initialize,
    C_Finalize,
    C_GetInfo,
    C_GetFunctionList,
    C_GetSlotList,
    C_GetSlotInfo,
    C_GetTokenInfo,
    C_GetMechanismList,
    C_GetMechanismInfo,
    C_InitToken,
    C_InitPIN,
    C_SetPIN,
    C_OpenSession,
    C_CloseSession,
    C_CloseAllSessions,
    C_GetSessionInfo,
    C_GetOperationState,
    C_SetOperationState,
    C_Login,
    C_Logout,
    C_CreateObject,
    C_CopyObject,
    C_DestroyObject,
    C_GetObjectSize,
    C_GetAttributeValue,
    C_SetAttributeValue,
    C_FindObjectsInit,
    C_FindObjects,
    C_FindObjectsFinal,
    C_EncryptInit,
    C_Encrypt,
    C_EncryptUpdate,
    C_EncryptFinal,
    C_DecryptInit,
    C_Decrypt,
    C_DecryptUpdate,
    C_DecryptFinal,
    C_DigestInit,
    C_Digest,
    C_DigestUpdate,
    C_DigestKey,
    C_DigestFinal,
    C_SignInit,
    C_Sign,
    C_SignUpdate,
    C_SignFinal,
    C_SignRecoverInit,
    C_SignRecover,
    C_VerifyInit,
    C_Verify,
    C_VerifyUpdate,
    C_VerifyFinal,
    C_VerifyRecoverInit,
    C_VerifyRecover,
    C_DigestEncryptUpdate,
    C_DecryptDigestUpdate,
    C_SignEncryptUpdate,
    C_DecryptVerifyUpdate,
    C_GenerateKey,
    C_GenerateKeyPair,
    C_WrapKey,
    C_UnwrapKey,
    C_DeriveKey,
    C_SeedRandom,
    C_GenerateRandom,
    C_GetFunctionStatus,
    C_CancelFunction,
    C_WaitForSlotEvent};

/**
 * @brief Maps an opaque caller session handle into its internal state structure.
 */
P11SessionPtr_t prvSessionPointerFromHandle(CK_SESSION_HANDLE xSession)
{
    return (P11SessionPtr_t)(uintptr_t)xSession;
}

/**
 * @brief Load the default key and certificate from storage.
 */
CK_RV pkcs11_get_attribute_parameter_index(
    CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_ATTRIBUTE_TYPE type, CK_ULONG_PTR index)
{
    CK_RV xResult      = CKR_ARGUMENTS_BAD;
    CK_ULONG i         = 0;
    CK_BBOOL foundType = CK_FALSE;

    ENSURE_OR_RETURN_ON_ERROR(NULL != pTemplate, CKR_ARGUMENTS_BAD);

    for (i = 0; i < ulCount; i++) {
        if (pTemplate[i].type == type) {
            foundType = CK_TRUE;
            xResult   = CKR_OK;
            break;
        }
    }
    if (foundType) {
        *index = i;
    }
    return xResult;
}

/**
 * @brief Query the list of interface function pointers.
 */
CK_DEFINE_FUNCTION(CK_RV, C_GetFunctionList)
(CK_FUNCTION_LIST_PTR_PTR ppxFunctionList)
{
    CK_RV xResult = CKR_OK;
    LOG_D("%s", __FUNCTION__);

    if (NULL == ppxFunctionList) {
        xResult = CKR_ARGUMENTS_BAD;
    }
    else {
        *ppxFunctionList = &prvP11FunctionList;
    }

    return xResult;
}

/**
 * @brief Initialize the Cryptoki module for use.
 */
CK_DEFINE_FUNCTION(CK_RV, C_Initialize)(CK_VOID_PTR pvInitArgs)
{
    CK_RV status = CKR_OK;

    LOG_D("%s", __FUNCTION__);

    ENSURE_OR_RETURN_ON_ERROR(cryptokiInitialized == false, CKR_CRYPTOKI_ALREADY_INITIALIZED);

    if (pvInitArgs) {
        CK_C_INITIALIZE_ARGS_PTR initArgs = (CK_C_INITIALIZE_ARGS_PTR)(pvInitArgs);

        ENSURE_OR_RETURN_ON_ERROR(initArgs->pReserved == NULL, CKR_ARGUMENTS_BAD);

        if (initArgs->flags & CKF_OS_LOCKING_OK) {
            // Application will call from multiple threads. Library should use locks.
            if ((initArgs->CreateMutex) && (initArgs->DestroyMutex) && (initArgs->LockMutex) &&
                (initArgs->UnlockMutex)) {
                // If mutex pointers are not null, library can use either OS locking or provided functions
                LOG_D("Warning: Init Mutex patameters are ignored. Using OS locking \n");
            }
            else if (!(initArgs->CreateMutex) && !(initArgs->DestroyMutex) && !(initArgs->LockMutex) &&
                     !(initArgs->UnlockMutex)) {
                // If mutex pointers are null, library must use OS locking.
                LOG_D("Info: Using OS locking \n");
            }
        }

        if (initArgs->flags & CKF_LIBRARY_CANT_CREATE_OS_THREADS) {
            // no threads are required.
            status = CKR_OK;
        }
    }

    if (!mutex_initialised) {
        if (sss_pkcs11_mutex_init() != 0) {
            status = CKR_CANT_LOCK;
            goto exit;
        }
        mutex_initialised = true;
    }

    cryptokiInitialized = true;
exit:
    return status;
}

/**
 * @brief Finishes a multiple-part digesting operation.
 */
CK_DEFINE_FUNCTION(CK_RV, C_DigestFinal)
(CK_SESSION_HANDLE xSession, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen)
{
    CK_RV xResult = CKR_FUNCTION_FAILED;
    LOG_D("%s", __FUNCTION__);
    uint8_t digest[64]      = {0}; /* MAX-SHA512 */
    size_t digestLen        = sizeof(digest);
    sss_status_t sss_status = kStatus_SSS_Fail;
    size_t outputLen        = 0;

    P11SessionPtr_t pxSession = prvSessionPointerFromHandle(xSession);

    ENSURE_OR_RETURN_ON_ERROR(pxSession != NULL, CKR_SESSION_HANDLE_INVALID);

    if (pulDigestLen == NULL) {
        pxSession->xOperationInProgress = pkcs11NO_OPERATION;
        xResult                         = CKR_ARGUMENTS_BAD;
        goto exit;
    }

    switch (pxSession->xOperationInProgress) {
    case CKM_SHA256:
        outputLen = 32;
        break;
    case CKM_SHA384:
        outputLen = 48;
        break;
    default:
        xResult = CKR_OPERATION_NOT_INITIALIZED;
        goto exit;
    }

    if (pDigest == NULL) {
        *pulDigestLen = outputLen;
        return CKR_OK;
    }

    else {
        if (*pulDigestLen < outputLen) {
            /*required length should be returned*/
            *pulDigestLen = outputLen;
            return CKR_BUFFER_TOO_SMALL;
        }
        if (sss_pkcs11_mutex_lock() != 0) {
            pxSession->xOperationInProgress = pkcs11NO_OPERATION;
            xResult                         = CKR_CANT_LOCK;
            goto exit;
        }
        if (pxSession->digestUpdateCalled != CK_TRUE) {
            pxSession->xOperationInProgress = pkcs11NO_OPERATION;
            xResult                         = CKR_OPERATION_ACTIVE;
            goto exit;
        }
        sss_status = sss_digest_finish(&pxSession->digest_ctx, digest, &digestLen);
        ENSURE_OR_GO_EXIT(sss_status == kStatus_SSS_Success);

        ENSURE_OR_GO_EXIT(*pulDigestLen >= digestLen);
        memcpy(pDigest, digest, digestLen);
        *pulDigestLen                   = digestLen;
        pxSession->xOperationInProgress = pkcs11NO_OPERATION;
    }
    xResult = CKR_OK;
exit:
    if (pxSession->digest_ctx.session != NULL) {
        sss_digest_context_free(&pxSession->digest_ctx);
    }
    if (sss_pkcs11_mutex_unlock() != 0) {
        return CKR_FUNCTION_FAILED;
    }
    return xResult;
}

/**
 * @brief Continues digesting operation in multiple parts.
 */
CK_DEFINE_FUNCTION(CK_RV, C_DigestUpdate)
(CK_SESSION_HANDLE xSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
    CK_RV xResult = CKR_FUNCTION_FAILED;
    LOG_D("%s", __FUNCTION__);

    P11SessionPtr_t pxSession = prvSessionPointerFromHandle(xSession);
    sss_status_t sss_status   = kStatus_SSS_Fail;
    size_t chunk              = 0;
    size_t offset             = 0;

    ENSURE_OR_RETURN_ON_ERROR(pxSession != NULL, CKR_SESSION_HANDLE_INVALID);
    ENSURE_OR_RETURN_ON_ERROR(sss_pkcs11_mutex_lock() == 0, CKR_CANT_LOCK);

    if (pxSession->xOperationInProgress == pkcs11NO_OPERATION) {
        xResult = CKR_OPERATION_NOT_INITIALIZED;
        goto exit;
    }

    if (pxSession->digestUpdateCalled != CK_TRUE) {
        sss_status = sss_digest_init(&pxSession->digest_ctx);
        ENSURE_OR_GO_EXIT(sss_status == kStatus_SSS_Success);
    }
    pxSession->digestUpdateCalled = CK_TRUE;
    do {
        if (ulPartLen > SIZE_MAX) {
            xResult = CKR_FUNCTION_FAILED;
            goto exit;
        }
        chunk = (ulPartLen > PKCS11_MAX_DIGEST_INPUT_DATA) ? PKCS11_MAX_DIGEST_INPUT_DATA : (size_t)ulPartLen;

        sss_status = sss_digest_update(&pxSession->digest_ctx, pPart + offset, chunk);
        ENSURE_OR_GO_EXIT(sss_status == kStatus_SSS_Success);

        ENSURE_OR_GO_EXIT((SIZE_MAX - offset) >= chunk);
        offset += chunk;
        ulPartLen -= chunk;
    } while (ulPartLen > 0);

    xResult = CKR_OK;
exit:
    if (xResult != CKR_OK) {
        if (pxSession->digest_ctx.session != NULL) {
            sss_digest_context_free(&pxSession->digest_ctx);
        }
        pxSession->xOperationInProgress = pkcs11NO_OPERATION;
    }
    if (sss_pkcs11_mutex_unlock() != 0) {
        return CKR_FUNCTION_FAILED;
    }
    return xResult;
}

/**
 * @brief initializes a message-digesting operation.
 */
CK_DEFINE_FUNCTION(CK_RV, C_DigestInit)
(CK_SESSION_HANDLE xSession, CK_MECHANISM_PTR pMechanism)
{
    CK_RV xResult             = CKR_FUNCTION_FAILED;
    P11SessionPtr_t pxSession = prvSessionPointerFromHandle(xSession);
    sss_status_t sss_status   = kStatus_SSS_Fail;
    sss_algorithm_t algorithm = kAlgorithm_None;

    LOG_D("%s", __FUNCTION__);

    ENSURE_OR_RETURN_ON_ERROR(pxSession != NULL, CKR_SESSION_HANDLE_INVALID);
    ENSURE_OR_RETURN_ON_ERROR(pMechanism != NULL, CKR_ARGUMENTS_BAD);
    ENSURE_OR_RETURN_ON_ERROR(sss_pkcs11_mutex_lock() == 0, CKR_CANT_LOCK);

    if (pxSession->xOperationInProgress != pkcs11NO_OPERATION) {
        xResult = CKR_SESSION_HANDLE_INVALID;
        goto exit;
    }

    pxSession->xOperationInProgress = pMechanism->mechanism;

    if (pkcs11_parse_digest_mechanism(pxSession, &algorithm) != CKR_OK) {
        pxSession->xOperationInProgress = pkcs11NO_OPERATION;
        xResult                         = CKR_MECHANISM_INVALID;
        goto exit;
    }

#if SSS_HAVE_NX_TYPE
    LOG_W("This will cause NVM flash writes !!");
    sss_status =
        sss_digest_context_init(&pxSession->digest_ctx, &pex_sss_demo_boot_ctx->session, algorithm, kMode_SSS_Digest);
#elif SSS_HAVE_HOSTCRYPTO_ANY
    sss_status = sss_digest_context_init(
        &pxSession->digest_ctx, &pex_sss_demo_boot_ctx->host_session, algorithm, kMode_SSS_Digest);
#else
    sss_status         = kStatus_SSS_Fail;
#endif
    ENSURE_OR_GO_EXIT(sss_status == kStatus_SSS_Success);

    xResult = CKR_OK;
exit:
    if (xResult == CKR_OK) {
        pxSession->digestUpdateCalled = CK_FALSE;
    }
    else {
        /* Error */
        if (pxSession->digest_ctx.session != NULL) {
            sss_digest_context_free(&pxSession->digest_ctx);
        }
        pxSession->xOperationInProgress = pkcs11NO_OPERATION;
    }
    if (sss_pkcs11_mutex_unlock() != 0) {
        return CKR_FUNCTION_FAILED;
    }
    return xResult;
}

/**
 * @brief Generate cryptographically random bytes.
 */
CK_DEFINE_FUNCTION(CK_RV, C_GenerateRandom)
(CK_SESSION_HANDLE xSession, CK_BYTE_PTR pucRandomData, CK_ULONG ulRandomLen)
{
    CK_RV xResult = CKR_FUNCTION_FAILED;
    LOG_D("%s", __FUNCTION__);
    sss_status_t sss_status       = kStatus_SSS_Fail;
    sss_rng_context_t sss_rng_ctx = {0};

    ENSURE_OR_RETURN_ON_ERROR(cryptokiInitialized == 1, CKR_CRYPTOKI_NOT_INITIALIZED);

    if (NULL == pucRandomData) {
        return CKR_ARGUMENTS_BAD;
    }

    if (ulRandomLen == 0) {
        return CKR_OK;
    }

    if (sss_pkcs11_mutex_lock() != 0) {
        return CKR_CANT_LOCK;
    }

#if SSS_HAVE_NX_TYPE
    sss_status = sss_rng_context_init(&sss_rng_ctx, &pex_sss_demo_boot_ctx->session /* Session */);
#elif SSS_HAVE_HOSTCRYPTO_ANY
    sss_status = sss_host_rng_context_init(&sss_rng_ctx, &pex_sss_demo_boot_ctx->host_session /* host Session */);
#else
    sss_status         = kStatus_SSS_Fail;
#endif
    ENSURE_OR_GO_EXIT(sss_status == kStatus_SSS_Success);

    sss_status = sss_rng_get_random(&sss_rng_ctx, pucRandomData, ulRandomLen);
    ENSURE_OR_GO_EXIT(sss_status == kStatus_SSS_Success);

    xResult = CKR_OK;
exit:
    if (sss_rng_ctx.session != NULL) {
        sss_rng_context_free(&sss_rng_ctx);
    }
    if (sss_pkcs11_mutex_unlock() != 0) {
        return CKR_FUNCTION_FAILED;
    }
    return xResult;
}

/**
 * @brief Verify the digital signature of the specified data using the public
 * key attached to this session.
 */
CK_DEFINE_FUNCTION(CK_RV, C_Verify)
(CK_SESSION_HANDLE xSession, CK_BYTE_PTR pucData, CK_ULONG ulDataLen, CK_BYTE_PTR pucSignature, CK_ULONG ulSignatureLen)
{
    CK_RV xResult = CKR_FUNCTION_FAILED;
    LOG_D("%s", __FUNCTION__);

    P11SessionPtr_t pxSessionObj     = prvSessionPointerFromHandle(xSession);
    sss_status_t status              = kStatus_SSS_Fail;
    sss_object_t object              = {0};
    sss_asymmetric_t asymmCtx        = {0};
    sss_algorithm_t algorithm        = kAlgorithm_None;
    sss_algorithm_t digest_algorithm = kAlgorithm_None;
    sss_mac_t ctx_hmac               = {0};
    uint8_t data[1024]               = {0};
    size_t dataLen                   = sizeof(data);
    sss_digest_t digestCtx           = {0};
    uint8_t signature_tmp[512]       = {0};
    size_t signature_tmp_len         = sizeof(signature_tmp);
    size_t chunk                     = 0;
    size_t ulDataLen_tmp             = ulDataLen;
    size_t offset                    = 0;
    uint8_t pubkey[100]              = {0};
    size_t pubkeylen                 = sizeof(pubkey);

    ENSURE_OR_RETURN_ON_ERROR(pxSessionObj != NULL, CKR_SESSION_HANDLE_INVALID);
    /*
     * Check parameters.
     */
    ENSURE_OR_RETURN_ON_ERROR(NULL != pucData, CKR_ARGUMENTS_BAD);
    ENSURE_OR_RETURN_ON_ERROR(NULL != pucSignature, CKR_ARGUMENTS_BAD);
    ENSURE_OR_RETURN_ON_ERROR(sss_pkcs11_mutex_lock() == 0, CKR_CANT_LOCK);

    if (pkcs11_parse_sign_mechanism(pxSessionObj, &algorithm) != CKR_OK) {
        pxSessionObj->xOperationInProgress = pkcs11NO_OPERATION;
        xResult                            = CKR_MECHANISM_INVALID;
        goto exit;
    }

    if ((pxSessionObj->xOperationInProgress != CKM_SHA256_HMAC) && (pxSessionObj->xOperationInProgress != CKM_ECDSA)) {
        if (pkcs11_get_digest_algorithm(algorithm, &digest_algorithm) != CKR_OK) {
            pxSessionObj->xOperationInProgress = pkcs11NO_OPERATION;
            xResult                            = CKR_ARGUMENTS_BAD;
            goto exit;
        }

#if SSS_HAVE_HOSTCRYPTO_ANY
        status = sss_digest_context_init(
            &digestCtx, &pex_sss_demo_boot_ctx->host_session, digest_algorithm, kMode_SSS_Digest);
#else
        status = kStatus_SSS_Fail;
#endif
        ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

        status = sss_digest_init(&digestCtx);
        ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

        while (ulDataLen_tmp > 0) {
            chunk  = (ulDataLen_tmp > PKCS11_MAX_DIGEST_INPUT_DATA) ? (PKCS11_MAX_DIGEST_INPUT_DATA) : (ulDataLen_tmp);
            status = sss_digest_update(&digestCtx, &pucData[offset], chunk);
            ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);
            ENSURE_OR_GO_EXIT((SIZE_MAX - offset) >= chunk);
            offset += chunk;
            ulDataLen_tmp -= chunk;
        }

        status = sss_digest_finish(&digestCtx, &data[0], &dataLen);
        ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

        if (digestCtx.session != NULL) {
            sss_digest_context_free(&digestCtx);
        }
    }
    else {
        ENSURE_OR_GO_EXIT(ulDataLen <= sizeof(data));
        memcpy(&data[0], pucData, ulDataLen);
        dataLen = ulDataLen;
        if (algorithm == kAlgorithm_SSS_ECDSA_SHA256 && ulDataLen < 20) {
            dataLen = 32;
        }
    }
    status = sss_key_object_init(&object, &pex_sss_demo_boot_ctx->ks);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    /* Checking for HMAC and validating */
    if (algorithm == kAlgorithm_SSS_HMAC_SHA256) {
        ENSURE_OR_GO_EXIT(pxSessionObj->xOperationKeyHandle <= UINT8_MAX);
        size_t macLen = ulSignatureLen;

        status = sss_key_object_get_handle(&object, kSSS_CipherType_AES, (uint32_t)pxSessionObj->xOperationKeyHandle);
        ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

        status = sss_mac_context_init(
            &ctx_hmac, &pex_sss_demo_boot_ctx->session, &object, algorithm, kMode_SSS_Mac_Validate);
        ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

        LOG_D("MAC Verify using NX");

        if (dataLen > PKCS11_MAX_INPUT_DATA) {
            status = sss_mac_init(&ctx_hmac);
            ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);
            do {
                chunk = (dataLen > PKCS11_MAX_HMAC_INPUT_DATA) ? PKCS11_MAX_HMAC_INPUT_DATA : dataLen;

                status = sss_mac_update(&ctx_hmac, &data[0] + offset, chunk);
                ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

                ENSURE_OR_GO_EXIT((SIZE_MAX - offset) >= chunk);
                offset += chunk;
                dataLen -= chunk;
            } while (dataLen > 0);
            status = sss_mac_finish(&ctx_hmac, pucSignature, &macLen);
            if (status != kStatus_SSS_Success) {
                LOG_E(" sss_mac_finish Failed...");
                xResult = CKR_SIGNATURE_INVALID;
                goto exit;
            }
        }
        else {
            status = sss_mac_one_go(&ctx_hmac, &data[0], dataLen, pucSignature, &macLen);
            if (status != kStatus_SSS_Success) {
                LOG_E(" sss_mac_one_go Failed...");
                xResult = CKR_SIGNATURE_INVALID;
                goto exit;
            }
        }
    }
    else { /* ECC */
        ENSURE_OR_GO_EXIT(pxSessionObj->xOperationKeyHandle <= UINT8_MAX);

        status =
            sss_key_object_get_handle(&object, kSSS_CipherType_EC_NIST_P, (uint32_t)pxSessionObj->xOperationKeyHandle);
        ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

        status = sss_key_object_allocate_handle(&object,
            (uint32_t)pxSessionObj->xOperationKeyHandle,
            kSSS_KeyPart_Public,
            (sss_cipher_type_t)object.cipherType,
            32,
            kKeyObject_Mode_Persistent);
        ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

        /* Converting public key from pem to der and provisioning for verify operation*/
#if (defined(SSS_HAVE_HOST_EMBEDDED) && !(SSS_HAVE_HOST_EMBEDDED))
        if (pkcs11GetPubKeyDer(&pubkey[0], &pubkeylen) != 0) {
            LOG_E("unable to get pubkey");
            xResult = CKR_FUNCTION_FAILED;
            goto exit;
        }
#endif //!SSS_HAVE_HOST_EMBEDDED
        status = sss_key_store_set_key(&pex_sss_demo_boot_ctx->ks, &object, pubkey, pubkeylen, 256, NULL, 0);
        ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);
        status = sss_asymmetric_context_init(
            &asymmCtx, &pex_sss_demo_boot_ctx->session, &object, kAlgorithm_SSS_ECDSA_SHA256, kMode_SSS_Verify);
        ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

        ENSURE_OR_GO_EXIT(asymmCtx.keyObject != NULL);

        if (((asymmCtx.keyObject->cipherType == kSSS_CipherType_EC_NIST_P) ||
                (asymmCtx.keyObject->cipherType == kSSS_CipherType_EC_BRAINPOOL)) &&
            ((CK_ULONG)(MAX_SIGN_RAW) == ulSignatureLen)) {
            if (CKR_OK != pkcs11_ecRandSToSignature(
                              (uint8_t *)pucSignature, (size_t)ulSignatureLen, &signature_tmp[0], &signature_tmp_len)) {
                goto exit;
            }
        }
        else {
            ENSURE_OR_GO_EXIT(ulSignatureLen <= sizeof(signature_tmp));
            memcpy(&signature_tmp[0], pucSignature, ulSignatureLen);
            signature_tmp_len = ulSignatureLen;
        }

        LOG_D("Verify using NX");
        status = sss_asymmetric_verify_digest(&asymmCtx, &data[0], dataLen, signature_tmp, signature_tmp_len);
        if (status != kStatus_SSS_Success) {
            LOG_E(" sss_asymmetric_verify_digest Failed...");
            xResult = CKR_SIGNATURE_INVALID;
            goto exit;
        }
    }

    xResult = CKR_OK;

exit:
    pxSessionObj->xOperationInProgress = pkcs11NO_OPERATION;

    if (asymmCtx.session != NULL) {
        sss_asymmetric_context_free(&asymmCtx);
    }
    if (ctx_hmac.session != NULL) {
        sss_mac_context_free(&ctx_hmac);
    }
    if (digestCtx.session != NULL) {
        sss_digest_context_free(&digestCtx);
    }
    if (sss_pkcs11_mutex_unlock() != 0) {
        return CKR_FUNCTION_FAILED;
    }
    return xResult;
}

/**
 * @brief To do sign operation in single shot.
 */
CK_DEFINE_FUNCTION(CK_RV, C_Sign)
(CK_SESSION_HANDLE xSession,
    CK_BYTE_PTR pucData,
    CK_ULONG ulDataLen,
    CK_BYTE_PTR pucSignature,
    CK_ULONG_PTR pulSignatureLen)
{
    CK_RV xResult                    = CKR_FUNCTION_FAILED;
    P11SessionPtr_t pxSessionObj     = prvSessionPointerFromHandle(xSession);
    sss_status_t status              = kStatus_SSS_Fail;
    sss_object_t object              = {0};
    sss_asymmetric_t asymmCtx        = {0};
    sss_algorithm_t algorithm        = kAlgorithm_None;
    sss_algorithm_t digest_algorithm = kAlgorithm_None;
    sss_mac_t ctx_hmac               = {0};
    uint8_t data[1024]               = {0};
    size_t dataLen                   = sizeof(data);
    sss_digest_t digestCtx           = {0};
    uint8_t hmacOutput[64]           = {0};
    size_t hmacOutputLen             = sizeof(hmacOutput);
    uint8_t signature[512]           = {0};
    size_t sigLen                    = sizeof(signature);
    size_t chunk                     = 0;
    size_t ulDataLen_tmp             = ulDataLen;
    size_t offset                    = 0;

    LOG_D("%s", __FUNCTION__);
    LOG_D(" Input data length = %ld", ulDataLen);

    ENSURE_OR_RETURN_ON_ERROR(pxSessionObj != NULL, CKR_SESSION_HANDLE_INVALID);
    /*
     * Check parameters.
     */
    ENSURE_OR_RETURN_ON_ERROR(NULL != pucData, CKR_ARGUMENTS_BAD);
    ENSURE_OR_RETURN_ON_ERROR(NULL != pulSignatureLen, CKR_ARGUMENTS_BAD);

    ENSURE_OR_RETURN_ON_ERROR(sss_pkcs11_mutex_lock() == 0, CKR_CANT_LOCK);
    ENSURE_OR_EXIT_WITH_STATUS_ON_ERROR(
        pkcs11_parse_sign_mechanism(pxSessionObj, &algorithm) == CKR_OK, xResult, CKR_MECHANISM_INVALID);

    if (pxSessionObj->xOperationInProgress == CKM_ECDSA) {
        /* CKM_ECDSA always deduce hashlen from ulDataLen value. so here value should be 32
         * as nx supports kAlgorithm_SSS_ECDSA_SHA256 only
         */
        if (ulDataLen != 32) {
            LOG_E("Provided datalen is incorrect !!");
            goto exit;
        }
        ENSURE_OR_GO_EXIT(ulDataLen <= sizeof(data));
        memcpy(&data[0], pucData, ulDataLen);
        dataLen = ulDataLen;
    }
    else if (pxSessionObj->xOperationInProgress == CKM_SHA256_HMAC) {
        /* Use RAW data for sign */
        ENSURE_OR_GO_EXIT(ulDataLen <= sizeof(data));
        memcpy(&data[0], pucData, ulDataLen);
        dataLen = ulDataLen;
    }
    else {
        ENSURE_OR_GO_EXIT(pkcs11_get_digest_algorithm(algorithm, &digest_algorithm) == CKR_OK);

#if SSS_HAVE_HOSTCRYPTO_ANY
        status = sss_digest_context_init(
            &digestCtx, &pex_sss_demo_boot_ctx->host_session, digest_algorithm, kMode_SSS_Digest);
#else
        status = kStatus_SSS_Fail;
#endif
        ENSURE_OR_EXIT_WITH_STATUS_ON_ERROR(status == kStatus_SSS_Success, xResult, CKR_DEVICE_ERROR);

        LOG_D("Calculate digest(%d) of input", digest_algorithm);
        status = sss_digest_init(&digestCtx);
        ENSURE_OR_EXIT_WITH_STATUS_ON_ERROR(status == kStatus_SSS_Success, xResult, CKR_DEVICE_ERROR);

        while (ulDataLen_tmp > 0) {
            chunk  = (ulDataLen_tmp > PKCS11_MAX_DIGEST_INPUT_DATA) ? (PKCS11_MAX_DIGEST_INPUT_DATA) : (ulDataLen_tmp);
            status = sss_digest_update(&digestCtx, &pucData[offset], chunk);
            ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);
            ENSURE_OR_GO_EXIT((SIZE_MAX - offset) >= chunk);
            offset += chunk;
            ulDataLen_tmp -= chunk;
        }

        status = sss_digest_finish(&digestCtx, &data[0], &dataLen);
        ENSURE_OR_EXIT_WITH_STATUS_ON_ERROR(status == kStatus_SSS_Success, xResult, CKR_DEVICE_ERROR);
    }

    /* Checking for HMAC and performing MAC operation */
    if (algorithm == kAlgorithm_SSS_HMAC_SHA256) {
        status = sss_key_object_init(&object, &pex_sss_demo_boot_ctx->ks);
        ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

        ENSURE_OR_GO_EXIT((pxSessionObj->xOperationKeyHandle) <= UINT8_MAX);
        status = sss_key_object_get_handle(&object, kSSS_CipherType_AES, (uint32_t)pxSessionObj->xOperationKeyHandle);
        ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

        status = sss_mac_context_init(&ctx_hmac, &pex_sss_demo_boot_ctx->session, &object, algorithm, kMode_SSS_Mac);
        ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

        LOG_D("MAC using SE05x");
        if (dataLen > PKCS11_MAX_INPUT_DATA) {
            status = sss_mac_init(&ctx_hmac);
            ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);
            chunk  = 0;
            offset = 0;
            do {
                chunk = (dataLen > PKCS11_MAX_HMAC_INPUT_DATA) ? PKCS11_MAX_HMAC_INPUT_DATA : dataLen;

                status = sss_mac_update(&ctx_hmac, &data[0] + offset, chunk);
                ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

                ENSURE_OR_GO_EXIT((SIZE_MAX - offset) >= chunk);
                offset += chunk;
                dataLen -= chunk;
            } while (dataLen > 0);

            status = sss_mac_finish(&ctx_hmac, &hmacOutput[0], &hmacOutputLen);
            ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);
        }
        else {
            status = sss_mac_one_go(&ctx_hmac, &data[0], dataLen, &hmacOutput[0], &hmacOutputLen);
            ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);
        }


        if (NULL != pucSignature) {
            ENSURE_OR_GO_EXIT(*pulSignatureLen >= hmacOutputLen);
            memcpy(pucSignature, &hmacOutput[0], hmacOutputLen);
            pxSessionObj->xOperationInProgress = pkcs11NO_OPERATION;
        }
        *pulSignatureLen = hmacOutputLen;
    }
    else {
        status = sss_key_object_init(&object, &pex_sss_demo_boot_ctx->ks);
        ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

        ENSURE_OR_GO_EXIT((pxSessionObj->xOperationKeyHandle) <= UINT8_MAX);
        status =
            sss_key_object_get_handle(&object, kSSS_CipherType_EC_NIST_P, (uint32_t)pxSessionObj->xOperationKeyHandle);
        ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

        status =
            sss_asymmetric_context_init(&asymmCtx, &pex_sss_demo_boot_ctx->session, &object, algorithm, kMode_SSS_Sign);
        ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

        LOG_D("Sign using NX");
        status = sss_asymmetric_sign_digest(&asymmCtx, &data[0], dataLen, &signature[0], &sigLen);
        ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

        ENSURE_OR_GO_EXIT(asymmCtx.keyObject != NULL);
        if ((asymmCtx.keyObject->cipherType == kSSS_CipherType_EC_NIST_P) ||
            (asymmCtx.keyObject->cipherType == kSSS_CipherType_EC_BRAINPOOL)) {
            ENSURE_OR_GO_EXIT(pkcs11_ecSignatureToRandS(signature, &sigLen) == CKR_OK);
        }

        if (NULL != pucSignature) {
            ENSURE_OR_EXIT_WITH_STATUS_ON_ERROR(*pulSignatureLen >= sigLen, xResult, CKR_BUFFER_TOO_SMALL);
            memcpy(pucSignature, &signature[0], sigLen);
            pxSessionObj->xOperationInProgress = pkcs11NO_OPERATION;
        }
        *pulSignatureLen = sigLen;
    }

    xResult = CKR_OK;
exit:
    if (digestCtx.session != NULL) {
        sss_digest_context_free(&digestCtx);
    }
    if (asymmCtx.session != NULL) {
        sss_asymmetric_context_free(&asymmCtx);
    }
    if (ctx_hmac.session != NULL) {
        sss_mac_context_free(&ctx_hmac);
    }
    if (sss_pkcs11_mutex_unlock() != 0) {
        return CKR_FUNCTION_FAILED;
    }
    return xResult;
}

sss_status_t pkcs11_sss_create_token_asymm(sss_key_store_t *keystore,
    sss_object_t *CreateObject,
    U32 ObjectId,
    sss_key_part_t KeyPart,
    sss_cipher_type_t CipherType,
    U8 *buffer,
    U32 bufferLen,
    U32 bitLen)
{
    sss_status_t status = kStatus_SSS_Fail;
    sss_status_t ret    = kStatus_SSS_Fail;
    uint8_t output[256] = {0};
    size_t olen         = sizeof(output);
    uint32_t keyId      = 0;

    if (pkcs11_parse_Convert_PemToDer((unsigned char *)buffer, (size_t)bufferLen, &output[0], &olen) == 0) {
        // Data was in PEM format. Nothing to be done.
    }
    else {
        ENSURE_OR_GO_EXIT(bufferLen <= sizeof(output));
        memcpy(&output[0], buffer, bufferLen);
        olen = bufferLen;
    }

    keyId = ObjectId & 0xFF;

    status = sss_key_object_init(CreateObject, keystore);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    status = sss_key_object_allocate_handle(CreateObject, keyId, KeyPart, CipherType, olen, kKeyObject_Mode_Persistent);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    status = sss_key_store_set_key(keystore, CreateObject, output, olen, bitLen, NULL, 0);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    ret = kStatus_SSS_Success;
exit:

    return ret;
}

sss_status_t pkcs11_sss_create_token_symm(sss_key_store_t *keystore,
    sss_object_t *CreateObject,
    U32 ObjectId,
    sss_key_part_t KeyPart,
    sss_cipher_type_t CipherType,
    U8 *buffer,
    U32 bufferLen,
    U32 bitLen)
{
    sss_status_t status = kStatus_SSS_Fail;
    sss_status_t ret    = kStatus_SSS_Fail;
    uint32_t keyId      = 0;

    sss_policy_u aeskeyPolicy     = {.type = KPolicy_ChgAESKey,
        .policy                        = {.chgAesKey = {
                       .hkdfEnabled        = 0,
                       .hmacEnabled        = 0,
                       .aeadEncIntEnabled  = 0,
                       .aeadEncEnabled     = 0,
                       .aeadDecEnabled     = 0,
                       .ecb_cbc_EncEnabled = 1,
                       .ecb_cbc_DecEnabled = 1,
                       .macSignEnabled     = 0,
                       .macVerifyEnabled   = 0,
                   }}};
    sss_policy_t aeskeyPolicyList = {.nPolicies = 1, .policies = {&aeskeyPolicy}};

    keyId  = ObjectId & 0xFF;
    status = sss_key_object_init(CreateObject, keystore);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    status = sss_key_object_allocate_handle(
        CreateObject, (uint32_t)keyId, KeyPart, CipherType, bufferLen, kKeyObject_Mode_Persistent);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    status = sss_key_store_set_key(
        keystore, CreateObject, buffer, bufferLen, bitLen, &aeskeyPolicyList, sizeof(aeskeyPolicyList));
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    ret = kStatus_SSS_Success;
exit:
    return ret;
}

sss_status_t pkcs11_sss_create_token_hmac(sss_key_store_t *keystore,
    sss_object_t *CreateObject,
    U32 ObjectId,
    sss_key_part_t KeyPart,
    sss_cipher_type_t CipherType,
    U8 *buffer,
    U32 bufferLen,
    U32 bitLen)
{
    sss_status_t status = kStatus_SSS_Fail;
    uint32_t keyId      = 0;

    sss_policy_u hmackeyPolicy     = {.type = KPolicy_ChgAESKey,
        .policy                         = {.chgAesKey = {
                       .hkdfEnabled        = 0,
                       .hmacEnabled        = 1,
                       .aeadEncIntEnabled  = 0,
                       .aeadEncEnabled     = 0,
                       .aeadDecEnabled     = 0,
                       .ecb_cbc_EncEnabled = 0,
                       .ecb_cbc_DecEnabled = 0,
                       .macSignEnabled     = 0,
                       .macVerifyEnabled   = 0,
                   }}};
    sss_policy_t hmackeyPolicyList = {.nPolicies = 1, .policies = {&hmackeyPolicy}};

    keyId  = ObjectId & 0xFF;
    status = sss_key_object_init(CreateObject, keystore);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    status = sss_key_object_allocate_handle(
        CreateObject, (uint32_t)keyId, KeyPart, CipherType, bufferLen, kKeyObject_Mode_Persistent);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    status = sss_key_store_set_key(
        keystore, CreateObject, buffer, bufferLen, bitLen, &hmackeyPolicyList, sizeof(hmackeyPolicyList));
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

exit:
    return status;
}

sss_status_t pkcs11_sss_create_token_cert(U32 ObjectId, U8 *buffer, U32 bufferLen)
{
    sss_status_t status                   = kStatus_SSS_Fail;
    uint8_t output[2048]                  = {0};
    size_t olen                           = sizeof(output);
    smStatus_t sm_status                  = SM_NOT_OK;
    uint8_t fileNo                        = 0;
    uint16_t isoFileID                    = 0;
    uint8_t fileOption                    = Nx_CommMode_NA;
    uint8_t fileReadAccess                = Nx_AccessCondition_Free_Access;
    uint8_t fileWriteAccess               = Nx_AccessCondition_Free_Access;
    uint8_t fileReadWriteAccess           = Nx_AccessCondition_Free_Access;
    uint8_t fileChangeAccess              = Nx_AccessCondition_Free_Access;
    size_t writeOffset                    = 0;
    size_t i                              = 0;
    uint8_t fIDList[NX_FILE_ID_LIST_SIZE] = {0};
    size_t fIDListLen                     = 0;
    bool fileExists                       = false;
    sss_nx_session_t *nx_session          = (sss_nx_session_t *)(&(pex_sss_demo_boot_ctx->session));

    if (pkcs11_parse_Convert_PemToDer((unsigned char *)buffer, (size_t)bufferLen, &output[0], &olen) == 0) {
        // Data was in PEM format. Nothing to be done.
    }
    else {
        ENSURE_OR_GO_EXIT(bufferLen <= sizeof(output));
        memcpy(&output[0], buffer, bufferLen);
        olen = bufferLen;
    }

    fileNo    = (uint8_t)(ObjectId & 0xFF);
    isoFileID = (uint16_t)(fileNo + 1);

    /* Check for the file exists */
    sm_status = nx_GetFileIDs(&nx_session->s_ctx, fIDList, &fIDListLen);
    ENSURE_OR_GO_EXIT(fIDListLen <= NX_FILE_ID_LIST_SIZE);
    ENSURE_OR_GO_EXIT(sm_status == SM_OK);

    for (i = 0; i < fIDListLen; i++) {
        if (fileNo == fIDList[i]) {
            fileExists = true;
            break;
        }
    }

    if (fileExists == false) {
        sm_status = nx_CreateStdDataFile(&nx_session->s_ctx,
            fileNo,
            isoFileID,
            fileOption,
            olen,
            fileReadAccess,
            fileWriteAccess,
            fileReadWriteAccess,
            fileChangeAccess);
        ENSURE_OR_GO_EXIT(sm_status == SM_OK);
        LOG_I("Certificate Data File creation successful !!!");
    }
    else {
        LOG_I("Certificate Data File already exist !!!");
    }

    sm_status = nx_WriteData(&nx_session->s_ctx, fileNo, writeOffset, &output[0], olen, Nx_CommMode_NA);

    if (sm_status != SM_OK) {
        LOG_E("Failed to write data");
        goto exit;
    }
    status = kStatus_SSS_Success;
exit:
    return status;
}

/**
 * @brief Un-initialize the Cryptoki module.
 */
CK_DEFINE_FUNCTION(CK_RV, C_Finalize)(CK_VOID_PTR pvReserved)
{
    CK_RV xResult = CKR_OK;
    LOG_D("%s", __FUNCTION__);

    ENSURE_OR_RETURN_ON_ERROR(NULL == pvReserved, CKR_ARGUMENTS_BAD);
    ENSURE_OR_RETURN_ON_ERROR(cryptokiInitialized == 1, CKR_CRYPTOKI_NOT_INITIALIZED);

    if (mutex_initialised) {
        if (sss_pkcs11_mutex_destroy() != 0) {
            LOG_W("unable to destroy mutex lock");
        }
        else {
            mutex_initialised = false;
        }
    }

    cryptokiInitialized = false;
    return xResult;
}

/**
 * @brief Start a session for a cryptographic command sequence.
 */
CK_DEFINE_FUNCTION(CK_RV, C_OpenSession)
(CK_SLOT_ID xSlotID, CK_FLAGS xFlags, CK_VOID_PTR pvApplication, CK_NOTIFY xNotify, CK_SESSION_HANDLE_PTR pxSession)
{
    AX_UNUSED_ARG(pvApplication);
    AX_UNUSED_ARG(xNotify);
    CK_RV xResult                = CKR_FUNCTION_FAILED;
    P11SessionPtr_t pxSessionObj = NULL;

    LOG_D("%s", __FUNCTION__);

    ENSURE_OR_RETURN_ON_ERROR(cryptokiInitialized == 1, CKR_CRYPTOKI_NOT_INITIALIZED);
    ENSURE_OR_RETURN_ON_ERROR(NULL != pxSession, CKR_ARGUMENTS_BAD);
    ENSURE_OR_RETURN_ON_ERROR(xSlotID == pkcs11SLOT_ID, CKR_SLOT_ID_INVALID);
    ENSURE_OR_RETURN_ON_ERROR((xFlags & CKF_SERIAL_SESSION), CKR_SESSION_PARALLEL_NOT_SUPPORTED);

    /*
     * Make space for the context.
     */
#if defined(USE_RTOS) && USE_RTOS == 1
    if (NULL == (pxSessionObj = (P11SessionPtr_t)pvPortMalloc(
                     sizeof(P11Session_t)))) /*lint !e9087 Allow casting void* to other types. */
    {
        xResult = CKR_HOST_MEMORY;
        goto exit;
    }
#else
    if (NULL == (pxSessionObj = (P11SessionPtr_t)SSS_MALLOC(
                     sizeof(P11Session_t)))) /*lint !e9087 Allow casting void* to other types. */
    {
        xResult = CKR_HOST_MEMORY;
        goto exit;
    }
#endif

    memset(pxSessionObj, 0, sizeof(P11Session_t));

    /*
    * Assign the session.
    */
    pxSessionObj->ulState = 0u != (xFlags & CKF_RW_SESSION) ? CKS_RW_PUBLIC_SESSION : CKS_RO_PUBLIC_SESSION;
    pxSessionObj->xOpened = CK_TRUE;
    pxSessionObj->xFlags  = xFlags;

    /*
    * Return the session.
    */

    *pxSession = (CK_SESSION_HANDLE)(uintptr_t)pxSessionObj;

    pxSessionObj->xOperationInProgress = pkcs11NO_OPERATION;
/* Lock for session open - required because multiple session_open will be attempted */
#ifdef PKCS11_SESSION_OPEN
    if (sss_pkcs11_mutex_lock() != 0) {
        xResult = CKR_CANT_LOCK;
        goto exit;
    }
    if (sessionCount == 0) {
        sss_status_t sss_status = kStatus_SSS_Fail;
        char *portName          = NULL;

        /* If portname is given in ENV */
        sss_status = ex_sss_boot_connectstring(0, NULL, &portName);
        ENSURE_OR_GO_EXIT(sss_status == kStatus_SSS_Success);

        sss_status = ex_sss_boot_open(pex_sss_demo_boot_ctx, portName);
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
        ENSURE_OR_EXIT_WITH_STATUS_ON_ERROR(sss_status == kStatus_SSS_Success, xResult, CKR_GENERAL_ERROR);

#if SSS_HAVE_HOSTCRYPTO_ANY
        if ((pex_sss_demo_boot_ctx->host_session.subsystem) == kType_SSS_SubSystem_NONE) {
            sss_type_t hostsubsystem = kType_SSS_SubSystem_NONE;
#if SSS_HAVE_HOSTCRYPTO_MBEDTLS
            hostsubsystem = kType_SSS_mbedTLS;
#elif SSS_HAVE_HOSTCRYPTO_OPENSSL
            hostsubsystem = kType_SSS_OpenSSL;
#endif
            sss_status = sss_host_session_open(
                &pex_sss_demo_boot_ctx->host_session, hostsubsystem, 0, kSSS_ConnectionType_Plain, NULL);
            ENSURE_OR_GO_EXIT(sss_status == kStatus_SSS_Success);
        }
#endif
        sss_status = ex_sss_key_store_and_object_init(pex_sss_demo_boot_ctx);
        ENSURE_OR_GO_EXIT(sss_status == kStatus_SSS_Success);

    }
#endif

    sessionCount++;
    xResult = CKR_OK;
exit:
    if (xResult != CKR_OK) {
        if (pxSessionObj != NULL) {
#if defined(USE_RTOS) && USE_RTOS == 1
            vPortFree(pxSessionObj);
#else
            SSS_FREE(pxSessionObj);
#endif
        }
        if (pex_sss_demo_boot_ctx != NULL) {
            ex_sss_session_close(pex_sss_demo_boot_ctx);
        }
    }
#ifdef PKCS11_SESSION_OPEN
    /* Unlock for session open - required because multiple session_open will be attempted */
    if (sss_pkcs11_mutex_unlock() != 0) {
        LOG_W("sss_pkcs11_mutex_unlock failed ");
    }
#endif
    return xResult;
}

/**
 * @brief Terminate a session and release resources.
 */
CK_DEFINE_FUNCTION(CK_RV, C_CloseSession)(CK_SESSION_HANDLE xSession)
{
    CK_RV xResult             = CKR_OK;
    P11SessionPtr_t pxSession = prvSessionPointerFromHandle(xSession);

    LOG_D("%s", __FUNCTION__);

    ENSURE_OR_RETURN_ON_ERROR(cryptokiInitialized == 1, CKR_CRYPTOKI_NOT_INITIALIZED);
    ENSURE_OR_RETURN_ON_ERROR(NULL != pxSession, CKR_SESSION_HANDLE_INVALID);

    /*
    * Tear down the session.
    */

#if defined(USE_RTOS) && USE_RTOS == 1
    vPortFree(pxSession);
#else
    SSS_FREE(pxSession);
#endif

#ifdef PKCS11_SESSION_OPEN

    if (sss_pkcs11_mutex_lock() != 0) {
        xResult = CKR_CANT_LOCK;
        return xResult;
    }

    if (sessionCount == 1) {
        ex_sss_session_close(pex_sss_demo_boot_ctx);
    }
#endif

    if (sessionCount <= 0) {
        xResult = CKR_FUNCTION_FAILED;
    }
    else {
        sessionCount--;
    }

    if (sss_pkcs11_mutex_unlock() != 0) {
        LOG_W("sss_pkcs11_mutex_unlock failed ");
    }

    return xResult;
}

/**
 * @brief Query the list of slots. A single default slot is implemented.
 */
CK_DEFINE_FUNCTION(CK_RV, C_GetSlotList)
(CK_BBOOL xTokenPresent, CK_SLOT_ID_PTR pxSlotList, CK_ULONG_PTR pulCount)
{
    AX_UNUSED_ARG(xTokenPresent);
    CK_RV xResult = CKR_OK;
    LOG_D("%s", __FUNCTION__);

    ENSURE_OR_RETURN_ON_ERROR(cryptokiInitialized == 1, CKR_CRYPTOKI_NOT_INITIALIZED);
    if (NULL == pulCount) {
        xResult = CKR_ARGUMENTS_BAD;
    }
    else if (NULL == pxSlotList) {
        *pulCount = 1;
    }
    else {
        if (*pulCount < 1) {
            xResult = CKR_BUFFER_TOO_SMALL;
        }
        else {
            pxSlotList[0] = (CK_ULONG)pkcs11SLOT_ID;
            *pulCount     = 1;
        }
    }
    return xResult;
}

/**
 * @brief Decrypts single-part encrypted data.
 */
CK_DEFINE_FUNCTION(CK_RV, C_Decrypt)
(CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pEncryptedData,
    CK_ULONG ulEncryptedDataLen,
    CK_BYTE_PTR pData,
    CK_ULONG_PTR pulDataLen)
{
    CK_RV xResult                = CKR_FUNCTION_FAILED;
    sss_algorithm_t algorithm    = kAlgorithm_None;
    P11SessionPtr_t pxSessionObj = prvSessionPointerFromHandle(hSession);

    LOG_D("%s", __FUNCTION__);

    ENSURE_OR_RETURN_ON_ERROR(pxSessionObj != NULL, CKR_SESSION_HANDLE_INVALID);
    if (pulDataLen == NULL) {
        pxSessionObj->xOperationInProgress = pkcs11NO_OPERATION;
        return CKR_ARGUMENTS_BAD;
    }
    if (!pEncryptedData) {
        pxSessionObj->xOperationInProgress = pkcs11NO_OPERATION;
        return CKR_ARGUMENTS_BAD;
    }

    if (pkcs11_parse_encryption_mechanism(pxSessionObj, &algorithm) != CKR_OK) {
        pxSessionObj->xOperationInProgress = pkcs11NO_OPERATION;
        return CKR_MECHANISM_INVALID;
    }

    if (algorithm == kAlgorithm_None) {
        pxSessionObj->xOperationInProgress = pkcs11NO_OPERATION;
        return CKR_MECHANISM_INVALID;
    }

    /*Symmetric Decryption*/
    xResult =
        pkcs11_nx_symmetric_decrypt(pxSessionObj, algorithm, pEncryptedData, ulEncryptedDataLen, pData, pulDataLen);

    return xResult;
}

/**
 * @brief Initializes a decryption operation.
 */
CK_DEFINE_FUNCTION(CK_RV, C_DecryptInit)
(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
    CK_RV xResult = CKR_OK;
    LOG_D("%s", __FUNCTION__);

    P11SessionPtr_t pxSession = prvSessionPointerFromHandle(hSession);
    sss_algorithm_t algorithm = kAlgorithm_None;
    sss_status_t status       = kStatus_SSS_Fail;
    sss_object_t obj          = {0};
    sss_cipher_type_t cipher  = 0;

    ENSURE_OR_RETURN_ON_ERROR(pxSession != NULL, CKR_SESSION_HANDLE_INVALID);
    ENSURE_OR_RETURN_ON_ERROR(pMechanism != NULL, CKR_ARGUMENTS_BAD);
    ENSURE_OR_RETURN_ON_ERROR(pxSession->xOperationInProgress == pkcs11NO_OPERATION, CKR_OPERATION_ACTIVE);

    status = pkcs11_get_validated_sss_symm_object(pxSession, hKey, &obj);
    if (status != kStatus_SSS_Success) {
        pxSession->xOperationInProgress = pkcs11NO_OPERATION;
        return CKR_KEY_HANDLE_INVALID;
    }
    pxSession->xOperationInProgress = pMechanism->mechanism;

    if (pkcs11_parse_encryption_mechanism(pxSession, &algorithm) != CKR_OK) {
        pxSession->xOperationInProgress = pkcs11NO_OPERATION;
        return CKR_MECHANISM_INVALID;
    }

    xResult = pkcs11_is_valid_keytype(algorithm, &cipher, &obj);
    if (xResult != CKR_OK) {
        pxSession->xOperationInProgress = pkcs11NO_OPERATION;
        return xResult;
    }

    if (pMechanism->ulParameterLen % 8 != 0) {
        pxSession->xOperationInProgress = pkcs11NO_OPERATION;
        return CKR_MECHANISM_PARAM_INVALID;
    }

    pxSession->xOperationKeyHandle = (CK_OBJECT_HANDLE)(hKey & 0xFF);
    if (pMechanism->pParameter) {
        pxSession->mechParameter    = pMechanism->pParameter;
        pxSession->mechParameterLen = pMechanism->ulParameterLen;
    }
    else {
        pxSession->mechParameterLen = 0;
    }

    return xResult;
}

/**
 * @brief Derives a key from a base key and creates a new key object.
 */
CK_DEFINE_FUNCTION(CK_RV, C_DeriveKey)
(CK_SESSION_HANDLE hSession,
    CK_MECHANISM_PTR pMechanism,
    CK_OBJECT_HANDLE hBaseKey,
    CK_ATTRIBUTE_PTR pTemplate,
    CK_ULONG ulAttributeCount,
    CK_OBJECT_HANDLE_PTR phKey)
{
    AX_UNUSED_ARG(hSession);
    AX_UNUSED_ARG(pMechanism);
    AX_UNUSED_ARG(hBaseKey);
    AX_UNUSED_ARG(pTemplate);
    AX_UNUSED_ARG(ulAttributeCount);
    AX_UNUSED_ARG(phKey);
    LOG_D("%s", __FUNCTION__);

    return CKR_FUNCTION_NOT_SUPPORTED;
}

/**
 * @brief To digest data in single-part.
 */
CK_DEFINE_FUNCTION(CK_RV, C_Digest)
(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen)
{
    CK_RV xResult                = CKR_FUNCTION_FAILED;
    sss_algorithm_t algorithm    = kAlgorithm_None;
    sss_status_t status          = kStatus_SSS_Fail;
    size_t outputLen             = 0;
    size_t inputLen              = ulDataLen;
    size_t chunk                 = 0;
    size_t offset                = 0;
    P11SessionPtr_t pxSessionObj = prvSessionPointerFromHandle(hSession);

    LOG_D("%s", __FUNCTION__);

    ENSURE_OR_RETURN_ON_ERROR(pData != NULL, CKR_ARGUMENTS_BAD);

    ENSURE_OR_RETURN_ON_ERROR(pxSessionObj != NULL, CKR_SESSION_HANDLE_INVALID);
    if ((pData == NULL) || (pulDigestLen == NULL)) {
        xResult                            = CKR_ARGUMENTS_BAD;
        pxSessionObj->xOperationInProgress = pkcs11NO_OPERATION;
        goto exit;
    }

    if (sss_pkcs11_mutex_lock() != 0) {
        xResult                            = CKR_CANT_LOCK;
        pxSessionObj->xOperationInProgress = pkcs11NO_OPERATION;
        goto exit;
    }

    if (pxSessionObj->digestUpdateCalled == CK_TRUE) {
        xResult                            = CKR_OPERATION_ACTIVE;
        pxSessionObj->xOperationInProgress = pkcs11NO_OPERATION;
        goto exit;
    }
    switch (pxSessionObj->xOperationInProgress) {
    case CKM_SHA256:
        outputLen = 32;
        algorithm = kAlgorithm_SSS_SHA256;
        break;
    case CKM_SHA384:
        outputLen = 48;
        algorithm = kAlgorithm_SSS_SHA384;
        break;
    default:
        xResult                            = CKR_OPERATION_NOT_INITIALIZED;
        pxSessionObj->xOperationInProgress = pkcs11NO_OPERATION;
        goto exit;
    }

    if (pDigest == NULL) {
        /* Return the required length */
        *pulDigestLen = outputLen;
    }
    else {
        status = sss_digest_context_init(
            &pxSessionObj->digest_ctx, &pex_sss_demo_boot_ctx->session, algorithm, kMode_SSS_Digest);
        ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

        if (outputLen > *pulDigestLen) {
            xResult = CKR_BUFFER_TOO_SMALL;
            /* Return the required length */
            *pulDigestLen = outputLen;
            goto exit;
        }
        if (inputLen > PKCS11_MAX_INPUT_DATA) {
            status = sss_digest_init(&pxSessionObj->digest_ctx);
            ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);
            do {
                chunk = (inputLen > PKCS11_MAX_DIGEST_INPUT_DATA) ? PKCS11_MAX_DIGEST_INPUT_DATA : inputLen;

                status = sss_digest_update(&pxSessionObj->digest_ctx, pData + offset, chunk);
                ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

                ENSURE_OR_GO_EXIT((SIZE_MAX - offset) >= chunk);
                offset += chunk;
                inputLen -= chunk;
            } while (inputLen > 0);

            status = sss_digest_finish(&pxSessionObj->digest_ctx, pDigest, &outputLen);
            ENSURE_OR_EXIT_WITH_STATUS_ON_ERROR(status == kStatus_SSS_Success, xResult, CKR_DEVICE_ERROR);
        }
        else {
            status = sss_digest_one_go(&pxSessionObj->digest_ctx, pData, inputLen, pDigest, &outputLen);
            ENSURE_OR_EXIT_WITH_STATUS_ON_ERROR(status == kStatus_SSS_Success, xResult, CKR_DEVICE_ERROR);
        }
        ENSURE_OR_EXIT_WITH_STATUS_ON_ERROR(outputLen <= *pulDigestLen, xResult, CKR_BUFFER_TOO_SMALL);
        *pulDigestLen                      = outputLen;
        pxSessionObj->xOperationInProgress = pkcs11NO_OPERATION;
    }

    xResult = CKR_OK;
exit:
    if (pxSessionObj->digest_ctx.session != NULL) {
        sss_digest_context_free(&pxSessionObj->digest_ctx);
    }
    if (sss_pkcs11_mutex_unlock() != 0) {
        return CKR_FUNCTION_FAILED;
    }
    return xResult;
}

/**
 * @brief Initializes the encryption for single-part data.
 */
CK_DEFINE_FUNCTION(CK_RV, C_Encrypt)
(CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pData,
    CK_ULONG ulDataLen,
    CK_BYTE_PTR pEncryptedData,
    CK_ULONG_PTR pulEncryptedDataLen)
{
    CK_RV xResult             = CKR_FUNCTION_FAILED;
    sss_algorithm_t algorithm = kAlgorithm_None;

    LOG_D("%s", __FUNCTION__);

    P11SessionPtr_t pxSessionObj = prvSessionPointerFromHandle(hSession);

    ENSURE_OR_RETURN_ON_ERROR(pxSessionObj != NULL, CKR_SESSION_HANDLE_INVALID);
    if ((pData == NULL) || (pulEncryptedDataLen == NULL)) {
        pxSessionObj->xOperationInProgress = pkcs11NO_OPERATION;
        return CKR_ARGUMENTS_BAD;
    }
    if (pkcs11_parse_encryption_mechanism(pxSessionObj, &algorithm) != CKR_OK) {
        pxSessionObj->xOperationInProgress = pkcs11NO_OPERATION;
        return CKR_MECHANISM_INVALID;
    }
    if (algorithm == kAlgorithm_None) {
        pxSessionObj->xOperationInProgress = pkcs11NO_OPERATION;
        return CKR_MECHANISM_INVALID;
    }

    /*Symmetric Encryption*/
    if (CKR_OK !=
        pkcs11_nx_symmetric_encrypt(pxSessionObj, algorithm, pData, ulDataLen, pEncryptedData, pulEncryptedDataLen)) {
        goto exit;
    }

    xResult = CKR_OK;
exit:
    return xResult;
}

/**
 * @brief Initializes an encryption operation.
 */
CK_DEFINE_FUNCTION(CK_RV, C_EncryptInit)
(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
    CK_RV xResult = CKR_OK;
    LOG_D("%s", __FUNCTION__);
    P11SessionPtr_t pxSession = prvSessionPointerFromHandle(hSession);
    sss_algorithm_t algorithm = kAlgorithm_None;
    sss_status_t status       = kStatus_SSS_Fail;
    sss_object_t obj          = {0};
    sss_cipher_type_t cipher  = 0;

    ENSURE_OR_RETURN_ON_ERROR(cryptokiInitialized == 1, CKR_CRYPTOKI_NOT_INITIALIZED);
    ENSURE_OR_RETURN_ON_ERROR(pxSession != NULL, CKR_SESSION_HANDLE_INVALID);
    ENSURE_OR_RETURN_ON_ERROR(pMechanism != NULL, CKR_ARGUMENTS_BAD);
    ENSURE_OR_RETURN_ON_ERROR(pxSession->xOperationInProgress == pkcs11NO_OPERATION, CKR_OPERATION_ACTIVE);

    status = pkcs11_get_validated_sss_symm_object(pxSession, hKey, &obj);
    if (status != kStatus_SSS_Success) {
        pxSession->xOperationInProgress = pkcs11NO_OPERATION;
        return CKR_KEY_HANDLE_INVALID;
    }
    pxSession->xOperationInProgress = pMechanism->mechanism;

    if (pMechanism->ulParameterLen % 8 != 0) {
        pxSession->xOperationInProgress = pkcs11NO_OPERATION;
        return CKR_MECHANISM_PARAM_INVALID;
    }
    pxSession->xOperationKeyHandle = (CK_OBJECT_HANDLE)(hKey & 0xFF);
    if (pMechanism->pParameter) {
        pxSession->mechParameter    = pMechanism->pParameter;
        pxSession->mechParameterLen = pMechanism->ulParameterLen;
    }
    else {
        pxSession->mechParameterLen = 0;
    }

    if (pkcs11_parse_encryption_mechanism(pxSession, &algorithm) != CKR_OK) {
        pxSession->xOperationInProgress = pkcs11NO_OPERATION;
        return CKR_MECHANISM_INVALID;
    }

    xResult = pkcs11_is_valid_keytype(algorithm, &cipher, &obj);
    if (xResult != CKR_OK) {
        pxSession->xOperationInProgress = pkcs11NO_OPERATION;
        return xResult;
    }

    return xResult;
}

/**
 * @brief Obtains general information about cryptoki.
 */
CK_DEFINE_FUNCTION(CK_RV, C_GetInfo)(CK_INFO_PTR pInfo)
{
    LOG_D("%s", __FUNCTION__);

    ENSURE_OR_RETURN_ON_ERROR(cryptokiInitialized == 1, CKR_CRYPTOKI_NOT_INITIALIZED);
    ENSURE_OR_RETURN_ON_ERROR(pInfo != NULL, CKR_ARGUMENTS_BAD);

    pInfo->cryptokiVersion.major = CRYPTOKI_VERSION_MAJOR;
    pInfo->cryptokiVersion.minor = CRYPTOKI_VERSION_MINOR;
    memset(pInfo->manufacturerID, ' ', sizeof(pInfo->manufacturerID));
    memset(pInfo->libraryDescription, ' ', sizeof(pInfo->libraryDescription));
    pInfo->flags          = 0;
    pInfo->libraryVersion = PKCS11_LIBRARY_VERSION;
    return CKR_OK;
}

/**
 * @brief Obtains information about a particular mechanism supported by a token.
 */
CK_DEFINE_FUNCTION(CK_RV, C_GetMechanismInfo)
(CK_SLOT_ID slotID, CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR pInfo)
{
    AX_UNUSED_ARG(slotID);
    LOG_D("%s", __FUNCTION__);

    CK_RV xResult               = CKR_MECHANISM_INVALID;
    CK_MECHANISM_INFO mech_info = {.ulMinKeySize = 0, .ulMaxKeySize = 0, .flags = CKF_HW};

    ENSURE_OR_RETURN_ON_ERROR(cryptokiInitialized == 1, CKR_CRYPTOKI_NOT_INITIALIZED);
    ENSURE_OR_RETURN_ON_ERROR(slotID == pkcs11SLOT_ID, CKR_SLOT_ID_INVALID);
    ENSURE_OR_RETURN_ON_ERROR(pInfo != NULL, CKR_ARGUMENTS_BAD);

    if (type == CKM_AES_ECB || type == CKM_AES_CBC || type == CKM_AES_CTR) {
        mech_info.ulMinKeySize = 128;
        mech_info.ulMaxKeySize = 256;
        mech_info.flags        = mech_info.flags | CKF_ENCRYPT | CKF_DECRYPT;
        xResult                = CKR_OK;
    }
    else if (type == CKM_SHA_1 || type == CKM_SHA224 || type == CKM_SHA256 || type == CKM_SHA384 ||
             type == CKM_SHA512) {
        mech_info.ulMinKeySize = 0;
        mech_info.ulMaxKeySize = 0;
        mech_info.flags        = mech_info.flags | CKF_DIGEST;
        xResult                = CKR_OK;
    }
    else if (type == CKM_ECDSA) {
        mech_info.ulMinKeySize = 192;
        mech_info.ulMaxKeySize = 521;
        mech_info.flags        = mech_info.flags | CKF_SIGN | CKF_VERIFY;
        xResult                = CKR_OK;
    }
    else if (type == CKM_ECDSA_SHA1 || type == CKM_ECDSA_SHA224 || type == CKM_ECDSA_SHA256 ||
             type == CKM_ECDSA_SHA384 || type == CKM_ECDSA_SHA512) {
        mech_info.ulMinKeySize = 192;
        mech_info.ulMaxKeySize = 521;
        mech_info.flags        = mech_info.flags | CKF_SIGN | CKF_VERIFY;
        xResult                = CKR_OK;
    }
    else if (type == CKM_EC_KEY_PAIR_GEN) {
        mech_info.ulMinKeySize = 192;
        mech_info.ulMaxKeySize = 521;
        mech_info.flags        = mech_info.flags | CKF_GENERATE_KEY_PAIR | CKF_EC_NAMEDCURVE;
        xResult                = CKR_OK;
    }
    else if (type == CKM_AES_KEY_GEN || type == CKM_DES2_KEY_GEN || type == CKM_DES3_KEY_GEN) {
        mech_info.ulMinKeySize = 128;
        mech_info.ulMaxKeySize = 256;
        mech_info.flags        = mech_info.flags | CKF_GENERATE;
        xResult                = CKR_OK;
    }
    else if (type == CKM_ECDH1_DERIVE) {
        mech_info.ulMinKeySize = 128;
        mech_info.ulMaxKeySize = 256;
        mech_info.flags        = mech_info.flags | CKF_DERIVE;
        xResult                = CKR_OK;
    }
    else if ((type == CKM_SHA_1_HMAC) || (type == CKM_SHA224_HMAC) || (type == CKM_SHA256_HMAC) ||
             (type == CKM_SHA384_HMAC) || (type == CKM_SHA512_HMAC)) {
        mech_info.ulMinKeySize = 128;
        mech_info.ulMaxKeySize = 512;
        mech_info.flags        = mech_info.flags | CKF_SIGN | CKF_VERIFY;
        xResult                = CKR_OK;
    }
    else if (type == CKM_GENERIC_SECRET_KEY_GEN) {
        mech_info.ulMinKeySize = 128;
        mech_info.ulMaxKeySize = 256;
        mech_info.flags        = mech_info.flags | CKF_GENERATE;
        xResult                = CKR_OK;
    }
    else {
        // do nothing.
    }

    if (xResult == CKR_OK) {
        memcpy(pInfo, &mech_info, sizeof(CK_MECHANISM_INFO));
    }

    return xResult;
}

/**
 * @brief Obtains a list of mechanism types supported by a token.
 */
CK_DEFINE_FUNCTION(CK_RV, C_GetMechanismList)
(CK_SLOT_ID slotID, CK_MECHANISM_TYPE_PTR pMechanismList, CK_ULONG_PTR pulCount)
{
    LOG_D("%s", __FUNCTION__);

    CK_RV xResult = CKR_OK;

    ENSURE_OR_RETURN_ON_ERROR(cryptokiInitialized == 1, CKR_CRYPTOKI_NOT_INITIALIZED);
    ENSURE_OR_RETURN_ON_ERROR(slotID == pkcs11SLOT_ID, CKR_SLOT_ID_INVALID);
    ENSURE_OR_RETURN_ON_ERROR(pulCount != NULL, CKR_ARGUMENTS_BAD);

    CK_MECHANISM_TYPE mechanisms[] = {
        /* AES Algorithms  */
        CKM_AES_ECB,
        CKM_AES_CBC,
        /* Digest algorithms */
        CKM_SHA256,
        CKM_SHA384,
        /* ECDSA */
        CKM_ECDSA,
        CKM_ECDSA_SHA256,
        /* Key Generation algorithms */
        CKM_EC_KEY_PAIR_GEN,
        CKM_AES_KEY_GEN,
        /* HMAC algorithms */
        CKM_SHA256_HMAC,
        CKM_GENERIC_SECRET_KEY_GEN,
    };

    CK_ULONG numOfMechs = sizeof(mechanisms) / sizeof(mechanisms[0]);

    if (pMechanismList) {
        if (*pulCount < numOfMechs) {
            xResult = CKR_BUFFER_TOO_SMALL;
        }
        else {
            memcpy(pMechanismList, &mechanisms[0], sizeof(mechanisms));
        }
    }

    *pulCount = numOfMechs;
    return xResult;
}

/**
 * @brief Obtains information about a particular slot in the system.
 */
CK_DEFINE_FUNCTION(CK_RV, C_GetSlotInfo)
(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo)
{
    LOG_D("%s", __FUNCTION__);

    ENSURE_OR_RETURN_ON_ERROR(cryptokiInitialized == 1, CKR_CRYPTOKI_NOT_INITIALIZED);
    ENSURE_OR_RETURN_ON_ERROR(pInfo != NULL, CKR_ARGUMENTS_BAD);

    if (slotID != 1) {
        return CKR_SLOT_ID_INVALID;
    }
    memset(&pInfo->slotDescription[0], ' ', sizeof(pInfo->slotDescription));
    memset(&pInfo->manufacturerID[0], ' ', sizeof(pInfo->manufacturerID));
    pInfo->flags                 = CKF_TOKEN_PRESENT | CKF_REMOVABLE_DEVICE | CKF_HW_SLOT;
    pInfo->hardwareVersion.major = NX_VER_MAJOR;
    pInfo->hardwareVersion.minor = NX_VER_MINOR;
    CK_VERSION libVersion        = PKCS11_LIBRARY_VERSION;
    memcpy(&pInfo->firmwareVersion, &libVersion, sizeof(CK_VERSION));
    memcpy(&pInfo->manufacturerID[0], "NXP", sizeof("NXP") - 1);
    return CKR_OK;
}

/**
 * @brief Obtains information about a particular token in the system.
 */
CK_DEFINE_FUNCTION(CK_RV, C_GetTokenInfo)
(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo)
{
    LOG_D("%s", __FUNCTION__);

    ENSURE_OR_RETURN_ON_ERROR(cryptokiInitialized == 1, CKR_CRYPTOKI_NOT_INITIALIZED);
    ENSURE_OR_RETURN_ON_ERROR(slotID == pkcs11SLOT_ID, CKR_SLOT_ID_INVALID);
    ENSURE_OR_RETURN_ON_ERROR(pInfo != NULL, CKR_ARGUMENTS_BAD);

    CK_TOKEN_INFO tokenInfo      = {0};
    unsigned char label[]        = PKCS11_TOKEN_LABEL;
    unsigned char manufacturer[] = PKCS11_MANUFACTURER;
    CK_VERSION libVersion        = PKCS11_LIBRARY_VERSION;

    memset(tokenInfo.label, ' ', sizeof(tokenInfo.label));
    memset(tokenInfo.manufacturerID, ' ', sizeof(tokenInfo.manufacturerID));
    memset(tokenInfo.model, ' ', sizeof(tokenInfo.model));
    memset(tokenInfo.serialNumber, ' ', sizeof(tokenInfo.serialNumber));
    memcpy(tokenInfo.label, label, sizeof(label));
    memcpy(tokenInfo.manufacturerID, manufacturer, sizeof(manufacturer));
    tokenInfo.ulMaxSessionCount     = 1;
    tokenInfo.ulMaxRwSessionCount   = 1;
    tokenInfo.ulMaxPinLen           = 10;
    tokenInfo.ulMinPinLen           = 0;
    tokenInfo.hardwareVersion.major = NX_VER_MAJOR;
    tokenInfo.hardwareVersion.minor = NX_VER_MINOR;
    memcpy(&tokenInfo.firmwareVersion, &libVersion, sizeof(CK_VERSION));
    tokenInfo.flags = CKF_RNG | CKF_TOKEN_INITIALIZED;
    memcpy(pInfo, &tokenInfo, sizeof(CK_TOKEN_INFO));

    return CKR_OK;
}

/**
 * @brief  Logs a user into a token along with usertype and pin.
 */
CK_DEFINE_FUNCTION(CK_RV, C_Login)
(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen)
{
    AX_UNUSED_ARG(hSession);
    AX_UNUSED_ARG(userType);
    AX_UNUSED_ARG(pPin);
    AX_UNUSED_ARG(ulPinLen);
    LOG_D("%s", __FUNCTION__);
    return CKR_OK;
}

/**
 * @brief Logs a user out from a token.
 */
CK_DEFINE_FUNCTION(CK_RV, C_Logout)(CK_SESSION_HANDLE hSession)
{
    AX_UNUSED_ARG(hSession);
    LOG_D("%s", __FUNCTION__);
    return CKR_OK;
}

/**
 * @brief Mixes additional seed material into the token’s random number generator.
 */
CK_DEFINE_FUNCTION(CK_RV, C_SeedRandom)
(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSeed, CK_ULONG ulSeedLen)
{
    AX_UNUSED_ARG(pSeed);
    AX_UNUSED_ARG(ulSeedLen);
    LOG_D("%s", __FUNCTION__);
    ENSURE_OR_RETURN_ON_ERROR(cryptokiInitialized == 1, CKR_CRYPTOKI_NOT_INITIALIZED);
    ENSURE_OR_RETURN_ON_ERROR(pSeed != NULL, CKR_ARGUMENTS_BAD);
    /* Nothing is done */
    return CKR_OK;
}

/**
 * @brief Finishes a multiple-part signature operation, returning the signature.
 */
CK_DEFINE_FUNCTION(CK_RV, C_SignFinal)
(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
    CK_RV xResult             = CKR_FUNCTION_FAILED;
    sss_status_t status       = kStatus_SSS_Fail;
    sss_asymmetric_t asymmCtx = {0};
    sss_algorithm_t algorithm = kAlgorithm_None;
    uint8_t data[64]          = {0};
    size_t dataLen            = sizeof(data);

    P11SessionPtr_t pxSessionObj = prvSessionPointerFromHandle(hSession);

    LOG_D("%s", __FUNCTION__);

    ENSURE_OR_RETURN_ON_ERROR(pxSessionObj != NULL, CKR_SESSION_HANDLE_INVALID);
    ENSURE_OR_EXIT_WITH_STATUS_ON_ERROR(pulSignatureLen != NULL, xResult, CKR_ARGUMENTS_BAD);
    ENSURE_OR_EXIT_WITH_STATUS_ON_ERROR(
        CKR_OK == pkcs11_parse_sign_mechanism(pxSessionObj, &algorithm), xResult, CKR_MECHANISM_INVALID);

    ENSURE_OR_EXIT_WITH_STATUS_ON_ERROR(sss_pkcs11_mutex_lock() == 0, xResult, CKR_CANT_LOCK);
    /* Checking for HMAC and performing MAC operation */
    if (algorithm == kAlgorithm_SSS_HMAC_SHA256) {
        LOG_D("MAC using SE05x");
        status = sss_mac_finish(&pxSessionObj->ctx_hmac, pSignature, (size_t *)pulSignatureLen);
        ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);
    }
    else {
        sss_object_t object = {0};
        status              = sss_digest_finish(&pxSessionObj->digest_ctx, &data[0], &dataLen);
        ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

        status = sss_key_object_init(&object, &pex_sss_demo_boot_ctx->ks);
        ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

        ENSURE_OR_GO_EXIT((pxSessionObj->xOperationKeyHandle) <= UINT8_MAX);

        status =
            sss_key_object_get_handle(&object, kSSS_CipherType_EC_NIST_P, (uint32_t)pxSessionObj->xOperationKeyHandle);
        ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

        status =
            sss_asymmetric_context_init(&asymmCtx, &pex_sss_demo_boot_ctx->session, &object, algorithm, kMode_SSS_Sign);
        ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

        status = sss_asymmetric_sign_digest(&asymmCtx, &data[0], dataLen, pSignature, (size_t *)pulSignatureLen);
        ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);
    }

    xResult = CKR_OK;
exit:
    if (pxSessionObj->ctx_hmac.session != NULL) {
        sss_mac_context_free(&pxSessionObj->ctx_hmac);
    }
    if (pxSessionObj->digest_ctx.session != NULL) {
        sss_digest_context_free(&pxSessionObj->digest_ctx);
    }
    if (asymmCtx.session != NULL) {
        sss_asymmetric_context_free(&asymmCtx);
    }
    pxSessionObj->xOperationInProgress = pkcs11NO_OPERATION;
    if (sss_pkcs11_mutex_unlock() != 0) {
        return CKR_FUNCTION_FAILED;
    }
    return xResult;
}

/**
 * @brief Continues a multiple-part signature operation, processing another data part.
 */
CK_DEFINE_FUNCTION(CK_RV, C_SignUpdate)
(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
    CK_RV xResult = CKR_FUNCTION_FAILED;
    LOG_D("%s", __FUNCTION__);
    P11SessionPtr_t pxSessionObj = prvSessionPointerFromHandle(hSession);
    sss_status_t status;
    sss_algorithm_t algorithm = kAlgorithm_None;
    sss_algorithm_t digest_algorithm;
    size_t chunk  = 0;
    size_t offset = 0;

    ENSURE_OR_RETURN_ON_ERROR(pxSessionObj != NULL, CKR_SESSION_HANDLE_INVALID);
    ENSURE_OR_EXIT_WITH_STATUS_ON_ERROR(pPart != NULL, xResult, CKR_ARGUMENTS_BAD);

    ENSURE_OR_EXIT_WITH_STATUS_ON_ERROR(sss_pkcs11_mutex_lock() == 0, xResult, CKR_CANT_LOCK);

    /* Check for mechanisms having multistep support */

    if (pxSessionObj->xOperationInProgress != CKM_ECDSA) {
        ENSURE_OR_EXIT_WITH_STATUS_ON_ERROR(
            pkcs11_parse_sign_mechanism(pxSessionObj, &algorithm) == CKR_OK, xResult, CKR_MECHANISM_INVALID);

        ENSURE_OR_EXIT_WITH_STATUS_ON_ERROR(
            pkcs11_get_digest_algorithm(algorithm, &digest_algorithm) == CKR_OK, xResult, CKR_MECHANISM_INVALID);

        if (algorithm == kAlgorithm_SSS_HMAC_SHA256) {
            if (pxSessionObj->ctx_hmac.session == NULL) { /* Avoid re-init of hmac context */
                sss_object_t object = {0};
                status              = sss_key_object_init(&object, &pex_sss_demo_boot_ctx->ks);
                ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);
                ENSURE_OR_GO_EXIT((pxSessionObj->xOperationKeyHandle) <= UINT8_MAX);

                status = sss_key_object_get_handle(
                    &object, kSSS_CipherType_AES, (uint32_t)pxSessionObj->xOperationKeyHandle);
                ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

                status = sss_mac_context_init(
                    &pxSessionObj->ctx_hmac, &pex_sss_demo_boot_ctx->session, &object, algorithm, kMode_SSS_Mac);
                ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

                status = sss_mac_init(&pxSessionObj->ctx_hmac);
                ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);
            }
            do {
                if (ulPartLen > SIZE_MAX) {
                    xResult = CKR_FUNCTION_FAILED;
                    goto exit;
                }
                chunk = (ulPartLen > PKCS11_MAX_HMAC_INPUT_DATA) ? PKCS11_MAX_HMAC_INPUT_DATA : ulPartLen;

                status = sss_mac_update(&pxSessionObj->ctx_hmac, pPart + offset, chunk);
                ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

                ENSURE_OR_GO_EXIT((SIZE_MAX - offset) >= chunk);
                offset += chunk;
                ulPartLen -= chunk;
            } while (ulPartLen > 0);
        }
        else {
            if (pxSessionObj->digest_ctx.session == NULL) { /* Avoid re-init of digest context */
#if SSS_HAVE_HOSTCRYPTO_ANY
                status = sss_digest_context_init(&pxSessionObj->digest_ctx,
                    &pex_sss_demo_boot_ctx->host_session,
                    digest_algorithm,
                    kMode_SSS_Digest);
#else
                status = kStatus_SSS_Fail;
#endif
                ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

                status = sss_digest_init(&pxSessionObj->digest_ctx);
                ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);
            }

            do {
                if (ulPartLen > SIZE_MAX) {
                    xResult = CKR_FUNCTION_FAILED;
                    goto exit;
                }
                chunk = (ulPartLen > PKCS11_MAX_DIGEST_INPUT_DATA) ? PKCS11_MAX_DIGEST_INPUT_DATA : ulPartLen;

                status = sss_digest_update(&pxSessionObj->digest_ctx, pPart + offset, chunk);
                ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

                ENSURE_OR_GO_EXIT((SIZE_MAX - offset) >= chunk);
                offset += chunk;
                ulPartLen -= chunk;
            } while (ulPartLen > 0);
        }
    }
    else {
        LOG_E("Mechanism is unsupported");
        xResult = CKR_MECHANISM_INVALID;
        goto exit;
    }

    xResult = CKR_OK;
exit:
    if (xResult != CKR_OK) {
        if (pxSessionObj->digest_ctx.session != NULL) {
            sss_digest_context_free(&pxSessionObj->digest_ctx);
        }
        if (pxSessionObj->ctx_hmac.session != NULL) {
            sss_mac_context_free(&pxSessionObj->ctx_hmac);
        }
        pxSessionObj->xOperationInProgress = pkcs11NO_OPERATION;
    }
    if (sss_pkcs11_mutex_unlock() != 0) {
        return CKR_FUNCTION_FAILED;
    }
    return xResult;
}

/**
 * @brief Begin a digital signature generation session.
 */
CK_DEFINE_FUNCTION(CK_RV, C_SignInit)
(CK_SESSION_HANDLE xSession, CK_MECHANISM_PTR pxMechanism, CK_OBJECT_HANDLE xKey)
{
    CK_RV xResult             = CKR_OK;
    P11SessionPtr_t pxSession = prvSessionPointerFromHandle(xSession);

    LOG_D("%s", __FUNCTION__);

    ENSURE_OR_RETURN_ON_ERROR(pxSession != NULL, CKR_SESSION_HANDLE_INVALID);
    ENSURE_OR_RETURN_ON_ERROR(NULL != pxMechanism, CKR_ARGUMENTS_BAD);
    //ENSURE_OR_RETURN_ON_ERROR(pxSession->xOperationInProgress == pkcs11NO_OPERATION, CKR_SESSION_HANDLE_INVALID);

    pxSession->xOperationInProgress = pxMechanism->mechanism;
    pxSession->xOperationKeyHandle  = (CK_OBJECT_HANDLE)(xKey & 0xFF);
    if (pxMechanism->pParameter) {
        pxSession->mechParameter    = pxMechanism->pParameter;
        pxSession->mechParameterLen = pxMechanism->ulParameterLen;
    }
    else {
        pxSession->mechParameterLen = 0;
    }

    if (pxSession->digest_ctx.session != NULL) {
        sss_digest_context_free(&pxSession->digest_ctx);
    }
    if (pxSession->ctx_hmac.session != NULL) {
        sss_mac_context_free(&pxSession->ctx_hmac);
    }

    return xResult;
}

/**
 * @brief Finishes a multiple-part verification operation and check's the signature.
 */
CK_DEFINE_FUNCTION(CK_RV, C_VerifyFinal)
(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
{
    CK_RV xResult       = CKR_FUNCTION_FAILED;
    sss_status_t status = {0};
    sss_algorithm_t algorithm;
    uint8_t data[64]    = {0};
    size_t dataLen      = sizeof(data);
    uint8_t pubkey[100] = {0};
    size_t pubkeylen    = sizeof(pubkey);

    LOG_D("%s", __FUNCTION__);

    P11SessionPtr_t pxSessionObj = prvSessionPointerFromHandle(hSession);

    ENSURE_OR_RETURN_ON_ERROR(pxSessionObj != NULL, CKR_SESSION_HANDLE_INVALID);

    ENSURE_OR_EXIT_WITH_STATUS_ON_ERROR(
        pkcs11_parse_sign_mechanism(pxSessionObj, &algorithm) == CKR_OK, xResult, CKR_MECHANISM_INVALID);

    ENSURE_OR_EXIT_WITH_STATUS_ON_ERROR(sss_pkcs11_mutex_lock() == 0, xResult, CKR_CANT_LOCK);

    /* Checking for HMAC and validating */
    if (algorithm == kAlgorithm_SSS_HMAC_SHA256) {
        size_t macLen = ulSignatureLen;

        LOG_D("MAC Verify using Nx");
        status = sss_mac_finish(&pxSessionObj->ctx_hmac, pSignature, &macLen);
        ENSURE_OR_EXIT_WITH_STATUS_ON_ERROR(status == kStatus_SSS_Success, xResult, CKR_SIGNATURE_INVALID);
    }
    else {
        /* ECC */
        sss_object_t object       = {0};
        sss_asymmetric_t asymmCtx = {0};
        status                    = sss_digest_finish(&pxSessionObj->digest_ctx, &data[0], &dataLen);
        ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

        status = sss_key_object_init(&object, &pex_sss_demo_boot_ctx->ks);
        ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

        ENSURE_OR_GO_EXIT((pxSessionObj->xOperationKeyHandle) <= UINT8_MAX);
        status =
            sss_key_object_get_handle(&object, kSSS_CipherType_EC_NIST_P, (uint32_t)pxSessionObj->xOperationKeyHandle);
        ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

        status = sss_key_object_allocate_handle(&object,
            (uint32_t)pxSessionObj->xOperationKeyHandle,
            kSSS_KeyPart_Public,
            (sss_cipher_type_t)object.cipherType,
            32,
            kKeyObject_Mode_Persistent);
        ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);
#if (defined(SSS_HAVE_HOST_EMBEDDED) && !(SSS_HAVE_HOST_EMBEDDED))
        if (pkcs11GetPubKeyDer(&pubkey[0], &pubkeylen) != 0) {
            LOG_E("unable to get pubkey");
            xResult = CKR_FUNCTION_FAILED;
            goto exit;
        }
#endif //!SSS_HAVE_HOST_EMBEDDED
        status = sss_key_store_set_key(&pex_sss_demo_boot_ctx->ks, &object, pubkey, pubkeylen, 256, NULL, 0);
        ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

        status = sss_asymmetric_context_init(
            &asymmCtx, &pex_sss_demo_boot_ctx->session, &object, algorithm, kMode_SSS_Verify);
        if (status != kStatus_SSS_Success) {
            xResult = CKR_FUNCTION_FAILED;
            if (asymmCtx.session != NULL) {
                sss_asymmetric_context_free(&asymmCtx);
            }
            goto exit;
        }

        status = sss_asymmetric_verify_digest(&asymmCtx, &data[0], dataLen, pSignature, ulSignatureLen);
        if (status != kStatus_SSS_Success) {
            xResult = CKR_SIGNATURE_INVALID;
            if (asymmCtx.session != NULL) {
                sss_asymmetric_context_free(&asymmCtx);
            }
            goto exit;
        }
        if (asymmCtx.session != NULL) {
            sss_asymmetric_context_free(&asymmCtx);
        }
    }

    xResult = CKR_OK;
exit:
    pxSessionObj->xOperationInProgress = pkcs11NO_OPERATION;
    if (pxSessionObj->ctx_hmac.session != NULL) {
        sss_mac_context_free(&pxSessionObj->ctx_hmac);
    }
    if (pxSessionObj->digest_ctx.session != NULL) {
        sss_digest_context_free(&pxSessionObj->digest_ctx);
    }
    if (sss_pkcs11_mutex_unlock() != 0) {
        return CKR_FUNCTION_FAILED;
    }
    return xResult;
}

/**
 * @brief Continues a multiple-part verification operation.
 */
CK_DEFINE_FUNCTION(CK_RV, C_VerifyUpdate)
(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
    CK_RV xResult = CKR_FUNCTION_FAILED;
    sss_status_t status;
    sss_algorithm_t algorithm;
    sss_algorithm_t digest_algorithm;
    size_t chunk  = 0;
    size_t offset = 0;

    LOG_D("%s", __FUNCTION__);

    P11SessionPtr_t pxSessionObj = prvSessionPointerFromHandle(hSession);

    ENSURE_OR_RETURN_ON_ERROR(pxSessionObj != NULL, CKR_SESSION_HANDLE_INVALID);
    ENSURE_OR_RETURN_ON_ERROR(pPart != NULL, CKR_ARGUMENTS_BAD);

    ENSURE_OR_EXIT_WITH_STATUS_ON_ERROR(sss_pkcs11_mutex_lock() == 0, xResult, CKR_CANT_LOCK);

    /* Check for mechanisms having multistep support */
    if (pxSessionObj->xOperationInProgress != CKM_ECDSA) {
        ENSURE_OR_EXIT_WITH_STATUS_ON_ERROR(
            CKR_OK == pkcs11_parse_sign_mechanism(pxSessionObj, &algorithm), xResult, CKR_MECHANISM_INVALID);

        ENSURE_OR_EXIT_WITH_STATUS_ON_ERROR(
            CKR_OK == pkcs11_get_digest_algorithm(algorithm, &digest_algorithm), xResult, CKR_MECHANISM_INVALID);

        if (algorithm == kAlgorithm_SSS_HMAC_SHA256) {
            if (pxSessionObj->ctx_hmac.session == NULL) { /* Avoid re-init of hmac context */
                sss_object_t object = {0};
                status              = sss_key_object_init(&object, &pex_sss_demo_boot_ctx->ks);
                ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);
                ENSURE_OR_GO_EXIT((pxSessionObj->xOperationKeyHandle) <= UINT8_MAX);

                status = sss_key_object_get_handle(
                    &object, kSSS_CipherType_AES, (uint32_t)pxSessionObj->xOperationKeyHandle);
                ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

                status = sss_mac_context_init(&pxSessionObj->ctx_hmac,
                    &pex_sss_demo_boot_ctx->session,
                    &object,
                    algorithm,
                    kMode_SSS_Mac_Validate);
                ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

                status = sss_mac_init(&pxSessionObj->ctx_hmac);
                ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);
            }
            do {
                if (ulPartLen > SIZE_MAX) {
                    xResult = CKR_FUNCTION_FAILED;
                    goto exit;
                }
                chunk = (ulPartLen > PKCS11_MAX_HMAC_INPUT_DATA) ? PKCS11_MAX_HMAC_INPUT_DATA : ulPartLen;

                status = sss_mac_update(&pxSessionObj->ctx_hmac, pPart + offset, chunk);
                ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

                ENSURE_OR_GO_EXIT((SIZE_MAX - offset) >= chunk);
                offset += chunk;
                ulPartLen -= chunk;
            } while (ulPartLen > 0);
        }
        else {
            if (pxSessionObj->digest_ctx.session == NULL) { /* Avoid re-init of digest context */
#if SSS_HAVE_HOSTCRYPTO_ANY
                status = sss_digest_context_init(&pxSessionObj->digest_ctx,
                    &pex_sss_demo_boot_ctx->host_session,
                    digest_algorithm,
                    kMode_SSS_Digest);
#else
                status = kStatus_SSS_Fail;
#endif
                ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

                status = sss_digest_init(&pxSessionObj->digest_ctx);
                ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);
            }

            do {
                if (ulPartLen > SIZE_MAX) {
                    xResult = CKR_FUNCTION_FAILED;
                    goto exit;
                }
                chunk = (ulPartLen > PKCS11_MAX_DIGEST_INPUT_DATA) ? PKCS11_MAX_DIGEST_INPUT_DATA : ulPartLen;

                status = sss_digest_update(&pxSessionObj->digest_ctx, pPart + offset, chunk);
                ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

                if ((SIZE_MAX - offset) < chunk) {
                    goto exit;
                }
                offset += chunk;
                ulPartLen -= chunk;
            } while (ulPartLen > 0);
        }
    }
    else {
        LOG_E("Mechanism is unsupported");
        xResult = CKR_MECHANISM_INVALID;
        goto exit;
    }

    xResult = CKR_OK;
exit:
    if (xResult != CKR_OK) {
        pxSessionObj->xOperationInProgress = pkcs11NO_OPERATION;
        if (pxSessionObj->digest_ctx.session != NULL) {
            sss_digest_context_free(&pxSessionObj->digest_ctx);
        }
        if (pxSessionObj->ctx_hmac.session != NULL) {
            sss_mac_context_free(&pxSessionObj->ctx_hmac);
        }
    }
    if (sss_pkcs11_mutex_unlock() != 0) {
        return CKR_FUNCTION_FAILED;
    }
    return xResult;
}

/**
 * @brief Begin a digital signature verification session.
 */
CK_DEFINE_FUNCTION(CK_RV, C_VerifyInit)
(CK_SESSION_HANDLE xSession, CK_MECHANISM_PTR pxMechanism, CK_OBJECT_HANDLE xKey)
{
    CK_RV xResult             = CKR_OK;
    P11SessionPtr_t pxSession = prvSessionPointerFromHandle(xSession);

    LOG_D("%s", __FUNCTION__);

    ENSURE_OR_RETURN_ON_ERROR(pxSession != NULL, CKR_SESSION_HANDLE_INVALID);
    ENSURE_OR_RETURN_ON_ERROR(NULL != pxMechanism, CKR_ARGUMENTS_BAD);
    ENSURE_OR_RETURN_ON_ERROR(pxSession->xOperationInProgress == pkcs11NO_OPERATION, CKR_SESSION_HANDLE_INVALID);

    pxSession->xOperationInProgress = pxMechanism->mechanism;
    pxSession->xOperationKeyHandle  = (CK_OBJECT_HANDLE)(xKey & 0xFF);

    if (pxMechanism->pParameter) {
        pxSession->mechParameter    = pxMechanism->pParameter;
        pxSession->mechParameterLen = pxMechanism->ulParameterLen;
    }
    else {
        pxSession->mechParameterLen = 0;
    }

    if (pxSession->digest_ctx.session != NULL) {
        sss_digest_context_free(&pxSession->digest_ctx);
    }
    if (pxSession->ctx_hmac.session != NULL) {
        sss_mac_context_free(&pxSession->ctx_hmac);
    }

    return xResult;
}

/**
 * @brief Obtains information about the session.
 */
CK_DEFINE_FUNCTION(CK_RV, C_GetSessionInfo)
(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo)
{
    LOG_D("%s", __FUNCTION__);
    CK_RV xResult            = CKR_SESSION_CLOSED;
    P11SessionPtr_t pSession = prvSessionPointerFromHandle(hSession);
    CK_FLAGS ro_flags        = CKF_SERIAL_SESSION;

    ENSURE_OR_RETURN_ON_ERROR(NULL != pInfo, CKR_ARGUMENTS_BAD);

    ENSURE_OR_RETURN_ON_ERROR(hSession > 0, CKR_SESSION_HANDLE_INVALID);
    ENSURE_OR_RETURN_ON_ERROR(pSession != NULL, CKR_SESSION_HANDLE_INVALID);

    if (sss_pkcs11_mutex_lock() != 0) {
        xResult = CKR_FUNCTION_FAILED;
        return xResult;
    }

    CK_SESSION_INFO session_info = {.slotID = pkcs11SLOT_ID,
        .state         = ((pSession->xFlags == ro_flags) ? CKS_RO_PUBLIC_SESSION : CKS_RW_PUBLIC_SESSION),
        .flags         = pSession->xFlags,
        .ulDeviceError = 0};

#if defined(USE_RTOS) && USE_RTOS == 1
#elif (__GNUC__ && defined(SSS_HAVE_HOST_EMBEDDED) && !(SSS_HAVE_HOST_EMBEDDED))
#else
    session_info.flags = session_info.flags | CKF_SERIAL_SESSION;
#endif

    if (sessionCount) {
        memcpy(pInfo, &session_info, sizeof(CK_SESSION_INFO));
        xResult = CKR_OK;
    }

    if (sss_pkcs11_mutex_unlock() != 0) {
        return CKR_FUNCTION_FAILED;
    }

    return xResult;
}

// LCOV_EXCL_START
/**
 * @brief Wraps (i.e., encrypts) a private or secret key.
 */
CK_DEFINE_FUNCTION(CK_RV, C_WrapKey)
(CK_SESSION_HANDLE hSession,
    CK_MECHANISM_PTR pMechanism,
    CK_OBJECT_HANDLE hWrappingKey,
    CK_OBJECT_HANDLE hKey,
    CK_BYTE_PTR pWrappedKey,
    CK_ULONG_PTR pulWrappedKeyLen)
{
    AX_UNUSED_ARG(hSession);
    AX_UNUSED_ARG(pMechanism);
    AX_UNUSED_ARG(hWrappingKey);
    AX_UNUSED_ARG(hKey);
    AX_UNUSED_ARG(pWrappedKey);
    AX_UNUSED_ARG(pulWrappedKeyLen);
    LOG_D("%s", __FUNCTION__);

    return CKR_FUNCTION_NOT_SUPPORTED;
}

/**
 * @brief Initializes a token along with slotID and Pin.
 */
CK_DEFINE_FUNCTION(CK_RV, C_InitToken)
(CK_SLOT_ID slotID, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen, CK_UTF8CHAR_PTR pLabel)
{
    AX_UNUSED_ARG(slotID);
    AX_UNUSED_ARG(pPin);
    AX_UNUSED_ARG(ulPinLen);
    AX_UNUSED_ARG(pLabel);
    LOG_D("%s", __FUNCTION__);

    return CKR_FUNCTION_NOT_SUPPORTED;
}

/**
 * @brief Initializes the normal user’s PIN.
 */
CK_DEFINE_FUNCTION(CK_RV, C_InitPIN)
(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen)
{
    AX_UNUSED_ARG(hSession);
    AX_UNUSED_ARG(pPin);
    AX_UNUSED_ARG(ulPinLen);
    LOG_D("%s", __FUNCTION__);

    return CKR_FUNCTION_NOT_SUPPORTED;
}

/**
 * @brief Modifies the PIN of the user that is currently logged in.
 */
CK_DEFINE_FUNCTION(CK_RV, C_SetPIN)
(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pOldPin, CK_ULONG ulOldLen, CK_UTF8CHAR_PTR pNewPin, CK_ULONG ulNewLen)
{
    AX_UNUSED_ARG(hSession);
    AX_UNUSED_ARG(pOldPin);
    AX_UNUSED_ARG(ulOldLen);
    AX_UNUSED_ARG(pNewPin);
    AX_UNUSED_ARG(ulNewLen);
    LOG_D("%s", __FUNCTION__);

    return CKR_FUNCTION_NOT_SUPPORTED;
}

/**
 * @brief Closes all sessions an application has with a token..
 */
CK_DEFINE_FUNCTION(CK_RV, C_CloseAllSessions)(CK_SLOT_ID slotID)
{
    AX_UNUSED_ARG(slotID);
    LOG_D("%s", __FUNCTION__);
    return CKR_FUNCTION_NOT_SUPPORTED;
}

/**
 * @brief Obtains a copy of the cryptographic operations state of a session, encoded as a string of bytes.
 */
CK_DEFINE_FUNCTION(CK_RV, C_GetOperationState)
(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG_PTR pulOperationStateLen)
{
    AX_UNUSED_ARG(hSession);
    AX_UNUSED_ARG(pOperationState);
    AX_UNUSED_ARG(pulOperationStateLen);
    LOG_D("%s", __FUNCTION__);
    return CKR_FUNCTION_NOT_SUPPORTED;
}

/**
 * @brief Restores the cryptographic operations state of a session from a string of bytes obtained with C_GetOperationState.
 */
CK_DEFINE_FUNCTION(CK_RV, C_SetOperationState)
(CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pOperationState,
    CK_ULONG ulOperationStateLen,
    CK_OBJECT_HANDLE hEncryptionKey,
    CK_OBJECT_HANDLE hAuthenticationKey)
{
    AX_UNUSED_ARG(hSession);
    AX_UNUSED_ARG(pOperationState);
    AX_UNUSED_ARG(ulOperationStateLen);
    AX_UNUSED_ARG(hEncryptionKey);
    AX_UNUSED_ARG(hAuthenticationKey);
    LOG_D("%s", __FUNCTION__);
    return CKR_FUNCTION_NOT_SUPPORTED;
}

/**
 * @brief Initializes a signature operation, where the data can be recovered from the signature.
 */
CK_DEFINE_FUNCTION(CK_RV, C_SignRecoverInit)
(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
    AX_UNUSED_ARG(hSession);
    AX_UNUSED_ARG(pMechanism);
    AX_UNUSED_ARG(hKey);
    LOG_D("%s", __FUNCTION__);
    return CKR_FUNCTION_NOT_SUPPORTED;
}

/**
 * @brief Signs data in a single operation, where the data can be recovered from the signature.
 */
CK_DEFINE_FUNCTION(CK_RV, C_SignRecover)
(CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pData,
    CK_ULONG ulDataLen,
    CK_BYTE_PTR pSignature,
    CK_ULONG_PTR pulSignatureLen)
{
    AX_UNUSED_ARG(hSession);
    AX_UNUSED_ARG(pData);
    AX_UNUSED_ARG(ulDataLen);
    AX_UNUSED_ARG(pSignature);
    AX_UNUSED_ARG(pulSignatureLen);
    LOG_D("%s", __FUNCTION__);
    return CKR_FUNCTION_NOT_SUPPORTED;
}

/**
 * @brief Initializes a signature verification operation, where the data is recovered from the signature.
 */
CK_DEFINE_FUNCTION(CK_RV, C_VerifyRecoverInit)
(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
    AX_UNUSED_ARG(hSession);
    AX_UNUSED_ARG(pMechanism);
    AX_UNUSED_ARG(hKey);
    LOG_D("%s", __FUNCTION__);
    return CKR_FUNCTION_NOT_SUPPORTED;
}

/**
 * @brief Verifies a signature in a single-part operation, where the data is recovered from the signature.
 */
CK_DEFINE_FUNCTION(CK_RV, C_VerifyRecover)
(CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pSignature,
    CK_ULONG ulSignatureLen,
    CK_BYTE_PTR pData,
    CK_ULONG_PTR pulDataLen)
{
    AX_UNUSED_ARG(hSession);
    AX_UNUSED_ARG(pSignature);
    AX_UNUSED_ARG(ulSignatureLen);
    AX_UNUSED_ARG(pData);
    AX_UNUSED_ARG(pulDataLen);
    LOG_D("%s", __FUNCTION__);
    return CKR_FUNCTION_NOT_SUPPORTED;
}

/**
 * @brief Continues multiple-part digest and encryption operations.
 */
CK_DEFINE_FUNCTION(CK_RV, C_DigestEncryptUpdate)
(CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pPart,
    CK_ULONG ulPartLen,
    CK_BYTE_PTR pEncryptedPart,
    CK_ULONG_PTR pulEncryptedPartLen)
{
    AX_UNUSED_ARG(hSession);
    AX_UNUSED_ARG(pPart);
    AX_UNUSED_ARG(ulPartLen);
    AX_UNUSED_ARG(pEncryptedPart);
    AX_UNUSED_ARG(pulEncryptedPartLen);
    LOG_D("%s", __FUNCTION__);
    return CKR_FUNCTION_NOT_SUPPORTED;
}

/**
 * @brief Continues a multiple-part combined decryption and digest operation.
 */
CK_DEFINE_FUNCTION(CK_RV, C_DecryptDigestUpdate)
(CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pEncryptedPart,
    CK_ULONG ulEncryptedPartLen,
    CK_BYTE_PTR pPart,
    CK_ULONG_PTR pulPartLen)
{
    AX_UNUSED_ARG(hSession);
    AX_UNUSED_ARG(pEncryptedPart);
    AX_UNUSED_ARG(ulEncryptedPartLen);
    AX_UNUSED_ARG(pPart);
    AX_UNUSED_ARG(pulPartLen);
    LOG_D("%s", __FUNCTION__);
    return CKR_FUNCTION_NOT_SUPPORTED;
}

/**
 * @brief Continues a multiple-part combined signature and encryption operation.
 */
CK_DEFINE_FUNCTION(CK_RV, C_SignEncryptUpdate)
(CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pPart,
    CK_ULONG ulPartLen,
    CK_BYTE_PTR pEncryptedPart,
    CK_ULONG_PTR pulEncryptedPartLen)
{
    AX_UNUSED_ARG(hSession);
    AX_UNUSED_ARG(pPart);
    AX_UNUSED_ARG(ulPartLen);
    AX_UNUSED_ARG(pEncryptedPart);
    AX_UNUSED_ARG(pulEncryptedPartLen);
    LOG_D("%s", __FUNCTION__);
    return CKR_FUNCTION_NOT_SUPPORTED;
}

/**
 * @brief Continues a multiple-part combined decryption and verification operation.
 */
CK_DEFINE_FUNCTION(CK_RV, C_DecryptVerifyUpdate)
(CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pEncryptedPart,
    CK_ULONG ulEncryptedPartLen,
    CK_BYTE_PTR pPart,
    CK_ULONG_PTR pulPartLen)
{
    AX_UNUSED_ARG(hSession);
    AX_UNUSED_ARG(pEncryptedPart);
    AX_UNUSED_ARG(ulEncryptedPartLen);
    AX_UNUSED_ARG(pPart);
    AX_UNUSED_ARG(pulPartLen);
    LOG_D("%s", __FUNCTION__);
    return CKR_FUNCTION_NOT_SUPPORTED;
}

/**
 * @brief Legacy function which always return value CKR_FUNCTION_NOT_PARALLEL.
 */
CK_DEFINE_FUNCTION(CK_RV, C_GetFunctionStatus)(CK_SESSION_HANDLE hSession)
{
    AX_UNUSED_ARG(hSession);
    LOG_D("%s", __FUNCTION__);
    return CKR_FUNCTION_NOT_PARALLEL;
}

/**
 * @brief Legacy function which always return value CKR_FUNCTION_NOT_PARALLEL.
 */
CK_DEFINE_FUNCTION(CK_RV, C_CancelFunction)(CK_SESSION_HANDLE hSession)
{
    AX_UNUSED_ARG(hSession);
    LOG_D("%s", __FUNCTION__);
    return CKR_FUNCTION_NOT_PARALLEL;
}

/**
 * @brief Waits for a slot event to occur.
 */
CK_DEFINE_FUNCTION(CK_RV, C_WaitForSlotEvent)
(CK_FLAGS flags, CK_SLOT_ID_PTR pSlot, CK_VOID_PTR pReserved)
{
    AX_UNUSED_ARG(flags);
    AX_UNUSED_ARG(pSlot);
    AX_UNUSED_ARG(pReserved);
    LOG_D("%s", __FUNCTION__);
    return CKR_FUNCTION_NOT_SUPPORTED;
}

/**
 * @brief Finishes a multiple-part decryption operation.
 */
CK_DEFINE_FUNCTION(CK_RV, C_DecryptFinal)
(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastPart, CK_ULONG_PTR pulLastPartLen)
{
    AX_UNUSED_ARG(hSession);
    AX_UNUSED_ARG(pLastPart);
    AX_UNUSED_ARG(pulLastPartLen);
    LOG_D("%s", __FUNCTION__);
    return CKR_FUNCTION_NOT_SUPPORTED;
}

/**
 * @brief Continues if there is multiple-part of data.
 */
CK_DEFINE_FUNCTION(CK_RV, C_DecryptUpdate)
(CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pEncryptedPart,
    CK_ULONG ulEncryptedPartLen,
    CK_BYTE_PTR pPart,
    CK_ULONG_PTR pulPartLen)
{
    AX_UNUSED_ARG(hSession);
    AX_UNUSED_ARG(pEncryptedPart);
    AX_UNUSED_ARG(ulEncryptedPartLen);
    AX_UNUSED_ARG(pPart);
    AX_UNUSED_ARG(pulPartLen);
    LOG_D("%s", __FUNCTION__);
    return CKR_FUNCTION_NOT_SUPPORTED;
}

/**
 * @brief Continues a multiple-part message-digesting operation by digesting the value of a secret key.
 */
CK_DEFINE_FUNCTION(CK_RV, C_DigestKey)
(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey)
{
    AX_UNUSED_ARG(hSession);
    AX_UNUSED_ARG(hKey);
    LOG_D("%s", __FUNCTION__);
    return CKR_FUNCTION_NOT_SUPPORTED;
}

/**
 * @brief continues a multiple-part encryption operation, processing another data part.
 */
CK_DEFINE_FUNCTION(CK_RV, C_EncryptUpdate)
(CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pPart,
    CK_ULONG ulPartLen,
    CK_BYTE_PTR pEncryptedPart,
    CK_ULONG_PTR pulEncryptedPartLen)
{
    AX_UNUSED_ARG(hSession);
    AX_UNUSED_ARG(pPart);
    AX_UNUSED_ARG(ulPartLen);
    AX_UNUSED_ARG(pEncryptedPart);
    AX_UNUSED_ARG(pulEncryptedPartLen);
    LOG_D("%s", __FUNCTION__);
    return CKR_FUNCTION_NOT_SUPPORTED;
}

/**
 * @brief Finishes a multiple-part data encryption operation.
 */
CK_DEFINE_FUNCTION(CK_RV, C_EncryptFinal)
(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastEncryptedPart, CK_ULONG_PTR pulLastEncryptedPartLen)
{
    AX_UNUSED_ARG(hSession);
    AX_UNUSED_ARG(pLastEncryptedPart);
    AX_UNUSED_ARG(pulLastEncryptedPartLen);
    LOG_D("%s", __FUNCTION__);
    return CKR_FUNCTION_NOT_SUPPORTED;
}

/**
 * @brief Modifies the value of one or more attributes of an object.
 */
CK_DEFINE_FUNCTION(CK_RV, C_SetAttributeValue)
(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
    AX_UNUSED_ARG(hSession);
    AX_UNUSED_ARG(hObject);
    AX_UNUSED_ARG(pTemplate);
    AX_UNUSED_ARG(ulCount);
    LOG_D("%s", __FUNCTION__);
    return CKR_FUNCTION_NOT_SUPPORTED;
}

/**
 * @brief unwraps a wrapped key, creating a new private key or secret key object.
 */
CK_DEFINE_FUNCTION(CK_RV, C_UnwrapKey)
(CK_SESSION_HANDLE hSession,
    CK_MECHANISM_PTR pMechanism,
    CK_OBJECT_HANDLE hUnwrappingKey,
    CK_BYTE_PTR pWrappedKey,
    CK_ULONG ulWrappedKeyLen,
    CK_ATTRIBUTE_PTR pTemplate,
    CK_ULONG ulAttributeCount,
    CK_OBJECT_HANDLE_PTR phKey)
{
    AX_UNUSED_ARG(hSession);
    AX_UNUSED_ARG(pMechanism);
    AX_UNUSED_ARG(hUnwrappingKey);
    AX_UNUSED_ARG(pWrappedKey);
    AX_UNUSED_ARG(ulWrappedKeyLen);
    AX_UNUSED_ARG(pTemplate);
    AX_UNUSED_ARG(ulAttributeCount);
    AX_UNUSED_ARG(phKey);

    LOG_D("%s", __FUNCTION__);

    return CKR_FUNCTION_NOT_SUPPORTED;
}
// LCOV_EXCL_STOP
