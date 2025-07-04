/*
 * Copyright 2024 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 */

/* ********************** Include files ********************** */
#include "sss_pkcs11_pal.h"

/* ********************** Public Functions ********************** */

/** @brief Symmetric Encryption.
 * This function generates a random IV (initialization vector), nonce
 * or initial counter value for the encryption operation as appropriate
 * for the chosen algorithm, key type and key size.
 *
 * @param pxSessionObj - Pointer to mechParameter for initializing initialization vector.
 * @param algorithm - Algorithm to be applied, e.g. kAlgorithm_SSS_AES_CBC.
 * @param pData - Buffer containing the input data.
 * @param ulDataLen - Length of the buffer pData.
 * @param pEncryptedData - Buffer containing the encrypted data.
 * @param pulEncryptedDataLen - Length of the buffer pEncryptedData.

 * @returns Status of the operation
 * @retval #CKR_OK The operation has completed successfully.
 * @retval #CKR_FUNCTION_FAILED The requested function could not be performed.
 * @retval #CKR_DEVICE_ERROR If some problem has occured with the token or slot.
 * @retval #CKR_BUFFER_TOO_SMALL The output of function is too large to fit in supplied buffer.
 */
CK_RV pkcs11_nx_symmetric_encrypt(P11SessionPtr_t pxSessionObj,
    sss_algorithm_t algorithm,
    CK_BYTE_PTR pData,
    CK_ULONG ulDataLen,
    CK_BYTE_PTR pEncryptedData,
    CK_ULONG_PTR pulEncryptedDataLen)
{
    CK_RV xResult              = CKR_FUNCTION_FAILED;
    sss_status_t status        = kStatus_SSS_Fail;
    sss_symmetric_t symmCtx    = {0};
    sss_object_t symmObject    = {0};
    uint8_t iv[AES_BLOCK_SIZE] = {0};
    size_t ivLen               = sizeof(iv);
    uint8_t encData[16]        = {0};
    size_t encDataLen          = sizeof(encData);

    if (algorithm == kAlgorithm_SSS_AES_CBC) {
        if (pxSessionObj->mechParameterLen != 0) {
            memcpy(iv, pxSessionObj->mechParameter, ivLen);
        }
    }

    ENSURE_OR_RETURN_ON_ERROR(sss_pkcs11_mutex_lock() == 0, CKR_CANT_LOCK);

    status = sss_key_object_init(&symmObject, &pex_sss_demo_boot_ctx->ks);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    ENSURE_OR_GO_EXIT((pxSessionObj->xOperationKeyHandle) <= UINT32_MAX);
    status = sss_key_object_get_handle(&symmObject, kSSS_CipherType_AES, pxSessionObj->xOperationKeyHandle);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    status = sss_symmetric_context_init(
        &symmCtx, &pex_sss_demo_boot_ctx->session, &symmObject, algorithm, kMode_SSS_Encrypt);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    /*Do Encryption*/
    status = sss_cipher_init(&symmCtx, iv, ivLen);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    status = sss_cipher_one_go(&symmCtx, iv, ivLen, (const uint8_t *)pData, encData, encDataLen);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    if (pEncryptedData) {
        if (*pulEncryptedDataLen < encDataLen) {
            /* Required length should be returned */
            *pulEncryptedDataLen = encDataLen;
            xResult              = CKR_BUFFER_TOO_SMALL;
            goto exit;
        }
        memcpy(pEncryptedData, &encData[0], encDataLen);
        pxSessionObj->xOperationInProgress = pkcs11NO_OPERATION;
    }
    *pulEncryptedDataLen = encDataLen;
    LOG_AU8_W(encData, encDataLen);

    xResult = CKR_OK;
exit:
    if (symmCtx.session != NULL) {
        sss_symmetric_context_free(&symmCtx);
    }
    if (sss_pkcs11_mutex_unlock() != 0) {
        return CKR_FUNCTION_FAILED;
    }
    return xResult;
}

/** @brief Symmetric Decryption.
 * This function generates a random IV (initialization vector), nonce
 * or initial counter value for the decryption operation as appropriate
 * for the chosen algorithm, key type and key size.
 *
 * @param pxSessionObj - Pointer to mechParameter for initializing initialization vector.
 * @param algorithm - Algorithm to be applied, e.g. kAlgorithm_SSS_AES_CBC.
 * @param pEncryptedData - Buffer containing the encrypted data.
 * @param ulEncryptedDataLen - Length of the buffer pEncryptedData.
 * @param pData - Buffer containing the decrypted data.
 * @param pulDecryptedDataLen - Length of the buffer pData.

 * @returns Status of the operation
 * @retval #CKR_OK The operation has completed successfully.
 * @retval #CKR_FUNCTION_FAILED The requested function could not be performed.
 * @retval #CKR_DEVICE_ERROR If some problem has occured with the token or slot.
 * @retval #CKR_BUFFER_TOO_SMALL The output of function is too large to fit in supplied buffer.
 */
CK_RV pkcs11_nx_symmetric_decrypt(P11SessionPtr_t pxSessionObj,
    sss_algorithm_t algorithm,
    CK_BYTE_PTR pEncryptedData,
    CK_ULONG ulEncryptedDataLen,
    CK_BYTE_PTR pData,
    CK_ULONG_PTR pulDecryptedDataLen)
{
    CK_RV xResult              = CKR_FUNCTION_FAILED;
    sss_status_t status        = kStatus_SSS_Fail;
    sss_symmetric_t symmCtx    = {0};
    sss_object_t symmObject    = {0};
    uint8_t iv[AES_BLOCK_SIZE] = {0};
    size_t ivLen               = sizeof(iv);
    uint8_t encData[256]       = {0};
    size_t encDataLen          = sizeof(encData);
    size_t tempOutBufLen       = encDataLen;
    uint8_t *pOut              = &encData[0];
    size_t i                   = 0;

    if (algorithm == kAlgorithm_SSS_AES_CBC) {
        if (pxSessionObj->mechParameterLen != 0) {
            memcpy(iv, pxSessionObj->mechParameter, ivLen);
        }
    }

    ENSURE_OR_RETURN_ON_ERROR(sss_pkcs11_mutex_lock() == 0, CKR_CANT_LOCK);

    status = sss_key_object_init(&symmObject, &pex_sss_demo_boot_ctx->ks);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    ENSURE_OR_GO_EXIT((pxSessionObj->xOperationKeyHandle) <= UINT32_MAX);

    status = sss_key_object_get_handle(&symmObject, kSSS_CipherType_AES, pxSessionObj->xOperationKeyHandle);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    status = sss_symmetric_context_init(
        &symmCtx, &pex_sss_demo_boot_ctx->session, &symmObject, algorithm, kMode_SSS_Decrypt);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    /*Do Decryption*/
    status = sss_cipher_init(&symmCtx, iv, ivLen);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    status =
        sss_cipher_update(&symmCtx, (const uint8_t *)pEncryptedData, (size_t)ulEncryptedDataLen, pOut, &tempOutBufLen);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    pOut       = pOut + tempOutBufLen;
    encDataLen = tempOutBufLen;
    ENSURE_OR_GO_EXIT(sizeof(encData) >= tempOutBufLen);
    tempOutBufLen = sizeof(encData) - tempOutBufLen;

    status = sss_cipher_finish(&symmCtx, NULL, 0, pOut, &tempOutBufLen);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    encDataLen = encDataLen + tempOutBufLen;

    while ((encData[encDataLen - 1 - i] == 0) && i < encDataLen) {
        i++;
    }
    encDataLen = encDataLen - i;
    if (pData) {
        ENSURE_OR_GO_EXIT(*pulDecryptedDataLen >= encDataLen);
        if (encDataLen > 0) {
            memcpy(pData, &encData[0], encDataLen);
            pxSessionObj->xOperationInProgress = pkcs11NO_OPERATION;
        }
    }
    *pulDecryptedDataLen = encDataLen;

    xResult = CKR_OK;
exit:
    if (symmCtx.session != NULL) {
        sss_symmetric_context_free(&symmCtx);
    }
    if (sss_pkcs11_mutex_unlock() != 0) {
        return CKR_FUNCTION_FAILED;
    }
    return xResult;
}
