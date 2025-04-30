/*
 * Copyright 2024 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 */

/* ********************** Include files ********************** */
#include "sss_pkcs11_pal.h"

/* ********************** Defines ********************** */
#define ASN1_SKIP_TO_NEXT_TAG(pTLV, taglen)            \
    {                                                  \
        if (taglen < 0x7F) {                           \
            pTLV += taglen + 1 + 1 /* Length byte */;  \
        }                                              \
        else if (taglen < 0xFF) {                      \
            pTLV += taglen + 1 + 2 /* Length bytes */; \
        }                                              \
        else {                                         \
            pTLV += taglen + 1 + 3 /* Length bytes */; \
        }                                              \
    }

#define IS_VALID_TAG(x)                                                                             \
    (x == ASN_TAG_SEQUENCE || x == ASN_TAG_OBJ_IDF || x == ASN_TAG_BITSTRING || x == ASN_TAG_INT || \
        x == ASN_TAG_OCTETSTRING || x == ASN_TAG_CNT_SPECIFIC || x == ASN_TAG_CRL_EXTENSIONS) ?     \
        1 :                                                                                         \
        0

/* ********************** Public Functions ********************** */

static int check_tag(int tag);
int asn_1_parse_tlv(uint8_t *pbuf, size_t *taglen, size_t *bufindex);

/** @brief ParseSign Mechanism.
 * This function mapping sign mechanism from PKCS#11.
 *
 * @param pxSession - Pointer to handle PKCS11 session.
 * @param algorithm - Algorithm to be applied, e.g. kAlgorithm_SSS_AES_CBC.
 *
 * @returns Status of the operation
 * @retval #CKR_OK The operation has completed successfully.
 * @retval #CKR_ARGUMENTS_BAD The arguments supplied to the function are not appropriate.
 * @retval #CKR_MECHANISM_INVALID If unknown mechanism specified.
 *
 */
CK_RV pkcs11_parse_sign_mechanism(P11SessionPtr_t pxSession, sss_algorithm_t *algorithm)
{
    CK_RV xResult = CKR_OK;
    switch (pxSession->xOperationInProgress) {
    case CKM_ECDSA:
        /* Default */
        *algorithm = kAlgorithm_SSS_ECDSA_SHA256;
        break;
    case CKM_ECDSA_SHA256:
        *algorithm = kAlgorithm_SSS_ECDSA_SHA256;
        break;
    case CKM_SHA256_HMAC:
        *algorithm = kAlgorithm_SSS_HMAC_SHA256;
        break;
    default:
        xResult = CKR_MECHANISM_INVALID;
        break;
    }
    return xResult;
}

/** @brief ParseEncryption Mechanism.
 * This function mapping encryption mechanism from PKCS#11.
 *
 * @param pxSession - Pointer to handle PKCS#11 session.
 * @param algorithm - Algorithm to be applied, e.g. kAlgorithm_SSS_AES_CBC.
 *
 * @returns Status of the operation
 * @retval #CKR_OK The operation has completed successfully.
 * @retval #CKR_ARGUMENTS_BAD The arguments supplied to the function are not appropriate.
 * @retval #CKR_MECHANISM_INVALID If unknown mechanism specified.
 *
 */
CK_RV pkcs11_parse_encryption_mechanism(P11SessionPtr_t pxSession, sss_algorithm_t *algorithm)
{
    CK_RV xResult = CKR_OK;

    switch (pxSession->xOperationInProgress) {
    case CKM_AES_ECB:
        *algorithm = kAlgorithm_SSS_AES_ECB;
        break;
    case CKM_AES_CBC:
        *algorithm = kAlgorithm_SSS_AES_CBC;
        break;

    default:
        xResult = CKR_MECHANISM_INVALID;
        break;
    }
    return xResult;
}

/** @brief ParseDigest Mechanism.
 *This function mapping digest mechanism from PKCS#11.
 *
 * @param pxSession - Pointer to handle PKCS#11 session.
 * @param algorithm - Algorithm to be applied, e.g. kAlgorithm_SSS_AES_CBC.
 *
 * @returns Status of the operation
 * @retval #CKR_OK The operation has completed successfully.
 * @retval #CKR_MECHANISM_INVALID If unknown mechanism specified.
 *
 */
CK_RV pkcs11_parse_digest_mechanism(P11SessionPtr_t pxSession, sss_algorithm_t *algorithm)
{
    CK_RV xResult = CKR_OK;
    switch (pxSession->xOperationInProgress) {
    case CKM_SHA256:
        *algorithm = kAlgorithm_SSS_SHA256;
        break;
    case CKM_SHA384:
        *algorithm = kAlgorithm_SSS_SHA384;
        break;
    default:
        xResult = CKR_MECHANISM_INVALID;
        break;
    }
    return xResult;
}

/** @brief Get SSS Algorithm.
 * This function defines the digest algorithm.
 *
 * @param algorithm - Algorithm to be applied, e.g. kAlgorithm_SSS_AES_CBC.
 * @param digest_algo - Algorithm to calculate the digest.
 *
 * @returns Status of the operation
 * @retval #CKR_OK The operation has completed successfully.
 * @retval #CKR_ARGUMENTS_BAD The arguments supplied to the function are not appropriate.
 *
 */
CK_RV pkcs11_get_digest_algorithm(const sss_algorithm_t algorithm, sss_algorithm_t *digest_algo)
{
    switch (algorithm) {
    case kAlgorithm_SSS_SHA1:
    case kAlgorithm_SSS_ECDSA_SHA1:
        *digest_algo = kAlgorithm_SSS_SHA1;
        break;
    case kAlgorithm_SSS_SHA224:
    case kAlgorithm_SSS_ECDSA_SHA224:
        *digest_algo = kAlgorithm_SSS_SHA224;
        break;
    case kAlgorithm_SSS_SHA256:
    case kAlgorithm_SSS_ECDSA_SHA256:
    case kAlgorithm_SSS_HMAC_SHA256:
        *digest_algo = kAlgorithm_SSS_SHA256;
        break;
    case kAlgorithm_SSS_SHA384:
    case kAlgorithm_SSS_ECDSA_SHA384:
        *digest_algo = kAlgorithm_SSS_SHA384;
        break;
    case kAlgorithm_SSS_SHA512:
    case kAlgorithm_SSS_ECDSA_SHA512:
        *digest_algo = kAlgorithm_SSS_SHA512;
        break;
    default:
        return CKR_ARGUMENTS_BAD;
    }
    return CKR_OK;
}

/** @brief isX509 Certificate.
 * Helper function to check for certificates at particular keyID.
 *
 * @param xObject - Pointer to handle PKCS#11 object.
 *
 * @returns Status of the operation
 * @retval #CK_FALSE The operation returns zero value.
 */
CK_BBOOL pkcs11_is_X509_certificate(uint32_t xObject)
{
    CK_BBOOL xResult     = CK_FALSE;
    uint8_t data[1024]   = {0};
    size_t dataLen       = 0;
    smStatus_t sm_status = SM_NOT_OK;

    sm_status = pkcs11_get_cert_file(xObject, &data[0], &dataLen);

    if (sm_status != SM_OK) {
        return xResult;
    }
    if (0 != pkcs11_parse_Cert(&data[0], dataLen)) {
        return xResult;
    }

    return CK_TRUE;
}

/** @brief Label To KeyId.
 * This function defines the label to the KeyId by using three different ways.
 *
 * @param label - The array containing the label.
 * @param labelSize - The size of the label.
 * @param keyId - Buffer containing generated keyId.
 *
 * @returns Status of the operation
 * @retval #CKR_OK The operation has completed successfully.
 * @retval #CKR_DEVICE_ERROR If some problem has occured with the token or slot.
 * @retval #CKR_ARGUMENTS_BAD The arguments supplied to the function are not appropriate.
 */
CK_RV pkcs11_label_to_keyId(unsigned char *label, size_t labelSize, uint32_t *keyId)
{
    CK_RV result = CKR_FUNCTION_FAILED;

    if (strncmp((char *)label, "sss:", strlen("sss:")) == 0) {
        char labelCopy[32] = {0};
        memset(labelCopy, '\0', sizeof(labelCopy));
        strncpy(labelCopy, (char *)label, labelSize);
        unsigned long long_id = 0;
        uint8_t key_id        = 0;
        char *id              = (char *)&labelCopy[0];
        long_id               = strtoul(id + 4, NULL, 16);

        /* Check for cert id*/
        if (CHECK_FOR_CERT_ID(long_id)) {
            key_id = (uint8_t)(long_id & 0xFF);
            if (((key_id != 0) && (key_id <= RESERVE_FILE_IDS)) || key_id >= MAX_CERT_IDS) {
                LOG_E("Invalid Label : %s", label);
                result = CKR_ARGUMENTS_BAD;
                goto exit;
            }
            *keyId = (uint32_t)((key_id & 0xFF) | CERT_ID_MASK);
        }
        /* Check for asymm id*/
        else if (CHECK_FOR_ASYMM_ID(long_id)) {
            key_id = (uint8_t)(long_id & 0xFF);
            if (key_id >= MAX_KEY_IDS) {
                LOG_E("Invalid Label : %s", label);
                result = CKR_ARGUMENTS_BAD;
                goto exit;
            }
            *keyId = (uint32_t)(key_id & 0xFF) | ASYMM_ID_MASK;
        }
        /* Check for symm id*/
        else if (CHECK_FOR_SYMM_ID(long_id)) {
            key_id = (uint8_t)(long_id & 0xFF);
            if ((key_id < MIN_SYMM_KEY_ID) || (key_id > MAX_SYMM_KEY_ID)) {
                LOG_E("Invalid Label : %s", label);
                result = CKR_ARGUMENTS_BAD;
                goto exit;
            }
            *keyId = (uint32_t)((key_id & 0xFF) | SYMM_ID_MASK);
        }
        else {
            LOG_E("Key Id is not supported");
            result = CKR_ARGUMENTS_BAD;
            goto exit;
        }
    }
    else {
        LOG_W("Key label is not supported");
        result = CKR_ARGUMENTS_BAD;
        goto exit;
    }

    result = CKR_OK;
exit:

    return result;
}

/** @brief parseCertificate GetAttribute.
 * Helper function for parsing the device certificates.
 *
 * @param xObject - Pointer to handle PKCS#11 object.
 * @param attributeType - This identifies the attribute type.
 * @param pData - Buffer containing the input data.
 * @param ulAttrLength - Length of the attribute type.
 *
 * @returns Status of the operation
 * @retval #CKR_OK The operation has completed successfully.
 * @retval #CKR_FUNCTION_FAILED The requested function could not be performed.
 * @retval #CKR_DEVICE_ERROR If some problem has occured with the token or slot.
 * @retval #CKR_BUFFER_TOO_SMALL The output of function is too large to fit in supplied buffer.
 * @retval #CKR_ATTRIBUTE_SENSITIVE The value of an attribute of an object which cannot be satisfied because the object is either sensitive or un-extractable.
 */
CK_RV pkcs11_parse_certificate_get_attribute(
    uint32_t xObject, CK_ATTRIBUTE_TYPE attributeType, uint8_t *pData, CK_ULONG *ulAttrLength)
{
    CK_RV xResult                    = CKR_FUNCTION_FAILED;
    sss_status_t status              = kStatus_SSS_Fail;
    sss_digest_t digestCtx           = {0};
    sss_algorithm_t digest_algorithm = kAlgorithm_SSS_SHA1;
    uint8_t data[2048]               = {0};
    size_t dataLen                   = sizeof(data);
    size_t i                         = 0;
    smStatus_t sm_status             = SM_NOT_OK;

    /* NOTE: MUTEX LOCK IS NOT USED HERE BECAUSE THIS FUNCTION IS CALLED ONLY WHEN WE HAVE ALREADY LOCKED THE MUTEX */

    sm_status = pkcs11_get_cert_file(xObject, &data[0], &dataLen);

    ENSURE_OR_GO_EXIT(sm_status == SM_OK);

    ENSURE_OR_GO_EXIT(pkcs11_parseCert_GetAttr(attributeType, &data[0], dataLen, pData, ulAttrLength) == CKR_OK);

    if ((attributeType == CKA_HASH_OF_ISSUER_PUBLIC_KEY) || (attributeType == CKA_HASH_OF_SUBJECT_PUBLIC_KEY)) {
        uint8_t *pTLV = &pData[0];
        ENSURE_OR_GO_EXIT(*pTLV == 0x30);

        /*
         *  Public key will be of the following format
         *  30 ZZ
         *      30 XX
         *          KEY_PARAMETERS
         *      03 YY
         *          PUBLIC_KEY
         */

        size_t tagLen = 0, bufindex = 0;
        int ret = asn_1_parse_tlv(pTLV, &tagLen, &bufindex); /* Parse initial sequence */
        ENSURE_OR_GO_EXIT(ret == 0);
        pTLV = pTLV + bufindex;
        ENSURE_OR_GO_EXIT(*pTLV == 0x30);
        bufindex = 0;
        ret      = asn_1_parse_tlv(pTLV, &tagLen, &bufindex); /* Parse key parameters */
        ENSURE_OR_GO_EXIT(ret == 0);
        /* Parse next tag */
        ASN1_SKIP_TO_NEXT_TAG(pTLV, tagLen)
        ENSURE_OR_GO_EXIT(*pTLV == 0x03);
        bufindex = 0;
        ret      = asn_1_parse_tlv(pTLV, &tagLen, &bufindex);
        ENSURE_OR_GO_EXIT(ret == 0);
        pTLV += bufindex;
        if (*pTLV == 0x00) {
            pTLV++;
            tagLen--;
        }

        status =
            sss_digest_context_init(&digestCtx, &pex_sss_demo_boot_ctx->session, digest_algorithm, kMode_SSS_Digest);
        ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

        status = sss_digest_init(&digestCtx);
        ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

        while (tagLen > 500) {
            status = sss_digest_update(&digestCtx, &pTLV[0 + i * 500], 500);
            ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

            i++;
            tagLen -= 500;
        }
        status = sss_digest_update(&digestCtx, &pTLV[0 + i * 500], tagLen);
        ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

        *ulAttrLength = 20 /* SHA-1 data length */;
        status        = sss_digest_finish(&digestCtx, &pData[0], (size_t *)ulAttrLength);
        ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);
    }

    xResult = CKR_OK;
exit:
    if (digestCtx.session != NULL) {
        sss_digest_context_free(&digestCtx);
    }
    return xResult;
}

/**
 * @brief readkeyId
 * Helper function for getting the list of keys provisioned on NX.
*/
smStatus_t pkcs11_read_key_id_list(uint32_t *idlist, size_t *idlistlen, CK_ULONG ulMaxObjectCount)
{
    AX_UNUSED_ARG(ulMaxObjectCount);
    size_t i, k = 0;
    smStatus_t retStatus       = SM_NOT_OK;
    sss_nx_session_t *pSession = (sss_nx_session_t *)&pex_sss_demo_boot_ctx->session;
    uint8_t entryCount         = 0;
    nx_ecc_key_meta_data_t eccPrivateKeyList[NX_KEY_SETTING_ECC_KEY_MAX_ENTRY] = {0};

    /* This condition would be checked by the calling API */
    ENSURE_OR_GO_EXIT(idlist != NULL);
    ENSURE_OR_GO_EXIT(idlistlen != NULL);

    entryCount = NX_KEY_SETTING_ECC_KEY_MAX_ENTRY;
    retStatus  = nx_GetKeySettings_ECCPrivateKeyList(&pSession->s_ctx, &entryCount, eccPrivateKeyList);
    ENSURE_OR_GO_EXIT(retStatus == SM_OK);

    if (entryCount == 0) {
        *idlistlen = 0;
        retStatus  = SM_NOT_OK;
        goto exit;
    }

    for (i = 0; i < entryCount; i++) {
        uint8_t id  = eccPrivateKeyList[i].keyId;
        idlist[k++] = id | ASYMM_ID_MASK;
        *idlistlen  = k;
    }

    retStatus = SM_OK;
exit:
    return retStatus;
}

/**
 * @brief readcertId
 * Helper function to get list of certificates/files present in NX
*/
smStatus_t pkcs11_read_cert_id_list(uint32_t *certidlist, size_t *certidlistlen)
{
    size_t i, k = 0;
    smStatus_t retStatus                  = SM_NOT_OK;
    sss_nx_session_t *pSession            = (sss_nx_session_t *)&pex_sss_demo_boot_ctx->session;
    uint8_t fIDList[NX_FILE_ID_LIST_SIZE] = {0};
    size_t fIDListLen                     = 0;

    ENSURE_OR_GO_EXIT(certidlist != NULL);
    ENSURE_OR_GO_EXIT(certidlistlen != NULL);

    retStatus = nx_GetFileIDs(&pSession->s_ctx, fIDList, &fIDListLen);
    ENSURE_OR_GO_EXIT(retStatus == SM_OK);

    if ((fIDListLen >= NX_FILE_ID_LIST_SIZE) || (fIDListLen <= RESERVE_FILE_IDS)) {
        retStatus = SM_NOT_OK;
        goto exit;
    }

    for (i = RESERVE_FILE_IDS; i < fIDListLen; i++) {
        uint32_t cert_id = fIDList[i];
        certidlist[k++]  = (cert_id | CERT_ID_MASK);
        *certidlistlen   = k;
    }

    retStatus = SM_OK;
exit:
    return retStatus;
}

/**
 * @brief readcertId
 * Helper function to get list of crypto keys present in NX
*/
smStatus_t pkcs11_read_symm_id_list(uint32_t *symmidlist, size_t *symmidlistlen)
{
    size_t i, k = 0;
    smStatus_t retStatus       = SM_NOT_OK;
    sss_nx_session_t *pSession = (sss_nx_session_t *)&pex_sss_demo_boot_ctx->session;
    uint8_t entryCount         = 0;
    nx_crypto_key_meta_data_t cryptoRequestKeyList[NX_KEY_SETTING_CRYPTO_KEY_MAX_ENTRY] = {0};

    ENSURE_OR_GO_EXIT(symmidlist != NULL);
    ENSURE_OR_GO_EXIT(symmidlistlen != NULL);

    entryCount = NX_KEY_SETTING_CRYPTO_KEY_MAX_ENTRY;
    retStatus  = nx_GetKeySettings_CryptoRequestKeyList(&pSession->s_ctx, &entryCount, cryptoRequestKeyList);
    ENSURE_OR_GO_EXIT(retStatus == SM_OK);

    if (entryCount == 0) {
        *symmidlistlen = 0;
        retStatus      = SM_NOT_OK;
        goto exit;
    }

    for (i = 0; i < entryCount; i++) {
        uint32_t id     = cryptoRequestKeyList[i].keyId;
        symmidlist[k++] = (id | SYMM_ID_MASK);
        *symmidlistlen  = k;
    }

    retStatus = SM_OK;
exit:
    return retStatus;
}

/**
 * @brief fileExists
 * Helper function to check whether the file exits or not.
*/
smStatus_t cert_file_exists(CK_OBJECT_HANDLE xObject, uint32_t *keyId)
{
    smStatus_t sm_status       = SM_NOT_OK;
    uint8_t fIDList[32]        = {0};
    size_t fIDListLen          = sizeof(fIDList);
    uint8_t i                  = 0;
    uint8_t certId             = 0;
    sss_nx_session_t *pSession = (sss_nx_session_t *)&pex_sss_demo_boot_ctx->session;

    certId    = (uint8_t)(xObject & 0xFF);
    sm_status = nx_GetFileIDs(&pSession->s_ctx, fIDList, &fIDListLen);
    if (sm_status != SM_OK) {
        LOG_E("Check file exist failed!!!");
        goto exit;
    }

    for (i = 0; i < fIDListLen; i++) {
        if (certId == fIDList[i]) {
            *keyId = certId;
            break;
        }
    }
    sm_status = SM_OK;
exit:
    return sm_status;
}

/**
 * @brief getCertFile
 * Helper function to get the certificate file from the NX.
*/
smStatus_t pkcs11_get_cert_file(CK_OBJECT_HANDLE xObject, uint8_t *cert, size_t *certLen)
{
    sss_nx_session_t *pSession      = (sss_nx_session_t *)&pex_sss_demo_boot_ctx->session;
    uint8_t certId                  = 0;
    smStatus_t sm_status            = SM_NOT_OK;
    size_t readOffset               = 0;
    Nx_FILEType_t certChainFileType = 0;
    uint8_t certChainFileOption = NX_FILE_OPTION_SDM_DISBALED | NX_FILE_OPTION_DEFERRED_DISABLED | Nx_CommMode_Plain;
    Nx_AccessCondition_t certChainFileReadAccessCondition      = Nx_AccessCondition_No_Access;
    Nx_AccessCondition_t certChainFileWriteAccessCondition     = Nx_AccessCondition_No_Access;
    Nx_AccessCondition_t certChainFileReadWriteAccessCondition = Nx_AccessCondition_No_Access;
    Nx_AccessCondition_t certChainFileChangeAccessCondition    = Nx_AccessCondition_No_Access;

    certId = (uint8_t)(xObject & 0xFF);

    sm_status = nx_GetFileSettings(&((sss_nx_session_t *)pSession)->s_ctx,
        certId,
        &certChainFileType,
        &certChainFileOption,
        &certChainFileReadAccessCondition,
        &certChainFileWriteAccessCondition,
        &certChainFileReadWriteAccessCondition,
        &certChainFileChangeAccessCondition,
        certLen,
        NULL);
    if (sm_status != SM_OK) {
        goto exit;
    }

    sm_status = nx_ReadData(
        &((sss_nx_session_t *)pSession)->s_ctx, certId, readOffset, (*certLen), &cert[0], certLen, Nx_CommMode_NA);

    if (sm_status != SM_OK) {
        goto exit;
    }

exit:
    return sm_status;
}

/**
 * @brief fileExists
 * Helper function to check whether the file exits or not.
*/
smStatus_t pkcs11_get_validated_cert_id(CK_OBJECT_HANDLE xObject, uint8_t *keyId)
{
    smStatus_t sm_status       = SM_NOT_OK;
    uint8_t fIDList[32]        = {0};
    size_t fIDListLen          = sizeof(fIDList);
    uint8_t i                  = 0;
    uint8_t certId             = 0;
    sss_nx_session_t *pSession = (sss_nx_session_t *)&pex_sss_demo_boot_ctx->session;

    certId    = (uint8_t)(xObject & 0xFF);
    sm_status = nx_GetFileIDs(&pSession->s_ctx, fIDList, &fIDListLen);
    if (sm_status != SM_OK) {
        LOG_E("Check file exist failed!!!");
        goto exit;
    }

    for (i = 0; i < fIDListLen; i++) {
        if (certId == fIDList[i]) {
            ENSURE_OR_EXIT_WITH_STATUS_ON_ERROR((UINTPTR_MAX - 4) > (uintptr_t)keyId, sm_status, SM_NOT_OK);
            *keyId++ = (uint8_t)((CERT_ID_MASK >> 3 * 8) & 0xFF);
            *keyId++ = (uint8_t)((xObject >> 2 * 8) & 0xFF);
            *keyId++ = (uint8_t)((xObject >> 1 * 8) & 0xFF);
            *keyId++ = (uint8_t)((xObject >> 0 * 8) & 0xFF);
            break;
        }
    }
    sm_status = SM_OK;
exit:
    return sm_status;
}

/**
 * @brief getValidatedObjectid
 * Helper function to check whether the given keyId is valid or not.
*/
sss_status_t pkcs11_get_validated_object_id(P11SessionPtr_t pxSession, CK_OBJECT_HANDLE xObject, uint8_t *keyId)
{
    sss_status_t sss_status = kStatus_SSS_Fail;
    sss_object_t sss_object = {0};
    uint8_t key_id          = 0;

    sss_status = sss_key_object_init(&sss_object, &pex_sss_demo_boot_ctx->ks);
    ENSURE_OR_GO_EXIT(sss_status == kStatus_SSS_Success);

    key_id     = (uint8_t)(xObject & 0xFF);
    sss_status = sss_key_object_get_handle(&sss_object, kSSS_CipherType_EC_NIST_P, key_id);
    ENSURE_OR_GO_EXIT(sss_status == kStatus_SSS_Success);
    ENSURE_OR_EXIT_WITH_STATUS_ON_ERROR((UINTPTR_MAX - 4) > (uintptr_t)keyId, sss_status, kStatus_SSS_Fail);
    *keyId++ = (uint8_t)((ASYMM_ID_MASK >> 3 * 8) & 0xFF);
    *keyId++ = (uint8_t)((xObject >> 2 * 8) & 0xFF);
    *keyId++ = (uint8_t)((xObject >> 1 * 8) & 0xFF);
    *keyId++ = (uint8_t)((xObject >> 0 * 8) & 0xFF);

exit:
    return sss_status;
}

/**
 * @brief getValidatedSymmObjectid
 * Helper function to check whether the given keyId is valid or not.
*/
sss_status_t pkcs11_get_validated_symm_object_id(P11SessionPtr_t pxSession, CK_OBJECT_HANDLE xObject, uint8_t *keyId)
{
    sss_status_t sss_status = kStatus_SSS_Fail;
    sss_object_t sss_object = {0};
    uint8_t key_id          = 0;

    sss_status = sss_key_object_init(&sss_object, &pex_sss_demo_boot_ctx->ks);
    ENSURE_OR_GO_EXIT(sss_status == kStatus_SSS_Success);
    key_id = (uint8_t)(xObject & 0xFF);

    sss_status = sss_key_object_get_handle(&sss_object, kSSS_CipherType_AES, key_id);
    ENSURE_OR_GO_EXIT(sss_status == kStatus_SSS_Success);
    ENSURE_OR_EXIT_WITH_STATUS_ON_ERROR((UINTPTR_MAX - 4) > (uintptr_t)keyId, sss_status, kStatus_SSS_Fail);
    *keyId++ = (uint8_t)((SYMM_ID_MASK >> 3 * 8) & 0xFF);
    *keyId++ = (uint8_t)((xObject >> 2 * 8) & 0xFF);
    *keyId++ = (uint8_t)((xObject >> 1 * 8) & 0xFF);
    *keyId++ = (uint8_t)((xObject >> 0 * 8) & 0xFF);

exit:
    return sss_status;
}

/**
 * @brief getValidatedObject
 * Helper function to check whether the object is valid or not.
*/
sss_status_t pkcs11_get_validated_sss_object(
    P11SessionPtr_t pxSession, CK_OBJECT_HANDLE xObject, sss_object_t *pSSSObject)
{
    sss_status_t sss_status = kStatus_SSS_Fail;
    uint8_t key_id          = 0;

    sss_status = sss_key_object_init(pSSSObject, &pex_sss_demo_boot_ctx->ks);
    ENSURE_OR_GO_EXIT(sss_status == kStatus_SSS_Success);

    key_id = (uint8_t)(xObject & 0xFF);

    sss_status = sss_key_object_get_handle(pSSSObject, kSSS_CipherType_EC_NIST_P, key_id);
    ENSURE_OR_GO_EXIT(sss_status == kStatus_SSS_Success);

exit:
    return sss_status;
}

/**
 * @brief getValidatedSymmObject
 * Helper function to check whether the object is valid or not.
*/
sss_status_t pkcs11_get_validated_sss_symm_object(
    P11SessionPtr_t pxSession, CK_OBJECT_HANDLE xObject, sss_object_t *pSSSObject)
{
    sss_status_t sss_status = kStatus_SSS_Fail;
    uint8_t keyId           = 0;

    sss_status = sss_key_object_init(pSSSObject, &pex_sss_demo_boot_ctx->ks);
    ENSURE_OR_GO_EXIT(sss_status == kStatus_SSS_Success);

    keyId      = (uint8_t)(xObject & 0xFF);
    sss_status = sss_key_object_get_handle(pSSSObject, kSSS_CipherType_AES, keyId);
    ENSURE_OR_GO_EXIT(sss_status == kStatus_SSS_Success);

exit:
    return sss_status;
}

/**
 * @brief checkKeyId
 * Helper function to check whether the object ID is valid or not..
*/
CK_RV pkcs11_check_key_id(
    sss_key_store_t *keystore, sss_object_t *sss_object, sss_cipher_type_t CipherType, uint32_t keyId)
{
    sss_status_t status = kStatus_SSS_Fail;
    CK_RV xResult       = CKR_FUNCTION_FAILED;

    status = sss_key_object_init(sss_object, keystore);
    if (status != kStatus_SSS_Success) {
        xResult = CKR_FUNCTION_FAILED;
        goto exit;
    }

    status = sss_key_object_get_handle(sss_object, CipherType, keyId);
    if (status != kStatus_SSS_Success) {
        xResult = CKR_FUNCTION_FAILED;
        goto exit;
    }
    xResult = CKR_OK;

exit:
    return xResult;
}

int asn_1_parse_tlv(uint8_t *pbuf, size_t *taglen, size_t *bufindex)
{
    size_t Len;
    uint8_t *buf = pbuf + *bufindex;
    int tag;
    int ret = 0;
    tag     = (int)*buf++; /*Exclude The Tag*/
    Len     = *buf++;
    if (check_tag(tag)) {
        ret = 1;
        goto exit;
    }
    if (Len <= 0x7FU) {
        *taglen = Len;
        *bufindex += 1 + 1;
        goto exit;
    }
    else if (Len == 0x81) {
        *taglen = *buf++;
        *bufindex += 1 + 2;
        goto exit;
    }
    else if (Len == 0x82) {
        *taglen = *buf++;
        *taglen = (*taglen << 8) | (*buf++);
        *bufindex += 1 + 3;
        goto exit;
    }
    ret = 1;
exit:
    return ret;
}

static int check_tag(int tag)
{
    int ret = 0;
    switch (tag) {
    case ASN_TAG_INT:
    case ASN_TAG_SEQUENCE:
    case ASN_TAG_BITSTRING:
    case ASN_TAG_OBJ_IDF:
    case ASN_TAG_OCTETSTRING:
        break;
    default:
        LOG_E("Wrong Tag parsed -- %d \n", tag);
        ret = 1;
        break;
    }
    return ret;
}

/** @brief valid keytype .
 * This function checks if the algorithm is valid for the keytype.
 *
 * @param algorithm - Algorithm, e.g. kAlgorithm_SSS_AES_CBC.
 * @param cipher - cipher to be applied, e.g. kSSS_CipherType_AES.
 * @param pSSSObject - sss object to be passed to compare the ciphertype.
 *
 * @returns Status of the operation
 * @retval #CKR_OK The operation has completed successfully.
 * @retval #CKR_MECHANISM_INVALID If unknown algorithm specified.
 * @retval CKR_KEY_TYPE_INCONSISTENT If the algrithm is invalid for the keytype.
 *
 */
CK_RV pkcs11_is_valid_keytype(sss_algorithm_t algorithm, sss_cipher_type_t *cipher, sss_object_t *pSSSObject)
{
    CK_RV xResult = CKR_OK;
    switch (algorithm) {
    case kAlgorithm_SSS_AES_ECB:
    case kAlgorithm_SSS_AES_CBC:
        *cipher = kSSS_CipherType_AES;
        break;
    default:
        xResult = CKR_MECHANISM_INVALID;
        break;
    }

    if (*cipher != (sss_cipher_type_t)pSSSObject->cipherType) {
        xResult = CKR_KEY_TYPE_INCONSISTENT;
    }
    return xResult;
}

/**
 * @brief  Get the keybitlen and ciphertype values based on the passed ec params
 *
 */
CK_RV pkcs11_get_ec_info(uint8_t *params, size_t *KeyBitLen, sss_cipher_type_t *cipher)
{
    CK_RV xResult = CKR_ARGUMENTS_BAD;

    if (memcmp(MBEDTLS_OID_EC_GRP_SECP256R1, &params[OID_START_INDEX], sizeof(MBEDTLS_OID_EC_GRP_SECP256R1) - 1) == 0) {
        *KeyBitLen = 256;
        *cipher    = kSSS_CipherType_EC_NIST_P;
        xResult    = CKR_OK;
        goto exit;
    }

    if (memcmp(OID_EC_GRP_BP256R1, &params[OID_START_INDEX], sizeof(OID_EC_GRP_BP256R1) - 1) == 0) {
        *KeyBitLen = 256;
        *cipher    = kSSS_CipherType_EC_BRAINPOOL;
        xResult    = CKR_OK;
        goto exit;
    }

exit:
    return xResult;
}