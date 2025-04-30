/*
 * Copyright 2024 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 */

/* ********************** Include files ********************** */
#include "sss_pkcs11_pal.h"

/* ********************** Local Defines ********************** */

/**
 * Defines OpenSC NON_REPUDIATION attribute
 */
#define SC_VENDOR_DEFINED 0x4F534300 /* OSC */
// CKA_OPENSC_NON_REPUDIATION for OpenSC 0.17
#define CKA_OPENSC_NON_REPUDIATION_0_17 (CKA_VENDOR_DEFINED | 1UL)
// CKA_OPENSC_NON_REPUDIATION for OpenSC 0.21
#define CKA_OPENSC_NON_REPUDIATION_0_21 (CKA_VENDOR_DEFINED | SC_VENDOR_DEFINED | 1UL)

extern bool cryptokiInitialized;
/* ********************** Public Functions ********************** */

/**
 * @brief Free resources attached to an object handle.
 */
CK_DEFINE_FUNCTION(CK_RV, C_DestroyObject)
(CK_SESSION_HANDLE xSession, CK_OBJECT_HANDLE xObject)
{
    AX_UNUSED_ARG(xSession);
    AX_UNUSED_ARG(xObject);
    LOG_D("%s", __FUNCTION__);
    LOG_I("Erasing of object is not supported !!");
    return CKR_FUNCTION_NOT_SUPPORTED;
}

/**
 * @brief Provides import and storage of a single client certificate and
 * associated private key.
 */
CK_DEFINE_FUNCTION(CK_RV, C_CreateObject)
(CK_SESSION_HANDLE xSession, CK_ATTRIBUTE_PTR pxTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR pxObject)
{
    AX_UNUSED_ARG(xSession);
    CK_RV xResult = CKR_FUNCTION_FAILED;
    LOG_D("%s", __FUNCTION__);
    sss_pkcs11_key_parse_t keyParse = {0};
    U8 buff[4096]                   = {0};
    CK_ULONG Valueindex             = 0;
    uint32_t keyId                  = 0xffffffff;
    CK_ULONG i                      = 0;
    CK_ULONG classIndex             = 0;
    size_t buff_len                 = sizeof(buff);
    CK_ULONG keyidindex;
    CK_ULONG labelIndex   = 0;
    CK_ULONG ecParamIndex = 0;
    CK_ULONG keyTypeIndex = 0;
    CK_BBOOL foundKeyId   = CK_FALSE;
    sss_status_t status;
    sss_cipher_type_t cipherType = kSSS_CipherType_EC_NIST_P;
    sss_key_part_t keyPart       = kSSS_KeyPart_NONE;
    CK_KEY_TYPE key_type;
    CK_ULONG index;
    sss_object_t tmp_object = {0};

    keyParse.pbuff                = &buff[0];
    size_t keyLen                 = 0;
    sss_rng_context_t sss_rng_ctx = {0};
    uint8_t randomKey[32]         = {0};
    sss_object_t secretObject     = {0};
    uint8_t ecParam[100]          = {0};
    size_t ecParamLen             = sizeof(ecParam);
    size_t KeyBitLen              = 0;

    /*
     * Check parameters.
     */
    ENSURE_OR_RETURN_ON_ERROR(cryptokiInitialized == 1, CKR_CRYPTOKI_NOT_INITIALIZED);
    ENSURE_OR_RETURN_ON_ERROR(pkcs11CREATEOBJECT_MINIMUM_ATTRIBUTE_COUNT <= ulCount, CKR_ARGUMENTS_BAD);
    ENSURE_OR_RETURN_ON_ERROR(pxTemplate != NULL, CKR_ARGUMENTS_BAD);
    ENSURE_OR_RETURN_ON_ERROR(pxObject != NULL, CKR_ARGUMENTS_BAD);
    ENSURE_OR_RETURN_ON_ERROR(ulCount != (CK_ULONG)-1, CKR_ARGUMENTS_BAD);
    ENSURE_OR_RETURN_ON_ERROR(sss_pkcs11_mutex_lock() == 0, CKR_CANT_LOCK);

    ENSURE_OR_EXIT_WITH_STATUS_ON_ERROR(
        pkcs11_get_attribute_parameter_index(pxTemplate, ulCount, CKA_CLASS, &classIndex) == CKR_OK,
        xResult,
        CKR_TEMPLATE_INCOMPLETE);

    /*Find the key id as it's needed while provisiong keys and certificate*/
    if (pkcs11_get_attribute_parameter_index(pxTemplate, ulCount, CKA_SSS_ID, &keyidindex) == CKR_OK) {
        foundKeyId = CK_TRUE;
    }

    /*
     * Handle the object by class.
     */
    switch (*((uint32_t *)pxTemplate[classIndex].pValue)) {
    case CKO_CERTIFICATE:
    case CKO_DATA: {
        ENSURE_OR_GO_EXIT(pkcs11_get_attribute_parameter_index(pxTemplate, ulCount, CKA_VALUE, &i) == CKR_OK);

        ENSURE_OR_EXIT_WITH_STATUS_ON_ERROR(pxTemplate[i].ulValueLen < buff_len, xResult, CKR_HOST_MEMORY);
        memcpy(buff, pxTemplate[i].pValue, pxTemplate[i].ulValueLen);
        buff_len = (size_t)pxTemplate[i].ulValueLen;

        if (0 != pxTemplate[i].ulValueLen) {
            if (!foundKeyId) {
                if (pkcs11_get_attribute_parameter_index(pxTemplate, ulCount, CKA_LABEL, &labelIndex) != CKR_OK) {
                    /* CKA_LABEL was not provided */
                    LOG_E("sss label is not provided !!");
                    xResult = CKR_ARGUMENTS_BAD;
                    goto exit;
                }
                else {
                    ENSURE_OR_GO_EXIT(
                        pkcs11_label_to_keyId(
                            pxTemplate[labelIndex].pValue, pxTemplate[labelIndex].ulValueLen, &keyId) == CKR_OK);
                }
            }

            if (*((uint32_t *)pxTemplate[classIndex].pValue) == CKO_CERTIFICATE) {
                ENSURE_OR_EXIT_WITH_STATUS_ON_ERROR(
                    pkcs11_parse_Cert(&buff[0], buff_len) == 0, xResult, CKR_ARGUMENTS_BAD);
            }
            else {
                //Do nothing for data object. Create binary file.
            }

            status = pkcs11_sss_create_token_cert(keyId, buff, buff_len);
            ENSURE_OR_EXIT_WITH_STATUS_ON_ERROR(status == kStatus_SSS_Success, xResult, CKR_DEVICE_ERROR);
            *pxObject = keyId;
        }
        break;
    }
    case CKO_PRIVATE_KEY: {
        /* Parses the private key in PEM format and converts it to DER format.
         * This is required because as SE shall require a key pair for storing keys
         */
        ENSURE_OR_EXIT_WITH_STATUS_ON_ERROR(
            pkcs11_parse_PrivateKey(pxTemplate, ulCount, &Valueindex, &keyParse) == 0, xResult, CKR_ARGUMENTS_BAD);

        if (!foundKeyId) {
            if (pkcs11_get_attribute_parameter_index(pxTemplate, ulCount, CKA_LABEL, &labelIndex) != CKR_OK) {
                /* CKA_LABEL was not provided */
                LOG_E("sss label is not provided !!");
                xResult = CKR_ARGUMENTS_BAD;
                goto exit;
            }
            else {
                ENSURE_OR_GO_EXIT(
                    pkcs11_label_to_keyId(pxTemplate[labelIndex].pValue, pxTemplate[labelIndex].ulValueLen, &keyId) ==
                    CKR_OK);
            }
        }

        ENSURE_OR_GO_EXIT(
            pkcs11_get_attribute_parameter_index(pxTemplate, ulCount, CKA_KEY_TYPE, &keyTypeIndex) == CKR_OK);

        ENSURE_OR_GO_EXIT((pxTemplate[keyTypeIndex].ulValueLen) <= sizeof(key_type));
        memcpy(&key_type, pxTemplate[keyTypeIndex].pValue, pxTemplate[keyTypeIndex].ulValueLen);

        if (key_type == CKK_EC) {
            ENSURE_OR_GO_EXIT(
                pkcs11_get_attribute_parameter_index(pxTemplate, ulCount, CKA_EC_PARAMS, &ecParamIndex) == CKR_OK);

            ENSURE_OR_GO_EXIT((pxTemplate[ecParamIndex].ulValueLen) <= ecParamLen);
            memcpy(ecParam, pxTemplate[ecParamIndex].pValue, pxTemplate[ecParamIndex].ulValueLen);
            /* Get the cipher type based on oid */
            ENSURE_OR_GO_EXIT(pkcs11_get_ec_info(&ecParam[0], &KeyBitLen, &cipherType) == CKR_OK);

            keyParse.cipherType = cipherType;
        }
        else {
            xResult = CKR_ARGUMENTS_BAD;
            goto exit;
        }

        if ((keyParse.cipherType == kSSS_CipherType_EC_NIST_P) ||
            (keyParse.cipherType == kSSS_CipherType_EC_BRAINPOOL)) {
            keyPart = kSSS_KeyPart_Private;
        }
        else {
            keyPart = kSSS_KeyPart_Pair;
        }
        ENSURE_OR_GO_EXIT((keyParse.buffLen) <= UINT32_MAX);
        ENSURE_OR_GO_EXIT((keyParse.keyBitLen) <= UINT32_MAX);
        status = pkcs11_sss_create_token_asymm(&pex_sss_demo_boot_ctx->ks,
            &tmp_object,
            keyId,
            keyPart,
            keyParse.cipherType,
            keyParse.pbuff,
            keyParse.buffLen,
            keyParse.keyBitLen);
        ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);
        *pxObject = keyId;
        break;
    }
    case CKO_PUBLIC_KEY: {
        /* Parses the public key in PEM format and converts it to DER format. */
        ENSURE_OR_EXIT_WITH_STATUS_ON_ERROR(
            pkcs11_parse_PublicKey(pxTemplate, ulCount, &Valueindex, &keyParse) == 0, xResult, CKR_ARGUMENTS_BAD);

        if (!foundKeyId) {
            if (pkcs11_get_attribute_parameter_index(pxTemplate, ulCount, CKA_LABEL, &labelIndex) != CKR_OK) {
                /* CKA_LABEL was not provided */
                LOG_E("sss label is not provided !!");
                xResult = CKR_ARGUMENTS_BAD;
                goto exit;
            }
            else {
                ENSURE_OR_GO_EXIT(
                    pkcs11_label_to_keyId(pxTemplate[labelIndex].pValue, pxTemplate[labelIndex].ulValueLen, &keyId) ==
                    CKR_OK);
            }
        }

        ENSURE_OR_GO_EXIT(
            pkcs11_get_attribute_parameter_index(pxTemplate, ulCount, CKA_KEY_TYPE, &keyTypeIndex) == CKR_OK);

        ENSURE_OR_GO_EXIT((pxTemplate[keyTypeIndex].ulValueLen) <= sizeof(key_type));
        memcpy(&key_type, pxTemplate[keyTypeIndex].pValue, pxTemplate[keyTypeIndex].ulValueLen);

        if (key_type == CKK_EC) {
            ENSURE_OR_GO_EXIT((keyParse.buffLen) <= ecParamLen);
            ecParamLen = keyParse.buffLen;
            memcpy(ecParam, keyParse.pbuff, ecParamLen);
            /* Get the ec params from public key */
            ENSURE_OR_GO_EXIT(pkcs11_ecPublickeyGetEcParams(&ecParam[0], &ecParamLen) == CKR_OK);
            /* Get the cipher type based on oid */
            ENSURE_OR_GO_EXIT(pkcs11_get_ec_info(&ecParam[0], &KeyBitLen, &cipherType) == CKR_OK);

            keyParse.cipherType = cipherType;
        }
        else {
            xResult = CKR_ARGUMENTS_BAD;
            goto exit;
        }
        ENSURE_OR_GO_EXIT((keyParse.buffLen) <= UINT32_MAX);
        ENSURE_OR_GO_EXIT((keyParse.keyBitLen) <= UINT32_MAX);
        status = pkcs11_sss_create_token_asymm(&pex_sss_demo_boot_ctx->ks,
            &tmp_object,
            keyId,
            kSSS_KeyPart_Public,
            keyParse.cipherType,
            keyParse.pbuff,
            keyParse.buffLen,
            keyParse.keyBitLen);
        ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);
        *pxObject = keyId;
        break;
    }
    case CKO_SECRET_KEY: {
        if (!foundKeyId) {
            if (pkcs11_get_attribute_parameter_index(pxTemplate, ulCount, CKA_LABEL, &labelIndex) != CKR_OK) {
                /* CKA_LABEL was not provided */
                LOG_E("sss label is not provided !!");
                xResult = CKR_ARGUMENTS_BAD;
                goto exit;
            }
            else {
                ENSURE_OR_GO_EXIT(
                    pkcs11_label_to_keyId(pxTemplate[labelIndex].pValue, pxTemplate[labelIndex].ulValueLen, &keyId) ==
                    CKR_OK);
            }
        }
        ENSURE_OR_GO_EXIT(pkcs11_get_attribute_parameter_index(pxTemplate, ulCount, CKA_VALUE, &i) == CKR_OK);
        index = 0;
        ENSURE_OR_GO_EXIT(pkcs11_get_attribute_parameter_index(pxTemplate, ulCount, CKA_KEY_TYPE, &index) == CKR_OK);
        memcpy(&key_type, pxTemplate[index].pValue, pxTemplate[index].ulValueLen);

        /* Treating generic keytype as HMAC only */
        if ((key_type == CKK_GENERIC_SECRET) || (key_type == CKK_SHA256_HMAC) || (key_type == CKK_AES)) {
            cipherType = kSSS_CipherType_AES;
        }
        else {
            LOG_E("Key_type 0x%X is not supported", key_type);
            xResult = CKR_ARGUMENTS_BAD;
            goto exit;
        }

        if (0 != pxTemplate[i].ulValueLen) {
            ENSURE_OR_GO_EXIT((pxTemplate[i].ulValueLen) <= (UINT32_MAX / 8));
            if ((key_type == CKK_GENERIC_SECRET) || (key_type == CKK_SHA256_HMAC)) {
                status = pkcs11_sss_create_token_hmac(&pex_sss_demo_boot_ctx->ks,
                    &secretObject,
                    keyId,
                    kSSS_KeyPart_Default,
                    cipherType,
                    (uint8_t *)pxTemplate[i].pValue,
                    pxTemplate[i].ulValueLen,
                    pxTemplate[i].ulValueLen * 8);
                ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);
            }
            else {
                status = pkcs11_sss_create_token_symm(&pex_sss_demo_boot_ctx->ks,
                    &secretObject,
                    keyId,
                    kSSS_KeyPart_Default,
                    cipherType,
                    (uint8_t *)pxTemplate[i].pValue,
                    pxTemplate[i].ulValueLen,
                    pxTemplate[i].ulValueLen * 8);
                ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);
            }
            *pxObject = keyId;
        }
        else { /* Key value is not provided, generate a random key */

            switch (key_type) {
            case CKK_GENERIC_SECRET:
            case CKK_AES:
                keyLen = 16;
                LOG_W("Keylength used:%lu", keyLen);
                break;
            default:
                LOG_E("Key_type 0x%X is not supported", key_type);
                xResult = CKR_ARGUMENTS_BAD;
                goto exit;
            }
            /* Generate random data */

            status = sss_rng_context_init(&sss_rng_ctx, &pex_sss_demo_boot_ctx->session);
            if (status != kStatus_SSS_Success) {
                xResult = CKR_DEVICE_ERROR;
                goto exit;
            }
            status = sss_rng_get_random(&sss_rng_ctx, randomKey, keyLen);
            if (status != kStatus_SSS_Success) {
                xResult = CKR_DEVICE_ERROR;
                goto exit;
            }

            /* Import secret key */
            status = pkcs11_sss_create_token_symm(&pex_sss_demo_boot_ctx->ks,
                &secretObject,
                keyId,
                kSSS_KeyPart_Default,
                cipherType,
                randomKey,
                keyLen,
                keyLen * 8);
            ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);
            *pxObject = keyId;
        }
        break;
    }
    default:
        goto exit;
    }

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
 * @brief Begin an enumeration sequence for the objects of the specified type.
 */
CK_DEFINE_FUNCTION(CK_RV, C_FindObjectsInit)
(CK_SESSION_HANDLE xSession, CK_ATTRIBUTE_PTR pxTemplate, CK_ULONG ulCount)
{
    P11SessionPtr_t pxSession = prvSessionPointerFromHandle(xSession);
    int classIndex            = 0;
    CK_BBOOL foundClass       = CK_FALSE;
    CK_ULONG i                = 0;
    LOG_D("%s", __FUNCTION__);

    ENSURE_OR_RETURN_ON_ERROR(cryptokiInitialized == 1, CKR_CRYPTOKI_NOT_INITIALIZED);
    ENSURE_OR_RETURN_ON_ERROR(pxSession != NULL, CKR_SESSION_HANDLE_INVALID);

    /*
     * Allow filtering on a single object class attribute.
     */
    pxSession->xFindObjectInit    = CK_TRUE;
    pxSession->xFindObjectClass   = pkcs11INVALID_OBJECT_CLASS; /* Invalid Class */
    pxSession->xFindObjectKeyType = pkcs11INVALID_KEY_TYPE;     /* Invalid Key Type */

    if (!pxTemplate) {
        pxSession->labelPresent          = CK_FALSE;
        pxSession->keyIdPresent          = CK_FALSE;
        pxSession->xFindObjectClass      = pkcs11INVALID_OBJECT_CLASS; /* Invalid Class */
        pxSession->xFindObjectKeyType    = pkcs11INVALID_KEY_TYPE;     /* Invalid Key Type */
        pxSession->xFindObjectTotalFound = 0;
        return CKR_OK;
    }

    for (i = 0; i < ulCount; i++) {
        if (pxTemplate[i].type == CKA_LABEL) {
            LOG_D("Label found \n");
            pxSession->labelPresent = CK_TRUE;
            if (snprintf(pxSession->label, sizeof(pxSession->label), "%s", (char *)pxTemplate[i].pValue) < 0) {
                LOG_E("snprintf error");
                pxSession->labelPresent = CK_FALSE;
                pxSession->labelLen     = 0;
                continue;
            }
            pxSession->labelLen = pxTemplate[i].ulValueLen;
        }
        else if (pxTemplate[i].type == CKA_CLASS) {
            classIndex = i;
            foundClass = CK_TRUE;
        }
        else if (pxTemplate[i].type == CKA_SSS_ID || pxTemplate[i].type == CKA_ID) {
            pxSession->keyIdPresent = CK_TRUE;
            memcpy(pxSession->keyId, pxTemplate[i].pValue, sizeof(pxSession->keyId));
        }
        else if (pxTemplate[i].type == CKA_KEY_TYPE) {
            memcpy(&pxSession->xFindObjectKeyType, pxTemplate[i].pValue, sizeof(CK_KEY_TYPE));
        }
    }
    if (foundClass) {
        memcpy(&pxSession->xFindObjectClass, pxTemplate[classIndex].pValue, sizeof(CK_OBJECT_CLASS));
    }

    return CKR_OK;
}

/**
 * @brief Query the objects of the requested type.
 */
CK_DEFINE_FUNCTION(CK_RV, C_FindObjects)
(CK_SESSION_HANDLE xSession, CK_OBJECT_HANDLE_PTR pxObject, CK_ULONG ulMaxObjectCount, CK_ULONG_PTR pulObjectCount)
{
    CK_RV xResult             = CKR_FUNCTION_FAILED;
    bool xDone                = false;
    P11SessionPtr_t pxSession = prvSessionPointerFromHandle(xSession);
    uint32_t keyId            = 0x0;
    smStatus_t sm_status      = SM_NOT_OK;
    uint32_t certId           = 0;
    uint32_t id               = 0;

    LOG_D("%s", __FUNCTION__);

    // Check parameters.
    ENSURE_OR_RETURN_ON_ERROR(pxSession != NULL, CKR_SESSION_HANDLE_INVALID);
    ENSURE_OR_RETURN_ON_ERROR((CK_BBOOL)CK_FALSE != pxSession->xFindObjectInit, CKR_OPERATION_NOT_INITIALIZED);
    ENSURE_OR_RETURN_ON_ERROR(!((false == xDone) && (0u == ulMaxObjectCount)), CKR_ARGUMENTS_BAD);
    ENSURE_OR_RETURN_ON_ERROR(!((false == xDone) && (!pxObject || !pulObjectCount)), CKR_ARGUMENTS_BAD);

    if (sss_pkcs11_mutex_lock() != 0) {
        xResult = CKR_CANT_LOCK;
        return xResult;
    }

    /*
     * Implementation Logic - Load object based on whether label / keyId was passed.
     * If neither was passed while initializing FindObjects operation
     * then we list the objects present on the secure element and filter
     * out based on object type required by the application.
     */
    if ((false == xDone) && pxSession->labelPresent) {
        if (pxSession->labelLen == 0) {
            *pulObjectCount = 0;
            xResult         = CKR_FUNCTION_FAILED;
        }
        else {
            if (pxSession->xFindObjectTotalFound == 1) {
                *pulObjectCount = 0;
            }
            else {
                xResult = pkcs11_label_to_keyId((unsigned char *)pxSession->label, pxSession->labelLen, &keyId);
                if ((xResult == CKR_OK) && (CHECK_FOR_ASYMM_ID(keyId))) {
                    sss_object_t object          = {0};
                    sss_cipher_type_t CipherType = kSSS_CipherType_EC_NIST_P;

                    id      = (uint32_t)(keyId & 0xFF);
                    xResult = pkcs11_check_key_id(&pex_sss_demo_boot_ctx->ks, &object, CipherType, id);

                    if (xResult == CKR_OK) {
                        *pxObject                        = keyId | ASYMM_ID_MASK;
                        *pulObjectCount                  = 1;
                        pxSession->xFindObjectTotalFound = 1;
                    }
                }
                /* Handle certificate IDs */
                else if ((xResult == CKR_OK) && (CHECK_FOR_CERT_ID(keyId))) {
                    sm_status = cert_file_exists((CK_ULONG)keyId, &certId);

                    if (sm_status != SM_OK) {
                        *pulObjectCount = 0;
                    }
                    else {
                        *pxObject                        = (certId | CERT_ID_MASK);
                        *pulObjectCount                  = 1;
                        pxSession->xFindObjectTotalFound = 1;
                    }
                }
                /* Handle Symmetric key ID */
                else if ((xResult == CKR_OK) && (CHECK_FOR_SYMM_ID(keyId))) {
                    sss_object_t object          = {0};
                    sss_cipher_type_t CipherType = kSSS_CipherType_AES;
                    id                           = (uint32_t)(keyId & 0xFF);
                    xResult = pkcs11_check_key_id(&pex_sss_demo_boot_ctx->ks, &object, CipherType, id);
                    if (xResult == CKR_OK) {
                        *pxObject                        = keyId | SYMM_ID_MASK;
                        *pulObjectCount                  = 1;
                        pxSession->xFindObjectTotalFound = 1;
                    }
                }
                else {
                    *pxObject       = 0;
                    *pulObjectCount = 0;
                }
            }
        }
        xDone = true;
    }
    else if ((false == xDone) && pxSession->keyIdPresent) {
        keyId = (uint32_t)((pxSession->keyId[0] << (8 * 3)) | (pxSession->keyId[1] << (8 * 2)) |
                           (pxSession->keyId[2] << (8 * 1)) | (pxSession->keyId[3] << (8 * 0)));

        if (pxSession->xFindObjectTotalFound == 1) {
            *pulObjectCount = 0;
        }
        else {
            if (CHECK_FOR_ASYMM_ID(keyId)) {
                sss_object_t object          = {0};
                sss_cipher_type_t CipherType = kSSS_CipherType_EC_NIST_P;

                id      = (uint32_t)(keyId & 0xFF);
                xResult = pkcs11_check_key_id(&pex_sss_demo_boot_ctx->ks, &object, CipherType, id);

                if (xResult == CKR_OK) {
                    *pxObject                        = keyId | ASYMM_ID_MASK;
                    *pulObjectCount                  = 1;
                    pxSession->xFindObjectTotalFound = 1;
                }
            }
            /* Handle certificate IDs */
            else if (CHECK_FOR_CERT_ID(keyId)) {
                sm_status = cert_file_exists((CK_ULONG)keyId, &certId);

                if (sm_status != SM_OK) {
                    *pulObjectCount = 0;
                }
                else {
                    *pxObject                        = (certId | CERT_ID_MASK);
                    *pulObjectCount                  = 1;
                    pxSession->xFindObjectTotalFound = 1;
                }
            }
            /* Handle symmetric key ID*/
            else if (CHECK_FOR_SYMM_ID(keyId)) {
                sss_object_t object          = {0};
                sss_cipher_type_t CipherType = kSSS_CipherType_AES;
                id                           = (uint32_t)(keyId & 0xFF);
                xResult                      = pkcs11_check_key_id(&pex_sss_demo_boot_ctx->ks, &object, CipherType, id);
                if (xResult == CKR_OK) {
                    *pxObject                        = keyId | SYMM_ID_MASK;
                    *pulObjectCount                  = 1;
                    pxSession->xFindObjectTotalFound = 1;
                }
            }
            else {
                *pxObject       = 0;
                *pulObjectCount = 0;
            }
        }

        xDone = true;
    }

    else if ((false == xDone)) {
    retry:
        xResult                                  = CKR_FUNCTION_FAILED;
        static uint32_t object_list[MAX_KEY_IDS] = {0};
        static size_t object_list_size           = 0;
        static uint32_t cert_id[MAX_CERT_IDS]    = {0};
        static size_t cert_list_size             = 0;
        static uint32_t symm_id[MAX_SYMM_IDS]    = {0};
        static size_t symm_list_size             = 0;

        /* Check for Asymm IDs list */
        if ((pxSession->CheckCertId == false) && (pxSession->CheckSymmId == false)) {
            memset(object_list, 0, sizeof(object_list));
            object_list_size = sizeof(object_list) / sizeof(object_list[0]);
            *pulObjectCount  = 0;
            sm_status        = pkcs11_read_key_id_list(object_list, &object_list_size, ulMaxObjectCount);
            /* In case of failure or getting all provisioned keyId lists go for checking the provisioned certificate files */
            if ((sm_status != SM_OK) || (pxSession->xFindObjectOutputOffset >= object_list_size)) {
                pxSession->xFindObjectOutputOffset = 0;
                xDone                              = true;
                pxSession->CheckCertId             = true;
                goto retry;
            }
            for (size_t i = 0; ((i < object_list_size) && (*pulObjectCount < MAX_ID_COUNT)); i++) {
                id = object_list[i];
                pxSession->xFindObjectOutputOffset++;

                if (pxSession->xFindObjectClass == pkcs11INVALID_OBJECT_CLASS &&
                    pxSession->xFindObjectKeyType == pkcs11INVALID_KEY_TYPE) {
                    /* For public key attributes */
                    memcpy(pxObject, &id, sizeof(id));
                    (*pulObjectCount)++;
                }
                else if (pxSession->xFindObjectClass != pkcs11INVALID_OBJECT_CLASS &&
                         pxSession->xFindObjectKeyType == pkcs11INVALID_KEY_TYPE) {
                    if (pxSession->xFindObjectClass == CKO_PRIVATE_KEY ||
                        pxSession->xFindObjectClass == CKO_PUBLIC_KEY) {
                        memcpy(pxObject, &id, sizeof(id));
                        (*pulObjectCount)++;
                    }
                }
                else if (pxSession->xFindObjectClass == pkcs11INVALID_OBJECT_CLASS &&
                         pxSession->xFindObjectKeyType != pkcs11INVALID_KEY_TYPE) {
                    if (pxSession->xFindObjectKeyType == CKK_EC) {
                        memcpy(pxObject, &id, sizeof(id));
                        (*pulObjectCount)++;
                    }
                }
                else if (pxSession->xFindObjectClass != pkcs11INVALID_OBJECT_CLASS &&
                         pxSession->xFindObjectKeyType != pkcs11INVALID_KEY_TYPE) {
                    if (pxSession->xFindObjectClass == CKO_PRIVATE_KEY ||
                        pxSession->xFindObjectClass == CKO_PUBLIC_KEY) {
                        if (pxSession->xFindObjectKeyType == CKK_EC) {
                            memcpy(pxObject, &id, sizeof(id));
                            (*pulObjectCount)++;
                        }
                    }
                }
            }
            xDone = true;
        }
        /* Check for Cert IDs list */
        else if ((pxSession->CheckCertId == true) && (pxSession->CheckSymmId == false)) {
            memset(cert_id, 0, sizeof(cert_id));
            cert_list_size  = sizeof(cert_id) / sizeof(cert_id[0]);
            *pulObjectCount = 0;
            sm_status       = pkcs11_read_cert_id_list(cert_id, &cert_list_size);

            /* check symm IDs after getting all certificate objects or getting any failure and reset the CheckCertId flag */
            if ((sm_status != SM_OK) || (cert_list_size == 0) ||
                (pxSession->xFindObjectOutputOffset >= cert_list_size)) {
                *pulObjectCount                    = 0;
                pxSession->xFindObjectOutputOffset = 0;
                pxSession->CheckCertId             = false;
                pxSession->CheckSymmId             = true;
                goto retry;
            }

            for (size_t i = pxSession->xFindObjectOutputOffset;
                 ((i < cert_list_size) && (*pulObjectCount < MAX_ID_COUNT));
                 i++) {
                pxSession->xFindObjectOutputOffset++;
                uint32_t certid = cert_id[i];

                if (pxSession->xFindObjectClass == pkcs11INVALID_OBJECT_CLASS &&
                    pxSession->xFindObjectKeyType == pkcs11INVALID_KEY_TYPE) {
                    memcpy(pxObject, &certid, sizeof(certid));
                    (*pulObjectCount)++;
                }
                else if (pxSession->xFindObjectClass != pkcs11INVALID_OBJECT_CLASS &&
                         pxSession->xFindObjectKeyType == pkcs11INVALID_KEY_TYPE) {
                    CK_BBOOL isX509Cert = CK_FALSE;
                    if (pxSession->xFindObjectClass == CKO_CERTIFICATE) {
                        isX509Cert = pkcs11_is_X509_certificate(certid);
                    }
                    if ((isX509Cert == CK_TRUE && pxSession->xFindObjectClass == CKO_CERTIFICATE)) {
                        memcpy(pxObject, &certid, sizeof(certid));
                        (*pulObjectCount)++;
                    }
                }
                else if (pxSession->xFindObjectClass != pkcs11INVALID_OBJECT_CLASS &&
                         pxSession->xFindObjectKeyType != pkcs11INVALID_KEY_TYPE) {
                    CK_BBOOL isX509Cert = CK_FALSE;
                    if (pxSession->xFindObjectClass == CKO_CERTIFICATE) {
                        isX509Cert = pkcs11_is_X509_certificate(certid);
                    }
                    if ((isX509Cert == CK_TRUE && pxSession->xFindObjectClass == CKO_CERTIFICATE)) {
                        memcpy(pxObject, &certid, sizeof(certid));
                        (*pulObjectCount)++;
                    }
                }
            }
        }
        /* Check for Symm IDs list */
        else if ((pxSession->CheckSymmId == true) && (pxSession->CheckCertId == false)) {
            memset(symm_id, 0, sizeof(symm_id));
            symm_list_size  = sizeof(symm_id) / sizeof(symm_id[0]);
            *pulObjectCount = 0;
            sm_status       = pkcs11_read_symm_id_list(symm_id, &symm_list_size);
            if ((sm_status != SM_OK) || (symm_list_size == 0)) {
                *pulObjectCount        = 0;
                xResult                = CKR_FUNCTION_FAILED;
                pxSession->CheckCertId = false;
                pxSession->CheckSymmId = false;

                goto exit;
            }

            /* Return after getting all symm objects and reset the CheckCertId and CheckSymmId flag */
            if (pxSession->xFindObjectOutputOffset >= symm_list_size) {
                *pulObjectCount        = 0;
                xResult                = CKR_OK;
                xDone                  = true;
                pxSession->CheckCertId = false;
                pxSession->CheckSymmId = false;

                goto exit;
            }

            for (size_t i = pxSession->xFindObjectOutputOffset;
                 ((i < symm_list_size) && (*pulObjectCount < MAX_ID_COUNT));
                 i++) {
                pxSession->xFindObjectOutputOffset++;
                uint32_t symmId = symm_id[i];

                if (pxSession->xFindObjectClass == pkcs11INVALID_OBJECT_CLASS &&
                    pxSession->xFindObjectKeyType == pkcs11INVALID_KEY_TYPE) {
                    memcpy(pxObject, &symmId, sizeof(symmId));
                    (*pulObjectCount)++;
                }
                else if (pxSession->xFindObjectClass != pkcs11INVALID_OBJECT_CLASS &&
                         pxSession->xFindObjectKeyType == pkcs11INVALID_KEY_TYPE) {
                    if (pxSession->xFindObjectClass == CKO_SECRET_KEY) {
                        memcpy(pxObject, &symmId, sizeof(symmId));
                        (*pulObjectCount)++;
                    }
                }
                else if (pxSession->xFindObjectClass == pkcs11INVALID_OBJECT_CLASS &&
                         pxSession->xFindObjectKeyType != pkcs11INVALID_KEY_TYPE) {
                    if (pxSession->xFindObjectKeyType == CKK_AES) {
                        memcpy(pxObject, &symmId, sizeof(symmId));
                        (*pulObjectCount)++;
                    }
                }
                else if (pxSession->xFindObjectClass != pkcs11INVALID_OBJECT_CLASS &&
                         pxSession->xFindObjectKeyType != pkcs11INVALID_KEY_TYPE) {
                    if (pxSession->xFindObjectClass == CKO_SECRET_KEY) {
                        memcpy(pxObject, &symmId, sizeof(symmId));
                        (*pulObjectCount)++;
                    }
                }
            }
        }
    }

    xResult = CKR_OK;
exit:
    if (sss_pkcs11_mutex_unlock() != 0) {
        if (xResult == CKR_OK) {
            xResult = CKR_FUNCTION_FAILED;
        }
    }
    return xResult;
}

/**
 * @brief Terminate object enumeration.
 */
CK_DEFINE_FUNCTION(CK_RV, C_FindObjectsFinal)(CK_SESSION_HANDLE xSession)
{
    P11SessionPtr_t pxSession = prvSessionPointerFromHandle(xSession);

    ENSURE_OR_RETURN_ON_ERROR(pxSession != NULL, CKR_SESSION_HANDLE_INVALID);
    ENSURE_OR_RETURN_ON_ERROR((CK_BBOOL)CK_FALSE != pxSession->xFindObjectInit, CKR_OPERATION_NOT_INITIALIZED);

    LOG_D("%s", __FUNCTION__);

    /*
    * Clean-up find objects state.
    */
    pxSession->labelPresent            = CK_FALSE;
    pxSession->keyIdPresent            = CK_FALSE;
    pxSession->xFindObjectInit         = CK_FALSE;
    pxSession->xFindObjectClass        = 0;
    pxSession->xFindObjectTotalFound   = 0;
    pxSession->xFindObjectKeyType      = pkcs11INVALID_KEY_TYPE;
    pxSession->xFindObjectOutputOffset = 0;

    return CKR_OK;
}

/**
 * @brief Create a new object by copying existing object.
 */
// LCOV_EXCL_START
CK_DEFINE_FUNCTION(CK_RV, C_CopyObject)
(CK_SESSION_HANDLE hSession,
    CK_OBJECT_HANDLE hObject,
    CK_ATTRIBUTE_PTR pTemplate,
    CK_ULONG ulCount,
    CK_OBJECT_HANDLE_PTR phNewObject)
{
    AX_UNUSED_ARG(hSession);
    AX_UNUSED_ARG(hObject);
    AX_UNUSED_ARG(pTemplate);
    AX_UNUSED_ARG(ulCount);
    AX_UNUSED_ARG(phNewObject);

    LOG_D("%s", __FUNCTION__);

    return CKR_FUNCTION_NOT_SUPPORTED;
}
// LCOV_EXCL_STOP

/**
 * @brief Generates a secret key.
 */
CK_DEFINE_FUNCTION(CK_RV, C_GenerateKey)
(CK_SESSION_HANDLE hSession,
    CK_MECHANISM_PTR pMechanism,
    CK_ATTRIBUTE_PTR pTemplate,
    CK_ULONG ulCount,
    CK_OBJECT_HANDLE_PTR phKey)
{
    /*
        Attribute.CLASS: ObjectClass.SECRET_KEY,
        Attribute.ID: id or b'',
        Attribute.LABEL: label or '',
        Attribute.TOKEN: store,
        Attribute.PRIVATE: True,
        Attribute.SENSITIVE: True,
        Attribute.ENCRYPT: MechanismFlag.ENCRYPT & capabilities,
        Attribute.DECRYPT: MechanismFlag.DECRYPT & capabilities,
        Attribute.WRAP: MechanismFlag.WRAP & capabilities,
        Attribute.UNWRAP: MechanismFlag.UNWRAP & capabilities,
        Attribute.SIGN: MechanismFlag.SIGN & capabilities,
        Attribute.VERIFY: MechanismFlag.VERIFY & capabilities,
        Attribute.DERIVE: MechanismFlag.DERIVE & capabilities,
        template_[Attribute.VALUE_LEN] = key_length // 8  # In bytes
    */
    CK_RV xResult                        = CKR_FUNCTION_FAILED;
    P11SessionPtr_t pxSession            = prvSessionPointerFromHandle(hSession);
    sss_status_t sss_status              = kStatus_SSS_Fail;
    sss_rng_context_t sss_rng_ctx        = {0};
    uint32_t keyId                       = 0x0;
    size_t keyLen                        = 0;
    sss_cipher_type_t cipherType         = kSSS_CipherType_NONE;
    CK_ULONG attributeIndex              = 0;
    CK_MECHANISM mech                    = {0};
    uint8_t randomKey[64]                = {0};
    sss_object_t sss_object              = {0};
    uint8_t keyIdBuff[MAX_KEY_ID_LENGTH] = {0};

    AX_UNUSED_ARG(hSession);
    LOG_D("%s", __FUNCTION__);
    ENSURE_OR_RETURN_ON_ERROR(NULL != pxSession, CKR_SESSION_HANDLE_INVALID);
    ENSURE_OR_RETURN_ON_ERROR(NULL != pMechanism, CKR_MECHANISM_INVALID);
    ENSURE_OR_RETURN_ON_ERROR(NULL != pTemplate, CKR_ARGUMENTS_BAD);
    ENSURE_OR_RETURN_ON_ERROR(NULL != phKey, CKR_ARGUMENTS_BAD);
    ENSURE_OR_RETURN_ON_ERROR(sss_pkcs11_mutex_lock() == 0, CKR_CANT_LOCK);

    mech = *pMechanism;
    if (mech.mechanism == CKM_AES_KEY_GEN || mech.mechanism == CKM_GENERIC_SECRET_KEY_GEN) {
        ENSURE_OR_GO_EXIT(
            pkcs11_get_attribute_parameter_index(pTemplate, ulCount, CKA_VALUE_LEN, &attributeIndex) == CKR_OK);

        keyLen = *((size_t *)pTemplate[attributeIndex].pValue);
        if ((keyLen != 16) && (keyLen != 32)) {
            LOG_E("Unsupported key length %d", keyLen);
            xResult = CKR_ARGUMENTS_BAD;
            goto exit;
        }

        cipherType = kSSS_CipherType_AES;
    }
    else {
        LOG_E("Unsupported mechanism");
        xResult = CKR_ARGUMENTS_BAD;
        goto exit;
    }

    xResult = pkcs11_get_attribute_parameter_index(pTemplate, ulCount, CKA_LABEL, &attributeIndex);
    if (xResult != CKR_OK) {
        /* CKA_LABEL was not provided. Check if CKA_ID was passed */
        xResult = pkcs11_get_attribute_parameter_index(pTemplate, ulCount, CKA_ID, &attributeIndex);
        if (CKR_OK != xResult) {
            /* CKA_LABEL/CKA_ID was not provided */
            LOG_E("CKA_LABEL/CKA_ID was not provided");
            xResult = CKR_ARGUMENTS_BAD;
            goto exit;
        }
        else {
            /* CKA_ID is provided. Use as keyID */
            memcpy(keyIdBuff, pTemplate[attributeIndex].pValue, sizeof(keyIdBuff));
            keyId = (uint32_t)(
                (keyIdBuff[0] << 8 * 3) | (keyIdBuff[1] << 8 * 2) | (keyIdBuff[2] << 8 * 1) | (keyIdBuff[3] << 8 * 0));
        }
    }
    else {
        xResult = pkcs11_label_to_keyId(pTemplate[attributeIndex].pValue, pTemplate[attributeIndex].ulValueLen, &keyId);
        ENSURE_OR_GO_EXIT(xResult == CKR_OK);
    }

    /* Generate random data */

    sss_status = sss_rng_context_init(&sss_rng_ctx, &pex_sss_demo_boot_ctx->session);
    if (sss_status != kStatus_SSS_Success) {
        xResult = CKR_DEVICE_ERROR;
        goto exit;
    }

    sss_status = sss_rng_get_random(&sss_rng_ctx, randomKey, keyLen);
    if (sss_status != kStatus_SSS_Success) {
        xResult = CKR_DEVICE_ERROR;
        goto exit;
    }

    keyId = (uint32_t)(keyId & 0xFF);
    /* Import secret key */
    sss_status = pkcs11_sss_create_token_symm(&pex_sss_demo_boot_ctx->ks,
        &sss_object,
        keyId,
        kSSS_KeyPart_Default,
        cipherType,
        randomKey,
        keyLen,
        keyLen * 8);
    if (sss_status == kStatus_SSS_Success) {
        *phKey = (keyId | SYMM_ID_MASK);
    }
    else {
        goto exit;
    }

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
 * @brief Generates a public-key/private-key pair.
 */
CK_DEFINE_FUNCTION(CK_RV, C_GenerateKeyPair)
(CK_SESSION_HANDLE hSession,
    CK_MECHANISM_PTR pMechanism,
    CK_ATTRIBUTE_PTR pPublicKeyTemplate,
    CK_ULONG ulPublicKeyAttributeCount,
    CK_ATTRIBUTE_PTR pPrivateKeyTemplate,
    CK_ULONG ulPrivateKeyAttributeCount,
    CK_OBJECT_HANDLE_PTR phPublicKey,
    CK_OBJECT_HANDLE_PTR phPrivateKey)
{
    CK_RV xResult                        = CKR_OK;
    P11SessionPtr_t pxSession            = prvSessionPointerFromHandle(hSession);
    size_t KeyBitLen                     = 0;
    CK_ULONG privateLabelIndex           = 0;
    CK_ULONG publicLabelIndex            = 0;
    uint32_t privKeyId                   = 0;
    uint32_t pubKeyId                    = 0;
    sss_status_t sss_status              = kStatus_SSS_Fail;
    sss_object_t sss_object              = {0};
    CK_BBOOL skipPublicKey               = CK_FALSE;
    sss_cipher_type_t cipherType         = kSSS_CipherType_Binary;
    uint8_t keyIdBuff[MAX_KEY_ID_LENGTH] = {0};
    CK_BBOOL ecKeyGen                    = CK_FALSE;
#if defined(SSS_HAVE_HOST_EMBEDDED) && !(SSS_HAVE_HOST_EMBEDDED)
    uint8_t pubkey[100] = {0};
    size_t pubkeylen    = sizeof(pubkey);
#endif //!SSS_HAVE_HOST_EMBEDDED

    LOG_D("%s", __FUNCTION__);

    if (pxSession == NULL) {
        xResult = CKR_SESSION_HANDLE_INVALID;
        return xResult;
    }

    if (!pMechanism) {
        return CKR_ARGUMENTS_BAD;
    }
    if (NULL == pPublicKeyTemplate) {
        return CKR_ARGUMENTS_BAD;
    }
    if (NULL == pPrivateKeyTemplate) {
        return CKR_ARGUMENTS_BAD;
    }
    if (sss_pkcs11_mutex_lock() != 0) {
        return CKR_CANT_LOCK;
    }

    switch (pMechanism->mechanism) {
    case CKM_EC_KEY_PAIR_GEN:
        ecKeyGen = CK_TRUE;
        break;
    default:
        xResult = CKR_MECHANISM_INVALID;
        goto exit;
    }

    if (ecKeyGen) {
        CK_ULONG ec_params_index = 0;
        uint8_t ec_params[40]    = {""};
        xResult                  = pkcs11_get_attribute_parameter_index(
            pPublicKeyTemplate, ulPublicKeyAttributeCount, CKA_EC_PARAMS, &ec_params_index);
        if (xResult != CKR_OK) {
            goto exit;
        }

        if (pPublicKeyTemplate[ec_params_index].ulValueLen > sizeof(ec_params)) {
            xResult = CKR_ARGUMENTS_BAD;
            goto exit;
        }
        memcpy(ec_params, pPublicKeyTemplate[ec_params_index].pValue, pPublicKeyTemplate[ec_params_index].ulValueLen);

        /* Get the ciphertype based on passed OID */
        if (pkcs11_get_ec_info(ec_params, &KeyBitLen, &cipherType) == 0) {
            goto cont;
        }

        return CKR_ARGUMENTS_BAD;
    }
    else {
        xResult = CKR_MECHANISM_INVALID;
        return xResult;
    }

cont:

    xResult = pkcs11_get_attribute_parameter_index(
        pPrivateKeyTemplate, ulPrivateKeyAttributeCount, CKA_LABEL, &privateLabelIndex);
    if (xResult != CKR_OK) {
        /* CKA_LABEL was not provided. Check if CKA_ID was passed */
        xResult = pkcs11_get_attribute_parameter_index(
            pPrivateKeyTemplate, ulPrivateKeyAttributeCount, CKA_ID, &privateLabelIndex);
        if (CKR_OK != xResult) {
            /* CKA_ID was also not provided */
            LOG_E("CKA_ID was not provided");
            xResult = CKR_ARGUMENTS_BAD;
            goto exit;
        }
        else {
            /* CKA_ID is provided. Use as keyID */
            memcpy(keyIdBuff, pPrivateKeyTemplate[privateLabelIndex].pValue, sizeof(keyIdBuff));
            privKeyId = (uint32_t)(
                (keyIdBuff[0] << 8 * 3) | (keyIdBuff[1] << 8 * 2) | (keyIdBuff[2] << 8 * 1) | (keyIdBuff[3] << 8 * 0));
        }
    }
    else {
        xResult = pkcs11_label_to_keyId(pPrivateKeyTemplate[privateLabelIndex].pValue,
            pPrivateKeyTemplate[privateLabelIndex].ulValueLen,
            &privKeyId);
        if (xResult != CKR_OK) {
            goto exit;
        }
    }

    xResult = pkcs11_get_attribute_parameter_index(
        pPublicKeyTemplate, ulPublicKeyAttributeCount, CKA_LABEL, &publicLabelIndex);
    if (xResult != CKR_OK) {
        /* CKA_LABEL was not provided. Check if CKA_ID was passed */
        xResult = pkcs11_get_attribute_parameter_index(
            pPrivateKeyTemplate, ulPrivateKeyAttributeCount, CKA_ID, &privateLabelIndex);
        if (CKR_OK != xResult) {
            /* CKA_ID was also not provided */
            LOG_E("CKA_ID was not provided");
            xResult = CKR_ARGUMENTS_BAD;
            goto exit;
        }
        else {
            /* CKA_ID is provided. Use as keyID */
            memcpy(keyIdBuff, pPrivateKeyTemplate[privateLabelIndex].pValue, sizeof(keyIdBuff));
            privKeyId = (uint32_t)(
                (keyIdBuff[0] << 8 * 3) | (keyIdBuff[1] << 8 * 2) | (keyIdBuff[2] << 8 * 1) | (keyIdBuff[3] << 8 * 0));
        }
    }
    else {
        xResult = pkcs11_label_to_keyId(
            pPublicKeyTemplate[publicLabelIndex].pValue, pPublicKeyTemplate[publicLabelIndex].ulValueLen, &pubKeyId);
        if (xResult != CKR_OK) {
            goto exit;
        }
    }

    privKeyId = privKeyId & 0xFF;
    pubKeyId  = pubKeyId & 0xFF;

    if (pubKeyId == privKeyId) {
        skipPublicKey = CK_TRUE;
    }

    sss_status = sss_key_object_init(&sss_object, &pex_sss_demo_boot_ctx->ks);
    if (sss_status != kStatus_SSS_Success) {
        xResult = CKR_FUNCTION_FAILED;
        goto exit;
    }

    sss_status = sss_key_object_allocate_handle(
        &sss_object, privKeyId, kSSS_KeyPart_Pair, cipherType, KeyBitLen * 8, kKeyObject_Mode_Persistent);
    if (sss_status != kStatus_SSS_Success) {
        xResult = CKR_FUNCTION_FAILED;
        goto exit;
    }

    sss_status = sss_key_store_generate_key(&pex_sss_demo_boot_ctx->ks, &sss_object, KeyBitLen, NULL);
    if (sss_status != kStatus_SSS_Success) {
        xResult = CKR_FUNCTION_FAILED;
        goto exit;
    }

#if defined(SSS_HAVE_HOST_EMBEDDED) && !(SSS_HAVE_HOST_EMBEDDED)
    /* Extract the public key and store it as a PEM file */
    sss_status = sss_key_store_get_key(&pex_sss_demo_boot_ctx->ks, &sss_object, pubkey, &pubkeylen, &KeyBitLen);
    if (sss_status != kStatus_SSS_Success) {
        xResult = CKR_FUNCTION_FAILED;
        goto exit;
    }

    xResult = pkcs11_parse_Convert_DerToPem(pubkey, pubkeylen);
    ENSURE_OR_GO_EXIT(xResult == CKR_OK);
#endif //!SSS_HAVE_HOST_EMBEDDED

    if (!skipPublicKey) {
        uint8_t public[100] = {0};
        size_t public_len   = sizeof(public);

        sss_status = sss_key_store_get_key(&pex_sss_demo_boot_ctx->ks, &sss_object, public, &public_len, &KeyBitLen);
        if (sss_status != kStatus_SSS_Success) {
            sss_status = sss_key_store_erase_key(&pex_sss_demo_boot_ctx->ks, &sss_object);
            xResult    = CKR_FUNCTION_FAILED;
            goto exit;
        }

        sss_object_t sss_pub_object = {0};

        sss_status = sss_key_object_init(&sss_pub_object, &pex_sss_demo_boot_ctx->ks);
        if (sss_status != kStatus_SSS_Success) {
            sss_status = sss_key_store_erase_key(&pex_sss_demo_boot_ctx->ks, &sss_object);
            xResult    = CKR_FUNCTION_FAILED;
            goto exit;
        }

        sss_status = sss_key_object_allocate_handle(
            &sss_pub_object, pubKeyId, kSSS_KeyPart_Public, cipherType, KeyBitLen * 8, kKeyObject_Mode_Persistent);
        if (sss_status != kStatus_SSS_Success) {
            sss_status = sss_key_store_erase_key(&pex_sss_demo_boot_ctx->ks, &sss_object);
            xResult    = CKR_FUNCTION_FAILED;
            goto exit;
        }

        sss_status =
            sss_key_store_set_key(&pex_sss_demo_boot_ctx->ks, &sss_pub_object, public, public_len, KeyBitLen, NULL, 0);
        if (sss_status != kStatus_SSS_Success) {
            sss_status = sss_key_store_erase_key(&pex_sss_demo_boot_ctx->ks, &sss_object);
            xResult    = CKR_FUNCTION_FAILED;
            goto exit;
        }
    }
    else {
        pubKeyId = privKeyId;
    }

    *phPublicKey  = pubKeyId | ASYMM_ID_MASK;
    *phPrivateKey = privKeyId | ASYMM_ID_MASK;

exit:
    if (sss_pkcs11_mutex_unlock() != 0) {
        return CKR_FUNCTION_FAILED;
    }
    return xResult;
}

/**
 * @brief Obtains the size of an object in bytes.
 */
// LCOV_EXCL_START
CK_DEFINE_FUNCTION(CK_RV, C_GetObjectSize)
(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ULONG_PTR pulSize)
{
    AX_UNUSED_ARG(hSession);
    AX_UNUSED_ARG(hObject);
    AX_UNUSED_ARG(pulSize);
    LOG_D("%s", __FUNCTION__);
    return CKR_FUNCTION_NOT_SUPPORTED;
}
// LCOV_EXCL_STOP

/**
 * @brief Query the value of the specified cryptographic object attribute.
 */
CK_DEFINE_FUNCTION(CK_RV, C_GetAttributeValue)
(CK_SESSION_HANDLE xSession, CK_OBJECT_HANDLE xObject, CK_ATTRIBUTE_PTR pxTemplate, CK_ULONG ulCount)
{
    CK_RV xResult             = CKR_OK;
    P11SessionPtr_t pxSession = prvSessionPointerFromHandle(xSession);
    CK_VOID_PTR pvAttr        = NULL;
    CK_ULONG ulAttrLength     = 0;
    CK_ULONG xP11KeyType, iAttrib, objectClass;
    CK_BBOOL supported = CK_FALSE;

    LOG_D("%s", __FUNCTION__);

    if (pxSession == NULL) {
        return CKR_SESSION_HANDLE_INVALID;
    }

    if (!pxTemplate) {
        return CKR_ARGUMENTS_BAD;
    }

    if (sss_pkcs11_mutex_lock() != 0) {
        xResult = CKR_CANT_LOCK;
        return xResult;
    }

    for (iAttrib = 0; iAttrib < ulCount && CKR_OK == xResult; iAttrib++) {
        /*
        * Get the attribute data and size.
        */
        ulAttrLength             = 0;
        CK_BBOOL infoUnavailable = CK_FALSE;
        sss_object_t sss_object  = {0};
        uint8_t data[2048]       = {0};
        size_t dataLen           = sizeof(data);
        size_t KeyBitLen         = 2048;
        char label[80];
        uint32_t keyId                       = 0;
        uint8_t keyIdBuff[MAX_KEY_ID_LENGTH] = {0};

        CK_CERTIFICATE_TYPE cert_type      = CKC_X_509;
        CK_MECHANISM_TYPE ecc_mechanisms[] = {
            /* ECDSA */
            CKM_ECDSA,
            CKM_ECDSA_SHA256,
        };
        CK_MECHANISM_TYPE aes_mechanisms[] = {
            /* AES Algorithms  */
            CKM_AES_ECB,
            CKM_AES_CBC,
        };

        CK_MECHANISM_TYPE keygen_mechanisms = 0;
        // LOG_I("Attribute required : 0x%08lx\n", pxTemplate[ iAttrib ].type);

        switch (pxTemplate[iAttrib].type) {
        /* Common key attributes */
        case CKA_ID: {
            if (CHECK_FOR_CERT_ID(xObject)) {
                if (SM_OK != pkcs11_get_validated_cert_id(xObject, &keyIdBuff[0])) {
                    ulAttrLength = 0;
                    xResult      = CKR_FUNCTION_FAILED;
                    break;
                }
            }
            else if (CHECK_FOR_SYMM_ID(xObject)) {
                if (kStatus_SSS_Success != pkcs11_get_validated_symm_object_id(pxSession, xObject, &keyIdBuff[0])) {
                    ulAttrLength = 0;
                    xResult      = CKR_FUNCTION_FAILED;
                    break;
                }
            }
            else {
                if (kStatus_SSS_Success != pkcs11_get_validated_object_id(pxSession, xObject, &keyIdBuff[0])) {
                    ulAttrLength = 0;
                    xResult      = CKR_FUNCTION_FAILED;
                    break;
                }
            }
            pvAttr       = (uint8_t *)&keyIdBuff[0];
            ulAttrLength = sizeof(keyIdBuff);
            break;
        }
        case CKA_CERTIFICATE_TYPE: {
            ulAttrLength = sizeof(cert_type);
            pvAttr       = &cert_type;
            break;
        }
        case CKA_LABEL: {
            if (CHECK_FOR_CERT_ID(xObject)) {
                if (SM_OK != cert_file_exists(xObject, &keyId)) {
                    ulAttrLength = 0;
                    xResult      = CKR_FUNCTION_FAILED;
                    break;
                }
                keyId = keyId | CERT_ID_MASK;
            }
            else if (CHECK_FOR_SYMM_ID(xObject)) {
                if (kStatus_SSS_Success != pkcs11_get_validated_sss_symm_object(pxSession, xObject, &sss_object)) {
                    ulAttrLength = 0;
                    xResult      = CKR_FUNCTION_FAILED;
                    break;
                }

                keyId = sss_object.keyId | SYMM_ID_MASK;
            }
            else {
                if (kStatus_SSS_Success != pkcs11_get_validated_sss_object(pxSession, xObject, &sss_object)) {
                    ulAttrLength = 0;
                    xResult      = CKR_FUNCTION_FAILED;
                    break;
                }

                keyId = sss_object.keyId | ASYMM_ID_MASK;
            }
            if (snprintf(label, sizeof(label), "sss:%08X", (unsigned int)keyId) < 0) {
                LOG_E("snprintf error");
                ulAttrLength = 0;
                xResult      = CKR_FUNCTION_FAILED;
                break;
            }
            ulAttrLength = strlen(label);
            pvAttr       = (char *)&label[0];
            break;
        }
        case CKA_ALWAYS_AUTHENTICATE: {
            supported    = CK_FALSE;
            pvAttr       = &supported;
            ulAttrLength = sizeof(supported);
            break;
        }
        case CKA_TOKEN: {
            supported    = CK_TRUE; /* Object is always on token */
            ulAttrLength = sizeof(supported);
            pvAttr       = &(supported);
            break;
        }
        case CKA_KEY_TYPE: {
            if (CHECK_FOR_SYMM_ID(xObject)) {
                if (kStatus_SSS_Success != pkcs11_get_validated_sss_symm_object(pxSession, xObject, &sss_object)) {
                    ulAttrLength = 0;
                    xResult      = CKR_FUNCTION_FAILED;
                    break;
                }
                switch (sss_object.cipherType) {
                case kSSS_CipherType_EC_NIST_P:
                case kSSS_CipherType_EC_BRAINPOOL:
                    xP11KeyType = CKK_EC;
                    break;
                case kSSS_CipherType_AES:
                    xP11KeyType = CKK_AES;
                    break;
                default:
                    xResult = CKR_ATTRIBUTE_VALUE_INVALID;
                    break;
                }
            }
            else {
                if (kStatus_SSS_Success != pkcs11_get_validated_sss_object(pxSession, xObject, &sss_object)) {
                    ulAttrLength = 0;
                    xResult      = CKR_FUNCTION_FAILED;
                    break;
                }

                switch (sss_object.cipherType) {
                case kSSS_CipherType_EC_NIST_P:
                case kSSS_CipherType_EC_BRAINPOOL:
                    xP11KeyType = CKK_EC;
                    break;
                default:
                    xResult = CKR_ATTRIBUTE_VALUE_INVALID;
                    break;
                }
            }

            ulAttrLength = sizeof(xP11KeyType);
            pvAttr       = &xP11KeyType;
            break;
        }
        case CKA_VALUE: {
            if (CHECK_FOR_CERT_ID(xObject)) {
                if (SM_OK != pkcs11_get_cert_file(xObject, &data[0], &dataLen)) {
                    ulAttrLength = 0;
                    xResult      = CKR_FUNCTION_FAILED;
                    break;
                }
                pvAttr       = (void *)&data[0];
                ulAttrLength = dataLen;
            }
            else if (CHECK_FOR_SYMM_ID(xObject)) {
                if (kStatus_SSS_Success != pkcs11_get_validated_sss_symm_object(pxSession, xObject, &sss_object)) {
                    ulAttrLength = 0;
                    xResult      = CKR_FUNCTION_FAILED;
                    break;
                }
                ulAttrLength = CK_UNAVAILABLE_INFORMATION;
                xResult      = CKR_ATTRIBUTE_SENSITIVE;
                LOG_W("Not allowed to readout symm key value");
                break;
            }
            else {
                if (kStatus_SSS_Success != pkcs11_get_validated_sss_object(pxSession, xObject, &sss_object)) {
                    ulAttrLength = 0;
                    xResult      = CKR_FUNCTION_FAILED;
                    break;
                }

                switch (sss_object.cipherType) {
                case kSSS_CipherType_Binary: {
                    if (kStatus_SSS_Success !=
                        sss_key_store_get_key(
                            &pex_sss_demo_boot_ctx->ks, &sss_object, &data[0], &dataLen, &KeyBitLen)) {
                        ulAttrLength = 0;
                        xResult      = CKR_FUNCTION_FAILED;
                        break;
                    }
                    pvAttr       = (void *)&data[0];
                    ulAttrLength = dataLen;
                    break;
                }
                case kSSS_CipherType_EC_NIST_P:
                case kSSS_CipherType_EC_BRAINPOOL: {
                    if (sss_object.objectType == kSSS_KeyPart_Pair || sss_object.objectType == kSSS_KeyPart_Private) {
                        ulAttrLength = 0;
                        xResult      = CKR_ATTRIBUTE_SENSITIVE;
                        break;
                    }
                    if (kStatus_SSS_Success !=
                        sss_key_store_get_key(
                            &pex_sss_demo_boot_ctx->ks, &sss_object, &data[0], &dataLen, &KeyBitLen)) {
                        ulAttrLength = 0;
                        xResult      = CKR_FUNCTION_FAILED;
                        break;
                    }
                    pvAttr       = (void *)&data[0];
                    ulAttrLength = dataLen;
                    break;
                }
                case kSSS_CipherType_AES:
                case kSSS_CipherType_HMAC: {
                    ulAttrLength = CK_UNAVAILABLE_INFORMATION;
                    xResult      = CKR_ATTRIBUTE_SENSITIVE;
                    LOG_W("Not allowed to readout symmetric value");
                    break;
                }
                default: {
                    ulAttrLength = 0;
                    xResult      = CKR_ARGUMENTS_BAD;
                    break;
                }
                }
            }

            break;
        }
        case CKA_VALUE_LEN: {
            ulAttrLength = CK_UNAVAILABLE_INFORMATION;
            xResult      = CKR_ATTRIBUTE_SENSITIVE;
            break;
        }
        case CKA_MODULUS_BITS:
        case CKA_PRIME_BITS: {
            ulAttrLength = CK_UNAVAILABLE_INFORMATION;
            xResult      = CKR_ATTRIBUTE_SENSITIVE;
            break;
        }
        case CKA_VENDOR_DEFINED: {
            supported    = CK_FALSE;
            pvAttr       = &supported;
            ulAttrLength = sizeof(supported);
            break;
        }
        case CKA_MODULUS: {
            supported    = CK_FALSE;
            pvAttr       = &supported;
            ulAttrLength = sizeof(supported);
            break;
        }
        case CKA_PUBLIC_EXPONENT: {
            supported    = CK_FALSE;
            pvAttr       = &supported;
            ulAttrLength = sizeof(supported);
            break;
        }
        case CKA_EC_PARAMS: {
            if (kStatus_SSS_Success != pkcs11_get_validated_sss_object(pxSession, xObject, &sss_object)) {
                ulAttrLength = 0;
                xResult      = CKR_FUNCTION_FAILED;
                break;
            }
            if (sss_object.cipherType == kSSS_CipherType_EC_NIST_P) {
                uint8_t tag         = 0x06;
                uint8_t ecParam[50] = {0};

                memcpy(&ecParam[2], (uint8_t *)MBEDTLS_OID_EC_GRP_SECP256R1, sizeof(MBEDTLS_OID_EC_GRP_SECP256R1) - 1);
                ecParam[0]   = tag;
                ecParam[1]   = sizeof(MBEDTLS_OID_EC_GRP_SECP256R1) - 1;
                ulAttrLength = sizeof(MBEDTLS_OID_EC_GRP_SECP256R1) + 1;
                pvAttr       = &ecParam[0];
                break;
            }
            else if (sss_object.cipherType == kSSS_CipherType_EC_BRAINPOOL) {
                uint8_t tag         = 0x06;
                uint8_t ecParam[50] = {0};

                memcpy(&ecParam[2], (uint8_t *)OID_EC_GRP_BP256R1, sizeof(OID_EC_GRP_BP256R1) - 1);
                ecParam[0]   = tag;
                ecParam[1]   = sizeof(OID_EC_GRP_BP256R1) - 1;
                ulAttrLength = sizeof(OID_EC_GRP_BP256R1) + 1;
                pvAttr       = &ecParam[0];
                break;
            }
            else {
                ulAttrLength = CK_UNAVAILABLE_INFORMATION;
                xResult      = CKR_ATTRIBUTE_SENSITIVE;
                break;
            }

            break;
        }
        case CKA_EC_POINT: {
            ulAttrLength = 0;
            xResult      = CKR_ATTRIBUTE_SENSITIVE;
            LOG_W("Not allowed to readout public key value");
            break;
        }
        case CKA_CLASS: {
            if (CHECK_FOR_CERT_ID(xObject)) {
                CK_BBOOL isX509Cert = CK_FALSE;
                isX509Cert          = pkcs11_is_X509_certificate(xObject);

                if (isX509Cert == CK_TRUE) {
                    objectClass  = CKO_CERTIFICATE;
                    pvAttr       = &objectClass;
                    ulAttrLength = sizeof(objectClass);
                }
                else {
                    objectClass  = CKO_DATA;
                    pvAttr       = &objectClass;
                    ulAttrLength = sizeof(objectClass);
                }
            }
            else if (CHECK_FOR_SYMM_ID(xObject)) {
                if (kStatus_SSS_Success != pkcs11_get_validated_sss_symm_object(pxSession, xObject, &sss_object)) {
                    ulAttrLength = 0;
                    xResult      = CKR_FUNCTION_FAILED;
                    break;
                }
                if (sss_object.objectType == kSSS_KeyPart_Default) {
                    if (sss_object.cipherType == kSSS_CipherType_AES) {
                        objectClass  = CKO_SECRET_KEY;
                        pvAttr       = &objectClass;
                        ulAttrLength = sizeof(objectClass);
                    }
                    else {
                        ulAttrLength    = CK_UNAVAILABLE_INFORMATION;
                        xResult         = CKR_ATTRIBUTE_SENSITIVE;
                        infoUnavailable = CK_TRUE;
                    }
                }
            }
            else {
                if (kStatus_SSS_Success != pkcs11_get_validated_sss_object(pxSession, xObject, &sss_object)) {
                    ulAttrLength = 0;
                    xResult      = CKR_FUNCTION_FAILED;
                    break;
                }

                if (sss_object.objectType == kSSS_KeyPart_Private || sss_object.objectType == kSSS_KeyPart_Pair) {
                    objectClass  = CKO_PRIVATE_KEY;
                    pvAttr       = &objectClass;
                    ulAttrLength = sizeof(objectClass);
                }
                else if (sss_object.objectType == kSSS_KeyPart_Public) {
                    objectClass  = CKO_PUBLIC_KEY;
                    pvAttr       = &objectClass;
                    ulAttrLength = sizeof(objectClass);
                }
                else if (sss_object.objectType == kSSS_KeyPart_Default) {
                    if (sss_object.cipherType == kSSS_CipherType_Binary) {
                        CK_BBOOL isX509Cert = CK_FALSE;
                        isX509Cert          = pkcs11_is_X509_certificate(sss_object.keyId);

                        if (isX509Cert == CK_TRUE) {
                            objectClass  = CKO_CERTIFICATE;
                            pvAttr       = &objectClass;
                            ulAttrLength = sizeof(objectClass);
                        }
                        else {
                            objectClass  = CKO_DATA;
                            pvAttr       = &objectClass;
                            ulAttrLength = sizeof(objectClass);
                        }
                    }
                    else {
                        objectClass  = CKO_SECRET_KEY;
                        pvAttr       = &objectClass;
                        ulAttrLength = sizeof(objectClass);
                    }
                }
                else {
                    ulAttrLength    = CK_UNAVAILABLE_INFORMATION;
                    xResult         = CKR_ATTRIBUTE_SENSITIVE;
                    infoUnavailable = CK_TRUE;
                }
            }
            break;
        }
        case CKA_HW_FEATURE_TYPE: {
            if (kStatus_SSS_Success != pkcs11_get_validated_sss_object(pxSession, xObject, &sss_object)) {
                ulAttrLength = 0;
                xResult      = CKR_FUNCTION_FAILED;
                break;
            }

            ulAttrLength    = CK_UNAVAILABLE_INFORMATION;
            xResult         = CKR_ATTRIBUTE_SENSITIVE;
            infoUnavailable = CK_TRUE;

            break;
        }
        case CKA_ENCRYPT: {
            if (CHECK_FOR_SYMM_ID(xObject)) {
                if (kStatus_SSS_Success != pkcs11_get_validated_sss_symm_object(pxSession, xObject, &sss_object)) {
                    ulAttrLength = 0;
                    xResult      = CKR_FUNCTION_FAILED;
                    break;
                }
                if (sss_object.cipherType == kSSS_CipherType_AES) {
                    supported    = CK_TRUE;
                    pvAttr       = &supported;
                    ulAttrLength = sizeof(supported);
                }
                else {
                    supported    = CK_FALSE;
                    pvAttr       = &supported;
                    ulAttrLength = sizeof(supported);
                }
            }
            else {
                if (kStatus_SSS_Success != pkcs11_get_validated_sss_object(pxSession, xObject, &sss_object)) {
                    ulAttrLength = 0;
                    xResult      = CKR_FUNCTION_FAILED;
                    break;
                }

                if (sss_object.objectType == kSSS_KeyPart_Public) {
                    supported    = CK_FALSE;
                    pvAttr       = &supported;
                    ulAttrLength = sizeof(supported);
                }
                else if (sss_object.objectType == kSSS_KeyPart_Default) {
                    if (sss_object.cipherType == kSSS_CipherType_AES) {
                        supported    = CK_TRUE;
                        pvAttr       = &supported;
                        ulAttrLength = sizeof(supported);
                    }
                    else {
                        supported    = CK_FALSE;
                        pvAttr       = &supported;
                        ulAttrLength = sizeof(supported);
                    }
                }
                else {
                    supported    = CK_FALSE;
                    pvAttr       = &supported;
                    ulAttrLength = sizeof(supported);
                }
            }
            break;
        }
        case CKA_DECRYPT: {
            if (CHECK_FOR_SYMM_ID(xObject)) {
                if (kStatus_SSS_Success != pkcs11_get_validated_sss_symm_object(pxSession, xObject, &sss_object)) {
                    ulAttrLength = 0;
                    xResult      = CKR_FUNCTION_FAILED;
                    break;
                }
                if (sss_object.cipherType == kSSS_CipherType_AES) {
                    supported    = CK_TRUE;
                    pvAttr       = &supported;
                    ulAttrLength = sizeof(supported);
                }
                else {
                    supported    = CK_FALSE;
                    pvAttr       = &supported;
                    ulAttrLength = sizeof(supported);
                }
            }
            else {
                if (kStatus_SSS_Success != pkcs11_get_validated_sss_object(pxSession, xObject, &sss_object)) {
                    ulAttrLength = 0;
                    xResult      = CKR_FUNCTION_FAILED;
                    break;
                }

                if (sss_object.objectType == kSSS_KeyPart_Private || sss_object.objectType == kSSS_KeyPart_Pair) {
                    supported    = CK_FALSE;
                    pvAttr       = &supported;
                    ulAttrLength = sizeof(supported);
                }
                else if (sss_object.objectType == kSSS_KeyPart_Default) {
                    if (sss_object.cipherType == kSSS_CipherType_AES) {
                        supported    = CK_TRUE;
                        pvAttr       = &supported;
                        ulAttrLength = sizeof(supported);
                    }
                    else {
                        supported    = CK_FALSE;
                        pvAttr       = &supported;
                        ulAttrLength = sizeof(supported);
                    }
                }
                else {
                    supported    = CK_FALSE;
                    pvAttr       = &supported;
                    ulAttrLength = sizeof(supported);
                }
            }
            break;
        }
        case CKA_SIGN: {
            if (CHECK_FOR_SYMM_ID(xObject)) {
                if (kStatus_SSS_Success != pkcs11_get_validated_sss_symm_object(pxSession, xObject, &sss_object)) {
                    ulAttrLength = 0;
                    xResult      = CKR_FUNCTION_FAILED;
                    break;
                }
                supported    = CK_FALSE;
                pvAttr       = &supported;
                ulAttrLength = sizeof(supported);
            }
            else {
                if (kStatus_SSS_Success != pkcs11_get_validated_sss_object(pxSession, xObject, &sss_object)) {
                    ulAttrLength = 0;
                    xResult      = CKR_FUNCTION_FAILED;
                    break;
                }

                if (sss_object.objectType == kSSS_KeyPart_Private || sss_object.objectType == kSSS_KeyPart_Pair) {
                    if (sss_object.cipherType == kSSS_CipherType_EC_NIST_P) {
                        supported    = CK_TRUE;
                        pvAttr       = &supported;
                        ulAttrLength = sizeof(supported);
                    }
                    else {
                        supported    = CK_FALSE;
                        pvAttr       = &supported;
                        ulAttrLength = sizeof(supported);
                    }
                }
                else {
                    supported    = CK_FALSE;
                    pvAttr       = &supported;
                    ulAttrLength = sizeof(supported);
                }
            }
            break;
        }
        case CKA_VERIFY: {
            if (CHECK_FOR_SYMM_ID(xObject)) {
                if (kStatus_SSS_Success != pkcs11_get_validated_sss_symm_object(pxSession, xObject, &sss_object)) {
                    ulAttrLength = 0;
                    xResult      = CKR_FUNCTION_FAILED;
                    break;
                }
                supported    = CK_FALSE;
                pvAttr       = &supported;
                ulAttrLength = sizeof(supported);
            }
            else {
                if (kStatus_SSS_Success != pkcs11_get_validated_sss_object(pxSession, xObject, &sss_object)) {
                    ulAttrLength = 0;
                    xResult      = CKR_FUNCTION_FAILED;
                    break;
                }

                if (sss_object.objectType == kSSS_KeyPart_Public) {
                    if (sss_object.cipherType == kSSS_CipherType_EC_NIST_P) {
                        supported    = CK_TRUE;
                        pvAttr       = &supported;
                        ulAttrLength = sizeof(supported);
                    }
                    else {
                        supported    = CK_FALSE;
                        pvAttr       = &supported;
                        ulAttrLength = sizeof(supported);
                    }
                }
                else {
                    supported    = CK_FALSE;
                    pvAttr       = &supported;
                    ulAttrLength = sizeof(supported);
                }
            }
            break;
        }
        case CKA_WRAP:
        case CKA_UNWRAP:
        case CKA_SIGN_RECOVER:
        case CKA_VERIFY_RECOVER: {
            supported    = CK_FALSE;
            ulAttrLength = sizeof(supported);
            pvAttr       = &(supported);
            break;
        }
        case CKA_DERIVE: {
            if (CHECK_FOR_SYMM_ID(xObject)) {
                if (kStatus_SSS_Success != pkcs11_get_validated_sss_symm_object(pxSession, xObject, &sss_object)) {
                    ulAttrLength = 0;
                    xResult      = CKR_FUNCTION_FAILED;
                    break;
                }
                supported    = CK_FALSE;
                pvAttr       = &supported;
                ulAttrLength = sizeof(supported);
            }
            else {
                if (kStatus_SSS_Success != pkcs11_get_validated_sss_object(pxSession, xObject, &sss_object)) {
                    ulAttrLength = 0;
                    xResult      = CKR_FUNCTION_FAILED;
                    break;
                }

                if (sss_object.objectType == kSSS_KeyPart_Pair && sss_object.cipherType == kSSS_CipherType_EC_NIST_P) {
                    supported    = CK_TRUE;
                    ulAttrLength = sizeof(supported);
                    pvAttr       = &(supported);
                }
                else {
                    supported    = CK_FALSE;
                    ulAttrLength = sizeof(supported);
                    pvAttr       = &(supported);
                }
            }
            break;
        }
        case CKA_HASH_OF_SUBJECT_PUBLIC_KEY:
        case CKA_HASH_OF_ISSUER_PUBLIC_KEY:
        case CKA_SUBJECT: {
            ulAttrLength = sizeof(data);
            if (xObject > UINT32_MAX) {
                pvAttr       = NULL;
                ulAttrLength = 0;
                xResult      = CKR_FUNCTION_FAILED;
                break;
            }
            xResult = pkcs11_parse_certificate_get_attribute(
                (uint32_t)xObject, pxTemplate[iAttrib].type, &data[0], &ulAttrLength);
            if (xResult != CKR_OK) {
                pvAttr       = NULL;
                ulAttrLength = 0;
            }
            else {
                pvAttr = &data[0];
            }
            break;
        }
        case CKA_OPENSC_NON_REPUDIATION_0_17:
        case CKA_OPENSC_NON_REPUDIATION_0_21: {
            // Not support NON-REPUDIATION signature
            supported    = CK_FALSE;
            pvAttr       = &supported;
            ulAttrLength = sizeof(supported);
            break;
        }
        case CKA_SENSITIVE:
        case CKA_ALWAYS_SENSITIVE: {
            supported = CK_FALSE;
            if (CHECK_FOR_SYMM_ID(xObject)) {
                if (kStatus_SSS_Success != pkcs11_get_validated_sss_symm_object(pxSession, xObject, &sss_object)) {
                    ulAttrLength = 0;
                    xResult      = CKR_FUNCTION_FAILED;
                    break;
                }
                if ((sss_object.objectType == kSSS_KeyPart_Default) &&
                    (sss_object.cipherType != kSSS_CipherType_Binary)) {
                    // Secret key
                    supported = CK_TRUE;
                }
                else {
                    supported = CK_FALSE;
                }
            }
            else {
                if (kStatus_SSS_Success != pkcs11_get_validated_sss_object(pxSession, xObject, &sss_object)) {
                    ulAttrLength = 0;
                    xResult      = CKR_FUNCTION_FAILED;
                    break;
                }

                if (sss_object.objectType == kSSS_KeyPart_Private || sss_object.objectType == kSSS_KeyPart_Pair) {
                    // Private key
                    supported = CK_TRUE;
                }
                else {
                    supported = CK_FALSE;
                }
            }
            pvAttr       = &supported;
            ulAttrLength = sizeof(supported);
            break;
        }
        case CKA_EXTRACTABLE: {
            supported = CK_TRUE;
            if (CHECK_FOR_SYMM_ID(xObject)) {
                if (kStatus_SSS_Success != pkcs11_get_validated_sss_symm_object(pxSession, xObject, &sss_object)) {
                    ulAttrLength = 0;
                    xResult      = CKR_FUNCTION_FAILED;
                    break;
                }
                if ((sss_object.objectType == kSSS_KeyPart_Default) &&
                    (sss_object.cipherType != kSSS_CipherType_Binary)) {
                    // Secret key
                    supported = CK_TRUE;
                }
                else {
                    supported = CK_FALSE;
                }
            }
            else {
                if (kStatus_SSS_Success != pkcs11_get_validated_sss_object(pxSession, xObject, &sss_object)) {
                    ulAttrLength = 0;
                    xResult      = CKR_FUNCTION_FAILED;
                    break;
                }

                // NX doesn't support ReadObjectAttributes, so use pre-defined value according to key type.
                supported = CK_TRUE;
                if (sss_object.objectType == kSSS_KeyPart_Private || sss_object.objectType == kSSS_KeyPart_Pair) {
                    // Private key
                    supported = CK_FALSE;
                }
                else if (sss_object.objectType == kSSS_KeyPart_Default) {
                    if ((sss_object.cipherType != kSSS_CipherType_Binary)) {
                        // Secret key
                        supported = CK_FALSE;
                    }
                }
            }

            pvAttr       = &supported;
            ulAttrLength = sizeof(supported);
            break;
        }
        case CKA_NEVER_EXTRACTABLE: {
            // Not NEVER_EXTRACTABLE
            supported    = CK_FALSE;
            pvAttr       = &supported;
            ulAttrLength = sizeof(supported);
            break;
        }
        case CKA_LOCAL: {
            supported    = CK_FALSE;
            pvAttr       = &supported;
            ulAttrLength = sizeof(supported);
            break;
        }
        case CKA_ALLOWED_MECHANISMS: {
            if (CHECK_FOR_SYMM_ID(xObject)) {
                if (kStatus_SSS_Success != pkcs11_get_validated_sss_symm_object(pxSession, xObject, &sss_object)) {
                    ulAttrLength = 0;
                    xResult      = CKR_FUNCTION_FAILED;
                    break;
                }
                if (sss_object.cipherType == kSSS_CipherType_AES) {
                    pvAttr       = (void *)aes_mechanisms;
                    ulAttrLength = sizeof(aes_mechanisms);

                    break;
                }
                else {
                    ulAttrLength = 0;
                    xResult      = CKR_ARGUMENTS_BAD;
                    break;
                }
            }
            else if (CHECK_FOR_ASYMM_ID(xObject)) {
                if (kStatus_SSS_Success != pkcs11_get_validated_sss_object(pxSession, xObject, &sss_object)) {
                    ulAttrLength = 0;
                    xResult      = CKR_FUNCTION_FAILED;
                    break;
                }

                switch (sss_object.cipherType) {
                case kSSS_CipherType_EC_NIST_P:
                case kSSS_CipherType_EC_BRAINPOOL:
                    pvAttr       = (void *)ecc_mechanisms;
                    ulAttrLength = sizeof(ecc_mechanisms);

                    break;
                default:
                    ulAttrLength = 0;
                    xResult      = CKR_ARGUMENTS_BAD;
                    break;
                }
            }
            else {
                ulAttrLength = 0;
                xResult      = CKR_ARGUMENTS_BAD;
                break;
            }
            break;
        }
        case CKA_APPLICATION:
        case CKA_OBJECT_ID: {
            // CKA_APPLICATION: Description of the application that manages the object (default empty)
            // CKA_VALUE: DER-encoding of the object identifier indicating the data object type (default empty)
            pvAttr       = NULL;
            ulAttrLength = 0;
            break;
        }
        case CKA_MODIFIABLE: {
            supported = CK_TRUE;
            if (kStatus_SSS_Success != pkcs11_get_validated_sss_object(pxSession, xObject, &sss_object)) {
                ulAttrLength = 0;
                xResult      = CKR_FUNCTION_FAILED;
                break;
            }

            supported    = CK_TRUE;
            pvAttr       = &supported;
            ulAttrLength = sizeof(supported);
            break;
        }
        case CKA_PRIVATE: {
            // When the CKA_PRIVATE attribute is CK_TRUE, a user may not access the object until
            // the user has been authenticated to the token.
            supported    = CK_FALSE;
            pvAttr       = &supported;
            ulAttrLength = sizeof(supported);
            break;
        }
        case CKA_KEY_GEN_MECHANISM: {
            /* Generated key is not local and has no keygen mechanism */
            keygen_mechanisms = CK_UNAVAILABLE_INFORMATION;
            pvAttr            = &keygen_mechanisms;
            ulAttrLength      = sizeof(keygen_mechanisms);
            break;
        }
        default: {
            LOG_W("Attribute required : 0x%08lx\n", pxTemplate[iAttrib].type);
            ulAttrLength    = CK_UNAVAILABLE_INFORMATION;
            infoUnavailable = CK_TRUE;
            xResult         = CKR_ATTRIBUTE_SENSITIVE;
            break;
        }
        }

        if (CKR_OK == xResult) {
            /*
            * Copy out the data and size.
            */

            if (NULL != pxTemplate[iAttrib].pValue && !infoUnavailable && (NULL != pvAttr)) {
                if (pxTemplate[iAttrib].ulValueLen < ulAttrLength) {
                    xResult      = CKR_BUFFER_TOO_SMALL;
                    ulAttrLength = CK_UNAVAILABLE_INFORMATION;
                }
                else {
                    memcpy(pxTemplate[iAttrib].pValue, pvAttr, ulAttrLength);
                }
            }
        }
        pxTemplate[iAttrib].ulValueLen = ulAttrLength;
    }
    if (sss_pkcs11_mutex_unlock() != 0) {
        return CKR_FUNCTION_FAILED;
    }
    return xResult;
}
