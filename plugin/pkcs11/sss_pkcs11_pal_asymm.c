/*
 * Copyright 2024-2025 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 */

/* ********************** Include files ********************** */
#include "sss_pkcs11_pal.h"
#include <limits.h>

/* ********************** Functions ********************** */

/*
 This is a simple function to insert a TLV into a buffer.
 params:
    tag             - ASN.1 Tag
    component       - byte array to be inserted
    componentLen    - Size of component to be inserted
    key             - Buffer into which component will be inserted
    keyLen          - Size of the buffer (key).

 Note : This function inserts the component at the end of the buffer and updates the
        keyLen to where the component is inserted with tag. (Points to the tag)
*/
CK_RV pkcs11_setASNTLV(uint8_t tag, uint8_t *component, const size_t componentLen, uint8_t *key, size_t *keyLen)
{
    if (componentLen <= 0) {
        return CKR_ARGUMENTS_BAD;
    }

    if (*keyLen < componentLen) {
        return CKR_ARGUMENTS_BAD;
    }

    *keyLen = *keyLen - componentLen;
    memcpy(&key[*keyLen], component, componentLen);

    if (componentLen <= 127) {
        if (*keyLen < 1) {
            return CKR_ARGUMENTS_BAD;
        }
        *keyLen      = *keyLen - 1;
        key[*keyLen] = componentLen;
    }
    else if (componentLen <= 255) {
        if (*keyLen < 2) {
            return CKR_ARGUMENTS_BAD;
        }
        *keyLen          = *keyLen - 2;
        key[*keyLen]     = 0x81;
        key[*keyLen + 1] = componentLen;
    }
    else {
        if (*keyLen < 3) {
            return CKR_ARGUMENTS_BAD;
        }
        *keyLen          = *keyLen - 3;
        key[*keyLen]     = 0x82;
        key[*keyLen + 1] = (componentLen & 0x00FF00) >> 8;
        key[*keyLen + 2] = (componentLen & 0x00FF);
    }
    if (*keyLen < 1) {
        return CKR_ARGUMENTS_BAD;
    }
    *keyLen = *keyLen - 1;

    key[*keyLen] = tag;

    return CKR_OK;
}

/** @brief Ec Signature To RandS.
 * This function generates RandS from signature.
 *
 * @param signature - Buffer containing the signature to read and verify.
 * @param sigLen - Size of signature in bytes.
 *
 * @returns Status of the operation
 * @retval #CKR_OK The operation has completed successfully.
 * @retval #CKR_FUNCTION_FAILED The requested function could not be performed.
 */
CK_RV pkcs11_ecSignatureToRandS(uint8_t *signature, size_t *sigLen)
{
    CK_RV xResult      = CKR_FUNCTION_FAILED;
    uint8_t rands[128] = {0};
    size_t index       = 0;
    size_t i           = 0;
    size_t len         = 0;
    if (signature[index++] != 0x30) {
        goto exit;
    }
    if ((*sigLen) < 2) {
        goto exit;
    }

    len = signature[index++];
    if ((len & 0x80) == 0x80) {
        if ((len & 0x7F) == 0x01) {
            index = index + 1;
        }
        else if ((len & 0x7F) == 0x02) {
            index = index + 2;
        }
    }

    if (index > *sigLen) {
        goto exit;
    }
    if (signature[index++] != 0x02) {
        goto exit;
    }

    len = signature[index++];

    if ((len & 0x42) == 0x42) {
        if ((signature[index]) == 0x00) {
            len--;
            index++;
        }
    }

    if (len & 0x01) {
        if ((signature[index]) == 0x00) {
            len--;
            index++;
        }
    }

    for (i = 0; i < len; i++) {
        rands[i] = signature[index++];
    }

    if (signature[index++] != 0x02) {
        goto exit;
    }

    len = signature[index++];

    if ((len & 0x42) == 0x42) {
        if ((signature[index]) == 0x00) {
            len--;
            index++;
        }
    }

    if (len & 0x01) {
        if ((signature[index]) == 0x00) {
            len--;
            index++;
        }
    }

    len = len + i;
    for (; i < len; i++) {
        rands[i] = signature[index++];
    }

    ENSURE_OR_GO_EXIT(i <= *sigLen);
    ENSURE_OR_GO_EXIT(i <= sizeof(rands));
    memcpy(&signature[0], &rands[0], i);
    *sigLen = i;

    xResult = CKR_OK;
exit:
    return xResult;
}

/** @brief Ec RandS To Signature.
 * This function generates signature from RandS.
 *
 * @param rands - Pointer to a location where rands recieved.
 * @param rands_len - Length in bytes of generated rands.
 * @param output - Output buffer containing the signature data.
 * @param outputLen - Size of the output in bytes.
 *
 * @returns Status of the operation
 * @retval #CKR_OK The operation has completed successfully.
 * @retval #CKR_FUNCTION_FAILED The requested function could not be performed.
 * @retval #CKR_ARGUMENTS_BAD The arguments supplied to the function are not appropriate.
 */
CK_RV pkcs11_ecRandSToSignature(uint8_t *rands, const size_t rands_len, uint8_t *output, size_t *outputLen)
{
    CK_RV xResult          = CKR_FUNCTION_FAILED;
    uint8_t signature[260] = {0};
    size_t signatureLen    = sizeof(signature);
    size_t componentLen    = (rands_len) / 2;
    uint8_t tag            = ASN_TAG_INT;
    size_t totalLen;

    xResult = pkcs11_setASNTLV(tag, &rands[componentLen], componentLen, signature, &signatureLen);
    if (xResult != CKR_OK) {
        goto exit;
    }

    xResult = pkcs11_setASNTLV(tag, &rands[0], componentLen, signature, &signatureLen);
    if (xResult != CKR_OK) {
        goto exit;
    }

    totalLen = sizeof(signature) - signatureLen;

    if (totalLen <= 127) {
        if (signatureLen < 1) {
            xResult = CKR_FUNCTION_FAILED;
            goto exit;
        }
        signatureLen = signatureLen - 1;

        signature[signatureLen] = totalLen;
    }
    else if (totalLen <= 255) {
        if (signatureLen < 2) {
            xResult = CKR_FUNCTION_FAILED;
            goto exit;
        }
        signatureLen = signatureLen - 2;

        signature[signatureLen]     = 0x81;
        signature[signatureLen + 1] = totalLen;
    }
    else {
        if (signatureLen < 3) {
            xResult = CKR_FUNCTION_FAILED;
            goto exit;
        }
        signatureLen = signatureLen - 3;

        signature[signatureLen]     = 0x82;
        signature[signatureLen + 1] = (totalLen & 0x00FF00) >> 8;
        signature[signatureLen + 2] = (totalLen & 0x00FF);
    }
    if (signatureLen < 1) {
        return CKR_ARGUMENTS_BAD;
    }
    signatureLen = signatureLen - 1;

    signature[signatureLen] = ASN_TAG_SEQUENCE;

    if (sizeof(signature) < signatureLen) {
        return CKR_BUFFER_TOO_SMALL;
    }
    totalLen = sizeof(signature) - signatureLen;
    memcpy(&output[0], &signature[signatureLen], totalLen);
    *outputLen = totalLen;

    xResult = CKR_OK;
exit:
    return xResult;
}

/** @brief Ec Public key Get Ec Params.
 * This function is to get Ec params.
 *
 * @param input - Pointer to a location where rands recieved.
 * @param dataLen - Length in bytes of generated rands.
 *
 * @returns Status of the operation
 * @retval #CKR_OK The operation has completed successfully.
 * @retval #CKR_FUNCTION_FAILED The requested function could not be performed.
 */
CK_RV pkcs11_ecPublickeyGetEcParams(uint8_t *input, size_t *inputLen)
{
    CK_RV xResult      = CKR_FUNCTION_FAILED;
    size_t index       = 0;
    uint8_t data[1024] = {0};
    size_t len         = 0;
    uint8_t tag        = 0;
    if (sizeof(data) <= *inputLen) {
        xResult = CKR_FUNCTION_FAILED;
        goto exit;
    }
    memcpy(&data[0], input, *inputLen);

    tag = data[index++];
    if (tag != ASN_TAG_SEQUENCE) {
        xResult = CKR_FUNCTION_FAILED;
        goto exit;
    }

    len = data[index++];

    if ((len & 0x80) == 0x80) {
        if ((len & 0x7F) == 0x01) {
            len = data[index++];
        }
        else if ((len & 0x7F) == 0x02) {
            len   = (data[index] << 8) | data[index + 1];
            index = index + 2;
        }
    }

    if (index > *inputLen) {
        goto exit;
    }

    tag = data[index++];
    if (tag != ASN_TAG_SEQUENCE) {
        xResult = CKR_FUNCTION_FAILED;
        goto exit;
    }

    len = data[index++];

    if ((len & 0x80) == 0x80) {
        if ((len & 0x7F) == 0x01) {
            len = data[index++];
        }
        else if ((len & 0x7F) == 0x02) {
            len   = (data[index] << 8) | data[index + 1];
            index = index + 2;
        }
    }

    if (index > *inputLen) {
        goto exit;
    }

    tag = data[index++];
    if (tag != ASN_TAG_OBJ_IDF) {
        xResult = CKR_FUNCTION_FAILED;
        goto exit;
    }

    len = data[index++];

    if ((len & 0x80) == 0x80) {
        if ((len & 0x7F) == 0x01) {
            len = data[index++];
        }
        else if ((len & 0x7F) == 0x02) {
            len   = (data[index] << 8) | data[index + 1];
            index = index + 2;
        }
    }

    index = index + len;

    if (index > *inputLen) {
        goto exit;
    }

    if (index >= sizeof(data)) {
        xResult = CKR_FUNCTION_FAILED;
        goto exit;
    }

    tag = data[index];
    if (tag != ASN_TAG_OBJ_IDF) {
        xResult = CKR_FUNCTION_FAILED;
        goto exit;
    }

    ENSURE_OR_GO_EXIT((index + 1) <= sizeof(data) - 1);
    len = data[index + 1];

    if ((len & 0x80) == 0x80) {
        if ((len & 0x7F) == 0x01) {
            ENSURE_OR_GO_EXIT((index + 2) <= sizeof(data) - 1);
            len = data[index + 2];
            ENSURE_OR_GO_EXIT((UINT_MAX - 1) >= len);
            len++;
        }
        else if ((len & 0x7F) == 0x02) {
            ENSURE_OR_GO_EXIT((index + 3) <= sizeof(data) - 1);
            len = (data[index + 2] << 8) | data[index + 3];
            ENSURE_OR_GO_EXIT((UINT_MAX - 2) >= len);
            len = len + 2;
        }
    }

    ENSURE_OR_GO_EXIT((UINT_MAX - 2) >= len);
    len = len + 2;
    ENSURE_OR_GO_EXIT((UINT_MAX - index) >= (size_t)len);

    if ((index + len) > *inputLen) {
        xResult = CKR_FUNCTION_FAILED;
        goto exit;
    }

    if (index > sizeof(data)) {
        xResult = CKR_FUNCTION_FAILED;
        goto exit;
    }

    memcpy(&input[0], &data[index], len);
    *inputLen = len;
    xResult   = CKR_OK;
exit:
    return xResult;
}
