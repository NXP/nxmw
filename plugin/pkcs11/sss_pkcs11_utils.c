/*
 * Copyright 2024 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 */

/* ********************** Include files ********************** */
#include "sss_pkcs11_pal.h"
#if defined(USE_RTOS) && (USE_RTOS == 1) /* FreeRTOS includes. */
#include "FreeRTOS.h"
#include "semphr.h"
#elif (__GNUC__ && defined(SSS_HAVE_HOST_EMBEDDED) && !(SSS_HAVE_HOST_EMBEDDED))
#include <errno.h>
#include <pthread.h>
#endif

/* ********************** Global variables ********************** */

/* Mutex handling */
bool pkcs11_lock_flag = 0; // 0: Unlocked, 1: Locked
#if defined(USE_RTOS) && (USE_RTOS == 1)
static SemaphoreHandle_t pkcs11_mutex = NULL;
#elif (__GNUC__ && defined(SSS_HAVE_HOST_EMBEDDED) && !(SSS_HAVE_HOST_EMBEDDED))
static pthread_mutex_t pkcs11_mutex;
#endif

/* ********************** Functions ********************** */

/*
 * @brief Mutex Init.
 * Return - 0:Success, 1:Error
 */
int sss_pkcs11_mutex_init(void)
{
#if defined(USE_RTOS) && (USE_RTOS == 1)
    pkcs11_mutex = xSemaphoreCreateMutex();
    if (pkcs11_mutex == NULL) {
        return 1;
    }
#elif (__GNUC__ && defined(SSS_HAVE_HOST_EMBEDDED) && !(SSS_HAVE_HOST_EMBEDDED))
    {
        int ret = EBUSY;
        while (ret == EBUSY) {
            ret = pthread_mutex_init(&pkcs11_mutex, NULL);
        }
        if (ret != 0) {
            return 1;
        }
    }
#else
    LOG_W("sss_pkcs11_mutex_init not implemented \n");
#endif
    return 0;
}

/**
 * @brief Mutex Lock.
 * Return - 0:Success, 1:Error
 */
int sss_pkcs11_mutex_lock(void)
{
#if defined(USE_RTOS) && (USE_RTOS == 1)
    if (xSemaphoreTake(pkcs11_mutex, portMAX_DELAY) == pdTRUE) {
        // Semaphore obtained
        pkcs11_lock_flag = 1;
        return 0;
    }
    return 1;
#elif (__GNUC__ && defined(SSS_HAVE_HOST_EMBEDDED) && !(SSS_HAVE_HOST_EMBEDDED))
    int ret = pthread_mutex_lock(&pkcs11_mutex);
    if (ret == 0) {
        pkcs11_lock_flag = 1;
    }
    return ret;
#else
    LOG_W("sss_pkcs11_mutex_lock not implemented \n");
    return 1;
#endif
}

/**
 * @brief Mutex Unlock.
 * Return - 0:Success, 1:Error
 */
int sss_pkcs11_mutex_unlock(void)
{
    if (pkcs11_lock_flag == 0) {
        return 0;
    }

#if defined(USE_RTOS) && (USE_RTOS == 1)
    if (xSemaphoreGive(pkcs11_mutex) == pdTRUE) {
        pkcs11_lock_flag = 0;
        return 0;
    }
    return 1;
#elif (__GNUC__ && defined(SSS_HAVE_HOST_EMBEDDED) && !(SSS_HAVE_HOST_EMBEDDED))
    if (pthread_mutex_unlock(&pkcs11_mutex) == 0) {
        pkcs11_lock_flag = 0;
        return 0;
    }
    return 1;
#else
    LOG_W("sss_pkcs11_mutex_unlock not implemented \n");
    return 1;
#endif
}

/**
 * @brief Mutex Destroy.
 * Return - 0:Success, 1:Error
 */
int sss_pkcs11_mutex_destroy(void)
{
#if defined(USE_RTOS) && (USE_RTOS == 1)
    vSemaphoreDelete(pkcs11_mutex); // no return value for function vSemaphoreDelete()
    return 0;
#elif (__GNUC__ && defined(SSS_HAVE_HOST_EMBEDDED) && !(SSS_HAVE_HOST_EMBEDDED))
    if (pthread_mutex_destroy(&pkcs11_mutex) == 0) {
        return 0;
    }
    return 1;
#else
    LOG_W("sss_pkcs11_mutex_destroy not implemented \n");
    return 1;
#endif
}

/**
 * @brief
 */
int pkcs11_parse_Cert(uint8_t *pCert, size_t certLen)
{
    int ret            = -1;
    unsigned char *p   = pCert;
    unsigned char *end = pCert + certLen;
    size_t len         = 0;
    size_t cmpLen      = 0;

    /* Parse first sequence tag */
    ret = sss_util_asn1_get_tag(&p, end, &len, ASN1_TAG_SEQUENCE | ASN1_TAG_CONSTRUCTED);
    if (ret != 0) {
        LOG_D("Error parsing ASN.1 data : %d", __LINE__);
        return ret;
    }
    /* Incrementing p for extracting len */
    p++;
    if ((*p & 0x80) == 0x80) {
        if ((*p & 0x7F) == 0x01) {
            cmpLen = *(p + 1);
        }
        else if ((*(p)&0x7F) == 0x02) {
            cmpLen = ((*(p + 1) << 8) + *(p + 2));
        }
    }
    else {
        cmpLen = *p;
    }
    p--;
    /* p now points to TBS bytes */
    /* Parse sequence tag of TBSCertificate */
    ret = sss_util_asn1_get_tag(&p, end, &len, ASN1_TAG_SEQUENCE | ASN1_TAG_CONSTRUCTED);
    if (ret != 0) {
        LOG_D("Error parsing ASN.1 data : %d", __LINE__);
        return ret;
    }
    if (cmpLen != len) {
        LOG_E("TBSCertificate length mismatch : %d", __LINE__);
        return ret;
    }
    p += len;
    /* Incrementing p for extracting len */
    p++;
    if ((*p & 0x80) == 0x80) {
        if ((*p & 0x7F) == 0x01) {
            cmpLen = *(p + 1);
        }
        else if ((*(p)&0x7F) == 0x02) {
            cmpLen = ((*(p + 1) << 8) + *(p + 2));
        }
    }
    else {
        cmpLen = *p;
    }
    p--;
    /* p now points to Certificate signature algorithm */
    /* Parse sequence tag of Certificate version */
    ret = sss_util_asn1_get_tag(&p, end, &len, ASN1_TAG_SEQUENCE | ASN1_TAG_CONSTRUCTED);
    if (ret != 0) {
        LOG_D("Error parsing ASN.1 data : %d", __LINE__);
        return ret;
    }
    if (cmpLen != len) {
        LOG_E("Cert signature algo length mismatch : %d", __LINE__);
        return ret;
    }
    p += len;
    /* Incrementing p for extracting len */
    p++;
    if ((*p & 0x80) == 0x80) {
        if ((*p & 0x7F) == 0x01) {
            cmpLen = *(p + 1);
        }
        else if ((*(p)&0x7F) == 0x02) {
            cmpLen = ((*(p + 1) << 8) + *(p + 2));
        }
    }
    else {
        cmpLen = *p;
    }
    p--;
    /* p now points to Certificate signature*/
    /* Parse sequence tag of Certificate signature */
    ret = sss_util_asn1_get_tag(&p, end, &len, ASN1_TAG_BIT_STRING);
    if (ret != 0) {
        LOG_D("Error parsing ASN.1 data : %d", __LINE__);
        return ret;
    }
    if (cmpLen != len) {
        LOG_E("Cert signature length mismatch : %d", __LINE__);
        return ret;
    }
    return ret;
}

/**
 * @brief Function for parsing the private key
 */
int pkcs11_private_key_parse(CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, uint8_t *pKey, size_t keyLen)
{
    CK_RV xResult        = CKR_OK;
    CK_KEY_TYPE key_type = CKK_EC;
    int ret              = 1;
    CK_ULONG index;
    xResult = pkcs11_get_attribute_parameter_index(pTemplate, ulCount, CKA_KEY_TYPE, &index);
    if (xResult != CKR_OK) {
        return 1;
    }
    memcpy(&key_type, pTemplate[index].pValue, pTemplate[index].ulValueLen);
    if (key_type == CKK_EC) { /*CKK_EC also means CKK_ECDSA both enum values are same*/
                              // Currently only for NIST-P curves
#if CKK_EC != CKK_ECDSA
#error "Assumed to be equal"
#endif

        unsigned char *p   = pKey;
        unsigned char *end = pKey + keyLen;
        size_t len         = 0;

        /* Parse first sequence tag */
        ret = sss_util_asn1_get_tag(&p, end, &len, ASN1_TAG_SEQUENCE | ASN1_TAG_CONSTRUCTED);
        if (ret != 0) {
            LOG_D("Error parsing ASN.1 data : %d", __LINE__);
            return 1;
        }
        /* p now points to version */
        /* Parse integer tag of version */
        ret = sss_util_asn1_get_tag(&p, end, &len, ASN1_TAG_INTEGER);
        if (ret != 0) {
            LOG_D("Error parsing ASN.1 data : %d", __LINE__);
            return 1;
        }
        p += len;

        /* p now points to octet String */
        /* Parse 0x04 tag of octet String */
        ret = sss_util_asn1_get_tag(&p, end, &len, ASN1_TAG_OCTET_STRING);
        if (ret != 0) {
            LOG_D("Error parsing ASN.1 data : %d", __LINE__);
            return 1;
        }
        p += len;
    }
    else {
        return 1;
    }

    return ret;
}

/**
 * @brief Function for parsing the public key
 */
int pkcs11_public_key_parse(CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, uint8_t *pKey, size_t keyLen)
{
    CK_RV xResult        = CKR_OK;
    CK_KEY_TYPE key_type = CKK_EC;
    int ret              = 1;
    CK_ULONG index;
    xResult = pkcs11_get_attribute_parameter_index(pTemplate, ulCount, CKA_KEY_TYPE, &index);
    if (xResult != CKR_OK) {
        return 1;
    }
    memcpy(&key_type, pTemplate[index].pValue, pTemplate[index].ulValueLen);

    if (key_type == CKK_EC) { /*CKK_EC also means CKK_ECDSA both enum values are same*/
                              // Currently only for NIST-P curves
#if CKK_EC != CKK_ECDSA
#error "Assumed to be equal"
#endif

        unsigned char *p   = pKey;
        unsigned char *end = pKey + keyLen;
        size_t len         = 0;

        /* Parse first sequence tag */
        ret = sss_util_asn1_get_tag(&p, end, &len, ASN1_TAG_SEQUENCE | ASN1_TAG_CONSTRUCTED);
        if (ret != 0) {
            LOG_D("Error parsing ASN.1 data : %d", __LINE__);
            return ret;
        }

        /* p now points to EC Params */
        /* Parse sequence tag of EC Params */
        ret = sss_util_asn1_get_tag(&p, end, &len, ASN1_TAG_SEQUENCE | ASN1_TAG_CONSTRUCTED);
        if (ret != 0) {
            LOG_D("Error parsing ASN.1 data : %d", __LINE__);
            return ret;
        }
        p += len;

        /* p now points to Bit String */
        /* Parse 0x03 tag of Bit String */
        ret = sss_util_asn1_get_tag(&p, end, &len, ASN1_TAG_BIT_STRING);
        if (ret != 0) {
            LOG_D("Error parsing ASN.1 data : %d", __LINE__);
            return ret;
        }
    }
    else {
        return 1;
    }

    return ret;
}

/**
 * @brief
 */
int pkcs11_parse_PrivateKey(
    CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_ULONG_PTR index, sss_pkcs11_key_parse_t *keyParse)
{
    CK_RV xResult = CKR_OK;
    int ret       = 1;
    CK_KEY_TYPE key_type;

    xResult = pkcs11_get_attribute_parameter_index(pTemplate, ulCount, CKA_VALUE, index);
    if (xResult != CKR_OK) {
        uint8_t key[4096] = {0};
        size_t keyLen     = sizeof(key);
        xResult           = pkcs11_create_raw_privateKey(pTemplate, ulCount, &key[0], &keyLen);
        if (xResult != CKR_OK) {
            return ret;
        }
        memcpy(keyParse->pbuff, key, keyLen);
        keyParse->buffLen = (size_t)keyLen;
        ret               = 0;
    }
    else {
        if (0 != pTemplate[*index].ulValueLen) {
            ret = pkcs11_private_key_parse(pTemplate, ulCount, pTemplate[*index].pValue, pTemplate[*index].ulValueLen);
            if (ret != 0) {
                uint8_t key[1024] = {0};
                size_t keyLen     = sizeof(key);
                xResult           = pkcs11_create_raw_privateKey(pTemplate, ulCount, &key[0], &keyLen);
                if (xResult != CKR_OK) {
                    return ret;
                }
                memcpy(keyParse->pbuff, key, keyLen);
                keyParse->buffLen = (size_t)keyLen;
            }
            else {
                memcpy(keyParse->pbuff, pTemplate[*index].pValue, pTemplate[*index].ulValueLen);
                keyParse->buffLen = (size_t)pTemplate[*index].ulValueLen;
            }
        }
    }

    key_type = CKK_EC;
    *index   = 0;
    xResult  = pkcs11_get_attribute_parameter_index(pTemplate, ulCount, CKA_KEY_TYPE, index);
    if (xResult != CKR_OK) {
        return 1;
    }
    memcpy(&key_type, pTemplate[*index].pValue, pTemplate[*index].ulValueLen);

    if (key_type == CKK_EC) { /*CKK_EC also means CKK_ECDSA both enum values are same*/
                              // Currently only for NIST-P curves
#if CKK_EC != CKK_ECDSA
#error "Assumed to be equal"
#endif

        /*To calculate the keyBitLen*/
        size_t keyLen = 0;
        *index        = 0;
        xResult       = pkcs11_get_attribute_parameter_index(pTemplate, ulCount, CKA_VALUE, index);
        if (xResult == CKR_OK) {
            keyLen = (size_t)pTemplate[*index].ulValueLen;
            ret    = 0;
        }
        else {
            unsigned char *p   = keyParse->pbuff;
            unsigned char *end = keyParse->pbuff + keyParse->buffLen;
            size_t len         = 0;

            /* Parse first sequence tag */
            ret = sss_util_asn1_get_tag(&p, end, &len, ASN1_TAG_SEQUENCE | ASN1_TAG_CONSTRUCTED);
            if (ret != 0) {
                LOG_E("Error parsing ASN.1 data : %d", __LINE__);
            }
            /* p now points to version */
            /* Parse integer tag of version */
            ret = sss_util_asn1_get_tag(&p, end, &len, ASN1_TAG_INTEGER);
            if (ret != 0) {
                LOG_E("Error parsing ASN.1 data : %d", __LINE__);
            }
            p += len;

            /* p now points to octet String */
            /* Parse 0x04 tag of octet String */
            ret = sss_util_asn1_get_tag(&p, end, &len, ASN1_TAG_OCTET_STRING);
            if (ret != 0) {
                LOG_E("Error parsing ASN.1 data : %d", __LINE__);
            }
            p += len;

            /* p now points to extension */
            /* Parse 0xA0 tag */
            ret = sss_util_asn1_get_tag(&p, end, &len, ASN1_TAG_CONSTRUCTED | ASN1_TAG_CONTEXT_SPECIFIC);
            if (ret != 0) {
                LOG_E("Error parsing ASN.1 data : %d", __LINE__);
            }
            p += len;

            /* p now points to context specific */
            /* Parse 0xA1 tag */
            ret = sss_util_asn1_get_tag(
                &p, end, &len, ASN1_TAG_CONSTRUCTED | ASN1_TAG_CONTEXT_SPECIFIC | ASN1_TAG_BOOLEAN);
            if (ret != 0) {
                LOG_E("Error parsing ASN.1 data : %d", __LINE__);
            }

            /* p now points to public key */
            /* Parse 0x03 tag of bit string */
            ret = sss_util_asn1_get_tag(&p, end, &len, ASN1_TAG_BIT_STRING);
            if (ret != 0) {
                LOG_E("Error parsing ASN.1 data : %d", __LINE__);
            }
            /* check for zero padding */
            if (*p == 0x00) {
                p++;
                if (len < 1) {
                    LOG_E("len will wrap");
                    return 1;
                }
                len--;
            }
            /* Uncompressed Key */

            if (*p == 0x04) {
                if (len < 1) {
                    LOG_E("len will wrap");
                    return 1;
                }
                len--;
            }
            keyLen = len / 2;
        }

        if (keyLen < 64) {
            keyParse->keyBitLen = keyLen * 8;
        }
        else if (keyLen == 66) {
            /*ECP_DP_SECP521R1 Case*/
            keyParse->keyBitLen = 521;
        }
        else {
            LOG_E("Invalid KeyLen");
            return 1;
        }
    }
    else {
        LOG_E("Key Type not supported");
        return 1;
    }

    return ret;
}

/**
 * @brief
 */
int pkcs11_parse_PublicKey(
    CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_ULONG_PTR index, sss_pkcs11_key_parse_t *keyParse)
{
    CK_RV xResult = CKR_OK;
    int ret       = 1;

    xResult = pkcs11_get_attribute_parameter_index(pTemplate, ulCount, CKA_VALUE, index);
    if (xResult != CKR_OK) {
        uint8_t key[2048] = {0};
        size_t keyLen     = sizeof(key);
        xResult           = pkcs11_create_raw_publicKey(pTemplate, ulCount, &key[0], &keyLen);
        if (xResult != CKR_OK) {
            return 1;
        }

        memcpy(keyParse->pbuff, &key[0], keyLen);
        keyParse->buffLen = keyLen;
        ret               = 0;
    }
    else {
        ret = pkcs11_public_key_parse(pTemplate, ulCount, pTemplate[*index].pValue, pTemplate[*index].ulValueLen);
        if (ret != 0) {
            xResult = CKR_ARGUMENTS_BAD;
            return ret;
        }

        memcpy(keyParse->pbuff, pTemplate[*index].pValue, pTemplate[*index].ulValueLen);
        keyParse->buffLen = (size_t)pTemplate[*index].ulValueLen;
    }

    CK_KEY_TYPE key_type = CKK_EC;
    *index               = 0;
    xResult              = pkcs11_get_attribute_parameter_index(pTemplate, ulCount, CKA_KEY_TYPE, index);
    if (xResult != CKR_OK) {
        return 1;
    }
    memcpy(&key_type, pTemplate[*index].pValue, pTemplate[*index].ulValueLen);

    if (key_type == CKK_EC) { /*CKK_EC also means CKK_ECDSA both enum values are same*/
                              // Currently only for NIST-P curves
#if CKK_EC != CKK_ECDSA
#error "Assumed to be equal"
#endif

        /*To calculate the keyBitLen*/

        unsigned char *p   = keyParse->pbuff;
        unsigned char *end = keyParse->pbuff + keyParse->buffLen;
        size_t len         = 0;
        size_t keyLen      = 0;

        /* Parse first sequence tag */
        ret = sss_util_asn1_get_tag(&p, end, &len, ASN1_TAG_SEQUENCE | ASN1_TAG_CONSTRUCTED);
        if (ret != 0) {
            LOG_E("Error parsing ASN.1 data : %d", __LINE__);
        }

        /* p now points to EC Params */
        /* Parse sequence tag of EC Params */
        ret = sss_util_asn1_get_tag(&p, end, &len, ASN1_TAG_SEQUENCE | ASN1_TAG_CONSTRUCTED);
        if (ret != 0) {
            LOG_E("Error parsing ASN.1 data : %d", __LINE__);
        }
        p += len;

        /* p now points to Bit String */
        /* Parse 0x03 tag of Bit String */
        ret = sss_util_asn1_get_tag(&p, end, &len, ASN1_TAG_BIT_STRING);
        if (ret != 0) {
            LOG_E("Error parsing ASN.1 data : %d", __LINE__);
        }

        /* check for zero padding */
        if (*p == 0x00) {
            p++;
            if (len < 1) {
                LOG_E("Invalid Key length");
                return 1;
            }
            len--;
        }
        /* Uncompressed Key */

        if (*p == 0x04) {
            if (len < 1) {
                LOG_E("Invalid Key length");
                return 1;
            }
            len--;
        }
        keyLen = len / 2;

        if (keyLen <= 64) {
            keyParse->keyBitLen = keyLen * 8;
        }
        else if (keyLen == 66) {
            /*ECP_DP_SECP521R1 Case*/
            keyParse->keyBitLen = 521;
        }
        else {
            LOG_E("Invalid KeyLen");
            return 1;
        }
    }
    else {
        LOG_E("Key Type not supported");
        return 1;
    }

    return ret;
}

/**
 * @brief
 */
int pkcs11_parse_Convert_PemToDer(const unsigned char *input, size_t ilen, unsigned char *output, size_t *olen)
{
    int ret;
    const unsigned char *s1, *s2, *end = input + ilen;
    size_t len = 0;

    s1 = (unsigned char *)strstr((const char *)input, "-----BEGIN");
    if (s1 == NULL) {
        return (-1);
    }

    s2 = (unsigned char *)strstr((const char *)input, "-----END");
    if (s2 == NULL) {
        return (-1);
    }

    s1 += 10;
    while (s1 < end && *s1 != '-')
        s1++;
    while (s1 < end && *s1 == '-')
        s1++;
    if (*s1 == '\r') {
        s1++;
    }
    if (*s1 == '\n') {
        s1++;
    }

    if (s2 <= s1 || s2 > end) {
        return (-1);
    }

    ret = base64_decode(NULL, 0, &len, (const unsigned char *)s1, s2 - s1);
    if (ret == ERR_BASE64_INVALID_CHARACTER) {
        return (ret);
    }

    if (len > *olen) {
        return (-1);
    }

    if ((ret = base64_decode(output, len, &len, (const unsigned char *)s1, s2 - s1)) != 0) {
        return (ret);
    }

    *olen = len;

    return (0);
}

/**
 * @brief
 */
CK_RV pkcs11_parseCert_GetAttr(
    CK_ATTRIBUTE_TYPE attributeType, uint8_t *pCert, size_t certLen, uint8_t *pData, CK_ULONG *ulAttrLength)
{
    CK_RV xResult            = CKR_OK;
    uint8_t pubdata[2048]    = {0};
    size_t pubdataLen        = sizeof(pubdata);
    uint8_t issuerData[256]  = {0};
    size_t issuerDataLen     = sizeof(issuerData);
    uint8_t subjectData[256] = {0};
    size_t subjectDataLen    = sizeof(subjectData);

    int ret            = -1;
    unsigned char *p   = pCert;
    unsigned char *end = pCert + certLen;
    size_t len         = 0;
    size_t certObjLen  = 0;

    /* Parsing the certificate for getting public key*/
    /* Parse first sequence tag */
    ret = sss_util_asn1_get_tag(&p, end, &len, ASN1_TAG_SEQUENCE | ASN1_TAG_CONSTRUCTED);
    if (ret != 0) {
        LOG_E("Error parsing ASN.1 data : %d", __LINE__);
    }
    /* p now points to TBS bytes */
    /* Parse sequence tag of TBSCertificate */
    ret = sss_util_asn1_get_tag(&p, end, &len, ASN1_TAG_SEQUENCE | ASN1_TAG_CONSTRUCTED);
    if (ret != 0) {
        LOG_E("Error parsing ASN.1 data : %d", __LINE__);
    }
    /* p now points to Certificate version */
    /* Parse 0xA0 tag of Certificate version */
    ret = sss_util_asn1_get_tag(&p, end, &len, ASN1_TAG_CONTEXT_SPECIFIC | ASN1_TAG_CONSTRUCTED);
    if (ret != 0) {
        LOG_E("Error parsing ASN.1 data : %d", __LINE__);
    }
    p += len;
    /* p now points to Certificate serial number */
    /* Parse ASN1_TAG_INTEGER tag of Certificate version */
    ret = sss_util_asn1_get_tag(&p, end, &len, ASN1_TAG_INTEGER);
    if (ret != 0) {
        LOG_E("Error parsing ASN.1 data : %d", __LINE__);
    }
    p += len;
    /* p now points to Certificate signature algorithm */
    /* Parse sequence tag of Certificate version */
    ret = sss_util_asn1_get_tag(&p, end, &len, ASN1_TAG_SEQUENCE | ASN1_TAG_CONSTRUCTED);
    if (ret != 0) {
        LOG_E("Error parsing ASN.1 data : %d", __LINE__);
    }

    p += len;

    /* Incrementing p for extracting len */
    p++;
    if ((*p & 0x80) == 0x80) {
        if ((*p & 0x7F) == 0x01) {
            certObjLen = *(p + 1) + 3;
        }
        else if ((*(p)&0x7F) == 0x02) {
            certObjLen = ((*(p + 1) << 8) + *(p + 2)) + 4;
        }
    }
    else {
        certObjLen = *p + 2;
    }
    p--;

    do {
        if ((p + certObjLen) > end) {
            LOG_E("Invalid certificate object");
            issuerDataLen = 0;
            break;
        }
        else if (certObjLen > issuerDataLen) {
            LOG_E("Insufficient buffer");
            issuerDataLen = 0;
            break;
        }
        if (len > 0) {
            memcpy(&issuerData[0], (void *)p, certObjLen);
            issuerDataLen = certObjLen;
        }
        else {
            issuerDataLen = 0;
        }
    } while (0);

    /* p now points to Certificate Issuer */
    /* Parse sequence tag of Certificate version */
    ret = sss_util_asn1_get_tag(&p, end, &len, ASN1_TAG_SEQUENCE | ASN1_TAG_CONSTRUCTED);
    if (ret != 0) {
        LOG_E("Error parsing ASN.1 data : %d", __LINE__);
    }
    p += len;
    /* p now points to Certificate Validity */
    /* Parse sequence tag of Certificate version */
    ret = sss_util_asn1_get_tag(&p, end, &len, ASN1_TAG_SEQUENCE | ASN1_TAG_CONSTRUCTED);
    if (ret != 0) {
        LOG_E("Error parsing ASN.1 data : %d", __LINE__);
    }
    p += len;

    /* Incrementing p for extracting len */
    p++;
    if ((*p & 0x80) == 0x80) {
        if ((*p & 0x7F) == 0x01) {
            certObjLen = *(p + 1) + 3;
        }
        else if ((*(p)&0x7F) == 0x02) {
            certObjLen = ((*(p + 1) << 8) + *(p + 2)) + 4;
        }
    }
    else {
        certObjLen = *p + 2;
    }
    p--;

    do {
        if ((p + certObjLen) > end) {
            LOG_E("Invalid certificate object");
            subjectDataLen = 0;
            break;
        }
        else if (certObjLen > subjectDataLen) {
            LOG_E("Insufficient buffer");
            subjectDataLen = 0;
            break;
        }
        if (certObjLen > 0) {
            memcpy(&subjectData[0], (void *)p, certObjLen);
            subjectDataLen = certObjLen;
        }
        else {
            subjectDataLen = 0;
        }
    } while (0);

    /* p now points to Certificate Subject */
    /* Parse sequence tag of Certificate version */
    ret = sss_util_asn1_get_tag(&p, end, &len, ASN1_TAG_SEQUENCE | ASN1_TAG_CONSTRUCTED);
    if (ret != 0) {
        LOG_E("Error parsing ASN.1 data : %d", __LINE__);
    }
    p += len;

    /* Incrementing p for extracting len, p now points to the public key info*/
    p++;
    if ((*p & 0x80) == 0x80) {
        if ((*p & 0x7F) == 0x01) {
            certObjLen = *(p + 1) + 3;
        }
        else if ((*(p)&0x7F) == 0x02) {
            certObjLen = ((*(p + 1) << 8) + *(p + 2)) + 4;
        }
    }
    else {
        certObjLen = *p + 2;
    }
    p--;

    do {
        if ((p + certObjLen) > end) {
            LOG_E("Invalid certificate object");
            issuerDataLen = 0;
            break;
        }
        else if (certObjLen > pubdataLen) {
            LOG_E("Insufficient buffer");
            pubdataLen = 0;
            break;
        }
        if (certObjLen > 0) {
            memcpy(&pubdata[0], (void *)p, certObjLen);
            pubdataLen = certObjLen;
        }
        else {
            pubdataLen = 0;
        }
    } while (0);

    switch (attributeType) {
    case CKA_HASH_OF_ISSUER_PUBLIC_KEY:
        if ((issuerData[0] != subjectData[0]) || (issuerDataLen != subjectDataLen) ||
            (memcmp(&issuerData[0], &subjectData[0], subjectDataLen) != 0)) {
            xResult = CKR_ATTRIBUTE_SENSITIVE;
        }
        else {
            if ((size_t)(*ulAttrLength) < pubdataLen) {
                LOG_E("Buffer too small");
                xResult = CKR_BUFFER_TOO_SMALL;
                break;
            }
            memcpy(&pData[0], &pubdata[0], pubdataLen);
            *ulAttrLength = pubdataLen;
        }
        break;

    case CKA_HASH_OF_SUBJECT_PUBLIC_KEY:
        if ((size_t)(*ulAttrLength) < pubdataLen) {
            LOG_E("Buffer too small");
            xResult = CKR_BUFFER_TOO_SMALL;
            break;
        }
        memset(&pData[0], 0, pubdataLen);
        memcpy(&pData[0], &pubdata[0], pubdataLen);
        *ulAttrLength = pubdataLen;
        break;

    case CKA_SUBJECT:
        if (subjectDataLen != 0) {
            if ((size_t)(*ulAttrLength) < subjectDataLen) {
                LOG_E("Buffer too small");
                xResult = CKR_BUFFER_TOO_SMALL;
                break;
            }
            memcpy(&pData[0], &subjectData[0], subjectDataLen);
            *ulAttrLength = subjectDataLen;
            break;
        }
        else {
            xResult = CKR_FUNCTION_FAILED;
            break;
        }

    default:
        LOG_W("Attribute required : 0x%08lx\n", attributeType);
        xResult = CKR_ATTRIBUTE_SENSITIVE;
    }
    return xResult;
}

/** @brief Create Raw Private Key.
 * This function generates a raw private key.
 *
 * @param pxTemplate - Pointer to a search template that specifies the attribute values to match.
 * @param ulCount - Number of attributes in the search template.
 * @param key_buffer - Buffer containing the key data.
 * @param keyLen - size of the key_buffer in bytes.
 *
 * @returns Status of the operation
 * @retval #CKR_OK The operation has completed successfully.
 * @retval #CKR_FUNCTION_FAILED The requested function could not be performed.
 * @retval #CKR_ARGUMENTS_BAD The arguments supplied to the function are not appropriate.
 */
CK_RV pkcs11_create_raw_privateKey(CK_ATTRIBUTE_PTR pxTemplate, CK_ULONG ulCount, uint8_t *key_buffer, size_t *keyLen)
{
    CK_RV xResult = CKR_FUNCTION_FAILED;
    CK_ULONG keyTypeIndex;
    CK_KEY_TYPE key_type = CKK_EC;

    xResult = pkcs11_get_attribute_parameter_index(pxTemplate, ulCount, CKA_KEY_TYPE, &keyTypeIndex);
    if (xResult != CKR_OK) {
        goto exit;
    }

    memcpy(&key_type, pxTemplate[keyTypeIndex].pValue, pxTemplate[keyTypeIndex].ulValueLen);

    if (key_type == CKK_EC) {
        CK_ULONG parameterIndex;
        if (pkcs11_get_attribute_parameter_index(pxTemplate, ulCount, CKA_EC_PARAMS, &parameterIndex) ||
            pkcs11_get_attribute_parameter_index(pxTemplate, ulCount, CKA_VALUE, &parameterIndex)) {
            xResult = CKR_ARGUMENTS_BAD;
            goto exit;
        }
        CK_ULONG valueIndex = 0;
        xResult             = pkcs11_get_attribute_parameter_index(pxTemplate, ulCount, CKA_VALUE, &valueIndex);
        if (xResult != CKR_OK) {
            return xResult;
        }
        memcpy(&key_buffer[0], pxTemplate[valueIndex].pValue, pxTemplate[valueIndex].ulValueLen);
        *keyLen = pxTemplate[valueIndex].ulValueLen;
    }
    else {
        xResult = CKR_ARGUMENTS_BAD;
    }

exit:
    return xResult;
}

/** @brief Create Raw Public Key.
 * This function generates a raw public key.
 *
 * @param pxTemplate - Pointer to a search template that specifies the attribute values to match.
 * @param ulCount - Number of attributes in the search template.
 * @param key_buffer - Buffer containing the key data.
 * @param keyLen - size of the key_buffer in bytes.
 *
 * @returns Status of the operation
 * @retval #CKR_OK The operation has completed successfully.
 * @retval #CKR_FUNCTION_FAILED The requested function could not be performed.
 * @retval #CKR_ARGUMENTS_BAD The arguments supplied to the function are not appropriate.
 */
CK_RV pkcs11_create_raw_publicKey(CK_ATTRIBUTE_PTR pxTemplate, CK_ULONG ulCount, uint8_t *key_buffer, size_t *keyLen)
{
    CK_RV xResult = CKR_FUNCTION_FAILED;
    CK_ULONG keyTypeIndex;
    CK_KEY_TYPE key_type = CKK_EC;
    CK_ULONG parameterIndex;

    xResult = pkcs11_get_attribute_parameter_index(pxTemplate, ulCount, CKA_KEY_TYPE, &keyTypeIndex);
    if (xResult != CKR_OK) {
        goto exit;
    }

    memcpy(&key_type, pxTemplate[keyTypeIndex].pValue, pxTemplate[keyTypeIndex].ulValueLen);
    if (key_type == CKK_EC) {
        if (pkcs11_get_attribute_parameter_index(pxTemplate, ulCount, CKA_EC_PARAMS, &parameterIndex) ||
            pkcs11_get_attribute_parameter_index(pxTemplate, ulCount, CKA_EC_POINT, &parameterIndex)) {
            xResult = CKR_ARGUMENTS_BAD;
            goto exit;
        }

        uint8_t key[2048]      = {0};
        size_t bufferSize_copy = *keyLen;
        size_t parameterLen    = 0;
        uint8_t tag            = ASN_TAG_BITSTRING;

        xResult      = pkcs11_get_attribute_parameter_index(pxTemplate, ulCount, CKA_EC_POINT, &parameterIndex);
        parameterLen = (size_t)pxTemplate[parameterIndex].ulValueLen;

        /**
            CKA_EC_POINT passed is DER encoded under Octet String tag. Decode the tag, length
            and parse the value.
        */

        uint8_t ecPointInput[150] = {0};
        size_t ecPointInput_size  = sizeof(ecPointInput);
        if (ecPointInput_size < (size_t)pxTemplate[parameterIndex].ulValueLen) {
            xResult = CKR_ARGUMENTS_BAD;
            goto exit;
        }
        memcpy(&ecPointInput[0],
            (uint8_t *)pxTemplate[parameterIndex].pValue,
            (size_t)pxTemplate[parameterIndex].ulValueLen);
        size_t i = 0;
        if (ecPointInput[i++] != ASN_TAG_OCTETSTRING) {
            xResult = CKR_ARGUMENTS_BAD;
            goto exit;
        }

        size_t len = ecPointInput[i++];

        if ((len & 0x80) == 0x80) {
            if ((len & 0x7F) == 0x01) {
                len = ecPointInput[i++];
            }
            else if ((len & 0x7F) == 0x02) {
                len = (ecPointInput[i] << 8) | (ecPointInput[i + 1]);
                i   = i + 2;
            }
            else {
                xResult = CKR_FUNCTION_FAILED;
                goto exit;
            }
        }

        uint8_t ecPoint[150] = {0};
        // size_t ecPoint_size = sizeof(ecPoint);
        if (len > sizeof(ecPoint) - 1) {
            xResult = CKR_ARGUMENTS_BAD;
            goto exit;
        }
        if (ecPointInput_size < i) {
            xResult = CKR_ARGUMENTS_BAD;
            goto exit;
        }
        if (len > sizeof(ecPointInput) - i) {
            xResult = CKR_ARGUMENTS_BAD;
            goto exit;
        }
        memcpy(&ecPoint[1], &ecPointInput[i], len);

        // xResult = pkcs11_setASNTLV(tag, (uint8_t*) pxTemplate[parameterIndex].pValue, parameterLen, key, keyLen);
        xResult = pkcs11_setASNTLV(tag, &ecPoint[0], len + 1, key, keyLen);
        if (xResult != CKR_OK) {
            goto exit;
        }

        uint8_t ecPubParams[50] = {0};
        size_t ecPubParams_size = sizeof(ecPubParams);

        tag          = ASN_TAG_OBJ_IDF;
        xResult      = pkcs11_get_attribute_parameter_index(pxTemplate, ulCount, CKA_EC_PARAMS, &parameterIndex);
        parameterLen = (size_t)pxTemplate[parameterIndex].ulValueLen;

        if (ecPubParams_size < parameterLen) {
            xResult = CKR_ARGUMENTS_BAD;
            goto exit;
        }
        ecPubParams_size = ecPubParams_size - parameterLen;
        memcpy(&ecPubParams[ecPubParams_size], (uint8_t *)pxTemplate[parameterIndex].pValue, parameterLen);

        uint8_t id_ecPublicKey[] = ID_ECPUBLICKEY;
        xResult = pkcs11_setASNTLV(tag, &id_ecPublicKey[0], sizeof(id_ecPublicKey), ecPubParams, &ecPubParams_size);
        if (xResult != CKR_OK) {
            goto exit;
        }

        tag = ASN_TAG_SEQUENCE;
        if (ecPubParams_size >= sizeof(ecPubParams)) {
            goto exit;
        }

        xResult =
            pkcs11_setASNTLV(tag, &ecPubParams[ecPubParams_size], sizeof(ecPubParams) - ecPubParams_size, key, keyLen);
        if (xResult != CKR_OK) {
            goto exit;
        }

        size_t totalLen = bufferSize_copy - *keyLen;

        if (totalLen <= 127) {
            if (*keyLen < 1) {
                xResult = CKR_FUNCTION_FAILED;
                goto exit;
            }
            *keyLen = *keyLen - 1;

            key[*keyLen] = totalLen;
        }
        else if (totalLen <= 255) {
            if (*keyLen < 2) {
                xResult = CKR_FUNCTION_FAILED;
                goto exit;
            }
            *keyLen = *keyLen - 2;

            key[*keyLen]     = 0x81;
            key[*keyLen + 1] = totalLen;
        }
        else {
            if (*keyLen < 3) {
                xResult = CKR_FUNCTION_FAILED;
                goto exit;
            }
            *keyLen = *keyLen - 3;

            key[*keyLen]     = 0x82;
            key[*keyLen + 1] = (totalLen & 0x00FF00) >> 8;
            key[*keyLen + 2] = (totalLen & 0x00FF);
        }

        if (*keyLen < 1) {
            return CKR_ARGUMENTS_BAD;
        }
        *keyLen = *keyLen - 1;

        key[*keyLen] = ASN_TAG_SEQUENCE;

        if (bufferSize_copy < *keyLen) {
            xResult = CKR_FUNCTION_FAILED;
            goto exit;
        }
        totalLen = bufferSize_copy - *keyLen;
        memcpy(&key_buffer[0], &key[*keyLen], totalLen);
        *keyLen = totalLen;
    }
    else {
        xResult = CKR_ARGUMENTS_BAD;
    }

exit:
    return xResult;
}

#if (defined(SSS_HAVE_HOST_EMBEDDED) && !(SSS_HAVE_HOST_EMBEDDED))

/**
 * @brief This function is to get the pem file path
*/
int get_file_path(char *pubKeyFilePath, const char *fileName, size_t fileNameLen)
{
    int cwdIndex = -1;
    for (size_t i = 0; i < sizeof(__FILE__); i++) {
        if (__FILE__[i] == OS_PATH_SEPARATOR) {
            cwdIndex = i;
        }
    }
    if (cwdIndex == -1) {
        LOG_E("Looks like you are in the root directory!");
        return 1;
    }
    size_t pathLen = 0;
    for (int i = 0; i < cwdIndex + 1; i++) {
        pubKeyFilePath[pathLen++] = __FILE__[i];
    }
    for (size_t i = 0; i < fileNameLen; i++) {
        pubKeyFilePath[pathLen++] = fileName[i];
    }
    LOG_I("FILE PATH %s", pubKeyFilePath);
    return 0;
}

/**
 * @brief This function converts der to pem format and write to the file
*/
CK_RV pkcs11_parse_Convert_DerToPem(unsigned char *pubkey, size_t publen)
{
    CK_RV xResult              = CKR_FUNCTION_FAILED;
    int ret                    = 0;
    uint8_t base64_format[256] = {0};
    size_t base64_olen         = 0;
    char pem_format[256]       = {0};
    FILE *fp                   = NULL;
    char pubKeyFilePath[200]   = {0};

    ret = base64_encode(base64_format, sizeof(base64_format), &base64_olen, pubkey, publen);
    ENSURE_OR_GO_EXIT(ret == 0);
    if (SNPRINTF(pem_format, sizeof(pem_format), BEGIN_PUBLIC "%s" END_PUBLIC, base64_format) < 0) {
        xResult = CKR_FUNCTION_FAILED;
        goto exit;
    }

    ret = get_file_path(pubKeyFilePath, PUBLIC_KEY_PEM_FILE, sizeof(PUBLIC_KEY_PEM_FILE));
    ENSURE_OR_GO_EXIT(ret == 0);

    fp = fopen(pubKeyFilePath, "wb+");
    if (fp == NULL) {
        LOG_E("Error in opening file, Is the public key path updated ??");
        xResult = CKR_FUNCTION_FAILED;
        goto exit;
    }
    if (fwrite(pem_format, 1, strlen(pem_format), fp) != strlen(pem_format)) {
        LOG_E("Failed to write");
        xResult = CKR_FUNCTION_FAILED;
        goto exit;
    }

    xResult = CKR_OK;

exit:

    if (fp != NULL) {
        if (fclose(fp) != 0) {
            LOG_E("fclose error");
        }
    }
    return xResult;
}

/**
 * @brief This function reads pem format pub key and converts to der format
*/

int pkcs11GetPubKeyDer(unsigned char *pubkey, size_t *publen)
{
    FILE *fp                 = NULL;
    uint8_t base64_key[256]  = {0};
    char pubKeyFilePath[200] = {0};
    int ret                  = 1;

    ret = get_file_path(pubKeyFilePath, PUBLIC_KEY_PEM_FILE, sizeof(PUBLIC_KEY_PEM_FILE));
    ENSURE_OR_GO_EXIT(ret == 0);

    fp = fopen(pubKeyFilePath, "rb");
    if (fp == NULL) {
        LOG_E("Cannot open file");
        ret = 1;
        goto exit;
    }
    if (fseek(fp, 0L, SEEK_SET) != 0) {
        LOG_E("fseek failed");
        ret = 1;
        goto exit;
    }
    if (fread(base64_key, 1, sizeof(base64_key), fp) < 1) {
        LOG_E("fread error");
        ret = 1;
        goto exit;
    }

    if (pkcs11_parse_Convert_PemToDer((unsigned char *)base64_key, sizeof(base64_key), pubkey, publen) != 0) {
        LOG_E("DER conversion failed");
        ret = 1;
        goto exit;
    }

    ret = 0;

exit:

    if (fp != NULL) {
        if (fclose(fp) != 0) {
            LOG_E("fclose error");
        }
    }
    return ret;
}

#endif //!SSS_HAVE_HOST_EMBEDDED
