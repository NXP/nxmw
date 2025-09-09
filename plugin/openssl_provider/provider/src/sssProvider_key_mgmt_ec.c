/**
 * @file sssProvider_key_mgmt_ec.c
 * @author NXP Semiconductors
 * @version 1.0
 * @par License
 *
 * Copyright 2024-2025 NXP
 * SPDX-License-Identifier: Apache-2.0
 *
 * @par Description
 * OpenSSL Provider implementation for EC key management
 *
 */

#if defined(SSS_USE_FTR_FILE)
#include "fsl_sss_ftr.h"
#else
#include "fsl_sss_ftr_default.h"
#endif

/* ********************** Include files ********************** */
#include <openssl/core_names.h>
#include <openssl/pem.h>
#include <openssl/decoder.h>
#include "sssProvider_main.h"
#include <limits.h>
#include <string.h>
#include "fsl_sss_nx_types.h"
#include "fsl_sss_util_asn1_der.h"

/* ********************** Defines **************************** */

#define SSS_DEFAULT_EC_KEY_ID 0x04
#define NX_MAGIC_NUM_SIZE 8
#define NX_MAGIC_NUM                                   \
    {                                                  \
        0xB6, 0xB5, 0xA6, 0xA5, 0xB6, 0xB5, 0xA6, 0xA5 \
    }
/* clang-format on */

/*
    Enable import of Keys in sss Provider
*/
#define SSS_ENABLE_EC_KEYMGMT_IMPORT_FUNC

/*
    NOTE:
    Enabling the below option will generate the key in
    Secure Element even when no key id is used.
    (key id used will be SSS_DEFAULT_EC_KEY_ID).
    For TLS use case, this will result in
    ephemeral key created at this location and used for ECDH.
*/
//#define SSS_ENABLE_NX_EC_KEY_GEN_WITH_NO_KEYID

#define TLS_NISTP_CLIENT_PUBLIC_KEY                                                                                 \
    {                                                                                                               \
        0x04, 0x6D, 0xC5, 0x82, 0x21, 0x09, 0xA0, 0x24, 0x4E, 0xEF, 0xCC, 0xD3, 0x3F, 0xBF, 0xF1, 0x56, 0x3A, 0x2A, \
            0x55, 0xD9, 0x72, 0x20, 0x5E, 0x69, 0x3B, 0x68, 0x2E, 0xC9, 0x85, 0x1A, 0x8D, 0xC3, 0xEB, 0x7B, 0xF8,   \
            0xAF, 0xDC, 0x7C, 0x65, 0xFC, 0x22, 0x4F, 0x91, 0xA6, 0x39, 0xE6, 0x4E, 0xB1, 0x48, 0x07, 0x20, 0x48,   \
            0xCD, 0xC9, 0x6F, 0x13, 0x8B, 0xDD, 0x2F, 0x6A, 0x81, 0xC0, 0x06, 0x85, 0x7D,                           \
    }

#define TLS_BP_CLIENT_PUBLIC_KEY                                                                                    \
    {                                                                                                               \
        0x04, 0x87, 0x28, 0x25, 0xEF, 0x2E, 0x8A, 0xA1, 0x61, 0xF5, 0x91, 0x9F, 0xBC, 0x4C, 0x30, 0x5C, 0x05, 0xE3, \
            0x2A, 0x21, 0x00, 0xDF, 0x05, 0x0E, 0xAC, 0x1B, 0x8D, 0xAF, 0x6E, 0xE8, 0x62, 0x69, 0x69, 0x52, 0x80,   \
            0xCF, 0x2C, 0xBE, 0x65, 0xDD, 0x36, 0xA6, 0x4D, 0x58, 0x46, 0x97, 0x6F, 0x77, 0xBC, 0xCC, 0x8E, 0x5C,   \
            0xCD, 0xDC, 0x36, 0x91, 0x53, 0xCD, 0x3A, 0x92, 0xBF, 0x0F, 0x67, 0xC8, 0x1A,                           \
    }

/* ********************** Private funtions ******************* */

static void sss_prov_get_curve(uint32_t cipherType, uint16_t keyLen, char **curve)
{
    if (cipherType == kSSS_CipherType_EC_NIST_P && keyLen == 32) {
        *curve = "P-256";
    }
    else if (cipherType == kSSS_CipherType_EC_BRAINPOOL && keyLen == 32) {
        *curve = "brainpoolP256r1";
    }
    else {
        *curve = NULL;
        sssProv_Print(LOG_ERR_ON, "Curve type not supported");
    }
    return;
}

static int sss_type_key_map_index(uint32_t cipherType, uint32_t keyBitLen)
{
    int i = 0;
    while ((sss_type_key_map[i].cipherType != 0) && (i < MAX_SSS_TYPE_KEY_MAP_ENTRIES)) {
        if ((sss_type_key_map[i].cipherType == cipherType) && (sss_type_key_map[i].keyBitLen == keyBitLen)) {
            return i;
        }
        i++;
    }
    return -1;
}

static int sss_get_key_len_cipher_type(char *curve_name, uint32_t *cipherType, uint16_t *keyBitLen)
{
    int i = 0;
    for (i = 0; i < MAX_SSS_TYPE_KEY_MAP_ENTRIES; i++) {
        if (0 == SSS_CMP_STR(sss_type_key_map[i].curve_name, curve_name)) {
            *cipherType = sss_type_key_map[i].cipherType;
            if ((sss_type_key_map[i].keyBitLen / 8U) > UINT16_MAX) {
                return -1;
            }
            *keyBitLen = sss_type_key_map[i].keyBitLen / 8U;
            return i;
        }
    }
    return -1;
}

static void *sss_ec_keymgmt_load(const void *reference, size_t reference_sz)
{
    sss_provider_store_obj_t *pStoreCtx = NULL;

    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);

    if (!reference || reference_sz != sizeof(pStoreCtx)) {
        return NULL;
    }

    pStoreCtx                               = *(sss_provider_store_obj_t **)reference;
    *(sss_provider_store_obj_t **)reference = NULL;
    return pStoreCtx;
}

#ifdef SSS_ENABLE_EC_KEYMGMT_IMPORT_FUNC
static void *sss_ec_keymgmt_new(void *provctx)
{
    sss_provider_store_obj_t *pStoreCtx = OPENSSL_zalloc(sizeof(sss_provider_store_obj_t));

    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);
    if (pStoreCtx != NULL) {
        pStoreCtx->pProvCtx = provctx;
    }

    return pStoreCtx;
}
#endif /*SSS_ENABLE_EC_KEYMGMT_IMPORT_FUNC*/

static void sss_ec_keymgmt_free(void *keydata)
{
    sss_provider_store_obj_t *pStoreCtx = (sss_provider_store_obj_t *)keydata;
    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);

    if (pStoreCtx != NULL) {
        if (pStoreCtx->pEVPPkey != NULL) {
            EVP_PKEY_free(pStoreCtx->pEVPPkey);
            pStoreCtx->pEVPPkey = NULL;
        }
    }

    if (keydata != NULL) {
        OPENSSL_free(keydata);
    }
    return;
}

static int sss_ec_keymgmt_get_params(void *keydata, OSSL_PARAM params[])
{
    sss_provider_store_obj_t *pStoreCtx  = (sss_provider_store_obj_t *)keydata;
    sss_nx_session_t *pSession           = NULL;
    OSSL_PARAM *p                        = NULL;
    int ret                              = 0;
    int keylen_bits                      = 0;
    int pkey_bits                        = 0;
    int pkey_security_bits               = 0;
    uint8_t public_key[256]              = {0};
    size_t public_key_len                = sizeof(public_key);
    unsigned char privkey[66]            = {0}; /*max key bitLen 521 */
    int index                            = 0;
    BIGNUM *bn_priv_key                  = NULL;
    uint8_t magic_num[NX_MAGIC_NUM_SIZE] = NX_MAGIC_NUM;
    int security_bits                    = 0;
    char group_name[32]                  = {0};
    size_t group_name_len                = sizeof(group_name);

    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);

    if (params == NULL) {
        return 1;
    }

    ENSURE_OR_GO_CLEANUP(pStoreCtx != NULL);

    if (pStoreCtx->isEVPKey) {
        ENSURE_OR_GO_CLEANUP(pStoreCtx->pEVPPkey != NULL);

        /* EVP_PKEY_size() returns the maximum suitable size for the output buffers
        for almost all operations that can be done with pkey */
        pStoreCtx->maxSize = EVP_PKEY_size(pStoreCtx->pEVPPkey);

        pkey_bits = EVP_PKEY_bits(pStoreCtx->pEVPPkey);
        ENSURE_OR_GO_CLEANUP(pkey_bits > 0);

        p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS);
        if (p != NULL && !OSSL_PARAM_set_int(p, pkey_bits)) {
            goto cleanup;
        }
        p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MAX_SIZE);
        if (p != NULL && !OSSL_PARAM_set_int(p, pStoreCtx->maxSize)) { /* Signature size */
            goto cleanup;
        }
        p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY);
        if (p != NULL && !EVP_PKEY_get_params(pStoreCtx->pEVPPkey, params)) {
            goto cleanup;
        }

        pkey_security_bits = EVP_PKEY_security_bits(pStoreCtx->pEVPPkey);
        ENSURE_OR_GO_CLEANUP(pkey_security_bits > 0);

        p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_SECURITY_BITS);
        if (p != NULL && !OSSL_PARAM_set_int(p, pkey_security_bits)) {
            goto cleanup;
        }
        p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_GROUP_NAME);
        if (p != NULL) {
            if (!EVP_PKEY_get_utf8_string_param(
                    pStoreCtx->pEVPPkey, "group", group_name, group_name_len, &group_name_len)) {
                goto cleanup;
            }
            if (!OSSL_PARAM_set_utf8_string(p, group_name)) {
                goto cleanup;
            }
        }
    }
    else {
        ENSURE_OR_GO_CLEANUP(pStoreCtx->pProvCtx != NULL);
        ENSURE_OR_GO_CLEANUP(pStoreCtx->pProvCtx->p_ex_sss_boot_ctx != NULL);

        pSession = (sss_nx_session_t *)&pStoreCtx->pProvCtx->p_ex_sss_boot_ctx->session;

        pStoreCtx->key_len = 32; /*Key length can not be read from NX*/
        keylen_bits        = pStoreCtx->key_len * 8;

        if (keylen_bits >= 256) {
            security_bits = 128;
        }
        else {
            security_bits = keylen_bits / 2;
        }

        p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_GROUP_NAME);
        if (p != NULL) {
            index = sss_type_key_map_index(pStoreCtx->object.cipherType, keylen_bits);
            ENSURE_OR_GO_CLEANUP(index != -1);

            if ((!OSSL_PARAM_set_utf8_string(p, sss_type_key_map[index].curve_name))) {
                goto cleanup;
            }
        }

        p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS);
        if ((p != NULL) && (!OSSL_PARAM_set_int(p, keylen_bits))) {
            goto cleanup;
        }

        p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MAX_SIZE);
        if ((p != NULL) && (!OSSL_PARAM_set_int(p, (((pStoreCtx->key_len) * 2) + 8)))) { /* Signature size */
            goto cleanup;
        }

        p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_PUB_KEY);
        if (p != NULL) {
            BIGNUM *bn_pub_key = NULL;
            bn_pub_key         = BN_bin2bn(public_key, public_key_len, NULL);
            p->data_size       = public_key_len;
            if (!OSSL_PARAM_set_BN(p, bn_pub_key)) {
                goto cleanup;
            }
        }

        p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_PRIV_KEY);
        if (p != NULL) {
            ENSURE_OR_GO_CLEANUP(sizeof(privkey) >= pStoreCtx->key_len);
            ENSURE_OR_GO_CLEANUP(pStoreCtx->key_len > 0);
            privkey[pStoreCtx->key_len - 1] = 0x10;                            /* Start pattern */
            memcpy(&privkey[2], magic_num, sizeof(magic_num));                 /* Magic number */
            memcpy(&privkey[10], &pStoreCtx->keyid, sizeof(pStoreCtx->keyid)); /* Key id information */
            privkey[1] = 0x10;                                                 /* Indicate a private key */
            privkey[2] = 0x00;                                                 /* Reserved */

            bn_priv_key = BN_bin2bn(privkey, pStoreCtx->key_len, NULL);

            p->data_size = pStoreCtx->key_len;
            if (!OSSL_PARAM_set_BN(p, bn_priv_key)) {
                goto cleanup;
            }
        }

        p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_DEFAULT_DIGEST);
        if ((p != NULL) && (!OSSL_PARAM_set_utf8_string(p, "SHA256"))) {
            goto cleanup;
        }

        p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MANDATORY_DIGEST);
        if ((p != NULL) && (!OSSL_PARAM_set_utf8_string(p, "SHA256"))) {
            goto cleanup;
        }

        p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY);
        if (p != NULL) {
            params->data_size   = public_key_len;
            params->return_size = public_key_len;
            if (!OSSL_PARAM_set_octet_string(params, public_key, public_key_len)) {
                goto cleanup;
            }
        }

        p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_SECURITY_BITS);
        if (p != NULL && !OSSL_PARAM_set_int(p, security_bits)) {
            goto cleanup;
        }
    }

    ret = 1;
cleanup:
    return ret;
}

static const OSSL_PARAM ec_settable_params[] = {
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, NULL, 0), OSSL_PARAM_END};

static int sss_ec_keymgmt_set_params(void *keydata, OSSL_PARAM params[])
{
    sss_provider_store_obj_t *pStoreCtx = (sss_provider_store_obj_t *)keydata;
    OSSL_PARAM *p                       = NULL;

    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);

    if (params == NULL) {
        return 1;
    }

    ENSURE_OR_GO_CLEANUP(pStoreCtx != NULL);
    ENSURE_OR_GO_CLEANUP(pStoreCtx->pEVPPkey != NULL);

    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY);
    if (p != NULL && !EVP_PKEY_set_params(pStoreCtx->pEVPPkey, params)) {
        goto cleanup;
    }
    return 1;

cleanup:
    return 0;
}

static const OSSL_PARAM *sss_ec_keymgmt_gettable_params(void *provctx)
{
    static OSSL_PARAM gettable[] = {OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_MAX_SIZE, NULL),
        OSSL_PARAM_END};

    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);

    (void)(provctx);
    return gettable;
}

static const OSSL_PARAM *sss_ec_keymgmt_settable_params(void *provctx)
{
    (void)(provctx);
    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);
    return ec_settable_params;
}

static const char *sss_ec_keymgmt_query_operation_name(int operation_id)
{
    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);
    switch (operation_id) {
    case OSSL_OP_KEYEXCH:
        return "ECDH";
    case OSSL_OP_SIGNATURE:
        return "ECDSA";
    default:
        return NULL;
    }
}

static int sss_ec_keymgmt_has(const void *keydata, int selection)
{
    sss_provider_store_obj_t *pStoreCtx = (sss_provider_store_obj_t *)keydata;
    int ok                              = 1;

    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);

    if (pStoreCtx == NULL) {
        return 0;
    }

    if (pStoreCtx->isEVPKey) {
        if (pStoreCtx->pEVPPkey == NULL) {
            return 0;
        }

        if (EVP_PKEY_id(pStoreCtx->pEVPPkey) == EVP_PKEY_EC) {
            if (selection == OSSL_KEYMGMT_SELECT_PRIVATE_KEY) {
                int ret = (pStoreCtx->isPrivateKey) ? (ok) : (0);
                return ret;
            }
            else if (selection == OSSL_KEYMGMT_SELECT_PUBLIC_KEY) {
                int ret = (pStoreCtx->isPrivateKey) ? (0) : (ok);
                return ret;
            }
            else if (selection == OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) {
                return ok;
            }
            else {
                // Any other - return 0.
                return 0;
            }
        }
        else {
            // Control should not have come here.
            return 0;
        }
    }
    else {
        if (selection == OSSL_KEYMGMT_SELECT_PRIVATE_KEY) {
            if (pStoreCtx->object.objectType == kSSS_KeyPart_Pair ||
                pStoreCtx->object.objectType == kSSS_KeyPart_Private) {
                return ok;
            }
            else {
                return 0;
            }
        }
        else if (selection == OSSL_KEYMGMT_SELECT_PUBLIC_KEY) {
            if (pStoreCtx->object.objectType == kSSS_KeyPart_Public ||
                pStoreCtx->object.objectType == kSSS_KeyPart_Pair) {
                return ok;
            }
            else {
                return 0;
            }
        }
        else if (selection == OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) {
            if (pStoreCtx->object.cipherType == kSSS_CipherType_EC_NIST_P ||
                pStoreCtx->object.cipherType == kSSS_CipherType_EC_BRAINPOOL) {
                return ok;
            }
            else {
                return 0;
            }
        }
        else {
            // Any other - return 0.
            return 0;
        }
    }
}

#ifdef SSS_ENABLE_EC_KEYMGMT_IMPORT_FUNC
static int sss_ec_keymgmt_import(void *keydata, int selection, OSSL_PARAM params[])
{
    sss_status_t status                 = kStatus_SSS_Fail;
    sss_provider_store_obj_t *pStoreCtx = (sss_provider_store_obj_t *)keydata;
    unsigned int magic_num              = {0};
    uint8_t *priv_key_data              = NULL;
    size_t priv_key_data_len            = 0;
    BIGNUM *bn_priv_key                 = NULL;
    int res                             = 0;
    char *keyType                       = NULL;

    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);

    ENSURE_OR_GO_CLEANUP(pStoreCtx != NULL);
    OSSL_PARAM *p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_GROUP_NAME);
    ENSURE_OR_GO_CLEANUP(p != NULL);

    res = OSSL_PARAM_get_utf8_string(p, &keyType, 16);
    ENSURE_OR_GO_CLEANUP(res == 1);

    if (selection & OSSL_KEYMGMT_SELECT_KEYPAIR) {
        OSSL_PARAM *param = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_PRIV_KEY);
        if (param != NULL) {
            res = OSSL_PARAM_get_BN(param, &bn_priv_key);
            ENSURE_OR_GO_CLEANUP(res == 1);

            ENSURE_OR_GO_CLEANUP((SIZE_MAX - 7) >= (size_t)(BN_num_bits(bn_priv_key)));
            priv_key_data_len = BN_num_bytes(bn_priv_key);
            ENSURE_OR_GO_CLEANUP(priv_key_data_len != 0);

            priv_key_data = (uint8_t *)OPENSSL_malloc(priv_key_data_len);
            ENSURE_OR_GO_CLEANUP(priv_key_data != NULL);

            res = BN_bn2bin(bn_priv_key, priv_key_data);
            ENSURE_OR_GO_CLEANUP(res == (int)priv_key_data_len);

            pStoreCtx->key_len = (uint16_t)priv_key_data_len;

            ENSURE_OR_GO_CLEANUP(priv_key_data_len >= 14);

            param = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_PUB_KEY);
            ENSURE_OR_GO_CLEANUP(param != NULL);

            magic_num = priv_key_data[priv_key_data_len - 3] | (priv_key_data[priv_key_data_len - 4] << 8) |
                        (priv_key_data[priv_key_data_len - 5] << 16) | (priv_key_data[priv_key_data_len - 6] << 24);

            if (magic_num != SIGNATURE_REFKEY_ID) // This is a not a reference key
            {
                sssProv_Print(LOG_DBG_ON,
                    "Key not handled in sssProvider (Not a ref "
                    "key). Fall back to default provider\n");
                status = kStatus_SSS_Fail;
                goto cleanup;
            }
            else {
                pStoreCtx->keyid =
                    priv_key_data[priv_key_data_len - 11] | (priv_key_data[priv_key_data_len - 12] << 8) |
                    (priv_key_data[priv_key_data_len - 13] << 16) | (priv_key_data[priv_key_data_len - 14] << 24);
                ENSURE_OR_GO_CLEANUP(pStoreCtx->keyid != 0);

                status = sss_key_object_init(&(pStoreCtx->object), &pStoreCtx->pProvCtx->p_ex_sss_boot_ctx->ks);
                ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

                status = sss_key_object_get_handle(&(pStoreCtx->object), kSSS_CipherType_EC_NIST_P, pStoreCtx->keyid);
                ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

                pStoreCtx->isEVPKey = 0;
            }
        }
        else {
            sssProv_Print(LOG_DBG_ON, "Key not handled in sssProvider. Fall back to default provider\n");
            status = kStatus_SSS_Fail;
            goto cleanup;
        }
    }

cleanup:
    if (priv_key_data != NULL) {
        OPENSSL_free(priv_key_data);
    }
    if (bn_priv_key != NULL) {
        BN_free(bn_priv_key);
    }
    if (keyType != NULL) {
        OPENSSL_free(keyType);
    }

    if (status != kStatus_SSS_Success) {
        return 0;
    }

    return 1;
}

static const OSSL_PARAM *sss_ec_keymgmt_import_types(int selection)
{
    static OSSL_PARAM importable_params[4] = {0};
    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);
    (void)(selection);
    importable_params[0] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY, 0, 0);
    importable_params[1] = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0);
    importable_params[2] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0);
    importable_params[3] = OSSL_PARAM_construct_end();
    return importable_params;
}
#endif /*SSS_ENABLE_EC_KEYMGMT_IMPORT_FUNC*/

static int sss_ec_keymgmt_export(void *keydata, int selection, OSSL_CALLBACK *param_cb, void *cbarg)
{
    sss_provider_store_obj_t *pStoreCtx  = (sss_provider_store_obj_t *)keydata;
    OSSL_PARAM params[8]                 = {0};
    uint8_t i                            = 0;
    uint8_t public_key[256]              = {0};
    size_t public_key_len                = sizeof(public_key);
    unsigned char privkey[66]            = {0}; /*max key bits 521 */
    size_t private_key_len               = sizeof(privkey);
    char group_name[32]                  = {0};
    int keylen_bits                      = 0;
    int index                            = 0;
    uint8_t magic_num[NX_MAGIC_NUM_SIZE] = NX_MAGIC_NUM;
    OSSL_PARAM params_tmp[2]             = {
        0,
    };

    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);

    if (pStoreCtx->isEVPKey == 1) {
        ENSURE_OR_GO_CLEANUP(pStoreCtx->pEVPPkey != NULL);

        if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) {
            params_tmp[0] =
                OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, &public_key[0], public_key_len);
            params_tmp[1] = OSSL_PARAM_construct_end();
            ENSURE_OR_GO_CLEANUP(EVP_PKEY_get_params(pStoreCtx->pEVPPkey, params_tmp) == 1);
            public_key_len = params_tmp[0].return_size;
            params[i++]    = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY, &public_key[0], public_key_len);
        }

        if (selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) {
            params_tmp[0] =
                OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, &group_name[0], sizeof(group_name));
            params_tmp[1] = OSSL_PARAM_construct_end();
            ENSURE_OR_GO_CLEANUP(EVP_PKEY_get_params(pStoreCtx->pEVPPkey, params_tmp) == 1);
            params[i++] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, &group_name[0], 0);
        }

        if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) {
            params_tmp[0] = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_PRIV_KEY, &privkey[0], sizeof(privkey));
            params_tmp[1] = OSSL_PARAM_construct_end();
            ENSURE_OR_GO_CLEANUP(EVP_PKEY_get_params(pStoreCtx->pEVPPkey, params_tmp) == 1);
            private_key_len = params_tmp[0].return_size;
            params[i++]     = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_PRIV_KEY, &privkey[0], private_key_len);
        }

        params[i++] = OSSL_PARAM_construct_end();
    }
    else {
        if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) {
            sss_nx_object_t *keyobj = (sss_nx_object_t *)&pStoreCtx->object;
            if (keyobj->cipherType == kSSS_CipherType_EC_NIST_P) {
                if (keyobj->pubKeyLen != 0) {
                    ENSURE_OR_GO_CLEANUP(keyobj->pubKeyLen > 26);
                    memcpy(public_key, keyobj->pubKey + 26, keyobj->pubKeyLen - 26);
                }
            }
            else if (keyobj->cipherType == kSSS_CipherType_EC_BRAINPOOL) {
                if (keyobj->pubKeyLen != 0) {
                    ENSURE_OR_GO_CLEANUP(keyobj->pubKeyLen > 27);
                    memcpy(public_key, keyobj->pubKey + 27, keyobj->pubKeyLen - 27);
                }
            }
            if (pStoreCtx->pProvCtx->pKeyGen == NULL) {
                params[i++] = OSSL_PARAM_construct_octet_string(
                    OSSL_PKEY_PARAM_PUB_KEY, pStoreCtx->pub_key, pStoreCtx->pub_key_len);
            }
            else {
                params[i++] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY, &public_key[0], 65);
            }
        }

        if (selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) {
            keylen_bits = pStoreCtx->key_len * 8;

            index = sss_type_key_map_index(pStoreCtx->object.cipherType, keylen_bits);
            ENSURE_OR_GO_CLEANUP(index != -1);
            params[i++] =
                OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, sss_type_key_map[index].curve_name, 0);
        }

        if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) {
            //create reference key
            ENSURE_OR_GO_CLEANUP(sizeof(privkey) >= pStoreCtx->key_len);
            ENSURE_OR_GO_CLEANUP(pStoreCtx->key_len > 0);
            privkey[pStoreCtx->key_len - 1] = 0x10;                            /* start Pattern */
            privkey[1]                      = 0x10;                            /* Indicate Private Key */
            privkey[2]                      = 0x00;                            /* Reserved*/
            memcpy(&privkey[2], magic_num, sizeof(magic_num));                 /* Magic Number */
            memcpy(&privkey[10], &pStoreCtx->keyid, sizeof(pStoreCtx->keyid)); /* key id Information */
            params[i++] = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_PRIV_KEY, &privkey[0], pStoreCtx->key_len);
        }

        params[i++] = OSSL_PARAM_construct_end();
    }

    return param_cb(params, cbarg);
cleanup:
    return 0;
}

static const OSSL_PARAM *sss_ec_keymgmt_export_types(int selection)
{
    static OSSL_PARAM exportable_params[3] = {0};
    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);
    (void)(selection);
    exportable_params[0] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY, 0, 0);
    exportable_params[1] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0);
    exportable_params[2] = OSSL_PARAM_construct_end();
    return exportable_params;
}

static void *sss_ec_keymgmt_gen_init(void *provctx, int selection, const OSSL_PARAM params[])
{
    sss_provider_context_t *sssProvCtx  = (sss_provider_context_t *)provctx;
    sss_provider_store_obj_t *pStoreCtx = NULL;

    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);

    (void)(params);
    (void)(selection);

    if ((pStoreCtx = OPENSSL_zalloc(sizeof(sss_provider_store_obj_t))) == NULL) {
        return NULL;
    }

    pStoreCtx->isEVPKey = 0;
    pStoreCtx->pProvCtx = provctx;
    if (sssProvCtx->pKeyGen == NULL) {
        sssProvCtx->pKeyGen = pStoreCtx;
    }
    return pStoreCtx;
}

static int sss_keymgmt_ec_gen_set_params(void *keydata, const OSSL_PARAM params[])
{
    sss_provider_store_obj_t *pStoreCtx = (sss_provider_store_obj_t *)keydata;
    const OSSL_PARAM *p;
    int ret           = 0;
    char grp_name[32] = {
        0,
    };
    char *pgrp_name              = &grp_name[0];
    char *grp_name_tmp           = NULL;
    char *keyId_str              = NULL;
    int index                    = 0;
    unsigned long int strtol_ret = 0;

    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);

    (void)(keydata);

    ENSURE_OR_GO_CLEANUP(params != NULL);
    ENSURE_OR_GO_CLEANUP(pStoreCtx != NULL);

    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_GROUP_NAME);
    ENSURE_OR_GO_CLEANUP(p != NULL);
    ENSURE_OR_GO_CLEANUP(OSSL_PARAM_get_utf8_string(p, &pgrp_name, sizeof(grp_name)));

    grp_name_tmp = OPENSSL_strdup(pgrp_name);
    ENSURE_OR_GO_CLEANUP(grp_name_tmp != NULL);

    keyId_str = strtok(grp_name_tmp, ":");
    keyId_str = strtok(NULL, ":");

    if (keyId_str == NULL) {
        sssProv_Print(LOG_DBG_ON, "No key id found. Default id will be used \n");
        pStoreCtx->keyid = SSS_DEFAULT_EC_KEY_ID;
    }
    else {
        strtol_ret = strtoul(keyId_str, NULL, 0);
        if ((strtol_ret > 0) && (strtol_ret < UINT32_MAX)) {
            pStoreCtx->keyid = strtol_ret;
        }
        else {
            goto cleanup;
        }
    }

    index = sss_get_key_len_cipher_type(grp_name, &pStoreCtx->object.cipherType, &pStoreCtx->key_len);
    ENSURE_OR_GO_CLEANUP(index != -1);

    ret = 1;
cleanup:

    if (grp_name_tmp != NULL) {
        OPENSSL_free(grp_name_tmp);
    }
    return ret;
}

static const OSSL_PARAM *sss_keymgmt_ec_gen_settable_params(void *keydata, void *vprovctx)
{
    static OSSL_PARAM settable[] = {OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0), OSSL_PARAM_END};
    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);
    (void)(keydata);
    (void)(vprovctx);

    return settable;
}

static void *sss_keymgmt_ec_gen(void *keydata, OSSL_CALLBACK *osslcb, void *cbarg)
{
    sss_status_t status                 = kStatus_SSS_Fail;
    sss_provider_store_obj_t *pStoreCtx = (sss_provider_store_obj_t *)keydata;
    uint32_t cipherType                 = 0;
    sss_nx_session_t *pSession          = NULL;
    int keyLen                          = 0;
    sss_provider_context_t *sssProvCtx  = (sss_provider_context_t *)pStoreCtx->pProvCtx;
    sss_provider_store_obj_t *tmp       = (sss_provider_store_obj_t *)sssProvCtx->pKeyGen;
    char *ec_curve                      = NULL;
    EVP_PKEY *key                       = NULL;
    OSSL_PARAM params[2];
    EVP_PKEY_CTX *gctx = NULL;

    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);

    (void)(osslcb);
    (void)(cbarg);

    ENSURE_OR_GO_CLEANUP(pStoreCtx != NULL);
    ENSURE_OR_GO_CLEANUP(tmp != NULL);

#ifndef SSS_ENABLE_NX_EC_KEY_GEN_WITH_NO_KEYID
    if (pStoreCtx->keyid == SSS_DEFAULT_EC_KEY_ID) {
        gctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", "provider!=nxp_prov");
        ENSURE_OR_GO_CLEANUP(gctx != NULL);

        if (1 != EVP_PKEY_keygen_init(gctx)) {
            EVP_PKEY_CTX_free(gctx);
            goto cleanup;
        }

        sss_prov_get_curve(pStoreCtx->object.cipherType, pStoreCtx->key_len, &ec_curve);
        if (ec_curve == NULL) {
            EVP_PKEY_CTX_free(gctx);
            goto cleanup;
        }

        params[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, ec_curve, 0);
        params[1] = OSSL_PARAM_construct_end();

        if (1 != EVP_PKEY_CTX_set_params(gctx, params)) {
            EVP_PKEY_CTX_free(gctx);
            goto cleanup;
        }

        sssProv_Print(LOG_FLOW_ON, "Generate ECC key on Host \n");

        if (EVP_PKEY_generate(gctx, &key) <= 0) {
            EVP_PKEY_CTX_free(gctx);
            goto cleanup;
        }
        pStoreCtx->pEVPPkey = key;
        pStoreCtx->isEVPKey = 1;
        status              = kStatus_SSS_Success;
        EVP_PKEY_CTX_free(gctx);
    }
    else {
#endif // SSS_ENABLE_NX_EC_KEY_GEN_WITH_NO_KEYID

        cipherType = pStoreCtx->object.cipherType;

        pSession = (sss_nx_session_t *)&pStoreCtx->pProvCtx->p_ex_sss_boot_ctx->session;

        status = sss_key_object_init(&pStoreCtx->object, &pStoreCtx->pProvCtx->p_ex_sss_boot_ctx->ks);
        ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

        keyLen = pStoreCtx->key_len * 8;

        status = sss_key_object_allocate_handle(
            &pStoreCtx->object, pStoreCtx->keyid, kSSS_KeyPart_Pair, cipherType, keyLen, kKeyObject_Mode_Persistent);
        ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

        sssProv_Print(
            LOG_FLOW_ON, "Generate ECC key inside Secure Authenticator with default policy (Sign enabled) \n");
        sssProv_Print(LOG_DBG_ON, "(At key id 0x%X from Secure Authenticator) \n", pStoreCtx->keyid);

        status =
            sss_key_store_generate_key(&pStoreCtx->pProvCtx->p_ex_sss_boot_ctx->ks, &pStoreCtx->object, keyLen, NULL);
        ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

        gctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", "provider!=nxp_prov");
        if (gctx == NULL) {
            status = kStatus_SSS_Fail;
            goto cleanup;
        }

        if (1 != EVP_PKEY_keygen_init(gctx)) {
            status = kStatus_SSS_Fail;
            EVP_PKEY_CTX_free(gctx);
            goto cleanup;
        }

        sss_prov_get_curve(pStoreCtx->object.cipherType, pStoreCtx->key_len, &ec_curve);
        if (ec_curve == NULL) {
            status = kStatus_SSS_Fail;
            EVP_PKEY_CTX_free(gctx);
            goto cleanup;
        }

        params[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, ec_curve, 0);
        params[1] = OSSL_PARAM_construct_end();

        if (1 != EVP_PKEY_CTX_set_params(gctx, params)) {
            status = kStatus_SSS_Fail;
            EVP_PKEY_CTX_free(gctx);
            goto cleanup;
        }
        // Generating a key on host to set the params of pStoreCtx->pEVPPkey.
        if (EVP_PKEY_generate(gctx, &key) <= 0) {
            status = kStatus_SSS_Fail;
            EVP_PKEY_CTX_free(gctx);
            goto cleanup;
        }
        pStoreCtx->pEVPPkey = key;
        status              = kStatus_SSS_Success;
        EVP_PKEY_CTX_free(gctx);

#ifndef SSS_ENABLE_NX_EC_KEY_GEN_WITH_NO_KEYID
    }
#endif // SSS_ENABLE_NX_EC_KEY_GEN_WITH_NO_KEYID

cleanup:
    if (status == kStatus_SSS_Fail) {
        return NULL;
    }
    return keydata;
}

static void sss_keymgmt_gen_cleanup(void *keydata)
{
    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);
    (void)(keydata);
    return;
}

static int sss_ec_keymgmt_gen_set_template(void *genctx, void *keydata)
{
    sss_provider_store_obj_t *pStoreCtx = (sss_provider_store_obj_t *)keydata;
    sss_provider_store_obj_t *gStoreCtx = (sss_provider_store_obj_t *)genctx;
    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);

    gStoreCtx->object  = pStoreCtx->object;
    gStoreCtx->keyid   = pStoreCtx->keyid;
    gStoreCtx->key_len = pStoreCtx->key_len;
    genctx             = gStoreCtx;

    return 1;
}

static void *sss_keymgmt_ec_dup(const void *keydata, int selection)
{
    sss_provider_store_obj_t *pStoreCtx   = (sss_provider_store_obj_t *)keydata;
    sss_provider_store_obj_t *outStoreCtx = NULL;

    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);

    (void)(selection);

    outStoreCtx = OPENSSL_zalloc(sizeof(sss_provider_store_obj_t));
    if (outStoreCtx == NULL) {
        return NULL;
    }

    if (pStoreCtx != NULL) {
        outStoreCtx->keyid        = pStoreCtx->keyid;
        outStoreCtx->key_len      = pStoreCtx->key_len;
        outStoreCtx->maxSize      = pStoreCtx->maxSize;
        outStoreCtx->isPrivateKey = pStoreCtx->isPrivateKey;
        outStoreCtx->isEVPKey     = pStoreCtx->isEVPKey;

        memcpy(&(outStoreCtx->object), &(pStoreCtx->object), sizeof(pStoreCtx->object));
        outStoreCtx->pProvCtx = pStoreCtx->pProvCtx;

        if (pStoreCtx->pEVPPkey != NULL) {
            outStoreCtx->pEVPPkey = EVP_PKEY_dup(pStoreCtx->pEVPPkey);
        }

        return outStoreCtx;
    }
    else {
        OPENSSL_free(outStoreCtx);
        return NULL;
    }
}

const OSSL_DISPATCH sss_ec_keymgmt_functions[] = {{OSSL_FUNC_KEYMGMT_LOAD, (void (*)(void))sss_ec_keymgmt_load},
#ifdef SSS_ENABLE_EC_KEYMGMT_IMPORT_FUNC
    {OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))sss_ec_keymgmt_new},
#endif /*SSS_ENABLE_EC_KEYMGMT_IMPORT_FUNC*/
    {OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))sss_ec_keymgmt_free},
    {OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*)(void))sss_ec_keymgmt_get_params},
    {OSSL_FUNC_KEYMGMT_GEN_SET_TEMPLATE, (void (*)(void))sss_ec_keymgmt_gen_set_template},
    {OSSL_FUNC_KEYMGMT_SET_PARAMS, (void (*)(void))sss_ec_keymgmt_set_params},
    {OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (void (*)(void))sss_ec_keymgmt_gettable_params},
    {OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS, (void (*)(void))sss_ec_keymgmt_settable_params},
    {OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME, (void (*)(void))sss_ec_keymgmt_query_operation_name},
    {OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))sss_ec_keymgmt_has},
#ifdef SSS_ENABLE_EC_KEYMGMT_IMPORT_FUNC
    {OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))sss_ec_keymgmt_import},
    {OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void))sss_ec_keymgmt_import_types},
#endif /*SSS_ENABLE_EC_KEYMGMT_IMPORT_FUNC*/
    {OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))sss_ec_keymgmt_export},
    {OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void (*)(void))sss_ec_keymgmt_export_types},
    /* To generate the key in NX */
    {OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void))sss_ec_keymgmt_gen_init},
    {OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS, (void (*)(void))sss_keymgmt_ec_gen_set_params},
    {OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS, (void (*)(void))sss_keymgmt_ec_gen_settable_params},
    {OSSL_FUNC_KEYMGMT_GEN, (void (*)(void))sss_keymgmt_ec_gen},
    {OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (void (*)(void))sss_keymgmt_gen_cleanup},
    {OSSL_FUNC_KEYMGMT_DUP, (void (*)(void))sss_keymgmt_ec_dup},
    {0, NULL}};
