/*
 *
 * Copyright 2018-2020, 2022-2023 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 */

/* Key store in PC : For testing */

/* ************************************************************************** */
/* Includes                                                                   */
/* ************************************************************************** */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "fsl_sss_keyid_map.h"
#include "fsl_sss_openssl_apis.h"
#include "nxEnsure.h"
#include "nxLog_msg.h"

#if SSS_HAVE_HOSTCRYPTO_OPENSSL
#include <openssl/evp.h>

/* ************************************************************************** */
/* Local Defines                                                              */
/* ************************************************************************** */

/* File allocation table file name */
#define FAT_FILENAME "sss_fat.bin"
#define MAX_FILE_NAME_SIZE 255

/* ************************************************************************** */
/* Structures and Typedefs                                                    */
/* ************************************************************************** */

/* ************************************************************************** */
/* Global Variables                                                           */
/* ************************************************************************** */

/* ************************************************************************** */
/* Static function declarations                                               */
/* ************************************************************************** */

/* ************************************************************************** */
/* Public Functions                                                           */
/* ************************************************************************** */

sss_status_t ks_openssl_load_key(sss_openssl_object_t *sss_key, keyStoreTable_t *keystore_shadow, uint32_t extKeyId)
{
    sss_status_t retval                    = kStatus_SSS_Fail;
    char file_name[MAX_FILE_NAME_SIZE]     = {0};
    FILE *fp                               = NULL;
    size_t size                            = 0;
    uint32_t i                             = 0;
    keyIdAndTypeIndexLookup_t *shadowEntry = NULL;
    EVP_PKEY *pkey                         = NULL;
    int evp_pkey_bits                      = 0;

    ENSURE_OR_GO_EXIT(NULL != sss_key)
    ENSURE_OR_GO_EXIT(NULL != sss_key->keyStore)
    ENSURE_OR_GO_EXIT(NULL != sss_key->keyStore->session)
    ENSURE_OR_GO_EXIT(NULL != keystore_shadow)

    for (i = 0; i < sss_key->keyStore->max_object_count; i++) {
        if (keystore_shadow->entries[i].extKeyId == extKeyId) {
            shadowEntry         = &keystore_shadow->entries[i];
            sss_key->keyId      = shadowEntry->extKeyId;
            sss_key->cipherType = shadowEntry->cipherType;
            sss_key->objectType = (shadowEntry->keyPart & 0x0F);
            ks_sw_getKeyFileName(
                file_name, sizeof(file_name), (const sss_object_t *)sss_key, sss_key->keyStore->session->szRootPath);
            retval = kStatus_SSS_Success;
            break;
        }
    }
    ENSURE_OR_GO_EXIT(kStatus_SSS_Success == retval)

    fp = fopen(file_name, "rb");
    if (NULL == fp) {
        LOG_E("Can not open file");
        retval = kStatus_SSS_Fail;
        goto exit;
    }

    /*Buffer: max RSA key*/
    uint8_t keyBuf[3000]   = {0};
    const uint8_t *buf_ptr = keyBuf;
    long signed_size       = 0;

    if (0 != fseek(fp, 0, SEEK_END)) {
        LOG_E("Error in fseek, hence closing the file");
        retval = kStatus_SSS_Fail;
        if (0 != fclose(fp)) {
            LOG_E("Error in fclose");
        }
        goto exit;
    }

    signed_size = ftell(fp);
    if (signed_size < 0) {
        LOG_E("Error in ftell, hence closing the file");
        retval = kStatus_SSS_Fail;
        if (0 != fclose(fp)) {
            LOG_E("Error in fclose");
        }
        goto exit;
    }

    size = (size_t)signed_size;
    if (0 != fseek(fp, 0, SEEK_END)) {
        LOG_E("Error in fseek, hence closing the file");
        retval = kStatus_SSS_Fail;
        if (0 != fclose(fp)) {
            LOG_E("Error in fclose");
        }
        goto exit;
    }

    if (0 == fread(keyBuf, size, 1, fp)) {
        LOG_E("Error in fread, hence closing the file");
        retval = kStatus_SSS_Fail;
    }

    if (0 != fclose(fp)) {
        LOG_E("Error in fclose");
        goto exit;
    }

    retval = sss_openssl_key_object_allocate(sss_key,
        shadowEntry->extKeyId,
        (shadowEntry->keyPart & 0x0F),
        shadowEntry->cipherType,
        size,
        kKeyObject_Mode_Persistent);
    ENSURE_OR_GO_EXIT(kStatus_SSS_Success == retval)

    switch (sss_key->cipherType) {
    case kSSS_CipherType_EC_NIST_P:
    case kSSS_CipherType_EC_BRAINPOOL: {
        if (sss_key->contents != NULL) {
            EVP_PKEY_free((EVP_PKEY *)sss_key->contents);
        }
        if (sss_key->objectType == kSSS_KeyPart_Public) {
            pkey = d2i_PublicKey(EVP_PKEY_EC, NULL, &buf_ptr, (long)size);
        }
        else {
            pkey = d2i_AutoPrivateKey(NULL, &buf_ptr, (long)size);
        }

        if (pkey == NULL) {
            retval = kStatus_SSS_Fail;
        }
        else {
            sss_key->contents = (void *)pkey;
        }
        evp_pkey_bits = EVP_PKEY_bits(pkey);
        if (evp_pkey_bits < 0) {
            retval = kStatus_SSS_Fail;
            goto exit;
        }
        sss_key->keyBitLen = evp_pkey_bits;
    } break;
    default: {
        retval = sss_openssl_key_store_set_key(sss_key->keyStore, sss_key, keyBuf, size, size * 8, NULL, 0);
    } break;
    }

exit:
    return retval;
}

#ifdef _MSC_VER
#define UNLINK _unlink
#else
#define UNLINK unlink
#endif

sss_status_t ks_openssl_remove_key(const sss_openssl_object_t *sss_key)
{
    sss_status_t retval                = kStatus_SSS_Fail;
    char file_name[MAX_FILE_NAME_SIZE] = {0};

    ENSURE_OR_GO_EXIT(NULL != sss_key)
    ENSURE_OR_GO_EXIT(NULL != sss_key->keyStore)
    ENSURE_OR_GO_EXIT(NULL != sss_key->keyStore->session)

    ks_sw_getKeyFileName(
        file_name, sizeof(file_name), (const sss_object_t *)sss_key, sss_key->keyStore->session->szRootPath);
    if (0 == UNLINK(file_name)) {
        retval = kStatus_SSS_Success;
    }

exit:
    return retval;
}

/* ************************************************************************** */
/* Private Functions                                                          */
/* ************************************************************************** */

#endif /* OpenSSL */
