/*
 *
 * Copyright 2018-2020, 2022-2024 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 */

/* Key store in PC : For testing */

/* ************************************************************************** */
/* Includes                                                                   */
/* ************************************************************************** */

#if defined(SSS_USE_FTR_FILE)
#include "fsl_sss_ftr.h"
#else
#include "fsl_sss_ftr_default.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "fsl_sss_keyid_map.h"
#if SSS_HAVE_HOSTCRYPTO_MBEDTLS
#include "fsl_sss_mbedtls_apis.h"
#endif
#if SSS_HAVE_HOSTCRYPTO_OPENSSL
#include "fsl_sss_openssl_types.h"
#endif
#include "nxEnsure.h"
#include "nxLog_msg.h"
#include "sm_types.h"

#if (defined(MBEDTLS_FS_IO) && (defined(SSS_HAVE_HOST_PCWINDOWS) && (SSS_HAVE_HOST_PCWINDOWS)) || \
     (defined(SSS_HAVE_HOST_PCLINUX64) && (SSS_HAVE_HOST_PCLINUX64)) ||                           \
     (defined(SSS_HAVE_HOST_RASPBIAN) && (SSS_HAVE_HOST_RASPBIAN))) ||                            \
    defined(SSS_HAVE_HOSTCRYPTO_OPENSSL) && (SSS_HAVE_HOSTCRYPTO_OPENSSL)

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

/* For the key sss_key, what will the file name look like */
void ks_sw_getKeyFileName(
    char *const file_name, const size_t size, const sss_object_t *sss_key, const char *root_folder)
{
    ENSURE_OR_GO_EXIT(NULL != file_name)
    ENSURE_OR_GO_EXIT(NULL != sss_key)
    ENSURE_OR_GO_EXIT(NULL != root_folder)

    uint32_t keyId      = sss_key->keyId;
    uint32_t keyType    = sss_key->objectType;
    uint32_t cipherType = sss_key->cipherType;
    if (SNPRINTF(file_name, size - 1, "%s/sss_%08X_%04d_%04d.bin", root_folder, keyId, keyType, cipherType) < 0) {
        LOG_E("snprintf error");
        goto exit;
    }

exit:
    return;
}

void ks_sw_fat_allocate(keyStoreTable_t **keystore_shadow)
{
    keyStoreTable_t *pKeyStoreShadow           = NULL;
    keyIdAndTypeIndexLookup_t *ppLookupEntries = NULL;

    ENSURE_OR_GO_EXIT(NULL != keystore_shadow)

    pKeyStoreShadow = SSS_MALLOC(sizeof(keyStoreTable_t));
    if (pKeyStoreShadow == NULL) {
        LOG_E("Error in pKeyStoreShadow mem allocation");
        goto exit;
    }

    ppLookupEntries = SSS_MALLOC(KS_N_ENTIRES * sizeof(keyIdAndTypeIndexLookup_t));
    if (ppLookupEntries == NULL) {
        LOG_E("Error in ppLookupEntries mem allocation");
        SSS_FREE(pKeyStoreShadow);
        goto exit;
    }

    memset(ppLookupEntries, 0, (KS_N_ENTIRES * sizeof(keyIdAndTypeIndexLookup_t)));
    ks_common_init_fat(pKeyStoreShadow, ppLookupEntries, KS_N_ENTIRES);
    *keystore_shadow = pKeyStoreShadow;

exit:
    return;
}

void ks_sw_fat_free(keyStoreTable_t *keystore_shadow)
{
    if (NULL != keystore_shadow) {
        if (NULL != keystore_shadow->entries) {
            SSS_FREE(keystore_shadow->entries);
        }
        memset(keystore_shadow, 0, sizeof(*keystore_shadow));
        SSS_FREE(keystore_shadow);
    }
}

static void ks_file_unlink(const char *szRootPath)
{
    char file_name[MAX_FILE_NAME_SIZE] = {0};
    if (SNPRINTF(file_name, sizeof(file_name), "%s/" FAT_FILENAME, szRootPath) < 0) {
        LOG_E("snprintf error");
        goto exit;
    }
#ifdef _WIN32
    _unlink(file_name);
#else
    unlink(file_name);
#endif

exit:
    return;
}

void ks_sw_fat_remove(const char *szRootPath)
{
    char file_name[MAX_FILE_NAME_SIZE] = {0};
    FILE *fp                           = NULL;

    ENSURE_OR_GO_EXIT(NULL != szRootPath)
    if (SNPRINTF(file_name, sizeof(file_name), "%s/" FAT_FILENAME, szRootPath) < 0) {
        LOG_E("snprintf error");
        goto exit;
    }

    fp = fopen(file_name, "rb");
    if (NULL == fp) {
        LOG_I("No %s to delete", file_name);
        goto exit;
    }

    if (0 != fclose(fp)) {
        LOG_E(" fclose error");
    }

    ks_file_unlink(szRootPath);

exit:
    return;
}

static sss_status_t ks_sw_fat_update(keyStoreTable_t *keystore_shadow, const char *szRootPath)
{
    sss_status_t retval                = kStatus_SSS_Fail;
    char file_name[MAX_FILE_NAME_SIZE] = {
        0,
    };
    FILE *fp   = NULL;
    size_t ret = 0;
    int fret   = -1;

    ENSURE_OR_GO_EXIT(NULL != keystore_shadow)
    ENSURE_OR_GO_EXIT(NULL != szRootPath)

    if (SNPRINTF(file_name, sizeof(file_name), "%s/" FAT_FILENAME, szRootPath) < 0) {
        LOG_E("snprintf error");
        goto exit;
    }
    fp = fopen(file_name, "wb+");
    if (fp == NULL) {
        LOG_E("Can not open the file");
        goto exit;
    }

    fret = fseek(fp, 0, SEEK_SET);
    if (fret != 0) {
        LOG_E("fseek error, hence calling fclose");
        fret = fclose(fp);
        if (fret != 0) {
            LOG_E("fclose error");
        }
        goto exit;
    }
    ret = fwrite(keystore_shadow, sizeof(*keystore_shadow), 1, fp);
    if (ret != 1) {
        LOG_E("fwrite error, hence calling fclose");
        fret = fclose(fp);
        if (fret != 0) {
            LOG_E("fclose error");
        }
        goto exit;
    }
    ret = fwrite(keystore_shadow->entries, sizeof(*keystore_shadow->entries) * keystore_shadow->maxEntries, 1, fp);
    if (ret != 1) {
        LOG_E("fwrite error, hence calling fclose");
        fret = fclose(fp);
        if (fret != 0) {
            LOG_E("fclose error");
        }
        goto exit;
    }
    fret = fclose(fp);
    if (fret != 0) {
        LOG_E("fclose error");
        goto exit;
    }

    retval = kStatus_SSS_Success;

exit:
    return retval;
}

#if defined(MBEDTLS_FS_IO)
sss_status_t ks_mbedtls_fat_update(sss_mbedtls_key_store_t *keyStore)
{
    if (NULL == keyStore || NULL == keyStore->session) {
        return kStatus_SSS_Fail;
    }
    return ks_sw_fat_update(keyStore->keystore_shadow, keyStore->session->szRootPath);
}
#endif

#if SSS_HAVE_HOSTCRYPTO_OPENSSL
sss_status_t ks_openssl_fat_update(sss_openssl_key_store_t *keyStore)
{
    if (NULL == keyStore || NULL == keyStore->session) {
        return kStatus_SSS_Fail;
    }
    return ks_sw_fat_update(keyStore->keystore_shadow, keyStore->session->szRootPath);
}
#endif

sss_status_t ks_sw_fat_load(const char *szRootPath, keyStoreTable_t *pKeystore_shadow)
{
    sss_status_t retval                = kStatus_SSS_Fail;
    char file_name[MAX_FILE_NAME_SIZE] = {0};
    FILE *fp                           = NULL;
    size_t ret                         = 0;
    keyStoreTable_t fileShadow         = {0};

    ENSURE_OR_GO_EXIT(NULL != pKeystore_shadow);
    ENSURE_OR_GO_EXIT(NULL != szRootPath);
    if (SNPRINTF(file_name, sizeof(file_name), "%s/" FAT_FILENAME, szRootPath) < 0) {
        LOG_E("snprintf error");
        goto exit;
    }
    fp = fopen(file_name, "rb");
    if (fp == NULL) {
        /* File did not exist, and it's OK most of the time
         * because the test code comes through this path.
         * hence return fail, but do not log any message. */
        goto exit;
    }

    ret = fread(&fileShadow, 1, sizeof(fileShadow), fp);
    if (ret > 0 && fileShadow.maxEntries == pKeystore_shadow->maxEntries &&
        fileShadow.magic == pKeystore_shadow->magic && fileShadow.version == pKeystore_shadow->version) {
        ret =
            fread(pKeystore_shadow->entries, 1, sizeof(*pKeystore_shadow->entries) * pKeystore_shadow->maxEntries, fp);
        if (0 == ret) {
            LOG_E("Error in fread");
            goto exit;
        }
    }
    else {
        LOG_E("ERROR! keystore_shadow != pKeystore_shadow");
    }

    retval = kStatus_SSS_Success;

exit:
    if (fp != NULL) {
        if (0 != fclose(fp)) {
            LOG_E("Error in fclose");
        }
    }
    return retval;
}

#if defined(MBEDTLS_FS_IO)
sss_status_t ks_mbedtls_load_key(sss_mbedtls_object_t *sss_key, keyStoreTable_t *keystore_shadow, uint32_t extKeyId)
{
    sss_status_t retval                = kStatus_SSS_Fail;
    char file_name[MAX_FILE_NAME_SIZE] = {0};
    FILE *fp                           = NULL;
    int ret                            = -1;
    size_t size = 0, key_read_size = 0;
    uint32_t i                             = 0;
    keyIdAndTypeIndexLookup_t *shadowEntry = NULL;
    uint8_t *keyBuf                        = NULL;
    int signed_val                         = 0;

    ENSURE_OR_GO_EXIT(NULL != sss_key)
    ENSURE_OR_GO_EXIT(NULL != sss_key->keyStore)
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
    if (fp == NULL) {
        LOG_E("Can not open file");
        retval = kStatus_SSS_Fail;
        goto exit;
    }
    /* Buffer to hold max RSA Key*/
    if (0 != fseek(fp, 0, SEEK_END)) {
        LOG_E("fseek failed, hence closing the file");
        retval = kStatus_SSS_Fail;
        if (0 != fclose(fp)) {
            LOG_E("Error in fclose");
        }
        goto exit;
    }

    signed_val = ftell(fp);
    if (signed_val < 0) {
        LOG_E("File does not contain any data");
        retval = kStatus_SSS_Fail;
        ret    = fclose(fp);
        if (0 != ret) {
            LOG_E("Error in fclose");
        }
        goto exit;
    }

    size = (size_t)signed_val;
    if (fseek(fp, 0, SEEK_SET)) {
        LOG_E("Error in fseek, hence closing the file");
        ret = fclose(fp);
        if (0 != ret) {
            LOG_E("fclose error");
        }
        goto exit;
    }

    keyBuf = SSS_CALLOC(1, size);
    if (keyBuf == NULL) {
        ret = fclose(fp);
        if (0 != ret) {
            LOG_E("fclose error");
        }
        goto exit;
    }

    key_read_size = fread(keyBuf, size, 1, fp);
    if (key_read_size != 1) {
        LOG_E("fread failed, hence calling fclose");
        retval = kStatus_SSS_Fail;
        ret    = fclose(fp);
        if (0 != ret) {
            LOG_E("fclose failed");
        }
        if (keyBuf != NULL) {
            SSS_FREE(keyBuf);
        }
        goto exit;
    }

    ret = fclose(fp);
    if (0 != ret) {
        LOG_E("Error in fclose");
        if (keyBuf != NULL) {
            SSS_FREE(keyBuf);
        }
        goto exit;
    }

    retval = ks_mbedtls_key_object_create(sss_key,
        shadowEntry->extKeyId,
        (shadowEntry->keyPart & 0x0F),
        shadowEntry->cipherType,
        size,
        kKeyObject_Mode_Persistent);
    if (kStatus_SSS_Success != retval) {
        if (keyBuf != NULL) {
            SSS_FREE(keyBuf);
        }
        goto exit;
    }

    retval = sss_mbedtls_key_store_set_key(sss_key->keyStore, sss_key, keyBuf, size, size * 8 /* FIXME */, NULL, 0);

    if (keyBuf != NULL) {
        SSS_FREE(keyBuf);
    }

exit:
    return retval;
}

#ifdef _MSC_VER
#define UNLINK _unlink
#else
#define UNLINK unlink
#endif

sss_status_t ks_mbedtls_remove_key(const sss_mbedtls_object_t *sss_key)
{
    sss_status_t retval                = kStatus_SSS_Fail;
    char file_name[MAX_FILE_NAME_SIZE] = {0};

    ENSURE_OR_GO_EXIT(NULL != sss_key)
    ENSURE_OR_GO_EXIT(NULL != sss_key->keyStore)
    ENSURE_OR_GO_EXIT(NULL != sss_key->keyStore->session)

    ks_sw_getKeyFileName(
        file_name, sizeof(file_name), (const sss_object_t *)sss_key, sss_key->keyStore->session->szRootPath);
    if (0 != UNLINK(file_name)) {
        goto exit;
    }

    retval = kStatus_SSS_Success;

exit:
    return retval;
}
#endif

/* ************************************************************************** */
/* Private Functions                                                          */
/* ************************************************************************** */

#endif /* MBEDTLS_FS_IO */
