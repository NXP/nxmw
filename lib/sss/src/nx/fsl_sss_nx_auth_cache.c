/*
 *
 * Copyright 2022-2024 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 */

/* *****************************************************************************************************************
* Includes
* ***************************************************************************************************************** */

#if defined(SSS_USE_FTR_FILE)
#include "fsl_sss_ftr.h"
#else
#include "fsl_sss_ftr_default.h"
#endif

#if SSS_HAVE_NX_TYPE

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <limits.h>
#include "nxEnsure.h"
#include "nxLog_msg.h"
#include "fsl_sss_nx_auth_types.h"

#ifdef EX_SSS_SIGMA_I_CERT_INCLUDE_DIR

#if defined(_MSC_VER)
#define OS_PATH_SEPARATOR "\\"
#else
#define OS_PATH_SEPARATOR "/"
#endif

bool ex_sss_nx_dir_exists(const char *pathname);
sss_status_t ex_sss_write_file_to_fs(const char *fileName, uint8_t *certBuf, size_t certLen);
sss_status_t ex_sss_read_file_from_fs(char *fileName, uint8_t *buffer, size_t *bufferLen);

sss_status_t ex_sss_nx_read_cache_file(char *fileName, uint8_t *buffer, size_t *bufferLen)
{
    sss_status_t status                                                        = kStatus_SSS_Fail;
    int ret                                                                    = -1;
    char fullPathFileName[EX_MAX_INCLUDE_DIR_LENGTH + EX_MAX_EXTRA_DIR_LENGTH] = {0};
    char *cache_path_env                                                       = NULL;

    if ((fileName == NULL) || (buffer == NULL) || (bufferLen == NULL)) {
        LOG_E("Load cache file with invalid parameters");
        goto exit;
    }
    ENSURE_OR_GO_EXIT(strlen(fileName) < EX_MAX_EXTRA_DIR_LENGTH);

    memset(fullPathFileName, 0, sizeof(fullPathFileName));

#if defined(_MSC_VER)
    size_t sz = 0;
    _dupenv_s(&cache_path_env, &sz, EX_SSS_SIGMA_I_CERT_PATH_ENV_VAR);
#else
    cache_path_env = getenv(EX_SSS_SIGMA_I_CERT_PATH_ENV_VAR);
#endif //_MSC_VER

    if (cache_path_env != NULL) {
        ENSURE_OR_GO_EXIT(strlen(cache_path_env) < EX_MAX_INCLUDE_DIR_LENGTH);
        ret = sprintf(fullPathFileName,
            "%s%s%s%s%s",
            cache_path_env,
            OS_PATH_SEPARATOR,
            "cert_cache",
            OS_PATH_SEPARATOR,
            fileName);
        ENSURE_OR_GO_EXIT(ret >= 0);

        LOG_D("Using cache file from:'%s' (ENV=%s)", fullPathFileName, EX_SSS_SIGMA_I_CERT_PATH_ENV_VAR);

        // Get cache from file
        status = ex_sss_read_file_from_fs(fullPathFileName, buffer, bufferLen);

#if defined(_MSC_VER)
        free(cache_path_env);
#endif //_MSC_VER
    }
    else if (ex_sss_nx_dir_exists(EX_SSS_SIGMA_I_CERT_INCLUDE_DIR) == true) {
        // Get file file from default path
        ret = sprintf(fullPathFileName, "%s%s", EX_SSS_SIGMA_I_CACHE_FILE_DIR, fileName);
        ENSURE_OR_GO_EXIT(ret >= 0);

        LOG_D("Using cache file from:'%s' (Default path). ", fullPathFileName);
        status = ex_sss_read_file_from_fs(fullPathFileName, buffer, bufferLen);
    }

exit:
    if ((status != kStatus_SSS_Success) && (bufferLen != NULL)) {
        *bufferLen = 0;
    }

    return status;
}

sss_status_t ex_sss_nx_write_cache_file(char *fileName, uint8_t *buffer, size_t bufferLen)
{
    sss_status_t status                                                        = kStatus_SSS_Fail;
    int ret                                                                    = -1;
    char fullPathFileName[EX_MAX_INCLUDE_DIR_LENGTH + EX_MAX_EXTRA_DIR_LENGTH] = {0};
    char *cache_path_env                                                       = NULL;

    if ((fileName == NULL) || (buffer == NULL)) {
        LOG_E("Load cache file with invalid parameters");
        goto exit;
    }
    ENSURE_OR_GO_EXIT(strlen(fileName) < EX_MAX_EXTRA_DIR_LENGTH);

    memset(fullPathFileName, 0, sizeof(fullPathFileName));

#if defined(_MSC_VER)
    size_t sz = 0;
    _dupenv_s(&cache_path_env, &sz, EX_SSS_SIGMA_I_CERT_PATH_ENV_VAR);
#else
    cache_path_env = getenv(EX_SSS_SIGMA_I_CERT_PATH_ENV_VAR);
#endif //_MSC_VER

    if (cache_path_env != NULL) {
        ENSURE_OR_GO_EXIT(strlen(cache_path_env) < EX_MAX_INCLUDE_DIR_LENGTH);
        ret = sprintf(fullPathFileName,
            "%s%s%s%s%s",
            cache_path_env,
            OS_PATH_SEPARATOR,
            "cert_cache",
            OS_PATH_SEPARATOR,
            fileName);
        ENSURE_OR_GO_EXIT(ret >= 0);

        LOG_D("Using cache file from:'%s' (ENV=%s)", fullPathFileName, EX_SSS_SIGMA_I_CERT_PATH_ENV_VAR);

        // Write data to file
        status = ex_sss_write_file_to_fs(fullPathFileName, buffer, bufferLen);

#if defined(_MSC_VER)
        free(cache_path_env);
#endif //_MSC_VER
    }
    else {
        // Write file file to default path
        ret = sprintf(fullPathFileName, "%s%s", EX_SSS_SIGMA_I_CACHE_FILE_DIR, fileName);
        ENSURE_OR_GO_EXIT(ret >= 0);

        LOG_D("Using cache file from:'%s' (Default path). ", fullPathFileName);
        status = ex_sss_write_file_to_fs(fullPathFileName, buffer, bufferLen);
    }

exit:

    return status;
}

/**
 * @brief         Find matching item in cert hash.
 *
 *                Go through host cert hash and looking for valid item
 *                with correct cert hash and.
 *
 * @param         pCertHashBuf          Cert hash buffer.
 * @param         certHashBufLen        Cert hash buffer length.
 * @param[out]    found                 Searching result, the item number.
 *
 * @return        Status of searching.
 */
sss_status_t ex_find_hash_in_cache(uint8_t *pCertHashBuf, size_t certHashBufLen, int *found)
{
    sss_status_t status                                                = kStatus_SSS_Fail;
    int i                                                              = -1;
    int ret                                                            = -1;
    char filename[EX_MAX_INCLUDE_DIR_LENGTH + EX_MAX_EXTRA_DIR_LENGTH] = {0};
    uint8_t certBuf[NX_SHA256_BYTE_LEN]                                = {0};
    size_t certBufLen                                                  = 0;

    ENSURE_OR_GO_EXIT(pCertHashBuf != NULL);
    ENSURE_OR_GO_EXIT(found != NULL);
    ENSURE_OR_GO_EXIT(certHashBufLen == NX_SHA256_BYTE_LEN);

    *found = NX_LEAF_CERT_CACHE_ITEM_NA;

    for (i = 0; i < NX_LEAF_CERT_CACHE_MAX; i++) {
        status = kStatus_SSS_Fail;

        // Load device CA cache file.
        memset(filename, 0, sizeof(filename));
        ret = sprintf(filename, "%s%d.hex", EX_DEVICE_CACHE_HASH_FILE_PREFIX, i);
        ENSURE_OR_GO_EXIT(ret >= 0);

        memset(certBuf, 0, NX_SHA256_BYTE_LEN);
        certBufLen = NX_SHA256_BYTE_LEN;

        status = ex_sss_nx_read_cache_file(filename, certBuf, &certBufLen);
        if (status == kStatus_SSS_Success) {
            if ((certBufLen == certHashBufLen) && (memcmp(certBuf, pCertHashBuf, certHashBufLen) == 0)) {
                // Find matching cache item
                *found = i;
                break;
            }
        }
    }
    status = kStatus_SSS_Success;

exit:
    return status;
}

/**
 * @brief         Get public key in cert hash.
 *
 *                Get public key in cert hash.
 *
 * @param[in]     index                 Cert hash buffer index.
 * @param[out]    pPublicKeyBuf         Cert hash buffer.
 * @param[out]    pPublicKeyBufLen      Cert hash buffer length.
 *
 * @return        Status of searching.
 */
sss_status_t ex_get_pk_from_cache(int index, uint8_t *pPublicKeyBuf, size_t *pPublicKeyBufLen)
{
    sss_status_t status                                                = kStatus_SSS_Fail;
    int ret                                                            = -1;
    char filename[EX_MAX_INCLUDE_DIR_LENGTH + EX_MAX_EXTRA_DIR_LENGTH] = {0};
    uint8_t pkBuf[NX_PUBLIC_KEY_BUFFER_SIZE]                           = {0};
    size_t pkBufLen                                                    = 0;

    ENSURE_OR_GO_EXIT(pPublicKeyBuf != NULL);
    ENSURE_OR_GO_EXIT(pPublicKeyBufLen != NULL);
    ENSURE_OR_GO_EXIT(*pPublicKeyBufLen >= NX_PUBLIC_KEY_BUFFER_SIZE);
    ENSURE_OR_GO_EXIT((index >= 0) && (index < NX_LEAF_CERT_CACHE_MAX));

    // Load device public key cache file.
    memset(filename, 0, sizeof(filename));
    ret = sprintf(filename, "%s%d.hex", EX_DEVICE_CACHE_PUBKEY_FILE_PREFIX, index);
    ENSURE_OR_GO_EXIT(ret >= 0);

    memset(pkBuf, 0, NX_PUBLIC_KEY_BUFFER_SIZE);
    pkBufLen = NX_PUBLIC_KEY_BUFFER_SIZE;

    status = ex_sss_nx_read_cache_file(filename, pkBuf, &pkBufLen);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    memcpy(pPublicKeyBuf, pkBuf, pkBufLen);
    *pPublicKeyBufLen = pkBufLen;

    status = kStatus_SSS_Success;

exit:
    return status;
}

/**
 * @brief         Insert leaf cert hash and pulbic key into cache.
 *
 *                Found an empty slot and insert hash-signature-public key
 *
 * @param         pCertHashBuf          Cert Hash.
 * @param         certHashBufLen        Cert Hash Length.
 * @param         publicKey             Public Key.
 * @param         publicKeyLen          Public Key Length.
 *
 * @return        Status of insert.
 */
sss_status_t ex_insert_hash_pk_to_cache(
    uint8_t *pCertHashBuf, size_t certHashBufLen, uint8_t *publicKey, size_t publicKeyLen)
{
    sss_status_t status = kStatus_SSS_Fail;
    int i = -1, ret = -1;

    char filename[EX_MAX_INCLUDE_DIR_LENGTH + EX_MAX_EXTRA_DIR_LENGTH] = {0};
    uint8_t hashBuf[NX_SHA256_BYTE_LEN]                                = {0};
    size_t hashBufLen                                                  = 0;

    ENSURE_OR_GO_EXIT(pCertHashBuf != NULL);
    ENSURE_OR_GO_EXIT(certHashBufLen == NX_SHA256_BYTE_LEN);
    ENSURE_OR_GO_EXIT(publicKey != NULL);

    for (i = 0; i < NX_LEAF_CERT_CACHE_MAX; i++) {
        status = kStatus_SSS_Fail;

        // Load device CA cache file.
        memset(filename, 0, sizeof(filename));
        ret = sprintf(filename, "%s%d.hex", EX_DEVICE_CACHE_HASH_FILE_PREFIX, i);
        ENSURE_OR_GO_EXIT(ret >= 0);

        memset(hashBuf, 0, NX_SHA256_BYTE_LEN);
        hashBufLen = NX_SHA256_BYTE_LEN;

        status = ex_sss_nx_read_cache_file(filename, hashBuf, &hashBufLen);
        if (status == kStatus_SSS_Success) {
            // Slot has been used.
            continue;
        }
        else {
            // Find empty slot.
            // Write device leaf certifiacate to cache
            status = ex_sss_nx_write_cache_file(filename, pCertHashBuf, certHashBufLen);
            if (status != kStatus_SSS_Success) {
                // Cache directory may not exist. Ignore the error.
                LOG_W("Can't write cache file %s. Does directory exist?", filename);
                break;
            }

            // Write device leaf certifiacate public key to cache
            ret = -1;
            memset(filename, 0, sizeof(filename));
            ret = sprintf(filename, "%s%d.hex", EX_DEVICE_CACHE_PUBKEY_FILE_PREFIX, i);
            ENSURE_OR_GO_EXIT(ret >= 0);

            status = ex_sss_nx_write_cache_file(filename, publicKey, publicKeyLen);
            if (status != kStatus_SSS_Success) {
                // Cache directory may not exist. Ignore the error.
                LOG_W("Can't write cache file %s. Does directory exist?", filename);
                break;
            }

            break;
        }
    }

    if (i >= NX_LEAF_CERT_CACHE_MAX) {
        // No empty slot
        LOG_I("No empty certificate slot");
    }

    status = kStatus_SSS_Success;

exit:
    return status;
}

sss_status_t ex_get_parent_cert_from_cache(int index, uint8_t *pCertBuf, size_t *pCertBufLen)
{
    sss_status_t status                                                = kStatus_SSS_Fail;
    int ret                                                            = -1;
    char filename[EX_MAX_INCLUDE_DIR_LENGTH + EX_MAX_EXTRA_DIR_LENGTH] = {0};

    ENSURE_OR_GO_EXIT((index >= 0) && (index <= NX_PARENT_CERT_CACHE_MAX));
    ENSURE_OR_GO_EXIT(pCertBuf != NULL);
    ENSURE_OR_GO_EXIT(pCertBufLen != NULL);
    ENSURE_OR_GO_EXIT(*pCertBufLen >= NX_MAX_CERT_BUFFER_SIZE);

    memset(filename, 0, sizeof(filename));
    ret = sprintf(filename, "%s%d.hex", EX_DEVICE_CACHE_CA_CERT_FILE_PREFIX, index);
    ENSURE_OR_GO_EXIT(ret >= 0);

    status = ex_sss_nx_read_cache_file(filename, pCertBuf, pCertBufLen);

exit:
    return status;
}

/**
 * @brief         Insert Parent certificate into cache.
 *
 *                Go through parent certificate cache to check if already in cache.
 *                If not, insert parent certificate into 1st unused slot.
 *
 * @param         pCertBuf          Cert buffer.
 * @param         certBufLen        Cert buffer length.
 *
 * @return        Status of insert.
 */
sss_status_t ex_parent_cert_cache_insert(uint8_t *pCertBuf, size_t certBufLen)
{
    sss_status_t status                                                = kStatus_SSS_Fail;
    int i                                                              = 0;
    int freeSlot                                                       = -1;
    char filename[EX_MAX_INCLUDE_DIR_LENGTH + EX_MAX_EXTRA_DIR_LENGTH] = {0};
    uint8_t *pCacheBuf                                                 = NULL;
    size_t cacheBufLen                                                 = 0;
    int ret                                                            = -1;

    ENSURE_OR_GO_EXIT(pCertBuf != NULL);

    pCacheBuf = (uint8_t *)SSS_MALLOC(NX_MAX_CERT_BUFFER_SIZE);
    ENSURE_OR_GO_EXIT(pCacheBuf != NULL);
    cacheBufLen = NX_MAX_CERT_BUFFER_SIZE;

    // Go through parent certificate cache to check if already in cache.
    // Also find first unused slot.
    for (i = 0; i < NX_PARENT_CERT_CACHE_MAX; i++) {
        // Read device CA cache file.
        memset(filename, 0, sizeof(filename));
        ret = -1;
        ret = sprintf(filename, "%s%d.hex", EX_DEVICE_CACHE_CA_CERT_FILE_PREFIX, i);
        ENSURE_OR_GO_EXIT(ret >= 0);

        memset(pCacheBuf, 0, NX_MAX_CERT_BUFFER_SIZE);
        cacheBufLen = NX_MAX_CERT_BUFFER_SIZE;
        status      = ex_sss_nx_read_cache_file(filename, pCacheBuf, &cacheBufLen);
        if (status == kStatus_SSS_Success) {
            if ((certBufLen == cacheBufLen) && (memcmp(pCertBuf, pCacheBuf, cacheBufLen) == 0)) {
                // Already in cache.
                LOG_D("Certificate already in CA cert cache");
                goto exit;
            }
        }
        else {
            if (freeSlot == -1) {
                freeSlot = i; // Find free Slot.
            }
        }
    }

    status = kStatus_SSS_Fail;
    // If not in cache, then write to first unused slot.
    if (freeSlot == -1) {
        // No empty slot
        LOG_W("No empty certificate cache slot. This CA certificate will not be cached.");
    }
    else {
        // Save certificate to cache.
        LOG_D("Cache CA cert to slot %d", freeSlot);

        memset(filename, 0, sizeof(filename));
        ret = -1;
        ret = sprintf(filename, "%s%d.hex", EX_DEVICE_CACHE_CA_CERT_FILE_PREFIX, freeSlot);
        ENSURE_OR_GO_EXIT(ret >= 0);

        status = kStatus_SSS_Fail;
        status = ex_sss_nx_write_cache_file(filename, pCertBuf, certBufLen);
        if (status != kStatus_SSS_Success) {
            // Cache directory may not exist. Ignore the error.
            LOG_W("Can't write cache file %s. Does directory exist?", filename);
        }
    }

    status = kStatus_SSS_Success;

exit:
    if (pCacheBuf != NULL) {
        SSS_FREE(pCacheBuf);
    }

    return status;
}
#else

/**
 * @brief         Find matching item in cert hash.
 *
 *                Go through host cert hash and looking for valid item
 *                with correct cert hash and.
 *
 * @param         pCertHashBuf          Cert hash buffer.
 * @param         certHashBufLen        Cert hash buffer length.
 * @param[out]    found                 Searching result, the item number.
 *
 * @return        Status of searching.
 */
sss_status_t ex_find_hash_in_cache(uint8_t *pCertHashBuf, size_t certHashBufLen, int *found)
{
    sss_status_t status = kStatus_SSS_Fail;

    ENSURE_OR_GO_EXIT(found != NULL);

    LOG_D("Not support cache system.");

    *found = NX_LEAF_CERT_CACHE_ITEM_NA;

    status = kStatus_SSS_Success;
exit:
    return status;
}

/**
 * @brief         Get public key in cert hash.
 *
 *                Get public key in cert hash.
 *
 * @param[in]     index                 Cert hash buffer index.
 * @param[out]    pPublicKeyBuf         Cert hash buffer.
 * @param[out]    pPublicKeyBufLen      Cert hash buffer length.
 *
 * @return        Status of searching.
 */
sss_status_t ex_get_pk_from_cache(int index, uint8_t *pPublicKeyBuf, size_t *pPublicKeyBufLen)
{
    sss_status_t status = kStatus_SSS_Fail;

    ENSURE_OR_GO_EXIT(pPublicKeyBufLen != NULL);

    LOG_D("Not support cache system.");

    *pPublicKeyBufLen = 0;

    status = kStatus_SSS_Success;

exit:
    return status;
}

/**
 * @brief         Insert leaf cert hash and pulbic key into cache.
 *
 *                Found an empty slot and insert hash-signature-public key
 *
 * @param         pCertHashBuf          Cert Hash.
 * @param         certHashBufLen        Cert Hash Length.
 * @param         publicKey             Public Key.
 * @param         publicKeyLen          Public Key Length.
 *
 * @return        Status of insert.
 */
sss_status_t ex_insert_hash_pk_to_cache(
    uint8_t *pCertHashBuf, size_t certHashBufLen, uint8_t *publicKey, size_t publicKeyLen)
{
    LOG_D("No cache system available");

    return kStatus_SSS_Success;
}

sss_status_t ex_get_parent_cert_from_cache(int index, uint8_t *pCertBuf, size_t *pCertBufLen)
{
    LOG_D("No cache available");
    return kStatus_SSS_Fail;
}

/**
 * @brief         Insert Parent certificate into cache.
 *
 *                Go through parent certificate cache to check if already in cache.
 *                If not, insert parent certificate into 1st unused slot.
 *
 * @param         pCertBuf          Cert buffer.
 * @param         certBufLen        Cert buffer length.
 *
 * @return        Status of insert.
 */
sss_status_t ex_parent_cert_cache_insert(uint8_t *pCertBuf, size_t certBufLen)
{
    LOG_D("No cache system available");

    return kStatus_SSS_Success;
}

#endif

#endif //#if SSS_HAVE_NX_TYPE
