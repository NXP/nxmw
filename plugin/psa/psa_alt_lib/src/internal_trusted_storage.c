/*
 *  PSA ITS simulator over stdio files.
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  Copyright 2020,2025 NXP
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#if defined(SSS_USE_FTR_FILE)
#include "fsl_sss_ftr.h"
#else
#include "fsl_sss_ftr_default.h"
#endif

#if defined(MBEDTLS_CONFIG_FILE)
#include MBEDTLS_CONFIG_FILE
#else
#include "mbedtls/config.h"
#endif

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#define mbedtls_snprintf snprintf
#endif

#if defined(_WIN32)
#include <windows.h>
#endif

#include "psa_crypto_its.h"
#include "psa_crypto_storage.h"

#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "psa/internal_trusted_storage.h"

#if defined(MBEDTLS_PSA_CRYPTO_SE_C)
// #include "sm_types.h"
#include "psa_alt.h"
#endif

#if !defined(PSA_ITS_STORAGE_PREFIX)
#define PSA_ITS_STORAGE_PREFIX ""
#endif

#define PSA_ITS_STORAGE_FILENAME_PATTERN "%08x%08x"
#define PSA_ITS_STORAGE_SUFFIX ".psa_its"
#define PSA_ITS_STORAGE_FILENAME_LENGTH                                       \
    (sizeof(PSA_ITS_STORAGE_PREFIX) - 1 +    /*prefix without terminating 0*/ \
        16 +                                 /*UID (64-bit number in hex)*/   \
        sizeof(PSA_ITS_STORAGE_SUFFIX) - 1 + /*suffix without terminating 0*/ \
        1 /*terminating null byte*/)
#define PSA_ITS_STORAGE_TEMP PSA_ITS_STORAGE_PREFIX "tempfile" PSA_ITS_STORAGE_SUFFIX

/* The maximum value of psa_storage_info_t.size */
#define PSA_ITS_MAX_SIZE 0xffffffff

#define PSA_ITS_MAGIC_STRING "PSA\0ITS\0"
#define PSA_ITS_MAGIC_LENGTH 8

/* As rename fails on Windows if the new filepath already exists,
 * use MoveFileExA with the MOVEFILE_REPLACE_EXISTING flag instead.
 * Returns 0 on success, nonzero on failure. */
#if defined(_WIN32)
#define rename_replace_existing(oldpath, newpath) (!MoveFileExA(oldpath, newpath, MOVEFILE_REPLACE_EXISTING))
#else
#define rename_replace_existing(oldpath, newpath) rename(oldpath, newpath)
#endif

typedef struct
{
    uint8_t magic[PSA_ITS_MAGIC_LENGTH];
    uint8_t size[sizeof(uint32_t)];
    uint8_t flags[sizeof(psa_storage_create_flags_t)];
} psa_its_file_header_t;

static void psa_its_fill_filename(psa_storage_uid_t uid, char *filename)
{
    /* Break up the UID into two 32-bit pieces so as not to rely on
     * long long support in snprintf. */
    mbedtls_snprintf(filename,
        PSA_ITS_STORAGE_FILENAME_LENGTH,
        "%s" PSA_ITS_STORAGE_FILENAME_PATTERN "%s",
        PSA_ITS_STORAGE_PREFIX,
        (unsigned)(uid >> 32),
        (unsigned)(uid & 0xffffffff),
        PSA_ITS_STORAGE_SUFFIX);
}

static psa_status_t psa_its_read_file(psa_storage_uid_t uid, struct psa_storage_info_t *p_info, FILE **p_stream)
{
    char filename[PSA_ITS_STORAGE_FILENAME_LENGTH];
    psa_its_file_header_t header;
    size_t n;

    *p_stream = NULL;
    psa_its_fill_filename(uid, filename);

#if defined(MBEDTLS_PSA_CRYPTO_SE_C) && SSS_HAVE_HOST_LPCXPRESSO55S
    psa_status_t psa_status = PSA_ERROR_STORAGE_FAILURE;
    uint8_t data[4096]      = {0};
    size_t dataLen          = sizeof(data);
    /*read from flash*/
    psa_status = psa_alt_read_flash_its_file(uid, data, &dataLen);
    if (psa_status != PSA_SUCCESS) {
        if (uid == PSA_CRYPTO_ITS_TRANSACTION_UID) {
            return PSA_ERROR_DOES_NOT_EXIST;
        }
        else {
            return psa_status;
        }
    }
    memcpy(&header, &data[0], sizeof(header));
    n = sizeof(header);
#endif
    if (n != sizeof(header))
        return (PSA_ERROR_DATA_CORRUPT);

    if (memcmp(header.magic, PSA_ITS_MAGIC_STRING, PSA_ITS_MAGIC_LENGTH) != 0)
        return (PSA_ERROR_DATA_CORRUPT);

    p_info->size  = (header.size[0] | header.size[1] << 8 | header.size[2] << 16 | header.size[3] << 24);
    p_info->flags = (header.flags[0] | header.flags[1] << 8 | header.flags[2] << 16 | header.flags[3] << 24);
    return (PSA_SUCCESS);
}

psa_status_t psa_its_get_info(psa_storage_uid_t uid, struct psa_storage_info_t *p_info)
{
    psa_status_t status;
    FILE *stream = NULL;
    status       = psa_its_read_file(uid, p_info, &stream);
    if (stream != NULL)
        fclose(stream);
    return (status);
}

psa_status_t psa_its_get(
    psa_storage_uid_t uid, uint32_t data_offset, uint32_t data_length, void *p_data, size_t *p_data_length)
{
    psa_status_t status;
    FILE *stream = NULL;
    struct psa_storage_info_t info;

    status = psa_its_read_file(uid, &info, &stream);
    if (status != PSA_SUCCESS)
        goto exit;
    status = PSA_ERROR_INVALID_ARGUMENT;
    if (data_offset + data_length < data_offset)
        goto exit;
#if SIZE_MAX < 0xffffffff
    if (data_offset + data_length > SIZE_MAX)
        goto exit;
#endif
    if (data_offset + data_length > info.size)
        goto exit;

    status = PSA_ERROR_STORAGE_FAILURE;
#if defined(MBEDTLS_PSA_CRYPTO_SE_C) && SSS_HAVE_HOST_LPCXPRESSO55S
    psa_status_t psa_status = status;
    uint8_t data[4096]      = {0};
    size_t dataLen          = sizeof(data);
    size_t offset           = 0;
    /*read from flash*/
    psa_status = psa_alt_read_flash_its_file(uid, data, &dataLen);
    if (psa_status != PSA_SUCCESS) {
        status = psa_status;
        goto exit;
    }
    if ((data_offset + data_length) > (dataLen - sizeof(psa_its_file_header_t))) {
        status = PSA_ERROR_INVALID_ARGUMENT;
        goto exit;
    }
    offset = sizeof(psa_its_file_header_t) + data_offset;
    memcpy(p_data, &data[offset], data_length);
    if (p_data_length != NULL) {
        *p_data_length = data_length;
    }

    status = PSA_SUCCESS;
#endif
exit:
    if (stream != NULL)
        fclose(stream);
    return (status);
}

psa_status_t psa_its_set(
    psa_storage_uid_t uid, uint32_t data_length, const void *p_data, psa_storage_create_flags_t create_flags)
{
    psa_status_t status = PSA_ERROR_STORAGE_FAILURE;
    char filename[PSA_ITS_STORAGE_FILENAME_LENGTH];
    psa_its_file_header_t header;

    memcpy(header.magic, PSA_ITS_MAGIC_STRING, PSA_ITS_MAGIC_LENGTH);
    header.size[0]  = data_length & 0xff;
    header.size[1]  = (data_length >> 8) & 0xff;
    header.size[2]  = (data_length >> 16) & 0xff;
    header.size[3]  = (data_length >> 24) & 0xff;
    header.flags[0] = create_flags & 0xff;
    header.flags[1] = (create_flags >> 8) & 0xff;
    header.flags[2] = (create_flags >> 16) & 0xff;
    header.flags[3] = (create_flags >> 24) & 0xff;

    psa_its_fill_filename(uid, filename);

    printf("\n psa_its_fill_filename complete: filename is %s\n", filename);
    // printf("\n psa_its_fill_filename complete: uid is %x\n", uid);

#if defined(MBEDTLS_PSA_CRYPTO_SE_C) && SSS_HAVE_HOST_LPCXPRESSO55S
    uint8_t *p_store_data = (uint8_t *)malloc(sizeof(header) + data_length); // [4096] = { 0 };
    memcpy(p_store_data, &header, sizeof(header));
    memcpy(p_store_data + sizeof(header), p_data, data_length);
    size_t dataLen = sizeof(header) + data_length;
    /*write into flash*/
    status = psa_alt_store_flash_its_file(uid, p_store_data, dataLen);
    if (p_store_data) {
        free(p_store_data);
    }
#endif
    return (status);
}

psa_status_t psa_its_remove(psa_storage_uid_t uid)
{
    char filename[PSA_ITS_STORAGE_FILENAME_LENGTH];
    psa_its_fill_filename(uid, filename);
#if defined(MBEDTLS_PSA_CRYPTO_SE_C) && SSS_HAVE_HOST_LPCXPRESSO55S
    psa_status_t psa_status = PSA_ERROR_DOES_NOT_EXIST;
    /*earse flash*/
    psa_status = psa_alt_remove_flash_its_file(uid);
    return psa_status;
#endif
}
