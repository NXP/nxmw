/*
 *
 * Copyright 2022-2024 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 */

/* ************************************************************************** */
/* Includes                                                                   */
/* ************************************************************************** */

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "ex_sss_boot.h"
#include "fsl_sss_nx_apis.h"
#include "fsl_sss_nx_auth_types.h"
#include "fsl_sss_nx_auth_keys.h"
#include "nxEnsure.h"
#include "nxLog_msg.h"
#include "nx_Personalization.h"
#include "nx_apdu.h"
#if SSS_HAVE_HOSTCRYPTO_MBEDTLS
#include "mbedtls/asn1write.h"
#include "mbedtls/x509_crt.h"
#elif SSS_HAVE_HOSTCRYPTO_OPENSSL
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#endif

#ifdef EX_SSS_SIGMA_I_CERT_INCLUDE_DIR // FILE SYSTEM

#if defined(_MSC_VER)
#define OS_PATH_SEPARATOR "\\"
#else
#define OS_PATH_SEPARATOR "/"
#endif

sss_status_t nx_provision_read_file_from_fs(char *fileName, uint8_t *buffer, size_t *bufferLen)
{
    sss_status_t status = kStatus_SSS_Fail;
    FILE *fp            = NULL;
    int ret             = -1;
    size_t fileSize     = 0;
    size_t maxBufLen    = 0;

    if ((fileName == NULL) || (buffer == NULL) || (bufferLen == NULL)) {
        LOG_E("Load file with invalid parameters");
        goto exit;
    }

    maxBufLen = *bufferLen;

    if (strstr(fileName, "..") != NULL) {
        LOG_W("Potential directory traversal");
    }
    if ((fp = fopen(fileName, "rb")) != NULL) {
        memset(buffer, 0, maxBufLen);
        fileSize = fread(buffer, sizeof(char), maxBufLen, fp);

        if ((fileSize == 0) || ferror(fp)) { /* fread failed */
            LOG_E("Error reading cert from %s", fileName);
            ret = fclose(fp);
            if (ret != 0) {
                LOG_E("Error failed to close file");
            }
            goto exit;
        }
        else { /* fread success */
            LOG_D("Number of characters read = %i\n", fileSize);
            *bufferLen = fileSize;
        }

        ret = fclose(fp);
        if (ret != 0) {
            goto exit;
        }
        LOG_I("Read file from %s", fileName);
    }
    else {
        LOG_D("Can not open file from %s", fileName);
        *bufferLen = 0;
        goto exit;
    }

    status = kStatus_SSS_Success;

exit:
    return status;
}

sss_status_t nx_provision_full_file_name(char *dirName, char *fileName, Nx_ECCurve_t curveType, char *fullPathFileName)
{
    sss_status_t status = kStatus_SSS_Fail;
    int ret             = -1;

    ENSURE_OR_GO_EXIT(dirName != NULL);
    ENSURE_OR_GO_EXIT(fileName != NULL);
    ENSURE_OR_GO_EXIT((curveType == Nx_ECCurve_Brainpool256) || (curveType == Nx_ECCurve_NIST_P256));
    ENSURE_OR_GO_EXIT(strlen(dirName) < EX_MAX_INCLUDE_DIR_LENGTH);
    ENSURE_OR_GO_EXIT(strlen(fileName) < EX_MAX_EXTRA_FILE_NAME_LENGTH);

    if (curveType == Nx_ECCurve_Brainpool256) {
        ret = sprintf(fullPathFileName,
            "%s%s%s%s%s%s%s",
            dirName,
            OS_PATH_SEPARATOR,
            "cert_and_key",
            OS_PATH_SEPARATOR,
            "brainpool",
            OS_PATH_SEPARATOR,
            fileName);
    }
    else {
        ret = sprintf(fullPathFileName,
            "%s%s%s%s%s%s%s",
            dirName,
            OS_PATH_SEPARATOR,
            "cert_and_key",
            OS_PATH_SEPARATOR,
            "nist_p",
            OS_PATH_SEPARATOR,
            fileName);
    }

    ENSURE_OR_GO_EXIT(ret >= 0);

    status = kStatus_SSS_Success;

exit:
    return status;
}

bool nx_provision_dir_exists(const char *pathname)
{
    struct stat info;

    if (stat(pathname, &info) != 0) {
        return false;
    }
    else if (info.st_mode & S_IFDIR) {
        return true;
    }
    else {
        return false;
    }
}

#endif //#ifdef EX_SSS_SIGMA_I_CERT_INCLUDE_DIR
