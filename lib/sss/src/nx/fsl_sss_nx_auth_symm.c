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

/* *****************************************************************************************************************
* Internal Definitions
* ***************************************************************************************************************** */
#ifndef MAKE_TEST_ID
#define MAKE_TEST_ID(ID) (0xEF000000u + ID)
#endif /* MAKE_TEST_ID */

#ifdef EX_SSS_APPKEY_FILE_PATH
sss_status_t nx_util_get_app_keys_from_fs(uint8_t *appkeyBuf, size_t appkeyBufLen, size_t *appkeyLen);
#endif // EX_SSS_APPKEY_FILE_PATH
#ifdef EX_SSS_D_KEY_INPUT_FILE_PATH
sss_status_t ex_sss_util_get_dkeyinput_from_fs(uint8_t *uid,
    size_t uidLen,
    uint8_t *application_identifier,
    size_t application_identifier_len,
    uint8_t *system_identifier,
    size_t system_identifier_len);
#endif // EX_SSS_D_KEY_INPUT_FILE_PATH

#if defined(EX_SSS_PCDCAP2_FILE_PATH) || defined(EX_SSS_D_KEY_INPUT_FILE_PATH)
static sss_status_t convert_string_into_integer(bool flag, char *stringin, uint8_t *intout, size_t intoutLen)
{
    sss_status_t status = kStatus_SSS_Fail;
    size_t j            = 0;
    char charac         = 0;

    ENSURE_OR_GO_EXIT(NULL != stringin)
    ENSURE_OR_GO_EXIT(NULL != intout)

    charac = stringin[j];
    if (TRUE == flag) {
        LOG_E("Duplicate intout value");
        goto exit;
    }
    while (!isspace(charac)) {
        if (j <= SIZE_MAX - 1) {
            j++;
        }
        else {
            LOG_E("Too long source string!");
            goto exit;
        }
        charac = stringin[j];
    }
    while (isspace(charac)) {
        if (j <= SIZE_MAX - 1) {
            j++;
        }
        else {
            LOG_E("Too long source string!");
            goto exit;
        }
        charac = stringin[j];
    }
    if (stringin[j] == '\0') {
        LOG_E("Invalid intout Value");
        goto exit;
    }

    for (size_t count = 0; count < intoutLen; count++) {
        if (sscanf(&stringin[j], "%2hhx", &intout[count]) != 1) {
            LOG_E("Cannot copy data");
            goto exit;
        }

        if (j <= SIZE_MAX - 2) {
            j = j + 2;
        }
        else {
            LOG_E("Too long source string!");
            goto exit;
        }
    }

    status = kStatus_SSS_Success;

exit:
    return status;
}
#endif // defined(EX_SSS_PCDCAP2_FILE_PATH) || defined(EX_SSS_D_KEY_INPUT_FILE_PATH)

#if SSS_HAVE_AUTH_SYMM_DIVERSIFY_ENABLED
static void add_padding_dkey_input(uint8_t *diversifyInput, size_t diversifyInputBufSize, size_t *diversifyInputLen)
{
    uint16_t zeroBytesToPad = 0;

    ENSURE_OR_GO_EXIT(diversifyInputLen != NULL);
    ENSURE_OR_GO_EXIT(diversifyInput != NULL);
    zeroBytesToPad = (EX_DIVERSIFY_INPUT_SIZE -
                         ((*diversifyInputLen + EX_DIVERSIFY_INPUT_PAD_BYTE_SIZE) % EX_DIVERSIFY_INPUT_SIZE)) %
                     EX_DIVERSIFY_INPUT_SIZE;
    ENSURE_OR_GO_EXIT((UINT_MAX - 1) > (*diversifyInputLen));
    ENSURE_OR_GO_EXIT(*diversifyInputLen < EX_DIVERSIFY_INPUT_SIZE); // supports only 32Byte padding
    ENSURE_OR_GO_EXIT(zeroBytesToPad + (*diversifyInputLen) <= diversifyInputBufSize);
    // pad and adjust the length of the diversify key input data
    diversifyInput[(*diversifyInputLen)] = EX_DIVERSIFY_INPUT_PAD_BYTE;
    *diversifyInputLen += EX_DIVERSIFY_INPUT_PAD_BYTE_SIZE;
    ENSURE_OR_GO_EXIT((UINT_MAX - (*diversifyInputLen)) > zeroBytesToPad);
    memset(&diversifyInput[(*diversifyInputLen)], 0x00, zeroBytesToPad);

exit:
    return;
}
#endif // SSS_HAVE_AUTH_SYMM_DIVERSIFY_ENABLED

#ifdef EX_SSS_D_KEY_INPUT_FILE_PATH
static sss_status_t read_dkeyinput_file(FILE *dkey_input_file_handle,
    uint8_t *uid,
    size_t uidLen,
    uint8_t *application_identifier,
    size_t application_identifier_len,
    uint8_t *system_identifier,
    size_t system_identifier_len)
{
    sss_status_t status                           = kStatus_SSS_Fail;
    char file_data[EX_AUTH_FILE_DATABUF_MAX_SIZE] = {0};
    char *pdata                                   = &file_data[0];
    bool uid_flag                                 = false;
    bool aid_flag                                 = false;
    bool sid_flag                                 = false;

    if (dkey_input_file_handle == NULL) {
        LOG_E("Cannot open dkey input file");
        status = kStatus_SSS_Fail;
        return status;
    }

    while (fgets(pdata, sizeof(file_data), dkey_input_file_handle)) {
        size_t i = 0;

        /*Don't need leading spaces*/
        for (i = 0; i < strlen(pdata); i++) {
            char charac = pdata[i];
            if (!isspace(charac)) {
                break;
            }
        }

        if (strncmp(&pdata[i], "UID ", strlen("UID ")) == 0) {
#if UNSECURE_LOGGING_OF_APP_KEYS
            LOG_I("%s", &pdata[i]);
#endif
            status = convert_string_into_integer(uid_flag, &pdata[i], uid, uidLen);
            if (status != kStatus_SSS_Success) {
                if (0 != fclose(dkey_input_file_handle)) {
                    LOG_E("Unable to close dkey input file");
                }
                return status;
            }
            uid_flag = true;
        }
        else if (!(strncmp(&pdata[i], "AID ", strlen("AID ")))) {
#if UNSECURE_LOGGING_OF_APP_KEYS
            LOG_I("%s", &pdata[i]);
#endif
            status =
                convert_string_into_integer(aid_flag, &pdata[i], application_identifier, application_identifier_len);
            if (status != kStatus_SSS_Success) {
                if (0 != fclose(dkey_input_file_handle)) {
                    LOG_E("Unable to close dkey input file");
                }
                return status;
            }
            aid_flag = true;
        }
        else if (!(strncmp(&pdata[i], "SID ", strlen("SID ")))) {
#if UNSECURE_LOGGING_OF_APP_KEYS
            LOG_I("%s", &pdata[i]);
#endif
            status = convert_string_into_integer(sid_flag, &pdata[i], system_identifier, system_identifier_len);
            if (status != kStatus_SSS_Success) {
                if (0 != fclose(dkey_input_file_handle)) {
                    LOG_E("Unable to close dkey input file");
                }
                return status;
            }
            sid_flag = true;
        }
        else {
            LOG_E("Unknown key type %s", &pdata[i]);
            status = kStatus_SSS_Fail;
            if (0 != fclose(dkey_input_file_handle)) {
                LOG_E("Unable to close dkey input file");
            }
            return status;
        }
    }

    if (0 != fclose(dkey_input_file_handle)) {
        LOG_E("Unable to close dkey input file");
        return kStatus_SSS_Fail;
    }
    return kStatus_SSS_Success;
}

sss_status_t ex_sss_util_get_dkeyinput_from_fs(uint8_t *uid,
    size_t uidLen,
    uint8_t *application_identifier,
    size_t application_identifier_len,
    uint8_t *system_identifier,
    size_t system_identifier_len)
{
    sss_status_t status  = kStatus_SSS_Fail;
    const char *filename = EX_SSS_D_KEY_INPUT_FILE_PATH;
    FILE *fp             = NULL;
    LOG_D("Using File: %s", filename);

    if (strstr(filename, "..") != NULL) {
        LOG_W("Potential directory traversal");
    }

    fp = fopen(filename, "rb");
    if (fp != NULL) {
        // File exists. Get keys from file
        LOG_W("get inputs to derive dkey from:'%s' (FILE=%s)", filename, EX_SSS_D_KEY_INPUT_FILE_PATH);
        status = read_dkeyinput_file(fp,
            uid,
            uidLen,
            application_identifier,
            application_identifier_len,
            system_identifier,
            system_identifier_len);
    }
    else {
        // File does not exist. Check env variable
        char *dkey_input_path_env = NULL;
#if defined(_MSC_VER)
        size_t sz = 0;
        _dupenv_s(&dkey_input_path_env, &sz, EX_SSS_BOOT_D_KEY_PATH_ENV);
#else
        dkey_input_path_env = getenv(EX_SSS_BOOT_D_KEY_PATH_ENV);
#endif //_MSC_VER

        if (dkey_input_path_env != NULL) {
            if (strstr(dkey_input_path_env, "..") != NULL) {
                LOG_W("Potential directory traversal");
            }
            fp = fopen(dkey_input_path_env, "r");
            if (fp != NULL) {
                LOG_W("get inputs to derive dkey from:'%s' (ENV=%s)", dkey_input_path_env, EX_SSS_BOOT_D_KEY_PATH_ENV);
                status = read_dkeyinput_file(fp,
                    uid,
                    uidLen,
                    application_identifier,
                    application_identifier_len,
                    system_identifier,
                    system_identifier_len);
            }
            else {
                LOG_E("The path set in:'%s' (ENV=%s) is invalid!", dkey_input_path_env, EX_SSS_BOOT_D_KEY_PATH_ENV);
                LOG_I("Make sure the path is correct");
            }

#if defined(_MSC_VER)
            free(dkey_input_path_env);
#endif //_MSC_VER
        }
        else {
            LOG_I(
                "Using default inputs to derive dkey. "
                "You can use get inputs to derive dkey from file by setting ENV=%s to its path",
                EX_SSS_BOOT_D_KEY_PATH_ENV);
        }
    }

    if (status != kStatus_SSS_Success) {
        LOG_D("Using default get inputs to derive dkey");
    }

    return status;
}
#endif // EX_SSS_D_KEY_INPUT_FILE_PATH

#ifdef EX_SSS_PCDCAP2_FILE_PATH

static sss_status_t read_pcdcap2_from_file(FILE *pcdcap2_file_handle, uint8_t *pcdcap2, size_t pcdcap2_len)
{
    sss_status_t status                           = kStatus_SSS_Fail;
    char file_data[EX_AUTH_FILE_DATABUF_MAX_SIZE] = {0};
    char *pdata                                   = &file_data[0];
    bool pcdCAP2_flag                             = false;

    if (pcdcap2_file_handle == NULL) {
        LOG_E("Cannot open PCDCap2 file");
        goto exit;
    }

    while (fgets(pdata, sizeof(file_data), pcdcap2_file_handle)) {
        size_t i = 0;

        /*Don't need leading spaces*/
        for (i = 0; i < strlen(pdata); i++) {
            char charac = pdata[i];
            if (!isspace(charac)) {
                break;
            }
        }

        if (strncmp(&pdata[i], "PCDCAP2 ", strlen("PCDCAP2 ")) == 0) {
            LOG_I("%s", &pdata[i]);
            status = convert_string_into_integer(pcdCAP2_flag, &pdata[i], pcdcap2, pcdcap2_len);
            if (status != kStatus_SSS_Success) {
                if (0 != fclose(pcdcap2_file_handle)) {
                    LOG_E("Unable to close pcdcap2_file_handle");
                }
                goto exit;
            }
            pcdCAP2_flag = true;
        }
        else {
            LOG_E("Unknown pcdcap2 data %s", &pdata[i]);
            status = kStatus_SSS_Fail;
            if (0 != fclose(pcdcap2_file_handle)) {
                LOG_E("Unable to close pcdcap2_file_handle");
            }
            goto exit;
        }
    }

    if (0 != fclose(pcdcap2_file_handle)) {
        LOG_E("Unable to close pcdcap2_file_handle");
        status = kStatus_SSS_Fail;
        goto exit;
    }

    status = kStatus_SSS_Success;

exit:
    return status;
}

sss_status_t get_pcdcap2_val_from_fs(uint8_t *pcdcap2, size_t pcdcap2_len)
{
    sss_status_t status  = kStatus_SSS_Fail;
    const char *filename = EX_SSS_PCDCAP2_FILE_PATH;
    FILE *fp             = NULL;
    LOG_D("Using File: %s", filename);

    if (strstr(filename, "..") != NULL) {
        LOG_W("Potential directory traversal");
    }

    fp = fopen(filename, "rb");
    if (fp != NULL) {
        // File exists. Get PCDCap2 from file
        LOG_W("Using PCDCap2 from:'%s' (FILE=%s)", filename, EX_SSS_PCDCAP2_FILE_PATH);
        status = read_pcdcap2_from_file(fp, pcdcap2, pcdcap2_len);
    }
    else {
        // File does not exist. Check env variable
        char *pcdcap2_path_env = NULL;
#if defined(_MSC_VER)
        size_t sz = 0;
        _dupenv_s(&pcdcap2_path_env, &sz, EX_SSS_BOOT_PCDCAP2_PATH_ENV);
#else
        pcdcap2_path_env    = getenv(EX_SSS_BOOT_PCDCAP2_PATH_ENV);
#endif //_MSC_VER

        if (pcdcap2_path_env != NULL) {
            if (strstr(pcdcap2_path_env, "..") != NULL) {
                LOG_W("Potential directory traversal");
            }
            fp = fopen(pcdcap2_path_env, "r");
            if (fp != NULL) {
                LOG_W("Using PCDCap2 from:'%s' (ENV=%s)", pcdcap2_path_env, EX_SSS_BOOT_PCDCAP2_PATH_ENV);
                status = read_pcdcap2_from_file(fp, pcdcap2, pcdcap2_len);
            }
            else {
                LOG_E("The PCDCap2 path set in:'%s' (ENV=%s) is invalid!",
                    pcdcap2_path_env,
                    EX_SSS_BOOT_PCDCAP2_PATH_ENV);
                LOG_I("Make sure the path is correct");
            }
#if defined(_MSC_VER)
            free(pcdcap2_path_env);
#endif //_MSC_VER
        }
        else {
            LOG_I(
                "Using PCDCap from (EX_SYMM_AUTH_PCDCCAP2) from file - lib/sss/inc/fsl_sss_nx_auth_keys.h. "
                "(You can use PCDCap2 from file by setting ENV=%s to its path)",
                EX_SSS_BOOT_PCDCAP2_PATH_ENV);
        }
    }

    if (status != kStatus_SSS_Success) {
        LOG_D("Using PCDCap from (EX_SYMM_AUTH_PCDCCAP2) from file - lib/sss/inc/fsl_sss_nx_auth_keys.h. ");
    }

    return status;
}
#endif // EX_SSS_PCDCAP2_FILE_PATH

#ifdef EX_SSS_APPKEY_FILE_PATH

static sss_status_t convert_string_into_integer_calculate_and_return_len(
    bool flag, char *stringin, uint8_t *intoutBuf, size_t intoutBufLen, size_t *intoutLen)
{
    sss_status_t status = kStatus_SSS_Fail;
    size_t j            = 0;
    size_t stringintLen = 0;
    size_t count        = 0;
    char charac         = stringin[j];
    if (NULL == intoutBuf || NULL == intoutLen) {
        LOG_E("Buffer is null");
        goto exit;
    }
    if (true == flag) {
        LOG_E("Duplicate intoutBuf value");
        goto exit;
    }
    while (0 == isspace(charac)) {
        if (j <= SIZE_MAX - 1) {
            j++;
        }
        else {
            LOG_E("Too long source string!");
            goto exit;
        }
        charac = stringin[j];
    }
    while (0 != isspace(charac)) {
        if (j <= SIZE_MAX - 1) {
            j++;
        }
        else {
            LOG_E("Too long source string!");
            goto exit;
        }
        charac = stringin[j];
    }
    if (stringin[j] == '\0') {
        LOG_E("Invalid intoutBuf Value");
        goto exit;
    }

    stringintLen = strlen(&stringin[j]) / 2;
    if (stringintLen > intoutBufLen) {
        LOG_E("Buffer will overflow Cannot copy data");
        goto exit;
    }
    for (count = 0; count < stringintLen; count++) {
        if (sscanf(&stringin[j], "%2hhx", &intoutBuf[count]) != 1) {
            LOG_E("Cannot copy data");
            goto exit;
        }

        if (j <= SIZE_MAX - 2) {
            j = j + 2;
        }
        else {
            LOG_E("Too long source string!");
            goto exit;
        }
    }
    *intoutLen = count;
    status     = kStatus_SSS_Success;

exit:
    return status;
}

static sss_status_t read_app_keys_from_file(
    FILE *appkey_file_handle, uint8_t *appkeyBuf, size_t appkeyBufLen, size_t *appkeyLen)
{
    sss_status_t status                           = kStatus_SSS_Fail;
    char file_data[EX_AUTH_FILE_DATABUF_MAX_SIZE] = {0};
    char *pdata                                   = &file_data[0];
    bool appkey_flag                              = false;

    if (appkey_file_handle == NULL) {
        LOG_E("Cannot open appkey file");
        goto exit;
    }

    while (fgets(pdata, sizeof(file_data), appkey_file_handle)) {
        size_t i = 0;

        /*Don't need leading spaces*/
        for (i = 0; i < strlen(pdata); i++) {
            char charac = pdata[i];
            if (!isspace(charac)) {
                break;
            }
        }

        if (strncmp(&pdata[i], "APPKEY ", strlen("APPKEY ")) == 0) {
#if UNSECURE_LOGGING_OF_APP_KEYS
            LOG_I("%s", &pdata[i]);
#endif
            status = convert_string_into_integer_calculate_and_return_len(
                appkey_flag, &pdata[i], appkeyBuf, appkeyBufLen, appkeyLen);
            if (status != kStatus_SSS_Success) {
                if (0 != fclose(appkey_file_handle)) {
                    LOG_E("Unable to close appkey file");
                }
                goto exit;
            }
            appkey_flag = true;
        }
        else {
            LOG_E("Unknown key type %s", &pdata[i]);
            status = kStatus_SSS_Fail;
            if (0 != fclose(appkey_file_handle)) {
                LOG_E("Unable to close appkey file");
            }
            goto exit;
        }
    }

    if (0 != fclose(appkey_file_handle)) {
        LOG_E("Unable to close appkey file");
        status = kStatus_SSS_Fail;
        goto exit;
    }

    status = kStatus_SSS_Success;
exit:
    return status;
}

sss_status_t nx_util_get_app_keys_from_fs(uint8_t *appkeyBuf, size_t appkeyBufLen, size_t *appkeyLen)
{
    sss_status_t status  = kStatus_SSS_Fail;
    const char *filename = EX_SSS_APPKEY_FILE_PATH;
    FILE *fp             = NULL;
    LOG_D("Using File: %s", filename);

    if (strstr(filename, "..") != NULL) {
        LOG_W("Potential directory traversal");
    }

    fp = fopen(filename, "rb");
    if (fp != NULL) {
        // File exists. Get keys from file
        LOG_W("Using appkeys from:'%s' (FILE=%s)", filename, EX_SSS_APPKEY_FILE_PATH);
        status = read_app_keys_from_file(fp, appkeyBuf, appkeyBufLen, appkeyLen);
    }
    else {
        // File does not exist. Check env variable
        char *appkey_path_env = NULL;
#if defined(_MSC_VER)
        size_t sz = 0;
        _dupenv_s(&appkey_path_env, &sz, EX_SSS_BOOT_APPKEY_PATH_ENV);
#else
        appkey_path_env     = getenv(EX_SSS_BOOT_APPKEY_PATH_ENV);
#endif //_MSC_VER

        if (appkey_path_env != NULL) {
            if (strstr(appkey_path_env, "..") != NULL) {
                LOG_W("Potential directory traversal");
            }

            fp = fopen(appkey_path_env, "r");
            if (fp != NULL) {
                LOG_W("Using appkeys from:'%s' (ENV=%s)", appkey_path_env, EX_SSS_BOOT_APPKEY_PATH_ENV);
                status = read_app_keys_from_file(fp, appkeyBuf, appkeyBufLen, appkeyLen);
            }
            else {
                LOG_E(
                    "The appkeys path set in:'%s' (ENV=%s) is invalid!", appkey_path_env, EX_SSS_BOOT_APPKEY_PATH_ENV);
                LOG_I("Make sure the path is correct");
            }
#if defined(_MSC_VER)
            free(appkey_path_env);
#endif //_MSC_VER
        }
        else {
            LOG_I(
                "Using appkey (EX_SYMM_AUTH_AES*_KEY) from file - lib/sss/inc/fsl_sss_nx_auth_keys.h. "
                "(You can use appkeys from file by setting ENV=%s to its path)",
                EX_SSS_BOOT_APPKEY_PATH_ENV);
        }
    }

    if (status != kStatus_SSS_Success) {
        LOG_D("Using appkey (EX_SYMM_AUTH_AES*_KEY) from file - lib/sss/inc/fsl_sss_nx_auth_keys.h. ");
    }

    return status;
}

#endif // EX_SSS_APPKEY_FILE_PATH

#if SSS_HAVE_HOSTCRYPTO_ANY
/* Function to Set Init and Allocate static SymmKeys and Init Allocate dynamic keys */
sss_status_t nx_prepare_host_for_auth_key_symm_auth(
    nx_auth_symm_ctx_t *pAuthCtx, sss_key_store_t *pKs, nx_connect_ctx_t *nx_conn_ctx)
{
    sss_status_t status                      = kStatus_SSS_Fail;
    uint32_t keyId                           = MAKE_TEST_ID(__LINE__);
    size_t keyBitLen                         = 0;
    nx_secure_symm_type_t secure_tunnel_type = nx_conn_ctx->auth.ctx.symmAuth.dyn_ctx.selectedSecureTunnelType;

    /* Initializing the appKey buffer with 32 bytes, which is the maximum it can be. */
    uint8_t appKey[EX_SYMM_AUTH_AES256_KEY_SIZE] = {0};
    size_t appKeySize                            = sizeof(appKey);

    if ((pAuthCtx == NULL) || (pKs == NULL)) {
        return status;
    }

    nx_auth_symm_static_ctx_t *static_ctx = &(pAuthCtx->static_ctx);
    nx_auth_symm_dynamic_ctx_t *dyn_ctx   = &(pAuthCtx->dyn_ctx);

    // appKey logic moved from init to here
    if (secure_tunnel_type == knx_SecureSymmType_AES128_NTAG) {
#if defined(SSS_HAVE_SECURE_TUNNELING_NTAG_AES128_EV2) && (SSS_HAVE_SECURE_TUNNELING_NTAG_AES128_EV2) || \
    defined(SSS_HAVE_ALL_AUTH_CODE_ENABLED) && (SSS_HAVE_ALL_AUTH_CODE_ENABLED)
        uint8_t defAppkeyAES128[EX_SYMM_AUTH_AES128_KEY_SIZE] = EX_SYMM_AUTH_AES128_KEY;
        memcpy(appKey, defAppkeyAES128, sizeof(defAppkeyAES128));
        appKeySize = sizeof(defAppkeyAES128);

#ifdef EX_SSS_APPKEY_FILE_PATH
        uint8_t fileAppKeyAES128[EX_SYMM_AUTH_AES128_KEY_SIZE] = {0};
        size_t fileAppKeyAES128Len                             = 0;
        status = nx_util_get_app_keys_from_fs(&fileAppKeyAES128[0], sizeof(fileAppKeyAES128), &fileAppKeyAES128Len);
        if (status == kStatus_SSS_Success) {
            if (fileAppKeyAES128Len == EX_SYMM_AUTH_AES128_KEY_SIZE) {
                memcpy(appKey, fileAppKeyAES128, fileAppKeyAES128Len);
                appKeySize = fileAppKeyAES128Len;
            }
            else {
                LOG_E("Invalid KeyLen");
                goto exit;
            }
        }
#endif // EX_SSS_APPKEY_FILE_PATH
        keyBitLen = EX_SYMM_AUTH_AES128_KEY_BIT_LEN;
#endif // SSS_HAVE_SECURE_TUNNELING_NTAG_AES128_EV2
    }
    else if (secure_tunnel_type == knx_SecureSymmType_AES256_NTAG) {
#if defined(SSS_HAVE_SECURE_TUNNELING_NTAG_AES256_EV2) && (SSS_HAVE_SECURE_TUNNELING_NTAG_AES256_EV2) || \
    defined(SSS_HAVE_ALL_AUTH_CODE_ENABLED) && (SSS_HAVE_ALL_AUTH_CODE_ENABLED)
        uint8_t defAppkeyAES256[EX_SYMM_AUTH_AES256_KEY_SIZE] = EX_SYMM_AUTH_AES256_KEY;
        memcpy(appKey, defAppkeyAES256, sizeof(defAppkeyAES256));
        appKeySize = sizeof(defAppkeyAES256);

#ifdef EX_SSS_APPKEY_FILE_PATH
        uint8_t fileAppKeyAES256[EX_SYMM_AUTH_AES256_KEY_SIZE] = {0};
        size_t fileAppKeyAES256Len                             = 0;
        status = nx_util_get_app_keys_from_fs(&fileAppKeyAES256[0], sizeof(fileAppKeyAES256), &fileAppKeyAES256Len);
        if (status == kStatus_SSS_Success) {
            if (fileAppKeyAES256Len == EX_SYMM_AUTH_AES256_KEY_SIZE) {
                memcpy(appKey, fileAppKeyAES256, fileAppKeyAES256Len);
                appKeySize = fileAppKeyAES256Len;
            }
            else {
                LOG_E("Invalid KeyLen");
                goto exit;
            }
        }
#endif // EX_SSS_APPKEY_FILE_PATH
        keyBitLen = EX_SYMM_AUTH_AES256_KEY_BIT_LEN;
#endif // SSS_HAVE_SECURE_TUNNELING_NTAG_AES256_EV2
    }
    else {
        LOG_E("Invalid secure_tunnel_type");
        goto exit;
    }

    static_ctx->appKeySize = appKeySize;

    status = sss_host_key_object_init(&static_ctx->appKey, pKs);
    ENSURE_OR_GO_EXIT(kStatus_SSS_Success == status)

    status = sss_host_key_object_allocate_handle(
        &static_ctx->appKey, keyId, kSSS_KeyPart_Default, kSSS_CipherType_AES, appKeySize, kKeyObject_Mode_Transient);
    ENSURE_OR_GO_EXIT(kStatus_SSS_Success == status)

    status = sss_host_key_store_set_key(pKs, &static_ctx->appKey, appKey, appKeySize, keyBitLen, NULL, 0);
    ENSURE_OR_GO_EXIT(kStatus_SSS_Success == status)

#if SSS_HAVE_AUTH_SYMM_DIVERSIFY_ENABLED
    sss_algorithm_t algorithm = kAlgorithm_SSS_CMAC_AES;
    sss_mode_t mode           = kMode_SSS_Mac;
    sss_mac_t macCtx          = {0};

    uint8_t uidBufDefault[EX_DIVERSIFY_UID_LEN]     = EX_DIVERSIFY_INPUT_UID;
    size_t uidBufDefaultLen                         = sizeof(uidBufDefault);
    uint8_t aidBufDefault[EX_DIVERSIFY_AID_LEN]     = EX_DIVERSIFY_INPUT_AID;
    size_t aidBufDefaultLen                         = sizeof(aidBufDefault);
    uint8_t sidBufDefault[EX_DIVERSIFY_SID_LEN]     = EX_DIVERSIFY_INPUT_SID;
    size_t sidBufDefaultLen                         = sizeof(sidBufDefault);
    uint8_t diversifyInput[EX_DIVERSIFY_INPUT_SIZE] = {0};
    size_t diversifyInputLen                        = 0;

#if defined(EX_SSS_D_KEY_INPUT_FILE_PATH)
    uint8_t uidBuf_fs[EX_DIVERSIFY_UID_LEN] = {0};
    size_t uidBufLen_fs                     = sizeof(uidBuf_fs);
    uint8_t aidBuf_fs[EX_DIVERSIFY_AID_LEN] = {0};
    size_t aidBufLen_fs                     = sizeof(aidBuf_fs);
    uint8_t sidBuf_fs[EX_DIVERSIFY_SID_LEN] = {0};
    size_t sidBufLen_fs                     = sizeof(sidBuf_fs);
    status                                  = ex_sss_util_get_dkeyinput_from_fs(
        &uidBuf_fs[0], uidBufLen_fs, &aidBuf_fs[0], aidBufLen_fs, &sidBuf_fs[0], sidBufLen_fs);
    if (status == kStatus_SSS_Success) {
        memcpy(uidBufDefault, uidBuf_fs, uidBufLen_fs);
        uidBufDefaultLen = uidBufLen_fs;
        memcpy(aidBufDefault, aidBuf_fs, aidBufLen_fs);
        aidBufDefaultLen = aidBufLen_fs;
        memcpy(sidBufDefault, sidBuf_fs, sidBufLen_fs);
        sidBufDefaultLen = sidBufLen_fs;
    }
#endif // EX_SSS_D_KEY_INPUT_FILE_PATH
    diversifyInputLen = 1;
    memcpy(diversifyInput + diversifyInputLen, uidBufDefault, uidBufDefaultLen);
    diversifyInputLen += uidBufDefaultLen;
    memcpy(diversifyInput + diversifyInputLen, aidBufDefault, aidBufDefaultLen);
    diversifyInputLen += aidBufDefaultLen;
    memcpy(diversifyInput + diversifyInputLen, sidBufDefault, sidBufDefaultLen);
    diversifyInputLen += sidBufDefaultLen;

    if (diversifyInputLen < 16) {
        add_padding_dkey_input(&diversifyInput[0], sizeof(diversifyInput), &diversifyInputLen);
    }

    if (static_ctx->appKeySize == EX_SYMM_AUTH_AES128_KEY_SIZE) {
#if defined(SSS_HAVE_SECURE_TUNNELING_NTAG_AES128_EV2) && (SSS_HAVE_SECURE_TUNNELING_NTAG_AES128_EV2)
        diversifyInput[0]                                        = EX_AES128_DIVERSIFY_INPUT_CONSTANT_BYTE;
        uint8_t aes128DiversifyKey[EX_SYMM_AUTH_AES128_KEY_SIZE] = {0};
        size_t aes128DiversifyKeyLen                             = EX_SYMM_AUTH_AES128_KEY_SIZE;

        status =
            sss_mac_context_init(&macCtx, static_ctx->appKey.keyStore->session, &static_ctx->appKey, algorithm, mode);
        if (status != kStatus_SSS_Success) {
            return status;
        }

        status = sss_mac_one_go(&macCtx, diversifyInput, diversifyInputLen, aes128DiversifyKey, &aes128DiversifyKeyLen);
        if (status != kStatus_SSS_Success) {
            if (macCtx.session != NULL) {
                sss_mac_context_free(&macCtx);
            }
            return status;
        }

        if (macCtx.session != NULL) {
            sss_mac_context_free(&macCtx);
        }

        status = sss_host_key_store_set_key(
            pKs, &static_ctx->appKey, aes128DiversifyKey, aes128DiversifyKeyLen, keyBitLen, NULL, 0);
        if (status != kStatus_SSS_Success) {
            return status;
        }
#endif // SSS_HAVE_SECURE_TUNNELING_NTAG_AES128_EV2
    }
    else if (static_ctx->appKeySize == EX_SYMM_AUTH_AES256_KEY_SIZE) {
#if defined(SSS_HAVE_SECURE_TUNNELING_NTAG_AES256_EV2) && (SSS_HAVE_SECURE_TUNNELING_NTAG_AES256_EV2)
        uint8_t aes256DiversifyKey[EX_SYMM_AUTH_AES256_KEY_SIZE] = {0};
        size_t aes256DiversifyKeyLen                             = 0;
        uint8_t diversifyKeyA[EX_DIVERSIFY_KEY_SIZE]             = {0};
        size_t diversifyKeyALen                                  = sizeof(diversifyKeyA);
        uint8_t diversifyKeyB[EX_DIVERSIFY_KEY_SIZE]             = {0};
        size_t diversifyKeyBLen                                  = sizeof(diversifyKeyB);
        uint8_t diversifyInputD1[EX_DIVERSIFY_INPUT_SIZE]        = {0};
        uint8_t diversifyInputD2[EX_DIVERSIFY_INPUT_SIZE]        = {0};

        status =
            sss_mac_context_init(&macCtx, static_ctx->appKey.keyStore->session, &static_ctx->appKey, algorithm, mode);
        if (status != kStatus_SSS_Success) {
            return status;
        }

        memcpy(diversifyInputD1, diversifyInput, diversifyInputLen);
        diversifyInputD1[0] = EX_AES256_DIVERSIFY_INPUT_D1_CONSTANT_BYTE;

        status = sss_mac_one_go(&macCtx, diversifyInputD1, diversifyInputLen, diversifyKeyA, &diversifyKeyALen);
        if (status != kStatus_SSS_Success) {
            if (macCtx.session != NULL) {
                sss_mac_context_free(&macCtx);
            }
            return status;
        }

        memcpy(diversifyInputD2, diversifyInput, diversifyInputLen);
        diversifyInputD2[0] = EX_AES256_DIVERSIFY_INPUT_D2_CONSTANT_BYTE;

        status = sss_mac_one_go(&macCtx, diversifyInputD2, diversifyInputLen, diversifyKeyB, &diversifyKeyBLen);
        if (status != kStatus_SSS_Success) {
            if (macCtx.session != NULL) {
                sss_mac_context_free(&macCtx);
            }
            return status;
        }

        if (macCtx.session != NULL) {
            sss_mac_context_free(&macCtx);
        }

        memcpy(aes256DiversifyKey, diversifyKeyA, diversifyKeyALen);
        memcpy(aes256DiversifyKey + diversifyKeyALen, diversifyKeyB, diversifyKeyBLen);

        aes256DiversifyKeyLen = diversifyKeyALen + diversifyKeyBLen;

        status = sss_host_key_store_set_key(
            pKs, &static_ctx->appKey, aes256DiversifyKey, aes256DiversifyKeyLen, keyBitLen, NULL, 0);
        if (status != kStatus_SSS_Success) {
            return status;
        }
#endif // SSS_HAVE_SECURE_TUNNELING_NTAG_AES256_EV2
    }
    else {
        status = kStatus_SSS_Fail;
        LOG_E("Static app key length invalid");
        return status;
    }
#endif // SSS_HAVE_AUTH_SYMM_DIVERSIFY_ENABLED

    status = sss_host_key_object_init(&dyn_ctx->k_e2, pKs);
    ENSURE_OR_GO_EXIT(kStatus_SSS_Success == status)

    status = sss_host_key_object_allocate_handle(
        &dyn_ctx->k_e2, keyId, kSSS_KeyPart_Default, kSSS_CipherType_AES, appKeySize, kKeyObject_Mode_Transient);
    ENSURE_OR_GO_EXIT(kStatus_SSS_Success == status)

    status = sss_host_key_object_init(&dyn_ctx->k_m2, pKs);
    ENSURE_OR_GO_EXIT(kStatus_SSS_Success == status)

    status = sss_host_key_object_allocate_handle(
        &dyn_ctx->k_m2, keyId, kSSS_KeyPart_Default, kSSS_CipherType_AES, appKeySize, kKeyObject_Mode_Transient);
    ENSURE_OR_GO_EXIT(kStatus_SSS_Success == status)

exit:
    return status;
}
#endif // SSS_HAVE_HOSTCRYPTO_ANY

sss_status_t nx_init_conn_context_symm_auth(nx_connect_ctx_t *nx_conn_ctx,
    nx_auth_type_t auth_type,
    nx_secure_symm_type_t secure_tunnel_type,
    uint8_t key_no,
    bool pcdcap2_flag)
{
    sss_status_t status = kStatus_SSS_Fail;

    ENSURE_OR_GO_EXIT(NULL != nx_conn_ctx)

    nx_conn_ctx->auth.authType                                      = auth_type;
    nx_conn_ctx->auth.ctx.symmAuth.dyn_ctx.selectedSecureTunnelType = secure_tunnel_type;
    nx_conn_ctx->auth.ctx.symmAuth.dyn_ctx.keyNo                    = key_no;

    if (pcdcap2_flag == true) {
        uint8_t pcdCap2[NX_PCD_CAPABILITIES_LEN] = EX_SYMM_AUTH_PCDCCAP2;
        memcpy(nx_conn_ctx->auth.ctx.symmAuth.static_ctx.PCDCap2, pcdCap2, sizeof(pcdCap2));
        nx_conn_ctx->auth.ctx.symmAuth.static_ctx.PCDCap2Len = sizeof(pcdCap2);

#ifdef EX_SSS_PCDCAP2_FILE_PATH
        uint8_t file_pcdcap2[NX_PCD_CAPABILITIES_LEN] = {0};
        // read pcdcap2 value from FS
        status = get_pcdcap2_val_from_fs(&file_pcdcap2[0], sizeof(file_pcdcap2));
        if (status == kStatus_SSS_Success) {
            memcpy(nx_conn_ctx->auth.ctx.symmAuth.static_ctx.PCDCap2, file_pcdcap2, sizeof(file_pcdcap2));
            nx_conn_ctx->auth.ctx.symmAuth.static_ctx.PCDCap2Len = sizeof(file_pcdcap2);
        }
#endif // EX_SSS_PCDCAP2_FILE_PATH
    }

    status = kStatus_SSS_Success;
exit:
    return status;
}

#endif // SSS_HAVE_NX_TYPE
