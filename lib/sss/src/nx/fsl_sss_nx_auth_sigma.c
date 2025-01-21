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
#include "nx_apdu.h"
#include "fsl_sss_nx_auth_types.h"
#include "fsl_sss_util_asn1_der.h"
#include "ex_sss_boot.h"

/* *****************************************************************************************************************
* Internal Definitions
* ***************************************************************************************************************** */
#define EX_SIGMA_I_AUTH_ECC_KEY_SIZE 256
#ifndef MAKE_TEST_ID
#define MAKE_TEST_ID(ID) (0xEF000000u + ID)
#endif /* MAKE_TEST_ID */

#if defined(_MSC_VER)
#define OS_PATH_SEPARATOR "\\"
#else
#define OS_PATH_SEPARATOR "/"
#endif

#define EX_LEAF_CERT_KEYPAIR_FILE "host_leaf_keypair.der"

/* *****************************************************************************************************************
* Functions Prototypes
* ***************************************************************************************************************** */

sss_status_t nx_prepare_host_for_auth_key_symm_auth(
    nx_auth_symm_ctx_t *pAuthCtx, sss_key_store_t *pKs, nx_connect_ctx_t *nx_conn_ctx);

sss_status_t ex_find_hash_in_cache(uint8_t *pCertHashBuf, size_t certHashBufLen, int *found);

sss_status_t ex_get_pk_from_cache(int index, uint8_t *pPublicKeyBuf, size_t *pPublicKeyBufLen);

sss_status_t ex_insert_hash_pk_to_cache(
    uint8_t *pCertHashBuf, size_t certHashBufLen, uint8_t *publicKey, size_t publicKeyLen);

sss_status_t ex_get_parent_cert_from_cache(int index, uint8_t *pCertBuf, size_t *pCertBufLen);

sss_status_t ex_parent_cert_cache_insert(uint8_t *pCertBuf, size_t certBufLen);

/* *****************************************************************************************************************
* Functions
* ***************************************************************************************************************** */

#ifdef EX_SSS_SIGMA_I_CERT_INCLUDE_DIR

sss_status_t ex_sss_read_file_from_fs(char *fileName, uint8_t *buffer, size_t *bufferLen)
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

    if (strstr(fileName, "..") != NULL) {
        LOG_W("Potential directory traversal");
    }

    maxBufLen = *bufferLen;
    if ((fp = fopen(fileName, "rb")) != NULL) {
        memset(buffer, 0, maxBufLen);
        fileSize = fread(buffer, sizeof(char), maxBufLen, fp);

        if ((fileSize == 0) || ferror(fp)) { /* fread failed */
            LOG_E("Error reading cert from %s", fileName);
            ret = fclose(fp);
            if (ret != 0) {
                LOG_E("fclose error");
            }
            goto exit;
        }
        else { /* fread success */
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

sss_status_t ex_sss_write_file_to_fs(const char *fileName, uint8_t *certBuf, size_t certLen)
{
    sss_status_t status = kStatus_SSS_Fail;
    FILE *fp            = NULL;
    size_t fileSize     = 0;

    if ((fileName == NULL) || (certBuf == NULL)) {
        LOG_E("Write to files with invalid parameters");
        goto exit;
    }

    if (strstr(fileName, "..") != NULL) {
        LOG_W("Potential directory traversal");
    }

    if ((fp = fopen(fileName, "wb")) != NULL) {
        fileSize = fwrite(certBuf, sizeof(char), certLen, fp);

        if (0 == ferror(fp)) { /* fwrite success */
            if (fileSize == certLen) {
                LOG_D("Number of characters written = %i\n", fileSize);
            }
            else {
                LOG_E("fwrite success but all characters not written!");
                goto exit;
            }
        }
        else { /* fwrite failed */
            LOG_E("Error writing to file %s", fileName);
            goto exit;
        }
    }
    else {
        LOG_W("Can not open file from %s", fileName);
        goto exit;
    }

    status = kStatus_SSS_Success;

exit:
    if (fp != NULL) {
        if (0 != fclose(fp)) {
            LOG_E("Error in fclose");
        }
    }
    return status;
}

static sss_status_t ex_sss_get_full_path_file_name(
    char *dirName, char *fileName, sss_cipher_type_t curveType, char *fullPathFileName)
{
    sss_status_t status = kStatus_SSS_Fail;
    int ret             = -1;

    ENSURE_OR_GO_EXIT(dirName != NULL);
    ENSURE_OR_GO_EXIT(fileName != NULL);
    ENSURE_OR_GO_EXIT((curveType == kSSS_CipherType_EC_BRAINPOOL) || (curveType == kSSS_CipherType_EC_NIST_P));
    ENSURE_OR_GO_EXIT(strlen(dirName) < EX_MAX_INCLUDE_DIR_LENGTH);
    ENSURE_OR_GO_EXIT(strlen(fileName) < EX_MAX_EXTRA_FILE_NAME_LENGTH);

    if (curveType == kSSS_CipherType_EC_BRAINPOOL) {
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

bool ex_sss_nx_dir_exists(const char *pathname)
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

#endif

#if SSS_HAVE_HOSTCRYPTO_ANY
static sss_status_t ex_sss_nx_default_host_keypair(sss_cipher_type_t curveType, uint8_t *buffer, size_t *bufferLen)
{
    sss_status_t status = kStatus_SSS_Fail;

    ENSURE_OR_GO_EXIT(buffer != NULL);
    ENSURE_OR_GO_EXIT(bufferLen != NULL);
    ENSURE_OR_GO_EXIT((curveType == kSSS_CipherType_EC_BRAINPOOL) || (curveType == kSSS_CipherType_EC_NIST_P));

    if (curveType == kSSS_CipherType_EC_BRAINPOOL) {
#ifdef EX_SSS_SIGMA_I_BRAINPOOL256_HOST_LEAF_KEYPAIR
        uint8_t keyPairBP256[] = EX_SSS_SIGMA_I_BRAINPOOL256_HOST_LEAF_KEYPAIR;
        ENSURE_OR_GO_EXIT(*bufferLen >= sizeof(keyPairBP256));
        memcpy(buffer, keyPairBP256, sizeof(keyPairBP256));
        *bufferLen = sizeof(keyPairBP256);
#else
        LOG_E("EX_SSS_SIGMA_I_BRAINPOOL256_HOST_LEAF_KEYPAIR not defined");
        goto exit;
#endif
    }
    else {
#ifdef EX_SSS_SIGMA_I_NISTP256_HOST_LEAF_KEYPAIR
        uint8_t keyPairNistp256[] = EX_SSS_SIGMA_I_NISTP256_HOST_LEAF_KEYPAIR;
        ENSURE_OR_GO_EXIT(*bufferLen >= sizeof(keyPairNistp256));
        memcpy(buffer, keyPairNistp256, sizeof(keyPairNistp256));
        *bufferLen = sizeof(keyPairNistp256);
#else
        LOG_E("EX_SSS_SIGMA_I_NISTP256_HOST_LEAF_KEYPAIR not defined");
        goto exit;
#endif
    }

#if defined(EX_SSS_SIGMA_I_BRAINPOOL256_HOST_LEAF_KEYPAIR) || defined(EX_SSS_SIGMA_I_NISTP256_HOST_LEAF_KEYPAIR)
    status = kStatus_SSS_Success;
#endif

exit:
    return status;
}

static sss_status_t ex_sss_nx_get_host_leaf_keypair(sss_cipher_type_t curveType, uint8_t *buffer, size_t *bufferLen)
{
    sss_status_t status = kStatus_SSS_Fail;
    size_t maxBuffLen   = 0;

#ifdef EX_SSS_SIGMA_I_CERT_INCLUDE_DIR
    char *fileName                                                             = EX_LEAF_CERT_KEYPAIR_FILE;
    char *cert_key_path_env                                                    = NULL;
    char fullPathFileName[EX_MAX_INCLUDE_DIR_LENGTH + EX_MAX_EXTRA_DIR_LENGTH] = {0};

#if defined(_MSC_VER)
    size_t sz = 0;
    _dupenv_s(&cert_key_path_env, &sz, EX_SSS_SIGMA_I_CERT_PATH_ENV_VAR);
#else
    cert_key_path_env = getenv(EX_SSS_SIGMA_I_CERT_PATH_ENV_VAR);
#endif //_MSC_VER

    ENSURE_OR_GO_EXIT(buffer != NULL);
    ENSURE_OR_GO_EXIT(bufferLen != NULL);

    maxBuffLen = *bufferLen;

    if (cert_key_path_env != NULL) {
        // Get file from Path indicated by ENV
        LOG_I("Using certificate/key from:'%s' (ENV=%s)", cert_key_path_env, EX_SSS_SIGMA_I_CERT_PATH_ENV_VAR);

        status = ex_sss_get_full_path_file_name(cert_key_path_env, fileName, curveType, fullPathFileName);
        ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

        status = ex_sss_read_file_from_fs(fullPathFileName, buffer, &maxBuffLen);
#if defined(_MSC_VER)
        if (cert_key_path_env) {
            free(cert_key_path_env);
        }
#endif //_MSC_VER
    }
    else if (ex_sss_nx_dir_exists(EX_SSS_SIGMA_I_CERT_INCLUDE_DIR) == true) {
        LOG_I(
            "Using certificate/key from:'%s' (Default path). "
            "You can specify certificates/keys file using ENV=%s",
            EX_SSS_SIGMA_I_CERT_INCLUDE_DIR,
            EX_SSS_SIGMA_I_CERT_PATH_ENV_VAR);

        status = ex_sss_get_full_path_file_name(EX_SSS_SIGMA_I_CERT_INCLUDE_DIR, fileName, curveType, fullPathFileName);
        ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

        status = kStatus_SSS_Fail;
        status = ex_sss_read_file_from_fs(fullPathFileName, buffer, &maxBuffLen);
        ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);
    }
    else {
        // Get default value.
        LOG_I(
            "Using certificate/key from lib/sss/inc/fsl_sss_nx_auth_keys.h "
            "(cert_depth3_x509_rev1)");
        status = ex_sss_nx_default_host_keypair(curveType, buffer, &maxBuffLen);
        ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);
    }
#else

    ENSURE_OR_GO_EXIT(buffer != NULL);
    ENSURE_OR_GO_EXIT(bufferLen != NULL);

    maxBuffLen = *bufferLen;

    // Get default value.
    LOG_I(
        "Using certificate/key from lib/sss/inc/fsl_sss_nx_auth_keys.h "
        "(cert_depth3_x509_rev1)");
    status = ex_sss_nx_default_host_keypair(curveType, buffer, &maxBuffLen);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);
#endif

    *bufferLen = maxBuffLen;
exit:
    return status;
}

static sss_status_t ex_sss_nx_load_host_keypair(
    nx_auth_sigma_ctx_t *pAuthCtx, sss_key_store_t *pKs, sss_cipher_type_t host_cert_curve_type)
{
    sss_status_t status                                        = kStatus_SSS_Fail;
    uint8_t hostKeyPairBuffer[NX_MAX_HOST_KEYPAIR_BUFFER_SIZE] = {0}; // Buffer for host keypair.
    size_t hostKeyPairBufferLen                                = 0;

    if ((pAuthCtx == NULL) || (pKs == NULL)) {
        LOG_E("Invalid parameters");
        goto exit;
    }

    // Read host leaf keypair.
    hostKeyPairBufferLen = sizeof(hostKeyPairBuffer);
    status = ex_sss_nx_get_host_leaf_keypair(host_cert_curve_type, hostKeyPairBuffer, &hostKeyPairBufferLen);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);
    status = kStatus_SSS_Fail;

    if (hostKeyPairBufferLen == 0) {
        LOG_E("No host leaf keypair available");
        goto exit;
    }
    else {
        status = sss_host_key_store_set_key(
            pKs, &pAuthCtx->static_ctx.leafCertKeypair, hostKeyPairBuffer, hostKeyPairBufferLen, 256, NULL, 0);
    }

exit:
    return status;
}

static sss_status_t nx_auth_init_alloc_keypair(
    sss_object_t *keyObject, sss_key_store_t *pKs, uint32_t keyId, sss_cipher_type_t cipherType)
{
    sss_status_t status = kStatus_SSS_Fail;

    status = sss_host_key_object_init(keyObject, pKs);
    ENSURE_OR_GO_EXIT(kStatus_SSS_Success == status)

    status = sss_host_key_object_allocate_handle(
        keyObject, keyId, kSSS_KeyPart_Pair, cipherType, EX_SIGMA_I_AUTH_ECC_KEY_SIZE / 8, kKeyObject_Mode_Transient);
exit:
    return status;
}

/* Function to Set Init and Allocate static keys and Init Allocate dynamic keys */
sss_status_t nx_prepare_host_for_auth_key_sigma_i(nx_auth_sigma_ctx_t *pAuthCtx,
    sss_key_store_t *pKs,
    sss_cipher_type_t host_cert_curve_type,
    sss_cipher_type_t host_ephem_curve_type)
{
    sss_status_t status = kStatus_SSS_Fail;

    if ((pAuthCtx == NULL) || (pKs == NULL)) {
        return status;
    }

    nx_auth_sigma_static_ctx_t *pStatic_ctx = &(pAuthCtx->static_ctx);
    nx_auth_sigma_dynamic_ctx_t *pDyn_ctx   = &(pAuthCtx->dyn_ctx);

    /* Init Allocate leaf cert Key */
    status =
        nx_auth_init_alloc_keypair(&pStatic_ctx->leafCertKeypair, pKs, MAKE_TEST_ID(__LINE__), host_cert_curve_type);
    if (status != kStatus_SSS_Success) {
        return status;
    }

    /* Get leaf cert Key and set keyobject */
    status = ex_sss_nx_load_host_keypair(pAuthCtx, pKs, host_cert_curve_type);
    if (status != kStatus_SSS_Success) {
        return status;
    }

    /* Init Allocate Ephemeral Key */
    status = nx_auth_init_alloc_keypair(&pStatic_ctx->ephemKeypair, pKs, MAKE_TEST_ID(__LINE__), host_ephem_curve_type);
    if (status != kStatus_SSS_Success) {
        return status;
    }

    /* Generate Ephemeral Key */
    status = sss_host_key_store_generate_key(pKs, &pStatic_ctx->ephemKeypair, EX_SIGMA_I_AUTH_ECC_KEY_SIZE, 0);
    if (status != kStatus_SSS_Success) {
        return status;
    }

    /* Init Allocate SE Ephemeral Key */
    status = sss_host_key_object_init(&pStatic_ctx->seEphemPubKey, pKs);
    if (status != kStatus_SSS_Success) {
        return status;
    }

    status = sss_host_key_object_allocate_handle(&pStatic_ctx->seEphemPubKey,
        MAKE_TEST_ID(__LINE__),
        kSSS_KeyPart_Public,
        host_ephem_curve_type, // host and se ephermeral key should use same curve type.
        EX_SIGMA_I_AUTH_ECC_KEY_SIZE / 8,
        kKeyObject_Mode_Transient);
    if (status != kStatus_SSS_Success) {
        return status;
    }
    /* Init SE leaf cert public key. Allocate will be done after received the leaf cert */
    status = sss_host_key_object_init(&pStatic_ctx->seLeafCertPubKey, pKs);
    if (status != kStatus_SSS_Success) {
        return status;
    }

    /* Init Allocate AES256 CMAC KDF Key. Allocate will be done when AES128/256 is decided. */
    status = sss_host_key_object_init(&pDyn_ctx->kdfCmac, pKs);
    if (status != kStatus_SSS_Success) {
        return status;
    }

    /* Init Encryption/Decryption key. Allocate will be done when AES128/256 is decided. */
    status = sss_host_key_object_init(&pDyn_ctx->k_e1, pKs);
    if (status != kStatus_SSS_Success) {
        return status;
    }

    status = sss_host_key_object_init(&pDyn_ctx->k_m1, pKs);
    if (status != kStatus_SSS_Success) {
        return status;
    }

    status = sss_host_key_object_init(&pDyn_ctx->k_e2, pKs);
    if (status != kStatus_SSS_Success) {
        return status;
    }

    status = sss_host_key_object_init(&pDyn_ctx->k_m2, pKs);
    return status;
}
#endif // SSS_HAVE_HOSTCRYPTO_ANY

sss_status_t nx_init_conn_context_sigma_auth(nx_connect_ctx_t *nx_conn_ctx,
    nx_auth_type_t auth_type,
    nx_secure_symm_type_t secure_tunnel_type,
    sss_cipher_type_t host_cert_curve_type,
    sss_cipher_type_t host_ephem_curve_type,
    auth_cache_type_t cache_type,
    auth_compress_type_t compress_type,
    uint8_t se_cert_repo_id,
    uint16_t cert_ac_map)
{
    sss_status_t status = kStatus_SSS_Fail;

    if (nx_conn_ctx == NULL) {
        LOG_E("Init authentication with invalid parameters");
        goto exit;
    }

    nx_conn_ctx->auth.authType                                        = auth_type;
    nx_conn_ctx->auth.ctx.sigmai.dyn_ctx.authType                     = auth_type;
    nx_conn_ctx->auth.ctx.sigmai.dyn_ctx.selectedSecureTunnelType     = secure_tunnel_type;
    nx_conn_ctx->auth.ctx.sigmai.dyn_ctx.hostCacheType                = cache_type;
    nx_conn_ctx->auth.ctx.sigmai.dyn_ctx.hostCompressType             = compress_type;
    nx_conn_ctx->auth.ctx.sigmai.dyn_ctx.hostEphemCurveType           = host_ephem_curve_type;
    nx_conn_ctx->auth.ctx.sigmai.dyn_ctx.certACMap                    = cert_ac_map;
    nx_conn_ctx->auth.ctx.sigmai.static_ctx.supportedSecureTunnelType = secure_tunnel_type;
    nx_conn_ctx->auth.ctx.sigmai.static_ctx.hostCertCurveType         = host_cert_curve_type;
    nx_conn_ctx->auth.ctx.sigmai.static_ctx.seCertRepoId              = se_cert_repo_id;

    status = kStatus_SSS_Success;
exit:
    return status;
}

#endif //#if SSS_HAVE_NX_TYPE
