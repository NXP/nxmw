/*
 *
 * Copyright 2023-2024 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 */

/* ************************************************************************** */
/* Includes                                                                   */
/* ************************************************************************** */
#include <ex_sss_boot.h>
#include <nxEnsure.h>
#include <nxLog_msg.h>
#include <string.h>
#include <openssl/pem.h>
#include <nx_apdu.h>
#include <nx_apdu_tlv.h>
#include <nx_enums.h>

/* ************************************************************************** */
/* Local Defines                                                              */
/* ************************************************************************** */
#define EC_KEY_BIT_LEN 256
#define MAX_PATH 200
#define PRIV_KEY_ID 2

#if defined(__linux__)
#define PRV_KEY_FILE "credentials/nx_device_key.pem"
#define OS_PATH_SEPARATOR '/'
#else
#define PRV_KEY_FILE "credentials\\nx_device_key.pem"
#define OS_PATH_SEPARATOR '\\'
#endif

#define PRIV_KEY_CIPHER_TYPE kSSS_CipherType_EC_NIST_P

/* ************************************************************************** */
/* Structures and Typedefs                                                    */
/* ************************************************************************** */

/* ************************************************************************** */
/* Global Variables                                                           */
/* ************************************************************************** */
static ex_sss_boot_ctx_t gex_sss_provision_client_ctx;

/* ************************************************************************** */
/* Static function declarations                                               */
/* ************************************************************************** */

/* ************************************************************************** */
/* Private Functions                                                          */
/* ************************************************************************** */

/* ************************************************************************** */
/* Public Functions                                                           */
/* ************************************************************************** */

#define EX_SSS_BOOT_PCONTEXT (&gex_sss_provision_client_ctx)
#define EX_SSS_BOOT_EXPOSE_ARGC_ARGV 0

#include <ex_sss_main_inc.h>

sss_status_t get_file_path(char *prvKeyFilePath, const char *fileName, size_t fileNameLen)
{
    int cwdIndex = -1;
    for (size_t i = 0; i < sizeof(__FILE__); i++) {
        if (__FILE__[i] == OS_PATH_SEPARATOR) {
            cwdIndex = i;
        }
    }
    if (cwdIndex == -1) {
        LOG_E("Looks like you are in the root directory!");
        return kStatus_SSS_Fail;
    }
    size_t pathLen = 0;
    for (int i = 0; i < cwdIndex + 1; i++) {
        prvKeyFilePath[pathLen++] = __FILE__[i];
    }
    for (size_t i = 0; i < fileNameLen; i++) {
        prvKeyFilePath[pathLen++] = fileName[i];
    }
    LOG_I("FILE PATH %s", prvKeyFilePath);
    return kStatus_SSS_Success;
}

sss_status_t ex_sss_entry(ex_sss_boot_ctx_t *pCtx)
{
    sss_status_t status        = kStatus_SSS_Success;
    smStatus_t sm_status       = SM_NOT_OK;
    sss_nx_session_t *pSession = NULL;
    uint8_t prvKey[32]         = {0};
    size_t prvKeyLen           = sizeof(prvKey);
    sss_object_t keyObject     = {0};

    sss_policy_u keyGenPolicy     = {.type = KPolicy_GenECKey,
        .policy                        = {.genEcKey = {
                       .sdmEnabled      = 0,
                       .sigmaiEnabled   = 0,
                       .ecdhEnabled     = 0,
                       .eccSignEnabled  = 1,
                       .writeCommMode   = kCommMode_SSS_Full,
                       .writeAccessCond = Nx_AccessCondition_Auth_Required_0x1,
                       .userCommMode    = kCommMode_SSS_NA,
                   }}};
    sss_policy_t keyGenPolicyList = {.nPolicies = 1, .policies = {&keyGenPolicy}};
    FILE *fpPrvKeyFile            = NULL;
    char prvKeyFilePath[MAX_PATH];
    char *name         = NULL;
    char *header       = NULL;
    uint8_t *prvKeyDer = NULL;
    long prvKeyDerLen  = 0;
    size_t i           = 0;
    int pemReadStatus;

    LOG_I("Running ex_aws_provision_client");
    ENSURE_OR_GO_CLEANUP(NULL != pCtx);
    pSession = (sss_nx_session_t *)&pCtx->session;

    /* Reading private key from tls_client.pem */
    status = get_file_path(prvKeyFilePath, PRV_KEY_FILE, sizeof(PRV_KEY_FILE));
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    fpPrvKeyFile = fopen(prvKeyFilePath, "r");
    if (fpPrvKeyFile == NULL) {
        status = kStatus_SSS_Fail;
        LOG_E("Private key file not found!");
        goto cleanup;
    }
    pemReadStatus = PEM_read(fpPrvKeyFile, &name, &header, &prvKeyDer, &prvKeyDerLen);
    if (pemReadStatus != 1) {
        status = kStatus_SSS_Fail;
        LOG_E("Error reading private key file!");
        goto cleanup;
    }

    if (prvKeyDerLen < (32 /*private key length*/ + 7 /*header*/)) {
        status = kStatus_SSS_Fail;
        LOG_E("Buffer does not contain private key!");
        goto cleanup;
    }
    else {
        LOG_I("Private key read.");
    }

    for (i = 0; i < prvKeyLen; i++) {
        prvKey[i] = prvKeyDer[i + 7];
    }
    if (prvKeyDer != NULL) {
        OPENSSL_free(prvKeyDer);
    }

    /* Storing the read private key */
    status = sss_key_object_init(&keyObject, &pCtx->ks);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_key_object_allocate_handle(&keyObject,
        PRIV_KEY_ID,
        kSSS_KeyPart_Private,
        PRIV_KEY_CIPHER_TYPE,
        EC_KEY_BIT_LEN,
        kKeyObject_Mode_Persistent);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    LOG_MAU8_I("----------Private key---------\n", prvKey, prvKeyLen);

    status = sss_key_store_set_key(
        &pCtx->ks, &keyObject, prvKey, prvKeyLen, EC_KEY_BIT_LEN, &keyGenPolicyList, sizeof(keyGenPolicyList));
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

cleanup:
    if (kStatus_SSS_Success == status) {
        LOG_I("ex_tls_provision_client Example Success !!!...");
    }
    else {
        LOG_E("ex_tls_provision_client Example Failed !!!...");
    }
    if (fpPrvKeyFile != NULL) {
        if (0 != fclose(fpPrvKeyFile)) {
            LOG_W("Failed to close the file handle");
        }
    }
    if (keyObject.keyStore != NULL) {
        sss_key_object_free(&keyObject);
    }
    if (name != NULL) {
        OPENSSL_free(name);
    }
    if (header != NULL) {
        OPENSSL_free(header);
    }

    return status;
}
