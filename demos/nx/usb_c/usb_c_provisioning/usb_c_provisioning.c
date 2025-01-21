/*
 *
 * Copyright 2023-2024 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 */

/*******************************************************************
* Header Files
*******************************************************************/
#if defined(SSS_USE_FTR_FILE)
#include "fsl_sss_ftr.h"
#else
#include "fsl_sss_ftr_default.h"
#endif

#include "usb_c_provisioning.h"
#include "fsl_sss_api.h"
#include "fsl_sss_nx_apis.h"
#include "sm_types.h"
#include "nxLog_msg.h"
#include "ex_sss_boot.h"
#include "nx_apdu.h"
#include "nx_enums.h"

static ex_sss_boot_ctx_t gex_usb_c_provisioning_ctx;

#define EX_SSS_BOOT_PCONTEXT (&gex_usb_c_provisioning_ctx)
#define EX_SSS_BOOT_EXPOSE_ARGC_ARGV 0

/* ************************************************************************** */
/* Include "main()" with the platform specific startup code for Plug & Trust  */
/* MW examples which will call ex_sss_entry()                                 */
/* ************************************************************************** */
#include <ex_sss_main_inc.h>

/*******************************************************************
* Static Functions
*******************************************************************/
static sss_status_t add_usb_c_private_key(
    sss_key_store_t *pKs, const uint8_t *keyBuff, size_t keyBuffSize, uint8_t slot_id);
static smStatus_t add_usb_c_certificate(sss_session_t *pSession,
    const uint8_t *hashBuff,
    size_t hashBuffSize,
    const uint8_t *certBuff,
    size_t certBuffSize,
    uint8_t slot_id);

sss_status_t ex_sss_entry(ex_sss_boot_ctx_t *pCtx)
{
    sss_status_t status  = kStatus_SSS_Fail;
    smStatus_t sm_status = SM_NOT_OK;

    if (pCtx == NULL) {
        LOG_E("Invalid pointer");
        goto exit;
    }

    status = add_usb_c_private_key(&(pCtx->ks), usb_c_ec_priv_key, usb_c_ec_priv_key_len, USB_C_PROVISIONING_SLOT_ID);
    if (status != kStatus_SSS_Success) {
        LOG_E("Failed to store USB-C private key");
        goto exit;
    }

    sm_status = add_usb_c_certificate(&(pCtx->session),
        usb_c_certificate_chain_hash,
        usb_c_certificate_chain_hash_len,
        usb_c_certificate_chain,
        usb_c_certificate_chain_len,
        USB_C_PROVISIONING_SLOT_ID);
    if (sm_status != SM_OK) {
        LOG_E("Failed to store USB-C certificate chain");
        goto exit;
    }

    LOG_I("USB-C Provisioning Example Success !!!...");
exit:
    LOG_I("USB-C Provisioning Example Finished");
    return status;
}

static sss_status_t add_usb_c_private_key(
    sss_key_store_t *pKs, const uint8_t *keyBuff, size_t keyBuffSize, uint8_t slot_id)
{
    sss_status_t status             = kStatus_SSS_Fail;
    sss_object_t private_key        = {0};
    uint32_t key_id                 = USB_C_SLOT_ID_TO_KEY_ID(slot_id);
    const sss_policy_u keyGenPolicy = {.type = KPolicy_GenECKey,
        .policy                              = {.genEcKey = {
                       .sdmEnabled      = 0,
                       .sigmaiEnabled   = 0,
                       .ecdhEnabled     = 0,
                       .eccSignEnabled  = 1,
                       .writeCommMode   = kCommMode_SSS_Full,
                       .writeAccessCond = Nx_AccessCondition_Auth_Required_0x0,
                       .userCommMode    = kCommMode_SSS_NA,
                   }}};
    sss_policy_t policy_for_ec_key  = {.nPolicies = 1, .policies = {&keyGenPolicy}};

    if (pKs == NULL) {
        LOG_E("Add private key with wrong parameter!!!");
        goto exit;
    }

    status = sss_key_object_init(&private_key, pKs);
    if (status != kStatus_SSS_Success) {
        LOG_I("sss_key_object_init failed");
        goto exit;
    }

    status = sss_key_object_allocate_handle(
        &private_key, key_id, kSSS_KeyPart_Private, kSSS_CipherType_EC_NIST_P, keyBuffSize, kKeyObject_Mode_Persistent);
    if (status != kStatus_SSS_Success) {
        LOG_E("sss_key_object_allocate_handle failed");
        goto exit;
    }

    status = sss_key_store_set_key(
        pKs, &private_key, keyBuff, keyBuffSize, 256, &policy_for_ec_key, sizeof(policy_for_ec_key));
    if (status != kStatus_SSS_Success) {
        LOG_E("sss_key_store_set_key failed");
    }
exit:
    return status;
}

static smStatus_t add_usb_c_certificate(sss_session_t *pSession,
    const uint8_t *hashBuff,
    size_t hashBuffSize,
    const uint8_t *certBuff,
    size_t certBuffSize,
    uint8_t slot_id)
{
    smStatus_t retStatus        = SM_NOT_OK;
    uint8_t fileNo              = USB_C_SLOT_ID_TO_CERT_FILE_ID(USB_C_PROVISIONING_SLOT_ID);
    uint16_t isoFileID          = USB_C_SLOT_ID_TO_CERT_ISO_FILE_ID(USB_C_PROVISIONING_SLOT_ID);
    uint8_t fileReadAccess      = Nx_AccessCondition_Auth_Required_0x0;
    uint8_t fileWriteAccess     = Nx_AccessCondition_Auth_Required_0x0;
    uint8_t fileReadWriteAccess = Nx_AccessCondition_Auth_Required_0x0;
    uint8_t fileChangeAccess    = Nx_AccessCondition_Auth_Required_0x0;
    uint8_t fileOption          = Nx_CommMode_FULL;
    pSeSession_t session_ctx    = NULL;

    uint8_t fIDList[NX_FILE_ID_LIST_SIZE] = {0};
    size_t fIDListLen                     = 0;
    bool fileExists                       = false;
    size_t i                              = 0;

    if (usb_c_certificate_chain_len > (SIZE_MAX - usb_c_certificate_chain_hash_len)) {
        LOG_E("Certificate chain length and ceritificate hash length add up to a very large value!!!");
        goto exit;
    }
    size_t fileSize    = usb_c_certificate_chain_len + usb_c_certificate_chain_hash_len;
    size_t writeOffset = 0;

    if (pSession == NULL) {
        LOG_E("Add certificate with wrong parameter!!!");
        goto exit;
    }

    /*Create file with the defined parameters*/
    session_ctx = &((sss_nx_session_t *)pSession)->s_ctx;

    if (session_ctx->authType == knx_AuthType_SYMM_AUTH) {
        if (session_ctx->ctx.pdynSymmAuthCtx != NULL) {
            fileReadAccess      = session_ctx->ctx.pdynSymmAuthCtx->keyNo;
            fileWriteAccess     = session_ctx->ctx.pdynSymmAuthCtx->keyNo;
            fileChangeAccess    = session_ctx->ctx.pdynSymmAuthCtx->keyNo;
            fileReadWriteAccess = session_ctx->ctx.pdynSymmAuthCtx->keyNo;
            LOG_W("fileReadAccess, fileWriteAccess, fileChangeAccess, fileReadWriteAccess values are overwritten");
        }
        else {
            LOG_E("Invalid symm auth context !!!");
        }
    }
    // Check if the file exists
    retStatus = nx_GetFileIDs(&((sss_nx_session_t *)pSession)->s_ctx, fIDList, &fIDListLen);
    if ((fIDListLen > NX_FILE_ID_LIST_SIZE) || (retStatus != SM_OK)) {
        goto exit;
    }

    for (i = 0; i < fIDListLen; i++) {
        if (fileNo == fIDList[i]) {
            fileExists = true;
            break;
        }
    }

    if (fileExists == false) {
        retStatus = nx_CreateStdDataFile(&((sss_nx_session_t *)pSession)->s_ctx,
            fileNo,
            isoFileID,
            fileOption,
            fileSize,
            fileReadAccess,
            fileWriteAccess,
            fileReadWriteAccess,
            fileChangeAccess);
        if (retStatus != SM_OK) {
            LOG_E("File creation failed!!!");
            goto exit;
        }
    }
    else {
        LOG_I("File already exist !!!");
    }

    retStatus = nx_WriteData(&((sss_nx_session_t *)pSession)->s_ctx,
        fileNo,
        writeOffset,
        (uint8_t *)usb_c_certificate_chain_hash,
        usb_c_certificate_chain_hash_len,
        Nx_CommMode_NA);
    if (retStatus != SM_OK) {
        LOG_E("File write certificate hash failed!!!");
        goto exit;
    }

    writeOffset += usb_c_certificate_chain_hash_len;
    retStatus = nx_WriteData(&((sss_nx_session_t *)pSession)->s_ctx,
        fileNo,
        writeOffset,
        (uint8_t *)usb_c_certificate_chain,
        usb_c_certificate_chain_len,
        Nx_CommMode_NA);
    if (retStatus != SM_OK) {
        LOG_E("File write certificate chain failed!!!");
        goto exit;
    }

exit:
    return retStatus;
}
