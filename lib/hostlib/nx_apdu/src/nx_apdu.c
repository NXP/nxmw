/*
 *
 * Copyright 2022-2024 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 */

#if defined(SSS_USE_FTR_FILE)
#include "fsl_sss_ftr.h"
#else
#include "fsl_sss_ftr_default.h"
#endif

#include <stdio.h>
#include <limits.h>
#include <string.h>
#include "nxLog_msg.h"
#include "nxEnsure.h"
#include "nx_apdu.h"

#define NEWLINE() printf("\r\n")

static smStatus_t ecc_existing_key_commMode(
    pSeSession_t session_ctx, uint8_t keyId, bool *found, nx_ev2_comm_mode_t *commMode);

static smStatus_t ca_root_existing_key_commMode(
    pSeSession_t session_ctx, uint8_t keyId, bool *found, nx_ev2_comm_mode_t *commMode);

static smStatus_t secure_messaging_get_commMode(
    pSeSession_t session_ctx, uint8_t cmdByte, nx_ev2_comm_mode_t *commMode, void *options);

static uint16_t swap_uint16(uint8_t *input);

static uint32_t swap_uint32(uint8_t *input);

static Nx_CommMode_t commMode_convert(nx_ev2_comm_mode_t ev2CommMode);

static uint16_t swap_uint16(uint8_t *input)
{
    uint16_t outputData = 0;

    if (input != NULL) {
        outputData = *input;
        outputData |= (*(input + 1)) << 8;
    }
    else {
        LOG_E("Fail to swap uint16.");
        outputData = 0;
    }

    return outputData;
}

static uint32_t swap_uint32(uint8_t *input)
{
    uint32_t outputData = 0;

    if (input != NULL) {
        outputData = *input;
        outputData |= (*(input + 1)) << 8;
        outputData |= (*(input + 2)) << 16;
        outputData |= (*(input + 3)) << 24;
    }
    else {
        LOG_E("Fail to swap uint32.");
        outputData = 0;
    }

    return outputData;
}

static Nx_CommMode_t commMode_convert(nx_ev2_comm_mode_t ev2CommMode)
{
    if (ev2CommMode == EV2_CommMode_PLAIN) {
        return Nx_CommMode_Plain;
    }
    else if (ev2CommMode == EV2_CommMode_MAC) {
        return Nx_CommMode_MAC;
    }
    else if (ev2CommMode == EV2_CommMode_FULL) {
        return Nx_CommMode_FULL;
    }
    else {
        return Nx_CommMode_NA;
    }
}

static smStatus_t ecc_existing_key_commMode(
    pSeSession_t session_ctx, uint8_t keyId, bool *found, nx_ev2_comm_mode_t *commMode)
{
    smStatus_t retStatus                                                       = SM_NOT_OK;
    nx_ecc_key_meta_data_t eccPrivateKeyList[NX_KEY_SETTING_ECC_KEY_MAX_ENTRY] = {0};
    uint8_t entryCount                                                         = NX_KEY_SETTING_ECC_KEY_MAX_ENTRY;
    uint8_t i                                                                  = 0;

    if ((session_ctx == NULL) || (found == NULL) || (commMode == NULL)) {
        LOG_E("Invalid parameters");
        goto cleanup;
    }

    *found = false;

    retStatus = nx_GetKeySettings_ECCPrivateKeyList(session_ctx, &entryCount, eccPrivateKeyList);
    if (retStatus != SM_OK) {
        LOG_E("nx_GetKeySettings_ECCPrivateKeyList failed");
        goto cleanup;
    }

    for (i = 0; i < entryCount; i++) {
        if (eccPrivateKeyList[i].keyId == keyId) {
            *found = true;
            if (eccPrivateKeyList[i].writeCommMode == Nx_CommMode_FULL) {
                *commMode = EV2_CommMode_FULL;
            }
            else if (eccPrivateKeyList[i].writeCommMode == Nx_CommMode_MAC) {
                *commMode = EV2_CommMode_MAC;
            }
            else if (eccPrivateKeyList[i].writeCommMode == Nx_CommMode_Plain) {
                *commMode = EV2_CommMode_PLAIN;
            }
            else {
                LOG_E("Unknown commMode for the ECC key at %u", keyId);
            }
            break;
        }
    }

    memset(eccPrivateKeyList, 0, sizeof(eccPrivateKeyList));
cleanup:
    return retStatus;
}

static smStatus_t ca_root_existing_key_commMode(
    pSeSession_t session_ctx, uint8_t keyId, bool *found, nx_ev2_comm_mode_t *commMode)
{
    smStatus_t retStatus                                                         = SM_NOT_OK;
    nx_ca_root_key_meta_data_t caRootKeyList[NX_KEY_SETTING_CAROOTKEY_MAX_ENTRY] = {0};
    uint8_t entryCount                                                           = NX_KEY_SETTING_CAROOTKEY_MAX_ENTRY;
    uint8_t i                                                                    = 0;

    if ((session_ctx == NULL) || (found == NULL) || (commMode == NULL)) {
        LOG_E("Invalid parameters");
        goto cleanup;
    }

    *found = false;

    retStatus = nx_GetKeySettings_CARootKeyList(session_ctx, &entryCount, caRootKeyList);
    if (retStatus != SM_OK) {
        LOG_E("nx_GetKeySettings_CARootKeyList failed");
        goto cleanup;
    }

    for (i = 0; i < entryCount; i++) {
        if (caRootKeyList[i].keyId == keyId) {
            *found = true;
            if (caRootKeyList[i].writeCommMode == Nx_CommMode_FULL) {
                *commMode = EV2_CommMode_FULL;
            }
            else if (caRootKeyList[i].writeCommMode == Nx_CommMode_MAC) {
                *commMode = EV2_CommMode_MAC;
            }
            else if (caRootKeyList[i].writeCommMode == Nx_CommMode_Plain) {
                *commMode = EV2_CommMode_PLAIN;
            }
            else {
                LOG_E("Unknown commMode for the CA root key at %u", keyId);
            }
            break;
        }
    }

    memset(caRootKeyList, 0, sizeof(caRootKeyList));
cleanup:
    return retStatus;
}

static smStatus_t secure_messaging_get_commMode(
    pSeSession_t session_ctx, uint8_t cmdByte, nx_ev2_comm_mode_t *commMode, void *options)
{
    smStatus_t retStatus = SM_NOT_OK;
    uint8_t keyAC        = 0;
    uint8_t rootKeyAC    = 0;
    uint8_t *pKeyId      = NULL;
    bool foundKey        = false;
    uint8_t *pFileNo     = NULL;
    uint8_t *action      = NULL;
    uint8_t *repoID      = NULL;

    if ((session_ctx == NULL) || (commMode == NULL)) {
        LOG_E("Invalid parameters");
        goto cleanup;
    }

    switch (cmdByte) {
    case NX_INS_MGMT_KEY_PAIR:
        if (options == NULL) {
            LOG_E("Input Options Parameter is NULL");
            goto cleanup;
        }
        pKeyId = (uint8_t *)options;

        retStatus = ecc_existing_key_commMode(session_ctx, *pKeyId, &foundKey, commMode);
        if (retStatus != SM_OK) {
            goto cleanup;
        }

        if (foundKey == false) {
            // Not existing key, get default CommMode
            retStatus = nx_GetConfig_EccKeyMgmt(session_ctx, &keyAC, &rootKeyAC);
            if (retStatus != SM_OK) {
                LOG_E("nx_GetConfig_EccKeyMgmt failed");
                goto cleanup;
            }
            if (((keyAC & NX_CONF_COMM_MODE_MASK) >> NX_COMM_MODE_BIT_SHIFT) == Nx_CommMode_FULL) {
                *commMode = EV2_CommMode_FULL;
            }
            else if (((keyAC & NX_CONF_COMM_MODE_MASK) >> NX_COMM_MODE_BIT_SHIFT) == Nx_CommMode_MAC) {
                *commMode = EV2_CommMode_MAC;
            }
            else if (((keyAC & NX_CONF_COMM_MODE_MASK) >> NX_COMM_MODE_BIT_SHIFT) == Nx_CommMode_Plain) {
                *commMode = EV2_CommMode_PLAIN;
            }
            else {
                LOG_E("Invalid commMode");
                retStatus = SM_NOT_OK;
            }
        }

        break;

    case NX_INS_MGMT_CA_ROOT_KEY:
        if (options == NULL) {
            LOG_E("Input Options Parameter is NULL");
            goto cleanup;
        }
        pKeyId = (uint8_t *)options;

        retStatus = ca_root_existing_key_commMode(session_ctx, *pKeyId, &foundKey, commMode);
        if (retStatus != SM_OK) {
            goto cleanup;
        }

        if (foundKey == false) {
            // Not existing key, get default CommMode
            retStatus = nx_GetConfig_EccKeyMgmt(session_ctx, &keyAC, &rootKeyAC);
            if (retStatus != SM_OK) {
                LOG_E("nx_GetConfig_EccKeyMgmt failed");
                goto cleanup;
            }
            if (((rootKeyAC & NX_CONF_COMM_MODE_MASK) >> NX_COMM_MODE_BIT_SHIFT) == Nx_CommMode_FULL) {
                *commMode = EV2_CommMode_FULL;
            }
            else if (((rootKeyAC & NX_CONF_COMM_MODE_MASK) >> NX_COMM_MODE_BIT_SHIFT) == Nx_CommMode_MAC) {
                *commMode = EV2_CommMode_MAC;
            }
            else if (((rootKeyAC & NX_CONF_COMM_MODE_MASK) >> NX_COMM_MODE_BIT_SHIFT) == Nx_CommMode_Plain) {
                *commMode = EV2_CommMode_PLAIN;
            }
            else {
                LOG_E("Invalid commMode");
                retStatus = SM_NOT_OK;
            }
        }

        break;

    case NX_INS_READ_DATA:
    case NX_INS_WRITE_DATA:
    case NX_INS_CHANGE_FILE_SETTING: {
        size_t fileSize        = 0;
        Nx_FILEType_t fileType = Nx_FILEType_NA;
        uint8_t fileOption     = NX_FILE_OPTION_SDM_DISBALED | NX_FILE_OPTION_DEFERRED_DISABLED | Nx_CommMode_Plain;
        Nx_AccessCondition_t readAccessCondition      = Nx_AccessCondition_No_Access;
        Nx_AccessCondition_t writeAccessCondition     = Nx_AccessCondition_No_Access;
        Nx_AccessCondition_t readWriteAccessCondition = Nx_AccessCondition_No_Access;
        Nx_AccessCondition_t changeAccessCondition    = Nx_AccessCondition_No_Access;
        nx_file_SDM_config_t sdmConfig                = {0};
        uint8_t readAC = 0, writeAC = 0, readwriteAC = 0, changeAC = 0;

        if (options == NULL) {
            LOG_E("Input Options Parameter is NULL");
            goto cleanup;
        }

        pFileNo   = (uint8_t *)options;
        retStatus = nx_GetFileSettings(session_ctx,
            *pFileNo,
            &fileType,
            &fileOption,
            &readAccessCondition,
            &writeAccessCondition,
            &readWriteAccessCondition,
            &changeAccessCondition,
            &fileSize,
            &sdmConfig);

        if (retStatus != SM_OK) {
            LOG_E("nx_GetFileSettings_StandardData failed");
            goto cleanup;
        }

        readAC      = (uint8_t)readAccessCondition;
        readwriteAC = (uint8_t)readWriteAccessCondition;
        writeAC     = (uint8_t)writeAccessCondition;
        changeAC    = (uint8_t)changeAccessCondition;

        if (cmdByte == NX_INS_READ_DATA) { // Cmd.ReadData
            // Under an active authentication, if the only valid access condition for a certain access right is free access (0xE),
            // CommMode.Plain is to be applied.
            if ((readAC == Nx_AccessCondition_Free_Access) && (readwriteAC == Nx_AccessCondition_Free_Access)) {
                *commMode = EV2_CommMode_PLAIN;
            }
            else if (((session_ctx->authType == knx_AuthType_SIGMA_I_Verifier) ||
                         (session_ctx->authType == knx_AuthType_SIGMA_I_Prover)) &&
                     (session_ctx->ctx.pdynSigICtx->certACMap <= NX_AC_BITMAP_MAX) &&
                     (readAC == Nx_AccessCondition_Free_Access) &&
                     (((session_ctx->ctx.pdynSigICtx->certACMap) & (1 << readwriteAC)) == 0)) {
                *commMode = EV2_CommMode_PLAIN;
            }
            else if (((session_ctx->authType == knx_AuthType_SIGMA_I_Verifier) ||
                         (session_ctx->authType == knx_AuthType_SIGMA_I_Prover)) &&
                     (session_ctx->ctx.pdynSigICtx->certACMap <= NX_AC_BITMAP_MAX) &&
                     ((session_ctx->ctx.pdynSigICtx->certACMap & (1 << readAC)) == 0) &&
                     (readwriteAC == Nx_AccessCondition_Free_Access)) {
                *commMode = EV2_CommMode_PLAIN;
            }
            else if ((session_ctx->authType == knx_AuthType_SYMM_AUTH) &&
                     ((readAC == Nx_AccessCondition_Free_Access) &&
                         ((session_ctx->ctx.pdynSymmAuthCtx->keyNo) != (readwriteAC)))) {
                *commMode = EV2_CommMode_PLAIN;
            }
            else if ((session_ctx->authType == knx_AuthType_SYMM_AUTH) &&
                     ((readwriteAC == Nx_AccessCondition_Free_Access) &&
                         ((session_ctx->ctx.pdynSymmAuthCtx->keyNo) != (readAC)))) {
                *commMode = EV2_CommMode_PLAIN;
            }
            else {
                if ((fileOption & NX_FILE_OPTION_COMM_MODE_MASK) == Nx_CommMode_FULL) {
                    *commMode = EV2_CommMode_FULL;
                }
                else if ((fileOption & NX_FILE_OPTION_COMM_MODE_MASK) == Nx_CommMode_MAC) {
                    *commMode = EV2_CommMode_MAC;
                }
                else if ((fileOption & NX_FILE_OPTION_COMM_MODE_MASK) == Nx_CommMode_Plain) {
                    *commMode = EV2_CommMode_PLAIN;
                }
                else {
                    LOG_E("Invalid file commMode");
                    retStatus = SM_NOT_OK;
                }
            }
        }
        else if (cmdByte == NX_INS_WRITE_DATA) { // Cmd.WriteData
            // Under an active authentication, if the only valid access condition for a certain access right is free access (0xE),
            // CommMode.Plain is to be applied.
            if ((writeAC == Nx_AccessCondition_Free_Access) && (readwriteAC == Nx_AccessCondition_Free_Access)) {
                *commMode = EV2_CommMode_PLAIN;
            }
            else if (((session_ctx->authType == knx_AuthType_SIGMA_I_Verifier) ||
                         (session_ctx->authType == knx_AuthType_SIGMA_I_Prover)) &&
                     (session_ctx->ctx.pdynSigICtx->certACMap <= NX_AC_BITMAP_MAX) &&
                     (writeAC == Nx_AccessCondition_Free_Access) &&
                     ((session_ctx->ctx.pdynSigICtx->certACMap & (1 << readwriteAC)) == 0)) {
                *commMode = EV2_CommMode_PLAIN;
            }
            else if (((session_ctx->authType == knx_AuthType_SIGMA_I_Verifier) ||
                         (session_ctx->authType == knx_AuthType_SIGMA_I_Prover)) &&
                     (session_ctx->ctx.pdynSigICtx->certACMap <= NX_AC_BITMAP_MAX) &&
                     ((session_ctx->ctx.pdynSigICtx->certACMap & (1 << writeAC)) == 0) &&
                     (readwriteAC == Nx_AccessCondition_Free_Access)) {
                *commMode = EV2_CommMode_PLAIN;
            }
            else if ((session_ctx->authType == knx_AuthType_SYMM_AUTH) &&
                     ((writeAC == Nx_AccessCondition_Free_Access) &&
                         ((session_ctx->ctx.pdynSymmAuthCtx->keyNo) != (readwriteAC)))) {
                *commMode = EV2_CommMode_PLAIN;
            }
            else if ((session_ctx->authType == knx_AuthType_SYMM_AUTH) &&
                     ((readwriteAC == Nx_AccessCondition_Free_Access) &&
                         ((session_ctx->ctx.pdynSymmAuthCtx->keyNo) != (writeAC)))) {
                *commMode = EV2_CommMode_PLAIN;
            }
            else {
                if ((fileOption & NX_FILE_OPTION_COMM_MODE_MASK) == Nx_CommMode_FULL) {
                    *commMode = EV2_CommMode_FULL;
                }
                else if ((fileOption & NX_FILE_OPTION_COMM_MODE_MASK) == Nx_CommMode_MAC) {
                    *commMode = EV2_CommMode_MAC;
                }
                else if ((fileOption & NX_FILE_OPTION_COMM_MODE_MASK) == Nx_CommMode_Plain) {
                    *commMode = EV2_CommMode_PLAIN;
                }
                else {
                    LOG_E("Invalid commMode");
                    retStatus = SM_NOT_OK;
                }
            }
        }
        else {
            // Cmd.ChangeFileSettings
            if (changeAC == Nx_AccessCondition_Free_Access) {
                *commMode = EV2_CommMode_PLAIN;
            }
            else {
                *commMode = EV2_CommMode_FULL;
            }
        }

        break;
    }
    case NX_INS_GET_FILE_COUNTERS: {
        Nx_FILEType_t fileType                        = Nx_FILEType_NA;
        uint8_t fileOption                            = 0x00;
        Nx_AccessCondition_t readAccessCondition      = Nx_AccessCondition_No_Access;
        Nx_AccessCondition_t writeAccessCondition     = Nx_AccessCondition_No_Access;
        Nx_AccessCondition_t readWriteAccessCondition = Nx_AccessCondition_No_Access;
        Nx_AccessCondition_t changeAccessCondition    = Nx_AccessCondition_No_Access;

        if (options == NULL) {
            LOG_E("Input Options Parameter is NULL");
            goto cleanup;
        }

        pFileNo   = (uint8_t *)options;
        retStatus = nx_GetFileSettings(session_ctx,
            *pFileNo,
            &fileType,
            &fileOption,
            &readAccessCondition,
            &writeAccessCondition,
            &readWriteAccessCondition,
            &changeAccessCondition,
            NULL,
            NULL);
        if (retStatus != SM_OK) {
            LOG_E("nx_GetFileSettings_Counter failed");
            goto cleanup;
        }

        if (fileType == Nx_FILEType_Standard) {
            *commMode = EV2_CommMode_FULL;
        }
        else { // Counter file
            if ((fileOption & NX_FILE_OPTION_COMM_MODE_MASK) == Nx_CommMode_FULL) {
                *commMode = EV2_CommMode_FULL;
            }
            else if ((fileOption & NX_FILE_OPTION_COMM_MODE_MASK) == Nx_CommMode_MAC) {
                *commMode = EV2_CommMode_MAC;
            }
            else if ((fileOption & NX_FILE_OPTION_COMM_MODE_MASK) == Nx_CommMode_Plain) {
                *commMode = EV2_CommMode_PLAIN;
            }
            else {
                LOG_E("Invalid file commMode");
                retStatus = SM_NOT_OK;
            }
        }
        break;
    }
    case NX_INS_INCREMENT_COUNTER_FILE: {
        Nx_FILEType_t fileType = Nx_FILEType_NA;
        uint8_t fileOption     = NX_FILE_OPTION_SDM_DISBALED | NX_FILE_OPTION_DEFERRED_DISABLED | Nx_CommMode_Plain;
        Nx_AccessCondition_t readAccessCondition      = Nx_AccessCondition_No_Access;
        Nx_AccessCondition_t writeAccessCondition     = Nx_AccessCondition_No_Access;
        Nx_AccessCondition_t readWriteAccessCondition = Nx_AccessCondition_No_Access;
        Nx_AccessCondition_t changeAccessCondition    = Nx_AccessCondition_No_Access;

        if (options == NULL) {
            LOG_E("Input Options Parameter is NULL");
            goto cleanup;
        }

        pFileNo   = (uint8_t *)options;
        retStatus = nx_GetFileSettings(session_ctx,
            *pFileNo,
            &fileType,
            &fileOption,
            &readAccessCondition,
            &writeAccessCondition,
            &readWriteAccessCondition,
            &changeAccessCondition,
            NULL,
            NULL);

        if (retStatus != SM_OK) {
            LOG_E("nx_GetFileSettings_Counter failed");
            goto cleanup;
        }

        if ((fileOption & NX_FILE_OPTION_COMM_MODE_MASK) == Nx_CommMode_FULL) {
            *commMode = EV2_CommMode_FULL;
        }
        else if ((fileOption & NX_FILE_OPTION_COMM_MODE_MASK) == Nx_CommMode_MAC) {
            *commMode = EV2_CommMode_MAC;
        }
        else if ((fileOption & NX_FILE_OPTION_COMM_MODE_MASK) == Nx_CommMode_Plain) {
            *commMode = EV2_CommMode_PLAIN;
        }
        else {
            LOG_E("Invalid commMode");
            retStatus = SM_NOT_OK;
        }

        break;
    }
    case NX_INS_MGNT_GPIO:
    case NX_INS_READ_GPIO: {
        // Get GPIO configuration
        uint8_t mgmtCommMode        = Nx_CommMode_NA;
        uint8_t readCommMode        = Nx_CommMode_NA;
        uint8_t thisAPICommMode     = Nx_CommMode_NA;
        Nx_gpio_config_t gpioConfig = {0};
        retStatus                   = nx_GetConfig_GPIOMgmt(session_ctx, &gpioConfig);
        mgmtCommMode                = ((gpioConfig.acManage & NX_CONF_COMM_MODE_MASK) >> NX_COMM_MODE_BIT_SHIFT);
        readCommMode                = ((gpioConfig.acRead & NX_CONF_COMM_MODE_MASK) >> NX_COMM_MODE_BIT_SHIFT);
        if (retStatus != SM_OK) {
            LOG_E("nx_GetConfig_GPIOMgmt failed");
            goto cleanup;
        }
        if (cmdByte == NX_INS_MGNT_GPIO) {
            thisAPICommMode = mgmtCommMode;
        }
        else {
            thisAPICommMode = readCommMode;
        }

        if (thisAPICommMode == Nx_CommMode_FULL) {
            *commMode = EV2_CommMode_FULL;
        }
        else if (thisAPICommMode == Nx_CommMode_MAC) {
            *commMode = EV2_CommMode_MAC;
        }
        else if (thisAPICommMode == Nx_CommMode_Plain) {
            *commMode = EV2_CommMode_PLAIN;
        }
        break;
    }
    case NX_INS_CRYPTO_REQ: {
        // Get Crypto API Management configuration
        Nx_CommMode_t thisAPICommMode = Nx_CommMode_NA;
        uint8_t cryptoAPISupport      = NX_CONF_CRYPTOAPI_ASYMMETRIC_DISABLED | NX_CONF_CRYPTOAPI_SYMMETRIC_DISABLED;
        uint8_t acCryptoRequest       = Nx_AccessCondition_No_Access;
        uint8_t acChangeKey           = Nx_AccessCondition_No_Access;
        uint8_t TBPolicyCount         = NX_TB_POLICY_MAX_COUNT;
        Nx_slot_buffer_policy_t TBPolicy[NX_TB_POLICY_MAX_COUNT] = {0};
        uint8_t SBPolicyCount                                    = NX_SB_POLICY_MAX_COUNT;
        Nx_slot_buffer_policy_t SBPolicy[NX_SB_POLICY_MAX_COUNT] = {0};

        retStatus = nx_GetConfig_CryptoAPIMgmt(session_ctx,
            &cryptoAPISupport,
            &acCryptoRequest,
            &acChangeKey,
            &TBPolicyCount,
            &TBPolicy[0],
            &SBPolicyCount,
            &SBPolicy[0]);

        if (retStatus != SM_OK) {
            LOG_E("nx_GetConfig_CryptoAPIMgmt failed");
            goto cleanup;
        }
        thisAPICommMode = (acCryptoRequest & NX_CONF_COMM_MODE_MASK) >> NX_COMM_MODE_BIT_SHIFT;
        if (thisAPICommMode == Nx_CommMode_FULL) {
            *commMode = EV2_CommMode_FULL;
        }
        else if (thisAPICommMode == Nx_CommMode_MAC) {
            *commMode = EV2_CommMode_MAC;
        }
        else if (thisAPICommMode == Nx_CommMode_Plain) {
            *commMode = EV2_CommMode_PLAIN;
        }
        else {
            LOG_E("Invalid commMode");
            retStatus = SM_NOT_OK;
        }
        break;
    }
    case NX_INS_GET_CARDUID:
    case NX_INS_SET_CONFIG:
    case NX_INS_GET_CONFIG:
    case NX_INS_CHANGE_KEY:
        *commMode = EV2_CommMode_FULL;
        break;
    case NX_INS_GET_KEY_SETTINGS:
    case NX_INS_GET_VERSION:
    case NX_INS_GET_ISO_FILE_IDS:
    case NX_INS_GET_KEY_VERSION:
    case NX_INS_GET_FILE_IDS:
    case NX_INS_CREATE_STD_DATA_FILE:
    case NX_INS_CREATE_COUNTER_FILE:
    case NX_INS_GET_FILE_SETTINGS:
        *commMode = EV2_CommMode_MAC;
        break;
    case NX_INS_MGMT_CERT_REPO:
        if (options == NULL) {
            LOG_E("Input Options Parameter is NULL");
            goto cleanup;
        }
        uint8_t leafCacheSize   = 0x00;
        uint8_t intermCacheSize = 0x00;
        uint8_t acManageCertRepo =
            (0b0010 << NX_COMM_MODE_BIT_SHIFT) | Nx_AccessCondition_No_Access; // default commMode and No Access
        uint8_t featureSelection                             = NX_CONF_CERT_SIGMA_I_CACHE_DISABLED;
        Nx_MgCertRepo_GetCommModeParams_t *GetCommModeParams = NULL;
        GetCommModeParams                                    = (Nx_MgCertRepo_GetCommModeParams_t *)options;
        action                                               = &GetCommModeParams->action;
        if (*action == NX_MgCertRepoINS_CreateRepo) {
            // Leaf cache size: 8; Interm cache size: 8; Feature: Host Certificate Support; AC: Plain+0xE
            retStatus = nx_GetConfig_CertMgmt(
                session_ctx, &leafCacheSize, &intermCacheSize, &featureSelection, &acManageCertRepo);
            if (retStatus != SM_OK) {
                LOG_E("nx_GetConfig_EccKeyMgmt failed");
                goto cleanup;
            }

            if (((acManageCertRepo & NX_CONF_COMM_MODE_MASK) >> NX_COMM_MODE_BIT_SHIFT) == Nx_CommMode_FULL) {
                *commMode = EV2_CommMode_FULL;
            }
            else if (((acManageCertRepo & NX_CONF_COMM_MODE_MASK) >> NX_COMM_MODE_BIT_SHIFT) == Nx_CommMode_MAC) {
                *commMode = EV2_CommMode_MAC;
            }
            else if (((acManageCertRepo & NX_CONF_COMM_MODE_MASK) >> NX_COMM_MODE_BIT_SHIFT) == Nx_CommMode_Plain) {
                *commMode = EV2_CommMode_PLAIN;
            }
            else {
                LOG_E("Invalid commMode");
                retStatus = SM_NOT_OK;
            }
        }
        else if (*action == NX_MgCertRepoINS_LoadCert || *action == NX_MgCertRepoINS_LoadCertMapping ||
                 *action == NX_MgCertRepoINS_ActivateRepo || *action == NX_MgCertRepoINS_ResetRepo) {
            uint8_t repoPrivateKeyId        = 0;
            uint16_t repoSize               = 0;
            Nx_CommMode_t repoWriteCommMode = Nx_CommMode_NA;
            uint8_t repoWriteAccessCond     = Nx_AccessCondition_No_Access;
            Nx_CommMode_t repoReadCommMode  = Nx_CommMode_NA;
            uint8_t repoReadAccessCond      = Nx_AccessCondition_No_Access;

            repoID = (uint8_t *)options;

            retStatus = nx_ReadCertRepo_Metadata(session_ctx,
                GetCommModeParams->repoID,
                &repoPrivateKeyId,
                &repoSize,
                &repoWriteCommMode,
                &repoWriteAccessCond,
                &repoReadCommMode,
                &repoReadAccessCond);
            if (retStatus != SM_OK) {
                LOG_E("nx_ReadCertRepo_Metadata failed");
                goto cleanup;
            }
            if (repoWriteCommMode == Nx_CommMode_FULL) {
                *commMode = EV2_CommMode_FULL;
            }
            else if (repoWriteCommMode == Nx_CommMode_MAC) {
                *commMode = EV2_CommMode_MAC;
            }
            else if (repoWriteCommMode == Nx_CommMode_Plain) {
                *commMode = EV2_CommMode_PLAIN;
            }
            else {
                LOG_E("Invalid commMode");
                retStatus = SM_NOT_OK;
            }
        }
        else {
            LOG_E("Input action Parameter is not supported");
            goto cleanup;
        }
        break;

    case NX_INS_READ_CERT_REPO: {
        uint8_t repoPrivateKeyId        = 0;
        uint16_t repoSize               = 0;
        Nx_CommMode_t repoWriteCommMode = Nx_CommMode_NA;
        uint8_t repoWriteAccessCond     = Nx_AccessCondition_No_Access;
        Nx_CommMode_t repoReadCommMode  = Nx_CommMode_NA;
        uint8_t repoReadAccessCond      = Nx_AccessCondition_No_Access;

        repoID = (uint8_t *)options;

        retStatus = nx_ReadCertRepo_Metadata(session_ctx,
            *repoID,
            &repoPrivateKeyId,
            &repoSize,
            &repoWriteCommMode,
            &repoWriteAccessCond,
            &repoReadCommMode,
            &repoReadAccessCond);
        if (retStatus != SM_OK) {
            LOG_E("nx_ReadCertRepo_Metadata failed");
            goto cleanup;
        }
        if (repoReadCommMode == Nx_CommMode_FULL) {
            *commMode = EV2_CommMode_FULL;
        }
        else if (repoReadCommMode == Nx_CommMode_MAC) {
            *commMode = EV2_CommMode_MAC;
        }
        else if (repoReadCommMode == Nx_CommMode_Plain) {
            *commMode = EV2_CommMode_PLAIN;
        }
        else {
            LOG_E("Invalid commMode");
            retStatus = SM_NOT_OK;
        }
        break;
    }

    case NX_INS_FREE_MEM:
        *commMode = EV2_CommMode_MAC;
        break;
    case NX_INS_ADDITIONAL_FRAME_REQ:
        *commMode = (EV2_CommMode_PLAIN & 0x0F);
        break;

    default:
        return SM_NOT_OK;
    }

    retStatus = SM_OK;

cleanup:
    return retStatus;
}

smStatus_t nx_get_comm_mode(pSeSession_t session_ctx,
    Nx_CommMode_t knownCommMode,
    uint8_t cmdByte,
    nx_ev2_comm_mode_t *out_commMode,
    void *options)
{
    smStatus_t retStatus = SM_NOT_OK;

    if ((session_ctx == NULL) || (out_commMode == NULL)) {
        goto exit;
    }

    // In case user doesn't provide valid commMode, get commMode from SE configuration.
    if (knownCommMode == Nx_CommMode_NA) {
        if ((session_ctx->authType == knx_AuthType_SIGMA_I_Verifier) ||
            (session_ctx->authType == knx_AuthType_SIGMA_I_Prover) ||
            (session_ctx->authType == knx_AuthType_SYMM_AUTH)) {
            // Get commMode in case of authenticated.
            retStatus = secure_messaging_get_commMode(session_ctx, cmdByte, out_commMode, options);
            if (retStatus != SM_OK) {
                goto exit;
            }
            if (cmdByte == NX_INS_CRYPTO_REQ) {
                session_ctx->userCryptoCommMode = commMode_convert(*out_commMode);
            }
        }
    }
    else if (knownCommMode == Nx_CommMode_Plain) {
        *out_commMode = EV2_CommMode_PLAIN;
    }
    else if (knownCommMode == Nx_CommMode_MAC) {
        *out_commMode = EV2_CommMode_MAC;
    }
    else {
        *out_commMode = EV2_CommMode_FULL;
    }

    retStatus = SM_OK;
exit:
    return retStatus;
}

void nx_sesson_bind(SeSession_t *pSession, nx_connect_ctx_t *pConnectCtx2)
{
    if ((NULL != pSession) && (NULL != pConnectCtx2)) {
        pConnectCtx2->auth.ctx.symmAuth.dyn_ctx.CmdCtr     = pSession->ctx.pdynSymmAuthCtx->CmdCtr;
        pConnectCtx2->auth.ctx.symmAuth.dyn_ctx.TI         = pSession->ctx.pdynSymmAuthCtx->TI;
        pConnectCtx2->auth.ctx.symmAuth.dyn_ctx.authStatus = pSession->ctx.pdynSymmAuthCtx->authStatus;
        pConnectCtx2->conn_ctx                             = pSession->conn_ctx;
    }
    else {
        LOG_E("Fail to bind session");
    }
    return;
}

void nx_sesson_unbind(SeSession_t *pSession)
{
    if (NULL != pSession) {
        pSession->conn_ctx = NULL;
    }
    else {
        LOG_E("Fail to unbind session");
    }
    return;
}

smStatus_t nx_FreeMem(pSeSession_t session_ctx, uint32_t *freeMemSize)
{
    smStatus_t retStatus                      = SM_NOT_OK;
    tlvHeader_t hdr                           = {{NX_CLA, NX_INS_FREE_MEM, NX_P1_DEFAULT, NX_P2_DEFAULT}};
    uint8_t cmdHeaderBuf[NX_MAX_BUF_SIZE_CMD] = {0};
    size_t cmdHeaderBufLen                    = 0;
    uint8_t cmdDataBuf[NX_MAX_BUF_SIZE_CMD]   = {0};
    size_t cmdDataBufBufLen                   = 0;
    uint8_t rspbuf[NX_MAX_BUF_SIZE_RSP]       = {0};
    uint8_t *pRspbuf                          = &rspbuf[0];
    size_t rspbufLen                          = sizeof(rspbuf);
    uint8_t freeMemBuf[3]                     = {0};
#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "FreeMem []");
#endif /* VERBOSE_APDU_LOGS */

    ENSURE_OR_GO_CLEANUP(NULL != session_ctx)
    ENSURE_OR_GO_CLEANUP(NULL != freeMemSize)

    LOG_I("session_ctx->authType %x", session_ctx->authType);
    retStatus = DoAPDUTxRx_s_Case4_ext(
        session_ctx, &hdr, cmdHeaderBuf, cmdHeaderBufLen, cmdDataBuf, cmdDataBufBufLen, rspbuf, &rspbufLen, NULL);
    if (retStatus == SM_OK) {
        retStatus = SM_NOT_OK;
        if (rspbufLen != 5) {
            goto cleanup;
        }
        memcpy(freeMemBuf, rspbuf, 3);
        *freeMemSize = (uint32_t)((freeMemBuf[2] << 16) | (freeMemBuf[1] << 8) | freeMemBuf[0]);
        retStatus    = (pRspbuf[3] << 8) | (pRspbuf[4]);
        if (retStatus == SM_OK_ALT) {
            retStatus = SM_OK;
        }
    }

cleanup:
    return retStatus;
}

smStatus_t nx_GetVersion(pSeSession_t session_ctx, bool getFabID, Nx_VersionParams_t *pVersionInfo)
{
    smStatus_t retStatus                      = SM_NOT_OK;
    tlvHeader_t hdr                           = {{NX_CLA, NX_INS_GET_VERSION, NX_P1_DEFAULT, NX_P2_DEFAULT}};
    uint8_t cmdHeaderBuf[NX_MAX_BUF_SIZE_CMD] = {0};
    size_t cmdHeaderBufLen                    = 0;
    uint8_t cmdDataBuf[NX_MAX_BUF_SIZE_CMD]   = {0};
    size_t cmdDataBufBufLen                   = 0;
    int tlvRet                                = 1;
    uint8_t rspbuf[NX_MAX_BUF_SIZE_RSP]       = {0};
    uint8_t *pRspbuf                          = &rspbuf[0];
    size_t rspbufLen                          = sizeof(rspbuf);
    nx_ev2_comm_mode_t commMode               = EV2_CommMode_NA;
    void *options                             = NULL;
    uint8_t *pCmdHeaderBuf                    = &cmdHeaderBuf[0];

    ENSURE_OR_GO_CLEANUP(NULL != session_ctx)
    ENSURE_OR_GO_CLEANUP(NULL != pVersionInfo)

    if (((session_ctx->authType == knx_AuthType_SIGMA_I_Verifier) ||
            (session_ctx->authType == knx_AuthType_SIGMA_I_Prover)) &&
        (session_ctx->ctx.pdynSigICtx != NULL)) {
        if (session_ctx->ctx.pdynSigICtx->selectedSecureTunnelType != knx_SecureSymmType_None) {
            retStatus = secure_messaging_get_commMode(session_ctx, NX_INS_GET_VERSION, &commMode, NULL);
            if (retStatus != SM_OK) {
                LOG_E("Fail to get commMode for Cmd.GetVersion.");
                goto cleanup;
            }

            options = &commMode;
        }
    }
    else if ((session_ctx->authType == knx_AuthType_SYMM_AUTH) && (session_ctx->ctx.pdynSymmAuthCtx != NULL)) {
        retStatus = secure_messaging_get_commMode(session_ctx, NX_INS_GET_VERSION, &commMode, NULL);
        if (retStatus != SM_OK) {
            LOG_E("Fail to get commMode for Cmd.GetVersion.");
            goto cleanup;
        }
        options = &commMode;
    }

    retStatus = SM_NOT_OK; //reinitialized

#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "GetVersion []");
#endif /* VERBOSE_APDU_LOGS */

    if (true == getFabID) {
        tlvRet = SET_U8("Option", &pCmdHeaderBuf, &cmdHeaderBufLen, Nx_GetVersionOption_ReturnFabId);
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);
    }

    retStatus = DoAPDUTxRx_s_Case4(
        session_ctx, &hdr, cmdHeaderBuf, cmdHeaderBufLen, cmdDataBuf, cmdDataBufBufLen, rspbuf, &rspbufLen, options);
    if (retStatus == SM_OK) {
        retStatus       = SM_NOT_OK;
        size_t rspIndex = 0;

        if ((rspbufLen != 30) && (rspbufLen != 31) && (rspbufLen != 35) && (rspbufLen != 36)) {
            goto cleanup;
        }

        tlvRet = get_U8(pRspbuf, &rspIndex, rspbufLen, &(pVersionInfo->vendorID1)); /*  */
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);

        tlvRet = get_U8(pRspbuf, &rspIndex, rspbufLen, &(pVersionInfo->hwType)); /*  */
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);

        tlvRet = get_U8(pRspbuf, &rspIndex, rspbufLen, &(pVersionInfo->hwSubType)); /*  */
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);

        tlvRet = get_U8(pRspbuf, &rspIndex, rspbufLen, &(pVersionInfo->hwMajorVersion)); /*  */
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);

        tlvRet = get_U8(pRspbuf, &rspIndex, rspbufLen, &(pVersionInfo->hwMinorVersion)); /*  */
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);

        tlvRet = get_U8(pRspbuf, &rspIndex, rspbufLen, &(pVersionInfo->hwStorageSize)); /*  */
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);

        tlvRet = get_U8(pRspbuf, &rspIndex, rspbufLen, &(pVersionInfo->hwProtocol)); /*  */
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);

        tlvRet = get_U8(pRspbuf, &rspIndex, rspbufLen, &(pVersionInfo->vendorID2)); /*  */
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);

        tlvRet = get_U8(pRspbuf, &rspIndex, rspbufLen, &(pVersionInfo->swType)); /*  */
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);

        tlvRet = get_U8(pRspbuf, &rspIndex, rspbufLen, &(pVersionInfo->swSubType)); /*  */
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);

        tlvRet = get_U8(pRspbuf, &rspIndex, rspbufLen, &(pVersionInfo->swMajorVersion)); /*  */
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);

        tlvRet = get_U8(pRspbuf, &rspIndex, rspbufLen, &(pVersionInfo->swMinorVersion)); /*  */
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);

        tlvRet = get_U8(pRspbuf, &rspIndex, rspbufLen, &(pVersionInfo->swStorageSize)); /*  */
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);

        tlvRet = get_U8(pRspbuf, &rspIndex, rspbufLen, &(pVersionInfo->swProtocol)); /*  */
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);

        if ((rspbufLen == 35) || (rspbufLen == 36)) {
            // non-7-byte UID (10 bytes)
            tlvRet = get_U8(pRspbuf, &rspIndex, rspbufLen, &(pVersionInfo->uidFormat)); /*  */
            ENSURE_OR_GO_CLEANUP(0 == tlvRet);

            tlvRet = get_U8(pRspbuf, &rspIndex, rspbufLen, &(pVersionInfo->uidLength)); /*  */
            ENSURE_OR_GO_CLEANUP(0 == tlvRet);

            if (pVersionInfo->uidLength > sizeof(pVersionInfo->uid)) {
                goto cleanup;
            }

            tlvRet = get_u8buf(pRspbuf, &rspIndex, rspbufLen, &(pVersionInfo->uid[0]), pVersionInfo->uidLength); /*  */
            ENSURE_OR_GO_CLEANUP(0 == tlvRet);
        }
        else {
            // 7-byte UID
            pVersionInfo->uidFormat = NX_VERSION_UID_FORMAT_INVALID;
            pVersionInfo->uidLength = 7;

            tlvRet = get_u8buf(pRspbuf, &rspIndex, rspbufLen, &(pVersionInfo->uid[0]), 7); /*  */
            ENSURE_OR_GO_CLEANUP(0 == tlvRet);
        }

        tlvRet = get_U24_LSB(pRspbuf, &rspIndex, rspbufLen, &(pVersionInfo->batchNo)); /* FabKey Server Batch Number */
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);

        tlvRet = get_U16_LSB(pRspbuf, &rspIndex, rspbufLen, &(pVersionInfo->fabKeyID)); /* FabKey identifier */
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);

        tlvRet = get_U8(
            pRspbuf, &rspIndex, rspbufLen, &(pVersionInfo->cwProd)); /* The calender week of production in BCD coding */
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);

        tlvRet = get_U8(pRspbuf, &rspIndex, rspbufLen, &(pVersionInfo->yearProd)); /*  */
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);

        if (getFabID) {
            tlvRet = get_U8(pRspbuf, &rspIndex, rspbufLen, &(pVersionInfo->fabID)); /*  */
            ENSURE_OR_GO_CLEANUP(0 == tlvRet);
        }

        if ((rspIndex + 2) == rspbufLen) {
            retStatus = (pRspbuf[rspIndex] << 8) | (pRspbuf[rspIndex + 1]);
            if (retStatus == SM_OK_ALT) {
                retStatus = SM_OK;
            }
        }
    }

cleanup:
    return retStatus;
}

smStatus_t nx_Activate_Config(pSeSession_t session_ctx, nx_activate_config_t *configList)
{
    smStatus_t retStatus                      = SM_NOT_OK;
    tlvHeader_t hdr                           = {{NX_CLA, NX_INS_ACTIVATE_CONFIG, NX_P1_DEFAULT, NX_P2_DEFAULT}};
    uint8_t cmdHeaderBuf[NX_MAX_BUF_SIZE_CMD] = {0};
    size_t cmdHeaderBufLen                    = 0;
    uint8_t *pCmdHeaderBuf                    = &cmdHeaderBuf[0];
    int tlvRet                                = 1;
    uint8_t rspbuf[NX_MAX_BUF_SIZE_RSP]       = {0};
    size_t rspbufLen                          = sizeof(rspbuf);
    uint8_t *pRspbuf                          = &rspbuf[0];
    uint8_t confCount                         = 0;
    uint8_t confList[NX_ACTIVATE_CONF_ELEMENT_SIZE * NX_ACTIVATE_CONF_COUNT_MAX] = {0};
#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "ActivateConfiguration []");
#endif /* VERBOSE_APDU_LOGS */

    if ((session_ctx == NULL) || (configList == NULL)) {
        goto cleanup;
    }

    if (configList->randomID == 1) {
        confList[confCount * 2]     = 0x5C;
        confList[confCount * 2 + 1] = Nx_ConfigDeferOption_PICC_Rnd_ID;
        confCount++;
    }
    if (configList->silentMode == 1) {
        confList[confCount * 2]     = 0x5C;
        confList[confCount * 2 + 1] = Nx_ConfigDeferOption_Silent_Mode;
        confCount++;
    }
    if (configList->tagTamperBoot == 1) {
        confList[confCount * 2]     = 0x5C;
        confList[confCount * 2 + 1] = Nx_ConfigDeferOption_GPIO_Config;
        confCount++;
    }
    if (configList->changeFileSetting == 1) {
        confList[confCount * 2]     = 0x5F;
        confList[confCount * 2 + 1] = Nx_Config_ChangeFileSettings_SDM_ENC;
        confCount++;
    }

    if (confCount == 0) {
        goto cleanup;
    }

    tlvRet = SET_U8("ConfCount", &pCmdHeaderBuf, &cmdHeaderBufLen, confCount);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet =
        SET_u8buf("ConfList", &pCmdHeaderBuf, &cmdHeaderBufLen, confList, NX_ACTIVATE_CONF_ELEMENT_SIZE * confCount);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    retStatus = DoAPDUTxRx_s_Case4(session_ctx, &hdr, cmdHeaderBuf, cmdHeaderBufLen, NULL, 0, rspbuf, &rspbufLen, NULL);

    if (retStatus == SM_OK) {
        retStatus       = SM_NOT_OK;
        size_t rspIndex = 0;

        if (rspbufLen != 2) {
            goto cleanup;
        }

        retStatus = (pRspbuf[rspIndex] << 8) | (pRspbuf[rspIndex + 1]);
        if (retStatus == SM_OK_ALT) {
            retStatus = SM_OK;
        }
    }

cleanup:
    return retStatus;
}

smStatus_t nx_GetCardUID(pSeSession_t session_ctx, uint8_t *pGetCardUID, size_t *getCardUIDLen)
{
    smStatus_t retStatus                      = SM_NOT_OK;
    tlvHeader_t hdr                           = {{NX_CLA, NX_INS_GET_CARDUID, NX_P1_DEFAULT, NX_P2_DEFAULT}};
    uint8_t cmdHeaderBuf[NX_MAX_BUF_SIZE_CMD] = {0};
    size_t cmdHeaderBufLen                    = 0;
    uint8_t cmdDataBuf[NX_MAX_BUF_SIZE_CMD]   = {0};
    size_t cmdDataBufBufLen                   = 0;
    int tlvRet                                = 1;
    uint8_t rspbuf[NX_MAX_BUF_SIZE_RSP]       = {0};
    uint8_t *pRspbuf                          = &rspbuf[0];
    size_t rspbufLen                          = sizeof(rspbuf);
    uint8_t uidFormat = 0, uidLength = 0;
#if VERBOSE_APDU_LOGS
    NEWLINE();

    nLog("APDU", NX_LEVEL_DEBUG, "GetCardUID []");

#endif /* VERBOSE_APDU_LOGS */

    ENSURE_OR_GO_CLEANUP(NULL != session_ctx)
    ENSURE_OR_GO_CLEANUP(NULL != pGetCardUID)
    ENSURE_OR_GO_CLEANUP(NULL != getCardUIDLen)

    retStatus = DoAPDUTxRx_s_Case4_ext(
        session_ctx, &hdr, cmdHeaderBuf, cmdHeaderBufLen, cmdDataBuf, cmdDataBufBufLen, rspbuf, &rspbufLen, NULL);
    if (retStatus == SM_OK) {
        retStatus       = SM_NOT_OK;
        size_t rspIndex = 0;

        if ((rspbufLen != 9) && (rspbufLen != 14)) { // 9 Bytes for 7-byte UID, 14 bytes for 10-byte UID.
            goto cleanup;
        }

        if (rspbufLen == 9) {
            tlvRet = get_u8buf(pRspbuf, &rspIndex, rspbufLen, pGetCardUID, NX_CONF_UID_LENGTH_7_BYTES); /*  */
            ENSURE_OR_GO_CLEANUP(0 == tlvRet);

            *getCardUIDLen = 7;
        }
        else if (rspbufLen == 14) {
            tlvRet = get_U8(pRspbuf, &rspIndex, rspbufLen, &uidFormat);
            if ((0 != tlvRet) || (uidFormat != NX_CONF_UID_FORMAT_LENGTH)) {
                goto cleanup;
            }

            tlvRet = get_U8(pRspbuf, &rspIndex, rspbufLen, &uidLength);
            if ((0 != tlvRet) || (uidLength != NX_CONF_UID_LENGTH_10_BYTES)) {
                goto cleanup;
            }

            tlvRet = get_u8buf(pRspbuf, &rspIndex, rspbufLen, pGetCardUID, NX_CONF_UID_LENGTH_10_BYTES); /*  */
            ENSURE_OR_GO_CLEANUP(0 == tlvRet);

            *getCardUIDLen = NX_CONF_UID_LENGTH_10_BYTES;
        }

        if ((rspIndex + 2) == rspbufLen) {
            retStatus = (pRspbuf[rspIndex] << 8) | (pRspbuf[rspIndex + 1]);
            if (retStatus == SM_OK_ALT) {
                retStatus = SM_OK;
            }
        }
    }

cleanup:
    return retStatus;
}

smStatus_t nx_ManageKeyPair(pSeSession_t session_ctx,
    uint8_t objectID,
    Nx_MgtKeyPair_Act_t option,
    Nx_ECCurve_t curveID,
    uint16_t policy,
    Nx_CommMode_t writeCommMode,
    uint8_t writeAccessCond,
    uint32_t kucLimit,
    const uint8_t *privateKey,
    size_t privateKeyLen,
    uint8_t *pubKey,
    size_t *pubKeyLen,
    Nx_CommMode_t knownCommMode)
{
    smStatus_t retStatus                      = SM_NOT_OK;
    tlvHeader_t hdr                           = {{NX_CLA, NX_INS_MGMT_KEY_PAIR, NX_P1_DEFAULT, NX_P2_DEFAULT}};
    uint8_t cmdHeaderBuf[NX_MAX_BUF_SIZE_CMD] = {0};
    size_t cmdHeaderBufLen                    = 0;
    uint8_t cmdDataBuf[NX_MAX_BUF_SIZE_CMD]   = {0};
    size_t cmdDataBufBufLen                   = 0;
    int tlvRet                                = 1;
    uint8_t *pCmdHeaderBuf                    = &cmdHeaderBuf[0];
    uint8_t *pCmdDataBuf                      = &cmdDataBuf[0];
    uint8_t rspbuf[NX_MAX_BUF_SIZE_RSP]       = {0};
    size_t rspbufLen                          = sizeof(rspbuf);
    uint8_t writeAccess                       = 0;
    nx_ev2_comm_mode_t commMode               = EV2_CommMode_PLAIN;
    void *options                             = &commMode;

    if (session_ctx == NULL) {
        LOG_E("nx_ManageKeyPair Invalid Parameters!!!");
        goto cleanup;
    }

    retStatus = nx_get_comm_mode(session_ctx, knownCommMode, NX_INS_MGMT_KEY_PAIR, &commMode, &objectID);
    ENSURE_OR_GO_CLEANUP(SM_OK == retStatus);

    retStatus = SM_NOT_OK; //reinitialized
#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "ManageKeyPair []");
#endif /* VERBOSE_APDU_LOGS */

    if ((writeCommMode << NX_COMM_MODE_BIT_SHIFT) > UINT8_MAX) {
        LOG_E("Passed writeCommMode is incorrect");
        goto cleanup;
    }
    writeAccess = ((writeCommMode << NX_COMM_MODE_BIT_SHIFT) | writeAccessCond);

    tlvRet = SET_U8("KeyNo", &pCmdHeaderBuf, &cmdHeaderBufLen, objectID);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_U8("Option", &pCmdHeaderBuf, &cmdHeaderBufLen, option);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_U8("curveID", &pCmdHeaderBuf, &cmdHeaderBufLen, curveID);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_U16_LSB("KeyPolicy(LSB)", &pCmdHeaderBuf, &cmdHeaderBufLen, policy);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_U8("writeAccessCond", &pCmdHeaderBuf, &cmdHeaderBufLen, writeAccess);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_U32_LSB("KUCLimit(LSB)", &pCmdHeaderBuf, &cmdHeaderBufLen, kucLimit);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    if (option == Nx_MgtKeyPair_Act_Import_SK) {
        if (privateKey != NULL) {
            tlvRet = SET_u8buf("Private key", &pCmdDataBuf, &cmdDataBufBufLen, privateKey, privateKeyLen);
            ENSURE_OR_GO_CLEANUP(0 == tlvRet);
        }
        else {
            LOG_E("nx_ManageCertRepo_CreateCertRepo Invalid Parameter Of Private Key!!!");
        }
    }

    retStatus = DoAPDUTxRx_s_Case4(
        session_ctx, &hdr, cmdHeaderBuf, cmdHeaderBufLen, cmdDataBuf, cmdDataBufBufLen, rspbuf, &rspbufLen, options);

    if (retStatus == SM_OK) {
        retStatus = SM_NOT_OK;

        if (option == Nx_MgtKeyPair_Act_Generate_Keypair) {
            // Generate keypair will return public key.
            if (rspbufLen != 67) { // 65 Bytes public key + 2 bytes SW
                goto cleanup;
            }
            retStatus = (rspbuf[rspbufLen - 2] << 8) | (rspbuf[rspbufLen - 1]);
            if (retStatus == SM_OK_ALT) {
                if (pubKey != NULL && pubKeyLen != NULL && (*pubKeyLen) >= 65) {
                    memcpy(pubKey, rspbuf, rspbufLen - 2);
                    *pubKeyLen = rspbufLen - 2;
                }
                else {
                    LOG_W("public key buffer is not sufficient. publci key not copied");
                }
                retStatus = SM_OK;
            }
        }
        else {                    // Import or update meta data.
            if (rspbufLen != 2) { // 2 bytes SW
                goto cleanup;
            }
            retStatus = (rspbuf[rspbufLen - 2] << 8) | (rspbuf[rspbufLen - 1]);
            if (retStatus == SM_OK_ALT) {
                retStatus = SM_OK;
            }
        }
    }

cleanup:
    return retStatus;
}

smStatus_t nx_ManageCARootKey(pSeSession_t session_ctx,
    uint8_t objectID,
    uint8_t curveID,
    uint16_t acBitmap,
    Nx_CommMode_t writeCommMode,
    uint8_t writeAccessCond,
    const uint8_t *pubKey,
    size_t pubKeyLen,
    const uint8_t *caIssuerName,
    uint8_t caIssuerNameLen,
    Nx_CommMode_t userCommMode)
{
    smStatus_t retStatus                      = SM_NOT_OK;
    tlvHeader_t hdr                           = {{NX_CLA, NX_INS_MGMT_CA_ROOT_KEY, NX_P1_DEFAULT, NX_P2_DEFAULT}};
    uint8_t cmdHeaderBuf[NX_MAX_BUF_SIZE_CMD] = {0};
    size_t cmdHeaderBufLen                    = 0;
    uint8_t cmdDataBuf[NX_MAX_BUF_SIZE_CMD]   = {0};
    size_t cmdDataBufBufLen                   = 0;
    int tlvRet                                = 1;
    uint8_t *pCmdHeaderBuf                    = &cmdHeaderBuf[0];
    uint8_t *pCmdDataBuf                      = &cmdDataBuf[0];
    uint8_t rspbuf[NX_MAX_BUF_SIZE_RSP]       = {0};
    size_t rspbufLen                          = sizeof(rspbuf);
    uint8_t writeAccess                       = 0;
    uint8_t readAccessCond                    = 0;
    nx_ev2_comm_mode_t commMode               = EV2_CommMode_PLAIN;
    void *options                             = &commMode;

    if ((session_ctx == NULL) || (pubKey == NULL)) {
        LOG_E("nx_ManageCARootKey Invalid Parameters!!!");
        goto cleanup;
    }

    retStatus = nx_get_comm_mode(session_ctx, userCommMode, NX_INS_MGMT_CA_ROOT_KEY, &commMode, &objectID);
    ENSURE_OR_GO_CLEANUP(SM_OK == retStatus);

    retStatus = SM_NOT_OK; //reinitialized

#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "ManageCARootKey []");
#endif /* VERBOSE_APDU_LOGS */

    if ((writeCommMode << NX_COMM_MODE_BIT_SHIFT) > UINT8_MAX) {
        LOG_E("Passed writeCommMode is incorrect");
        goto cleanup;
    }
    writeAccess    = ((writeCommMode << NX_COMM_MODE_BIT_SHIFT) | writeAccessCond);
    readAccessCond = ((Nx_CommMode_FULL << NX_COMM_MODE_BIT_SHIFT) | Nx_AccessCondition_No_Access);

    tlvRet = SET_U8("KeyNo", &pCmdHeaderBuf, &cmdHeaderBufLen, objectID);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_U8("curveID", &pCmdHeaderBuf, &cmdHeaderBufLen, curveID);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_U16_LSB("accessRight(LSB)", &pCmdHeaderBuf, &cmdHeaderBufLen, acBitmap);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_U8("writeAccessCond", &pCmdHeaderBuf, &cmdHeaderBufLen, writeAccess);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_U8("readAccessCond", &pCmdHeaderBuf, &cmdHeaderBufLen, readAccessCond);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_U8("Reserved", &pCmdHeaderBuf, &cmdHeaderBufLen, 0x00);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_u8buf("Public key", &pCmdDataBuf, &cmdDataBufBufLen, pubKey, pubKeyLen);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_U8("CA Subject Name Len", &pCmdDataBuf, &cmdDataBufBufLen, caIssuerNameLen);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    if (caIssuerNameLen != 0) {
        if (caIssuerName == NULL) {
            LOG_E("nx_ManageCARootKey Invalid CA Issuer Name!!!");
            goto cleanup;
        }
        tlvRet = SET_u8buf("CA Issuer Name", &pCmdDataBuf, &cmdDataBufBufLen, caIssuerName, caIssuerNameLen);
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);
    }

    retStatus = DoAPDUTxRx_s_Case4(
        session_ctx, &hdr, cmdHeaderBuf, cmdHeaderBufLen, cmdDataBuf, cmdDataBufBufLen, rspbuf, &rspbufLen, options);

cleanup:
    return retStatus;
}

smStatus_t nx_SetConfig_EccKeyMgmt(pSeSession_t session_ctx, uint8_t acManageKeyPair, uint8_t acManageCARootKey)
{
    smStatus_t retStatus                      = SM_NOT_OK;
    tlvHeader_t hdr                           = {{NX_CLA, NX_INS_SET_CONFIG, NX_P1_DEFAULT, NX_P2_DEFAULT}};
    uint8_t cmdHeaderBuf[NX_MAX_BUF_SIZE_CMD] = {0};
    size_t cmdHeaderBufLen                    = 0;
    uint8_t cmdDataBuf[NX_MAX_BUF_SIZE_CMD]   = {0};
    size_t cmdDataBufBufLen                   = 0;
    int tlvRet                                = 1;
    uint8_t *pCmdHeaderBuf                    = &cmdHeaderBuf[0];
    uint8_t *pCmdDataBuf                      = &cmdDataBuf[0];
    uint8_t rspbuf[NX_MAX_BUF_SIZE_RSP]       = {0};
    size_t rspbufLen                          = sizeof(rspbuf);
    uint8_t *pRspbuf                          = &rspbuf[0];

#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "SetConfiguration [ECC Key Management]");
#endif /* VERBOSE_APDU_LOGS */

    if ((session_ctx == NULL) || (acManageKeyPair > 0x3F) || (acManageCARootKey > 0x3F)) {
        goto cleanup;
    }

    tlvRet = SET_U8("Option", &pCmdHeaderBuf, &cmdHeaderBufLen, Nx_ConfigOption_ECC_Key_Mgmt);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    acManageKeyPair = acManageKeyPair & NX_CONF_COMM_MODE_AND_AC_MASK;
    tlvRet          = SET_U8("ManageKeyPair AC", &pCmdDataBuf, &cmdDataBufBufLen, acManageKeyPair);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    acManageCARootKey = acManageCARootKey & NX_CONF_COMM_MODE_AND_AC_MASK;
    tlvRet            = SET_U8("ManageCARootKey AC", &pCmdDataBuf, &cmdDataBufBufLen, acManageCARootKey);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    retStatus = DoAPDUTxRx_s_Case4(
        session_ctx, &hdr, cmdHeaderBuf, cmdHeaderBufLen, cmdDataBuf, cmdDataBufBufLen, rspbuf, &rspbufLen, NULL);

    if (retStatus == SM_OK) {
        retStatus       = SM_NOT_OK;
        size_t rspIndex = 0;

        if (rspbufLen != 2) {
            goto cleanup;
        }

        retStatus = (pRspbuf[rspIndex] << 8) | (pRspbuf[rspIndex + 1]);
        if (retStatus == SM_OK_ALT) {
            retStatus = SM_OK;
        }
    }

cleanup:
    return retStatus;
}

smStatus_t nx_SetConfig_PICCConfig(pSeSession_t session_ctx, uint8_t PICCConfig)
{
    smStatus_t retStatus                      = SM_NOT_OK;
    tlvHeader_t hdr                           = {{NX_CLA, NX_INS_SET_CONFIG, NX_P1_DEFAULT, NX_P2_DEFAULT}};
    uint8_t cmdHeaderBuf[NX_MAX_BUF_SIZE_CMD] = {0};
    size_t cmdHeaderBufLen                    = 0;
    uint8_t cmdDataBuf[NX_MAX_BUF_SIZE_CMD]   = {0};
    size_t cmdDataBufBufLen                   = 0;
    int tlvRet                                = 1;
    uint8_t *pCmdHeaderBuf                    = &cmdHeaderBuf[0];
    uint8_t *pCmdDataBuf                      = &cmdDataBuf[0];
    uint8_t rspbuf[NX_MAX_BUF_SIZE_RSP]       = {0};
    size_t rspbufLen                          = sizeof(rspbuf);
    uint8_t *pRspbuf                          = &rspbuf[0];
#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "SetConfiguration [PICC Configurations]");
#endif /* VERBOSE_APDU_LOGS */

    if (session_ctx == NULL) {
        goto cleanup;
    }

    tlvRet = SET_U8("Option", &pCmdHeaderBuf, &cmdHeaderBufLen, Nx_ConfigOption_PICC_Config);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    PICCConfig = PICCConfig & NX_CONF_PICC_USERID_MASK;
    tlvRet     = SET_U8("PICC Configurations", &pCmdDataBuf, &cmdDataBufBufLen, PICCConfig);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    retStatus = DoAPDUTxRx_s_Case4(
        session_ctx, &hdr, cmdHeaderBuf, cmdHeaderBufLen, cmdDataBuf, cmdDataBufBufLen, rspbuf, &rspbufLen, NULL);

    if (retStatus == SM_OK) {
        retStatus       = SM_NOT_OK;
        size_t rspIndex = 0;

        if (rspbufLen != 2) {
            goto cleanup;
        }

        retStatus = (pRspbuf[rspIndex] << 8) | (pRspbuf[rspIndex + 1]);
        if (retStatus == SM_OK_ALT) {
            retStatus = SM_OK;
        }
    }

cleanup:
    return retStatus;
}

smStatus_t nx_SetConfig_ATSUpdate(pSeSession_t session_ctx, uint8_t *userATS, size_t userATSLen)
{
    smStatus_t retStatus                      = SM_NOT_OK;
    tlvHeader_t hdr                           = {{NX_CLA, NX_INS_SET_CONFIG, NX_P1_DEFAULT, NX_P2_DEFAULT}};
    uint8_t cmdHeaderBuf[NX_MAX_BUF_SIZE_CMD] = {0};
    size_t cmdHeaderBufLen                    = 0;
    uint8_t cmdDataBuf[NX_MAX_BUF_SIZE_CMD]   = {0};
    size_t cmdDataBufBufLen                   = 0;
    int tlvRet                                = 1;
    uint8_t *pCmdHeaderBuf                    = &cmdHeaderBuf[0];
    uint8_t *pCmdDataBuf                      = &cmdDataBuf[0];
    uint8_t rspbuf[NX_MAX_BUF_SIZE_RSP]       = {0};
    size_t rspbufLen                          = sizeof(rspbuf);
    uint8_t *pRspbuf                          = &rspbuf[0];
#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "SetConfiguration [ATS Update]");
#endif /* VERBOSE_APDU_LOGS */

    if ((session_ctx == NULL) || (userATS == NULL) || (userATSLen == 0)) {
        goto cleanup;
    }

    tlvRet = SET_U8("Option", &pCmdHeaderBuf, &cmdHeaderBufLen, Nx_ConfigOption_ATS_Update);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_u8buf("UserATS", &pCmdDataBuf, &cmdDataBufBufLen, userATS, userATSLen);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    retStatus = DoAPDUTxRx_s_Case4(
        session_ctx, &hdr, cmdHeaderBuf, cmdHeaderBufLen, cmdDataBuf, cmdDataBufBufLen, rspbuf, &rspbufLen, NULL);
    if (retStatus == SM_OK) {
        retStatus = SM_NOT_OK;
        if (rspbufLen < 2) {
            goto cleanup;
        }
        retStatus = (pRspbuf[rspbufLen - 2] << 8) | (pRspbuf[rspbufLen - 1]);
        if (retStatus == SM_OK_ALT) {
            retStatus = SM_OK;
        }
    }

cleanup:
    return retStatus;
}

smStatus_t nx_SetConfig_SAKUpdate(pSeSession_t session_ctx, uint8_t sak1, uint8_t sak2)
{
    smStatus_t retStatus                      = SM_NOT_OK;
    tlvHeader_t hdr                           = {{NX_CLA, NX_INS_SET_CONFIG, NX_P1_DEFAULT, NX_P2_DEFAULT}};
    uint8_t cmdHeaderBuf[NX_MAX_BUF_SIZE_CMD] = {0};
    size_t cmdHeaderBufLen                    = 0;
    uint8_t cmdDataBuf[NX_MAX_BUF_SIZE_CMD]   = {0};
    size_t cmdDataBufBufLen                   = 0;
    int tlvRet                                = 1;
    uint8_t *pCmdHeaderBuf                    = &cmdHeaderBuf[0];
    uint8_t *pCmdDataBuf                      = &cmdDataBuf[0];
    uint8_t rspbuf[NX_MAX_BUF_SIZE_RSP]       = {0};
    size_t rspbufLen                          = sizeof(rspbuf);
    uint8_t *pRspbuf                          = &rspbuf[0];
#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "SetConfiguration [SAK Update]");
#endif /* VERBOSE_APDU_LOGS */

    if (session_ctx == NULL) {
        goto cleanup;
    }

    tlvRet = SET_U8("Option", &pCmdHeaderBuf, &cmdHeaderBufLen, Nx_ConfigOption_SAK_Update);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_U16_LSB("UserSAK(LSB)", &pCmdDataBuf, &cmdDataBufBufLen, (sak2 << 8) | sak1);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    retStatus = DoAPDUTxRx_s_Case4(
        session_ctx, &hdr, cmdHeaderBuf, cmdHeaderBufLen, cmdDataBuf, cmdDataBufBufLen, rspbuf, &rspbufLen, NULL);

    if (retStatus == SM_OK) {
        retStatus       = SM_NOT_OK;
        size_t rspIndex = 0;

        if (rspbufLen != 2) {
            goto cleanup;
        }

        retStatus = (pRspbuf[rspIndex] << 8) | (pRspbuf[rspIndex + 1]);
        if (retStatus == SM_OK_ALT) {
            retStatus = SM_OK;
        }
    }

cleanup:
    return retStatus;
}

smStatus_t nx_SetConfig_SMConfig(pSeSession_t session_ctx, uint8_t SMConfigA, uint8_t SMConfigB)
{
    smStatus_t retStatus                      = SM_NOT_OK;
    tlvHeader_t hdr                           = {{NX_CLA, NX_INS_SET_CONFIG, NX_P1_DEFAULT, NX_P2_DEFAULT}};
    uint8_t cmdHeaderBuf[NX_MAX_BUF_SIZE_CMD] = {0};
    size_t cmdHeaderBufLen                    = 0;
    uint8_t cmdDataBuf[NX_MAX_BUF_SIZE_CMD]   = {0};
    size_t cmdDataBufBufLen                   = 0;
    int tlvRet                                = 1;
    uint8_t *pCmdHeaderBuf                    = &cmdHeaderBuf[0];
    uint8_t *pCmdDataBuf                      = &cmdDataBuf[0];
    uint8_t rspbuf[NX_MAX_BUF_SIZE_RSP]       = {0};
    size_t rspbufLen                          = sizeof(rspbuf);
    uint8_t *pRspbuf                          = &rspbuf[0];
#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "SetConfiguration [Secure Messaging Configuration]");
#endif /* VERBOSE_APDU_LOGS */

    if (session_ctx == NULL) {
        goto cleanup;
    }

    tlvRet = SET_U8("Option", &pCmdHeaderBuf, &cmdHeaderBufLen, Nx_ConfigOption_Secure_Msg_Config);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);
    SMConfigB = SMConfigB & NX_CONF_SMCONFIG_BYTE_B_MASK;
    tlvRet    = SET_U8("SMConfigB", &pCmdDataBuf, &cmdDataBufBufLen, SMConfigB);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);
    SMConfigA = SMConfigA & NX_CONF_SMCONFIG_BYTE_A_RFU_MASK;
    tlvRet    = SET_U8("SMConfigA", &pCmdDataBuf, &cmdDataBufBufLen, SMConfigA);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    retStatus = DoAPDUTxRx_s_Case4(
        session_ctx, &hdr, cmdHeaderBuf, cmdHeaderBufLen, cmdDataBuf, cmdDataBufBufLen, rspbuf, &rspbufLen, NULL);

    if (retStatus == SM_OK) {
        retStatus       = SM_NOT_OK;
        size_t rspIndex = 0;

        if (rspbufLen != 2) {
            goto cleanup;
        }

        retStatus = (pRspbuf[rspIndex] << 8) | (pRspbuf[rspIndex + 1]);
        if (retStatus == SM_OK_ALT) {
            retStatus = SM_OK;
        }
    }

cleanup:
    return retStatus;
}

smStatus_t nx_SetConfig_CapData(pSeSession_t session_ctx, uint8_t *CapDataBuf, uint8_t CapDataBufLen)
{
    smStatus_t retStatus                      = SM_NOT_OK;
    tlvHeader_t hdr                           = {{NX_CLA, NX_INS_SET_CONFIG, NX_P1_DEFAULT, NX_P2_DEFAULT}};
    uint8_t cmdHeaderBuf[NX_MAX_BUF_SIZE_CMD] = {0};
    size_t cmdHeaderBufLen                    = 0;
    uint8_t cmdDataBuf[NX_MAX_BUF_SIZE_CMD]   = {0};
    size_t cmdDataBufBufLen                   = 0;
    int tlvRet                                = 1;
    uint8_t *pCmdHeaderBuf                    = &cmdHeaderBuf[0];
    uint8_t *pCmdDataBuf                      = &cmdDataBuf[0];
    uint8_t rspbuf[NX_MAX_BUF_SIZE_RSP]       = {0};
    size_t rspbufLen                          = sizeof(rspbuf);
    uint8_t *pRspbuf                          = &rspbuf[0];
#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "SetConfiguration [Capability Data]");
#endif /* VERBOSE_APDU_LOGS */

    if ((NULL == session_ctx) || (NULL == CapDataBuf)) {
        goto cleanup;
    }

    tlvRet = SET_U8("Option", &pCmdHeaderBuf, &cmdHeaderBufLen, Nx_ConfigOption_Capability_Data);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    if (CapDataBufLen == NX_CONF_CAPABILITY_DATA_LEN) {
        memset(CapDataBuf, 0x00, NX_CONF_CAPABILITY_RFU_DATA_LEN);
        tlvRet = SET_u8buf("Capability Data", &pCmdDataBuf, &cmdDataBufBufLen, CapDataBuf, CapDataBufLen);
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);
    }
    else {
        goto cleanup;
    }

    retStatus = DoAPDUTxRx_s_Case4(
        session_ctx, &hdr, cmdHeaderBuf, cmdHeaderBufLen, cmdDataBuf, cmdDataBufBufLen, rspbuf, &rspbufLen, NULL);

    if (retStatus == SM_OK) {
        retStatus       = SM_NOT_OK;
        size_t rspIndex = 0;

        if (rspbufLen != 2) {
            goto cleanup;
        }

        retStatus = (pRspbuf[rspIndex] << 8) | (pRspbuf[rspIndex + 1]);
        if (retStatus == SM_OK_ALT) {
            retStatus = SM_OK;
        }
    }

cleanup:
    return retStatus;
}

smStatus_t nx_SetConfig_ATQAUpdate(pSeSession_t session_ctx, uint16_t userATQA)
{
    smStatus_t retStatus                      = SM_NOT_OK;
    tlvHeader_t hdr                           = {{NX_CLA, NX_INS_SET_CONFIG, NX_P1_DEFAULT, NX_P2_DEFAULT}};
    uint8_t cmdHeaderBuf[NX_MAX_BUF_SIZE_CMD] = {0};
    size_t cmdHeaderBufLen                    = 0;
    uint8_t cmdDataBuf[NX_MAX_BUF_SIZE_CMD]   = {0};
    size_t cmdDataBufBufLen                   = 0;
    int tlvRet                                = 1;
    uint8_t *pCmdHeaderBuf                    = &cmdHeaderBuf[0];
    uint8_t *pCmdDataBuf                      = &cmdDataBuf[0];
    uint8_t rspbuf[NX_MAX_BUF_SIZE_RSP]       = {0};
    size_t rspbufLen                          = sizeof(rspbuf);
    uint8_t *pRspbuf                          = &rspbuf[0];
#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "SetConfiguration [ATQA Update]");
#endif /* VERBOSE_APDU_LOGS */

    if (session_ctx == NULL) {
        goto cleanup;
    }

    tlvRet = SET_U8("Option", &pCmdHeaderBuf, &cmdHeaderBufLen, Nx_ConfigOption_ATQA_Update);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_U16_LSB("UserATQA(LSB)", &pCmdDataBuf, &cmdDataBufBufLen, userATQA);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    retStatus = DoAPDUTxRx_s_Case4(
        session_ctx, &hdr, cmdHeaderBuf, cmdHeaderBufLen, cmdDataBuf, cmdDataBufBufLen, rspbuf, &rspbufLen, NULL);

    if (retStatus == SM_OK) {
        retStatus       = SM_NOT_OK;
        size_t rspIndex = 0;

        if (rspbufLen != 2) {
            goto cleanup;
        }

        retStatus = (pRspbuf[rspIndex] << 8) | (pRspbuf[rspIndex + 1]);
        if (retStatus == SM_OK_ALT) {
            retStatus = SM_OK;
        }
    }

cleanup:
    return retStatus;
}

smStatus_t nx_SetConfig_SilentModeConfig(pSeSession_t session_ctx, uint8_t silentMode, uint8_t REQS, uint8_t WUPS)
{
    smStatus_t retStatus                      = SM_NOT_OK;
    tlvHeader_t hdr                           = {{NX_CLA, NX_INS_SET_CONFIG, NX_P1_DEFAULT, NX_P2_DEFAULT}};
    uint8_t cmdHeaderBuf[NX_MAX_BUF_SIZE_CMD] = {0};
    size_t cmdHeaderBufLen                    = 0;
    uint8_t cmdDataBuf[NX_MAX_BUF_SIZE_CMD]   = {0};
    size_t cmdDataBufBufLen                   = 0;
    int tlvRet                                = 1;
    uint8_t *pCmdHeaderBuf                    = &cmdHeaderBuf[0];
    uint8_t *pCmdDataBuf                      = &cmdDataBuf[0];
    uint8_t rspbuf[NX_MAX_BUF_SIZE_RSP]       = {0};
    size_t rspbufLen                          = sizeof(rspbuf);
    uint8_t *pRspbuf                          = &rspbuf[0];
#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "SetConfiguration [Silent Mode Configuration]");
#endif /* VERBOSE_APDU_LOGS */

    if (session_ctx == NULL) {
        goto cleanup;
    }

    tlvRet = SET_U8("Option", &pCmdHeaderBuf, &cmdHeaderBufLen, Nx_ConfigOption_Silent_Mode_Config);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    silentMode = silentMode & NX_CONF_SILENTMODE_SILENT_OPTIONS_MASK;
    tlvRet     = SET_U8("SilentMode", &pCmdDataBuf, &cmdDataBufBufLen, silentMode);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    if (silentMode & NX_CONF_SILENTMODE_CUSTOMIZED_REQS_WUPS_ENABLE) {
        tlvRet = SET_U8("REQS", &pCmdDataBuf, &cmdDataBufBufLen, REQS);
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);

        tlvRet = SET_U8("WUPS", &pCmdDataBuf, &cmdDataBufBufLen, WUPS);
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);
    }

    retStatus = DoAPDUTxRx_s_Case4(
        session_ctx, &hdr, cmdHeaderBuf, cmdHeaderBufLen, cmdDataBuf, cmdDataBufBufLen, rspbuf, &rspbufLen, NULL);

    if (retStatus == SM_OK) {
        retStatus       = SM_NOT_OK;
        size_t rspIndex = 0;

        if (rspbufLen != 2) {
            goto cleanup;
        }

        retStatus = (pRspbuf[rspIndex] << 8) | (pRspbuf[rspIndex + 1]);
        if (retStatus == SM_OK_ALT) {
            retStatus = SM_OK;
        }
    }

cleanup:
    return retStatus;
}

smStatus_t nx_SetConfig_EnhancedPrivacyConfig(pSeSession_t session_ctx, uint8_t privacyOption, uint8_t appPrivacyKey)
{
    smStatus_t retStatus                      = SM_NOT_OK;
    tlvHeader_t hdr                           = {{NX_CLA, NX_INS_SET_CONFIG, NX_P1_DEFAULT, NX_P2_DEFAULT}};
    uint8_t cmdHeaderBuf[NX_MAX_BUF_SIZE_CMD] = {0};
    size_t cmdHeaderBufLen                    = 0;
    uint8_t cmdDataBuf[NX_MAX_BUF_SIZE_CMD]   = {0};
    size_t cmdDataBufBufLen                   = 0;
    int tlvRet                                = 1;
    uint8_t *pCmdHeaderBuf                    = &cmdHeaderBuf[0];
    uint8_t *pCmdDataBuf                      = &cmdDataBuf[0];
    uint8_t rspbuf[NX_MAX_BUF_SIZE_RSP]       = {0};
    size_t rspbufLen                          = sizeof(rspbuf);
    uint8_t *pRspbuf                          = &rspbuf[0];
#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "SetConfiguration [Enhanced Privacy Configuration]");
#endif /* VERBOSE_APDU_LOGS */

    if (NULL == session_ctx) {
        goto cleanup;
    }

    tlvRet = SET_U8("Option", &pCmdHeaderBuf, &cmdHeaderBufLen, Nx_ConfigOption_Enhanced_Privacy_Config);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    privacyOption = privacyOption & NX_CONF_PRIVACY_FEATURES_MASK;
    tlvRet        = SET_U8("PrivacyOption", &pCmdDataBuf, &cmdDataBufBufLen, privacyOption);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_U8("AppPrivacyKey", &pCmdDataBuf, &cmdDataBufBufLen, appPrivacyKey);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    retStatus = DoAPDUTxRx_s_Case4(
        session_ctx, &hdr, cmdHeaderBuf, cmdHeaderBufLen, cmdDataBuf, cmdDataBufBufLen, rspbuf, &rspbufLen, NULL);

    if (retStatus == SM_OK) {
        retStatus       = SM_NOT_OK;
        size_t rspIndex = 0;

        if (rspbufLen != 2) {
            goto cleanup;
        }

        retStatus = (pRspbuf[rspIndex] << 8) | (pRspbuf[rspIndex + 1]);
        if (retStatus == SM_OK_ALT) {
            retStatus = SM_OK;
        }
    }

cleanup:
    return retStatus;
}

smStatus_t nx_SetConfig_NFCMgmt(pSeSession_t session_ctx, uint8_t nfcSupport, uint16_t protocolOptions)
{
    smStatus_t retStatus                      = SM_NOT_OK;
    tlvHeader_t hdr                           = {{NX_CLA, NX_INS_SET_CONFIG, NX_P1_DEFAULT, NX_P2_DEFAULT}};
    uint8_t cmdHeaderBuf[NX_MAX_BUF_SIZE_CMD] = {0};
    size_t cmdHeaderBufLen                    = 0;
    uint8_t cmdDataBuf[NX_MAX_BUF_SIZE_CMD]   = {0};
    size_t cmdDataBufBufLen                   = 0;
    int tlvRet                                = 1;
    uint8_t *pCmdHeaderBuf                    = &cmdHeaderBuf[0];
    uint8_t *pCmdDataBuf                      = &cmdDataBuf[0];
    uint8_t rspbuf[NX_MAX_BUF_SIZE_RSP]       = {0};
    uint8_t *pRspbuf                          = &rspbuf[0];
    size_t rspbufLen                          = sizeof(rspbuf);
#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "SetConfiguration [NFC Management]");
#endif /* VERBOSE_APDU_LOGS */

    if (NULL == session_ctx) {
        goto cleanup;
    }

    tlvRet = SET_U8("Option", &pCmdHeaderBuf, &cmdHeaderBufLen, Nx_ConfigOption_NFC_Mgmt);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    nfcSupport = nfcSupport & NX_CONF_NFC_SUPPORT_MASK;
    tlvRet     = SET_U8("NFCSupport", &pCmdDataBuf, &cmdDataBufBufLen, nfcSupport);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_U16_LSB("ProtocolOptions", &pCmdDataBuf, &cmdDataBufBufLen, protocolOptions);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    retStatus = DoAPDUTxRx_s_Case4(
        session_ctx, &hdr, cmdHeaderBuf, cmdHeaderBufLen, cmdDataBuf, cmdDataBufBufLen, rspbuf, &rspbufLen, NULL);

    if (retStatus == SM_OK) {
        retStatus       = SM_NOT_OK;
        size_t rspIndex = 0;

        if (rspbufLen != 2) {
            goto cleanup;
        }

        retStatus = (pRspbuf[rspIndex] << 8) | (pRspbuf[rspIndex + 1]);
        if (retStatus == SM_OK_ALT) {
            retStatus = SM_OK;
        }
    }

cleanup:
    return retStatus;
}

smStatus_t nx_SetConfig_I2CMgmt(pSeSession_t session_ctx, uint8_t i2cSupport, uint8_t i2cAddr, uint16_t protocolOptions)
{
    smStatus_t retStatus                      = SM_NOT_OK;
    tlvHeader_t hdr                           = {{NX_CLA, NX_INS_SET_CONFIG, NX_P1_DEFAULT, NX_P2_DEFAULT}};
    uint8_t cmdHeaderBuf[NX_MAX_BUF_SIZE_CMD] = {0};
    size_t cmdHeaderBufLen                    = 0;
    uint8_t cmdDataBuf[NX_MAX_BUF_SIZE_CMD]   = {0};
    size_t cmdDataBufBufLen                   = 0;
    int tlvRet                                = 1;
    uint8_t *pCmdHeaderBuf                    = &cmdHeaderBuf[0];
    uint8_t *pCmdDataBuf                      = &cmdDataBuf[0];
    uint8_t rspbuf[NX_MAX_BUF_SIZE_RSP]       = {0};
    uint8_t *pRspbuf                          = &rspbuf[0];
    size_t rspbufLen                          = sizeof(rspbuf);
#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "SetConfiguration [I2C Management]");
#endif /* VERBOSE_APDU_LOGS */

    if (session_ctx == NULL) {
        goto cleanup;
    }

    tlvRet = SET_U8("Option", &pCmdHeaderBuf, &cmdHeaderBufLen, Nx_ConfigOption_I2C_Mgmt);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    i2cSupport = i2cSupport & NX_CONF_I2C_SUPPORT_MASK;
    tlvRet     = SET_U8("I2CSupport", &pCmdDataBuf, &cmdDataBufBufLen, i2cSupport);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_U8("I2CAddress", &pCmdDataBuf, &cmdDataBufBufLen, i2cAddr);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_U16_LSB("ProtocolOptions", &pCmdDataBuf, &cmdDataBufBufLen, protocolOptions);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    retStatus = DoAPDUTxRx_s_Case4(
        session_ctx, &hdr, cmdHeaderBuf, cmdHeaderBufLen, cmdDataBuf, cmdDataBufBufLen, rspbuf, &rspbufLen, NULL);
    if (retStatus == SM_OK) {
        retStatus = SM_NOT_OK;
        if (rspbufLen < 2) {
            goto cleanup;
        }

        retStatus = (pRspbuf[rspbufLen - 2] << 8) | (pRspbuf[rspbufLen - 1]);
        if (retStatus == SM_OK_ALT) {
            retStatus = SM_OK;
        }
    }

cleanup:
    return retStatus;
}

smStatus_t nx_SetConfig_GPIOMgmt(pSeSession_t session_ctx, Nx_gpio_config_t gpioConfig)
{
    smStatus_t retStatus                      = SM_NOT_OK;
    tlvHeader_t hdr                           = {{NX_CLA, NX_INS_SET_CONFIG, NX_P1_DEFAULT, NX_P2_DEFAULT}};
    uint8_t cmdHeaderBuf[NX_MAX_BUF_SIZE_CMD] = {0};
    size_t cmdHeaderBufLen                    = 0;
    uint8_t cmdDataBuf[NX_MAX_BUF_SIZE_CMD]   = {0};
    size_t cmdDataBufBufLen                   = 0;
    int tlvRet                                = 1;
    uint8_t *pCmdHeaderBuf                    = &cmdHeaderBuf[0];
    uint8_t *pCmdDataBuf                      = &cmdDataBuf[0];
    uint8_t rspbuf[NX_MAX_BUF_SIZE_RSP]       = {0};
    uint8_t *pRspbuf                          = &rspbuf[0];
    size_t rspbufLen                          = sizeof(rspbuf);
    uint8_t gpio1Config                       = 0; // Determined based on gpio1mode
    uint8_t gpio1PadCtrlA =
        (gpioConfig.gpio1DebounceFilterValue & NX_CONF_GPIO_DEBOUNCE_FILTER_VALUE_PADCTRL_A_MASK) >> 8;
    uint8_t gpio1PadCtrlB = gpioConfig.gpio1DebounceFilterValue & NX_CONF_GPIO_DEBOUNCE_FILTER_VALUE_PADCTRL_B_MASK;
    uint8_t gpio1PadCtrlC = (gpioConfig.gpio1DebounceFilterEnabled << NX_CONF_GPIO_DEBOUNCE_FILTER_ENABLED_OFFSET) |
                            (gpioConfig.gpio1InputFilterSelection << NX_CONF_GPIO_INPUT_FILTER_SELECTION_OFFSET);
    uint8_t gpio1PadCtrlD = (gpioConfig.gpio1InputCfg << NX_CONF_GPIO_INPUT_CONF_OFFSET) |
                            (gpioConfig.gpio1OutputCfg << NX_CONF_GPIO_OUTPUT_CONF_OFFSET) |
                            (gpioConfig.gpio1Supply1v1n1v2 << NX_CONF_GPIO_SUPPLY_SELECTION_OFFSET);
    uint32_t gpio1PadCtrl = CALC_NX_CONF_GPIO_PAD_CTRL(gpio1PadCtrlA, gpio1PadCtrlB, gpio1PadCtrlC, gpio1PadCtrlD);

    uint8_t gpio2Config = 0; // Determined based on gpio2mode
    uint8_t gpio2PadCtrlA =
        (gpioConfig.gpio2DebounceFilterValue & NX_CONF_GPIO_DEBOUNCE_FILTER_VALUE_PADCTRL_A_MASK) >> 8;
    uint8_t gpio2PadCtrlB = gpioConfig.gpio2DebounceFilterValue & NX_CONF_GPIO_DEBOUNCE_FILTER_VALUE_PADCTRL_B_MASK;
    uint8_t gpio2PadCtrlC = (gpioConfig.gpio2DebounceFilterEnabled << NX_CONF_GPIO_DEBOUNCE_FILTER_ENABLED_OFFSET) |
                            (gpioConfig.gpio2InputFilterSelection << NX_CONF_GPIO_INPUT_FILTER_SELECTION_OFFSET);
    uint8_t gpio2PadCtrlD = (gpioConfig.gpio2InputCfg << NX_CONF_GPIO_INPUT_CONF_OFFSET) |
                            (gpioConfig.gpio2OutputCfg << NX_CONF_GPIO_OUTPUT_CONF_OFFSET) |
                            (gpioConfig.gpio2Supply1v1n1v2 << NX_CONF_GPIO_SUPPLY_SELECTION_OFFSET);
    uint32_t gpio2PadCtrl = CALC_NX_CONF_GPIO_PAD_CTRL(gpio2PadCtrlA, gpio2PadCtrlB, gpio2PadCtrlC, gpio2PadCtrlD);

    uint8_t mgmtGPIOAC = gpioConfig.acManage;
    uint8_t readGPIOAC = gpioConfig.acRead;

#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "SetConfiguration GPIOMgmt[GPIO Management]");
#endif /* VERBOSE_APDU_LOGS */

    if (session_ctx == NULL) {
        goto cleanup;
    }

    tlvRet = SET_U8("Option", &pCmdHeaderBuf, &cmdHeaderBufLen, Nx_ConfigOption_GPIO_Mgmt);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_U8("GPIO1Mode", &pCmdDataBuf, &cmdDataBufBufLen, gpioConfig.gpio1Mode);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    if (gpioConfig.gpio1Mode == Nx_GPIOMgmtCfg_GPIOMode_Output) {
        gpio1Config = gpioConfig.gpio1OutputInitStateHigh;
    }
    else if (gpioConfig.gpio1Mode == Nx_GPIOMgmtCfg_GPIOMode_DownstreamPowerOut) {
        gpio1Config = (gpioConfig.gpio1PowerOutI2CEnabled << NX_CONF_GPIO_I2C_SUPPORT_ENABLED_OFFSET) |
                      (gpioConfig.gpio1PowerOutBackpowerEnabled << NX_CONF_GPIO_BACKPOWER_ENABLED_OFFSET);
    }
    else {
        gpio1Config = 0;
    }
    tlvRet = SET_U8("GPIO1Config", &pCmdDataBuf, &cmdDataBufBufLen, gpio1Config);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_U32_LSB("GPIO1PadCtrl", &pCmdDataBuf, &cmdDataBufBufLen, gpio1PadCtrl);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_U8("GPIO2Mode", &pCmdDataBuf, &cmdDataBufBufLen, gpioConfig.gpio2Mode);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    if (gpioConfig.gpio2Mode == Nx_GPIOMgmtCfg_GPIOMode_Output) {
        gpio2Config = gpioConfig.gpio2OutputInitStateHigh;
    }
    else if (gpioConfig.gpio2Mode == Nx_GPIOMgmtCfg_GPIOMode_DownstreamPowerOut) {
        gpio2Config = (gpioConfig.gpio2PowerOutI2CEnabled << NX_CONF_GPIO_I2C_SUPPORT_ENABLED_OFFSET) |
                      (gpioConfig.gpio2PowerOutBackpowerEnabled << NX_CONF_GPIO_BACKPOWER_ENABLED_OFFSET);
    }
    else {
        gpio2Config = 0;
    }
    tlvRet = SET_U8("GPIO2Config", &pCmdDataBuf, &cmdDataBufBufLen, gpio2Config);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_U32_LSB("GPIO2PadCtrl", &pCmdDataBuf, &cmdDataBufBufLen, gpio2PadCtrl);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_U8("GPIO1Notif", &pCmdDataBuf, &cmdDataBufBufLen, gpioConfig.gpio1OutputNotif);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_U8("GPIO2Notif", &pCmdDataBuf, &cmdDataBufBufLen, gpioConfig.gpio2OutputNotif);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    mgmtGPIOAC = mgmtGPIOAC & NX_CONF_COMM_MODE_AND_AC_MASK;
    tlvRet     = SET_U8("ManageGPIOAccessCondition", &pCmdDataBuf, &cmdDataBufBufLen, mgmtGPIOAC);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    readGPIOAC = readGPIOAC & NX_CONF_COMM_MODE_AND_AC_MASK;
    tlvRet     = SET_U8("ReadGPIOAccessCondition", &pCmdDataBuf, &cmdDataBufBufLen, readGPIOAC);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_U8("DefaultTarget", &pCmdDataBuf, &cmdDataBufBufLen, gpioConfig.gpio1PowerOutDefaultTarget);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_U8("InRushTarget", &pCmdDataBuf, &cmdDataBufBufLen, gpioConfig.gpio1PowerOutInRushTarget);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_U16_LSB("InRushDuration", &pCmdDataBuf, &cmdDataBufBufLen, gpioConfig.gpio1PowerOutInRushDuration);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_U8("AdditionalCurrent", &pCmdDataBuf, &cmdDataBufBufLen, gpioConfig.gpio1PowerOutAdditionalCurrent);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_U8("NFCPauseFileNo", &pCmdDataBuf, &cmdDataBufBufLen, gpioConfig.gpio2OutputNFCPauseFileNo);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet =
        SET_U24_LSB("NFCPauseOffset", &pCmdDataBuf, &cmdDataBufBufLen, (size_t)gpioConfig.gpio2OutputNFCPauseOffset);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet =
        SET_U24_LSB("NFCPauseLength", &pCmdDataBuf, &cmdDataBufBufLen, (size_t)gpioConfig.gpio2OutputNFCPauseLength);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    retStatus = DoAPDUTxRx_s_Case4(
        session_ctx, &hdr, cmdHeaderBuf, cmdHeaderBufLen, cmdDataBuf, cmdDataBufBufLen, rspbuf, &rspbufLen, NULL);
    if (retStatus == SM_OK) {
        retStatus = SM_NOT_OK;
        if (rspbufLen < 2) {
            goto cleanup;
        }

        retStatus = (pRspbuf[rspbufLen - 2] << 8) | (pRspbuf[rspbufLen - 1]);
        if (retStatus == SM_OK_ALT) {
            retStatus = SM_OK;
        }
    }

cleanup:
    return retStatus;
}

smStatus_t nx_SetConfig_CertMgmt(pSeSession_t session_ctx,
    uint8_t leafCacheSize,
    uint8_t intermCacheSize,
    uint8_t featureSelection,
    uint8_t acManageCertRepo)
{
    smStatus_t retStatus                      = SM_NOT_OK;
    tlvHeader_t hdr                           = {{NX_CLA, NX_INS_SET_CONFIG, NX_P1_DEFAULT, NX_P2_DEFAULT}};
    uint8_t cmdHeaderBuf[NX_MAX_BUF_SIZE_CMD] = {0};
    size_t cmdHeaderBufLen                    = 0;
    uint8_t cmdDataBuf[NX_MAX_BUF_SIZE_CMD]   = {0};
    size_t cmdDataBufBufLen                   = 0;
    int tlvRet                                = 1;
    uint8_t *pCmdHeaderBuf                    = &cmdHeaderBuf[0];
    uint8_t *pCmdDataBuf                      = &cmdDataBuf[0];
    uint8_t rspbuf[NX_MAX_BUF_SIZE_RSP]       = {0};
    size_t rspbufLen                          = sizeof(rspbuf);
    uint8_t *pRspbuf                          = &rspbuf[0];

#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "SetConfiguration [Certificate Management]");
#endif /* VERBOSE_APDU_LOGS */

    if (session_ctx == NULL) {
        goto cleanup;
    }

    if ((leafCacheSize < NX_CONF_CERT_LEAF_CACHE_SIZE_MIN) || (leafCacheSize > NX_CONF_CERT_LEAF_CACHE_SIZE_MAX)) {
        goto cleanup;
    }
    if ((intermCacheSize < NX_CONF_CERT_INTERM_CACHE_SIZE_MIN) ||
        (intermCacheSize > NX_CONF_CERT_INTERM_CACHE_SIZE_MAX)) {
        goto cleanup;
    }

    if (acManageCertRepo > 0x3F) {
        LOG_E("attempt to set a reserved bit");
        goto cleanup;
    }

    tlvRet = SET_U8("Option", &pCmdHeaderBuf, &cmdHeaderBufLen, Nx_ConfigOption_Cert_Mgmt);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_U8("LeafCacheSize", &pCmdDataBuf, &cmdDataBufBufLen, leafCacheSize);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_U8("IntermCacheSize", &pCmdDataBuf, &cmdDataBufBufLen, intermCacheSize);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);
    featureSelection = featureSelection & NX_CONF_CERT_FEATURE_SELECTION_MASK;
    tlvRet           = SET_U8("FeatureSelection", &pCmdDataBuf, &cmdDataBufBufLen, featureSelection);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    acManageCertRepo = acManageCertRepo & NX_CONF_COMM_MODE_AND_AC_MASK;
    tlvRet           = SET_U8("ManageCertRepoAccessCondition", &pCmdDataBuf, &cmdDataBufBufLen, acManageCertRepo);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    retStatus = DoAPDUTxRx_s_Case4(
        session_ctx, &hdr, cmdHeaderBuf, cmdHeaderBufLen, cmdDataBuf, cmdDataBufBufLen, rspbuf, &rspbufLen, NULL);

    if (retStatus == SM_OK) {
        retStatus       = SM_NOT_OK;
        size_t rspIndex = 0;

        if (rspbufLen != 2) {
            goto cleanup;
        }

        retStatus = (pRspbuf[rspIndex] << 8) | (pRspbuf[rspIndex + 1]);
        if (retStatus == SM_OK_ALT) {
            retStatus = SM_OK;
        }
    }

cleanup:
    return retStatus;
}

smStatus_t nx_SetConfig_WatchdogTimerMgmt(
    pSeSession_t session_ctx, uint8_t HWDTValue, uint8_t AWDT1Value, uint8_t AWDT2Value)
{
    smStatus_t retStatus                      = SM_NOT_OK;
    tlvHeader_t hdr                           = {{NX_CLA, NX_INS_SET_CONFIG, NX_P1_DEFAULT, NX_P2_DEFAULT}};
    uint8_t cmdHeaderBuf[NX_MAX_BUF_SIZE_CMD] = {0};
    size_t cmdHeaderBufLen                    = 0;
    uint8_t cmdDataBuf[NX_MAX_BUF_SIZE_CMD]   = {0};
    size_t cmdDataBufBufLen                   = 0;
    int tlvRet                                = 1;
    uint8_t *pCmdHeaderBuf                    = &cmdHeaderBuf[0];
    uint8_t *pCmdDataBuf                      = &cmdDataBuf[0];
    uint8_t rspbuf[NX_MAX_BUF_SIZE_RSP]       = {0};
    size_t rspbufLen                          = sizeof(rspbuf);
    uint8_t *pRspbuf                          = &rspbuf[0];
#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "SetConfiguration [Watchdog Timer Management]");
#endif /* VERBOSE_APDU_LOGS */

    if (session_ctx == NULL) {
        goto cleanup;
    }

    tlvRet = SET_U8("Option", &pCmdHeaderBuf, &cmdHeaderBufLen, Nx_ConfigOption_Watchdog_Mgmt);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_U8("HWDTValue", &pCmdDataBuf, &cmdDataBufBufLen, HWDTValue);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_U8("AWDT1Value", &pCmdDataBuf, &cmdDataBufBufLen, AWDT1Value);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_U8("AWDT2Value", &pCmdDataBuf, &cmdDataBufBufLen, AWDT2Value);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    retStatus = DoAPDUTxRx_s_Case4(
        session_ctx, &hdr, cmdHeaderBuf, cmdHeaderBufLen, cmdDataBuf, cmdDataBufBufLen, rspbuf, &rspbufLen, NULL);

    if (retStatus == SM_OK) {
        retStatus       = SM_NOT_OK;
        size_t rspIndex = 0;

        if (rspbufLen != 2) {
            goto cleanup;
        }

        retStatus = (pRspbuf[rspIndex] << 8) | (pRspbuf[rspIndex + 1]);
        if (retStatus == SM_OK_ALT) {
            retStatus = SM_OK;
        }
    }

cleanup:
    return retStatus;
}

smStatus_t nx_SetConfig_CryptoAPIMgmt(pSeSession_t session_ctx,
    uint8_t cryptoAPISupport,
    uint8_t acCryptoRequest,
    uint8_t acChangeKey,
    uint8_t TBPolicyCount,
    Nx_slot_buffer_policy_t *TBPolicy,
    uint8_t SBPolicyCount,
    Nx_slot_buffer_policy_t *SBPolicy)
{
    smStatus_t retStatus                      = SM_NOT_OK;
    tlvHeader_t hdr                           = {{NX_CLA, NX_INS_SET_CONFIG, NX_P1_DEFAULT, NX_P2_DEFAULT}};
    uint8_t cmdHeaderBuf[NX_MAX_BUF_SIZE_CMD] = {0};
    size_t cmdHeaderBufLen                    = 0;
    uint8_t cmdDataBuf[NX_MAX_BUF_SIZE_CMD]   = {0};
    size_t cmdDataBufBufLen                   = 0;
    int tlvRet                                = 1;
    uint8_t *pCmdHeaderBuf                    = &cmdHeaderBuf[0];
    uint8_t *pCmdDataBuf                      = &cmdDataBuf[0];
    uint8_t rspbuf[NX_MAX_BUF_SIZE_RSP]       = {0};
    size_t rspbufLen                          = sizeof(rspbuf);
    uint8_t *pRspbuf                          = &rspbuf[0];
    uint8_t commMode                          = 0;
#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "SetConfiguration [Crypto API Management]");
#endif /* VERBOSE_APDU_LOGS */

    if (session_ctx == NULL) {
        goto cleanup;
    }

    if ((TBPolicyCount > NX_TB_POLICY_MAX_COUNT) || (SBPolicyCount > NX_SB_POLICY_MAX_COUNT)) {
        goto cleanup;
    }
    if ((TBPolicy == NULL) || (SBPolicy == NULL)) {
        goto cleanup;
    }

    tlvRet = SET_U8("Option", &pCmdHeaderBuf, &cmdHeaderBufLen, Nx_ConfigOption_Crypto_API_Mgmt);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    cryptoAPISupport = cryptoAPISupport & NX_CONF_CRYPTOAPI_SUPPORT_MASK;
    tlvRet           = SET_U8("Support", &pCmdDataBuf, &cmdDataBufBufLen, cryptoAPISupport);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    acCryptoRequest = acCryptoRequest & NX_CONF_COMM_MODE_AND_AC_MASK;

    tlvRet = SET_U8("AccessCondition", &pCmdDataBuf, &cmdDataBufBufLen, acCryptoRequest);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    acChangeKey = acChangeKey & NX_CONF_AC_MASK;

    tlvRet = SET_U8("changeAccessCondition", &pCmdDataBuf, &cmdDataBufBufLen, acChangeKey);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_U8("TBPolicyCount", &pCmdDataBuf, &cmdDataBufBufLen, TBPolicyCount);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_u8buf(
        "TBPolicy", &pCmdDataBuf, &cmdDataBufBufLen, (uint8_t *)TBPolicy, (TBPolicyCount * NX_POLICY_BUF_SIZE));
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_U8("SBPolicyCount", &pCmdDataBuf, &cmdDataBufBufLen, SBPolicyCount);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_u8buf(
        "SBPolicy", &pCmdDataBuf, &cmdDataBufBufLen, (uint8_t *)SBPolicy, (SBPolicyCount * NX_POLICY_BUF_SIZE));
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    retStatus = DoAPDUTxRx_s_Case4(
        session_ctx, &hdr, cmdHeaderBuf, cmdHeaderBufLen, cmdDataBuf, cmdDataBufBufLen, rspbuf, &rspbufLen, NULL);
    if (retStatus == SM_OK) {
        retStatus       = SM_NOT_OK;
        size_t rspIndex = 0;

        if (rspbufLen != 2) {
            goto cleanup;
        }

        retStatus = (pRspbuf[rspIndex] << 8) | (pRspbuf[rspIndex + 1]);
        if (retStatus == SM_OK_ALT) {
            retStatus = SM_OK;
        }
    }

    retStatus = SM_NOT_OK;
    commMode  = ((acCryptoRequest >> NX_COMM_MODE_BIT_SHIFT) & NX_COMM_MODE_BIT_MASK);
    if ((commMode == Nx_CommMode_Plain) || (commMode == Nx_CommMode_MAC) || (commMode == Nx_CommMode_FULL)) {
        retStatus                       = SM_OK;
        session_ctx->userCryptoCommMode = commMode;
    }
    else {
        goto cleanup;
    }

cleanup:
    return retStatus;
}

smStatus_t nx_SetConfig_AuthCounterLimit(
    pSeSession_t session_ctx, uint8_t authCtrFileID, uint8_t authCtrOption, uint32_t authCtrLimit)
{
    smStatus_t retStatus                      = SM_NOT_OK;
    tlvHeader_t hdr                           = {{NX_CLA, NX_INS_SET_CONFIG, NX_P1_DEFAULT, NX_P2_DEFAULT}};
    uint8_t cmdHeaderBuf[NX_MAX_BUF_SIZE_CMD] = {0};
    size_t cmdHeaderBufLen                    = 0;
    uint8_t cmdDataBuf[NX_MAX_BUF_SIZE_CMD]   = {0};
    size_t cmdDataBufBufLen                   = 0;
    int tlvRet                                = 1;
    uint8_t *pCmdHeaderBuf                    = &cmdHeaderBuf[0];
    uint8_t *pCmdDataBuf                      = &cmdDataBuf[0];
    uint8_t rspbuf[NX_MAX_BUF_SIZE_RSP]       = {0};
    size_t rspbufLen                          = sizeof(rspbuf);
    uint8_t *pRspbuf                          = &rspbuf[0];

#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "SetConfiguration [Authentication Counter and Limit Configuration]");
#endif /* VERBOSE_APDU_LOGS */

    if (session_ctx == NULL) {
        goto cleanup;
    }

    tlvRet = SET_U8("Option", &pCmdHeaderBuf, &cmdHeaderBufLen, Nx_ConfigOption_Auth_Counter_Limit);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_U8("AuthCtrFileID", &pCmdDataBuf, &cmdDataBufBufLen, authCtrFileID);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    authCtrOption = authCtrOption & NX_CONF_AUTH_COUNTER_AES_AUTH_ENABLED_MASK;

    tlvRet = SET_U8("AuthCtrOption", &pCmdDataBuf, &cmdDataBufBufLen, authCtrOption);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_U32_LSB("AuthCtrLimit", &pCmdDataBuf, &cmdDataBufBufLen, authCtrLimit);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    retStatus = DoAPDUTxRx_s_Case4(
        session_ctx, &hdr, cmdHeaderBuf, cmdHeaderBufLen, cmdDataBuf, cmdDataBufBufLen, rspbuf, &rspbufLen, NULL);

    if (retStatus == SM_OK) {
        retStatus       = SM_NOT_OK;
        size_t rspIndex = 0;

        if (rspbufLen != 2) {
            goto cleanup;
        }

        retStatus = (pRspbuf[rspIndex] << 8) | (pRspbuf[rspIndex + 1]);
        if (retStatus == SM_OK_ALT) {
            retStatus = SM_OK;
        }
    }

cleanup:
    return retStatus;
}

smStatus_t nx_SetConfig_HaltWakeupConfig(
    pSeSession_t session_ctx, uint8_t wakeupOptionA, uint8_t wakeupOptionB, uint8_t RDACSetting, uint8_t HALTOption)
{
    smStatus_t retStatus                      = SM_NOT_OK;
    tlvHeader_t hdr                           = {{NX_CLA, NX_INS_SET_CONFIG, NX_P1_DEFAULT, NX_P2_DEFAULT}};
    uint8_t cmdHeaderBuf[NX_MAX_BUF_SIZE_CMD] = {0};
    size_t cmdHeaderBufLen                    = 0;
    uint8_t cmdDataBuf[NX_MAX_BUF_SIZE_CMD]   = {0};
    size_t cmdDataBufBufLen                   = 0;
    uint8_t rspbuf[NX_MAX_BUF_SIZE_RSP]       = {0};
    size_t rspbufLen                          = sizeof(rspbuf);
    uint8_t *pRspbuf                          = &rspbuf[0];
    int tlvRet                                = 1;
    uint8_t *pCmdHeaderBuf                    = &cmdHeaderBuf[0];
    uint8_t *pCmdDataBuf                      = &cmdDataBuf[0];
    uint8_t i2cWakeupAddress                  = 0x00;
    uint8_t i2cWakeupCycle                    = 0x00;
#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "SetConfiguration [HALT and Wake-up Configuration]");
#endif /* VERBOSE_APDU_LOGS */

    if (session_ctx == NULL) {
        goto cleanup;
    }

    // Check max i2c address and cycle value.
    i2cWakeupAddress = ((wakeupOptionB & NX_CONF_HALT_WAKEUPB_I2C_WAKEUP_ADDRESS_MASK) >>
                        NX_CONF_HALT_WAKEUPB_I2C_WAKEUP_ADDRESS_BITOFFSET);
    i2cWakeupAddress |= ((wakeupOptionA & NX_CONF_HALT_WAKEUPA_I2C_WAKEUP_ADDRESS_MASK)
                         << NX_CONF_HALT_WAKEUPA_I2C_WAKEUP_ADDRESS_BIT_SHIFT);

    if ((i2cWakeupAddress & NX_CONF_HALT_WAKEUP_I2C_WAKEUP_ADDRESS_MASK) > NX_CONF_HALT_WAKEUP_I2C_WAKEUP_ADDRESS_MAX) {
        goto cleanup;
    }

    i2cWakeupCycle = ((wakeupOptionB & NX_CONF_HALT_WAKEUPB_I2C_WAKEUP_CYCLE_MASK) >>
                      NX_CONF_HALT_WAKEUPB_I2C_WAKEUP_CYCLE_BITOFFSET);
    if (i2cWakeupCycle > NX_CONF_HALT_WAKEUPA_I2C_WAKEUP_CYCLE_MAX) {
        goto cleanup;
    }

    tlvRet = SET_U8("Option", &pCmdHeaderBuf, &cmdHeaderBufLen, Nx_ConfigOption_Halt_Wakeup_Config);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_U8("WakeUpA", &pCmdDataBuf, &cmdDataBufBufLen, wakeupOptionA);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_U8("WakeUpB", &pCmdDataBuf, &cmdDataBufBufLen, wakeupOptionB);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_U8("RDASetting", &pCmdDataBuf, &cmdDataBufBufLen, RDACSetting);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    HALTOption = HALTOption & NX_CONF_HALT_OPTION_GPIO_RESET_MASK;
    tlvRet     = SET_U8("HALTOption", &pCmdDataBuf, &cmdDataBufBufLen, HALTOption);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    retStatus = DoAPDUTxRx_s_Case4(
        session_ctx, &hdr, cmdHeaderBuf, cmdHeaderBufLen, cmdDataBuf, cmdDataBufBufLen, rspbuf, &rspbufLen, NULL);

    if (retStatus == SM_OK) {
        retStatus       = SM_NOT_OK;
        size_t rspIndex = 0;

        if (rspbufLen != 2) {
            goto cleanup;
        }

        retStatus = (pRspbuf[rspIndex] << 8) | (pRspbuf[rspIndex + 1]);
        if (retStatus == SM_OK_ALT) {
            retStatus = SM_OK;
        }
    }

cleanup:
    return retStatus;
}

smStatus_t nx_SetConfig_DeferConfig(pSeSession_t session_ctx, uint8_t deferralCount, uint8_t *deferralList)
{
    smStatus_t retStatus                      = SM_NOT_OK;
    tlvHeader_t hdr                           = {{NX_CLA, NX_INS_SET_CONFIG, NX_P1_DEFAULT, NX_P2_DEFAULT}};
    uint8_t cmdHeaderBuf[NX_MAX_BUF_SIZE_CMD] = {0};
    size_t cmdHeaderBufLen                    = 0;
    uint8_t cmdDataBuf[NX_MAX_BUF_SIZE_CMD]   = {0};
    size_t cmdDataBufBufLen                   = 0;
    uint8_t rspbuf[NX_MAX_BUF_SIZE_RSP]       = {0};
    size_t rspbufLen                          = sizeof(rspbuf);
    uint8_t *pRspbuf                          = &rspbuf[0];
    int tlvRet                                = 1;
    uint8_t *pCmdHeaderBuf                    = &cmdHeaderBuf[0];
    uint8_t *pCmdDataBuf                      = &cmdDataBuf[0];

#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "SetConfiguration [Defer Configurations]");
#endif /* VERBOSE_APDU_LOGS */

    if ((session_ctx == NULL) || (deferralList == NULL)) {
        goto cleanup;
    }

    if ((deferralCount == 0) || (deferralCount > NX_CONF_DEFERRAL_COUNT_MAX)) {
        goto cleanup;
    }

    tlvRet = SET_U8("Option", &pCmdHeaderBuf, &cmdHeaderBufLen, Nx_ConfigOption_Defer_Config);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_U8("DeferralCount", &pCmdDataBuf, &cmdDataBufBufLen, deferralCount);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_u8buf(
        "Defer Configurations", &pCmdDataBuf, &cmdDataBufBufLen, deferralList, NX_CONF_DEFERRAL_SIZE * deferralCount);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    retStatus = DoAPDUTxRx_s_Case4(
        session_ctx, &hdr, cmdHeaderBuf, cmdHeaderBufLen, cmdDataBuf, cmdDataBufBufLen, rspbuf, &rspbufLen, NULL);

    if (retStatus == SM_OK) {
        retStatus       = SM_NOT_OK;
        size_t rspIndex = 0;

        if (rspbufLen != 2) {
            goto cleanup;
        }

        retStatus = (pRspbuf[rspIndex] << 8) | (pRspbuf[rspIndex + 1]);
        if (retStatus == SM_OK_ALT) {
            retStatus = SM_OK;
        }
    }

cleanup:
    return retStatus;
}

smStatus_t nx_SetConfig_LockConfig(pSeSession_t session_ctx, uint32_t lockBitMap)
{
    smStatus_t retStatus                      = SM_NOT_OK;
    tlvHeader_t hdr                           = {{NX_CLA, NX_INS_SET_CONFIG, NX_P1_DEFAULT, NX_P2_DEFAULT}};
    uint8_t cmdHeaderBuf[NX_MAX_BUF_SIZE_CMD] = {0};
    size_t cmdHeaderBufLen                    = 0;
    uint8_t cmdDataBuf[NX_MAX_BUF_SIZE_CMD]   = {0};
    size_t cmdDataBufBufLen                   = 0;
    int tlvRet                                = 1;
    uint8_t *pCmdHeaderBuf                    = &cmdHeaderBuf[0];
    uint8_t *pCmdDataBuf                      = &cmdDataBuf[0];
    uint8_t rspbuf[NX_MAX_BUF_SIZE_RSP]       = {0};
    size_t rspbufLen                          = sizeof(rspbuf);
    uint8_t *pRspbuf                          = &rspbuf[0];
    uint8_t lockBitMapBuf[3]                  = {0};
    uint8_t lockBitMapBufLen                  = sizeof(lockBitMapBuf);
#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "SetConfiguration [Lock Configurations]");
#endif /* VERBOSE_APDU_LOGS */

    if (session_ctx == NULL) {
        goto cleanup;
    }

    if (lockBitMap >
        ((1 << NX_NUM_CARD_CONFIGURATIONS) - 1)) { /* At max, NX_NUM_CARD_CONFIGURATIONS number of bits can be set */
        goto cleanup;
    }

    tlvRet = SET_U8("Option", &pCmdHeaderBuf, &cmdHeaderBufLen, Nx_ConfigOption_Lock_Config);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    lockBitMapBuf[0] = (lockBitMap >> (2 * 8)) & 0xFF;
    lockBitMapBuf[1] = (lockBitMap >> (1 * 8)) & 0xFF;
    lockBitMapBuf[2] = (lockBitMap >> (0 * 8)) & 0xFF;
    tlvRet           = SET_u8buf("LockBitMap", &pCmdDataBuf, &cmdDataBufBufLen, lockBitMapBuf, lockBitMapBufLen);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    retStatus = DoAPDUTxRx_s_Case4(
        session_ctx, &hdr, cmdHeaderBuf, cmdHeaderBufLen, cmdDataBuf, cmdDataBufBufLen, rspbuf, &rspbufLen, NULL);

    if (retStatus == SM_OK) {
        retStatus       = SM_NOT_OK;
        size_t rspIndex = 0;

        if (rspbufLen != 2) {
            goto cleanup;
        }

        retStatus = (pRspbuf[rspIndex] << 8) | (pRspbuf[rspIndex + 1]);
        if (retStatus == SM_OK_ALT) {
            retStatus = SM_OK;
        }
    }

cleanup:
    return retStatus;
}

smStatus_t nx_GetConfig_ManufactureConfig(pSeSession_t session_ctx, uint16_t *productFeature)
{
    smStatus_t retStatus                      = SM_NOT_OK;
    tlvHeader_t hdr                           = {{NX_CLA, NX_INS_GET_CONFIG, NX_P1_DEFAULT, NX_P2_DEFAULT}};
    uint8_t cmdHeaderBuf[NX_MAX_BUF_SIZE_CMD] = {0};
    size_t cmdHeaderBufLen                    = 0;
    uint8_t cmdDataBuf[NX_MAX_BUF_SIZE_CMD]   = {0};
    size_t cmdDataBufBufLen                   = 0;
    uint8_t rspbuf[NX_MAX_BUF_SIZE_RSP]       = {0};
    uint8_t *pRspbuf                          = &rspbuf[0];
    size_t rspbufLen                          = sizeof(rspbuf);
#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "GetConfiguration [manufacturer configuration]");
#endif /* VERBOSE_APDU_LOGS */

    ENSURE_OR_GO_CLEANUP(NULL != session_ctx)
    ENSURE_OR_GO_CLEANUP(NULL != productFeature)

    retStatus = DoAPDUTxRx_s_Case4(
        session_ctx, &hdr, cmdHeaderBuf, cmdHeaderBufLen, cmdDataBuf, cmdDataBufBufLen, rspbuf, &rspbufLen, NULL);
    if (retStatus == SM_OK) {
        retStatus       = SM_NOT_OK;
        size_t rspIndex = 0;
        int tlvRet      = 0;
        if (rspbufLen != 4) {
            goto cleanup;
        }

        tlvRet = get_U16_LSB(pRspbuf, &rspIndex, rspbufLen, productFeature); /*  */
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);

        retStatus = (pRspbuf[rspbufLen - 2] << 8) | (pRspbuf[rspbufLen - 1]);
        if (retStatus == SM_OK_ALT) {
            retStatus = SM_OK;
        }
    }

cleanup:
    return retStatus;
}

smStatus_t nx_GetConfig_PICCConfig(pSeSession_t session_ctx, uint8_t *PICCConfig)
{
    smStatus_t retStatus                      = SM_NOT_OK;
    tlvHeader_t hdr                           = {{NX_CLA, NX_INS_GET_CONFIG, NX_P1_DEFAULT, NX_P2_DEFAULT}};
    uint8_t cmdHeaderBuf[NX_MAX_BUF_SIZE_CMD] = {0};
    size_t cmdHeaderBufLen                    = 0;
    uint8_t cmdDataBuf[NX_MAX_BUF_SIZE_CMD]   = {0};
    size_t cmdDataBufBufLen                   = 0;
    int tlvRet                                = 1;
    uint8_t *pCmdHeaderBuf                    = &cmdHeaderBuf[0];
    uint8_t rspbuf[NX_MAX_BUF_SIZE_RSP]       = {0};
    uint8_t *pRspbuf                          = &rspbuf[0];
    size_t rspbufLen                          = sizeof(rspbuf);
#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "GetConfiguration [PICC Configurations]");
#endif /* VERBOSE_APDU_LOGS */

    if ((session_ctx == NULL) || (PICCConfig == NULL)) {
        goto cleanup;
    }

    tlvRet = SET_U8("Option", &pCmdHeaderBuf, &cmdHeaderBufLen, Nx_ConfigOption_PICC_Config);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    retStatus = DoAPDUTxRx_s_Case4(
        session_ctx, &hdr, cmdHeaderBuf, cmdHeaderBufLen, cmdDataBuf, cmdDataBufBufLen, rspbuf, &rspbufLen, NULL);
    if (retStatus == SM_OK) {
        retStatus = SM_NOT_OK;
        if (rspbufLen != 3) {
            goto cleanup;
        }
        *PICCConfig = rspbuf[0];
        retStatus   = (pRspbuf[rspbufLen - 2] << 8) | (pRspbuf[rspbufLen - 1]);
        if (retStatus == SM_OK_ALT) {
            retStatus = SM_OK;
        }
    }

cleanup:
    return retStatus;
}

smStatus_t nx_GetConfig_ATSUpdate(pSeSession_t session_ctx, uint8_t *userATS, size_t *userATSLen)
{
    smStatus_t retStatus                      = SM_NOT_OK;
    tlvHeader_t hdr                           = {{NX_CLA, NX_INS_GET_CONFIG, NX_P1_DEFAULT, NX_P2_DEFAULT}};
    uint8_t cmdHeaderBuf[NX_MAX_BUF_SIZE_CMD] = {0};
    size_t cmdHeaderBufLen                    = 0;
    uint8_t cmdDataBuf[NX_MAX_BUF_SIZE_CMD]   = {0};
    size_t cmdDataBufBufLen                   = 0;
    int tlvRet                                = 1;
    uint8_t *pCmdHeaderBuf                    = &cmdHeaderBuf[0];
    uint8_t rspbuf[NX_MAX_BUF_SIZE_RSP]       = {0};
    uint8_t *pRspbuf                          = &rspbuf[0];
    size_t rspbufLen                          = sizeof(rspbuf);
#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "GetConfiguration [ATS Update]");
#endif /* VERBOSE_APDU_LOGS */

    if ((session_ctx == NULL) || (userATS == NULL) || (userATSLen == NULL)) {
        goto cleanup;
    }

    tlvRet = SET_U8("Option", &pCmdHeaderBuf, &cmdHeaderBufLen, Nx_ConfigOption_ATS_Update);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    retStatus = DoAPDUTxRx_s_Case4(
        session_ctx, &hdr, cmdHeaderBuf, cmdHeaderBufLen, cmdDataBuf, cmdDataBufBufLen, rspbuf, &rspbufLen, NULL);
    if (retStatus == SM_OK) {
        retStatus = SM_NOT_OK;
        if ((rspbufLen >= 3) && (rspbufLen <= 22)) {
            memcpy(userATS, rspbuf, rspbufLen - 2);
            *userATSLen = rspbufLen - 2;
            retStatus   = (pRspbuf[rspbufLen - 2] << 8) | (pRspbuf[rspbufLen - 1]);
            if (retStatus == SM_OK_ALT) {
                retStatus = SM_OK;
            }
        }
    }

cleanup:
    return retStatus;
}

smStatus_t nx_GetConfig_SAKUpdate(pSeSession_t session_ctx, uint8_t *sak1, uint8_t *sak2)
{
    smStatus_t retStatus                      = SM_NOT_OK;
    tlvHeader_t hdr                           = {{NX_CLA, NX_INS_GET_CONFIG, NX_P1_DEFAULT, NX_P2_DEFAULT}};
    uint8_t cmdHeaderBuf[NX_MAX_BUF_SIZE_CMD] = {0};
    size_t cmdHeaderBufLen                    = 0;
    uint8_t cmdDataBuf[NX_MAX_BUF_SIZE_CMD]   = {0};
    size_t cmdDataBufBufLen                   = 0;
    int tlvRet                                = 1;
    uint8_t *pCmdHeaderBuf                    = &cmdHeaderBuf[0];
    uint8_t rspbuf[NX_MAX_BUF_SIZE_RSP]       = {0};
    uint8_t *pRspbuf                          = &rspbuf[0];
    size_t rspbufLen                          = sizeof(rspbuf);
#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "GetConfiguration [SAK Update]");
#endif /* VERBOSE_APDU_LOGS */

    if ((session_ctx == NULL) || (sak1 == NULL) || (sak2 == NULL)) {
        goto cleanup;
    }

    tlvRet = SET_U8("Option", &pCmdHeaderBuf, &cmdHeaderBufLen, Nx_ConfigOption_SAK_Update);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    retStatus = DoAPDUTxRx_s_Case4(
        session_ctx, &hdr, cmdHeaderBuf, cmdHeaderBufLen, cmdDataBuf, cmdDataBufBufLen, rspbuf, &rspbufLen, NULL);
    if (retStatus == SM_OK) {
        retStatus       = SM_NOT_OK;
        size_t rspIndex = 0;

        if (rspbufLen != 4) { // 2 UserSAK + 2 bytes SW
            goto cleanup;
        }

        tlvRet = get_U8(pRspbuf, &rspIndex, rspbufLen, sak1); /*  */
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);
        tlvRet = get_U8(pRspbuf, &rspIndex, rspbufLen, sak2); /*  */
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);
        if ((rspIndex + 2) == rspbufLen) {
            retStatus = (pRspbuf[rspIndex] << 8) | (pRspbuf[rspIndex + 1]);
        }

        if (retStatus == SM_OK_ALT) {
            retStatus = SM_OK;
        }
    }

cleanup:
    return retStatus;
}

smStatus_t nx_GetConfig_SMConfig(pSeSession_t session_ctx, uint8_t *SMConfigA, uint8_t *SMConfigB)
{
    smStatus_t retStatus                      = SM_NOT_OK;
    tlvHeader_t hdr                           = {{NX_CLA, NX_INS_GET_CONFIG, NX_P1_DEFAULT, NX_P2_DEFAULT}};
    uint8_t cmdHeaderBuf[NX_MAX_BUF_SIZE_CMD] = {0};
    size_t cmdHeaderBufLen                    = 0;
    uint8_t cmdDataBuf[NX_MAX_BUF_SIZE_CMD]   = {0};
    size_t cmdDataBufBufLen                   = 0;
    int tlvRet                                = 1;
    uint8_t *pCmdHeaderBuf                    = &cmdHeaderBuf[0];
    uint8_t rspbuf[NX_MAX_BUF_SIZE_RSP]       = {0};
    uint8_t *pRspbuf                          = &rspbuf[0];
    size_t rspbufLen                          = sizeof(rspbuf);
#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "GetConfiguration [Secure Messaging Configuration]");
#endif /* VERBOSE_APDU_LOGS */

    if ((NULL == session_ctx) || (NULL == SMConfigA) || (NULL == SMConfigB)) {
        goto cleanup;
    }

    tlvRet = SET_U8("Option", &pCmdHeaderBuf, &cmdHeaderBufLen, Nx_ConfigOption_Secure_Msg_Config);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    retStatus = DoAPDUTxRx_s_Case4(
        session_ctx, &hdr, cmdHeaderBuf, cmdHeaderBufLen, cmdDataBuf, cmdDataBufBufLen, rspbuf, &rspbufLen, NULL);
    if (retStatus == SM_OK) {
        retStatus       = SM_NOT_OK;
        size_t rspIndex = 0;

        if (rspbufLen != 4) { // 2 UserSAK + 2 bytes SW
            goto cleanup;
        }

        tlvRet = get_U8(pRspbuf, &rspIndex, rspbufLen, SMConfigB); /*  */
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);

        tlvRet = get_U8(pRspbuf, &rspIndex, rspbufLen, SMConfigA); /*  */
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);

        if ((rspIndex + 2) == rspbufLen) {
            retStatus = (pRspbuf[rspIndex] << 8) | (pRspbuf[rspIndex + 1]);
        }
        if (retStatus == SM_OK_ALT) {
            retStatus = SM_OK;
        }
    }

cleanup:
    return retStatus;
}

smStatus_t nx_GetConfig_CapData(pSeSession_t session_ctx, uint8_t *CapDataBuf, uint8_t *CapDataBufLen)
{
    smStatus_t retStatus                      = SM_NOT_OK;
    tlvHeader_t hdr                           = {{NX_CLA, NX_INS_GET_CONFIG, NX_P1_DEFAULT, NX_P2_DEFAULT}};
    uint8_t cmdHeaderBuf[NX_MAX_BUF_SIZE_CMD] = {0};
    size_t cmdHeaderBufLen                    = 0;
    uint8_t cmdDataBuf[NX_MAX_BUF_SIZE_CMD]   = {0};
    size_t cmdDataBufBufLen                   = 0;
    int tlvRet                                = 1;
    uint8_t *pCmdHeaderBuf                    = &cmdHeaderBuf[0];
    uint8_t rspbuf[NX_MAX_BUF_SIZE_RSP]       = {0};
    uint8_t *pRspbuf                          = &rspbuf[0];
    size_t rspbufLen                          = sizeof(rspbuf);
#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "GetConfiguration [Capability Data]");
#endif /* VERBOSE_APDU_LOGS */

    if ((session_ctx == NULL) || (CapDataBuf == NULL) || (CapDataBufLen == NULL)) {
        goto cleanup;
    }

    tlvRet = SET_U8("Option", &pCmdHeaderBuf, &cmdHeaderBufLen, Nx_ConfigOption_Capability_Data);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    retStatus = DoAPDUTxRx_s_Case4(
        session_ctx, &hdr, cmdHeaderBuf, cmdHeaderBufLen, cmdDataBuf, cmdDataBufBufLen, rspbuf, &rspbufLen, NULL);
    if (retStatus == SM_OK) {
        retStatus       = SM_NOT_OK;
        size_t rspIndex = 0;

        if (rspbufLen != NX_CONF_CAPABILITY_DATA_LEN + 2) { // 10 CapData  + 2 bytes SW
            goto cleanup;
        }
        if (*CapDataBufLen >= NX_CONF_CAPABILITY_DATA_LEN) {
            tlvRet =
                get_u8buf(pRspbuf, &rspIndex, rspbufLen, (uint8_t *)CapDataBuf, NX_CONF_CAPABILITY_DATA_LEN); /*  */
            ENSURE_OR_GO_CLEANUP(0 == tlvRet);
            *CapDataBufLen = NX_CONF_CAPABILITY_DATA_LEN;
        }
        else {
            *CapDataBufLen = 0;
            goto cleanup;
        }

        if ((rspIndex + 2) == rspbufLen) {
            retStatus = (pRspbuf[rspIndex] << 8) | (pRspbuf[rspIndex + 1]);
        }

        if (retStatus == SM_OK_ALT) {
            retStatus = SM_OK;
        }
    }

cleanup:
    return retStatus;
}

smStatus_t nx_GetConfig_ATQAUpdate(pSeSession_t session_ctx, uint16_t *userATQA)
{
    smStatus_t retStatus                      = SM_NOT_OK;
    tlvHeader_t hdr                           = {{NX_CLA, NX_INS_GET_CONFIG, NX_P1_DEFAULT, NX_P2_DEFAULT}};
    uint8_t cmdHeaderBuf[NX_MAX_BUF_SIZE_CMD] = {0};
    size_t cmdHeaderBufLen                    = 0;
    uint8_t cmdDataBuf[NX_MAX_BUF_SIZE_CMD]   = {0};
    size_t cmdDataBufBufLen                   = 0;
    int tlvRet                                = 1;
    uint8_t *pCmdHeaderBuf                    = &cmdHeaderBuf[0];
    uint8_t rspbuf[NX_MAX_BUF_SIZE_RSP]       = {0};
    uint8_t *pRspbuf                          = &rspbuf[0];
    size_t rspbufLen                          = sizeof(rspbuf);
#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "GetConfiguration [ATQA Update]");
#endif /* VERBOSE_APDU_LOGS */

    if ((session_ctx == NULL) || (userATQA == NULL)) {
        goto cleanup;
    }

    tlvRet = SET_U8("Option", &pCmdHeaderBuf, &cmdHeaderBufLen, Nx_ConfigOption_ATQA_Update);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    retStatus = DoAPDUTxRx_s_Case4(
        session_ctx, &hdr, cmdHeaderBuf, cmdHeaderBufLen, cmdDataBuf, cmdDataBufBufLen, rspbuf, &rspbufLen, NULL);
    if (retStatus == SM_OK) {
        retStatus       = SM_NOT_OK;
        size_t rspIndex = 0;

        if (rspbufLen != 4) { // 2 UserSAK + 2 bytes SW
            goto cleanup;
        }

        tlvRet = get_U16_LSB(pRspbuf, &rspIndex, rspbufLen, userATQA); /*  */
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);
        if ((rspIndex + 2) == rspbufLen) {
            retStatus = (pRspbuf[rspIndex] << 8) | (pRspbuf[rspIndex + 1]);
        }

        if (retStatus == SM_OK_ALT) {
            retStatus = SM_OK;
        }
    }

cleanup:
    return retStatus;
}

smStatus_t nx_GetConfig_SilentModeConfig(pSeSession_t session_ctx, uint8_t *silentMode, uint8_t *REQS, uint8_t *WUPS)
{
    smStatus_t retStatus                      = SM_NOT_OK;
    tlvHeader_t hdr                           = {{NX_CLA, NX_INS_GET_CONFIG, NX_P1_DEFAULT, NX_P2_DEFAULT}};
    uint8_t cmdHeaderBuf[NX_MAX_BUF_SIZE_CMD] = {0};
    size_t cmdHeaderBufLen                    = 0;
    uint8_t cmdDataBuf[NX_MAX_BUF_SIZE_CMD]   = {0};
    size_t cmdDataBufBufLen                   = 0;
    int tlvRet                                = 1;
    uint8_t *pCmdHeaderBuf                    = &cmdHeaderBuf[0];
    uint8_t rspbuf[NX_MAX_BUF_SIZE_RSP]       = {0};
    uint8_t *pRspbuf                          = &rspbuf[0];
    size_t rspbufLen                          = sizeof(rspbuf);
#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "GetConfiguration [Silent Mode Configuration]");
#endif /* VERBOSE_APDU_LOGS */

    if ((NULL == session_ctx) || (NULL == silentMode) || (NULL == REQS) || (NULL == WUPS)) {
        goto cleanup;
    }

    tlvRet = SET_U8("Option", &pCmdHeaderBuf, &cmdHeaderBufLen, Nx_ConfigOption_Silent_Mode_Config);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    retStatus = DoAPDUTxRx_s_Case4(
        session_ctx, &hdr, cmdHeaderBuf, cmdHeaderBufLen, cmdDataBuf, cmdDataBufBufLen, rspbuf, &rspbufLen, NULL);
    if (retStatus == SM_OK) {
        retStatus       = SM_NOT_OK;
        size_t rspIndex = 0;

        if ((rspbufLen != 3) && (rspbufLen != 5)) { // + 2 bytes SW
            goto cleanup;
        }

        tlvRet = get_U8(pRspbuf, &rspIndex, rspbufLen, silentMode); /*  */
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);

        if (*silentMode & NX_CONF_SILENTMODE_CUSTOMIZED_REQS_WUPS_ENABLE) {
            if (rspbufLen != 5) { // + 2 bytes SW
                goto cleanup;
            }

            tlvRet = get_U8(pRspbuf, &rspIndex, rspbufLen, REQS); /*  */
            ENSURE_OR_GO_CLEANUP(0 == tlvRet);

            tlvRet = get_U8(pRspbuf, &rspIndex, rspbufLen, WUPS); /*  */
            ENSURE_OR_GO_CLEANUP(0 == tlvRet);
        }
        else if (rspbufLen != 3) { // + 2 bytes SW
            goto cleanup;
        }

        if ((rspIndex + 2) == rspbufLen) {
            retStatus = (pRspbuf[rspIndex] << 8) | (pRspbuf[rspIndex + 1]);
        }

        if (retStatus == SM_OK_ALT) {
            retStatus = SM_OK;
        }
    }

cleanup:
    return retStatus;
}

smStatus_t nx_GetConfig_EnhancedPrivacyConfig(pSeSession_t session_ctx, uint8_t *privacyOption, uint8_t *appPrivacyKey)
{
    smStatus_t retStatus                      = SM_NOT_OK;
    tlvHeader_t hdr                           = {{NX_CLA, NX_INS_GET_CONFIG, NX_P1_DEFAULT, NX_P2_DEFAULT}};
    uint8_t cmdHeaderBuf[NX_MAX_BUF_SIZE_CMD] = {0};
    size_t cmdHeaderBufLen                    = 0;
    uint8_t cmdDataBuf[NX_MAX_BUF_SIZE_CMD]   = {0};
    size_t cmdDataBufBufLen                   = 0;
    int tlvRet                                = 1;
    uint8_t *pCmdHeaderBuf                    = &cmdHeaderBuf[0];
    uint8_t rspbuf[NX_MAX_BUF_SIZE_RSP]       = {0};
    uint8_t *pRspbuf                          = &rspbuf[0];
    size_t rspbufLen                          = sizeof(rspbuf);
#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "GetConfiguration [Enhanced Privacy Configuration]");
#endif /* VERBOSE_APDU_LOGS */

    if ((NULL == session_ctx) || (NULL == privacyOption) || (NULL == appPrivacyKey)) {
        goto cleanup;
    }

    tlvRet = SET_U8("Option", &pCmdHeaderBuf, &cmdHeaderBufLen, Nx_ConfigOption_Enhanced_Privacy_Config);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    retStatus = DoAPDUTxRx_s_Case4(
        session_ctx, &hdr, cmdHeaderBuf, cmdHeaderBufLen, cmdDataBuf, cmdDataBufBufLen, rspbuf, &rspbufLen, NULL);
    if (retStatus == SM_OK) {
        retStatus       = SM_NOT_OK;
        size_t rspIndex = 0;

        if (rspbufLen != 4) { // + 2 bytes SW
            goto cleanup;
        }

        tlvRet = get_U8(pRspbuf, &rspIndex, rspbufLen, privacyOption); /*  */
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);

        tlvRet = get_U8(pRspbuf, &rspIndex, rspbufLen, appPrivacyKey); /*  */
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);

        if ((rspIndex + 2) == rspbufLen) {
            retStatus = (pRspbuf[rspIndex] << 8) | (pRspbuf[rspIndex + 1]);
        }

        if (retStatus == SM_OK_ALT) {
            retStatus = SM_OK;
        }
    }

cleanup:
    return retStatus;
}

smStatus_t nx_GetConfig_NFCMgmt(pSeSession_t session_ctx, uint8_t *nfcSupport, uint16_t *protocolOptions)
{
    smStatus_t retStatus                      = SM_NOT_OK;
    tlvHeader_t hdr                           = {{NX_CLA, NX_INS_GET_CONFIG, NX_P1_DEFAULT, NX_P2_DEFAULT}};
    uint8_t cmdHeaderBuf[NX_MAX_BUF_SIZE_CMD] = {0};
    size_t cmdHeaderBufLen                    = 0;
    uint8_t cmdDataBuf[NX_MAX_BUF_SIZE_CMD]   = {0};
    size_t cmdDataBufBufLen                   = 0;
    int tlvRet                                = 1;
    uint8_t *pCmdHeaderBuf                    = &cmdHeaderBuf[0];
    uint8_t rspbuf[NX_MAX_BUF_SIZE_RSP]       = {0};
    uint8_t *pRspbuf                          = &rspbuf[0];
    size_t rspbufLen                          = sizeof(rspbuf);
#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "GetConfiguration [NFC Management]");
#endif /* VERBOSE_APDU_LOGS */

    if ((NULL == session_ctx) || (NULL == nfcSupport) || (NULL == protocolOptions)) {
        goto cleanup;
    }

    tlvRet = SET_U8("Option", &pCmdHeaderBuf, &cmdHeaderBufLen, Nx_ConfigOption_NFC_Mgmt);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    retStatus = DoAPDUTxRx_s_Case4(
        session_ctx, &hdr, cmdHeaderBuf, cmdHeaderBufLen, cmdDataBuf, cmdDataBufBufLen, rspbuf, &rspbufLen, NULL);
    if (retStatus == SM_OK) {
        retStatus       = SM_NOT_OK;
        size_t rspIndex = 0;

        if (rspbufLen < 5) { // 3 + 2 bytes SW
            goto cleanup;
        }

        tlvRet = get_U8(pRspbuf, &rspIndex, rspbufLen, nfcSupport); /*  */
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);

        tlvRet = get_U16_LSB(pRspbuf, &rspIndex, rspbufLen, protocolOptions); /*  */
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);

        if ((rspIndex + 2) == rspbufLen) {
            retStatus = (pRspbuf[rspIndex] << 8) | (pRspbuf[rspIndex + 1]);
        }

        if (retStatus == SM_OK_ALT) {
            retStatus = SM_OK;
        }
    }

cleanup:
    return retStatus;
}

smStatus_t nx_GetConfig_I2CMgmt(
    pSeSession_t session_ctx, uint8_t *i2cSupport, uint8_t *i2cAddr, uint16_t *protocolOptions)
{
    smStatus_t retStatus                      = SM_NOT_OK;
    tlvHeader_t hdr                           = {{NX_CLA, NX_INS_GET_CONFIG, NX_P1_DEFAULT, NX_P2_DEFAULT}};
    uint8_t cmdHeaderBuf[NX_MAX_BUF_SIZE_CMD] = {0};
    size_t cmdHeaderBufLen                    = 0;
    uint8_t cmdDataBuf[NX_MAX_BUF_SIZE_CMD]   = {0};
    size_t cmdDataBufBufLen                   = 0;
    int tlvRet                                = 1;
    uint8_t *pCmdHeaderBuf                    = &cmdHeaderBuf[0];
    uint8_t rspbuf[NX_MAX_BUF_SIZE_RSP]       = {0};
    uint8_t *pRspbuf                          = &rspbuf[0];
    size_t rspbufLen                          = sizeof(rspbuf);

#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "GetConfiguration [I2C Management]");
#endif /* VERBOSE_APDU_LOGS */

    if ((session_ctx == NULL) || (i2cSupport == NULL) || (i2cAddr == NULL) || (protocolOptions == NULL)) {
        goto cleanup;
    }

    tlvRet = SET_U8("Option", &pCmdHeaderBuf, &cmdHeaderBufLen, Nx_ConfigOption_I2C_Mgmt);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    retStatus = DoAPDUTxRx_s_Case4(
        session_ctx, &hdr, cmdHeaderBuf, cmdHeaderBufLen, cmdDataBuf, cmdDataBufBufLen, rspbuf, &rspbufLen, NULL);
    if (retStatus == SM_OK) {
        retStatus       = SM_NOT_OK;
        size_t rspIndex = 0;

        if (rspbufLen < 6) { // 3 + 2 bytes SW
            goto cleanup;
        }

        tlvRet = get_U8(pRspbuf, &rspIndex, rspbufLen, i2cSupport); /*  */
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);

        tlvRet = get_U8(pRspbuf, &rspIndex, rspbufLen, i2cAddr); /*  */
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);

        tlvRet = get_U16_LSB(pRspbuf, &rspIndex, rspbufLen, protocolOptions); /*  */
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);

        if ((rspIndex + 2) == rspbufLen) {
            retStatus = (pRspbuf[rspIndex] << 8) | (pRspbuf[rspIndex + 1]);
        }

        if (retStatus == SM_OK_ALT) {
            retStatus = SM_OK;
        }
    }

cleanup:
    return retStatus;
}

smStatus_t nx_GetConfig_GPIOMgmt(pSeSession_t session_ctx, Nx_gpio_config_t *gpioConfig)
{
    smStatus_t retStatus                      = SM_NOT_OK;
    tlvHeader_t hdr                           = {{NX_CLA, NX_INS_GET_CONFIG, NX_P1_DEFAULT, NX_P2_DEFAULT}};
    uint8_t cmdHeaderBuf[NX_MAX_BUF_SIZE_CMD] = {0};
    size_t cmdHeaderBufLen                    = 0;
    uint8_t cmdDataBuf[NX_MAX_BUF_SIZE_CMD]   = {0};
    size_t cmdDataBufBufLen                   = 0;
    int tlvRet                                = 1;
    uint8_t *pCmdHeaderBuf                    = &cmdHeaderBuf[0];
    uint8_t rspbuf[NX_MAX_BUF_SIZE_RSP]       = {0};
    uint8_t *pRspbuf                          = &rspbuf[0];
    size_t rspbufLen                          = sizeof(rspbuf);
    uint8_t gpio1Config                       = 0;
    uint32_t gpio1PadCtrl                     = 0;
    uint8_t gpio2Config                       = 0;
    uint32_t gpio2PadCtrl                     = 0;
    uint8_t mgmtGPIOAC                        = 0;
    uint8_t readGPIOAC                        = 0;
#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "GetConfiguration GPIOMgmt[GPIO Management]");
#endif /* VERBOSE_APDU_LOGS */

    if ((session_ctx == NULL) || (gpioConfig == NULL)) {
        goto cleanup;
    }

    tlvRet = SET_U8("Option", &pCmdHeaderBuf, &cmdHeaderBufLen, Nx_ConfigOption_GPIO_Mgmt);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    retStatus = DoAPDUTxRx_s_Case4(
        session_ctx, &hdr, cmdHeaderBuf, cmdHeaderBufLen, cmdDataBuf, cmdDataBufBufLen, rspbuf, &rspbufLen, NULL);
    if (retStatus == SM_OK) {
        retStatus       = SM_NOT_OK;
        size_t rspIndex = 0;

        tlvRet = get_U8(pRspbuf, &rspIndex, rspbufLen, (uint8_t *)&(gpioConfig->gpio1Mode)); /*  */
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);

        tlvRet = get_U8(pRspbuf, &rspIndex, rspbufLen, &gpio1Config); /*  */
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);
        if (gpioConfig->gpio1Mode == Nx_GPIOMgmtCfg_GPIOMode_Output) {
            gpioConfig->gpio1OutputInitStateHigh = (gpio1Config & NX_CONF_GPIO_INIT_STATE) ? 1 : 0;
        }
        else if (gpioConfig->gpio1Mode == Nx_GPIOMgmtCfg_GPIOMode_DownstreamPowerOut) {
            gpioConfig->gpio1PowerOutI2CEnabled       = (gpio1Config & NX_CONF_GPIO_I2C_SUPPORT_ENABLED) ? 1 : 0;
            gpioConfig->gpio1PowerOutBackpowerEnabled = (gpio1Config & NX_CONF_GPIO_BACKPOWER_ENABLED) ? 1 : 0;
        }

        tlvRet = get_U32_LSB(pRspbuf, &rspIndex, rspbufLen, &gpio1PadCtrl); /*  */
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);
        gpioConfig->gpio1DebounceFilterValue   = (gpio1PadCtrl & NX_CONF_GPIO_DEBOUNCE_FILTER_VALUE_MASK) >> 16;
        gpioConfig->gpio1DebounceFilterEnabled = (gpio1PadCtrl & NX_CONF_GPIO_DEBOUNCE_FILTER_ENABLED) ? 1 : 0;
        gpioConfig->gpio1InputFilterSelection  = (gpio1PadCtrl & NX_CONF_GPIO_INPUT_FILTER_SELECTION_MASK) >> 8;
        gpioConfig->gpio1InputCfg              = (gpio1PadCtrl & NX_CONF_GPIO_INPUT_CONF_MASK) >> 5;
        gpioConfig->gpio1OutputCfg             = (gpio1PadCtrl & NX_CONF_GPIO_OUTPUT_CONF_MASK) >> 1;
        gpioConfig->gpio1Supply1v1n1v2         = (gpio1PadCtrl & NX_CONF_GPIO_SUPPLY_SELECTION_MASK) ? 1 : 0;

        tlvRet = get_U8(pRspbuf, &rspIndex, rspbufLen, (uint8_t *)&(gpioConfig->gpio2Mode)); /*  */
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);

        tlvRet = get_U8(pRspbuf, &rspIndex, rspbufLen, &gpio2Config); /*  */
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);
        if (gpioConfig->gpio2Mode == Nx_GPIOMgmtCfg_GPIOMode_Output) {
            gpioConfig->gpio2OutputInitStateHigh = (gpio2Config & NX_CONF_GPIO_INIT_STATE) ? 1 : 0;
        }
        else if (gpioConfig->gpio2Mode == Nx_GPIOMgmtCfg_GPIOMode_DownstreamPowerOut) {
            gpioConfig->gpio2PowerOutI2CEnabled       = (gpio2Config & NX_CONF_GPIO_I2C_SUPPORT_ENABLED) ? 1 : 0;
            gpioConfig->gpio2PowerOutBackpowerEnabled = (gpio2Config & NX_CONF_GPIO_BACKPOWER_ENABLED) ? 1 : 0;
        }

        tlvRet = get_U32_LSB(pRspbuf, &rspIndex, rspbufLen, &gpio2PadCtrl); /*  */
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);
        gpioConfig->gpio2DebounceFilterValue   = (gpio2PadCtrl & NX_CONF_GPIO_DEBOUNCE_FILTER_VALUE_MASK >> 16);
        gpioConfig->gpio2DebounceFilterEnabled = (gpio2PadCtrl & NX_CONF_GPIO_DEBOUNCE_FILTER_ENABLED) ? 1 : 0;
        gpioConfig->gpio2InputFilterSelection  = (gpio2PadCtrl & NX_CONF_GPIO_INPUT_FILTER_SELECTION_MASK) >> 8;
        gpioConfig->gpio2InputCfg              = (gpio2PadCtrl & NX_CONF_GPIO_INPUT_CONF_MASK) >> 5;
        gpioConfig->gpio2OutputCfg             = (gpio2PadCtrl & NX_CONF_GPIO_OUTPUT_CONF_MASK) >> 1;
        gpioConfig->gpio2Supply1v1n1v2         = (gpio2PadCtrl & NX_CONF_GPIO_SUPPLY_SELECTION_MASK) ? 1 : 0;

        tlvRet = get_U8(pRspbuf, &rspIndex, rspbufLen, (uint8_t *)&(gpioConfig->gpio1OutputNotif)); /*  */
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);

        tlvRet = get_U8(pRspbuf, &rspIndex, rspbufLen, (uint8_t *)&(gpioConfig->gpio2OutputNotif)); /*  */
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);

        tlvRet = get_U8(pRspbuf, &rspIndex, rspbufLen, &mgmtGPIOAC); /*  */
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);
        gpioConfig->acManage = mgmtGPIOAC;

        tlvRet = get_U8(pRspbuf, &rspIndex, rspbufLen, &readGPIOAC); /*  */
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);
        gpioConfig->acRead = readGPIOAC;

        tlvRet = get_U8(pRspbuf, &rspIndex, rspbufLen, (uint8_t *)&(gpioConfig->gpio1PowerOutDefaultTarget)); /*  */
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);

        tlvRet = get_U8(pRspbuf, &rspIndex, rspbufLen, (uint8_t *)&(gpioConfig->gpio1PowerOutInRushTarget)); /*  */
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);

        tlvRet = get_U16_LSB(pRspbuf, &rspIndex, rspbufLen, &(gpioConfig->gpio1PowerOutInRushDuration)); /*  */
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);

        tlvRet = get_U8(pRspbuf, &rspIndex, rspbufLen, &(gpioConfig->gpio1PowerOutAdditionalCurrent)); /*  */
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);

        tlvRet = get_U8(pRspbuf, &rspIndex, rspbufLen, &(gpioConfig->gpio2OutputNFCPauseFileNo)); /*  */
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);

        tlvRet = get_U24_LSB(pRspbuf, &rspIndex, rspbufLen, &(gpioConfig->gpio2OutputNFCPauseOffset)); /*  */
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);

        tlvRet = get_U24_LSB(pRspbuf, &rspIndex, rspbufLen, &(gpioConfig->gpio2OutputNFCPauseLength)); /*  */
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);

        if ((rspIndex + 2) == rspbufLen) {
            retStatus = (pRspbuf[rspIndex] << 8) | (pRspbuf[rspIndex + 1]);
        }

        if (retStatus == SM_OK_ALT) {
            retStatus = SM_OK;
        }
    }

cleanup:
    return retStatus;
}

smStatus_t nx_GetConfig_EccKeyMgmt(pSeSession_t session_ctx, uint8_t *acManageKeyPair, uint8_t *acManageCARootKey)
{
    smStatus_t retStatus                      = SM_NOT_OK;
    tlvHeader_t hdr                           = {{NX_CLA, NX_INS_GET_CONFIG, NX_P1_DEFAULT, NX_P2_DEFAULT}};
    uint8_t cmdHeaderBuf[NX_MAX_BUF_SIZE_CMD] = {0};
    size_t cmdHeaderBufLen                    = 0;
    uint8_t cmdDataBuf[NX_MAX_BUF_SIZE_CMD]   = {0};
    size_t cmdDataBufBufLen                   = 0;
    int tlvRet                                = 1;
    uint8_t *pCmdHeaderBuf                    = &cmdHeaderBuf[0];
    uint8_t rspbuf[NX_MAX_BUF_SIZE_RSP]       = {0};
    uint8_t *pRspbuf                          = &rspbuf[0];
    size_t rspbufLen                          = sizeof(rspbuf);
#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "GetConfiguration [ECC Key Management]");
#endif /* VERBOSE_APDU_LOGS */

    if ((session_ctx == NULL) || (acManageKeyPair == NULL) || (acManageCARootKey == NULL)) {
        goto cleanup;
    }

    tlvRet = SET_U8("Option", &pCmdHeaderBuf, &cmdHeaderBufLen, Nx_ConfigOption_ECC_Key_Mgmt);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    retStatus = DoAPDUTxRx_s_Case4(
        session_ctx, &hdr, cmdHeaderBuf, cmdHeaderBufLen, cmdDataBuf, cmdDataBufBufLen, rspbuf, &rspbufLen, NULL);
    if (retStatus == SM_OK) {
        retStatus       = SM_NOT_OK;
        size_t rspIndex = 0;

        if (rspbufLen != 4) { // 4 + 2 bytes SW
            goto cleanup;
        }

        tlvRet = get_U8(pRspbuf, &rspIndex, rspbufLen, acManageKeyPair); /*  */
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);

        tlvRet = get_U8(pRspbuf, &rspIndex, rspbufLen, acManageCARootKey); /*  */
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);

        if ((rspIndex + 2) == rspbufLen) {
            retStatus = (pRspbuf[rspIndex] << 8) | (pRspbuf[rspIndex + 1]);
        }

        if (retStatus == SM_OK_ALT) {
            retStatus = SM_OK;
        }
    }

cleanup:
    return retStatus;
}

smStatus_t nx_GetConfig_CertMgmt(pSeSession_t session_ctx,
    uint8_t *leafCacheSize,
    uint8_t *intermCacheSize,
    uint8_t *featureSelection,
    uint8_t *acManageCertRepo)
{
    smStatus_t retStatus                      = SM_NOT_OK;
    tlvHeader_t hdr                           = {{NX_CLA, NX_INS_GET_CONFIG, NX_P1_DEFAULT, NX_P2_DEFAULT}};
    uint8_t cmdHeaderBuf[NX_MAX_BUF_SIZE_CMD] = {0};
    size_t cmdHeaderBufLen                    = 0;
    uint8_t cmdDataBuf[NX_MAX_BUF_SIZE_CMD]   = {0};
    size_t cmdDataBufBufLen                   = 0;
    int tlvRet                                = 1;
    uint8_t *pCmdHeaderBuf                    = &cmdHeaderBuf[0];
    uint8_t rspbuf[NX_MAX_BUF_SIZE_RSP]       = {0};
    uint8_t *pRspbuf                          = &rspbuf[0];
    size_t rspbufLen                          = sizeof(rspbuf);

#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "GetConfiguration [Certificate Management]");
#endif /* VERBOSE_APDU_LOGS */

    if ((session_ctx == NULL) || (leafCacheSize == NULL) || (intermCacheSize == NULL) || (featureSelection == NULL) ||
        (acManageCertRepo == NULL)) {
        goto cleanup;
    }

    tlvRet = SET_U8("Option", &pCmdHeaderBuf, &cmdHeaderBufLen, Nx_ConfigOption_Cert_Mgmt);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    retStatus = DoAPDUTxRx_s_Case4(
        session_ctx, &hdr, cmdHeaderBuf, cmdHeaderBufLen, cmdDataBuf, cmdDataBufBufLen, rspbuf, &rspbufLen, NULL);
    if (retStatus == SM_OK) {
        retStatus       = SM_NOT_OK;
        size_t rspIndex = 0;

        if (rspbufLen != 6) { // 4 + 2 bytes SW
            goto cleanup;
        }

        tlvRet = get_U8(pRspbuf, &rspIndex, rspbufLen, leafCacheSize); /*  */
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);

        tlvRet = get_U8(pRspbuf, &rspIndex, rspbufLen, intermCacheSize); /*  */
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);

        tlvRet = get_U8(pRspbuf, &rspIndex, rspbufLen, featureSelection); /*  */
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);

        tlvRet = get_U8(pRspbuf, &rspIndex, rspbufLen, acManageCertRepo); /*  */
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);

        if ((rspIndex + 2) == rspbufLen) {
            retStatus = (pRspbuf[rspIndex] << 8) | (pRspbuf[rspIndex + 1]);
        }

        if (retStatus == SM_OK_ALT) {
            retStatus = SM_OK;
        }
    }

cleanup:
    return retStatus;
}

smStatus_t nx_GetConfig_WatchdogTimerMgmt(
    pSeSession_t session_ctx, uint8_t *HWDTValue, uint8_t *AWDT1Value, uint8_t *AWDT2Value)
{
    smStatus_t retStatus                      = SM_NOT_OK;
    tlvHeader_t hdr                           = {{NX_CLA, NX_INS_GET_CONFIG, NX_P1_DEFAULT, NX_P2_DEFAULT}};
    uint8_t cmdHeaderBuf[NX_MAX_BUF_SIZE_CMD] = {0};
    size_t cmdHeaderBufLen                    = 0;
    uint8_t cmdDataBuf[NX_MAX_BUF_SIZE_CMD]   = {0};
    size_t cmdDataBufBufLen                   = 0;
    int tlvRet                                = 1;
    uint8_t *pCmdHeaderBuf                    = &cmdHeaderBuf[0];
    uint8_t rspbuf[NX_MAX_BUF_SIZE_RSP]       = {0};
    uint8_t *pRspbuf                          = &rspbuf[0];
    size_t rspbufLen                          = sizeof(rspbuf);
#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "GetConfiguration [Watchdog Timer Management]");
#endif /* VERBOSE_APDU_LOGS */

    if ((session_ctx == NULL) || (HWDTValue == NULL) || (AWDT1Value == NULL) || (AWDT2Value == NULL)) {
        goto cleanup;
    }

    tlvRet = SET_U8("Option", &pCmdHeaderBuf, &cmdHeaderBufLen, Nx_ConfigOption_Watchdog_Mgmt);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    retStatus = DoAPDUTxRx_s_Case4(
        session_ctx, &hdr, cmdHeaderBuf, cmdHeaderBufLen, cmdDataBuf, cmdDataBufBufLen, rspbuf, &rspbufLen, NULL);
    if (retStatus == SM_OK) {
        retStatus       = SM_NOT_OK;
        size_t rspIndex = 0;

        if (rspbufLen != 5) { // 3 + 2 bytes SW
            goto cleanup;
        }

        tlvRet = get_U8(pRspbuf, &rspIndex, rspbufLen, HWDTValue); /*  */
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);

        tlvRet = get_U8(pRspbuf, &rspIndex, rspbufLen, AWDT1Value); /*  */
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);

        tlvRet = get_U8(pRspbuf, &rspIndex, rspbufLen, AWDT2Value); /*  */
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);

        if ((rspIndex + 2) == rspbufLen) {
            retStatus = (pRspbuf[rspIndex] << 8) | (pRspbuf[rspIndex + 1]);
        }

        if (retStatus == SM_OK_ALT) {
            retStatus = SM_OK;
        }
    }

cleanup:
    return retStatus;
}

smStatus_t nx_GetConfig_CryptoAPIMgmt(pSeSession_t session_ctx,
    uint8_t *cryptoAPISupport,
    uint8_t *acCryptoRequest,
    uint8_t *acChangeKey,
    uint8_t *TBPolicyCount,
    Nx_slot_buffer_policy_t *TBPolicy,
    uint8_t *SBPolicyCount,
    Nx_slot_buffer_policy_t *SBPolicy)
{
    smStatus_t retStatus                      = SM_NOT_OK;
    tlvHeader_t hdr                           = {{NX_CLA, NX_INS_GET_CONFIG, NX_P1_DEFAULT, NX_P2_DEFAULT}};
    uint8_t cmdHeaderBuf[NX_MAX_BUF_SIZE_CMD] = {0};
    size_t cmdHeaderBufLen                    = 0;
    uint8_t cmdDataBuf[NX_MAX_BUF_SIZE_CMD]   = {0};
    size_t cmdDataBufBufLen                   = 0;
    int tlvRet                                = 1;
    uint8_t *pCmdHeaderBuf                    = &cmdHeaderBuf[0];
    uint8_t rspbuf[NX_MAX_BUF_SIZE_RSP]       = {0};
    uint8_t *pRspbuf                          = &rspbuf[0];
    size_t rspbufLen                          = sizeof(rspbuf);
    uint8_t maxTBPolicyCnt                    = 0;
    uint8_t maxSBPolicyCnt                    = 0;

#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "GetConfiguration [Crypto API Management]");
#endif /* VERBOSE_APDU_LOGS */

    ENSURE_OR_GO_CLEANUP(NULL != session_ctx)
    ENSURE_OR_GO_CLEANUP(NULL != cryptoAPISupport)
    ENSURE_OR_GO_CLEANUP(NULL != acCryptoRequest)
    ENSURE_OR_GO_CLEANUP(NULL != acChangeKey)
    ENSURE_OR_GO_CLEANUP(NULL != TBPolicyCount)
    ENSURE_OR_GO_CLEANUP(NULL != TBPolicy)
    ENSURE_OR_GO_CLEANUP(NULL != SBPolicyCount)
    ENSURE_OR_GO_CLEANUP(NULL != SBPolicy)

    maxTBPolicyCnt = (*TBPolicyCount);
    maxSBPolicyCnt = (*SBPolicyCount);

    tlvRet = SET_U8("Option", &pCmdHeaderBuf, &cmdHeaderBufLen, Nx_ConfigOption_Crypto_API_Mgmt);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);
    retStatus = DoAPDUTxRx_s_Case4(
        session_ctx, &hdr, cmdHeaderBuf, cmdHeaderBufLen, cmdDataBuf, cmdDataBufBufLen, rspbuf, &rspbufLen, NULL);
    if (retStatus == SM_OK) {
        retStatus       = SM_NOT_OK;
        size_t rspIndex = 0;

        if ((rspbufLen < 5) || (rspbufLen > 79)) { // 3 + 2 bytes SW
            goto cleanup;
        }

        tlvRet = get_U8(pRspbuf, &rspIndex, rspbufLen, cryptoAPISupport); /*  */
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);

        tlvRet = get_U8(pRspbuf, &rspIndex, rspbufLen, acCryptoRequest); /*  */
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);

        tlvRet = get_U8(pRspbuf, &rspIndex, rspbufLen, acChangeKey);
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);
        *acChangeKey = *acChangeKey & NX_CONF_AC_MASK;

        tlvRet = get_U8(pRspbuf, &rspIndex, rspbufLen, TBPolicyCount); /*  */
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);

        if (*TBPolicyCount > maxTBPolicyCnt) {
            goto cleanup;
        }

        tlvRet =
            get_u8buf(pRspbuf, &rspIndex, rspbufLen, (uint8_t *)TBPolicy, *TBPolicyCount * NX_POLICY_BUF_SIZE); /*  */
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);

        tlvRet = get_U8(pRspbuf, &rspIndex, rspbufLen, SBPolicyCount); /*  */
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);

        if (*SBPolicyCount > maxSBPolicyCnt) {
            goto cleanup;
        }

        tlvRet = get_u8buf(pRspbuf, &rspIndex, rspbufLen, (uint8_t *)SBPolicy, (*SBPolicyCount) * NX_POLICY_BUF_SIZE);
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);

        if ((rspIndex + 2) == rspbufLen) {
            retStatus = (pRspbuf[rspIndex] << 8) | (pRspbuf[rspIndex + 1]);
        }

        if (retStatus == SM_OK_ALT) {
            retStatus = SM_OK;
        }
    }

cleanup:
    return retStatus;
}

smStatus_t nx_GetConfig_AuthCounterLimit(
    pSeSession_t session_ctx, uint8_t *authCtrFileID, uint8_t *authCtrOption, uint32_t *authCtrLimit)
{
    smStatus_t retStatus                      = SM_NOT_OK;
    tlvHeader_t hdr                           = {{NX_CLA, NX_INS_GET_CONFIG, NX_P1_DEFAULT, NX_P2_DEFAULT}};
    uint8_t cmdHeaderBuf[NX_MAX_BUF_SIZE_CMD] = {0};
    size_t cmdHeaderBufLen                    = 0;
    uint8_t cmdDataBuf[NX_MAX_BUF_SIZE_CMD]   = {0};
    size_t cmdDataBufBufLen                   = 0;
    int tlvRet                                = 1;
    uint8_t *pCmdHeaderBuf                    = &cmdHeaderBuf[0];
    uint8_t rspbuf[NX_MAX_BUF_SIZE_RSP]       = {0};
    uint8_t *pRspbuf                          = &rspbuf[0];
    size_t rspbufLen                          = sizeof(rspbuf);
#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "GetConfiguration [Authentication Counter and Limit Configuration]");
#endif /* VERBOSE_APDU_LOGS */

    if ((session_ctx == NULL) || (authCtrFileID == NULL) || (authCtrOption == NULL) || (authCtrLimit == NULL)) {
        goto cleanup;
    }

    tlvRet = SET_U8("Option", &pCmdHeaderBuf, &cmdHeaderBufLen, Nx_ConfigOption_Auth_Counter_Limit);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    retStatus = DoAPDUTxRx_s_Case4(
        session_ctx, &hdr, cmdHeaderBuf, cmdHeaderBufLen, cmdDataBuf, cmdDataBufBufLen, rspbuf, &rspbufLen, NULL);
    if (retStatus == SM_OK) {
        retStatus       = SM_NOT_OK;
        size_t rspIndex = 0;

        if (rspbufLen != 8) { // 6 + 2 bytes SW
            goto cleanup;
        }

        tlvRet = get_U8(pRspbuf, &rspIndex, rspbufLen, authCtrFileID);
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);

        tlvRet = get_U8(pRspbuf, &rspIndex, rspbufLen, authCtrOption);
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);

        tlvRet = get_U32_LSB(pRspbuf, &rspIndex, rspbufLen, authCtrLimit);
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);

        if ((rspIndex + 2) == rspbufLen) {
            retStatus = (pRspbuf[rspIndex] << 8) | (pRspbuf[rspIndex + 1]);
        }

        if (retStatus == SM_OK_ALT) {
            retStatus = SM_OK;
        }
    }

cleanup:
    return retStatus;
}

smStatus_t nx_GetConfig_HaltWakeupConfig(
    pSeSession_t session_ctx, uint8_t *wakeupOptionA, uint8_t *wakeupOptionB, uint8_t *RDACSetting, uint8_t *HALTOption)
{
    smStatus_t retStatus                      = SM_NOT_OK;
    tlvHeader_t hdr                           = {{NX_CLA, NX_INS_GET_CONFIG, NX_P1_DEFAULT, NX_P2_DEFAULT}};
    uint8_t cmdHeaderBuf[NX_MAX_BUF_SIZE_CMD] = {0};
    size_t cmdHeaderBufLen                    = 0;
    uint8_t cmdDataBuf[NX_MAX_BUF_SIZE_CMD]   = {0};
    size_t cmdDataBufBufLen                   = 0;
    int tlvRet                                = 1;
    uint8_t *pCmdHeaderBuf                    = &cmdHeaderBuf[0];
    uint8_t rspbuf[NX_MAX_BUF_SIZE_RSP]       = {0};
    uint8_t *pRspbuf                          = &rspbuf[0];
    size_t rspbufLen                          = sizeof(rspbuf);

#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "GetConfiguration [HALT and Wake-up Configuration]");
#endif /* VERBOSE_APDU_LOGS */

    if ((session_ctx == NULL) || (wakeupOptionA == NULL) || (wakeupOptionB == NULL) || (RDACSetting == NULL) ||
        (HALTOption == NULL)) {
        goto cleanup;
    }

    tlvRet = SET_U8("Option", &pCmdHeaderBuf, &cmdHeaderBufLen, 0x17);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    retStatus = DoAPDUTxRx_s_Case4(
        session_ctx, &hdr, cmdHeaderBuf, cmdHeaderBufLen, cmdDataBuf, cmdDataBufBufLen, rspbuf, &rspbufLen, NULL);
    if (retStatus == SM_OK) {
        retStatus       = SM_NOT_OK;
        size_t rspIndex = 0;

        if (rspbufLen != 6) { // 4 + 2 bytes SW
            goto cleanup;
        }

        tlvRet = get_U8(pRspbuf, &rspIndex, rspbufLen, wakeupOptionA); /*  */
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);

        tlvRet = get_U8(pRspbuf, &rspIndex, rspbufLen, wakeupOptionB); /*  */
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);

        tlvRet = get_U8(pRspbuf, &rspIndex, rspbufLen, RDACSetting); /*  */
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);

        tlvRet = get_U8(pRspbuf, &rspIndex, rspbufLen, HALTOption); /*  */
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);

        if ((rspIndex + 2) == rspbufLen) {
            retStatus = (pRspbuf[rspIndex] << 8) | (pRspbuf[rspIndex + 1]);
        }

        if (retStatus == SM_OK_ALT) {
            retStatus = SM_OK;
        }
    }

cleanup:
    return retStatus;
}

smStatus_t nx_GetConfig_DeferConfig(pSeSession_t session_ctx, uint8_t *deferralCount, uint8_t *deferralList)
{
    smStatus_t retStatus                      = SM_NOT_OK;
    tlvHeader_t hdr                           = {{NX_CLA, NX_INS_GET_CONFIG, NX_P1_DEFAULT, NX_P2_DEFAULT}};
    uint8_t cmdHeaderBuf[NX_MAX_BUF_SIZE_CMD] = {0};
    size_t cmdHeaderBufLen                    = 0;
    int tlvRet                                = 1;
    uint8_t *pCmdHeaderBuf                    = &cmdHeaderBuf[0];
    uint8_t rspbuf[NX_MAX_BUF_SIZE_RSP]       = {0};
    uint8_t *pRspbuf                          = &rspbuf[0];
    size_t rspbufLen                          = sizeof(rspbuf);

#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "GetConfiguration [Defer Configurations]");
#endif /* VERBOSE_APDU_LOGS */

    if ((session_ctx == NULL) || (deferralCount == NULL) || (deferralList == NULL)) {
        goto cleanup;
    }

    tlvRet = SET_U8("Option", &pCmdHeaderBuf, &cmdHeaderBufLen, Nx_ConfigOption_Defer_Config);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    retStatus = DoAPDUTxRx_s_Case4(session_ctx, &hdr, cmdHeaderBuf, cmdHeaderBufLen, NULL, 0, rspbuf, &rspbufLen, NULL);
    if (retStatus == SM_OK) {
        retStatus       = SM_NOT_OK;
        size_t rspIndex = 0;

        if (rspbufLen < 5) { // 1 + 2 + 2 bytes SW
            goto cleanup;
        }

        tlvRet = get_U8(pRspbuf, &rspIndex, rspbufLen, deferralCount); /*  */
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);
        if (*deferralCount > NX_CONF_DEFERRAL_COUNT_MAX) {
            goto cleanup;
        }

        tlvRet =
            get_u8buf(pRspbuf, &rspIndex, rspbufLen, deferralList, (*deferralCount) * NX_CONF_DEFERRAL_SIZE); /*  */
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);

        if ((rspIndex + 2) == rspbufLen) {
            retStatus = (pRspbuf[rspIndex] << 8) | (pRspbuf[rspIndex + 1]);
        }

        if (retStatus == SM_OK_ALT) {
            retStatus = SM_OK;
        }
    }

cleanup:
    return retStatus;
}

smStatus_t nx_GetConfig_LockConfig(pSeSession_t session_ctx, uint32_t *lockBitMap)
{
    smStatus_t retStatus                      = SM_NOT_OK;
    tlvHeader_t hdr                           = {{NX_CLA, NX_INS_GET_CONFIG, NX_P1_DEFAULT, NX_P2_DEFAULT}};
    uint8_t cmdHeaderBuf[NX_MAX_BUF_SIZE_CMD] = {0};
    size_t cmdHeaderBufLen                    = 0;
    uint8_t cmdDataBuf[NX_MAX_BUF_SIZE_CMD]   = {0};
    size_t cmdDataBufBufLen                   = 0;
    int tlvRet                                = 1;
    uint8_t *pCmdHeaderBuf                    = &cmdHeaderBuf[0];
    uint8_t rspbuf[NX_MAX_BUF_SIZE_RSP]       = {0};
    uint8_t lockMapBuf[3]                     = {0};
    uint8_t *pRspbuf                          = &rspbuf[0];
    size_t rspbufLen                          = sizeof(rspbuf);
#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "GetConfiguration [Lock Configurations]");
#endif /* VERBOSE_APDU_LOGS */

    if ((session_ctx == NULL) || (lockBitMap == NULL)) {
        goto cleanup;
    }

    tlvRet = SET_U8("Option", &pCmdHeaderBuf, &cmdHeaderBufLen, Nx_ConfigOption_Lock_Config);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    retStatus = DoAPDUTxRx_s_Case4(
        session_ctx, &hdr, cmdHeaderBuf, cmdHeaderBufLen, cmdDataBuf, cmdDataBufBufLen, rspbuf, &rspbufLen, NULL);
    if (retStatus == SM_OK) {
        retStatus       = SM_NOT_OK;
        size_t rspIndex = 0;

        if (rspbufLen != 5) { // 3 + 2 bytes SW
            goto cleanup;
        }

        tlvRet = get_u8buf(pRspbuf, &rspIndex, rspbufLen, lockMapBuf, 3);
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);
        *lockBitMap = 0;
        *lockBitMap |= lockMapBuf[0] << 2 * 8;
        *lockBitMap |= lockMapBuf[1] << 1 * 8;
        *lockBitMap |= lockMapBuf[2] << 0 * 8;

        if ((rspIndex + 2) == rspbufLen) {
            retStatus = (pRspbuf[rspIndex] << 8) | (pRspbuf[rspIndex + 1]);
        }

        if (retStatus == SM_OK_ALT) {
            retStatus = SM_OK;
        }
    }

cleanup:
    return retStatus;
}

smStatus_t nx_ManageGPIO_Output(pSeSession_t session_ctx,
    uint8_t gpioNo,
    uint8_t operation,
    uint8_t *nfcPauseRespData,
    size_t nfcPauseRespDataLen,
    Nx_CommMode_t knownCommMode)
{
    smStatus_t retStatus                = SM_NOT_OK;
    tlvHeader_t hdr                     = {{NX_CLA, NX_INS_MGNT_GPIO, NX_P1_DEFAULT, NX_P2_DEFAULT}};
    uint8_t cmdbuf[NX_MAX_BUF_SIZE_CMD] = {0};
    size_t cmdbufLen                    = 0;
    int tlvRet                          = 1;
    uint8_t *pCmdbuf                    = &cmdbuf[0];
    uint8_t rspbuf[NX_MAX_BUF_SIZE_RSP] = {0};
    size_t rspbufLen                    = sizeof(rspbuf);
    nx_ev2_comm_mode_t commMode         = EV2_CommMode_PLAIN;
    void *options                       = &commMode;

    if (session_ctx == NULL) {
        LOG_E("nx_ManageGPIO_Output Invalid Parameters!!!");
        goto cleanup;
    }

    retStatus = nx_get_comm_mode(session_ctx, knownCommMode, NX_INS_MGNT_GPIO, &commMode, NULL);
    ENSURE_OR_GO_CLEANUP(SM_OK == retStatus);

    retStatus = SM_NOT_OK; //reinitialized

#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "ManageGPIO [Output]");
#endif /* VERBOSE_APDU_LOGS */

    tlvRet = SET_U8("GPIONo", &pCmdbuf, &cmdbufLen, gpioNo);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    operation = operation & NX_MANAGE_GPIO_NFC_AND_OUTPUT_MASK;
    tlvRet    = SET_U8("Operation", &pCmdbuf, &cmdbufLen, operation);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    if (((operation & NX_MGMT_NFC_ACTION_MASK) == NX_MGMT_NFC_ACTION_NFC_RELEASE_PAUSE) && (nfcPauseRespData != NULL) &&
        (nfcPauseRespDataLen > 0)) {
        ENSURE_OR_GO_CLEANUP(cmdbufLen < NX_MAX_BUF_SIZE_CMD);
        memcpy(&cmdbuf[cmdbufLen], nfcPauseRespData, nfcPauseRespDataLen);
        ENSURE_OR_GO_CLEANUP((UINT_MAX - cmdbufLen) >= nfcPauseRespDataLen);
        cmdbufLen += nfcPauseRespDataLen;
    }

    retStatus = DoAPDUTxRx_s_Case4(session_ctx, &hdr, cmdbuf, cmdbufLen, NULL, 0, rspbuf, &rspbufLen, options);

    if (retStatus == SM_OK) {
        retStatus = SM_NOT_OK;
        if (rspbufLen != 2) {
            goto cleanup;
        }
        retStatus = (rspbuf[rspbufLen - 2] << 8) | (rspbuf[rspbufLen - 1]);

        if (retStatus == SM_OK_ALT) {
            retStatus = SM_OK;
        }
    }

cleanup:
    return retStatus;
}

smStatus_t nx_ManageGPIO_PowerOut(pSeSession_t session_ctx,
    uint8_t gpioNo,
    uint8_t operation,
    uint8_t *powerOutMeasureResult,
    Nx_CommMode_t knownCommMode)
{
    smStatus_t retStatus                = SM_NOT_OK;
    tlvHeader_t hdr                     = {{NX_CLA, NX_INS_MGNT_GPIO, NX_P1_DEFAULT, NX_P2_DEFAULT}};
    uint8_t cmdbuf[NX_MAX_BUF_SIZE_CMD] = {0};
    size_t cmdbufLen                    = 0;
    int tlvRet                          = 1;
    uint8_t *pCmdbuf                    = &cmdbuf[0];
    uint8_t rspbuf[NX_MAX_BUF_SIZE_RSP] = {0};
    uint8_t *pRspbuf                    = &rspbuf[0];
    size_t rspbufLen                    = sizeof(rspbuf);
    size_t rspIndex                     = 0;
    nx_ev2_comm_mode_t commMode         = EV2_CommMode_PLAIN;
    void *options                       = &commMode;

    if (session_ctx == NULL) {
        LOG_E("nx_ManageGPIO_PowerOut Invalid Parameters!!!");
        goto cleanup;
    }

    retStatus = nx_get_comm_mode(session_ctx, knownCommMode, NX_INS_MGNT_GPIO, &commMode, NULL);
    ENSURE_OR_GO_CLEANUP(SM_OK == retStatus);

    retStatus = SM_NOT_OK; //reinitialized

#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "ManageGPIO [PowerOut]");
#endif /* VERBOSE_APDU_LOGS */

    tlvRet = SET_U8("GPIONo", &pCmdbuf, &cmdbufLen, gpioNo);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_U8("Operation", &pCmdbuf, &cmdbufLen, operation);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    retStatus = DoAPDUTxRx_s_Case4(session_ctx, &hdr, cmdbuf, cmdbufLen, NULL, 0, rspbuf, &rspbufLen, options);

    if (retStatus == SM_OK) {
        retStatus = SM_NOT_OK;

        if (operation & NX_MGMT_GPIO_MEASUREMENT_CONTROL_EXECUTE_MEASURE) {
            if ((rspbufLen != 3) || (NULL == powerOutMeasureResult)) {
                goto cleanup;
            }
            tlvRet = get_U8(pRspbuf, &rspIndex, rspbufLen, powerOutMeasureResult); /*  */
            ENSURE_OR_GO_CLEANUP(0 == tlvRet);
        }
        else {
            if (rspbufLen != 2) {
                goto cleanup;
            }
        }

        retStatus = (rspbuf[rspbufLen - 2] << 8) | (rspbuf[rspbufLen - 1]);
        if (retStatus == SM_OK_ALT) {
            retStatus = SM_OK;
        }
    }

cleanup:
    return retStatus;
}

smStatus_t nx_ReadGPIO(pSeSession_t session_ctx,
    Nx_GPIO_Status_t *tagTamperPermStatus,
    Nx_GPIO_Status_t *gpio1CurrentOrTTCurrentStatus,
    Nx_GPIO_Status_t *gpio2CurrentStatus,
    Nx_CommMode_t knownCommMode)
{
    smStatus_t retStatus                = SM_NOT_OK;
    tlvHeader_t hdr                     = {{NX_CLA, NX_INS_READ_GPIO, NX_P1_DEFAULT, NX_P2_DEFAULT}};
    uint8_t cmdbuf[NX_MAX_BUF_SIZE_CMD] = {0};
    size_t cmdbufLen                    = 0;
    uint8_t rspbuf[NX_MAX_BUF_SIZE_RSP] = {0};
    size_t rspbufLen                    = sizeof(rspbuf);
    nx_ev2_comm_mode_t commMode         = EV2_CommMode_PLAIN;
    void *options                       = &commMode;

    if (session_ctx == NULL || tagTamperPermStatus == NULL || gpio1CurrentOrTTCurrentStatus == NULL ||
        gpio2CurrentStatus == NULL) {
        LOG_E("nx_ReadGPIO Invalid Parameters!!!");
        goto cleanup;
    }

    // In case user doesn't provide valid commMode, get commMode from SE configuration.
    retStatus = nx_get_comm_mode(session_ctx, knownCommMode, NX_INS_READ_GPIO, &commMode, NULL);
    ENSURE_OR_GO_CLEANUP(SM_OK == retStatus);

    retStatus = SM_NOT_OK; //reinitialized

#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "ReadGPIO []");
#endif /* VERBOSE_APDU_LOGS */

    retStatus = DoAPDUTxRx_s_Case4(session_ctx, &hdr, cmdbuf, cmdbufLen, NULL, 0, rspbuf, &rspbufLen, options);
    if (retStatus == SM_OK) {
        retStatus = SM_NOT_OK;
        if (rspbufLen != 5) { // rsp + 2 bytes SW
            goto cleanup;
        }
        *tagTamperPermStatus           = rspbuf[0];
        *gpio1CurrentOrTTCurrentStatus = rspbuf[1];
        *gpio2CurrentStatus            = rspbuf[2];
        retStatus                      = (rspbuf[rspbufLen - 2] << 8) | (rspbuf[rspbufLen - 1]);
        if (retStatus == SM_OK_ALT) {
            retStatus = SM_OK;
        }
    }

    retStatus = SM_OK;
cleanup:
    return retStatus;
}

smStatus_t nx_ChangeKey(pSeSession_t session_ctx,
    uint8_t objectID,
    NX_KEY_TYPE_t keyType,
    uint16_t policy,
    uint8_t *keyData,
    size_t keyDataLen)
{
    smStatus_t retStatus                      = SM_NOT_OK;
    tlvHeader_t hdr                           = {{NX_CLA, NX_INS_CHANGE_KEY, NX_P1_DEFAULT, NX_P2_DEFAULT}};
    uint8_t cmdHeaderBuf[NX_MAX_BUF_SIZE_CMD] = {0};
    size_t cmdHeaderBufLen                    = 0;
    uint8_t cmdDataBuf[NX_MAX_BUF_SIZE_CMD]   = {0};
    size_t cmdDataBufBufLen                   = 0;
    int tlvRet                                = 1;
    uint8_t *pCmdHeaderBuf                    = &cmdHeaderBuf[0];
    uint8_t *pCmdDataBuf                      = &cmdDataBuf[0];
    uint8_t rspbuf[NX_MAX_BUF_SIZE_RSP]       = {0};
    uint8_t *pRspbuf                          = &rspbuf[0];
    size_t rspbufLen                          = sizeof(rspbuf);
    size_t rspIndex                           = 0;
    nx_ev2_comm_mode_t commMode               = EV2_CommMode_PLAIN;
    void *options                             = &commMode;

    if ((session_ctx == NULL) || (keyData == NULL)) {
        LOG_E("nx_ChangeKey Invalid Parameters!!!");
        goto cleanup;
    }

    if ((session_ctx->authType == knx_AuthType_SIGMA_I_Verifier) ||
        (session_ctx->authType == knx_AuthType_SIGMA_I_Prover) || (session_ctx->authType == knx_AuthType_SYMM_AUTH)) {
        // Get commMode in case of authenticated.
        retStatus = secure_messaging_get_commMode(session_ctx, NX_INS_CHANGE_KEY, &commMode, NULL);
        if (retStatus != SM_OK) {
            goto cleanup;
        }
    }

#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "ChangeKey []");
#endif /* VERBOSE_APDU_LOGS */

    if (((objectID > NX_KEY_MGMT_MAX_APP_KEY_NUMBER) && (objectID < NX_KEY_MGMT_MIN_CRYPTO_KEY_NUMBER)) ||
        (objectID > NX_KEY_MGMT_MAX_CRYPTO_KEY_NUMBER)) {
        goto cleanup;
    }

    if (objectID > NX_KEY_MGMT_MIN_APP_KEY_NUMBER && objectID <= NX_KEY_MGMT_MAX_APP_KEY_NUMBER) {
        tlvRet = SET_U8("KeyNo", &pCmdHeaderBuf, &cmdHeaderBufLen, (objectID));
    }
    else {
        tlvRet = SET_U8("KeyNo", &pCmdHeaderBuf, &cmdHeaderBufLen, (keyType << 6) | (objectID));
    }
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    if (objectID >= NX_KEY_MGMT_MIN_CRYPTO_KEY_NUMBER && objectID <= NX_KEY_MGMT_MAX_CRYPTO_KEY_NUMBER) {
        tlvRet = SET_U16_LSB("KeyPolicy", &pCmdHeaderBuf, &cmdHeaderBufLen, policy);
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);
    }

    tlvRet = SET_u8buf("KeyData", &pCmdDataBuf, &cmdDataBufBufLen, keyData, keyDataLen);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    retStatus = DoAPDUTxRx_s_Case4(
        session_ctx, &hdr, cmdHeaderBuf, cmdHeaderBufLen, cmdDataBuf, cmdDataBufBufLen, rspbuf, &rspbufLen, options);

    if (retStatus == SM_OK) {
        retStatus = SM_NOT_OK;

        if (rspbufLen != 2) {
            goto cleanup;
        }

        retStatus = (pRspbuf[rspIndex] << 8) | (pRspbuf[rspIndex + 1]);
        if (retStatus == SM_OK_ALT) {
            retStatus = SM_OK;
        }
    }
cleanup:
    return retStatus;
}

smStatus_t nx_GetKeySettings_AppKeys(
    pSeSession_t session_ctx, uint8_t *keySetting, NX_KEY_TYPE_t *keyType, uint8_t *keyNumber)
{
    smStatus_t retStatus                      = SM_NOT_OK;
    tlvHeader_t hdr                           = {{NX_CLA, NX_INS_GET_KEY_SETTINGS, NX_P1_DEFAULT, NX_P2_DEFAULT}};
    uint8_t cmdHeaderBuf[NX_MAX_BUF_SIZE_CMD] = {0};
    size_t cmdHeaderBufLen                    = 0;
    uint8_t cmdDataBuf[NX_MAX_BUF_SIZE_CMD]   = {0};
    size_t cmdDataBufBufLen                   = 0;
    int tlvRet                                = 1;
    uint8_t rspbuf[NX_MAX_BUF_SIZE_RSP]       = {0};
    uint8_t *pRspbuf                          = &rspbuf[0];
    size_t rspbufLen                          = sizeof(rspbuf);
    size_t rspIndex                           = 0;
    nx_ev2_comm_mode_t commMode               = EV2_CommMode_PLAIN;
    void *options                             = &commMode;

    if ((session_ctx == NULL) || (keySetting == NULL) || (keyType == NULL) || (keyNumber == NULL)) {
        LOG_E("nx_GetKeySettings_AppKeys Invalid Parameters!!!");
        goto cleanup;
    }

    if ((session_ctx->authType == knx_AuthType_SIGMA_I_Verifier) ||
        (session_ctx->authType == knx_AuthType_SIGMA_I_Prover) || (session_ctx->authType == knx_AuthType_SYMM_AUTH)) {
        // Get commMode in case of authenticated.
        retStatus = secure_messaging_get_commMode(session_ctx, NX_INS_GET_KEY_SETTINGS, &commMode, NULL);
        if (retStatus != SM_OK) {
            goto cleanup;
        }
    }

#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "GetKeySettings [AppKeys]");
#endif /* VERBOSE_APDU_LOGS */

    retStatus = DoAPDUTxRx_s_Case4(
        session_ctx, &hdr, cmdHeaderBuf, cmdHeaderBufLen, cmdDataBuf, cmdDataBufBufLen, rspbuf, &rspbufLen, options);
    if (retStatus == SM_OK) {
        retStatus = SM_NOT_OK;
        if (rspbufLen != 4) {
            goto cleanup;
        }

        tlvRet = get_U8(pRspbuf, &rspIndex, rspbufLen, keySetting); /*  */
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);

        tlvRet = get_U8(pRspbuf, &rspIndex, rspbufLen, keyNumber); /*  */
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);

        *keyType   = (*keyNumber & 0xC0) >> 6;
        *keyNumber = (*keyNumber & 0x3F);

        if ((rspIndex + 2) == rspbufLen) {
            retStatus = (pRspbuf[rspIndex] << 8) | (pRspbuf[rspIndex + 1]);
        }

        if (retStatus == SM_OK_ALT) {
            retStatus = SM_OK;
        }
    }

cleanup:
    return retStatus;
}

smStatus_t nx_GetKeySettings_CryptoRequestKeyList(
    pSeSession_t session_ctx, uint8_t *keyCount, nx_crypto_key_meta_data_t *cryptoRequestKeyList)
{
    smStatus_t retStatus                      = SM_NOT_OK;
    tlvHeader_t hdr                           = {{NX_CLA, NX_INS_GET_KEY_SETTINGS, NX_P1_DEFAULT, NX_P2_DEFAULT}};
    uint8_t cmdHeaderBuf[NX_MAX_BUF_SIZE_CMD] = {0};
    size_t cmdHeaderBufLen                    = 0;
    uint8_t cmdDataBuf[NX_MAX_BUF_SIZE_CMD]   = {0};
    size_t cmdDataBufBufLen                   = 0;
    int tlvRet                                = 1;
    uint8_t *pCmdHeaderBuf                    = &cmdHeaderBuf[0];
    uint8_t rspbuf[NX_MAX_BUF_SIZE_RSP]       = {0};
    uint8_t *pRspbuf                          = &rspbuf[0];
    size_t rspbufLen                          = sizeof(rspbuf);
    size_t rspIndex                           = 0;
    nx_ev2_comm_mode_t commMode               = EV2_CommMode_PLAIN;
    uint8_t maxKeyCount                       = 0;
    int i                                     = 0;
    uint8_t keyList[NX_KEY_SETTING_CRYPTO_KEY_MAX_ENTRY * NX_KEY_SETTING_CRYPTO_KEY_META_DATA_BYTES];
    nx_crypto_key_meta_data_t *pMetaDta = NULL;
    void *options                       = &commMode;

    if ((session_ctx == NULL) || (keyCount == NULL) || (cryptoRequestKeyList == NULL)) {
        LOG_E("nx_GetKeySettings_CryptoRequestKeyList Invalid Parameters!!!");
        goto cleanup;
    }

    if ((session_ctx->authType == knx_AuthType_SIGMA_I_Verifier) ||
        (session_ctx->authType == knx_AuthType_SIGMA_I_Prover) || (session_ctx->authType == knx_AuthType_SYMM_AUTH)) {
        // Get commMode in case of authenticated.
        retStatus = secure_messaging_get_commMode(session_ctx, NX_INS_GET_KEY_SETTINGS, &commMode, NULL);
        if (retStatus != SM_OK) {
            goto cleanup;
        }
    }

#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "GetKeySettings [CryptoRequestKeyLis]");
#endif /* VERBOSE_APDU_LOGS */

    maxKeyCount = *keyCount;

    tlvRet = SET_U8("Option", &pCmdHeaderBuf, &cmdHeaderBufLen, Nx_GetKeySettingOpt_CryptoKey);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    retStatus = DoAPDUTxRx_s_Case4(
        session_ctx, &hdr, cmdHeaderBuf, cmdHeaderBufLen, cmdDataBuf, cmdDataBufBufLen, rspbuf, &rspbufLen, options);
    if (retStatus == SM_OK) {
        retStatus = SM_NOT_OK;
        if (rspbufLen < 1) {
            goto cleanup;
        }

        tlvRet = get_U8(pRspbuf, &rspIndex, rspbufLen, keyCount); /*  */
        if ((0 != tlvRet) || ((*keyCount) > maxKeyCount)) {
            goto cleanup;
        }

        tlvRet = get_u8buf(
            pRspbuf, &rspIndex, rspbufLen, keyList, (NX_KEY_SETTING_CRYPTO_KEY_META_DATA_BYTES * (*keyCount))); /*  */
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);

        for (i = 0; i < (*keyCount); i++) {
            pMetaDta = cryptoRequestKeyList + i;
            pMetaDta->keyId =
                keyList[NX_KEY_SETTING_CRYPTO_KEY_META_DATA_BYTES * i + NX_KEY_SETTING_CRYPTO_KEY_NO_OFFSET];
            pMetaDta->keyType =
                keyList[NX_KEY_SETTING_CRYPTO_KEY_META_DATA_BYTES * i + NX_KEY_SETTING_CRYPTO_KEY_TYPE_OFFSET];
            pMetaDta->keyPolicy = swap_uint16(
                &keyList[NX_KEY_SETTING_CRYPTO_KEY_META_DATA_BYTES * i + NX_KEY_SETTING_CRYPTO_KEY_POLICY_OFFSET]);
        }

        if ((rspIndex + 2) == rspbufLen) {
            retStatus = (pRspbuf[rspIndex] << 8) | (pRspbuf[rspIndex + 1]);
        }

        if (retStatus == SM_OK_ALT) {
            retStatus = SM_OK;
        }
    }

cleanup:
    return retStatus;
}

smStatus_t nx_GetKeySettings_ECCPrivateKeyList(
    pSeSession_t session_ctx, uint8_t *keyCount, nx_ecc_key_meta_data_t *eccPrivateKeyList)
{
    smStatus_t retStatus                      = SM_NOT_OK;
    tlvHeader_t hdr                           = {{NX_CLA, NX_INS_GET_KEY_SETTINGS, NX_P1_DEFAULT, NX_P2_DEFAULT}};
    uint8_t cmdHeaderBuf[NX_MAX_BUF_SIZE_CMD] = {0};
    size_t cmdHeaderBufLen                    = 0;
    uint8_t cmdDataBuf[NX_MAX_BUF_SIZE_CMD]   = {0};
    size_t cmdDataBufBufLen                   = 0;
    int tlvRet                                = 1;
    uint8_t *pCmdHeaderBuf                    = &cmdHeaderBuf[0];
    uint8_t rspbuf[NX_MAX_BUF_SIZE_RSP]       = {0};
    uint8_t *pRspbuf                          = &rspbuf[0];
    size_t rspbufLen                          = sizeof(rspbuf);
    size_t rspIndex                           = 0;
    uint8_t maxKeyCount                       = 0;
    int i                                     = 0;
    uint8_t keyList[NX_KEY_SETTING_ECC_KEY_MAX_ENTRY * NX_KEY_SETTING_ECC_KEY_META_DATA_BYTES];
    nx_ecc_key_meta_data_t *pMetaDta = NULL;
    uint8_t writeAccess              = 0;
    nx_ev2_comm_mode_t commMode      = EV2_CommMode_PLAIN;
    void *options                    = &commMode;

    if ((session_ctx == NULL) || (eccPrivateKeyList == NULL) || (keyCount == NULL)) {
        goto cleanup;
    }

    if ((session_ctx->authType == knx_AuthType_SIGMA_I_Verifier) ||
        (session_ctx->authType == knx_AuthType_SIGMA_I_Prover) || (session_ctx->authType == knx_AuthType_SYMM_AUTH)) {
        // Get commMode in case of authenticated.
        retStatus = secure_messaging_get_commMode(session_ctx, NX_INS_GET_KEY_SETTINGS, &commMode, NULL);
        if (retStatus != SM_OK) {
            goto cleanup;
        }
    }

#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "GetKeySettings [ECCPrivateKeyList]");
#endif /* VERBOSE_APDU_LOGS */

    maxKeyCount = *keyCount;

    tlvRet = SET_U8("Option", &pCmdHeaderBuf, &cmdHeaderBufLen, Nx_GetKeySettingOpt_ECCPrivKey);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    retStatus = DoAPDUTxRx_s_Case4(
        session_ctx, &hdr, cmdHeaderBuf, cmdHeaderBufLen, cmdDataBuf, cmdDataBufBufLen, rspbuf, &rspbufLen, options);
    if (retStatus == SM_OK) {
        retStatus = SM_NOT_OK;
        if (rspbufLen < 1) {
            goto cleanup;
        }

        tlvRet = get_U8(pRspbuf, &rspIndex, rspbufLen, keyCount); /*  */
        if ((0 != tlvRet) || (*keyCount > maxKeyCount)) {
            goto cleanup;
        }

        tlvRet = get_u8buf(pRspbuf,
            &rspIndex,
            rspbufLen,
            (uint8_t *)keyList,
            (*keyCount) * NX_KEY_SETTING_ECC_KEY_META_DATA_BYTES); /*  */
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);

        for (i = 0; i < (*keyCount); i++) {
            pMetaDta        = eccPrivateKeyList + i;
            pMetaDta->keyId = keyList[NX_KEY_SETTING_ECC_KEY_META_DATA_BYTES * i + NX_KEY_SETTING_ECC_KEY_NO_OFFSET];
            pMetaDta->curveId =
                keyList[NX_KEY_SETTING_ECC_KEY_META_DATA_BYTES * i + NX_KEY_SETTING_ECC_KEY_CURVE_ID_OFFSET];
            pMetaDta->keyPolicy = swap_uint16(
                &keyList[NX_KEY_SETTING_ECC_KEY_META_DATA_BYTES * i + NX_KEY_SETTING_ECC_KEY_POLICY_OFFSET]);
            writeAccess =
                keyList[NX_KEY_SETTING_ECC_KEY_META_DATA_BYTES * i + NX_KEY_SETTING_ECC_KEY_WRITE_ACCESS_OFFSET];
            pMetaDta->writeCommMode   = (writeAccess >> NX_COMM_MODE_BIT_SHIFT) & NX_COMM_MODE_BIT_MASK;
            pMetaDta->writeAccessCond = writeAccess & NX_ACCESS_CONDITION_BIT_MASK;
            pMetaDta->kucLimit        = swap_uint32(
                &keyList[NX_KEY_SETTING_ECC_KEY_META_DATA_BYTES * i + NX_KEY_SETTING_ECC_KEY_USAGE_CTR_LIMIT_OFFSET]);
            pMetaDta->keyUsageCtr = swap_uint32(
                &keyList[NX_KEY_SETTING_ECC_KEY_META_DATA_BYTES * i + NX_KEY_SETTING_ECC_KEY_USAGE_CTR_OFFSET]);
        }

        if ((rspIndex + 2) == rspbufLen) {
            retStatus = (pRspbuf[rspIndex] << 8) | (pRspbuf[rspIndex + 1]);
        }

        if (retStatus == SM_OK_ALT) {
            retStatus = SM_OK;
        }
    }

cleanup:
    return retStatus;
}

smStatus_t nx_GetKeySettings_CARootKeyList(
    pSeSession_t session_ctx, uint8_t *keyCount, nx_ca_root_key_meta_data_t *caRootKeyList)
{
    smStatus_t retStatus                      = SM_NOT_OK;
    tlvHeader_t hdr                           = {{NX_CLA, NX_INS_GET_KEY_SETTINGS, NX_P1_DEFAULT, NX_P2_DEFAULT}};
    uint8_t cmdHeaderBuf[NX_MAX_BUF_SIZE_CMD] = {0};
    size_t cmdHeaderBufLen                    = 0;
    uint8_t cmdDataBuf[NX_MAX_BUF_SIZE_CMD]   = {0};
    size_t cmdDataBufBufLen                   = 0;
    int tlvRet                                = 1;
    uint8_t *pCmdHeaderBuf                    = &cmdHeaderBuf[0];
    uint8_t rspbuf[NX_MAX_BUF_SIZE_RSP]       = {0};
    uint8_t *pRspbuf                          = &rspbuf[0];
    size_t rspbufLen                          = sizeof(rspbuf);
    size_t rspIndex                           = 0;
    int i                                     = 0;
    uint8_t keyList[NX_KEY_SETTING_CAROOTKEY_MAX_ENTRY * NX_KEY_SETTING_CAROOTKEY_META_DATA_BYTES];
    nx_ca_root_key_meta_data_t *pMetaDta = NULL;
    uint8_t writeAccess                  = 0;
    uint8_t maxKeyCount                  = 0;
    nx_ev2_comm_mode_t commMode          = EV2_CommMode_PLAIN;
    void *options                        = &commMode;

    if ((session_ctx == NULL) || (caRootKeyList == NULL) || (keyCount == NULL)) {
        goto cleanup;
    }

    if ((session_ctx->authType == knx_AuthType_SIGMA_I_Verifier) ||
        (session_ctx->authType == knx_AuthType_SIGMA_I_Prover) || (session_ctx->authType == knx_AuthType_SYMM_AUTH)) {
        // Get commMode in case of authenticated.
        retStatus = secure_messaging_get_commMode(session_ctx, NX_INS_GET_KEY_SETTINGS, &commMode, NULL);
        if (retStatus != SM_OK) {
            goto cleanup;
        }
    }

#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "GetKeySettings [CARootKeyList]");
#endif /* VERBOSE_APDU_LOGS */

    maxKeyCount = *keyCount;

    tlvRet = SET_U8("Option", &pCmdHeaderBuf, &cmdHeaderBufLen, Nx_GetKeySettingOpt_CARootKey);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    retStatus = DoAPDUTxRx_s_Case4(
        session_ctx, &hdr, cmdHeaderBuf, cmdHeaderBufLen, cmdDataBuf, cmdDataBufBufLen, rspbuf, &rspbufLen, options);
    if (retStatus == SM_OK) {
        retStatus = SM_NOT_OK;
        if (rspbufLen < 1) {
            goto cleanup;
        }

        tlvRet = get_U8(pRspbuf, &rspIndex, rspbufLen, keyCount); /*  */
        if ((0 != tlvRet) || (*keyCount > maxKeyCount)) {
            goto cleanup;
        }

        tlvRet = get_u8buf(pRspbuf,
            &rspIndex,
            rspbufLen,
            (uint8_t *)keyList,
            (*keyCount) * NX_KEY_SETTING_CAROOTKEY_META_DATA_BYTES); /*  */
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);

        for (i = 0; i < (*keyCount); i++) {
            pMetaDta = caRootKeyList + i;
            pMetaDta->keyId =
                keyList[NX_KEY_SETTING_CAROOTKEY_META_DATA_BYTES * i + NX_KEY_SETTING_CAROOTKEY_NO_OFFSET];
            pMetaDta->curveId =
                keyList[NX_KEY_SETTING_CAROOTKEY_META_DATA_BYTES * i + NX_KEY_SETTING_CAROOTKEY_CURVE_ID_OFFSET];
            pMetaDta->acBitmap = swap_uint16(
                &keyList[NX_KEY_SETTING_CAROOTKEY_META_DATA_BYTES * i + NX_KEY_SETTING_CAROOTKEY_ACCESS_BITMAP_OFFSET]);
            writeAccess =
                keyList[NX_KEY_SETTING_CAROOTKEY_META_DATA_BYTES * i + NX_KEY_SETTING_CAROOTKEY_WRITE_ACCESS_OFFSET];
            pMetaDta->writeCommMode   = (writeAccess >> NX_COMM_MODE_BIT_SHIFT) & NX_COMM_MODE_BIT_MASK;
            pMetaDta->writeAccessCond = writeAccess & NX_ACCESS_CONDITION_BIT_MASK;
        }

        if ((rspIndex + 2) == rspbufLen) {
            retStatus = (pRspbuf[rspIndex] << 8) | (pRspbuf[rspIndex + 1]);
        }

        if (retStatus == SM_OK_ALT) {
            retStatus = SM_OK;
        }
    }

cleanup:
    return retStatus;
}

smStatus_t nx_GetKeyVersion(pSeSession_t session_ctx, uint8_t objectID, uint8_t *keyVer)
{
    smStatus_t retStatus                      = SM_NOT_OK;
    tlvHeader_t hdr                           = {{NX_CLA, NX_INS_GET_KEY_VERSION, NX_P1_DEFAULT, NX_P2_DEFAULT}};
    uint8_t cmdHeaderBuf[NX_MAX_BUF_SIZE_CMD] = {0};
    size_t cmdHeaderBufLen                    = 0;
    uint8_t cmdDataBuf[NX_MAX_BUF_SIZE_CMD]   = {0};
    size_t cmdDataBufBufLen                   = 0;
    int tlvRet                                = 1;
    uint8_t *pCmdHeaderBuf                    = &cmdHeaderBuf[0];
    uint8_t rspbuf[NX_MAX_BUF_SIZE_RSP]       = {0};
    uint8_t *pRspbuf                          = &rspbuf[0];
    size_t rspbufLen                          = sizeof(rspbuf);
    size_t rspIndex                           = 0;
    nx_ev2_comm_mode_t commMode               = EV2_CommMode_PLAIN;
    void *options                             = &commMode;

    if ((session_ctx == NULL) || (keyVer == NULL)) {
        goto cleanup;
    }

    if ((session_ctx->authType == knx_AuthType_SIGMA_I_Verifier) ||
        (session_ctx->authType == knx_AuthType_SIGMA_I_Prover) || (session_ctx->authType == knx_AuthType_SYMM_AUTH)) {
        // Get commMode in case of authenticated.
        retStatus = secure_messaging_get_commMode(session_ctx, NX_INS_GET_KEY_VERSION, &commMode, NULL);
        if (retStatus != SM_OK) {
            goto cleanup;
        }
    }

#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "GetKeyVersion []");
#endif /* VERBOSE_APDU_LOGS */

    tlvRet = SET_U8("KeyNo", &pCmdHeaderBuf, &cmdHeaderBufLen, objectID);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    retStatus = DoAPDUTxRx_s_Case4(
        session_ctx, &hdr, cmdHeaderBuf, cmdHeaderBufLen, cmdDataBuf, cmdDataBufBufLen, rspbuf, &rspbufLen, options);
    if (retStatus == SM_OK) {
        retStatus = SM_NOT_OK;
        if (rspbufLen != 3) {
            goto cleanup;
        }
        tlvRet = get_U8(pRspbuf, &rspIndex, rspbufLen, keyVer); /*  */
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);

        if ((rspIndex + 2) == rspbufLen) {
            retStatus = (pRspbuf[rspIndex] << 8) | (pRspbuf[rspIndex + 1]);
        }

        if (retStatus == SM_OK_ALT) {
            retStatus = SM_OK;
        }
    }

cleanup:
    return retStatus;
}

smStatus_t nx_ReadCertRepo_Cert(pSeSession_t session_ctx,
    uint8_t repoID,
    NX_CERTIFICATE_LEVEL_t dataItem,
    uint8_t *certificate,
    size_t *certificateLen,
    Nx_CommMode_t knownCommMode)
{
    smStatus_t retStatus                = SM_NOT_OK;
    tlvHeader_t hdr                     = {{NX_CLA, NX_INS_READ_CERT_REPO, NX_P1_DEFAULT, NX_P2_DEFAULT}};
    uint8_t cmdbuf[NX_MAX_BUF_SIZE_CMD] = {0};
    size_t cmdbufLen                    = 0;
    int tlvRet                          = 1;
    uint8_t *pCmdbuf                    = &cmdbuf[0];
    uint8_t rspbuf[NX_MAX_BUF_SIZE_RSP] = {0};
    size_t rspbufLen                    = sizeof(rspbuf);
    nx_ev2_comm_mode_t commMode         = EV2_CommMode_PLAIN;
    void *options                       = &commMode;

    if ((session_ctx == NULL) || (certificate == NULL) || (certificateLen == NULL)) {
        LOG_E("nx_ReadCertRepo_Cert Invalid Parameters!!!");
        goto cleanup;
    }

    if ((dataItem != NX_CERTIFICATE_LEVEL_LEAF) && (dataItem != NX_CERTIFICATE_LEVEL_P1) &&
        (dataItem != NX_CERTIFICATE_LEVEL_P2)) {
        LOG_E("nx_ReadCertRepo_Cert Invalid Certificate Level!!!");
        goto cleanup;
    }

    retStatus = nx_get_comm_mode(session_ctx, knownCommMode, NX_INS_READ_CERT_REPO, &commMode, &repoID);
    ENSURE_OR_GO_CLEANUP(SM_OK == retStatus);

#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "ReadCertRepo Cert [%x]", dataItem);
#endif /* VERBOSE_APDU_LOGS */

    tlvRet = SET_U8("Cert Repository ID", &pCmdbuf, &cmdbufLen, repoID);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_U8("cert level", &pCmdbuf, &cmdbufLen, dataItem);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    retStatus = DoAPDUTxRx_s_Case4_ext(session_ctx, &hdr, cmdbuf, cmdbufLen, NULL, 0, rspbuf, &rspbufLen, options);

    if (retStatus == SM_OK) {
        if (*certificateLen >= (rspbufLen - 2)) {
            memcpy(certificate, rspbuf, rspbufLen - 2); //certificate len is xx
            *certificateLen = rspbufLen - 2;
        }
        else {
            LOG_E("nx_ReadCertRepo_Cert Buffer Overflow!!!");
            retStatus = SM_NOT_OK;
            goto cleanup;
        }

        retStatus = (rspbuf[rspbufLen - 2] << 8) | (rspbuf[rspbufLen - 1]);
        if (retStatus == SM_OK_ALT) {
            retStatus = SM_OK;
        }
    }

cleanup:
    return retStatus;
}

smStatus_t nx_ReadCertRepo_Metadata(pSeSession_t session_ctx,
    uint8_t repoID,
    uint8_t *privateKeyId,
    uint16_t *repoSize,
    Nx_CommMode_t *writeCommMode,
    uint8_t *writeAccessCond,
    Nx_CommMode_t *readCommMode,
    uint8_t *readAccessCond)
{
    smStatus_t retStatus                = SM_NOT_OK;
    tlvHeader_t hdr                     = {{NX_CLA, NX_INS_READ_CERT_REPO, NX_P1_DEFAULT, NX_P2_DEFAULT}};
    uint8_t cmdbuf[NX_MAX_BUF_SIZE_CMD] = {0};
    size_t cmdbufLen                    = 0;
    int tlvRet                          = 1;
    uint8_t *pCmdbuf                    = &cmdbuf[0];
    uint8_t rspbuf[NX_MAX_BUF_SIZE_RSP] = {0};
    uint8_t *pRspbuf                    = &rspbuf[0];
    size_t rspbufLen                    = sizeof(rspbuf);
    nx_ev2_comm_mode_t commMode         = EV2_CommMode_PLAIN;
    uint8_t writeAccessRight = 0, readAccessRight = 0;
#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "ReadCertRepo Metadata []");
#endif /* VERBOSE_APDU_LOGS */
    void *options = &commMode;

    if ((session_ctx == NULL) || (privateKeyId == NULL) || (repoSize == NULL) || (writeCommMode == NULL) ||
        (writeAccessCond == NULL) || (readCommMode == NULL) || (readAccessCond == NULL)) {
        LOG_E("nx_ReadCertRepo_Metadata Invalid Parameters!!!");
        goto cleanup;
    }

    if ((session_ctx->authType == knx_AuthType_SIGMA_I_Verifier) ||
        (session_ctx->authType == knx_AuthType_SIGMA_I_Prover) || (session_ctx->authType == knx_AuthType_SYMM_AUTH)) {
        // Get commMode in case of authenticated.
        commMode = EV2_CommMode_MAC;
    }

    tlvRet = SET_U8("Cert Repository ID", &pCmdbuf, &cmdbufLen, repoID);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_U8("cert level", &pCmdbuf, &cmdbufLen, NX_DATA_ITEM_REPO_META_DATA);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    retStatus = DoAPDUTxRx_s_Case4_ext(session_ctx, &hdr, cmdbuf, cmdbufLen, NULL, 0, rspbuf, &rspbufLen, options);

    if (retStatus == SM_OK) {
        size_t rspIndex = 0;

        tlvRet = get_U8(pRspbuf, &rspIndex, rspbufLen, privateKeyId); /*  */
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);

        tlvRet = get_U16_LSB(pRspbuf, &rspIndex, rspbufLen, repoSize); /*  */
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);

        tlvRet = get_U8(pRspbuf, &rspIndex, rspbufLen, &writeAccessRight); /*  */
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);

        tlvRet = get_U8(pRspbuf, &rspIndex, rspbufLen, &readAccessRight); /*  */
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);

        // Decode write access condition and commMode
        if (((writeAccessRight >> NX_COMM_MODE_BIT_SHIFT) & NX_COMM_MODE_BIT_MASK) == Nx_CommMode_FULL) {
            *writeCommMode = Nx_CommMode_FULL;
        }
        else if (((writeAccessRight >> NX_COMM_MODE_BIT_SHIFT) & NX_COMM_MODE_BIT_MASK) == Nx_CommMode_MAC) {
            *writeCommMode = Nx_CommMode_MAC;
        }
        else {
            *writeCommMode = Nx_CommMode_Plain;
        }
        *writeAccessCond = (writeAccessRight & NX_ACCESS_CONDITION_BIT_MASK);

        // Decode read access condition and commMode
        if (((readAccessRight >> NX_COMM_MODE_BIT_SHIFT) & NX_COMM_MODE_BIT_MASK) == Nx_CommMode_FULL) {
            *readCommMode = Nx_CommMode_FULL;
        }
        else if (((readAccessRight >> NX_COMM_MODE_BIT_SHIFT) & NX_COMM_MODE_BIT_MASK) == Nx_CommMode_MAC) {
            *readCommMode = Nx_CommMode_MAC;
        }
        else {
            *readCommMode = Nx_CommMode_Plain;
        }
        *readAccessCond = (readAccessRight & NX_ACCESS_CONDITION_BIT_MASK);

        retStatus = (rspbuf[rspbufLen - 2] << 8) | (rspbuf[rspbufLen - 1]);
        if (retStatus == SM_OK_ALT) {
            retStatus = SM_OK;
        }
    }

cleanup:
    return retStatus;
}

smStatus_t nx_ManageCertRepo_CreateCertRepo(pSeSession_t session_ctx,
    uint8_t repoID,
    uint8_t privateKeyId,
    uint16_t repoSize,
    Nx_CommMode_t writeCommMode,
    uint8_t writeAccessCond,
    Nx_CommMode_t readCommMode,
    uint8_t readAccessCond,
    Nx_CommMode_t knownCommMode)
{
    smStatus_t retStatus                = SM_NOT_OK;
    tlvHeader_t hdr                     = {{NX_CLA, NX_INS_MGMT_CERT_REPO, NX_P1_DEFAULT, NX_P2_DEFAULT}};
    uint8_t cmdbuf[NX_MAX_BUF_SIZE_CMD] = {0};
    size_t cmdbufLen                    = 0;
    int tlvRet                          = 1;
    uint8_t action                      = NX_MgCertRepoINS_CreateRepo;
    Nx_MgCertRepo_GetCommModeParams_t GetCommModeParams = {0};
    GetCommModeParams.repoID                            = repoID;
    GetCommModeParams.action                            = NX_MgCertRepoINS_CreateRepo;
    uint8_t *pCmdbuf                                    = &cmdbuf[0];
    uint8_t rspbuf[NX_MAX_BUF_SIZE_RSP]                 = {0};
    size_t rspbufLen                                    = sizeof(rspbuf);
    uint8_t *pRspbuf                                    = &rspbuf[0];
    uint8_t writeAccess = 0, readAccess = 0;
    nx_ev2_comm_mode_t commMode = EV2_CommMode_PLAIN;
    void *options               = &commMode;

    if (session_ctx == NULL) {
        LOG_E("nx_ManageCertRepo_CreateCertRepo Invalid Parameters!!!");
        goto cleanup;
    }

    retStatus = nx_get_comm_mode(session_ctx, knownCommMode, NX_INS_MGMT_CERT_REPO, &commMode, &GetCommModeParams);
    ENSURE_OR_GO_CLEANUP(SM_OK == retStatus);

    retStatus = SM_NOT_OK; //reinitialized

#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "ManageCertRepo [CreateCertRepo]");
#endif /* VERBOSE_APDU_LOGS */

    if ((writeCommMode << NX_COMM_MODE_BIT_SHIFT) > UINT8_MAX) {
        LOG_E("Passed writeCommMode is incorrect");
        goto cleanup;
    }
    writeAccess = ((writeCommMode << NX_COMM_MODE_BIT_SHIFT) | writeAccessCond);

    if ((readCommMode << NX_COMM_MODE_BIT_SHIFT) > UINT8_MAX) {
        LOG_E("Passed readCommMode is incorrect");
        goto cleanup;
    }
    readAccess = ((readCommMode << NX_COMM_MODE_BIT_SHIFT) | readAccessCond);

    tlvRet = SET_U8("action", &pCmdbuf, &cmdbufLen, action);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_U8("repoID", &pCmdbuf, &cmdbufLen, repoID);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_U8("cert private keyID", &pCmdbuf, &cmdbufLen, privateKeyId);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_U16_LSB("repoSize(LSB)", &pCmdbuf, &cmdbufLen, repoSize);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_U8("writeAccess", &pCmdbuf, &cmdbufLen, writeAccess);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_U8("readAccess", &pCmdbuf, &cmdbufLen, readAccess);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    retStatus = DoAPDUTxRx_s_Case4(session_ctx, &hdr, cmdbuf, cmdbufLen, NULL, 0, rspbuf, &rspbufLen, options);

    if (retStatus == SM_OK) {
        retStatus       = SM_NOT_OK;
        size_t rspIndex = 0;

        if (rspbufLen != 2) {
            goto cleanup;
        }

        retStatus = (pRspbuf[rspIndex] << 8) | (pRspbuf[rspIndex + 1]);
        if (retStatus == SM_OK_ALT) {
            retStatus = SM_OK;
        }
    }

cleanup:
    return retStatus;
}

smStatus_t nx_ManageCertRepo_LoadCert(pSeSession_t session_ctx,
    uint8_t repoID,
    NX_CERTIFICATE_LEVEL_t certLevel,
    const uint8_t *certBuf,
    uint16_t certBufLen,
    Nx_CommMode_t knownCommMode)
{
    smStatus_t retStatus                = SM_NOT_OK;
    tlvHeader_t hdr                     = {{NX_CLA, NX_INS_MGMT_CERT_REPO, NX_P1_DEFAULT, NX_P2_DEFAULT}};
    uint8_t cmdbuf[NX_MAX_BUF_SIZE_CMD] = {0};
    size_t cmdbufLen                    = 0;
    int tlvRet                          = 1;
    uint8_t action                      = NX_MgCertRepoINS_LoadCert;
    Nx_MgCertRepo_GetCommModeParams_t GetCommModeParams;
    GetCommModeParams.repoID            = repoID;
    GetCommModeParams.action            = NX_MgCertRepoINS_LoadCert;
    uint8_t *pCmdbuf                    = &cmdbuf[0];
    uint8_t rspbuf[NX_MAX_BUF_SIZE_RSP] = {0};
    size_t rspbufLen                    = sizeof(rspbuf);
    nx_ev2_comm_mode_t commMode         = EV2_CommMode_PLAIN;
    void *options                       = &commMode;

    if ((session_ctx == NULL) || (certBuf == NULL)) {
        LOG_E("nx_ManageCertRepo_LoadCert Invalid Parameters!!!");
        goto cleanup;
    }

    retStatus = nx_get_comm_mode(session_ctx, knownCommMode, NX_INS_MGMT_CERT_REPO, &commMode, &GetCommModeParams);
    ENSURE_OR_GO_CLEANUP(SM_OK == retStatus);

    retStatus = SM_NOT_OK; //reinitialized

#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "ManageCertRepo [LoadCert]");
#endif /* VERBOSE_APDU_LOGS */

    tlvRet = SET_U8("action", &pCmdbuf, &cmdbufLen, action);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_U8("repoID", &pCmdbuf, &cmdbufLen, repoID);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_U8("cert level", &pCmdbuf, &cmdbufLen, certLevel);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_u8buf("cert", &pCmdbuf, &cmdbufLen, certBuf, certBufLen);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    retStatus = DoAPDUTxRx_s_Case4_ext(session_ctx, &hdr, cmdbuf, cmdbufLen, NULL, 0, rspbuf, &rspbufLen, options);

cleanup:
    return retStatus;
}

smStatus_t nx_ManageCertRepo_LoadCertMapping(pSeSession_t session_ctx,
    uint8_t repoID,
    NX_CERTIFICATE_LEVEL_t certLevel,
    const uint8_t *certMapping,
    uint16_t certMappingLen,
    Nx_CommMode_t knownCommMode)
{
    smStatus_t retStatus                = SM_NOT_OK;
    tlvHeader_t hdr                     = {{NX_CLA, NX_INS_MGMT_CERT_REPO, NX_P1_DEFAULT, NX_P2_DEFAULT}};
    uint8_t cmdbuf[NX_MAX_BUF_SIZE_CMD] = {0};
    size_t cmdbufLen                    = 0;
    int tlvRet                          = 1;
    uint8_t action                      = NX_MgCertRepoINS_LoadCertMapping;
    Nx_MgCertRepo_GetCommModeParams_t GetCommModeParams = {0};
    GetCommModeParams.repoID                            = repoID;
    GetCommModeParams.action                            = NX_MgCertRepoINS_LoadCertMapping;
    uint8_t *pCmdbuf                                    = &cmdbuf[0];
    uint8_t rspbuf[NX_MAX_BUF_SIZE_RSP]                 = {0};
    size_t rspbufLen                                    = sizeof(rspbuf);
    nx_ev2_comm_mode_t commMode                         = EV2_CommMode_PLAIN;
    void *options                                       = &commMode;

    if ((session_ctx == NULL) || (certMapping == NULL)) {
        LOG_E("nx_ManageCertRepo_LoadCertMapping Invalid Parameters!!!");
        goto cleanup;
    }

    retStatus = nx_get_comm_mode(session_ctx, knownCommMode, NX_INS_MGMT_CERT_REPO, &commMode, &GetCommModeParams);
    ENSURE_OR_GO_CLEANUP(SM_OK == retStatus);

    retStatus = SM_NOT_OK; //reinitialized

#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "ManageCertRepo [LoadCertMapping]");
#endif /* VERBOSE_APDU_LOGS */

    tlvRet = SET_U8("action", &pCmdbuf, &cmdbufLen, action);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_U8("repoID", &pCmdbuf, &cmdbufLen, repoID);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_U8("cert level", &pCmdbuf, &cmdbufLen, certLevel);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_U16_LSB("cert mapping Len(LSB)", &pCmdbuf, &cmdbufLen, certMappingLen);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_u8buf("cert Mapping", &pCmdbuf, &cmdbufLen, certMapping, certMappingLen);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    retStatus = DoAPDUTxRx_s_Case4_ext(session_ctx, &hdr, cmdbuf, cmdbufLen, NULL, 0, rspbuf, &rspbufLen, options);

cleanup:
    return retStatus;
}

smStatus_t nx_ManageCertRepo_ActivateRepo(pSeSession_t session_ctx, uint8_t repoID, Nx_CommMode_t knownCommMode)
{
    smStatus_t retStatus                = SM_NOT_OK;
    tlvHeader_t hdr                     = {{NX_CLA, NX_INS_MGMT_CERT_REPO, NX_P1_DEFAULT, NX_P2_DEFAULT}};
    uint8_t cmdbuf[NX_MAX_BUF_SIZE_CMD] = {0};
    size_t cmdbufLen                    = 0;
    int tlvRet                          = 1;
    uint8_t action                      = NX_MgCertRepoINS_ActivateRepo;
    Nx_MgCertRepo_GetCommModeParams_t GetCommModeParams = {0};
    GetCommModeParams.repoID                            = repoID;
    GetCommModeParams.action                            = NX_MgCertRepoINS_ActivateRepo;
    uint8_t *pCmdbuf                                    = &cmdbuf[0];
    uint8_t rspbuf[NX_MAX_BUF_SIZE_RSP]                 = {0};
    size_t rspbufLen                                    = sizeof(rspbuf);
    uint8_t *pRspbuf                                    = &rspbuf[0];
    nx_ev2_comm_mode_t commMode                         = EV2_CommMode_PLAIN;
    void *options                                       = &commMode;

    if (session_ctx == NULL) {
        LOG_E("nx_ManageCertRepo_ActivateRepo Invalid Parameters!!!");
        goto cleanup;
    }

    retStatus = nx_get_comm_mode(session_ctx, knownCommMode, NX_INS_MGMT_CERT_REPO, &commMode, &GetCommModeParams);
    ENSURE_OR_GO_CLEANUP(SM_OK == retStatus);

    retStatus = SM_NOT_OK; //reinitialized

#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "ManageCertRepo [ActivateRepo]");
#endif /* VERBOSE_APDU_LOGS */

    tlvRet = SET_U8("action", &pCmdbuf, &cmdbufLen, action);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_U8("repoID", &pCmdbuf, &cmdbufLen, repoID);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    retStatus = DoAPDUTxRx_s_Case4(session_ctx, &hdr, cmdbuf, cmdbufLen, NULL, 0, rspbuf, &rspbufLen, options);

    if (retStatus == SM_OK) {
        retStatus       = SM_NOT_OK;
        size_t rspIndex = 0;

        if (rspbufLen != 2) {
            goto cleanup;
        }

        retStatus = (pRspbuf[rspIndex] << 8) | (pRspbuf[rspIndex + 1]);
        if (retStatus == SM_OK_ALT) {
            retStatus = SM_OK;
        }
    }

cleanup:
    return retStatus;
}

smStatus_t nx_ManageCertRepo_ResetRepo(pSeSession_t session_ctx,
    uint8_t repoID,
    Nx_CommMode_t writeCommMode,
    uint8_t writeAccessCond,
    Nx_CommMode_t readCommMode,
    uint8_t readAccessCond,
    Nx_CommMode_t knownCommMode)
{
    smStatus_t retStatus                = SM_NOT_OK;
    tlvHeader_t hdr                     = {{NX_CLA, NX_INS_MGMT_CERT_REPO, NX_P1_DEFAULT, NX_P2_DEFAULT}};
    uint8_t cmdbuf[NX_MAX_BUF_SIZE_CMD] = {0};
    size_t cmdbufLen                    = 0;
    int tlvRet                          = 1;
    uint8_t action                      = NX_MgCertRepoINS_ResetRepo;
    Nx_MgCertRepo_GetCommModeParams_t GetCommModeParams = {0};
    GetCommModeParams.repoID                            = repoID;
    GetCommModeParams.action                            = NX_MgCertRepoINS_ResetRepo;
    uint8_t *pCmdbuf                                    = &cmdbuf[0];
    uint8_t rspbuf[NX_MAX_BUF_SIZE_RSP]                 = {0};
    size_t rspbufLen                                    = sizeof(rspbuf);
    uint8_t *pRspbuf                                    = &rspbuf[0];
    uint8_t writeAccess = 0, readAccess = 0;
    nx_ev2_comm_mode_t commMode = EV2_CommMode_PLAIN;
    void *options               = &commMode;

    if (session_ctx == NULL) {
        LOG_E("nx_ManageCertRepo_ResetRepo Invalid Parameters!!!");
        goto cleanup;
    }

    retStatus = nx_get_comm_mode(session_ctx, knownCommMode, NX_INS_MGMT_CERT_REPO, &commMode, &GetCommModeParams);
    ENSURE_OR_GO_CLEANUP(SM_OK == retStatus);

    retStatus = SM_NOT_OK; //reinitialized

#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "ManageCertRepo [ResetRepo]");
#endif /* VERBOSE_APDU_LOGS */

    if ((writeCommMode << NX_COMM_MODE_BIT_SHIFT) > UINT8_MAX) {
        LOG_E("Passed writeCommMode is incorrect");
        goto cleanup;
    }
    writeAccess = ((writeCommMode << NX_COMM_MODE_BIT_SHIFT) | writeAccessCond);

    if ((readCommMode << NX_COMM_MODE_BIT_SHIFT) > UINT8_MAX) {
        LOG_E("Passed readCommMode is incorrect");
        goto cleanup;
    }
    readAccess = ((readCommMode << NX_COMM_MODE_BIT_SHIFT) | readAccessCond);

    tlvRet = SET_U8("action", &pCmdbuf, &cmdbufLen, action);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_U8("repoID", &pCmdbuf, &cmdbufLen, repoID);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_U8("writeAccess", &pCmdbuf, &cmdbufLen, writeAccess);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_U8("readAccess", &pCmdbuf, &cmdbufLen, readAccess);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    retStatus = DoAPDUTxRx_s_Case4(session_ctx, &hdr, cmdbuf, cmdbufLen, NULL, 0, rspbuf, &rspbufLen, options);

    if (retStatus == SM_OK) {
        retStatus       = SM_NOT_OK;
        size_t rspIndex = 0;

        if (rspbufLen != 2) {
            goto cleanup;
        }

        retStatus = (pRspbuf[rspIndex] << 8) | (pRspbuf[rspIndex + 1]);
        if (retStatus == SM_OK_ALT) {
            retStatus = SM_OK;
        }
    }

cleanup:
    return retStatus;
}

smStatus_t nx_CreateCounterFile(pSeSession_t session_ctx,
    uint8_t fileNo,
    uint32_t value,
    uint8_t fileOption,
    Nx_AccessCondition_t readAccessCondition,
    Nx_AccessCondition_t writeAccessCondition,
    Nx_AccessCondition_t readWriteAccessCondition,
    Nx_AccessCondition_t changeAccessCondition)
{
    smStatus_t retStatus                = SM_NOT_OK;
    tlvHeader_t hdr                     = {{NX_CLA, NX_INS_CREATE_COUNTER_FILE, NX_P1_DEFAULT, NX_P2_DEFAULT}};
    uint8_t cmdbuf[NX_MAX_BUF_SIZE_CMD] = {0};
    size_t cmdbufLen                    = 0;
    int tlvRet                          = 1;
    uint8_t *pCmdbuf                    = &cmdbuf[0];
    uint8_t rspbuf[NX_MAX_BUF_SIZE_RSP] = {0};
    size_t rspbufLen                    = sizeof(rspbuf);
    uint16_t accessRights = 0, readAC = 0, writeAC = 0, readWriteAC = 0, changeAC = 0;
    nx_ev2_comm_mode_t cmdCommMode = EV2_CommMode_PLAIN;
    void *options                  = &cmdCommMode;

    if (session_ctx == NULL) {
        LOG_E("nx_CreateCounterFile Invalid Parameters!!!");
        goto cleanup;
    }

    if ((session_ctx->authType == knx_AuthType_SIGMA_I_Verifier) ||
        (session_ctx->authType == knx_AuthType_SIGMA_I_Prover) || (session_ctx->authType == knx_AuthType_SYMM_AUTH)) {
        // Get commMode in case of authenticated.
        retStatus = secure_messaging_get_commMode(session_ctx, NX_INS_CREATE_COUNTER_FILE, &cmdCommMode, NULL);
        if (retStatus != SM_OK) {
            goto cleanup;
        }
    }

#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "CreateCounterFile []");
#endif /* VERBOSE_APDU_LOGS */

    if (session_ctx == NULL) {
        goto cleanup;
    }

    if (fileNo > NX_FILE_MAX_FILE_NUMBER) {
        goto cleanup;
    }

    fileOption   = fileOption & NX_FILE_OPTION_COMM_MODE_MASK;
    readAC       = readAccessCondition;
    writeAC      = writeAccessCondition;
    readWriteAC  = readWriteAccessCondition;
    changeAC     = changeAccessCondition;
    accessRights = (readAC << NX_FILE_AR_READ_OFFSET) | (writeAC << NX_FILE_AR_WRITE_OFFSET) |
                   (readWriteAC << NX_FILE_AR_READWRITE_OFFSET) | (changeAC << NX_FILE_AR_CHANGE_OFFSET);

    tlvRet = SET_U8("FileNo", &pCmdbuf, &cmdbufLen, fileNo);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_U8("fileOption", &pCmdbuf, &cmdbufLen, fileOption);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_U16_LSB("accessRights", &pCmdbuf, &cmdbufLen, accessRights);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_U32_LSB("Value", &pCmdbuf, &cmdbufLen, value);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    retStatus = DoAPDUTxRx_s_Case4(session_ctx, &hdr, cmdbuf, cmdbufLen, NULL, 0, rspbuf, &rspbufLen, options);

cleanup:
    return retStatus;
}

smStatus_t nx_IncrCounterFile(pSeSession_t session_ctx, uint8_t fileNo, uint32_t incrValue, Nx_CommMode_t knownCommMode)
{
    smStatus_t retStatus                      = SM_NOT_OK;
    tlvHeader_t hdr                           = {{NX_CLA, NX_INS_INCREMENT_COUNTER_FILE, NX_P1_DEFAULT, NX_P2_DEFAULT}};
    uint8_t cmdHeaderBuf[NX_MAX_BUF_SIZE_CMD] = {0};
    size_t cmdHeaderBufLen                    = 0;
    uint8_t cmdDataBuf[NX_MAX_BUF_SIZE_CMD]   = {0};
    size_t cmdDataBufBufLen                   = 0;
    int tlvRet                                = 1;
    uint8_t *pCmdHeaderBuf                    = &cmdHeaderBuf[0];
    uint8_t *pCmdDataBuf                      = &cmdDataBuf[0];
    uint8_t rspbuf[NX_MAX_BUF_SIZE_RSP]       = {0};
    size_t rspbufLen                          = sizeof(rspbuf);
    nx_ev2_comm_mode_t commMode               = EV2_CommMode_PLAIN;
    void *options                             = &commMode;

    if (session_ctx == NULL) {
        LOG_E("nx_IncrCounterFile Invalid Parameters!!!");
        goto cleanup;
    }

    retStatus = nx_get_comm_mode(session_ctx, knownCommMode, NX_INS_INCREMENT_COUNTER_FILE, &commMode, &fileNo);
    ENSURE_OR_GO_CLEANUP(SM_OK == retStatus);

    retStatus = SM_NOT_OK; //reinitialized

#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "IncrCounterFile []");
#endif /* VERBOSE_APDU_LOGS */

    tlvRet = SET_U8("FileNo", &pCmdHeaderBuf, &cmdHeaderBufLen, fileNo);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_U32_LSB("incrValue", &pCmdDataBuf, &cmdDataBufBufLen, incrValue);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    retStatus = DoAPDUTxRx_s_Case4(
        session_ctx, &hdr, cmdHeaderBuf, cmdHeaderBufLen, cmdDataBuf, cmdDataBufBufLen, rspbuf, &rspbufLen, options);

cleanup:
    return retStatus;
}

smStatus_t nx_GetFileCounters(pSeSession_t session_ctx, uint8_t fileNo, uint32_t *counter, Nx_CommMode_t knownCommMode)
{
    smStatus_t retStatus                = SM_NOT_OK;
    tlvHeader_t hdr                     = {{NX_CLA, NX_INS_GET_FILE_COUNTERS, NX_P1_DEFAULT, NX_P2_DEFAULT}};
    uint8_t cmdbuf[NX_MAX_BUF_SIZE_CMD] = {0};
    size_t cmdbufLen                    = 0;
    int tlvRet                          = 1;
    uint8_t *pCmdbuf                    = &cmdbuf[0];
    uint8_t rspbuf[NX_MAX_BUF_SIZE_RSP] = {0};
    size_t rspbufLen                    = sizeof(rspbuf);
    size_t rspIndex                     = 0;
    nx_ev2_comm_mode_t commMode         = EV2_CommMode_PLAIN;
    void *options                       = &commMode;

    if ((session_ctx == NULL) || (counter == NULL)) {
        LOG_E("nx_GetFileCounters Invalid Parameters!!!");
        goto cleanup;
    }

    retStatus = nx_get_comm_mode(session_ctx, knownCommMode, NX_INS_GET_FILE_COUNTERS, &commMode, &fileNo);
    ENSURE_OR_GO_CLEANUP(SM_OK == retStatus);

    retStatus = SM_NOT_OK; //reinitialized

#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "GetFileCounters_Counter []");
#endif /* VERBOSE_APDU_LOGS */

    fileNo = fileNo & NX_FILE_NO_MASK;
    tlvRet = SET_U8("FileNo", &pCmdbuf, &cmdbufLen, fileNo);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    retStatus = DoAPDUTxRx_s_Case4(session_ctx, &hdr, cmdbuf, cmdbufLen, NULL, 0, rspbuf, &rspbufLen, options);

    if (retStatus == SM_OK) {
        retStatus = SM_NOT_OK;

        if ((rspbufLen != 6) && (rspbufLen != 7)) {
            goto cleanup;
        }

        if (rspbufLen == 6) {
            tlvRet = get_U32_LSB(rspbuf, &rspIndex, rspbufLen, (uint32_t *)counter);
            ENSURE_OR_GO_CLEANUP(0 == tlvRet);
            if ((rspIndex + 2) == rspbufLen) {
                retStatus = (rspbuf[rspIndex] << 8) | (rspbuf[rspIndex + 1]);
            }
        }
        else {
            tlvRet = get_U24_LSB(rspbuf, &rspIndex, rspbufLen, (uint32_t *)counter);
            ENSURE_OR_GO_CLEANUP(0 == tlvRet);
            if ((rspIndex + 2) == (rspbufLen - 2)) { //reserved byte 2
                retStatus = (rspbuf[rspIndex + 2] << 8) | (rspbuf[rspIndex + 3]);
            }
        }

        if (retStatus == SM_OK_ALT) {
            retStatus = SM_OK;
        }
    }

cleanup:
    return retStatus;
}

smStatus_t nx_CreateStdDataFile(pSeSession_t session_ctx,
    uint8_t fileNo,
    uint16_t isoFileID,
    uint8_t fileOption,
    size_t fileSize,
    Nx_AccessCondition_t readAccessCondition,
    Nx_AccessCondition_t writeAccessCondition,
    Nx_AccessCondition_t readWriteAccessCondition,
    Nx_AccessCondition_t changeAccessCondition)
{
    smStatus_t retStatus                = SM_NOT_OK;
    tlvHeader_t hdr                     = {{NX_CLA, NX_INS_CREATE_STD_DATA_FILE, NX_P1_DEFAULT, NX_P2_DEFAULT}};
    uint8_t cmdbuf[NX_MAX_BUF_SIZE_CMD] = {0};
    size_t cmdbufLen                    = 0;
    int tlvRet                          = 1;
    uint8_t *pCmdbuf                    = &cmdbuf[0];
    uint8_t rspbuf[NX_MAX_BUF_SIZE_RSP] = {0};
    size_t rspbufLen                    = sizeof(rspbuf);
    uint8_t *pRspbuf                    = &rspbuf[0];
    uint16_t accessRights = 0, readAC = 0, writeAC = 0, readWriteAC = 0, changeAC = 0;
    nx_ev2_comm_mode_t cmdCommMode = EV2_CommMode_PLAIN;
    void *options                  = &cmdCommMode;

    if (session_ctx == NULL) {
        LOG_E("nx_CreateStdDataFile Invalid Parameters!!!");
        goto cleanup;
    }

    if ((fileSize < NX_FILE_SIZE_MIN) || (fileSize > NX_FILE_SIZE_MAX)) {
        LOG_E("nx_CreateStdDataFile Invalid File Size!!!");
        goto cleanup;
    }

    if ((session_ctx->authType == knx_AuthType_SIGMA_I_Verifier) ||
        (session_ctx->authType == knx_AuthType_SIGMA_I_Prover) || (session_ctx->authType == knx_AuthType_SYMM_AUTH)) {
        // Get commMode in case of authenticated.
        retStatus = secure_messaging_get_commMode(session_ctx, NX_INS_CREATE_STD_DATA_FILE, &cmdCommMode, NULL);
        if (retStatus != SM_OK) {
            goto cleanup;
        }
    }

#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "CreateStdDataFile []");
#endif /* VERBOSE_APDU_LOGS */

    fileNo = fileNo & NX_FILE_NO_MASK;
    tlvRet = SET_U8("FileNo", &pCmdbuf, &cmdbufLen, fileNo);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_U16_LSB("isoFileID", &pCmdbuf, &cmdbufLen, isoFileID);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    fileOption = fileOption & NX_FILE_OPTION_COMM_MODE_MASK;
    tlvRet     = SET_U8("fileOption", &pCmdbuf, &cmdbufLen, fileOption);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    readAC       = readAccessCondition;
    writeAC      = writeAccessCondition;
    readWriteAC  = readWriteAccessCondition;
    changeAC     = changeAccessCondition;
    accessRights = (readAC << NX_FILE_AR_READ_OFFSET) | (writeAC << NX_FILE_AR_WRITE_OFFSET) |
                   (readWriteAC << NX_FILE_AR_READWRITE_OFFSET) | (changeAC << NX_FILE_AR_CHANGE_OFFSET);
    tlvRet = SET_U16_LSB("accessRights", &pCmdbuf, &cmdbufLen, accessRights);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_U24_LSB("fileSize", &pCmdbuf, &cmdbufLen, fileSize);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    retStatus = DoAPDUTxRx_s_Case4(session_ctx, &hdr, cmdbuf, cmdbufLen, NULL, 0, rspbuf, &rspbufLen, options);

    if (retStatus == SM_OK) {
        retStatus       = SM_NOT_OK;
        size_t rspIndex = 0;

        if (rspbufLen != 2) {
            goto cleanup;
        }

        retStatus = (pRspbuf[rspIndex] << 8) | (pRspbuf[rspIndex + 1]);
        if (retStatus == SM_OK_ALT) {
            retStatus = SM_OK;
        }
    }

cleanup:
    return retStatus;
}

smStatus_t nx_ChangeFileSettings(pSeSession_t session_ctx,
    uint8_t fileNo,
    uint8_t fileOption,
    Nx_AccessCondition_t readAccessCondition,
    Nx_AccessCondition_t writeAccessCondition,
    Nx_AccessCondition_t readWriteAccessCondition,
    Nx_AccessCondition_t changeAccessCondition,
    nx_file_SDM_config_t *sdmConfig)
{
    smStatus_t retStatus                      = SM_NOT_OK;
    tlvHeader_t hdr                           = {{NX_CLA, NX_INS_CHANGE_FILE_SETTING, NX_P1_DEFAULT, NX_P2_DEFAULT}};
    uint8_t cmdHeaderBuf[NX_MAX_BUF_SIZE_CMD] = {0};
    size_t cmdHeaderBufLen                    = 0;
    uint8_t cmdDataBuf[NX_MAX_BUF_SIZE_CMD]   = {0};
    size_t cmdDataBufBufLen                   = 0;
    int tlvRet                                = 1;
    uint8_t *pCmdHeaderBuf                    = &cmdHeaderBuf[0];
    uint8_t *pCmdDataBuf                      = &cmdDataBuf[0];
    uint8_t rspbuf[NX_MAX_BUF_SIZE_RSP]       = {0};
    size_t rspbufLen                          = sizeof(rspbuf);
    uint8_t *pRspbuf                          = &rspbuf[0];
    uint16_t accessRights = 0, sdmAccessRights = 0;
    uint8_t deferOption            = 0;
    nx_ev2_comm_mode_t cmdCommMode = EV2_CommMode_PLAIN;
    void *options                  = &cmdCommMode;

    if (session_ctx == NULL) {
        LOG_E("nx_ChangeFileSettings Invalid Parameters!!!");
        goto cleanup;
    }

    if ((session_ctx->authType == knx_AuthType_SIGMA_I_Verifier) ||
        (session_ctx->authType == knx_AuthType_SIGMA_I_Prover) || (session_ctx->authType == knx_AuthType_SYMM_AUTH)) {
        // Get commMode in case of authenticated.
        retStatus = secure_messaging_get_commMode(session_ctx, NX_INS_CHANGE_FILE_SETTING, &cmdCommMode, &fileNo);
        if (retStatus != SM_OK) {
            goto cleanup;
        }
    }

    retStatus = SM_NOT_OK; //reinitialized

#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "ChangeFileSettings []");
#endif /* VERBOSE_APDU_LOGS */

    fileNo = fileNo & NX_FILE_NO_MASK;
    tlvRet = SET_U8("FileNo", &pCmdHeaderBuf, &cmdHeaderBufLen, fileNo);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    accessRights =
        ((readAccessCondition << NX_FILE_AR_READ_OFFSET) | (writeAccessCondition << NX_FILE_AR_WRITE_OFFSET) |
            (readWriteAccessCondition << NX_FILE_AR_READWRITE_OFFSET) |
            (changeAccessCondition << NX_FILE_AR_CHANGE_OFFSET));

    tlvRet = SET_U8("fileOption", &pCmdDataBuf, &cmdDataBufBufLen, fileOption);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_U16_LSB("accessRights", &pCmdDataBuf, &cmdDataBufBufLen, accessRights);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    if ((fileOption & NX_FILE_OPTION_SDM_ENABLED) == NX_FILE_OPTION_SDM_ENABLED) {
        if (sdmConfig == NULL) {
            LOG_E("nx_ChangeFileSettings Invalid SDM Parameters!!!");
            goto cleanup;
        }

        if ((sdmConfig->acSDMMetaRead << NX_FILE_SDMMetaRead_OFFSET) > UINT16_MAX) {
            LOG_E("Passed sdmconfig acSDMMetaRead is incorrect");
            goto cleanup;
        }
        sdmAccessRights = ((sdmConfig->acSDMMetaRead << NX_FILE_SDMMetaRead_OFFSET) |
                           (sdmConfig->acSDMFileRead << NX_FILE_SDMFileRead_OFFSET) |
                           (sdmConfig->acSDMFileRead2 << NX_FILE_SDMFileRead2_OFFSET) |
                           (sdmConfig->acSDMCtrRet << NX_FILE_SDMCtrRet_OFFSET));

        // SDMOption
        tlvRet = SET_U8("sdmOption", &pCmdDataBuf, &cmdDataBufBufLen, sdmConfig->sdmOption);
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);

        // SDMAccessRights
        tlvRet = SET_U16_LSB("sdmAccessRights", &pCmdDataBuf, &cmdDataBufBufLen, sdmAccessRights);
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);

        // VCUIDOffset
        if (((sdmConfig->sdmOption & NX_FILE_SDM_OPTIONS_VCUID) == NX_FILE_SDM_OPTIONS_VCUID) &&
            (sdmConfig->acSDMMetaRead == Nx_AccessCondition_Free_Access)) {
            if (sdmConfig->VCUIDOffset > NX_FILE_SDM_OFFSET_MAX) {
                LOG_E("nx_ChangeFileSettings Invalid VCUIDOffset!!!");
                goto cleanup;
            }

            tlvRet = SET_U24_LSB("vcuidOffset", &pCmdDataBuf, &cmdDataBufBufLen, sdmConfig->VCUIDOffset);
            ENSURE_OR_GO_CLEANUP(0 == tlvRet);
        }

        // SDMReadCtrOffset
        if (((sdmConfig->sdmOption & NX_FILE_SDM_OPTIONS_SDMReadCtr) == NX_FILE_SDM_OPTIONS_SDMReadCtr) &&
            (sdmConfig->acSDMMetaRead == Nx_AccessCondition_Free_Access)) {
            if (sdmConfig->SDMReadCtrOffset > NX_FILE_SDM_OFFSET_MAX) {
                LOG_E("nx_ChangeFileSettings Invalid SDMReadCtrOffset!!!");
                goto cleanup;
            }

            tlvRet = SET_U24_LSB("sdmReadCtrOffset", &pCmdDataBuf, &cmdDataBufBufLen, sdmConfig->SDMReadCtrOffset);
            ENSURE_OR_GO_CLEANUP(0 == tlvRet);
        }

        // PICCDataOffset
        if ((sdmConfig->acSDMMetaRead != Nx_SDMMetaRead_AccessCondition_Plain_PICCData) &&
            (sdmConfig->acSDMMetaRead != Nx_SDMMetaRead_AccessCondition_No_PICCData)) {
            if (sdmConfig->PICCDataOffset > NX_FILE_SDM_OFFSET_MAX) {
                LOG_E("nx_ChangeFileSettings Invalid PICCDataOffset!!!");
                goto cleanup;
            }

            tlvRet = SET_U24_LSB("piccDataOffset", &pCmdDataBuf, &cmdDataBufBufLen, sdmConfig->PICCDataOffset);
            ENSURE_OR_GO_CLEANUP(0 == tlvRet);
        }

        // GPIOStatusOffset
        if ((sdmConfig->sdmOption & NX_FILE_SDM_OPTIONS_GPIOStatus) == NX_FILE_SDM_OPTIONS_GPIOStatus) {
            if (sdmConfig->GPIOStatusOffset > NX_FILE_SDM_OFFSET_MAX) {
                LOG_E("nx_ChangeFileSettings Invalid GPIOStatusOffset!!!");
                goto cleanup;
            }

            tlvRet = SET_U24_LSB("gpioStatusOffset", &pCmdDataBuf, &cmdDataBufBufLen, sdmConfig->GPIOStatusOffset);
            ENSURE_OR_GO_CLEANUP(0 == tlvRet);
        }

        // SDMMACInputOffset
        if ((sdmConfig->acSDMFileRead != Nx_SDMFileRead_AccessCondition_No_SDM) ||
            (sdmConfig->acSDMFileRead2 != Nx_SDMFileRead_AccessCondition_No_SDM)) {
            if (sdmConfig->SDMMACInputOffset > NX_FILE_SDM_OFFSET_MAX) {
                LOG_E("nx_ChangeFileSettings Invalid SDMMACInputOffset!!!");
                goto cleanup;
            }

            tlvRet = SET_U24_LSB("sdmMacInputOffset", &pCmdDataBuf, &cmdDataBufBufLen, sdmConfig->SDMMACInputOffset);
            ENSURE_OR_GO_CLEANUP(0 == tlvRet);
        }

        // SDMENCOffset
        if (((sdmConfig->acSDMFileRead != Nx_SDMFileRead_AccessCondition_No_SDM) &&
                (sdmConfig->sdmOption & NX_FILE_SDM_OPTIONS_SDMENCFileData) == NX_FILE_SDM_OPTIONS_SDMENCFileData)) {
            if (sdmConfig->SDMENCOffset > NX_FILE_SDM_OFFSET_MAX) {
                LOG_E("nx_ChangeFileSettings Invalid SDMENCOffset!!!");
                goto cleanup;
            }

            if (sdmConfig->SDMENCLength > NX_FILE_SDM_ENC_LEN_MAX) {
                LOG_E("nx_ChangeFileSettings Invalid SDMENCLength!!!");
                goto cleanup;
            }

            tlvRet = SET_U24_LSB("sdmEncOffset", &pCmdDataBuf, &cmdDataBufBufLen, sdmConfig->SDMENCOffset);
            ENSURE_OR_GO_CLEANUP(0 == tlvRet);

            tlvRet = SET_U24_LSB("sdmEncLen", &pCmdDataBuf, &cmdDataBufBufLen, sdmConfig->SDMENCLength);
            ENSURE_OR_GO_CLEANUP(0 == tlvRet);
        }

        // SDMMACOffset
        if ((sdmConfig->acSDMFileRead != Nx_SDMFileRead_AccessCondition_No_SDM) ||
            (sdmConfig->acSDMFileRead2 != Nx_SDMFileRead_AccessCondition_No_SDM)) {
            if (sdmConfig->SDMMACOffset > NX_FILE_SDM_OFFSET_MAX) {
                LOG_E("nx_ChangeFileSettings Invalid SDMMACOffset!!!");
                goto cleanup;
            }

            tlvRet = SET_U24_LSB("sdmMACOffset", &pCmdDataBuf, &cmdDataBufBufLen, sdmConfig->SDMMACOffset);
            ENSURE_OR_GO_CLEANUP(0 == tlvRet);
        }

        // SDMReadCtrLimit
        if ((sdmConfig->sdmOption & NX_FILE_SDM_OPTIONS_SDMReadCtrLimit) == NX_FILE_SDM_OPTIONS_SDMReadCtrLimit) {
            if (sdmConfig->SDMReadCtrLimit > NX_FILE_SDM_READ_CTR_LIMIT_MAX) {
                LOG_E("nx_ChangeFileSettings Invalid SDMReadCtrLimit!!!");
                goto cleanup;
            }

            tlvRet = SET_U24_LSB("sdmReadCtrLimit", &pCmdDataBuf, &cmdDataBufBufLen, sdmConfig->SDMReadCtrLimit);
            ENSURE_OR_GO_CLEANUP(0 == tlvRet);
        }
    }

    if ((fileNo == NX_FILE_NDEF_FILE_NO) &&
        (fileOption & NX_FILE_OPTION_DEFERRED_ENABLED) == NX_FILE_OPTION_DEFERRED_ENABLED) {
        if (sdmConfig->deferSDMEncEnabled) {
            deferOption |= NX_CONF_DEFER_SDM_ENC_ENABLED;
        }

        tlvRet = SET_U8("DeferOption", &pCmdDataBuf, &cmdDataBufBufLen, deferOption);
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);

        tlvRet = SET_U8("DeferMethod", &pCmdDataBuf, &cmdDataBufBufLen, sdmConfig->sdmDeferMethod);
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);
    }

    retStatus = DoAPDUTxRx_s_Case4(
        session_ctx, &hdr, cmdHeaderBuf, cmdHeaderBufLen, cmdDataBuf, cmdDataBufBufLen, rspbuf, &rspbufLen, options);

    if (retStatus == SM_OK) {
        retStatus       = SM_NOT_OK;
        size_t rspIndex = 0;

        if (rspbufLen != 2) {
            goto cleanup;
        }

        retStatus = (pRspbuf[rspIndex] << 8) | (pRspbuf[rspIndex + 1]);
        if (retStatus == SM_OK_ALT) {
            retStatus = SM_OK;
        }
    }
cleanup:
    return retStatus;
}

smStatus_t nx_GetFileSettings(pSeSession_t session_ctx,
    uint8_t fileNo,
    Nx_FILEType_t *fileType,
    uint8_t *fileOption,
    Nx_AccessCondition_t *readAccessCondition,
    Nx_AccessCondition_t *writeAccessCondition,
    Nx_AccessCondition_t *readWriteAccessCondition,
    Nx_AccessCondition_t *changeAccessCondition,
    size_t *fileSize,
    nx_file_SDM_config_t *sdmConfig)
{
    smStatus_t retStatus                = SM_NOT_OK;
    tlvHeader_t hdr                     = {{NX_CLA, NX_INS_GET_FILE_SETTINGS, NX_P1_DEFAULT, NX_P2_DEFAULT}};
    uint8_t cmdbuf[NX_MAX_BUF_SIZE_CMD] = {0};
    size_t cmdbufLen                    = 0;
    int tlvRet                          = 1;
    size_t rspIndex                     = 0;
    uint8_t *pCmdbuf                    = &cmdbuf[0];
    uint8_t rspbuf[NX_MAX_BUF_SIZE_RSP] = {0};
    uint8_t *pRspbuf                    = &rspbuf[0];
    size_t rspbufLen                    = sizeof(rspbuf);
    uint8_t tmpUint8                    = 0;
    uint8_t deferOption                 = 0x00;
    uint16_t tmpUint16 = 0, accessRights = 0, sdmAccessRights = 0;
    uint32_t tmpUint32             = 0;
    nx_ev2_comm_mode_t cmdCommMode = EV2_CommMode_PLAIN;
    void *options                  = &cmdCommMode;

    if ((session_ctx == NULL) || (fileType == NULL) || (fileOption == NULL) || (readAccessCondition == NULL) ||
        (writeAccessCondition == NULL) || (readWriteAccessCondition == NULL) || (changeAccessCondition == NULL)) {
        LOG_E("nx_GetFileSettings Invalid Parameters!!!");
        goto cleanup;
    }

    if ((session_ctx->authType == knx_AuthType_SIGMA_I_Verifier) ||
        (session_ctx->authType == knx_AuthType_SIGMA_I_Prover) || (session_ctx->authType == knx_AuthType_SYMM_AUTH)) {
        // Get commMode in case of authenticated.
        retStatus = secure_messaging_get_commMode(session_ctx, NX_INS_GET_FILE_SETTINGS, &cmdCommMode, &fileNo);
        if (retStatus != SM_OK) {
            goto cleanup;
        }
    }

    retStatus = SM_NOT_OK; //reinitialized

#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "GetFileSettings []");
#endif /* VERBOSE_APDU_LOGS */

    fileNo = fileNo & NX_FILE_NO_MASK;
    tlvRet = SET_U8("FileNo", &pCmdbuf, &cmdbufLen, fileNo);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    retStatus = DoAPDUTxRx_s_Case4(session_ctx, &hdr, cmdbuf, cmdbufLen, NULL, 0, rspbuf, &rspbufLen, options);
    if (retStatus == SM_OK) {
        retStatus = SM_NOT_OK;
        if (rspbufLen < 6) {
            goto cleanup;
        }

        // FileType
        tlvRet = get_U8(pRspbuf, &rspIndex, rspbufLen, &tmpUint8);
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);
        if ((tmpUint8 == Nx_FILEType_Standard) || (tmpUint8 == Nx_FILEType_Counter)) {
            *fileType = tmpUint8;
        }
        else {
            LOG_E("nx_GetFileSettings Invalid File Type!!!");
            goto cleanup;
        }

        if (*fileType == Nx_FILEType_Standard) {
            // FileOption
            tlvRet = get_U8(pRspbuf, &rspIndex, rspbufLen, fileOption);
            ENSURE_OR_GO_CLEANUP(0 == tlvRet);

            tmpUint8 = *fileOption & NX_FILE_OPTION_COMM_MODE_MASK;
            if ((tmpUint8 != Nx_CommMode_Plain) && (tmpUint8 != Nx_CommMode_MAC) && (tmpUint8 != Nx_CommMode_FULL)) {
                goto cleanup;
            }

            // AccessRights
            tlvRet = get_U16_LSB(pRspbuf, &rspIndex, rspbufLen, &accessRights);
            ENSURE_OR_GO_CLEANUP(0 == tlvRet);

            tmpUint16 = (accessRights >> NX_FILE_AR_READ_OFFSET) & NX_FILE_AR_READ_MASK;
            if (tmpUint16 <= Nx_AccessCondition_No_Access) {
                *readAccessCondition = (Nx_AccessCondition_t)tmpUint16;
            }
            else {
                goto cleanup;
            }
            tmpUint16 = (accessRights >> NX_FILE_AR_WRITE_OFFSET) & NX_FILE_AR_WRITE_MASK;
            if (tmpUint16 <= Nx_AccessCondition_No_Access) {
                *writeAccessCondition = (Nx_AccessCondition_t)tmpUint16;
            }
            else {
                goto cleanup;
            }
            tmpUint16 = (accessRights >> NX_FILE_AR_READWRITE_OFFSET) & NX_FILE_AR_READWRITE_MASK;
            if (tmpUint16 <= Nx_AccessCondition_No_Access) {
                *readWriteAccessCondition = (Nx_AccessCondition_t)tmpUint16;
            }
            else {
                goto cleanup;
            }
            tmpUint16 = (accessRights >> NX_FILE_AR_CHANGE_OFFSET) & NX_FILE_AR_CHANGE_MASK;
            if (tmpUint16 <= Nx_AccessCondition_No_Access) {
                *changeAccessCondition = (Nx_AccessCondition_t)tmpUint16;
            }
            else {
                goto cleanup;
            }

            if (fileSize == NULL) {
                LOG_E("nx_GetFileSettings Invalid fileSize Parameters!!!");
                goto cleanup;
            }

            tlvRet = get_U24_LSB(pRspbuf, &rspIndex, rspbufLen, &tmpUint32);
            ENSURE_OR_GO_CLEANUP(0 == tlvRet);
            *fileSize = (size_t)tmpUint32;

            if (*fileOption & NX_FILE_SETTING_FILEOPTION_SDM_ENABLED) {
                // sdmOption
                tlvRet = get_U8(pRspbuf, &rspIndex, rspbufLen, &sdmConfig->sdmOption);
                ENSURE_OR_GO_CLEANUP(0 == tlvRet);

                // SDMAccessRights
                tlvRet = get_U16_LSB(pRspbuf, &rspIndex, rspbufLen, &sdmAccessRights);
                ENSURE_OR_GO_CLEANUP(0 == tlvRet);

                sdmConfig->acSDMMetaRead =
                    (uint8_t)((sdmAccessRights >> NX_FILE_SDMMetaRead_OFFSET) & NX_FILE_SDMMetaRead_MASK);
                sdmConfig->acSDMFileRead =
                    (uint8_t)((sdmAccessRights >> NX_FILE_SDMFileRead_OFFSET) & NX_FILE_SDMFileRead_MASK);
                sdmConfig->acSDMFileRead2 =
                    (uint8_t)((sdmAccessRights >> NX_FILE_SDMFileRead2_OFFSET) & NX_FILE_SDMFileRead2_MASK);
                sdmConfig->acSDMCtrRet =
                    (uint8_t)((sdmAccessRights >> NX_FILE_SDMCtrRet_OFFSET) & NX_FILE_SDMCtrRet_MASK);

                // VCUIDOffset
                if ((sdmConfig->sdmOption & NX_FILE_SDM_OPTIONS_VCUID) &&
                    (((sdmAccessRights >> NX_FILE_SDMMetaRead_OFFSET) & NX_FILE_SDMMetaRead_MASK) ==
                        Nx_SDMMetaRead_AccessCondition_Plain_PICCData)) {
                    tlvRet = get_U24_LSB(pRspbuf, &rspIndex, rspbufLen, &(sdmConfig->VCUIDOffset));
                    ENSURE_OR_GO_CLEANUP(0 == tlvRet);
                }

                // SDMReadCtrOffset
                if ((sdmConfig->sdmOption & NX_FILE_SDM_OPTIONS_SDMReadCtr) &&
                    (((sdmAccessRights >> NX_FILE_SDMMetaRead_OFFSET) & NX_FILE_SDMMetaRead_MASK) ==
                        Nx_SDMMetaRead_AccessCondition_Plain_PICCData)) {
                    tlvRet = get_U24_LSB(pRspbuf, &rspIndex, rspbufLen, &(sdmConfig->SDMReadCtrOffset));
                    ENSURE_OR_GO_CLEANUP(0 == tlvRet);
                }

                // PICCDataOffset
                if ((((sdmAccessRights >> NX_FILE_SDMMetaRead_OFFSET) & NX_FILE_SDMMetaRead_MASK) !=
                        Nx_SDMMetaRead_AccessCondition_Plain_PICCData) &&
                    (((sdmAccessRights >> NX_FILE_SDMMetaRead_OFFSET) & NX_FILE_SDMMetaRead_MASK) !=
                        Nx_SDMMetaRead_AccessCondition_Plain_PICCData)) {
                    tlvRet = get_U24_LSB(pRspbuf, &rspIndex, rspbufLen, &(sdmConfig->PICCDataOffset));
                    ENSURE_OR_GO_CLEANUP(0 == tlvRet);
                }

                // GPIOStatusOffset
                if (sdmConfig->sdmOption & NX_FILE_SDM_OPTIONS_GPIOStatus) {
                    tlvRet = get_U24_LSB(pRspbuf, &rspIndex, rspbufLen, &(sdmConfig->GPIOStatusOffset));
                    ENSURE_OR_GO_CLEANUP(0 == tlvRet);
                }

                // SDMMACInputOffset
                if (((sdmAccessRights >> NX_FILE_SDMFileRead_OFFSET) & NX_FILE_SDMFileRead_MASK) !=
                    Nx_SDMFileRead_AccessCondition_No_SDM) {
                    tlvRet = get_U24_LSB(pRspbuf, &rspIndex, rspbufLen, &(sdmConfig->SDMMACInputOffset));
                    ENSURE_OR_GO_CLEANUP(0 == tlvRet);
                }

                // SDMENCOffset, SDMENCLength
                if ((((sdmAccessRights >> NX_FILE_SDMFileRead_OFFSET) & NX_FILE_SDMFileRead_MASK) !=
                        Nx_SDMFileRead_AccessCondition_No_SDM) &&
                    (sdmConfig->sdmOption & NX_FILE_SDM_OPTIONS_SDMENCFileData)) {
                    tlvRet = get_U24_LSB(pRspbuf, &rspIndex, rspbufLen, &(sdmConfig->SDMENCOffset));
                    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

                    tlvRet = get_U24_LSB(pRspbuf, &rspIndex, rspbufLen, &(sdmConfig->SDMENCLength));
                    ENSURE_OR_GO_CLEANUP(0 == tlvRet);
                }

                // SDMMACOffset
                if (((sdmAccessRights >> NX_FILE_SDMFileRead_OFFSET) & NX_FILE_SDMFileRead_MASK) !=
                    Nx_SDMFileRead_AccessCondition_No_SDM) {
                    tlvRet = get_U24_LSB(pRspbuf, &rspIndex, rspbufLen, &(sdmConfig->SDMMACOffset));
                    ENSURE_OR_GO_CLEANUP(0 == tlvRet);
                }

                // SDMReadCtrLimit
                if (sdmConfig->sdmOption & NX_FILE_SDM_OPTIONS_SDMReadCtrLimit) {
                    tlvRet = get_U24_LSB(pRspbuf, &rspIndex, rspbufLen, &(sdmConfig->SDMReadCtrLimit));
                    ENSURE_OR_GO_CLEANUP(0 == tlvRet);
                }

                // DeferOption and DeferMethod
                if (*fileOption & NX_FILE_SETTING_FILEOPTION_DEFERRED_CONF_ENABLED) {
                    tlvRet = get_U8(pRspbuf, &rspIndex, rspbufLen, &deferOption);
                    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

                    if (deferOption & NX_CONF_DEFER_SDM_ENC_ENABLED) {
                        sdmConfig->deferSDMEncEnabled = true;
                    }
                    else {
                        sdmConfig->deferSDMEncEnabled = false;
                    }

                    tlvRet = get_U8(pRspbuf, &rspIndex, rspbufLen, &(sdmConfig->sdmDeferMethod));
                    ENSURE_OR_GO_CLEANUP(0 == tlvRet);
                }
            }
        }
        else { // Counter file
            // FileOption
            tlvRet = get_U8(pRspbuf, &rspIndex, rspbufLen, fileOption);
            ENSURE_OR_GO_CLEANUP(0 == tlvRet);

            tmpUint8 = *fileOption & NX_FILE_OPTION_COMM_MODE_MASK;
            if ((tmpUint8 != Nx_CommMode_Plain) && (tmpUint8 != Nx_CommMode_MAC) && (tmpUint8 != Nx_CommMode_FULL)) {
                goto cleanup;
            }

            // AccessRights
            tlvRet = get_U16_LSB(pRspbuf, &rspIndex, rspbufLen, &accessRights);
            ENSURE_OR_GO_CLEANUP(0 == tlvRet);

            tmpUint16 = (accessRights >> NX_FILE_AR_READ_OFFSET) & NX_FILE_AR_READ_MASK;
            if (tmpUint16 <= Nx_AccessCondition_No_Access) {
                *readAccessCondition = (Nx_AccessCondition_t)tmpUint16;
            }
            else {
                goto cleanup;
            }
            tmpUint16 = (accessRights >> NX_FILE_AR_WRITE_OFFSET) & NX_FILE_AR_WRITE_MASK;
            if (tmpUint16 <= Nx_AccessCondition_No_Access) {
                *writeAccessCondition = (Nx_AccessCondition_t)tmpUint16;
            }
            else {
                goto cleanup;
            }
            tmpUint16 = (accessRights >> NX_FILE_AR_READWRITE_OFFSET) & NX_FILE_AR_READWRITE_MASK;
            if (tmpUint16 <= Nx_AccessCondition_No_Access) {
                *readWriteAccessCondition = (Nx_AccessCondition_t)tmpUint16;
            }
            else {
                goto cleanup;
            }
            tmpUint16 = (accessRights >> NX_FILE_AR_CHANGE_OFFSET) & NX_FILE_AR_CHANGE_MASK;
            if (tmpUint16 <= Nx_AccessCondition_No_Access) {
                *changeAccessCondition = (Nx_AccessCondition_t)tmpUint16;
            }
            else {
                goto cleanup;
            }
        }

        retStatus = (pRspbuf[rspbufLen - 2] << 8) | (pRspbuf[rspbufLen - 1]);
        if (retStatus == SM_OK_ALT) {
            retStatus = SM_OK;
        }
    }

cleanup:
    return retStatus;
}

smStatus_t nx_GetFileIDs(pSeSession_t session_ctx, uint8_t *fIDList, size_t *fIDListLen)
{
    smStatus_t retStatus                = SM_NOT_OK;
    tlvHeader_t hdr                     = {{NX_CLA, NX_INS_GET_FILE_IDS, NX_P1_DEFAULT, NX_P2_DEFAULT}};
    uint8_t cmdbuf[NX_MAX_BUF_SIZE_CMD] = {0};
    size_t cmdbufLen                    = 0;
    int tlvRet                          = 1;
    size_t rspIndex                     = 0;
    uint8_t rspbuf[NX_MAX_BUF_SIZE_RSP] = {0};
    size_t rspbufLen                    = sizeof(rspbuf);
    nx_ev2_comm_mode_t cmdCommMode      = EV2_CommMode_PLAIN;
    void *options                       = &cmdCommMode;

    if ((session_ctx == NULL) || (fIDList == NULL) || (fIDListLen == NULL)) {
        LOG_E("nx_GetFileIDs Invalid Parameters!!!");
        goto cleanup;
    }

    if ((session_ctx->authType == knx_AuthType_SIGMA_I_Verifier) ||
        (session_ctx->authType == knx_AuthType_SIGMA_I_Prover) || (session_ctx->authType == knx_AuthType_SYMM_AUTH)) {
        // Get commMode in case of authenticated.
        retStatus = secure_messaging_get_commMode(session_ctx, NX_INS_GET_FILE_IDS, &cmdCommMode, NULL);
        if (retStatus != SM_OK) {
            goto cleanup;
        }
    }

#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "GetFileIDs []");
#endif /* VERBOSE_APDU_LOGS */

    retStatus = DoAPDUTxRx_s_Case4(session_ctx, &hdr, cmdbuf, cmdbufLen, NULL, 0, rspbuf, &rspbufLen, options);

    if (retStatus == SM_OK) {
        retStatus = SM_NOT_OK;
        if (rspbufLen > 34) { // 0..32 + 2 bytes SW
            goto cleanup;
        }
        else if (rspbufLen > 2) {
            tlvRet = get_u8buf(rspbuf, &rspIndex, rspbufLen, fIDList, rspbufLen - 2);
            ENSURE_OR_GO_CLEANUP(0 == tlvRet);
            *fIDListLen = rspbufLen - 2;
        }
        else {
            *fIDListLen = 0;
        }
        retStatus = (rspbuf[rspbufLen - 2] << 8) | (rspbuf[rspbufLen - 1]);
        if (retStatus == SM_OK_ALT) {
            retStatus = SM_OK;
        }
    }

cleanup:
    return retStatus;
}

smStatus_t nx_GetISOFileIDs(pSeSession_t session_ctx, uint8_t *fIDList, size_t *fIDListLen)
{
    smStatus_t retStatus                = SM_NOT_OK;
    tlvHeader_t hdr                     = {{NX_CLA, NX_INS_GET_ISO_FILE_IDS, NX_P1_DEFAULT, NX_P2_DEFAULT}};
    uint8_t cmdbuf[NX_MAX_BUF_SIZE_CMD] = {0};
    size_t cmdbufLen                    = 0;
    int tlvRet                          = 1;
    size_t rspIndex                     = 0;
    uint8_t rspbuf[NX_MAX_BUF_SIZE_RSP] = {0};
    size_t rspbufLen                    = sizeof(rspbuf);
    nx_ev2_comm_mode_t cmdCommMode      = EV2_CommMode_PLAIN;
    void *options                       = &cmdCommMode;

    if ((session_ctx == NULL) || (fIDList == NULL) || (fIDListLen == NULL)) {
        LOG_E("nx_GetFileIDs Invalid Parameters!!!");
        goto cleanup;
    }

    if ((session_ctx->authType == knx_AuthType_SIGMA_I_Verifier) ||
        (session_ctx->authType == knx_AuthType_SIGMA_I_Prover) || (session_ctx->authType == knx_AuthType_SYMM_AUTH)) {
        // Get commMode in case of authenticated.
        retStatus = secure_messaging_get_commMode(session_ctx, NX_INS_GET_ISO_FILE_IDS, &cmdCommMode, NULL);
        if (retStatus != SM_OK) {
            goto cleanup;
        }
    }

#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "GetISOFileIDs []");
#endif /* VERBOSE_APDU_LOGS */

    retStatus = DoAPDUTxRx_s_Case4(session_ctx, &hdr, cmdbuf, cmdbufLen, NULL, 0, rspbuf, &rspbufLen, options);
    if (retStatus == SM_OK) {
        retStatus = SM_NOT_OK;
        if (rspbufLen > 56) { // n*2 n[0..27] + 2 bytes SW
            goto cleanup;
        }
        else if (rspbufLen > 2) {
            tlvRet = get_u8buf(rspbuf, &rspIndex, rspbufLen, fIDList, rspbufLen - 2);
            ENSURE_OR_GO_CLEANUP(0 == tlvRet);
            *fIDListLen = rspbufLen - 2;
        }
        else {
            *fIDListLen = 0;
        }
        retStatus = (rspbuf[rspbufLen - 2] << 8) | (rspbuf[rspbufLen - 1]);
        if (retStatus == SM_OK_ALT) {
            retStatus = SM_OK;
        }
    }

cleanup:
    return retStatus;
}

smStatus_t nx_ReadData(pSeSession_t session_ctx,
    uint8_t fileNo,
    size_t offset,
    size_t dataLen,
    uint8_t *buffer,
    size_t *bufferSize,
    Nx_CommMode_t knownCommMode)
{
    smStatus_t retStatus                = SM_NOT_OK;
    tlvHeader_t hdr                     = {{NX_CLA, NX_INS_READ_DATA, NX_P1_DEFAULT, NX_P2_DEFAULT}};
    uint8_t cmdbuf[NX_MAX_BUF_SIZE_CMD] = {0};
    size_t cmdbufLen                    = 0;
    int tlvRet                          = 1;
    size_t rspIndex                     = 0;
    uint8_t *pCmdbuf                    = &cmdbuf[0];
    size_t length;
    uint8_t rspbuf[NX_MAX_BUF_SIZE_RSP] = {0};
    size_t rspbufLen                    = sizeof(rspbuf);
    nx_ev2_comm_mode_t cmdCommMode      = EV2_CommMode_PLAIN;
    void *options                       = &cmdCommMode;

    if ((session_ctx == NULL) || (buffer == NULL) || (bufferSize == NULL)) {
        LOG_E("nx_ReadData Invalid Parameters!!!");
        goto cleanup;
    }

    retStatus = nx_get_comm_mode(session_ctx, knownCommMode, NX_INS_READ_DATA, &cmdCommMode, &fileNo);
    ENSURE_OR_GO_CLEANUP(SM_OK == retStatus);

    retStatus = SM_NOT_OK; //reinitialized

#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "ReadData []");
#endif /* VERBOSE_APDU_LOGS */

    fileNo = fileNo & NX_FILE_NO_MASK;
    tlvRet = SET_U8("FileNo", &pCmdbuf, &cmdbufLen, fileNo);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_U24_LSB("offset", &pCmdbuf, &cmdbufLen, offset);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    if (dataLen > NX_DADA_MGMT_MAX_FILE_SIZE) {
        length = 0; // Entire data file.
    }
    else {
        length = dataLen;
    }

    tlvRet = SET_U24_LSB("length", &pCmdbuf, &cmdbufLen, length);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    retStatus = DoAPDUTxRx_s_Case4_ext(session_ctx, &hdr, cmdbuf, cmdbufLen, NULL, 0, rspbuf, &rspbufLen, options);

    if (retStatus == SM_OK) {
        retStatus = SM_NOT_OK;
        if (rspbufLen < 2) {
            goto cleanup;
        }
        else if (rspbufLen > 2) {
            if (*bufferSize >= rspbufLen - 2) {
                tlvRet = get_u8buf(rspbuf, &rspIndex, rspbufLen, buffer, rspbufLen - 2);
                ENSURE_OR_GO_CLEANUP(0 == tlvRet);
                *bufferSize = rspbufLen - 2;
            }
            else {
                goto cleanup;
            }
        }
        else if (rspbufLen == 2) {
            *bufferSize = 0;
        }
        retStatus = (rspbuf[rspbufLen - 2] << 8) | (rspbuf[rspbufLen - 1]);
        if (retStatus == SM_OK_ALT) {
            retStatus = SM_OK;
        }
    }

cleanup:
    return retStatus;
}

smStatus_t nx_WriteData(pSeSession_t session_ctx,
    uint8_t fileNo,
    size_t offset,
    const uint8_t *data,
    size_t dataLen,
    Nx_CommMode_t knownCommMode)
{
    smStatus_t retStatus                      = SM_NOT_OK;
    tlvHeader_t hdr                           = {{NX_CLA, NX_INS_WRITE_DATA, NX_P1_DEFAULT, NX_P2_DEFAULT}};
    uint8_t cmdHeaderBuf[NX_MAX_BUF_SIZE_CMD] = {0};
    size_t cmdHeaderBufLen                    = 0;
    uint8_t cmdDataBuf[NX_MAX_BUF_SIZE_CMD]   = {0};
    size_t cmdDataBufBufLen                   = 0;
    int tlvRet                                = 1;
    uint8_t *pCmdHeaderBuf                    = &cmdHeaderBuf[0];
    uint8_t *pCmdDataBuf                      = &cmdDataBuf[0];
    uint8_t rspbuf[NX_MAX_BUF_SIZE_RSP]       = {0};
    size_t rspbufLen                          = sizeof(rspbuf);
    nx_ev2_comm_mode_t cmdCommMode            = EV2_CommMode_PLAIN;
    void *options                             = &cmdCommMode;

    if ((session_ctx == NULL) || (data == NULL)) {
        LOG_E("nx_ReadData Invalid Parameters!!!");
        goto cleanup;
    }

    retStatus = nx_get_comm_mode(session_ctx, knownCommMode, NX_INS_WRITE_DATA, &cmdCommMode, &fileNo);
    ENSURE_OR_GO_CLEANUP(SM_OK == retStatus);

    retStatus = SM_NOT_OK; //reinitialized

#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "WriteData []");
#endif /* VERBOSE_APDU_LOGS */

    fileNo = fileNo & NX_FILE_NO_MASK;
    tlvRet = SET_U8("fileNo", &pCmdHeaderBuf, &cmdHeaderBufLen, fileNo);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_U24_LSB("offset", &pCmdHeaderBuf, &cmdHeaderBufLen, offset);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_U24_LSB("length", &pCmdHeaderBuf, &cmdHeaderBufLen, dataLen);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_u8buf("data", &pCmdDataBuf, &cmdDataBufBufLen, data, dataLen);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    retStatus = DoAPDUTxRx_s_Case4_ext(
        session_ctx, &hdr, cmdHeaderBuf, cmdHeaderBufLen, cmdDataBuf, cmdDataBufBufLen, rspbuf, &rspbufLen, options);

cleanup:
    return retStatus;
}

smStatus_t nx_ISOInternalAuthenticate(pSeSession_t session_ctx,
    uint8_t privKeyNo,
    uint8_t *optsA,
    size_t optsALen,
    uint8_t *rndA,
    size_t rndALen,
    uint8_t *rndB,
    size_t *rndBLen,
    uint8_t *sigB,
    size_t *sigBLen)
{
    smStatus_t retStatus                    = SM_NOT_OK;
    tlvHeader_t hdr                         = {{NX_CLA_ISO, NX_INS_ISO_INTERNAL_AUTH, NX_P1_DEFAULT, NX_P2_DEFAULT}};
    uint8_t cmdDataBuf[NX_MAX_BUF_SIZE_CMD] = {0};
    size_t cmdDataBufBufLen                 = 0;
    int tlvRet                              = 1;
    size_t rspIndex                         = 0;
    uint8_t *pCmdDataBuf                    = &cmdDataBuf[0];
    uint8_t rspbuf[NX_MAX_BUF_SIZE_RSP]     = {0};
    uint8_t temp[100]                       = {0};
    uint8_t *ptemp                          = &temp[0];
    size_t tempLen                          = 0;
    size_t rspbufLen                        = sizeof(rspbuf);
#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "ISOInternalAuthenticate []");
#endif /* VERBOSE_APDU_LOGS */

    ENSURE_OR_GO_CLEANUP(NULL != session_ctx)
    ENSURE_OR_GO_CLEANUP(NULL != optsA)
    ENSURE_OR_GO_CLEANUP(NULL != rndA)
    ENSURE_OR_GO_CLEANUP(NULL != rndB)
    ENSURE_OR_GO_CLEANUP(NULL != rndBLen)
    ENSURE_OR_GO_CLEANUP(NULL != sigB)
    ENSURE_OR_GO_CLEANUP(NULL != sigBLen)

    if ((rndALen != NX_ISO_INTERNAL_AUTH_RND_LENGTH) || (optsALen > NX_ISO_INTERNAL_AUTH_OPTSA_MAX_LENGTH)) {
        LOG_E("Invalid parameter for nx_ISOInternalAuthenticate.");
        goto cleanup;
    }

    hdr.hdr[3] = privKeyNo;

    tlvRet = TLVSET_u8buf("OptsA", &pCmdDataBuf, &cmdDataBufBufLen, NX_TAG_OPTS_A, optsA, optsALen);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = TLVSET_u8buf("rndA", &ptemp, &tempLen, NX_TAG_RNDA, rndA, rndALen);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = TLVSET_u8buf("AuthDOHdr", &pCmdDataBuf, &cmdDataBufBufLen, NX_TAG_AUTHDOHDR, temp, tempLen);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    retStatus =
        DoAPDUTxRx_s_Case4_ext(session_ctx, &hdr, NULL, 0, cmdDataBuf, cmdDataBufBufLen, rspbuf, &rspbufLen, NULL);
    if (retStatus == SM_OK) {
        retStatus = SM_NOT_OK;
        if (rspbufLen != 88) {
            goto cleanup;
        }

        tlvRet = tlvGet_ValueIndex(rspbuf, &rspIndex, rspbufLen, NX_TAG_AUTHDOHDR);
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);

        tlvRet = tlvGet_u8buf(rspbuf, &rspIndex, rspbufLen, NX_TAG_RNDB, rndB, rndBLen);
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);

        tlvRet = tlvGet_u8buf(rspbuf, &rspIndex, rspbufLen, NX_TAG_SIG_B, sigB, sigBLen);
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);

        if ((rspIndex + 2) == rspbufLen) {
            retStatus = (smStatus_t)((rspbuf[rspIndex] << 8) | (rspbuf[rspIndex + 1]));
        }
    }

cleanup:
    return retStatus;
}

smStatus_t nx_ISOSelectFile(pSeSession_t session_ctx,
    Nx_ISOSelectCtl_t selectionCtl,
    Nx_ISOSelectOpt_t option,
    uint8_t *data,
    size_t dataLen,
    uint8_t *FCIData,
    size_t *FCIDataLen)
{
    smStatus_t retStatus                    = SM_NOT_OK;
    tlvHeader_t hdr                         = {{NX_CLA_ISO, NX_INS_ISO_SELECT_FILE, selectionCtl, option}};
    uint8_t cmdDataBuf[NX_MAX_BUF_SIZE_CMD] = {0};
    size_t cmdDataBufBufLen                 = 0;
    int tlvRet                              = 1;
    size_t rspIndex                         = 0;
    uint8_t *pCmdDataBuf                    = &cmdDataBuf[0];
    uint8_t rspbuf[NX_MAX_BUF_SIZE_RSP]     = {0};
    size_t rspbufLen                        = sizeof(rspbuf);
#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "ISOSelectFile []");
#endif /* VERBOSE_APDU_LOGS */

    ENSURE_OR_GO_CLEANUP(NULL != session_ctx)
    ENSURE_OR_GO_CLEANUP(NULL != FCIDataLen)

    if (data != NULL) {
        tlvRet = SET_u8buf("Data", &pCmdDataBuf, &cmdDataBufBufLen, data, dataLen);
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);
    }

    retStatus =
        DoAPDUTxRx_s_Case4_ext(session_ctx, &hdr, NULL, 0, cmdDataBuf, cmdDataBufBufLen, rspbuf, &rspbufLen, NULL);
    if (retStatus == SM_OK) {
        retStatus = SM_NOT_OK;
        if (rspbufLen < 2) {
            goto cleanup;
        }
        else if ((rspbufLen - 2) > 0) {
            if ((FCIData != NULL) && (FCIDataLen != NULL) && (*FCIDataLen >= rspbufLen - 2)) {
                tlvRet = get_u8buf(rspbuf, &rspIndex, rspbufLen, FCIData, rspbufLen - 2);
                ENSURE_OR_GO_CLEANUP(0 == tlvRet);
                *FCIDataLen = rspbufLen - 2;
            }
            else {
                goto cleanup;
            }
        }
        else {
            *FCIDataLen = 0;
        }
        retStatus = (rspbuf[rspbufLen - 2] << 8) | (rspbuf[rspbufLen - 1]);
        if (retStatus == SM_OK_ALT) {
            retStatus = SM_OK;
        }
    }

cleanup:
    return retStatus;
}

smStatus_t nx_ISOReadBinary_ShortFile(
    pSeSession_t session_ctx, uint8_t shortISOFileID, size_t offset, uint8_t *data, size_t *dataLen)
{
    smStatus_t retStatus = SM_NOT_OK;
    shortISOFileID &= 0x1F;
    shortISOFileID |= 0x80;
    tlvHeader_t hdr                     = {{NX_CLA_ISO, NX_INS_ISO_READ_BINARY, shortISOFileID, 0}};
    int tlvRet                          = 1;
    size_t rspIndex                     = 0;
    uint8_t rspbuf[NX_MAX_BUF_SIZE_RSP] = {0};
    size_t rspbufLen                    = sizeof(rspbuf);

    ENSURE_OR_GO_CLEANUP(offset <= UINT8_MAX);
    hdr.hdr[3] = (uint8_t)offset;
#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "ISOReadBinary_ShortFile []");
#endif /* VERBOSE_APDU_LOGS */

    if ((session_ctx == NULL) || (data == NULL) || (dataLen == NULL)) {
        goto cleanup;
    }

    retStatus = DoAPDUTxRx_s_Case4_ext(session_ctx, &hdr, NULL, 0, NULL, 0, rspbuf, &rspbufLen, NULL);
    if (retStatus == SM_OK) {
        retStatus = SM_NOT_OK;
        if (rspbufLen < 2) {
            goto cleanup;
        }
        else if (rspbufLen > 2) {
            if (*dataLen >= rspbufLen - 2) {
                tlvRet = get_u8buf(rspbuf, &rspIndex, rspbufLen, data, rspbufLen - 2);
                ENSURE_OR_GO_CLEANUP(0 == tlvRet);
                *dataLen = rspbufLen - 2;
            }
            else {
                goto cleanup;
            }
        }
        else {
            *dataLen = 0;
        }
        retStatus = (rspbuf[rspbufLen - 2] << 8) | (rspbuf[rspbufLen - 1]);
        if (retStatus == SM_OK_ALT) {
            retStatus = SM_OK;
        }
    }

cleanup:
    return retStatus;
}

smStatus_t nx_ISOReadBinary(pSeSession_t session_ctx, size_t offset, uint8_t *data, size_t *dataLen)
{
    smStatus_t retStatus = SM_NOT_OK;
    tlvHeader_t hdr      = {
        {NX_CLA_ISO, NX_INS_ISO_READ_BINARY, (uint8_t)((offset & 0x7F00) >> 8), (uint8_t)(offset & 0xFF)}};
    int tlvRet                          = 1;
    size_t rspIndex                     = 0;
    uint8_t rspbuf[NX_MAX_BUF_SIZE_RSP] = {0};
    size_t rspbufLen                    = sizeof(rspbuf);
#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "ISOReadBinary []");
#endif /* VERBOSE_APDU_LOGS */

    if ((session_ctx == NULL) || (data == NULL) || (dataLen == NULL)) {
        goto cleanup;
    }

    retStatus = DoAPDUTxRx_s_Case4_ext(session_ctx, &hdr, NULL, 0, NULL, 0, rspbuf, &rspbufLen, NULL);
    if (retStatus == SM_OK) {
        retStatus = SM_NOT_OK;
        if (rspbufLen < 2) {
            goto cleanup;
        }
        else if (rspbufLen > 2) {
            if (*dataLen >= rspbufLen - 2) {
                tlvRet = get_u8buf(rspbuf, &rspIndex, rspbufLen, data, rspbufLen - 2);
                ENSURE_OR_GO_CLEANUP(0 == tlvRet);
                *dataLen = rspbufLen - 2;
            }
            else {
                goto cleanup;
            }
        }
        else {
            *dataLen = 0;
        }
        retStatus = (rspbuf[rspbufLen - 2] << 8) | (rspbuf[rspbufLen - 1]);
        if (retStatus == SM_OK_ALT) {
            retStatus = SM_OK;
        }
    }

cleanup:
    return retStatus;
}

smStatus_t nx_ISOUpdateBinary_ShortFile(
    pSeSession_t session_ctx, uint8_t shortISOFileID, size_t offset, const uint8_t *data, size_t dataLen)
{
    smStatus_t retStatus = SM_NOT_OK;
    shortISOFileID &= 0x1F;
    shortISOFileID |= 0x80;
    tlvHeader_t hdr                         = {{NX_CLA_ISO, NX_INS_ISO_UPDATE_BINARY, shortISOFileID, NX_P2_DEFAULT}};
    uint8_t cmdDataBuf[NX_MAX_BUF_SIZE_CMD] = {0};
    size_t cmdDataBufBufLen                 = 0;
    int tlvRet                              = 1;
    uint8_t *pCmdDataBuf                    = &cmdDataBuf[0];
#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "ISOUpdateBinary_ShortFile []");
#endif /* VERBOSE_APDU_LOGS */

    ENSURE_OR_GO_CLEANUP(NULL != session_ctx)
    ENSURE_OR_GO_CLEANUP(NULL != data)

    tlvRet = SET_u8buf("Data", &pCmdDataBuf, &cmdDataBufBufLen, data, dataLen);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    retStatus = DoAPDUTx_s_Case3(session_ctx, &hdr, NULL, 0, cmdDataBuf, cmdDataBufBufLen, NULL);

cleanup:
    return retStatus;
}

smStatus_t nx_ISOUpdateBinary(pSeSession_t session_ctx, size_t offset, const uint8_t *data, size_t dataLen)
{
    smStatus_t retStatus = SM_NOT_OK;
    tlvHeader_t hdr      = {
        {NX_CLA_ISO, NX_INS_ISO_UPDATE_BINARY, (uint8_t)((offset & 0x7F00) >> 8), (uint8_t)(offset & 0xFF)}};
    uint8_t cmdDataBuf[NX_MAX_BUF_SIZE_CMD] = {0};
    size_t cmdDataBufBufLen                 = 0;
    int tlvRet                              = 1;
    uint8_t *pCmdDataBuf                    = &cmdDataBuf[0];
#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "ISOUpdateBinary []");
#endif /* VERBOSE_APDU_LOGS */

    ENSURE_OR_GO_CLEANUP(NULL != session_ctx)
    ENSURE_OR_GO_CLEANUP(NULL != data)

    tlvRet = SET_u8buf("Data", &pCmdDataBuf, &cmdDataBufBufLen, data, dataLen);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    retStatus = DoAPDUTx_s_Case3(session_ctx, &hdr, NULL, 0, cmdDataBuf, cmdDataBufBufLen, NULL);

cleanup:
    return retStatus;
}

smStatus_t nx_CryptoRequest_SHA_Init(
    pSeSession_t session_ctx, uint8_t algorithm, uint8_t inputDataSrc, const uint8_t *inputData, size_t inputDataLen)
{
    smStatus_t retStatus                      = SM_NOT_OK;
    tlvHeader_t hdr                           = {{NX_CLA, NX_INS_CRYPTO_REQ, NX_P1_DEFAULT, NX_P2_DEFAULT}};
    uint8_t cmdHeaderBuf[NX_MAX_BUF_SIZE_CMD] = {0};
    size_t cmdHeaderBufLen                    = 0;
    uint8_t cmdDataBuf[NX_MAX_BUF_SIZE_CMD]   = {0};
    size_t cmdDataBufBufLen                   = 0;
    int tlvRet                                = 1;
    uint8_t *pCmdDataBuf                      = &cmdDataBuf[0];
    uint8_t rspbuf[NX_MAX_BUF_SIZE_RSP]       = {0};
    size_t rspbufLen                          = sizeof(rspbuf);
    nx_ev2_comm_mode_t commMode               = EV2_CommMode_PLAIN;
    void *options                             = &commMode;

    if (session_ctx == NULL) {
        goto cleanup;
    }

    retStatus = nx_get_comm_mode(session_ctx, session_ctx->userCryptoCommMode, NX_INS_CRYPTO_REQ, &commMode, NULL);
    ENSURE_OR_GO_CLEANUP(SM_OK == retStatus);

    retStatus = SM_NOT_OK; //reinitialized

#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "CryptoRequest SHA [Init]");
#endif /* VERBOSE_APDU_LOGS */

    tlvRet = SET_U8("Action", &pCmdDataBuf, &cmdDataBufBufLen, Nx_CryptoAPI_Operation_SHA);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_U8("Operation", &pCmdDataBuf, &cmdDataBufBufLen, kSE_DigestOperate_INIT);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_U8("Algorithm", &pCmdDataBuf, &cmdDataBufBufLen, algorithm);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_U8("Input Data Source", &pCmdDataBuf, &cmdDataBufBufLen, inputDataSrc);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    if (inputDataSrc != kSE_CryptoDataSrc_CommandBuf) {
        if (inputDataLen > UINT8_MAX) {
            retStatus = SM_NOT_OK;
            goto cleanup;
        }
        tlvRet = SET_U8("Input Data Length", &pCmdDataBuf, &cmdDataBufBufLen, (uint8_t)inputDataLen);
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);
    }
    else {
        if (inputData != NULL) {
            tlvRet = SET_u8buf("Input Data", &pCmdDataBuf, &cmdDataBufBufLen, inputData, inputDataLen);
            ENSURE_OR_GO_CLEANUP(0 == tlvRet);
        }
    }

    retStatus = DoAPDUTxRx_s_Case4(
        session_ctx, &hdr, cmdHeaderBuf, cmdHeaderBufLen, cmdDataBuf, cmdDataBufBufLen, rspbuf, &rspbufLen, options);

    if (retStatus == SM_OK) {
        retStatus = SM_NOT_OK;

        if (rspbufLen != 2) {
            goto cleanup;
        }

        retStatus = (rspbuf[rspbufLen - 2] << 8) | (rspbuf[rspbufLen - 1]);
        if (retStatus == SM_OK_ALT) {
            retStatus = SM_OK;
        }
    }

cleanup:
    return retStatus;
}

smStatus_t nx_CryptoRequest_SHA_Update(
    pSeSession_t session_ctx, uint8_t algorithm, uint8_t inputDataSrc, const uint8_t *inputData, size_t inputDataLen)
{
    smStatus_t retStatus                      = SM_NOT_OK;
    tlvHeader_t hdr                           = {{NX_CLA, NX_INS_CRYPTO_REQ, NX_P1_DEFAULT, NX_P2_DEFAULT}};
    uint8_t cmdHeaderBuf[NX_MAX_BUF_SIZE_CMD] = {0};
    size_t cmdHeaderBufLen                    = 0;
    uint8_t cmdDataBuf[NX_MAX_BUF_SIZE_CMD]   = {0};
    size_t cmdDataBufBufLen                   = 0;
    int tlvRet                                = 1;
    uint8_t *pCmdDataBuf                      = &cmdDataBuf[0];
    uint8_t rspbuf[NX_MAX_BUF_SIZE_RSP]       = {0};
    size_t rspbufLen                          = sizeof(rspbuf);
    nx_ev2_comm_mode_t commMode               = EV2_CommMode_PLAIN;
    void *options                             = &commMode;

    if (session_ctx == NULL) {
        goto cleanup;
    }

    retStatus = nx_get_comm_mode(session_ctx, session_ctx->userCryptoCommMode, NX_INS_CRYPTO_REQ, &commMode, NULL);
    ENSURE_OR_GO_CLEANUP(SM_OK == retStatus);

    retStatus = SM_NOT_OK; //reinitialized

#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "CryptoRequest SHA [Update]");
#endif /* VERBOSE_APDU_LOGS */

    tlvRet = SET_U8("Action", &pCmdDataBuf, &cmdDataBufBufLen, Nx_CryptoAPI_Operation_SHA);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_U8("Operation", &pCmdDataBuf, &cmdDataBufBufLen, kSE_DigestOperate_UPDATE);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_U8("Input Data Source", &pCmdDataBuf, &cmdDataBufBufLen, inputDataSrc);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    if (inputDataSrc != kSE_CryptoDataSrc_CommandBuf) {
        if (inputDataLen > UINT8_MAX) {
            retStatus = SM_NOT_OK;
            goto cleanup;
        }
        tlvRet = SET_U8("Input Data Length", &pCmdDataBuf, &cmdDataBufBufLen, (uint8_t)inputDataLen);
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);
    }
    else {
        if (inputData != NULL) {
            tlvRet = SET_u8buf("Input Data", &pCmdDataBuf, &cmdDataBufBufLen, inputData, inputDataLen);
            ENSURE_OR_GO_CLEANUP(0 == tlvRet);
        }
    }

    retStatus = DoAPDUTxRx_s_Case4(
        session_ctx, &hdr, cmdHeaderBuf, cmdHeaderBufLen, cmdDataBuf, cmdDataBufBufLen, rspbuf, &rspbufLen, options);

    if (retStatus == SM_OK) {
        retStatus = SM_NOT_OK;

        if (rspbufLen != 2) {
            goto cleanup;
        }

        retStatus = (rspbuf[rspbufLen - 2] << 8) | (rspbuf[rspbufLen - 1]);
        if (retStatus == SM_OK_ALT) {
            retStatus = SM_OK;
        }
    }

cleanup:
    return retStatus;
}

smStatus_t nx_CryptoRequest_SHA_Final(pSeSession_t session_ctx,
    uint8_t algorithm,
    uint8_t inputDataSrc,
    const uint8_t *inputData,
    size_t inputDataLen,
    uint8_t resultDst,
    uint8_t *outputData,
    size_t *outputDataLen)
{
    smStatus_t retStatus                      = SM_NOT_OK;
    tlvHeader_t hdr                           = {{NX_CLA, NX_INS_CRYPTO_REQ, NX_P1_DEFAULT, NX_P2_DEFAULT}};
    uint8_t cmdHeaderBuf[NX_MAX_BUF_SIZE_CMD] = {0};
    size_t cmdHeaderBufLen                    = 0;
    uint8_t cmdDataBuf[NX_MAX_BUF_SIZE_CMD]   = {0};
    size_t cmdDataBufBufLen                   = 0;
    int tlvRet                                = 1;
    uint8_t *pCmdDataBuf                      = &cmdDataBuf[0];
    size_t rspIndex                           = 0;
    uint8_t rspbuf[NX_MAX_BUF_SIZE_RSP]       = {0};
    size_t rspbufLen                          = sizeof(rspbuf);
    nx_ev2_comm_mode_t commMode               = EV2_CommMode_PLAIN;
    void *options                             = &commMode;

    if (session_ctx == NULL) {
        goto cleanup;
    }

    retStatus = nx_get_comm_mode(session_ctx, session_ctx->userCryptoCommMode, NX_INS_CRYPTO_REQ, &commMode, NULL);
    ENSURE_OR_GO_CLEANUP(SM_OK == retStatus);

    retStatus = SM_NOT_OK; //reinitialized

#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "CryptoRequest SHA [Final]");
#endif /* VERBOSE_APDU_LOGS */

    tlvRet = SET_U8("Action", &pCmdDataBuf, &cmdDataBufBufLen, Nx_CryptoAPI_Operation_SHA);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_U8("Operation", &pCmdDataBuf, &cmdDataBufBufLen, kSE_DigestOperate_FINALIZE);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_U8("Input Data Source", &pCmdDataBuf, &cmdDataBufBufLen, inputDataSrc);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    if (inputDataSrc != kSE_CryptoDataSrc_CommandBuf) {
        if (inputDataLen > UINT8_MAX) {
            retStatus = SM_NOT_OK;
            goto cleanup;
        }
        tlvRet = SET_U8("Input Data Length", &pCmdDataBuf, &cmdDataBufBufLen, (uint8_t)inputDataLen);
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);
    }
    else {
        if (inputData != NULL) {
            tlvRet = SET_u8buf("Input Data", &pCmdDataBuf, &cmdDataBufBufLen, inputData, inputDataLen);
            ENSURE_OR_GO_CLEANUP(0 == tlvRet);
        }
    }

    tlvRet = SET_U8("Result Destination", &pCmdDataBuf, &cmdDataBufBufLen, resultDst);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    retStatus = DoAPDUTxRx_s_Case4(
        session_ctx, &hdr, cmdHeaderBuf, cmdHeaderBufLen, cmdDataBuf, cmdDataBufBufLen, rspbuf, &rspbufLen, options);

    if (retStatus == SM_OK) {
        retStatus = SM_NOT_OK;

        if (resultDst == kSE_CryptoDataSrc_CommandBuf) {
            if ((outputData == NULL) || (outputDataLen == NULL)) {
                goto cleanup;
            }

            if (rspbufLen < 2) {
                goto cleanup;
            }

            if (*outputDataLen < rspbufLen - 2) {
                goto cleanup;
            }

            tlvRet = get_u8buf(rspbuf, &rspIndex, rspbufLen, outputData, rspbufLen - 2);
            ENSURE_OR_GO_CLEANUP(0 == tlvRet);
            *outputDataLen = rspbufLen - 2;
        }
        else {
            if (rspbufLen != 2) {
                goto cleanup;
            }
        }

        retStatus = (rspbuf[rspbufLen - 2] << 8) | (rspbuf[rspbufLen - 1]);
        if (retStatus == SM_OK_ALT) {
            retStatus = SM_OK;
        }
    }

cleanup:
    return retStatus;
}

smStatus_t nx_CryptoRequest_SHA_Oneshot(pSeSession_t session_ctx,
    uint8_t algorithm,
    uint8_t inputDataSrc,
    const uint8_t *inputData,
    size_t inputDataLen,
    uint8_t resultDst,
    uint8_t *outputData,
    size_t *outputDataLen)
{
    smStatus_t retStatus                      = SM_NOT_OK;
    tlvHeader_t hdr                           = {{NX_CLA, NX_INS_CRYPTO_REQ, NX_P1_DEFAULT, NX_P2_DEFAULT}};
    uint8_t cmdHeaderBuf[NX_MAX_BUF_SIZE_CMD] = {0};
    size_t cmdHeaderBufLen                    = 0;
    uint8_t cmdDataBuf[NX_MAX_BUF_SIZE_CMD]   = {0};
    size_t cmdDataBufBufLen                   = 0;
    int tlvRet                                = 1;
    uint8_t *pCmdDataBuf                      = &cmdDataBuf[0];
    size_t rspIndex                           = 0;
    uint8_t rspbuf[NX_MAX_BUF_SIZE_RSP]       = {0};
    size_t rspbufLen                          = sizeof(rspbuf);
    nx_ev2_comm_mode_t commMode               = EV2_CommMode_PLAIN;
    void *options                             = &commMode;

    if (session_ctx == NULL) {
        goto cleanup;
    }

    retStatus = nx_get_comm_mode(session_ctx, session_ctx->userCryptoCommMode, NX_INS_CRYPTO_REQ, &commMode, NULL);
    ENSURE_OR_GO_CLEANUP(SM_OK == retStatus);

    retStatus = SM_NOT_OK; //reinitialized

#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "CryptoRequest SHA [Oneshot]");
#endif /* VERBOSE_APDU_LOGS */

    tlvRet = SET_U8("Action", &pCmdDataBuf, &cmdDataBufBufLen, Nx_CryptoAPI_Operation_SHA);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_U8("Operation", &pCmdDataBuf, &cmdDataBufBufLen, kSE_DigestOperate_ONESHOT);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_U8("Algorithm", &pCmdDataBuf, &cmdDataBufBufLen, algorithm);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_U8("Input Data Source", &pCmdDataBuf, &cmdDataBufBufLen, inputDataSrc);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    if (inputDataSrc != kSE_CryptoDataSrc_CommandBuf) {
        if (inputDataLen > UINT8_MAX) {
            retStatus = SM_NOT_OK;
            goto cleanup;
        }
        tlvRet = SET_U8("Input Data Length", &pCmdDataBuf, &cmdDataBufBufLen, (uint8_t)inputDataLen);
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);
    }
    else {
        if (inputData != NULL) {
            tlvRet = SET_u8buf("Input Data", &pCmdDataBuf, &cmdDataBufBufLen, inputData, inputDataLen);
            ENSURE_OR_GO_CLEANUP(0 == tlvRet);
        }
    }

    tlvRet = SET_U8("Result Destination", &pCmdDataBuf, &cmdDataBufBufLen, resultDst);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    retStatus = DoAPDUTxRx_s_Case4(
        session_ctx, &hdr, cmdHeaderBuf, cmdHeaderBufLen, cmdDataBuf, cmdDataBufBufLen, rspbuf, &rspbufLen, options);

    if (retStatus == SM_OK) {
        retStatus = SM_NOT_OK;

        if (resultDst == kSE_CryptoDataSrc_CommandBuf) {
            if ((outputData == NULL) || (outputDataLen == NULL)) {
                goto cleanup;
            }

            if (rspbufLen < 2) {
                goto cleanup;
            }

            if (*outputDataLen < rspbufLen - 2) {
                goto cleanup;
            }

            tlvRet = get_u8buf(rspbuf, &rspIndex, rspbufLen, outputData, rspbufLen - 2);
            ENSURE_OR_GO_CLEANUP(0 == tlvRet);
            *outputDataLen = rspbufLen - 2;
        }
        else {
            if (rspbufLen != 2) {
                goto cleanup;
            }
        }

        retStatus = (rspbuf[rspbufLen - 2] << 8) | (rspbuf[rspbufLen - 1]);
        if (retStatus == SM_OK_ALT) {
            retStatus = SM_OK;
        }
    }

cleanup:
    return retStatus;
}

smStatus_t nx_CryptoRequest_RNG(
    pSeSession_t session_ctx, uint8_t rndLen, uint8_t resultDst, uint8_t *outputData, size_t *outputDataLen)
{
    smStatus_t retStatus                      = SM_NOT_OK;
    tlvHeader_t hdr                           = {{NX_CLA, NX_INS_CRYPTO_REQ, NX_P1_DEFAULT, NX_P2_DEFAULT}};
    uint8_t cmdHeaderBuf[NX_MAX_BUF_SIZE_CMD] = {0};
    size_t cmdHeaderBufLen                    = 0;
    uint8_t cmdDataBuf[NX_MAX_BUF_SIZE_CMD]   = {0};
    size_t cmdDataBufBufLen                   = 0;
    int tlvRet                                = 1;
    uint8_t *pCmdDataBuf                      = &cmdDataBuf[0];
    size_t rspIndex                           = 0;
    uint8_t rspbuf[NX_MAX_BUF_SIZE_RSP]       = {0};
    size_t rspbufLen                          = sizeof(rspbuf);
    nx_ev2_comm_mode_t commMode               = EV2_CommMode_PLAIN;
    void *options                             = &commMode;

    if (session_ctx == NULL) {
        goto cleanup;
    }

    retStatus = nx_get_comm_mode(session_ctx, session_ctx->userCryptoCommMode, NX_INS_CRYPTO_REQ, &commMode, NULL);
    ENSURE_OR_GO_CLEANUP(SM_OK == retStatus);

    retStatus = SM_NOT_OK; //reinitialized

#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "CryptoRequest RNG []");
#endif /* VERBOSE_APDU_LOGS */

    tlvRet = SET_U8("Action", &pCmdDataBuf, &cmdDataBufBufLen, Nx_CryptoAPI_Operation_RNG);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_U8("Num Bytes", &pCmdDataBuf, &cmdDataBufBufLen, rndLen);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_U8("Result Destination", &pCmdDataBuf, &cmdDataBufBufLen, resultDst);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    retStatus = DoAPDUTxRx_s_Case4(
        session_ctx, &hdr, cmdHeaderBuf, cmdHeaderBufLen, cmdDataBuf, cmdDataBufBufLen, rspbuf, &rspbufLen, options);

    if (retStatus == SM_OK) {
        retStatus = SM_NOT_OK;

        if (resultDst == kSE_CryptoDataSrc_CommandBuf) {
            if ((outputData == NULL) || (outputDataLen == NULL)) {
                goto cleanup;
            }

            if (rspbufLen < 2) {
                goto cleanup;
            }

            if (*outputDataLen < rspbufLen - 2) {
                goto cleanup;
            }

            tlvRet = get_u8buf(rspbuf, &rspIndex, rspbufLen, outputData, rspbufLen - 2);
            ENSURE_OR_GO_CLEANUP(0 == tlvRet);
            *outputDataLen = rspbufLen - 2;
        }
        else {
            if (rspbufLen != 2) {
                goto cleanup;
            }
        }

        retStatus = (rspbuf[rspbufLen - 2] << 8) | (rspbuf[rspbufLen - 1]);
        if (retStatus == SM_OK_ALT) {
            retStatus = SM_OK;
        }
    }

cleanup:
    return retStatus;
}

smStatus_t nx_CryptoRequest_ECCSign_Init(pSeSession_t session_ctx,
    uint8_t algorithm,
    uint8_t keyID,
    uint8_t inputSrc,
    uint8_t *inputData,
    size_t inputDataLen)
{
    smStatus_t retStatus                      = SM_NOT_OK;
    tlvHeader_t hdr                           = {{NX_CLA, NX_INS_CRYPTO_REQ, NX_P1_DEFAULT, NX_P2_DEFAULT}};
    uint8_t cmdHeaderBuf[NX_MAX_BUF_SIZE_CMD] = {0};
    size_t cmdHeaderBufLen                    = 0;
    uint8_t cmdDataBuf[NX_MAX_BUF_SIZE_CMD]   = {0};
    size_t cmdDataBufBufLen                   = 0;
    int tlvRet                                = 1;
    uint8_t *pCmdDataBuf                      = &cmdDataBuf[0];
    uint8_t rspbuf[NX_MAX_BUF_SIZE_RSP]       = {0};
    size_t rspbufLen                          = sizeof(rspbuf);
    nx_ev2_comm_mode_t commMode               = EV2_CommMode_PLAIN;
    void *options                             = &commMode;

    if (session_ctx == NULL) {
        goto cleanup;
    }

    retStatus = nx_get_comm_mode(session_ctx, session_ctx->userCryptoCommMode, NX_INS_CRYPTO_REQ, &commMode, NULL);
    ENSURE_OR_GO_CLEANUP(SM_OK == retStatus);

    retStatus = SM_NOT_OK; //reinitialized

#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "CryptoRequest_ECCSign [Init]");
#endif /* VERBOSE_APDU_LOGS */

    tlvRet = SET_U8("Action", &pCmdDataBuf, &cmdDataBufBufLen, Nx_CryptoAPI_Operation_ECCSign);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_U8("Operation", &pCmdDataBuf, &cmdDataBufBufLen, kSE_ECSignOperate_INIT);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_U8("Algorithm", &pCmdDataBuf, &cmdDataBufBufLen, algorithm);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_U8("Kep Pair Id", &pCmdDataBuf, &cmdDataBufBufLen, keyID);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_U8("Input Source", &pCmdDataBuf, &cmdDataBufBufLen, inputSrc);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    if (inputSrc != kSE_CryptoDataSrc_CommandBuf) {
        if (inputDataLen > UINT8_MAX) {
            retStatus = SM_NOT_OK;
            goto cleanup;
        }
        tlvRet = SET_U8("Input Data Length", &pCmdDataBuf, &cmdDataBufBufLen, (uint8_t)inputDataLen);
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);
    }
    else {
        if (inputData != NULL) {
            tlvRet = SET_u8buf("Input Data", &pCmdDataBuf, &cmdDataBufBufLen, inputData, inputDataLen);
            ENSURE_OR_GO_CLEANUP(0 == tlvRet);
        }
    }

    retStatus = DoAPDUTxRx_s_Case4(
        session_ctx, &hdr, cmdHeaderBuf, cmdHeaderBufLen, cmdDataBuf, cmdDataBufBufLen, rspbuf, &rspbufLen, options);

    if (retStatus == SM_OK) {
        retStatus = SM_NOT_OK;

        if (rspbufLen != 2) {
            goto cleanup;
        }

        retStatus = (rspbuf[rspbufLen - 2] << 8) | (rspbuf[rspbufLen - 1]);
        if (retStatus == SM_OK_ALT) {
            retStatus = SM_OK;
        }
    }

cleanup:
    return retStatus;
}

smStatus_t nx_CryptoRequest_ECCSign_Update(
    pSeSession_t session_ctx, uint8_t inputSrc, uint8_t *inputData, size_t inputDataLen)
{
    smStatus_t retStatus                      = SM_NOT_OK;
    tlvHeader_t hdr                           = {{NX_CLA, NX_INS_CRYPTO_REQ, NX_P1_DEFAULT, NX_P2_DEFAULT}};
    uint8_t cmdHeaderBuf[NX_MAX_BUF_SIZE_CMD] = {0};
    size_t cmdHeaderBufLen                    = 0;
    uint8_t cmdDataBuf[NX_MAX_BUF_SIZE_CMD]   = {0};
    size_t cmdDataBufBufLen                   = 0;
    int tlvRet                                = 1;
    uint8_t *pCmdDataBuf                      = &cmdDataBuf[0];
    uint8_t rspbuf[NX_MAX_BUF_SIZE_RSP]       = {0};
    size_t rspbufLen                          = sizeof(rspbuf);
    nx_ev2_comm_mode_t commMode               = EV2_CommMode_PLAIN;
    void *options                             = &commMode;

    if (session_ctx == NULL) {
        goto cleanup;
    }

    retStatus = nx_get_comm_mode(session_ctx, session_ctx->userCryptoCommMode, NX_INS_CRYPTO_REQ, &commMode, NULL);
    ENSURE_OR_GO_CLEANUP(SM_OK == retStatus);

    retStatus = SM_NOT_OK; //reinitialized

#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "CryptoRequest_ECCSign [Update]");
#endif /* VERBOSE_APDU_LOGS */

    tlvRet = SET_U8("Action", &pCmdDataBuf, &cmdDataBufBufLen, Nx_CryptoAPI_Operation_ECCSign);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_U8("Operation", &pCmdDataBuf, &cmdDataBufBufLen, kSE_ECSignOperate_UPDATE);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_U8("Input Source", &pCmdDataBuf, &cmdDataBufBufLen, inputSrc);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    if (inputSrc != kSE_CryptoDataSrc_CommandBuf) {
        if (inputDataLen > UINT8_MAX) {
            retStatus = SM_NOT_OK;
            goto cleanup;
        }
        tlvRet = SET_U8("Input Data Length", &pCmdDataBuf, &cmdDataBufBufLen, (uint8_t)inputDataLen);
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);
    }
    else {
        if (inputData != NULL) {
            tlvRet = SET_u8buf("Input Data", &pCmdDataBuf, &cmdDataBufBufLen, inputData, inputDataLen);
            ENSURE_OR_GO_CLEANUP(0 == tlvRet);
        }
    }

    retStatus = DoAPDUTxRx_s_Case4(
        session_ctx, &hdr, cmdHeaderBuf, cmdHeaderBufLen, cmdDataBuf, cmdDataBufBufLen, rspbuf, &rspbufLen, options);

    if (retStatus == SM_OK) {
        retStatus = SM_NOT_OK;

        if (rspbufLen != 2) {
            goto cleanup;
        }

        retStatus = (rspbuf[rspbufLen - 2] << 8) | (rspbuf[rspbufLen - 1]);
        if (retStatus == SM_OK_ALT) {
            retStatus = SM_OK;
        }
    }

cleanup:
    return retStatus;
}

smStatus_t nx_CryptoRequest_ECCSign_Final(pSeSession_t session_ctx,
    uint8_t inputSrc,
    uint8_t *inputData,
    size_t inputDataLen,
    uint8_t *outputSig,
    size_t *outputSigLen)
{
    smStatus_t retStatus                      = SM_NOT_OK;
    tlvHeader_t hdr                           = {{NX_CLA, NX_INS_CRYPTO_REQ, NX_P1_DEFAULT, NX_P2_DEFAULT}};
    uint8_t cmdHeaderBuf[NX_MAX_BUF_SIZE_CMD] = {0};
    size_t cmdHeaderBufLen                    = 0;
    uint8_t cmdDataBuf[NX_MAX_BUF_SIZE_CMD]   = {0};
    size_t cmdDataBufBufLen                   = 0;
    int tlvRet                                = 1;
    uint8_t *pCmdDataBuf                      = &cmdDataBuf[0];
    size_t rspIndex                           = 0;
    uint8_t rspbuf[NX_MAX_BUF_SIZE_RSP]       = {0};
    size_t rspbufLen                          = sizeof(rspbuf);
    nx_ev2_comm_mode_t commMode               = EV2_CommMode_PLAIN;
    void *options                             = &commMode;

    if (session_ctx == NULL) {
        goto cleanup;
    }

    retStatus = nx_get_comm_mode(session_ctx, session_ctx->userCryptoCommMode, NX_INS_CRYPTO_REQ, &commMode, NULL);
    ENSURE_OR_GO_CLEANUP(SM_OK == retStatus);

    retStatus = SM_NOT_OK; //reinitialized

#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "CryptoRequest_ECCSign [Final]");
#endif /* VERBOSE_APDU_LOGS */

    tlvRet = SET_U8("Action", &pCmdDataBuf, &cmdDataBufBufLen, Nx_CryptoAPI_Operation_ECCSign);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_U8("Operation", &pCmdDataBuf, &cmdDataBufBufLen, kSE_ECSignOperate_FINALIZE);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_U8("Input Source", &pCmdDataBuf, &cmdDataBufBufLen, inputSrc);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    if (inputSrc != kSE_CryptoDataSrc_CommandBuf) {
        if (inputDataLen > UINT8_MAX) {
            retStatus = SM_NOT_OK;
            goto cleanup;
        }
        tlvRet = SET_U8("Input Data Length", &pCmdDataBuf, &cmdDataBufBufLen, (uint8_t)inputDataLen);
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);
    }
    else {
        if (inputData != NULL) {
            tlvRet = SET_u8buf("Input Data", &pCmdDataBuf, &cmdDataBufBufLen, inputData, inputDataLen);
            ENSURE_OR_GO_CLEANUP(0 == tlvRet);
        }
    }

    retStatus = DoAPDUTxRx_s_Case4(
        session_ctx, &hdr, cmdHeaderBuf, cmdHeaderBufLen, cmdDataBuf, cmdDataBufBufLen, rspbuf, &rspbufLen, options);

    if (retStatus == SM_OK) {
        retStatus = SM_NOT_OK;

        if ((outputSig == NULL) || (outputSigLen == NULL)) {
            goto cleanup;
        }

        if (rspbufLen < 2) {
            goto cleanup;
        }

        if (*outputSigLen < rspbufLen - 2) {
            goto cleanup;
        }

        tlvRet = get_u8buf(rspbuf, &rspIndex, rspbufLen, outputSig, rspbufLen - 2);
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);
        *outputSigLen = rspbufLen - 2;

        retStatus = (rspbuf[rspbufLen - 2] << 8) | (rspbuf[rspbufLen - 1]);
        if (retStatus == SM_OK_ALT) {
            retStatus = SM_OK;
        }
    }

cleanup:
    return retStatus;
}

smStatus_t nx_CryptoRequest_ECCSign_Oneshot(pSeSession_t session_ctx,
    uint8_t algorithm,
    uint8_t keyID,
    uint8_t inputSrc,
    uint8_t *inputData,
    size_t inputDataLen,
    uint8_t *outputSig,
    size_t *outputSigLen)
{
    smStatus_t retStatus                      = SM_NOT_OK;
    tlvHeader_t hdr                           = {{NX_CLA, NX_INS_CRYPTO_REQ, NX_P1_DEFAULT, NX_P2_DEFAULT}};
    uint8_t cmdHeaderBuf[NX_MAX_BUF_SIZE_CMD] = {0};
    size_t cmdHeaderBufLen                    = 0;
    uint8_t cmdDataBuf[NX_MAX_BUF_SIZE_CMD]   = {0};
    size_t cmdDataBufBufLen                   = 0;
    int tlvRet                                = 1;
    uint8_t *pCmdDataBuf                      = &cmdDataBuf[0];
    size_t rspIndex                           = 0;
    uint8_t rspbuf[NX_MAX_BUF_SIZE_RSP]       = {0};
    size_t rspbufLen                          = sizeof(rspbuf);
    nx_ev2_comm_mode_t commMode               = EV2_CommMode_PLAIN;
    void *options                             = &commMode;

    if (session_ctx == NULL) {
        goto cleanup;
    }

    retStatus = nx_get_comm_mode(session_ctx, session_ctx->userCryptoCommMode, NX_INS_CRYPTO_REQ, &commMode, NULL);
    ENSURE_OR_GO_CLEANUP(SM_OK == retStatus);

    retStatus = SM_NOT_OK; //reinitialized

#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "CryptoRequest_ECCSign [Oneshot]");
#endif /* VERBOSE_APDU_LOGS */

    tlvRet = SET_U8("Action", &pCmdDataBuf, &cmdDataBufBufLen, Nx_CryptoAPI_Operation_ECCSign);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_U8("Operation", &pCmdDataBuf, &cmdDataBufBufLen, kSE_ECSignOperate_ONESHOT);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_U8("Algorithm", &pCmdDataBuf, &cmdDataBufBufLen, algorithm);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_U8("Kep Pair Id", &pCmdDataBuf, &cmdDataBufBufLen, keyID);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_U8("Input Source", &pCmdDataBuf, &cmdDataBufBufLen, inputSrc);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    if (inputSrc != kSE_CryptoDataSrc_CommandBuf) {
        if (inputDataLen > UINT8_MAX) {
            retStatus = SM_NOT_OK;
            goto cleanup;
        }
        tlvRet = SET_U8("Input Data Length", &pCmdDataBuf, &cmdDataBufBufLen, (uint8_t)inputDataLen);
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);
    }
    else {
        if (inputData != NULL) {
            tlvRet = SET_u8buf("Input Data", &pCmdDataBuf, &cmdDataBufBufLen, inputData, inputDataLen);
            ENSURE_OR_GO_CLEANUP(0 == tlvRet);
        }
    }

    retStatus = DoAPDUTxRx_s_Case4(
        session_ctx, &hdr, cmdHeaderBuf, cmdHeaderBufLen, cmdDataBuf, cmdDataBufBufLen, rspbuf, &rspbufLen, options);

    if (retStatus == SM_OK) {
        retStatus = SM_NOT_OK;

        if ((outputSig == NULL) || (outputSigLen == NULL)) {
            goto cleanup;
        }

        if (rspbufLen < 2) {
            goto cleanup;
        }

        if (*outputSigLen < rspbufLen - 2) {
            goto cleanup;
        }

        tlvRet = get_u8buf(rspbuf, &rspIndex, rspbufLen, outputSig, rspbufLen - 2);
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);
        *outputSigLen = rspbufLen - 2;

        retStatus = (rspbuf[rspbufLen - 2] << 8) | (rspbuf[rspbufLen - 1]);
        if (retStatus == SM_OK_ALT) {
            retStatus = SM_OK;
        }
    }

cleanup:
    return retStatus;
}

smStatus_t nx_CryptoRequest_ECCSign_Digest_Oneshot(pSeSession_t session_ctx,
    uint8_t algorithm,
    uint8_t keyID,
    uint8_t inputSrc,
    uint8_t *inputData,
    size_t inputDataLen,
    uint8_t *outputSig,
    size_t *outputSigLen)
{
    smStatus_t retStatus                      = SM_NOT_OK;
    tlvHeader_t hdr                           = {{NX_CLA, NX_INS_CRYPTO_REQ, NX_P1_DEFAULT, NX_P2_DEFAULT}};
    uint8_t cmdHeaderBuf[NX_MAX_BUF_SIZE_CMD] = {0};
    size_t cmdHeaderBufLen                    = 0;
    uint8_t cmdDataBuf[NX_MAX_BUF_SIZE_CMD]   = {0};
    size_t cmdDataBufBufLen                   = 0;
    int tlvRet                                = 1;
    uint8_t *pCmdDataBuf                      = &cmdDataBuf[0];
    size_t rspIndex                           = 0;
    uint8_t rspbuf[NX_MAX_BUF_SIZE_RSP]       = {0};
    size_t rspbufLen                          = sizeof(rspbuf);
    nx_ev2_comm_mode_t commMode               = EV2_CommMode_PLAIN;
    void *options                             = &commMode;

    if ((session_ctx == NULL) || (inputDataLen != 32)) {
        goto cleanup;
    }

    retStatus = nx_get_comm_mode(session_ctx, session_ctx->userCryptoCommMode, NX_INS_CRYPTO_REQ, &commMode, NULL);
    ENSURE_OR_GO_CLEANUP(SM_OK == retStatus);

    retStatus = SM_NOT_OK; //reinitialized

#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "CryptoRequest_ECCSign [Oneshot Sha256]");
#endif /* VERBOSE_APDU_LOGS */

    tlvRet = SET_U8("Action", &pCmdDataBuf, &cmdDataBufBufLen, Nx_CryptoAPI_Operation_ECCSign);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_U8("Operation", &pCmdDataBuf, &cmdDataBufBufLen, kSE_ECSignOperate_HASH_ONESHOT);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_U8("Algorithm", &pCmdDataBuf, &cmdDataBufBufLen, algorithm);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_U8("Kep Pair Id", &pCmdDataBuf, &cmdDataBufBufLen, keyID);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_U8("Input Source", &pCmdDataBuf, &cmdDataBufBufLen, inputSrc);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    if (inputSrc == kSE_CryptoDataSrc_CommandBuf) {
        if (inputData != NULL) {
            tlvRet = SET_u8buf("Input Data", &pCmdDataBuf, &cmdDataBufBufLen, inputData, inputDataLen);
            ENSURE_OR_GO_CLEANUP(0 == tlvRet);
        }
    }
    else {
        if (inputDataLen > UINT8_MAX) {
            retStatus = SM_NOT_OK;
            goto cleanup;
        }
        tlvRet = SET_U8("Input Data Length", &pCmdDataBuf, &cmdDataBufBufLen, (uint8_t)inputDataLen);
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);
    }

    retStatus = DoAPDUTxRx_s_Case4(
        session_ctx, &hdr, cmdHeaderBuf, cmdHeaderBufLen, cmdDataBuf, cmdDataBufBufLen, rspbuf, &rspbufLen, options);

    if (retStatus == SM_OK) {
        retStatus = SM_NOT_OK;

        if ((outputSig == NULL) || (outputSigLen == NULL)) {
            goto cleanup;
        }

        if (rspbufLen < 2) {
            goto cleanup;
        }

        if (*outputSigLen < rspbufLen - 2) {
            goto cleanup;
        }

        tlvRet = get_u8buf(rspbuf, &rspIndex, rspbufLen, outputSig, rspbufLen - 2);
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);
        *outputSigLen = rspbufLen - 2;

        retStatus = (rspbuf[rspbufLen - 2] << 8) | (rspbuf[rspbufLen - 1]);
        if (retStatus == SM_OK_ALT) {
            retStatus = SM_OK;
        }
    }

cleanup:
    return retStatus;
}

smStatus_t nx_CryptoRequest_ECCVerify_Init(pSeSession_t session_ctx,
    uint8_t algorithm,
    uint8_t curveID,
    uint8_t *hostPK,
    size_t hostPKLen,
    uint8_t inputSrc,
    uint8_t *inputData,
    size_t inputDataLen,
    uint16_t *result)
{
    smStatus_t retStatus                      = SM_NOT_OK;
    tlvHeader_t hdr                           = {{NX_CLA, NX_INS_CRYPTO_REQ, NX_P1_DEFAULT, NX_P2_DEFAULT}};
    uint8_t cmdHeaderBuf[NX_MAX_BUF_SIZE_CMD] = {0};
    size_t cmdHeaderBufLen                    = 0;
    uint8_t cmdDataBuf[NX_MAX_BUF_SIZE_CMD]   = {0};
    size_t cmdDataBufBufLen                   = 0;
    int tlvRet                                = 1;
    uint8_t *pCmdDataBuf                      = &cmdDataBuf[0];
    size_t rspIndex                           = 0;
    uint8_t rspbuf[NX_MAX_BUF_SIZE_RSP]       = {0};
    size_t rspbufLen                          = sizeof(rspbuf);
    nx_ev2_comm_mode_t commMode               = EV2_CommMode_PLAIN;
    void *options                             = &commMode;

    ENSURE_OR_GO_CLEANUP(NULL != session_ctx)
    ENSURE_OR_GO_CLEANUP(NULL != result)

    retStatus = nx_get_comm_mode(session_ctx, session_ctx->userCryptoCommMode, NX_INS_CRYPTO_REQ, &commMode, NULL);
    ENSURE_OR_GO_CLEANUP(SM_OK == retStatus);

    retStatus = SM_NOT_OK; //reinitialized

#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "CryptoRequest_ECCVerify [Init]");
#endif /* VERBOSE_APDU_LOGS */

    tlvRet = SET_U8("Action", &pCmdDataBuf, &cmdDataBufBufLen, Nx_CryptoAPI_Operation_ECCVerify);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_U8("Operation", &pCmdDataBuf, &cmdDataBufBufLen, kSE_ECSignOperate_INIT);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_U8("Algorithm", &pCmdDataBuf, &cmdDataBufBufLen, algorithm);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_U8("curveID", &pCmdDataBuf, &cmdDataBufBufLen, curveID);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    if ((hostPKLen == 0x41) && (hostPK != NULL)) {
        tlvRet = SET_u8buf("Host's Public Key", &pCmdDataBuf, &cmdDataBufBufLen, hostPK, hostPKLen);
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);
    }
    else {
        goto cleanup;
    }

    tlvRet = SET_U8("Input Source", &pCmdDataBuf, &cmdDataBufBufLen, inputSrc);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    if (inputSrc != kSE_CryptoDataSrc_CommandBuf) {
        if (inputDataLen > UINT8_MAX) {
            retStatus = SM_NOT_OK;
            goto cleanup;
        }
        tlvRet = SET_U8("Input Data Length", &pCmdDataBuf, &cmdDataBufBufLen, (uint8_t)inputDataLen);
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);
    }
    else {
        if (inputData != NULL) {
            tlvRet = SET_u8buf("Input Data", &pCmdDataBuf, &cmdDataBufBufLen, inputData, inputDataLen);
            ENSURE_OR_GO_CLEANUP(0 == tlvRet);
        }
    }

    retStatus = DoAPDUTxRx_s_Case4(
        session_ctx, &hdr, cmdHeaderBuf, cmdHeaderBufLen, cmdDataBuf, cmdDataBufBufLen, rspbuf, &rspbufLen, options);

    if (retStatus == SM_OK) {
        retStatus = SM_NOT_OK;

        if (rspbufLen < 2) {
            goto cleanup;
        }

        tlvRet = get_U16_LSB(rspbuf, &rspIndex, rspbufLen, result);
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);

        retStatus = (rspbuf[rspbufLen - 2] << 8) | (rspbuf[rspbufLen - 1]);
        if (retStatus == SM_OK_ALT) {
            retStatus = SM_OK;
        }
    }

cleanup:
    return retStatus;
}

smStatus_t nx_CryptoRequest_ECCVerify_Update(
    pSeSession_t session_ctx, uint8_t inputSrc, uint8_t *inputData, size_t inputDataLen, uint16_t *result)
{
    smStatus_t retStatus                      = SM_NOT_OK;
    tlvHeader_t hdr                           = {{NX_CLA, NX_INS_CRYPTO_REQ, NX_P1_DEFAULT, NX_P2_DEFAULT}};
    uint8_t cmdHeaderBuf[NX_MAX_BUF_SIZE_CMD] = {0};
    size_t cmdHeaderBufLen                    = 0;
    uint8_t cmdDataBuf[NX_MAX_BUF_SIZE_CMD]   = {0};
    size_t cmdDataBufBufLen                   = 0;
    int tlvRet                                = 1;
    uint8_t *pCmdDataBuf                      = &cmdDataBuf[0];
    size_t rspIndex                           = 0;
    uint8_t rspbuf[NX_MAX_BUF_SIZE_RSP]       = {0};
    size_t rspbufLen                          = sizeof(rspbuf);
    nx_ev2_comm_mode_t commMode               = EV2_CommMode_PLAIN;
    void *options                             = &commMode;

    ENSURE_OR_GO_CLEANUP(NULL != session_ctx)
    ENSURE_OR_GO_CLEANUP(NULL != result)

    retStatus = nx_get_comm_mode(session_ctx, session_ctx->userCryptoCommMode, NX_INS_CRYPTO_REQ, &commMode, NULL);
    ENSURE_OR_GO_CLEANUP(SM_OK == retStatus);

    retStatus = SM_NOT_OK; //reinitialized

#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "CryptoRequest_ECCVerify [Update]");
#endif /* VERBOSE_APDU_LOGS */

    tlvRet = SET_U8("Action", &pCmdDataBuf, &cmdDataBufBufLen, Nx_CryptoAPI_Operation_ECCVerify);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_U8("Operation", &pCmdDataBuf, &cmdDataBufBufLen, kSE_ECSignOperate_UPDATE);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_U8("Input Source", &pCmdDataBuf, &cmdDataBufBufLen, inputSrc);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    if (inputSrc != kSE_CryptoDataSrc_CommandBuf) {
        if (inputDataLen > UINT8_MAX) {
            retStatus = SM_NOT_OK;
            goto cleanup;
        }
        tlvRet = SET_U8("Input Data Length", &pCmdDataBuf, &cmdDataBufBufLen, (uint8_t)inputDataLen);
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);
    }
    else {
        if (inputData != NULL) {
            tlvRet = SET_u8buf("Input Data", &pCmdDataBuf, &cmdDataBufBufLen, inputData, inputDataLen);
            ENSURE_OR_GO_CLEANUP(0 == tlvRet);
        }
    }

    retStatus = DoAPDUTxRx_s_Case4(
        session_ctx, &hdr, cmdHeaderBuf, cmdHeaderBufLen, cmdDataBuf, cmdDataBufBufLen, rspbuf, &rspbufLen, options);

    if (retStatus == SM_OK) {
        retStatus = SM_NOT_OK;

        if (rspbufLen < 2) {
            goto cleanup;
        }

        tlvRet = get_U16_LSB(rspbuf, &rspIndex, rspbufLen, result);
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);

        retStatus = (rspbuf[rspbufLen - 2] << 8) | (rspbuf[rspbufLen - 1]);
        if (retStatus == SM_OK_ALT) {
            retStatus = SM_OK;
        }
    }

cleanup:
    return retStatus;
}

smStatus_t nx_CryptoRequest_ECCVerify_Final(pSeSession_t session_ctx,
    uint8_t *signature,
    size_t signatureLen,
    uint8_t inputSrc,
    uint8_t *inputData,
    size_t inputDataLen,
    uint16_t *result)
{
    smStatus_t retStatus                      = SM_NOT_OK;
    tlvHeader_t hdr                           = {{NX_CLA, NX_INS_CRYPTO_REQ, NX_P1_DEFAULT, NX_P2_DEFAULT}};
    uint8_t cmdHeaderBuf[NX_MAX_BUF_SIZE_CMD] = {0};
    size_t cmdHeaderBufLen                    = 0;
    uint8_t cmdDataBuf[NX_MAX_BUF_SIZE_CMD]   = {0};
    size_t cmdDataBufBufLen                   = 0;
    int tlvRet                                = 1;
    uint8_t *pCmdDataBuf                      = &cmdDataBuf[0];
    size_t rspIndex                           = 0;
    uint8_t rspbuf[NX_MAX_BUF_SIZE_RSP]       = {0};
    size_t rspbufLen                          = sizeof(rspbuf);
    nx_ev2_comm_mode_t commMode               = EV2_CommMode_PLAIN;
    void *options                             = &commMode;

    ENSURE_OR_GO_CLEANUP(NULL != session_ctx)
    ENSURE_OR_GO_CLEANUP(NULL != result)

    retStatus = nx_get_comm_mode(session_ctx, session_ctx->userCryptoCommMode, NX_INS_CRYPTO_REQ, &commMode, NULL);
    ENSURE_OR_GO_CLEANUP(SM_OK == retStatus);

    retStatus = SM_NOT_OK; //reinitialized

#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "CryptoRequest_ECCVerify [Finalize]");
#endif /* VERBOSE_APDU_LOGS */

    tlvRet = SET_U8("Action", &pCmdDataBuf, &cmdDataBufBufLen, Nx_CryptoAPI_Operation_ECCVerify);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_U8("Operation", &pCmdDataBuf, &cmdDataBufBufLen, kSE_ECSignOperate_FINALIZE);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    if ((signatureLen == 0x40) && (signature != NULL)) {
        tlvRet = SET_u8buf("Signature", &pCmdDataBuf, &cmdDataBufBufLen, signature, signatureLen);
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);
    }
    else {
        goto cleanup;
    }

    tlvRet = SET_U8("Input Source", &pCmdDataBuf, &cmdDataBufBufLen, inputSrc);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    if (inputSrc != kSE_CryptoDataSrc_CommandBuf) {
        if (inputDataLen > UINT8_MAX) {
            retStatus = SM_NOT_OK;
            goto cleanup;
        }
        tlvRet = SET_U8("Input Data Length", &pCmdDataBuf, &cmdDataBufBufLen, (uint8_t)inputDataLen);
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);
    }
    else {
        if (inputData != NULL) {
            tlvRet = SET_u8buf("Input Data", &pCmdDataBuf, &cmdDataBufBufLen, inputData, inputDataLen);
            ENSURE_OR_GO_CLEANUP(0 == tlvRet);
        }
    }

    retStatus = DoAPDUTxRx_s_Case4(
        session_ctx, &hdr, cmdHeaderBuf, cmdHeaderBufLen, cmdDataBuf, cmdDataBufBufLen, rspbuf, &rspbufLen, options);

    if (retStatus == SM_OK) {
        retStatus = SM_NOT_OK;

        if (rspbufLen < 2) {
            goto cleanup;
        }

        tlvRet = get_U16_LSB(rspbuf, &rspIndex, rspbufLen, result);
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);

        retStatus = (rspbuf[rspbufLen - 2] << 8) | (rspbuf[rspbufLen - 1]);
        if (retStatus == SM_OK_ALT) {
            retStatus = SM_OK;
        }
    }

cleanup:
    return retStatus;
}

smStatus_t nx_CryptoRequest_ECCVerify_Oneshot(pSeSession_t session_ctx,
    uint8_t algorithm,
    uint8_t curveID,
    uint8_t *hostPK,
    size_t hostPKLen,
    uint8_t *signature,
    size_t signatureLen,
    uint8_t inputSrc,
    uint8_t *inputData,
    size_t inputDataLen,
    uint16_t *result)
{
    smStatus_t retStatus                      = SM_NOT_OK;
    tlvHeader_t hdr                           = {{NX_CLA, NX_INS_CRYPTO_REQ, NX_P1_DEFAULT, NX_P2_DEFAULT}};
    uint8_t cmdHeaderBuf[NX_MAX_BUF_SIZE_CMD] = {0};
    size_t cmdHeaderBufLen                    = 0;
    uint8_t cmdDataBuf[NX_MAX_BUF_SIZE_CMD]   = {0};
    size_t cmdDataBufBufLen                   = 0;
    int tlvRet                                = 1;
    uint8_t *pCmdDataBuf                      = &cmdDataBuf[0];
    size_t rspIndex                           = 0;
    uint8_t rspbuf[NX_MAX_BUF_SIZE_RSP]       = {0};
    size_t rspbufLen                          = sizeof(rspbuf);
    nx_ev2_comm_mode_t commMode               = EV2_CommMode_PLAIN;
    void *options                             = &commMode;

    ENSURE_OR_GO_CLEANUP(NULL != session_ctx)
    ENSURE_OR_GO_CLEANUP(NULL != result)

    retStatus = nx_get_comm_mode(session_ctx, session_ctx->userCryptoCommMode, NX_INS_CRYPTO_REQ, &commMode, NULL);
    ENSURE_OR_GO_CLEANUP(SM_OK == retStatus);

    retStatus = SM_NOT_OK; //reinitialized

#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "CryptoRequest_ECCVerify []");
#endif /* VERBOSE_APDU_LOGS */

    tlvRet = SET_U8("Action", &pCmdDataBuf, &cmdDataBufBufLen, Nx_CryptoAPI_Operation_ECCVerify);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_U8("Operation", &pCmdDataBuf, &cmdDataBufBufLen, kSE_ECSignOperate_ONESHOT);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_U8("Algorithm", &pCmdDataBuf, &cmdDataBufBufLen, algorithm);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_U8("curveID", &pCmdDataBuf, &cmdDataBufBufLen, curveID);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    if ((hostPKLen == 0x41) && (hostPK != NULL)) {
        tlvRet = SET_u8buf("Host's Public Key", &pCmdDataBuf, &cmdDataBufBufLen, hostPK, hostPKLen);
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);
    }
    else {
        goto cleanup;
    }

    if ((signatureLen == 0x40) && (signature != NULL)) {
        tlvRet = SET_u8buf("Signature", &pCmdDataBuf, &cmdDataBufBufLen, signature, signatureLen);
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);
    }
    else {
        goto cleanup;
    }

    tlvRet = SET_U8("Input Source", &pCmdDataBuf, &cmdDataBufBufLen, inputSrc);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    if (inputSrc != kSE_CryptoDataSrc_CommandBuf) {
        if (inputDataLen > UINT8_MAX) {
            retStatus = SM_NOT_OK;
            goto cleanup;
        }
        tlvRet = SET_U8("Input Data Length", &pCmdDataBuf, &cmdDataBufBufLen, (uint8_t)inputDataLen);
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);
    }
    else {
        if (inputData != NULL) {
            tlvRet = SET_u8buf("Input Data", &pCmdDataBuf, &cmdDataBufBufLen, inputData, inputDataLen);
            ENSURE_OR_GO_CLEANUP(0 == tlvRet);
        }
    }

    retStatus = DoAPDUTxRx_s_Case4(
        session_ctx, &hdr, cmdHeaderBuf, cmdHeaderBufLen, cmdDataBuf, cmdDataBufBufLen, rspbuf, &rspbufLen, options);

    if (retStatus == SM_OK) {
        retStatus = SM_NOT_OK;

        if (rspbufLen < 2) {
            goto cleanup;
        }

        tlvRet = get_U16_LSB(rspbuf, &rspIndex, rspbufLen, result);
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);

        retStatus = (rspbuf[rspbufLen - 2] << 8) | (rspbuf[rspbufLen - 1]);
        if (retStatus == SM_OK_ALT) {
            retStatus = SM_OK;
        }
    }

cleanup:
    return retStatus;
}

smStatus_t nx_CryptoRequest_ECCVerify_Digest_Oneshot(pSeSession_t session_ctx,
    uint8_t algorithm,
    uint8_t curveID,
    uint8_t *hostPK,
    size_t hostPKLen,
    uint8_t *signature,
    size_t signatureLen,
    uint8_t inputSrc,
    uint8_t *inputData,
    size_t inputDataLen,
    uint16_t *result)
{
    smStatus_t retStatus                      = SM_NOT_OK;
    tlvHeader_t hdr                           = {{NX_CLA, NX_INS_CRYPTO_REQ, NX_P1_DEFAULT, NX_P2_DEFAULT}};
    uint8_t cmdHeaderBuf[NX_MAX_BUF_SIZE_CMD] = {0};
    size_t cmdHeaderBufLen                    = 0;
    uint8_t cmdDataBuf[NX_MAX_BUF_SIZE_CMD]   = {0};
    size_t cmdDataBufBufLen                   = 0;
    int tlvRet                                = 1;
    uint8_t *pCmdDataBuf                      = &cmdDataBuf[0];
    size_t rspIndex                           = 0;
    uint8_t rspbuf[NX_MAX_BUF_SIZE_RSP]       = {0};
    size_t rspbufLen                          = sizeof(rspbuf);
    nx_ev2_comm_mode_t commMode               = EV2_CommMode_PLAIN;
    void *options                             = &commMode;

    ENSURE_OR_GO_CLEANUP(NULL != session_ctx)
    ENSURE_OR_GO_CLEANUP(NULL != result)

    retStatus = nx_get_comm_mode(session_ctx, session_ctx->userCryptoCommMode, NX_INS_CRYPTO_REQ, &commMode, NULL);
    ENSURE_OR_GO_CLEANUP(SM_OK == retStatus);

    retStatus = SM_NOT_OK; //reinitialized

#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "CryptoRequest_ECCVerify []");
#endif /* VERBOSE_APDU_LOGS */

    tlvRet = SET_U8("Action", &pCmdDataBuf, &cmdDataBufBufLen, Nx_CryptoAPI_Operation_ECCVerify);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_U8("Operation", &pCmdDataBuf, &cmdDataBufBufLen, kSE_ECSignOperate_HASH_ONESHOT);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_U8("Algorithm", &pCmdDataBuf, &cmdDataBufBufLen, algorithm);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_U8("curveID", &pCmdDataBuf, &cmdDataBufBufLen, curveID);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    if ((hostPKLen == 0x41) && (hostPK != NULL)) {
        tlvRet = SET_u8buf("Host's Public Key", &pCmdDataBuf, &cmdDataBufBufLen, hostPK, hostPKLen);
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);
    }
    else {
        goto cleanup;
    }

    if ((signatureLen == 0x40) && (signature != NULL)) {
        tlvRet = SET_u8buf("Signature", &pCmdDataBuf, &cmdDataBufBufLen, signature, signatureLen);
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);
    }
    else {
        goto cleanup;
    }

    tlvRet = SET_U8("Input Source", &pCmdDataBuf, &cmdDataBufBufLen, inputSrc);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    if (inputDataLen == 32) {
        if (inputSrc != kSE_CryptoDataSrc_CommandBuf) {
            tlvRet = SET_U8("Input Data Length", &pCmdDataBuf, &cmdDataBufBufLen, (uint8_t)inputDataLen);
            ENSURE_OR_GO_CLEANUP(0 == tlvRet);
        }
        else {
            if (inputData != NULL) {
                tlvRet = SET_u8buf("Input Data", &pCmdDataBuf, &cmdDataBufBufLen, inputData, inputDataLen);
                ENSURE_OR_GO_CLEANUP(0 == tlvRet);
            }
            else {
                goto cleanup;
            }
        }
    }
    else {
        goto cleanup;
    }

    retStatus = DoAPDUTxRx_s_Case4(
        session_ctx, &hdr, cmdHeaderBuf, cmdHeaderBufLen, cmdDataBuf, cmdDataBufBufLen, rspbuf, &rspbufLen, options);

    if (retStatus == SM_OK) {
        retStatus = SM_NOT_OK;

        if (rspbufLen < 2) {
            goto cleanup;
        }

        tlvRet = get_U16_LSB(rspbuf, &rspIndex, rspbufLen, result);
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);

        retStatus = (rspbuf[rspbufLen - 2] << 8) | (rspbuf[rspbufLen - 1]);
        if (retStatus == SM_OK_ALT) {
            retStatus = SM_OK;
        }
    }

cleanup:
    return retStatus;
}

smStatus_t nx_CryptoRequest_ECDH_Oneshot(pSeSession_t session_ctx,
    uint8_t keyID,
    uint8_t sharedSecretDst,
    const uint8_t *hostPK,
    size_t hostPKLen,
    uint8_t *shareSecret,
    size_t *shareSecretLen,
    uint8_t *pubKey,
    size_t *pPubKeyLen)
{
    smStatus_t retStatus                      = SM_NOT_OK;
    tlvHeader_t hdr                           = {{NX_CLA, NX_INS_CRYPTO_REQ, NX_P1_DEFAULT, NX_P2_DEFAULT}};
    uint8_t cmdHeaderBuf[NX_MAX_BUF_SIZE_CMD] = {0};
    size_t cmdHeaderBufLen                    = 0;
    uint8_t cmdDataBuf[NX_MAX_BUF_SIZE_CMD]   = {0};
    size_t cmdDataBufBufLen                   = 0;
    int tlvRet                                = 1;
    uint8_t option                            = Nx_ECDHOption_SingleStep;
    uint8_t *pCmdDataBuf                      = &cmdDataBuf[0];
    size_t rspIndex                           = 0;
    uint8_t rspbuf[NX_MAX_BUF_SIZE_RSP]       = {0};
    size_t rspbufLen                          = sizeof(rspbuf);
    nx_ev2_comm_mode_t commMode               = EV2_CommMode_PLAIN;
    void *options                             = &commMode;
    size_t pubKeyLen                          = 0;

    if (session_ctx == NULL) {
        goto cleanup;
    }

    retStatus = nx_get_comm_mode(session_ctx, session_ctx->userCryptoCommMode, NX_INS_CRYPTO_REQ, &commMode, NULL);
    ENSURE_OR_GO_CLEANUP(SM_OK == retStatus);

    retStatus = SM_NOT_OK; //reinitialized

#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "CryptoRequest_ECDH []");
#endif /* VERBOSE_APDU_LOGS */

    tlvRet = SET_U8("Action", &pCmdDataBuf, &cmdDataBufBufLen, Nx_CryptoAPI_Operation_ECDH);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_U8("Option", &pCmdDataBuf, &cmdDataBufBufLen, option);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_U8("Kep Pair Id", &pCmdDataBuf, &cmdDataBufBufLen, keyID);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_U8("Shared secret Destination", &pCmdDataBuf, &cmdDataBufBufLen, sharedSecretDst);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    if ((hostPKLen == 0x41) && (hostPK != NULL)) {
        tlvRet = SET_u8buf("Host's Public Key", &pCmdDataBuf, &cmdDataBufBufLen, hostPK, hostPKLen);
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);
    }

    retStatus = DoAPDUTxRx_s_Case4(
        session_ctx, &hdr, cmdHeaderBuf, cmdHeaderBufLen, cmdDataBuf, cmdDataBufBufLen, rspbuf, &rspbufLen, options);

    if (retStatus == SM_OK) {
        retStatus = SM_NOT_OK;

        if ((keyID == NX_KEY_ID_EPHEM_NISTP256) || (keyID == NX_KEY_ID_EPHEM_BP256)) {
            if (pubKey != NULL && pPubKeyLen != NULL) {
                if ((rspbufLen < (NX_PUBLIC_KEY_LENGTH + 2)) || (*pPubKeyLen < NX_PUBLIC_KEY_LENGTH)) {
                    goto cleanup;
                }

                tlvRet = get_u8buf(rspbuf, &rspIndex, rspbufLen, pubKey, NX_PUBLIC_KEY_LENGTH);
                ENSURE_OR_GO_CLEANUP(0 == tlvRet);
            }
            pubKeyLen = NX_PUBLIC_KEY_LENGTH;
        }
        else {
            // No public key included if key id is not ephermal.
            pubKeyLen = 0;
        }
        if (pubKey != NULL && pPubKeyLen != NULL) {
            *pPubKeyLen = pubKeyLen;
        }

        if (sharedSecretDst == kSE_CryptoDataSrc_CommandBuf) {
            if ((shareSecret != NULL) && (shareSecretLen != NULL) && (*shareSecretLen >= NX_SHARED_SECRET_LENGTH) &&
                (rspbufLen == (pubKeyLen + NX_SHARED_SECRET_LENGTH + 2))) {
                tlvRet = get_u8buf(rspbuf, &rspIndex, rspbufLen, shareSecret, NX_SHARED_SECRET_LENGTH);
                ENSURE_OR_GO_CLEANUP(0 == tlvRet);
                *shareSecretLen = NX_SHARED_SECRET_LENGTH;
            }
            else {
                goto cleanup;
            }
        }

        retStatus = (rspbuf[rspbufLen - 2] << 8) | (rspbuf[rspbufLen - 1]);
        if (retStatus == SM_OK_ALT) {
            retStatus = SM_OK;
        }
    }

cleanup:
    return retStatus;
}

smStatus_t nx_CryptoRequest_ECDH_TwoStepPart1(
    pSeSession_t session_ctx, uint8_t keyID, uint8_t *pubKey, size_t *pubKeyLen)
{
    smStatus_t retStatus                      = SM_NOT_OK;
    tlvHeader_t hdr                           = {{NX_CLA, NX_INS_CRYPTO_REQ, NX_P1_DEFAULT, NX_P2_DEFAULT}};
    uint8_t cmdHeaderBuf[NX_MAX_BUF_SIZE_CMD] = {0};
    size_t cmdHeaderBufLen                    = 0;
    uint8_t cmdDataBuf[NX_MAX_BUF_SIZE_CMD]   = {0};
    size_t cmdDataBufBufLen                   = 0;
    int tlvRet                                = 1;
    uint8_t option                            = Nx_ECDHOption_TwoStep_1;
    uint8_t *pCmdDataBuf                      = &cmdDataBuf[0];
    size_t rspIndex                           = 0;
    uint8_t rspbuf[NX_MAX_BUF_SIZE_RSP]       = {0};
    size_t rspbufLen                          = sizeof(rspbuf);
    nx_ev2_comm_mode_t commMode               = EV2_CommMode_PLAIN;
    void *options                             = &commMode;

    ENSURE_OR_GO_CLEANUP(NULL != session_ctx)
    ENSURE_OR_GO_CLEANUP(NULL != pubKey)
    ENSURE_OR_GO_CLEANUP(NULL != pubKeyLen)

    retStatus = nx_get_comm_mode(session_ctx, session_ctx->userCryptoCommMode, NX_INS_CRYPTO_REQ, &commMode, NULL);
    ENSURE_OR_GO_CLEANUP(SM_OK == retStatus);

    retStatus = SM_NOT_OK; //reinitialized

#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "CryptoRequest_ECDH [Step1]");
#endif /* VERBOSE_APDU_LOGS */

    tlvRet = SET_U8("Action", &pCmdDataBuf, &cmdDataBufBufLen, Nx_CryptoAPI_Operation_ECDH);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_U8("Option", &pCmdDataBuf, &cmdDataBufBufLen, option);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_U8("Kep Pair Id", &pCmdDataBuf, &cmdDataBufBufLen, keyID);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    retStatus = DoAPDUTxRx_s_Case4(
        session_ctx, &hdr, cmdHeaderBuf, cmdHeaderBufLen, cmdDataBuf, cmdDataBufBufLen, rspbuf, &rspbufLen, options);

    if (retStatus == SM_OK) {
        retStatus = SM_NOT_OK;

        if ((rspbufLen != (NX_PUBLIC_KEY_LENGTH + 2)) || (*pubKeyLen < NX_PUBLIC_KEY_LENGTH)) {
            goto cleanup;
        }

        tlvRet = get_u8buf(rspbuf, &rspIndex, rspbufLen, pubKey, NX_PUBLIC_KEY_LENGTH);
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);
        *pubKeyLen = NX_PUBLIC_KEY_LENGTH;

        retStatus = (rspbuf[rspbufLen - 2] << 8) | (rspbuf[rspbufLen - 1]);
        if (retStatus == SM_OK_ALT) {
            retStatus = SM_OK;
        }
    }

cleanup:
    return retStatus;
}

smStatus_t nx_CryptoRequest_ECDH_TwoStepPart2(pSeSession_t session_ctx,
    uint8_t keyID,
    uint8_t sharedSecretDst,
    uint8_t *hostPK,
    size_t hostPKLen,
    uint8_t *shareSecret,
    size_t *shareSecretLen)
{
    smStatus_t retStatus                      = SM_NOT_OK;
    tlvHeader_t hdr                           = {{NX_CLA, NX_INS_CRYPTO_REQ, NX_P1_DEFAULT, NX_P2_DEFAULT}};
    uint8_t cmdHeaderBuf[NX_MAX_BUF_SIZE_CMD] = {0};
    size_t cmdHeaderBufLen                    = 0;
    uint8_t cmdDataBuf[NX_MAX_BUF_SIZE_CMD]   = {0};
    size_t cmdDataBufBufLen                   = 0;
    int tlvRet                                = 1;
    uint8_t option                            = Nx_ECDHOption_TwoStep_2;
    uint8_t *pCmdDataBuf                      = &cmdDataBuf[0];
    size_t rspIndex                           = 0;
    uint8_t rspbuf[NX_MAX_BUF_SIZE_RSP]       = {0};
    size_t rspbufLen                          = sizeof(rspbuf);
    nx_ev2_comm_mode_t commMode               = EV2_CommMode_PLAIN;
    void *options                             = &commMode;

    ENSURE_OR_GO_CLEANUP(NULL != session_ctx)

    retStatus = nx_get_comm_mode(session_ctx, session_ctx->userCryptoCommMode, NX_INS_CRYPTO_REQ, &commMode, NULL);
    ENSURE_OR_GO_CLEANUP(SM_OK == retStatus);

    retStatus = SM_NOT_OK; //reinitialized

#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "CryptoRequest_ECDH [Step2]");
#endif /* VERBOSE_APDU_LOGS */

    tlvRet = SET_U8("Action", &pCmdDataBuf, &cmdDataBufBufLen, Nx_CryptoAPI_Operation_ECDH);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_U8("Option", &pCmdDataBuf, &cmdDataBufBufLen, option);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_U8("Kep Pair Id", &pCmdDataBuf, &cmdDataBufBufLen, keyID);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_U8("Shared secret Destination", &pCmdDataBuf, &cmdDataBufBufLen, sharedSecretDst);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    if ((hostPKLen == 0x41) && (hostPK != NULL)) {
        tlvRet = SET_u8buf("Host's Public Key", &pCmdDataBuf, &cmdDataBufBufLen, hostPK, hostPKLen);
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);
    }

    retStatus = DoAPDUTxRx_s_Case4(
        session_ctx, &hdr, cmdHeaderBuf, cmdHeaderBufLen, cmdDataBuf, cmdDataBufBufLen, rspbuf, &rspbufLen, options);

    if (retStatus == SM_OK) {
        retStatus = SM_NOT_OK;

        if (rspbufLen < 2) {
            goto cleanup;
        }

        if (sharedSecretDst == kSE_CryptoDataSrc_CommandBuf) {
            ENSURE_OR_GO_CLEANUP(NULL != shareSecret)
            ENSURE_OR_GO_CLEANUP(NULL != shareSecretLen)
            if ((*shareSecretLen >= NX_SHARED_SECRET_LENGTH) && (rspbufLen == (NX_SHARED_SECRET_LENGTH + 2))) {
                tlvRet = get_u8buf(rspbuf, &rspIndex, rspbufLen, shareSecret, NX_SHARED_SECRET_LENGTH);
                ENSURE_OR_GO_CLEANUP(0 == tlvRet);
                *shareSecretLen = NX_SHARED_SECRET_LENGTH;
            }
            else {
                goto cleanup;
            }
        }

        retStatus = (rspbuf[rspbufLen - 2] << 8) | (rspbuf[rspbufLen - 1]);
        if (retStatus == SM_OK_ALT) {
            retStatus = SM_OK;
        }
    }

cleanup:
    return retStatus;
}

smStatus_t nx_CryptoRequest_AES_CMAC_Sign(pSeSession_t session_ctx,
    Nx_MAC_Operation_t operation,
    uint8_t keyID,
    uint8_t keyLen,
    uint8_t inputDataSrc,
    const uint8_t *inputData,
    size_t inputDataLen,
    uint8_t *dstData,
    size_t *dstDataLen)
{
    smStatus_t retStatus                      = SM_NOT_OK;
    tlvHeader_t hdr                           = {{NX_CLA, NX_INS_CRYPTO_REQ, NX_P1_DEFAULT, NX_P2_DEFAULT}};
    uint8_t cmdHeaderBuf[NX_MAX_BUF_SIZE_CMD] = {0};
    size_t cmdHeaderBufLen                    = 0;
    uint8_t cmdDataBuf[NX_MAX_BUF_SIZE_CMD]   = {0};
    size_t cmdDataBufBufLen                   = 0;
    int tlvRet                                = 1;
    uint8_t *pCmdDataBuf                      = &cmdDataBuf[0];
    uint8_t rspbuf[NX_MAX_BUF_SIZE_RSP]       = {0};
    size_t rspbufLen                          = sizeof(rspbuf);
    size_t rspIndex                           = 0;
    nx_ev2_comm_mode_t commMode               = EV2_CommMode_PLAIN;
    void *options                             = &commMode;

    if ((session_ctx == NULL) || (operation == Nx_MAC_Operation_NA)) {
        goto cleanup;
    }

    if ((keyID < NX_KEY_MGMT_MIN_CRYPTO_KEY_NUMBER) ||
        ((keyID > NX_KEY_MGMT_MAX_CRYPTO_KEY_NUMBER) && (keyID < kSE_CryptoAESKey_TB_SLOTNUM_MIN)) ||
        ((keyID > kSE_CryptoAESKey_TB_SLOTNUM_MAX) && (keyID < kSE_CryptoAESKey_SB_SLOTNUM_MIN)) ||
        (keyID > kSE_CryptoAESKey_SB_SLOTNUM_MAX)) {
        LOG_E("Invalid crypto AESKEY IDs");
        goto cleanup;
    }

    retStatus = nx_get_comm_mode(session_ctx, session_ctx->userCryptoCommMode, NX_INS_CRYPTO_REQ, &commMode, NULL);
    ENSURE_OR_GO_CLEANUP(SM_OK == retStatus);

    retStatus = SM_NOT_OK; //reinitialized

#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "CryptoRequest_AES_CMAC_Sign [%x]", operation);
#endif /* VERBOSE_APDU_LOGS */

    tlvRet = SET_U8("Action", &pCmdDataBuf, &cmdDataBufBufLen, Nx_CryptoAPI_Operation_AES_CMAC_Sign);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_U8("operation", &pCmdDataBuf, &cmdDataBufBufLen, operation);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    if ((operation == Nx_MAC_Operation_Initialize) || (operation == Nx_MAC_Operation_OneShot)) {
        tlvRet = SET_U8("aesPrimitive", &pCmdDataBuf, &cmdDataBufBufLen, Nx_MAC_Primitive_Sign);
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);

        tlvRet = SET_U8("Key ID", &pCmdDataBuf, &cmdDataBufBufLen, keyID);
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);

        if (keyID > NX_KEY_MGMT_MAX_CRYPTO_KEY_NUMBER) {
            tlvRet = SET_U8("Key length", &pCmdDataBuf, &cmdDataBufBufLen, keyLen);
            ENSURE_OR_GO_CLEANUP(0 == tlvRet);
        }
    }

    tlvRet = SET_U8("Input Data Source", &pCmdDataBuf, &cmdDataBufBufLen, inputDataSrc);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    if (inputDataSrc != kSE_CryptoDataSrc_CommandBuf) {
        if (inputDataLen > UINT8_MAX) {
            retStatus = SM_NOT_OK;
            goto cleanup;
        }
        tlvRet = SET_U8("Input Data Length", &pCmdDataBuf, &cmdDataBufBufLen, (uint8_t)inputDataLen);
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);
    }
    else if (inputData != NULL) {
        tlvRet = SET_u8buf("Input Data", &pCmdDataBuf, &cmdDataBufBufLen, inputData, inputDataLen);
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);
    }

    retStatus = DoAPDUTxRx_s_Case4(
        session_ctx, &hdr, cmdHeaderBuf, cmdHeaderBufLen, cmdDataBuf, cmdDataBufBufLen, rspbuf, &rspbufLen, options);

    if (retStatus == SM_OK) {
        retStatus = SM_NOT_OK;

        if (operation == Nx_MAC_Operation_Finish || operation == Nx_MAC_Operation_OneShot) {
            if ((dstData == NULL) || (dstDataLen == NULL)) {
                goto cleanup;
            }

            if (rspbufLen < 2) {
                goto cleanup;
            }
            else if (rspbufLen > 2) {
                if (*dstDataLen >= rspbufLen - 2) {
                    tlvRet = get_u8buf(rspbuf, &rspIndex, rspbufLen, dstData, rspbufLen - 2);
                    ENSURE_OR_GO_CLEANUP(0 == tlvRet);
                    *dstDataLen = rspbufLen - 2;
                }
                else {
                    LOG_E("Not enough output data buffer!");
                    goto cleanup;
                }
            }
            else { // (rspbufLen == 2)
                *dstDataLen = 0;
            }
        }
        else {
            if (rspbufLen != 2) {
                goto cleanup;
            }
        }

        retStatus = (rspbuf[rspbufLen - 2] << 8) | (rspbuf[rspbufLen - 1]);
        if (retStatus == SM_OK_ALT) {
            retStatus = SM_OK;
        }
    }

cleanup:
    return retStatus;
}

smStatus_t nx_CryptoRequest_AES_CMAC_Verify(pSeSession_t session_ctx,
    Nx_MAC_Operation_t operation,
    uint8_t keyID,
    uint8_t keyLen,
    uint8_t inputDataSrc,
    const uint8_t *inputData,
    size_t inputDataLen,
    uint8_t *cmac_data,
    size_t cmac_Len,
    uint16_t *verifyResult)
{
    smStatus_t retStatus                      = SM_NOT_OK;
    tlvHeader_t hdr                           = {{NX_CLA, NX_INS_CRYPTO_REQ, NX_P1_DEFAULT, NX_P2_DEFAULT}};
    uint8_t cmdHeaderBuf[NX_MAX_BUF_SIZE_CMD] = {0};
    size_t cmdHeaderBufLen                    = 0;
    uint8_t cmdDataBuf[NX_MAX_BUF_SIZE_CMD]   = {0};
    size_t cmdDataBufBufLen                   = 0;
    int tlvRet                                = 1;
    uint8_t *pCmdDataBuf                      = &cmdDataBuf[0];
    uint8_t rspbuf[NX_MAX_BUF_SIZE_RSP]       = {0};
    size_t rspbufLen                          = sizeof(rspbuf);
    size_t rspIndex                           = 0;
    nx_ev2_comm_mode_t commMode               = EV2_CommMode_PLAIN;
    void *options                             = &commMode;

    if ((session_ctx == NULL) || (operation == Nx_MAC_Operation_NA)) {
        goto cleanup;
    }

    if ((keyID < NX_KEY_MGMT_MIN_CRYPTO_KEY_NUMBER) ||
        ((keyID > NX_KEY_MGMT_MAX_CRYPTO_KEY_NUMBER) && (keyID < kSE_CryptoAESKey_TB_SLOTNUM_MIN)) ||
        ((keyID > kSE_CryptoAESKey_TB_SLOTNUM_MAX) && (keyID < kSE_CryptoAESKey_SB_SLOTNUM_MIN)) ||
        (keyID > kSE_CryptoAESKey_SB_SLOTNUM_MAX)) {
        LOG_E("Invalid crypto AESKEY IDs");
        goto cleanup;
    }

    retStatus = nx_get_comm_mode(session_ctx, session_ctx->userCryptoCommMode, NX_INS_CRYPTO_REQ, &commMode, NULL);
    ENSURE_OR_GO_CLEANUP(SM_OK == retStatus);

    retStatus = SM_NOT_OK; //reinitialized

#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "CryptoRequest_AES_CMAC_Verify [%x]", operation);
#endif /* VERBOSE_APDU_LOGS */

    tlvRet = SET_U8("Action", &pCmdDataBuf, &cmdDataBufBufLen, Nx_CryptoAPI_Operation_AES_CMAC_Verify);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_U8("operation", &pCmdDataBuf, &cmdDataBufBufLen, operation);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    if ((operation == Nx_MAC_Operation_Initialize) || (operation == Nx_MAC_Operation_OneShot)) {
        tlvRet = SET_U8("aesPrimitive", &pCmdDataBuf, &cmdDataBufBufLen, Nx_MAC_Primitive_Verify);
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);

        tlvRet = SET_U8("Key ID", &pCmdDataBuf, &cmdDataBufBufLen, keyID);
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);

        if (keyID > NX_KEY_MGMT_MAX_CRYPTO_KEY_NUMBER) {
            tlvRet = SET_U8("Key length", &pCmdDataBuf, &cmdDataBufBufLen, keyLen);
            ENSURE_OR_GO_CLEANUP(0 == tlvRet);
        }
    }

    if (operation == Nx_MAC_Operation_Finish || operation == Nx_MAC_Operation_OneShot) {
        if (((cmac_Len != 8) && (cmac_Len != 16)) || (cmac_data == NULL)) {
            retStatus = SM_NOT_OK;
            goto cleanup;
        }

        tlvRet = SET_U8("CMAC Data Length", &pCmdDataBuf, &cmdDataBufBufLen, (uint8_t)cmac_Len);
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);

        tlvRet = SET_u8buf("CMAC Data Length", &pCmdDataBuf, &cmdDataBufBufLen, cmac_data, cmac_Len);
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);
    }

    tlvRet = SET_U8("Input Data Source", &pCmdDataBuf, &cmdDataBufBufLen, inputDataSrc);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    if (inputDataSrc != kSE_CryptoDataSrc_CommandBuf) {
        if (inputDataLen > UINT8_MAX) {
            retStatus = SM_NOT_OK;
            goto cleanup;
        }
        tlvRet = SET_U8("Input Data Length", &pCmdDataBuf, &cmdDataBufBufLen, (uint8_t)inputDataLen);
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);
    }
    else if (inputData != NULL) {
        tlvRet = SET_u8buf("Input Data", &pCmdDataBuf, &cmdDataBufBufLen, inputData, inputDataLen);
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);
    }

    retStatus = DoAPDUTxRx_s_Case4(
        session_ctx, &hdr, cmdHeaderBuf, cmdHeaderBufLen, cmdDataBuf, cmdDataBufBufLen, rspbuf, &rspbufLen, options);

    if (retStatus == SM_OK) {
        retStatus = SM_NOT_OK;

        if (operation == Nx_MAC_Operation_Finish || operation == Nx_MAC_Operation_OneShot) {
            if (rspbufLen != 4) {
                goto cleanup;
            }

            if (verifyResult == NULL) {
                LOG_E("Invalid Parameter For Verify Result");
                goto cleanup;
            }

            tlvRet = get_U16_LSB(rspbuf, &rspIndex, rspbufLen, verifyResult);
            ENSURE_OR_GO_CLEANUP(0 == tlvRet);
        }
        else {
            if (rspbufLen != 2) {
                goto cleanup;
            }
        }

        retStatus = (rspbuf[rspbufLen - 2] << 8) | (rspbuf[rspbufLen - 1]);
        if (retStatus == SM_OK_ALT) {
            retStatus = SM_OK;
        }
    }

cleanup:
    return retStatus;
}

smStatus_t nx_CryptoRequest_AES_CBC_ECB_Init(pSeSession_t session_ctx,
    Nx_AES_Primitive_t aesPrimitive,
    uint8_t keyID,
    uint8_t keyLen,
    uint8_t icvSrc,
    const uint8_t *icvData,
    size_t icvDataLen,
    uint8_t inputDataSrc,
    const uint8_t *inputData,
    size_t inputDataLen,
    uint8_t *outputData,
    size_t *outputDataLen)
{
    smStatus_t retStatus                      = SM_NOT_OK;
    tlvHeader_t hdr                           = {{NX_CLA, NX_INS_CRYPTO_REQ, NX_P1_DEFAULT, NX_P2_DEFAULT}};
    uint8_t cmdHeaderBuf[NX_MAX_BUF_SIZE_CMD] = {0};
    size_t cmdHeaderBufLen                    = 0;
    uint8_t cmdDataBuf[NX_MAX_BUF_SIZE_CMD]   = {0};
    size_t cmdDataBufBufLen                   = 0;
    int tlvRet                                = 1;
    uint8_t *pCmdDataBuf                      = &cmdDataBuf[0];
    size_t rspIndex                           = 0;
    uint8_t rspbuf[NX_MAX_BUF_SIZE_RSP]       = {0};
    size_t rspbufLen                          = sizeof(rspbuf);
    nx_ev2_comm_mode_t commMode               = EV2_CommMode_PLAIN;
    void *options                             = &commMode;

    if ((session_ctx == NULL) || (outputData == NULL) || (outputDataLen == NULL)) {
        goto cleanup;
    }

    if ((keyID < NX_KEY_MGMT_MIN_CRYPTO_KEY_NUMBER) ||
        ((keyID > NX_KEY_MGMT_MAX_CRYPTO_KEY_NUMBER) && (keyID < kSE_CryptoAESKey_TB_SLOTNUM_MIN)) ||
        ((keyID > kSE_CryptoAESKey_TB_SLOTNUM_MAX) && (keyID < kSE_CryptoAESKey_SB_SLOTNUM_MIN)) ||
        (keyID > kSE_CryptoAESKey_SB_SLOTNUM_MAX)) {
        LOG_E("Invalid crypto AESKEY IDs");
        goto cleanup;
    }

    retStatus = nx_get_comm_mode(session_ctx, session_ctx->userCryptoCommMode, NX_INS_CRYPTO_REQ, &commMode, NULL);
    ENSURE_OR_GO_CLEANUP(SM_OK == retStatus);

    retStatus = SM_NOT_OK; //reinitialized
#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "CryptoRequest_AES_CBC_ECB_Init []");
#endif /* VERBOSE_APDU_LOGS */

    tlvRet = SET_U8("Action", &pCmdDataBuf, &cmdDataBufBufLen, Nx_CryptoAPI_Operation_AES_CBC_ECB);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_U8("operation", &pCmdDataBuf, &cmdDataBufBufLen, Nx_AES_Operation_Init);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_U8("aesPrimitive", &pCmdDataBuf, &cmdDataBufBufLen, aesPrimitive);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_U8("Key ID", &pCmdDataBuf, &cmdDataBufBufLen, keyID);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    if (keyID > NX_KEY_MGMT_MAX_CRYPTO_KEY_NUMBER) {
        tlvRet = SET_U8("Key length", &pCmdDataBuf, &cmdDataBufBufLen, keyLen);
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);
    }

    if ((aesPrimitive == Nx_AES_Primitive_CBC_Encrypt) || (aesPrimitive == Nx_AES_Primitive_CBC_Decrypt)) {
        tlvRet = SET_U8("icvSrc", &pCmdDataBuf, &cmdDataBufBufLen, icvSrc);
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);
        if (icvSrc == kSE_CryptoDataSrc_CommandBuf) {
            if ((icvDataLen == 0x10) && (icvData != NULL)) {
                tlvRet = SET_u8buf("icvData", &pCmdDataBuf, &cmdDataBufBufLen, icvData, icvDataLen);
                ENSURE_OR_GO_CLEANUP(0 == tlvRet);
            }
            else {
                retStatus = SM_NOT_OK;
                LOG_E("Invalid ICV command buffer!");
                goto cleanup;
            }
        }
    }

    tlvRet = SET_U8("Input Data Source", &pCmdDataBuf, &cmdDataBufBufLen, inputDataSrc);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    if (inputDataSrc != kSE_CryptoDataSrc_CommandBuf) {
        if (inputDataLen > UINT8_MAX) {
            retStatus = SM_NOT_OK;
            goto cleanup;
        }
        tlvRet = SET_U8("Input Data Length", &pCmdDataBuf, &cmdDataBufBufLen, (uint8_t)inputDataLen);
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);
    }
    else if (inputData != NULL) {
        tlvRet = SET_u8buf("Input Data", &pCmdDataBuf, &cmdDataBufBufLen, inputData, inputDataLen);
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);
    }

    retStatus = DoAPDUTxRx_s_Case4(
        session_ctx, &hdr, cmdHeaderBuf, cmdHeaderBufLen, cmdDataBuf, cmdDataBufBufLen, rspbuf, &rspbufLen, options);

    if (retStatus == SM_OK) {
        retStatus = SM_NOT_OK;

        if (rspbufLen < 2) {
            goto cleanup;
        }
        else if (rspbufLen > 2) {
            if (*outputDataLen >= rspbufLen - 2) {
                tlvRet = get_u8buf(rspbuf, &rspIndex, rspbufLen, outputData, rspbufLen - 2);
                ENSURE_OR_GO_CLEANUP(0 == tlvRet);
                *outputDataLen = rspbufLen - 2;
            }
            else {
                LOG_E("Not enough output data buffer!");
                goto cleanup;
            }
        }
        else { // (rspbufLen == 2)
            *outputDataLen = 0;
        }

        retStatus = (rspbuf[rspbufLen - 2] << 8) | (rspbuf[rspbufLen - 1]);
        if (retStatus == SM_OK_ALT) {
            retStatus = SM_OK;
        }
    }

cleanup:
    return retStatus;
}

smStatus_t nx_CryptoRequest_AES_CBC_ECB_Update(pSeSession_t session_ctx,
    uint8_t inputDataSrc,
    const uint8_t *inputData,
    size_t inputDataLen,
    uint8_t *outputData,
    size_t *outputDataLen)
{
    smStatus_t retStatus                      = SM_NOT_OK;
    tlvHeader_t hdr                           = {{NX_CLA, NX_INS_CRYPTO_REQ, NX_P1_DEFAULT, NX_P2_DEFAULT}};
    uint8_t cmdHeaderBuf[NX_MAX_BUF_SIZE_CMD] = {0};
    size_t cmdHeaderBufLen                    = 0;
    uint8_t cmdDataBuf[NX_MAX_BUF_SIZE_CMD]   = {0};
    size_t cmdDataBufBufLen                   = 0;
    int tlvRet                                = 1;
    uint8_t *pCmdDataBuf                      = &cmdDataBuf[0];
    size_t rspIndex                           = 0;
    uint8_t rspbuf[NX_MAX_BUF_SIZE_RSP]       = {0};
    size_t rspbufLen                          = sizeof(rspbuf);
    nx_ev2_comm_mode_t commMode               = EV2_CommMode_PLAIN;
    void *options                             = &commMode;

    if ((session_ctx == NULL) || (outputData == NULL) || (outputDataLen == NULL)) {
        goto cleanup;
    }

    retStatus = nx_get_comm_mode(session_ctx, session_ctx->userCryptoCommMode, NX_INS_CRYPTO_REQ, &commMode, NULL);
    ENSURE_OR_GO_CLEANUP(SM_OK == retStatus);

    retStatus = SM_NOT_OK; //reinitialized
#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "CryptoRequest_AES_CBC_ECB_Update []");
#endif /* VERBOSE_APDU_LOGS */

    tlvRet = SET_U8("Action", &pCmdDataBuf, &cmdDataBufBufLen, Nx_CryptoAPI_Operation_AES_CBC_ECB);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_U8("operation", &pCmdDataBuf, &cmdDataBufBufLen, Nx_AES_Operation_Update);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_U8("Input Data Source", &pCmdDataBuf, &cmdDataBufBufLen, inputDataSrc);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    if (inputDataSrc != kSE_CryptoDataSrc_CommandBuf) {
        if (inputDataLen > UINT8_MAX) {
            retStatus = SM_NOT_OK;
            goto cleanup;
        }
        tlvRet = SET_U8("Input Data Length", &pCmdDataBuf, &cmdDataBufBufLen, (uint8_t)inputDataLen);
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);
    }
    else if (inputData != NULL) {
        tlvRet = SET_u8buf("Input Data", &pCmdDataBuf, &cmdDataBufBufLen, inputData, inputDataLen);
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);
    }

    retStatus = DoAPDUTxRx_s_Case4(
        session_ctx, &hdr, cmdHeaderBuf, cmdHeaderBufLen, cmdDataBuf, cmdDataBufBufLen, rspbuf, &rspbufLen, options);

    if (retStatus == SM_OK) {
        retStatus = SM_NOT_OK;

        if (rspbufLen < 2) {
            goto cleanup;
        }
        else if (rspbufLen > 2) {
            if (*outputDataLen >= rspbufLen - 2) {
                tlvRet = get_u8buf(rspbuf, &rspIndex, rspbufLen, outputData, rspbufLen - 2);
                ENSURE_OR_GO_CLEANUP(0 == tlvRet);
                *outputDataLen = rspbufLen - 2;
            }
            else {
                LOG_E("Not enough output data buffer!");
                goto cleanup;
            }
        }
        else { // (rspbufLen == 2)
            *outputDataLen = 0;
        }

        retStatus = (rspbuf[rspbufLen - 2] << 8) | (rspbuf[rspbufLen - 1]);
        if (retStatus == SM_OK_ALT) {
            retStatus = SM_OK;
        }
    }

cleanup:
    return retStatus;
}

smStatus_t nx_CryptoRequest_AES_CBC_ECB_Final(pSeSession_t session_ctx,
    uint8_t inputDataSrc,
    const uint8_t *inputData,
    size_t inputDataLen,
    uint8_t *outputData,
    size_t *outputDataLen)
{
    smStatus_t retStatus                      = SM_NOT_OK;
    tlvHeader_t hdr                           = {{NX_CLA, NX_INS_CRYPTO_REQ, NX_P1_DEFAULT, NX_P2_DEFAULT}};
    uint8_t cmdHeaderBuf[NX_MAX_BUF_SIZE_CMD] = {0};
    size_t cmdHeaderBufLen                    = 0;
    uint8_t cmdDataBuf[NX_MAX_BUF_SIZE_CMD]   = {0};
    size_t cmdDataBufBufLen                   = 0;
    int tlvRet                                = 1;
    uint8_t *pCmdDataBuf                      = &cmdDataBuf[0];
    size_t rspIndex                           = 0;
    uint8_t rspbuf[NX_MAX_BUF_SIZE_RSP]       = {0};
    size_t rspbufLen                          = sizeof(rspbuf);
    nx_ev2_comm_mode_t commMode               = EV2_CommMode_PLAIN;
    void *options                             = &commMode;

    if ((session_ctx == NULL) || (outputData == NULL) || (outputDataLen == NULL)) {
        goto cleanup;
    }

    retStatus = nx_get_comm_mode(session_ctx, session_ctx->userCryptoCommMode, NX_INS_CRYPTO_REQ, &commMode, NULL);
    ENSURE_OR_GO_CLEANUP(SM_OK == retStatus);

    retStatus = SM_NOT_OK; //reinitialized
#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "CryptoRequest_AES_CBC_ECB_Final []");
#endif /* VERBOSE_APDU_LOGS */

    tlvRet = SET_U8("Action", &pCmdDataBuf, &cmdDataBufBufLen, Nx_CryptoAPI_Operation_AES_CBC_ECB);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_U8("operation", &pCmdDataBuf, &cmdDataBufBufLen, Nx_AES_Operation_Final);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_U8("Input Data Source", &pCmdDataBuf, &cmdDataBufBufLen, inputDataSrc);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    if (inputDataSrc != kSE_CryptoDataSrc_CommandBuf) {
        if (inputDataLen > UINT8_MAX) {
            retStatus = SM_NOT_OK;
            goto cleanup;
        }
        tlvRet = SET_U8("Input Data Length", &pCmdDataBuf, &cmdDataBufBufLen, (uint8_t)inputDataLen);
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);
    }
    else if (inputData != NULL) {
        tlvRet = SET_u8buf("Input Data", &pCmdDataBuf, &cmdDataBufBufLen, inputData, inputDataLen);
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);
    }

    retStatus = DoAPDUTxRx_s_Case4(
        session_ctx, &hdr, cmdHeaderBuf, cmdHeaderBufLen, cmdDataBuf, cmdDataBufBufLen, rspbuf, &rspbufLen, options);

    if (retStatus == SM_OK) {
        retStatus = SM_NOT_OK;

        if (rspbufLen < 2) {
            goto cleanup;
        }
        else if (rspbufLen > 2) {
            if (*outputDataLen >= rspbufLen - 2) {
                tlvRet = get_u8buf(rspbuf, &rspIndex, rspbufLen, outputData, rspbufLen - 2);
                ENSURE_OR_GO_CLEANUP(0 == tlvRet);
                *outputDataLen = rspbufLen - 2;
            }
            else {
                LOG_E("Not enough output data buffer!");
                goto cleanup;
            }
        }
        else { // (rspbufLen == 2)
            *outputDataLen = 0;
        }

        retStatus = (rspbuf[rspbufLen - 2] << 8) | (rspbuf[rspbufLen - 1]);
        if (retStatus == SM_OK_ALT) {
            retStatus = SM_OK;
        }
    }

cleanup:
    return retStatus;
}

smStatus_t nx_CryptoRequest_AES_CBC_ECB_Oneshot(pSeSession_t session_ctx,
    Nx_AES_Primitive_t aesPrimitive,
    uint8_t keyID,
    uint8_t keyLen,
    uint8_t icvSrc,
    const uint8_t *icvData,
    size_t icvDataLen,
    uint8_t inputDataSrc,
    const uint8_t *inputData,
    size_t inputDataLen,
    uint8_t resultDst,
    uint8_t *outputData)
{
    smStatus_t retStatus                      = SM_NOT_OK;
    tlvHeader_t hdr                           = {{NX_CLA, NX_INS_CRYPTO_REQ, NX_P1_DEFAULT, NX_P2_DEFAULT}};
    uint8_t cmdHeaderBuf[NX_MAX_BUF_SIZE_CMD] = {0};
    size_t cmdHeaderBufLen                    = 0;
    uint8_t cmdDataBuf[NX_MAX_BUF_SIZE_CMD]   = {0};
    size_t cmdDataBufBufLen                   = 0;
    int tlvRet                                = 1;
    uint8_t *pCmdDataBuf                      = &cmdDataBuf[0];
    size_t rspIndex                           = 0;
    uint8_t rspbuf[NX_MAX_BUF_SIZE_RSP]       = {0};
    size_t rspbufLen                          = sizeof(rspbuf);
    nx_ev2_comm_mode_t commMode               = EV2_CommMode_PLAIN;
    void *options                             = &commMode;
    size_t outputDataLen                      = inputDataLen;

    if (session_ctx == NULL) {
        goto cleanup;
    }

    if ((keyID < NX_KEY_MGMT_MIN_CRYPTO_KEY_NUMBER) ||
        ((keyID > NX_KEY_MGMT_MAX_CRYPTO_KEY_NUMBER) && (keyID < kSE_CryptoAESKey_TB_SLOTNUM_MIN)) ||
        ((keyID > kSE_CryptoAESKey_TB_SLOTNUM_MAX) && (keyID < kSE_CryptoAESKey_SB_SLOTNUM_MIN)) ||
        (keyID > kSE_CryptoAESKey_SB_SLOTNUM_MAX)) {
        LOG_E("Invalid crypto AESKEY IDs");
        goto cleanup;
    }

    retStatus = nx_get_comm_mode(session_ctx, session_ctx->userCryptoCommMode, NX_INS_CRYPTO_REQ, &commMode, NULL);
    ENSURE_OR_GO_CLEANUP(SM_OK == retStatus);

    retStatus = SM_NOT_OK; //reinitialized
#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "CryptoRequest_AES_CBC_ECB_Oneshot []");
#endif /* VERBOSE_APDU_LOGS */

    tlvRet = SET_U8("Action", &pCmdDataBuf, &cmdDataBufBufLen, Nx_CryptoAPI_Operation_AES_CBC_ECB);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_U8("operation", &pCmdDataBuf, &cmdDataBufBufLen, Nx_AES_Operation_OneShot);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_U8("aesPrimitive", &pCmdDataBuf, &cmdDataBufBufLen, aesPrimitive);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_U8("Key ID", &pCmdDataBuf, &cmdDataBufBufLen, keyID);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    if (keyID > NX_KEY_MGMT_MAX_CRYPTO_KEY_NUMBER) {
        tlvRet = SET_U8("Key length", &pCmdDataBuf, &cmdDataBufBufLen, keyLen);
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);
    }

    if ((aesPrimitive == Nx_AES_Primitive_CBC_Encrypt) || (aesPrimitive == Nx_AES_Primitive_CBC_Decrypt)) {
        tlvRet = SET_U8("icvSrc", &pCmdDataBuf, &cmdDataBufBufLen, icvSrc);
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);
        if (icvSrc == kSE_CryptoDataSrc_CommandBuf) {
            if ((icvDataLen == 0x10) && (icvData != NULL)) {
                tlvRet = SET_u8buf("icvData", &pCmdDataBuf, &cmdDataBufBufLen, icvData, icvDataLen);
                ENSURE_OR_GO_CLEANUP(0 == tlvRet);
            }
            else {
                retStatus = SM_NOT_OK;
                LOG_E("Invalid ICV command buffer!");
                goto cleanup;
            }
        }
    }

    tlvRet = SET_U8("Input Data Source", &pCmdDataBuf, &cmdDataBufBufLen, inputDataSrc);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    if (inputDataSrc != kSE_CryptoDataSrc_CommandBuf) {
        if (inputDataLen > UINT8_MAX) {
            retStatus = SM_NOT_OK;
            goto cleanup;
        }
        tlvRet = SET_U8("Input Data Length", &pCmdDataBuf, &cmdDataBufBufLen, (uint8_t)inputDataLen);
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);
    }
    else if (inputData != NULL) {
        tlvRet = SET_u8buf("Input Data", &pCmdDataBuf, &cmdDataBufBufLen, inputData, inputDataLen);
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);
    }

    tlvRet = SET_U8("resultDst", &pCmdDataBuf, &cmdDataBufBufLen, resultDst);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    retStatus = DoAPDUTxRx_s_Case4(
        session_ctx, &hdr, cmdHeaderBuf, cmdHeaderBufLen, cmdDataBuf, cmdDataBufBufLen, rspbuf, &rspbufLen, options);

    if (retStatus == SM_OK) {
        retStatus = SM_NOT_OK;

        if (rspbufLen < 2) {
            goto cleanup;
        }

        if (resultDst == kSE_CryptoDataSrc_CommandBuf) {
            if (outputDataLen != (rspbufLen - 2)) {
                LOG_E("Invalid output data length!");
                goto cleanup;
            }
            if (outputData == NULL) {
                LOG_E("Invalid output data buffer!");
                goto cleanup;
            }
            tlvRet = get_u8buf(rspbuf, &rspIndex, rspbufLen, outputData, outputDataLen);
            ENSURE_OR_GO_CLEANUP(0 == tlvRet);
        }

        retStatus = (rspbuf[rspbufLen - 2] << 8) | (rspbuf[rspbufLen - 1]);
        if (retStatus == SM_OK_ALT) {
            retStatus = SM_OK;
        }
    }

cleanup:
    return retStatus;
}

smStatus_t nx_CryptoRequest_AES_AEAD_Oneshot(pSeSession_t session_ctx,
    uint8_t action,
    uint8_t aesPrimitive,
    uint8_t keyID,
    uint8_t keyLen,
    uint8_t nonceSrc,
    uint8_t *nonceInput,
    size_t nonceDataLen,
    uint8_t *nonceOutput,
    size_t tagLen,
    uint8_t *tagInput,
    uint8_t *tagOutput,
    uint8_t aadSrc,
    const uint8_t *aad,
    size_t aadLen,
    uint8_t inputDataSrc,
    const uint8_t *inputData,
    size_t inputDataLen,
    uint8_t resultDst,
    uint16_t *verifyResult,
    uint8_t *outputData)
{
    smStatus_t retStatus                      = SM_NOT_OK;
    tlvHeader_t hdr                           = {{NX_CLA, NX_INS_CRYPTO_REQ, NX_P1_DEFAULT, NX_P2_DEFAULT}};
    uint8_t cmdHeaderBuf[NX_MAX_BUF_SIZE_CMD] = {0};
    size_t cmdHeaderBufLen                    = 0;
    uint8_t cmdDataBuf[NX_MAX_BUF_SIZE_CMD]   = {0};
    size_t cmdDataBufBufLen                   = 0;
    int tlvRet                                = 1;
    uint8_t *pCmdDataBuf                      = &cmdDataBuf[0];
    size_t rspIndex                           = 0;
    uint8_t rspbuf[NX_MAX_BUF_SIZE_RSP]       = {0};
    size_t rspbufLen                          = sizeof(rspbuf);
    nx_ev2_comm_mode_t commMode               = EV2_CommMode_PLAIN;
    void *options                             = &commMode;
    size_t outputDataLen                      = inputDataLen;

    if (session_ctx == NULL) {
        goto cleanup;
    }

    if ((keyID < NX_KEY_MGMT_MIN_CRYPTO_KEY_NUMBER) ||
        ((keyID > NX_KEY_MGMT_MAX_CRYPTO_KEY_NUMBER) && (keyID < kSE_CryptoAESKey_TB_SLOTNUM_MIN)) ||
        ((keyID > kSE_CryptoAESKey_TB_SLOTNUM_MAX) && (keyID < kSE_CryptoAESKey_SB_SLOTNUM_MIN)) ||
        (keyID > kSE_CryptoAESKey_SB_SLOTNUM_MAX)) {
        LOG_E("Invalid crypto AESKEY IDs");
        goto cleanup;
    }

    retStatus = nx_get_comm_mode(session_ctx, session_ctx->userCryptoCommMode, NX_INS_CRYPTO_REQ, &commMode, NULL);
    ENSURE_OR_GO_CLEANUP(SM_OK == retStatus);

    retStatus = SM_NOT_OK; //reinitialized
#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "CryptoRequest_AES_AEAD_Encrypt_Oneshot []");
#endif /* VERBOSE_APDU_LOGS */

    tlvRet = SET_U8("Action", &pCmdDataBuf, &cmdDataBufBufLen, action);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_U8("operation", &pCmdDataBuf, &cmdDataBufBufLen, Nx_AES_Operation_OneShot);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_U8("aesPrimitive", &pCmdDataBuf, &cmdDataBufBufLen, aesPrimitive);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_U8("Key ID", &pCmdDataBuf, &cmdDataBufBufLen, keyID);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    if (keyID > NX_KEY_MGMT_MAX_CRYPTO_KEY_NUMBER) {
        tlvRet = SET_U8("Key length", &pCmdDataBuf, &cmdDataBufBufLen, keyLen);
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);
    }

    if ((aesPrimitive != Nx_AES_Primitive_CCM_Encrypt_Sign_internal_nonce) &&
        (aesPrimitive != Nx_AES_Primitive_GCM_Encrypt_Sign_internal_nonce)) {
        tlvRet = SET_U8("nonceSrc", &pCmdDataBuf, &cmdDataBufBufLen, nonceSrc);
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);
    }

    if (aesPrimitive >= Nx_AES_Primitive_CCM_Encrypt_Sign && aesPrimitive <= Nx_AES_Primitive_CCM_Decrypt_Verify) {
        if (nonceDataLen != NX_CRYPTOREQ_AEAD_AES_CCM_NONCE_LEN) {
            LOG_E("Invalid nonceDataLen");
            goto cleanup;
        }
    }
    else if (aesPrimitive >= Nx_AES_Primitive_GCM_Encrypt_Sign && aesPrimitive <= Nx_AES_Primitive_GCM_Decrypt_Verify) {
        if (nonceDataLen < NX_CRYPTOREQ_AEAD_AES_GCM_MIM_NONCE_LEN ||
            nonceDataLen > NX_CRYPTOREQ_AEAD_AES_GCM_MAX_NONCE_LEN) {
            LOG_E("Invalid nonceDataLen");
            goto cleanup;
        }
    }
    else {
        LOG_E("unknown aesPrimitive type");
        goto cleanup;
    }

    tlvRet = SET_U8("nonceDataLen", &pCmdDataBuf, &cmdDataBufBufLen, (uint8_t)nonceDataLen);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    if ((aesPrimitive != Nx_AES_Primitive_CCM_Encrypt_Sign_internal_nonce) &&
        (aesPrimitive != Nx_AES_Primitive_GCM_Encrypt_Sign_internal_nonce)) {
        if ((nonceDataLen > 0) && (nonceInput != NULL)) {
            tlvRet = SET_u8buf("nonceData", &pCmdDataBuf, &cmdDataBufBufLen, nonceInput, nonceDataLen);
            ENSURE_OR_GO_CLEANUP(0 == tlvRet);
        }
    }

    tlvRet = SET_U8("aadSrc", &pCmdDataBuf, &cmdDataBufBufLen, aadSrc);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    if (aadLen > UINT16_MAX) {
        retStatus = SM_NOT_OK;
        goto cleanup;
    }
    tlvRet = SET_U8("aadLen", &pCmdDataBuf, &cmdDataBufBufLen, (uint8_t)aadLen);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    if ((aadLen > 0) && (aad != NULL)) {
        tlvRet = SET_u8buf("aad", &pCmdDataBuf, &cmdDataBufBufLen, aad, aadLen);
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);
    }

    tlvRet = SET_U8("inputDataSrc", &pCmdDataBuf, &cmdDataBufBufLen, inputDataSrc);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    if (inputDataLen > UINT8_MAX) {
        retStatus = SM_NOT_OK;
        goto cleanup;
    }

    tlvRet = SET_U8("Input Data Length", &pCmdDataBuf, &cmdDataBufBufLen, (uint8_t)inputDataLen);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    if ((inputDataLen > 0) && (inputData != NULL)) {
        tlvRet = SET_u8buf("Input Data", &pCmdDataBuf, &cmdDataBufBufLen, inputData, inputDataLen);
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);
    }

    if (aesPrimitive >= Nx_AES_Primitive_CCM_Encrypt_Sign && aesPrimitive <= Nx_AES_Primitive_CCM_Decrypt_Verify) {
        if (tagLen != NX_CRYPTOREQ_AEAD_AES_CCM_MIN_TAG_LEN && tagLen != NX_CRYPTOREQ_AEAD_AES_CCM_MAX_TAG_LEN) {
            LOG_E("Invalid tagLen");
            goto cleanup;
        }
    }
    else if (aesPrimitive >= Nx_AES_Primitive_GCM_Encrypt_Sign && aesPrimitive <= Nx_AES_Primitive_GCM_Decrypt_Verify) {
        if (tagLen < NX_CRYPTOREQ_AEAD_AES_GCM_MIN_TAG_LEN || tagLen > NX_CRYPTOREQ_AEAD_AES_GCM_MAX_TAG_LEN) {
            LOG_E("Invalid tagLen");
            goto cleanup;
        }
    }
    else {
        LOG_E("Unknown aesPrimitive type");
        goto cleanup;
    }

    tlvRet = SET_U8("tagLen", &pCmdDataBuf, &cmdDataBufBufLen, (uint8_t)tagLen);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    if (action == Nx_CryptoAPI_Operation_AES_Decrypt_Verify) {
        if (tagInput != NULL) {
            tlvRet = SET_u8buf("tag Data", &pCmdDataBuf, &cmdDataBufBufLen, tagInput, tagLen);
            ENSURE_OR_GO_CLEANUP(0 == tlvRet);
        }
        else {
            LOG_E("tagInput Buffer is null!");
            goto cleanup;
        }

        tlvRet = SET_U8("resultDst", &pCmdDataBuf, &cmdDataBufBufLen, resultDst);
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);
    }

    retStatus = DoAPDUTxRx_s_Case4(
        session_ctx, &hdr, cmdHeaderBuf, cmdHeaderBufLen, cmdDataBuf, cmdDataBufBufLen, rspbuf, &rspbufLen, options);

    if (retStatus == SM_OK) {
        retStatus = SM_NOT_OK;

        if (rspbufLen < 2) {
            goto cleanup;
        }

        if (action == Nx_CryptoAPI_Operation_AES_Encrypt_Sign) {
            if ((aesPrimitive == Nx_AES_Primitive_CCM_Encrypt_Sign_internal_nonce) ||
                (aesPrimitive == Nx_AES_Primitive_GCM_Encrypt_Sign_internal_nonce)) {
                if (NULL != nonceOutput) {
                    tlvRet = get_u8buf(rspbuf, &rspIndex, rspbufLen, nonceOutput, nonceDataLen);
                    ENSURE_OR_GO_CLEANUP(0 == tlvRet);
                }
                else {
                    LOG_E("No buffer supplied to read the internally generated nonce");
                    goto cleanup;
                }
            }

            if ((outputData != NULL) && (outputDataLen > 0)) {
                tlvRet = get_u8buf(rspbuf, &rspIndex, rspbufLen, outputData, outputDataLen);
                ENSURE_OR_GO_CLEANUP(0 == tlvRet);
            }

            if ((tagOutput != NULL) && (tagLen > 0)) {
                tlvRet = get_u8buf(rspbuf, &rspIndex, rspbufLen, tagOutput, tagLen);
                ENSURE_OR_GO_CLEANUP(0 == tlvRet);
            }
        }
        else {
            if (resultDst == kSE_CryptoDataSrc_CommandBuf) {
                if ((outputData != NULL) && (outputDataLen > 0) &&
                    (rspbufLen > (NX_CRYPTOREQ_AEAD_VERIFYRESULT_SIZE + 2))) {
                    tlvRet = get_u8buf(rspbuf, &rspIndex, rspbufLen, outputData, outputDataLen);
                    ENSURE_OR_GO_CLEANUP(0 == tlvRet);
                }
                else if ((outputDataLen > 0) && (rspbufLen <= (NX_CRYPTOREQ_AEAD_VERIFYRESULT_SIZE + 2))) {
                    goto cleanup;
                }
                else if ((outputData == NULL) && (outputDataLen > 0)) {
                    goto cleanup;
                }
            }
            tlvRet = get_U16_LSB(rspbuf, &rspIndex, rspbufLen, verifyResult);
            ENSURE_OR_GO_CLEANUP(0 == tlvRet);
        }

        retStatus = (rspbuf[rspbufLen - 2] << 8) | (rspbuf[rspbufLen - 1]);
        if (retStatus == SM_OK_ALT) {
            retStatus = SM_OK;
        }
    }

cleanup:
    return retStatus;
}

smStatus_t nx_CryptoRequest_AES_AEAD_Init(pSeSession_t session_ctx,
    uint8_t action,
    uint8_t aesPrimitive,
    uint8_t keyID,
    uint8_t keyLen,
    uint8_t nonceSrc,
    uint8_t *nonceInput,
    size_t nonceDataLen,
    uint8_t *nonceOutput,
    size_t totalAadLen,
    size_t totalInputLen,
    size_t tagLen,
    uint8_t aadSrc,
    uint8_t *aad,
    size_t aadLen,
    uint8_t inputDataSrc,
    uint8_t *inputData,
    size_t inputDataLen,
    uint8_t resultDst,
    uint8_t *outputData,
    size_t *outputDataLen)
{
    smStatus_t retStatus                      = SM_NOT_OK;
    tlvHeader_t hdr                           = {{NX_CLA, NX_INS_CRYPTO_REQ, NX_P1_DEFAULT, NX_P2_DEFAULT}};
    uint8_t cmdHeaderBuf[NX_MAX_BUF_SIZE_CMD] = {0};
    size_t cmdHeaderBufLen                    = 0;
    uint8_t cmdDataBuf[NX_MAX_BUF_SIZE_CMD]   = {0};
    size_t cmdDataBufBufLen                   = 0;
    int tlvRet                                = 1;
    uint8_t *pCmdDataBuf                      = &cmdDataBuf[0];
    size_t rspIndex                           = 0;
    uint8_t rspbuf[NX_MAX_BUF_SIZE_RSP]       = {0};
    size_t rspbufLen                          = sizeof(rspbuf);
    nx_ev2_comm_mode_t commMode               = EV2_CommMode_PLAIN;
    void *options                             = &commMode;

    if (session_ctx == NULL) {
        goto cleanup;
    }
    if ((keyID < NX_KEY_MGMT_MIN_CRYPTO_KEY_NUMBER) ||
        ((keyID > NX_KEY_MGMT_MAX_CRYPTO_KEY_NUMBER) && (keyID < kSE_CryptoAESKey_TB_SLOTNUM_MIN)) ||
        ((keyID > kSE_CryptoAESKey_TB_SLOTNUM_MAX) && (keyID < kSE_CryptoAESKey_SB_SLOTNUM_MIN)) ||
        (keyID > kSE_CryptoAESKey_SB_SLOTNUM_MAX)) {
        LOG_E("Invalid crypto AESKEY IDs");
        goto cleanup;
    }

    retStatus = nx_get_comm_mode(session_ctx, session_ctx->userCryptoCommMode, NX_INS_CRYPTO_REQ, &commMode, NULL);
    ENSURE_OR_GO_CLEANUP(SM_OK == retStatus);

    retStatus = SM_NOT_OK; //reinitialized
#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "CryptoRequest_AES_AEAD_Encrypt_Init []");
#endif /* VERBOSE_APDU_LOGS */

    tlvRet = SET_U8("Action", &pCmdDataBuf, &cmdDataBufBufLen, action);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_U8("operation", &pCmdDataBuf, &cmdDataBufBufLen, Nx_AES_Operation_Init);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_U8("aesPrimitive", &pCmdDataBuf, &cmdDataBufBufLen, aesPrimitive);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_U8("Key ID", &pCmdDataBuf, &cmdDataBufBufLen, keyID);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    if (keyID > NX_KEY_MGMT_MAX_CRYPTO_KEY_NUMBER) {
        tlvRet = SET_U8("Key length", &pCmdDataBuf, &cmdDataBufBufLen, keyLen);
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);
    }

    if ((aesPrimitive != Nx_AES_Primitive_CCM_Encrypt_Sign_internal_nonce) &&
        (aesPrimitive != Nx_AES_Primitive_GCM_Encrypt_Sign_internal_nonce)) {
        tlvRet = SET_U8("nonceSrc", &pCmdDataBuf, &cmdDataBufBufLen, nonceSrc);
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);
    }

    if (aesPrimitive >= Nx_AES_Primitive_CCM_Encrypt_Sign && aesPrimitive <= Nx_AES_Primitive_CCM_Decrypt_Verify) {
        if (nonceDataLen != NX_CRYPTOREQ_AEAD_AES_CCM_NONCE_LEN) {
            LOG_E("Invalid nonceDataLen");
            goto cleanup;
        }
    }
    else if (aesPrimitive >= Nx_AES_Primitive_GCM_Encrypt_Sign && aesPrimitive <= Nx_AES_Primitive_GCM_Decrypt_Verify) {
        if (nonceDataLen < NX_CRYPTOREQ_AEAD_AES_GCM_MIM_NONCE_LEN ||
            nonceDataLen > NX_CRYPTOREQ_AEAD_AES_GCM_MAX_NONCE_LEN) {
            LOG_E("Invalid nonceDataLen");
            goto cleanup;
        }
    }
    else {
        LOG_E("unknown aesPrimitive type");
        goto cleanup;
    }

    tlvRet = SET_U8("nonceDataLen", &pCmdDataBuf, &cmdDataBufBufLen, (uint8_t)nonceDataLen);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    if ((aesPrimitive != Nx_AES_Primitive_CCM_Encrypt_Sign_internal_nonce) &&
        (aesPrimitive != Nx_AES_Primitive_GCM_Encrypt_Sign_internal_nonce)) {
        if ((nonceDataLen > 0) && (nonceInput != NULL)) {
            tlvRet = SET_u8buf("nonceData", &pCmdDataBuf, &cmdDataBufBufLen, nonceInput, nonceDataLen);
            ENSURE_OR_GO_CLEANUP(0 == tlvRet);
        }
    }

    if (totalAadLen > UINT16_MAX) {
        retStatus = SM_NOT_OK;
        goto cleanup;
    }

    tlvRet = SET_U16_LSB("Total AAD Length", &pCmdDataBuf, &cmdDataBufBufLen, (uint16_t)totalAadLen);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_U16_LSB("Total Input Length", &pCmdDataBuf, &cmdDataBufBufLen, (uint16_t)totalInputLen);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    if (aesPrimitive >= Nx_AES_Primitive_CCM_Encrypt_Sign && aesPrimitive <= Nx_AES_Primitive_CCM_Decrypt_Verify) {
        if (tagLen != NX_CRYPTOREQ_AEAD_AES_CCM_MIN_TAG_LEN && tagLen != NX_CRYPTOREQ_AEAD_AES_CCM_MAX_TAG_LEN) {
            LOG_E("Invalid tagLen");
            goto cleanup;
        }
    }
    else if (aesPrimitive >= Nx_AES_Primitive_GCM_Encrypt_Sign && aesPrimitive <= Nx_AES_Primitive_GCM_Decrypt_Verify) {
        if (tagLen < NX_CRYPTOREQ_AEAD_AES_GCM_MIN_TAG_LEN || tagLen > NX_CRYPTOREQ_AEAD_AES_GCM_MAX_TAG_LEN) {
            LOG_E("Invalid tagLen");
            goto cleanup;
        }
    }
    else {
        LOG_E("Unknown aesPrimitive type");
        goto cleanup;
    }

    tlvRet = SET_U8("tagLen", &pCmdDataBuf, &cmdDataBufBufLen, (uint8_t)tagLen);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_U8("aadSrc", &pCmdDataBuf, &cmdDataBufBufLen, aadSrc);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    if (aadLen > UINT8_MAX) {
        retStatus = SM_NOT_OK;
        goto cleanup;
    }

    tlvRet = SET_U8("aadLen", &pCmdDataBuf, &cmdDataBufBufLen, (uint8_t)aadLen);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    if ((aadLen > 0) && (aad != NULL)) {
        tlvRet = SET_u8buf("aad", &pCmdDataBuf, &cmdDataBufBufLen, aad, aadLen);
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);
    }

    tlvRet = SET_U8("inputDataSrc", &pCmdDataBuf, &cmdDataBufBufLen, inputDataSrc);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    if (inputDataLen > UINT8_MAX) {
        retStatus = SM_NOT_OK;
        goto cleanup;
    }

    tlvRet = SET_U8("Input Data Length", &pCmdDataBuf, &cmdDataBufBufLen, (uint8_t)inputDataLen);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    if ((inputDataLen > 0) && (inputData != NULL)) {
        tlvRet = SET_u8buf("Input Data", &pCmdDataBuf, &cmdDataBufBufLen, inputData, inputDataLen);
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);
    }

    if (action == Nx_CryptoAPI_Operation_AES_Decrypt_Verify) {
        tlvRet = SET_U8("resultDst", &pCmdDataBuf, &cmdDataBufBufLen, resultDst);
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);
    }

    retStatus = DoAPDUTxRx_s_Case4(
        session_ctx, &hdr, cmdHeaderBuf, cmdHeaderBufLen, cmdDataBuf, cmdDataBufBufLen, rspbuf, &rspbufLen, options);

    if (retStatus == SM_OK) {
        retStatus = SM_NOT_OK;

        if (rspbufLen < 2) {
            goto cleanup;
        }

        if (action == Nx_CryptoAPI_Operation_AES_Encrypt_Sign) {
            if ((aesPrimitive == Nx_AES_Primitive_CCM_Encrypt_Sign_internal_nonce) ||
                (aesPrimitive == Nx_AES_Primitive_GCM_Encrypt_Sign_internal_nonce)) {
                if (NULL != nonceOutput) {
                    tlvRet = get_u8buf(rspbuf, &rspIndex, rspbufLen, nonceOutput, nonceDataLen);
                    ENSURE_OR_GO_CLEANUP(0 == tlvRet);
                }
                else {
                    LOG_E("No buffer supplied to read the internally generated nonce");
                    goto cleanup;
                }

                if (rspbufLen > (nonceDataLen + 2)) {
                    if ((outputData != NULL) && (outputDataLen != NULL)) {
                        if (*outputDataLen >= rspbufLen - (nonceDataLen + 2)) {
                            tlvRet =
                                get_u8buf(rspbuf, &rspIndex, rspbufLen, outputData, rspbufLen - (nonceDataLen + 2));
                            ENSURE_OR_GO_CLEANUP(0 == tlvRet);
                            *outputDataLen = rspbufLen - (nonceDataLen + 2);
                        }
                        else {
                            LOG_E("Not enough output data buffer!");
                            goto cleanup;
                        }
                    }
                    else {
                        LOG_E("OutputData or outputDataLen Buffer is null!");
                        goto cleanup;
                    }
                }
                else if (rspbufLen < (nonceDataLen + 2)) {
                    goto cleanup;
                }
                else if (outputDataLen != NULL) {
                    *outputDataLen = 0;
                }
            }
            else {
                if (rspbufLen > 2) {
                    if ((outputData != NULL) && (outputDataLen != NULL)) {
                        if (*outputDataLen >= rspbufLen - 2) {
                            tlvRet = get_u8buf(rspbuf, &rspIndex, rspbufLen, outputData, rspbufLen - 2);
                            ENSURE_OR_GO_CLEANUP(0 == tlvRet);
                            *outputDataLen = rspbufLen - 2;
                        }
                        else {
                            LOG_E("Not enough output data buffer!");
                            goto cleanup;
                        }
                    }
                    else {
                        LOG_E("OutputData or outputDataLen Buffer is null!");
                        goto cleanup;
                    }
                }
                else if (outputDataLen != NULL) {
                    *outputDataLen = 0;
                }
            }
        }
        else {
            if (resultDst == kSE_CryptoDataSrc_CommandBuf) {
                if (rspbufLen > 2) {
                    if ((outputData != NULL) && (outputDataLen != NULL)) {
                        if (*outputDataLen >= rspbufLen - 2) {
                            tlvRet = get_u8buf(rspbuf, &rspIndex, rspbufLen, outputData, rspbufLen - 2);
                            ENSURE_OR_GO_CLEANUP(0 == tlvRet);
                            *outputDataLen = rspbufLen - 2;
                        }
                        else {
                            LOG_E("Not enough output data buffer!");
                            goto cleanup;
                        }
                    }
                    else {
                        LOG_E("OutputData or outputDataLen Buffer is null!");
                        goto cleanup;
                    }
                }
                else if (outputDataLen != NULL) {
                    *outputDataLen = 0;
                }
            }
        }

        retStatus = (rspbuf[rspbufLen - 2] << 8) | (rspbuf[rspbufLen - 1]);
        if (retStatus == SM_OK_ALT) {
            retStatus = SM_OK;
        }
    }

cleanup:
    return retStatus;
}

smStatus_t nx_CryptoRequest_AES_AEAD_Update(pSeSession_t session_ctx,
    uint8_t action,
    uint8_t aadSrc,
    const uint8_t *aad,
    size_t aadLen,
    uint8_t inputDataSrc,
    const uint8_t *inputData,
    size_t inputDataLen,
    uint8_t resultDst,
    uint8_t *outputData,
    size_t *outputDataLen)
{
    smStatus_t retStatus                      = SM_NOT_OK;
    tlvHeader_t hdr                           = {{NX_CLA, NX_INS_CRYPTO_REQ, NX_P1_DEFAULT, NX_P2_DEFAULT}};
    uint8_t cmdHeaderBuf[NX_MAX_BUF_SIZE_CMD] = {0};
    size_t cmdHeaderBufLen                    = 0;
    uint8_t cmdDataBuf[NX_MAX_BUF_SIZE_CMD]   = {0};
    size_t cmdDataBufBufLen                   = 0;
    int tlvRet                                = 1;
    uint8_t *pCmdDataBuf                      = &cmdDataBuf[0];
    size_t rspIndex                           = 0;
    uint8_t rspbuf[NX_MAX_BUF_SIZE_RSP]       = {0};
    size_t rspbufLen                          = sizeof(rspbuf);
    nx_ev2_comm_mode_t commMode               = EV2_CommMode_PLAIN;
    void *options                             = &commMode;

    if (session_ctx == NULL) {
        goto cleanup;
    }

    retStatus = nx_get_comm_mode(session_ctx, session_ctx->userCryptoCommMode, NX_INS_CRYPTO_REQ, &commMode, NULL);
    ENSURE_OR_GO_CLEANUP(SM_OK == retStatus);

    retStatus = SM_NOT_OK; //reinitialized
#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "CryptoRequest_AES_AEAD_Encrypt_Update []");
#endif /* VERBOSE_APDU_LOGS */

    tlvRet = SET_U8("Action", &pCmdDataBuf, &cmdDataBufBufLen, action);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_U8("operation", &pCmdDataBuf, &cmdDataBufBufLen, Nx_AES_Operation_Update);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_U8("aadSrc", &pCmdDataBuf, &cmdDataBufBufLen, aadSrc);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    if (aadLen > UINT8_MAX) {
        retStatus = SM_NOT_OK;
        goto cleanup;
    }
    tlvRet = SET_U8("aadLen", &pCmdDataBuf, &cmdDataBufBufLen, (uint8_t)aadLen);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    if ((aadLen > 0) && (aad != NULL)) {
        tlvRet = SET_u8buf("aad", &pCmdDataBuf, &cmdDataBufBufLen, aad, aadLen);
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);
    }

    tlvRet = SET_U8("inputDataSrc", &pCmdDataBuf, &cmdDataBufBufLen, inputDataSrc);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    if (inputDataLen > UINT8_MAX) {
        retStatus = SM_NOT_OK;
        goto cleanup;
    }

    tlvRet = SET_U8("Input Data Length", &pCmdDataBuf, &cmdDataBufBufLen, (uint8_t)inputDataLen);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    if ((inputDataLen > 0) && (inputData != NULL)) {
        tlvRet = SET_u8buf("Input Data", &pCmdDataBuf, &cmdDataBufBufLen, inputData, inputDataLen);
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);
    }

    if (action == Nx_CryptoAPI_Operation_AES_Decrypt_Verify) {
        tlvRet = SET_U8("resultDst", &pCmdDataBuf, &cmdDataBufBufLen, resultDst);
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);
    }

    retStatus = DoAPDUTxRx_s_Case4(
        session_ctx, &hdr, cmdHeaderBuf, cmdHeaderBufLen, cmdDataBuf, cmdDataBufBufLen, rspbuf, &rspbufLen, options);

    if (retStatus == SM_OK) {
        retStatus = SM_NOT_OK;

        if (rspbufLen < 2) {
            goto cleanup;
        }

        if (action == Nx_CryptoAPI_Operation_AES_Encrypt_Sign) {
            if (rspbufLen > 2) {
                if ((outputData != NULL) && (outputDataLen != NULL)) {
                    if (*outputDataLen >= rspbufLen - 2) {
                        tlvRet = get_u8buf(rspbuf, &rspIndex, rspbufLen, outputData, rspbufLen - 2);
                        ENSURE_OR_GO_CLEANUP(0 == tlvRet);
                        *outputDataLen = rspbufLen - 2;
                    }
                    else {
                        LOG_E("Not enough output data buffer!");
                        goto cleanup;
                    }
                }
                else {
                    LOG_E("OutputData or outputDataLen Buffer is null!");
                    goto cleanup;
                }
            }
            else if (outputDataLen != NULL) {
                *outputDataLen = 0;
            }
        }
        else {
            if (resultDst == kSE_CryptoDataSrc_CommandBuf) {
                if (rspbufLen > 2) {
                    if ((outputData != NULL) && (outputDataLen != NULL)) {
                        if (*outputDataLen >= rspbufLen - 2) {
                            tlvRet = get_u8buf(rspbuf, &rspIndex, rspbufLen, outputData, rspbufLen - 2);
                            ENSURE_OR_GO_CLEANUP(0 == tlvRet);
                            *outputDataLen = rspbufLen - 2;
                        }
                        else {
                            LOG_E("Not enough output data buffer!");
                            goto cleanup;
                        }
                    }
                    else {
                        LOG_E("OutputData or outputDataLen Buffer is null!");
                        goto cleanup;
                    }
                }
                else if (outputDataLen != NULL) {
                    *outputDataLen = 0;
                }
            }
        }

        retStatus = (rspbuf[rspbufLen - 2] << 8) | (rspbuf[rspbufLen - 1]);
        if (retStatus == SM_OK_ALT) {
            retStatus = SM_OK;
        }
    }

cleanup:
    return retStatus;
}

smStatus_t nx_CryptoRequest_AES_AEAD_Final(pSeSession_t session_ctx,
    uint8_t action,
    uint8_t aadSrc,
    uint8_t *aad,
    size_t aadLen,
    size_t tagLen,
    uint8_t *tagInput,
    uint8_t *tagOutput,
    uint8_t inputDataSrc,
    const uint8_t *inputData,
    size_t inputDataLen,
    uint8_t resultDst,
    uint16_t *verifyResult,
    uint8_t *outputData,
    size_t *outputDataLen)
{
    smStatus_t retStatus                      = SM_NOT_OK;
    tlvHeader_t hdr                           = {{NX_CLA, NX_INS_CRYPTO_REQ, NX_P1_DEFAULT, NX_P2_DEFAULT}};
    uint8_t cmdHeaderBuf[NX_MAX_BUF_SIZE_CMD] = {0};
    size_t cmdHeaderBufLen                    = 0;
    uint8_t cmdDataBuf[NX_MAX_BUF_SIZE_CMD]   = {0};
    size_t cmdDataBufBufLen                   = 0;
    int tlvRet                                = 1;
    uint8_t *pCmdDataBuf                      = &cmdDataBuf[0];
    size_t rspIndex                           = 0;
    uint8_t rspbuf[NX_MAX_BUF_SIZE_RSP]       = {0};
    size_t rspbufLen                          = sizeof(rspbuf);
    nx_ev2_comm_mode_t commMode               = EV2_CommMode_PLAIN;
    void *options                             = &commMode;

    if (session_ctx == NULL) {
        goto cleanup;
    }

    retStatus = nx_get_comm_mode(session_ctx, session_ctx->userCryptoCommMode, NX_INS_CRYPTO_REQ, &commMode, NULL);
    ENSURE_OR_GO_CLEANUP(SM_OK == retStatus);

    retStatus = SM_NOT_OK; //reinitialized
#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "CryptoRequest_AES_AEAD_Encrypt_Final []");
#endif /* VERBOSE_APDU_LOGS */

    tlvRet = SET_U8("Action", &pCmdDataBuf, &cmdDataBufBufLen, action);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_U8("operation", &pCmdDataBuf, &cmdDataBufBufLen, Nx_AES_Operation_Final);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_U8("aadSrc", &pCmdDataBuf, &cmdDataBufBufLen, aadSrc);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    if (aadLen > UINT8_MAX) {
        retStatus = SM_NOT_OK;
        goto cleanup;
    }

    tlvRet = SET_U8("aadLen", &pCmdDataBuf, &cmdDataBufBufLen, (uint8_t)aadLen);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    if ((aadLen > 0) && (aad != NULL)) {
        tlvRet = SET_u8buf("aad", &pCmdDataBuf, &cmdDataBufBufLen, aad, aadLen);
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);
    }

    tlvRet = SET_U8("inputDataSrc", &pCmdDataBuf, &cmdDataBufBufLen, inputDataSrc);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    if (inputDataLen > UINT8_MAX) {
        retStatus = SM_NOT_OK;
        goto cleanup;
    }

    tlvRet = SET_U8("Input Data Length", &pCmdDataBuf, &cmdDataBufBufLen, (uint8_t)inputDataLen);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    if ((inputDataLen > 0) && (inputData != NULL)) {
        tlvRet = SET_u8buf("Input Data", &pCmdDataBuf, &cmdDataBufBufLen, inputData, inputDataLen);
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);
    }

    if (tagLen > NX_CRYPTOREQ_AEAD_AES_MAX_TAG_LEN) {
        retStatus = SM_NOT_OK;
        goto cleanup;
    }

    if (action == Nx_CryptoAPI_Operation_AES_Decrypt_Verify) {
        tlvRet = SET_U8("tagLen", &pCmdDataBuf, &cmdDataBufBufLen, (uint8_t)tagLen);
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);

        if (tagInput != NULL) {
            tlvRet = SET_u8buf("tag Data", &pCmdDataBuf, &cmdDataBufBufLen, tagInput, tagLen);
            ENSURE_OR_GO_CLEANUP(0 == tlvRet);
        }

        tlvRet = SET_U8("resultDst", &pCmdDataBuf, &cmdDataBufBufLen, resultDst);
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);
    }

    retStatus = DoAPDUTxRx_s_Case4(
        session_ctx, &hdr, cmdHeaderBuf, cmdHeaderBufLen, cmdDataBuf, cmdDataBufBufLen, rspbuf, &rspbufLen, options);

    if (retStatus == SM_OK) {
        retStatus = SM_NOT_OK;

        if (rspbufLen < 2) {
            goto cleanup;
        }

        if (action == Nx_CryptoAPI_Operation_AES_Encrypt_Sign) {
            if (rspbufLen > (tagLen + 2)) {
                if ((outputData != NULL) && (outputDataLen != NULL)) {
                    if (*outputDataLen >= rspbufLen - (tagLen + 2)) {
                        tlvRet = get_u8buf(rspbuf, &rspIndex, rspbufLen, outputData, rspbufLen - (tagLen + 2));
                        ENSURE_OR_GO_CLEANUP(0 == tlvRet);
                        *outputDataLen = rspbufLen - (tagLen + 2);
                    }
                    else {
                        LOG_E("Not enough output data buffer!");
                        goto cleanup;
                    }
                }
                else {
                    LOG_E("OutputData or outputDataLen Buffer is null!");
                    goto cleanup;
                }
            }
            else if (rspbufLen < (tagLen + 2)) {
                goto cleanup;
            }
            else if (outputDataLen != NULL) {
                *outputDataLen = 0;
            }

            if (NULL != tagOutput) {
                tlvRet = get_u8buf(rspbuf, &rspIndex, rspbufLen, tagOutput, tagLen);
                ENSURE_OR_GO_CLEANUP(0 == tlvRet);
            }
        }
        else {
            if (resultDst == kSE_CryptoDataSrc_CommandBuf) {
                if (rspbufLen > (NX_CRYPTOREQ_AEAD_VERIFYRESULT_SIZE + 2)) {
                    if ((outputData != NULL) && (outputDataLen != NULL)) {
                        if (*outputDataLen >= (rspbufLen - (NX_CRYPTOREQ_AEAD_VERIFYRESULT_SIZE + 2))) {
                            tlvRet = get_u8buf(rspbuf,
                                &rspIndex,
                                rspbufLen,
                                outputData,
                                rspbufLen - (NX_CRYPTOREQ_AEAD_VERIFYRESULT_SIZE + 2));
                            ENSURE_OR_GO_CLEANUP(0 == tlvRet);
                            *outputDataLen = rspbufLen - (NX_CRYPTOREQ_AEAD_VERIFYRESULT_SIZE + 2);
                        }
                        else {
                            LOG_E("Not enough output data buffer!");
                            goto cleanup;
                        }
                    }
                    else {
                        LOG_E("OutputData or outputDataLen Buffer is null!");
                        goto cleanup;
                    }
                }
                else if (rspbufLen < (NX_CRYPTOREQ_AEAD_VERIFYRESULT_SIZE + 2)) {
                    goto cleanup;
                }
                else if (outputDataLen != NULL) {
                    *outputDataLen = 0;
                }
            }

            tlvRet = get_U16_LSB(rspbuf, &rspIndex, rspbufLen, verifyResult);
            ENSURE_OR_GO_CLEANUP(0 == tlvRet);
        }

        retStatus = (rspbuf[rspbufLen - 2] << 8) | (rspbuf[rspbufLen - 1]);
        if (retStatus == SM_OK_ALT) {
            retStatus = SM_OK;
        }
    }

cleanup:
    return retStatus;
}

smStatus_t nx_CryptoRequest_Write_Internal_Buffer(
    pSeSession_t session_ctx, uint8_t dst, const uint8_t *dstData, size_t dstDataLen)
{
    smStatus_t retStatus                      = SM_NOT_OK;
    tlvHeader_t hdr                           = {{NX_CLA, NX_INS_CRYPTO_REQ, NX_P1_DEFAULT, NX_P2_DEFAULT}};
    uint8_t cmdHeaderBuf[NX_MAX_BUF_SIZE_CMD] = {0};
    size_t cmdHeaderBufLen                    = 0;
    uint8_t cmdDataBuf[NX_MAX_BUF_SIZE_CMD]   = {0};
    size_t cmdDataBufBufLen                   = 0;
    int tlvRet                                = 1;
    uint8_t *pCmdDataBuf                      = &cmdDataBuf[0];
    uint8_t rspbuf[NX_MAX_BUF_SIZE_RSP]       = {0};
    size_t rspbufLen                          = sizeof(rspbuf);
    nx_ev2_comm_mode_t commMode               = EV2_CommMode_PLAIN;
    void *options                             = &commMode;

    if (session_ctx == NULL) {
        goto cleanup;
    }

    retStatus = nx_get_comm_mode(session_ctx, session_ctx->userCryptoCommMode, NX_INS_CRYPTO_REQ, &commMode, NULL);
    ENSURE_OR_GO_CLEANUP(SM_OK == retStatus);

    retStatus = SM_NOT_OK; //reinitialized

#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "CryptoRequest Write_Internal_Buffer[]");
#endif /* VERBOSE_APDU_LOGS */

    tlvRet = SET_U8("Action", &pCmdDataBuf, &cmdDataBufBufLen, Nx_CryptoAPI_Operation_Write_Int_Buffer);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_U8("Destination", &pCmdDataBuf, &cmdDataBufBufLen, dst);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    if (dstDataLen > UINT8_MAX) {
        retStatus = SM_NOT_OK;
        goto cleanup;
    }
    tlvRet = SET_U8("Length", &pCmdDataBuf, &cmdDataBufBufLen, (uint8_t)dstDataLen);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    if ((dstDataLen > 0) && (dstData != NULL)) {
        tlvRet = SET_u8buf("dstData", &pCmdDataBuf, &cmdDataBufBufLen, dstData, dstDataLen);
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);
    }
    else {
        goto cleanup;
    }

    retStatus = DoAPDUTxRx_s_Case4(
        session_ctx, &hdr, cmdHeaderBuf, cmdHeaderBufLen, cmdDataBuf, cmdDataBufBufLen, rspbuf, &rspbufLen, options);

    if (retStatus == SM_OK) {
        retStatus = SM_NOT_OK;

        if (rspbufLen != 2) {
            goto cleanup;
        }

        retStatus = (rspbuf[rspbufLen - 2] << 8) | (rspbuf[rspbufLen - 1]);
        if (retStatus == SM_OK_ALT) {
            retStatus = SM_OK;
        }
    }

cleanup:
    return retStatus;
}

smStatus_t nx_CryptoRequest_HMAC_Sign(pSeSession_t session_ctx,
    Nx_MAC_Operation_t hmacOperation,
    SE_DigestMode_t digestAlgorithm,
    uint8_t keyID,
    uint8_t keyLen,
    uint8_t inputDataSrc,
    const uint8_t *inputData,
    size_t inputDataLen,
    uint8_t resultDst,
    uint8_t *hmacOutput,
    size_t *hmacOutputLen)
{
    smStatus_t retStatus                      = SM_NOT_OK;
    tlvHeader_t hdr                           = {{NX_CLA, NX_INS_CRYPTO_REQ, NX_P1_DEFAULT, NX_P2_DEFAULT}};
    uint8_t cmdHeaderBuf[NX_MAX_BUF_SIZE_CMD] = {0};
    size_t cmdHeaderBufLen                    = 0;
    uint8_t cmdDataBuf[NX_MAX_BUF_SIZE_CMD]   = {0};
    size_t cmdDataBufBufLen                   = 0;
    int tlvRet                                = 1;
    uint8_t *pCmdDataBuf                      = &cmdDataBuf[0];
    size_t rspIndex                           = 0;
    uint8_t rspbuf[NX_MAX_BUF_SIZE_RSP]       = {0};
    size_t rspbufLen                          = sizeof(rspbuf);
    nx_ev2_comm_mode_t commMode               = EV2_CommMode_PLAIN;
    void *options                             = &commMode;

    if ((session_ctx == NULL) || (hmacOperation == Nx_MAC_Operation_NA) || (digestAlgorithm == kSE_DigestMode_NA)) {
        goto cleanup;
    }

    if ((keyID < NX_KEY_MGMT_MIN_CRYPTO_KEY_NUMBER) ||
        ((keyID > NX_KEY_MGMT_MAX_CRYPTO_KEY_NUMBER) && (keyID < kSE_CryptoAESKey_TB_SLOTNUM_MIN)) ||
        ((keyID > kSE_CryptoAESKey_TB_SLOTNUM_MAX) && (keyID < kSE_CryptoAESKey_SB_SLOTNUM_MIN)) ||
        (keyID > kSE_CryptoAESKey_SB_SLOTNUM_MAX)) {
        LOG_E("Invalid crypto AESKEY IDs");
        goto cleanup;
    }

    retStatus = nx_get_comm_mode(session_ctx, session_ctx->userCryptoCommMode, NX_INS_CRYPTO_REQ, &commMode, NULL);
    ENSURE_OR_GO_CLEANUP(SM_OK == retStatus);

    retStatus = SM_NOT_OK; //reinitialized

#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "CryptoRequest_HMAC [%x]", hmacOperation);
#endif /* VERBOSE_APDU_LOGS */

    tlvRet = SET_U8("Action", &pCmdDataBuf, &cmdDataBufBufLen, Nx_CryptoAPI_Operation_HMAC);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_U8("hmacOperation", &pCmdDataBuf, &cmdDataBufBufLen, hmacOperation);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_U8("hmacPrimitive", &pCmdDataBuf, &cmdDataBufBufLen, Nx_MAC_Primitive_Sign);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    if ((hmacOperation == Nx_MAC_Operation_Initialize) || (hmacOperation == Nx_MAC_Operation_OneShot)) {
        tlvRet = SET_U8("digestAlgorithm", &pCmdDataBuf, &cmdDataBufBufLen, digestAlgorithm);
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);

        tlvRet = SET_U8("Key ID", &pCmdDataBuf, &cmdDataBufBufLen, keyID);
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);

        if (keyID > NX_KEY_MGMT_MAX_CRYPTO_KEY_NUMBER) {
            tlvRet = SET_U8("Key length", &pCmdDataBuf, &cmdDataBufBufLen, keyLen);
            ENSURE_OR_GO_CLEANUP(0 == tlvRet);
        }
    }

    tlvRet = SET_U8("Input Data Source", &pCmdDataBuf, &cmdDataBufBufLen, inputDataSrc);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    if (inputDataSrc != kSE_CryptoDataSrc_CommandBuf) {
        if (inputDataLen > UINT8_MAX) {
            retStatus = SM_NOT_OK;
            goto cleanup;
        }
        tlvRet = SET_U8("Input Data Length", &pCmdDataBuf, &cmdDataBufBufLen, (uint8_t)inputDataLen);
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);
    }
    else if (inputData != NULL) {
        tlvRet = SET_u8buf("Input Data", &pCmdDataBuf, &cmdDataBufBufLen, inputData, inputDataLen);
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);
    }

    if (hmacOperation == Nx_MAC_Operation_Finish || hmacOperation == Nx_MAC_Operation_OneShot) {
        tlvRet = SET_U8("resultDst", &pCmdDataBuf, &cmdDataBufBufLen, resultDst);
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);
    }

    retStatus = DoAPDUTxRx_s_Case4(
        session_ctx, &hdr, cmdHeaderBuf, cmdHeaderBufLen, cmdDataBuf, cmdDataBufBufLen, rspbuf, &rspbufLen, options);

    if (retStatus == SM_OK) {
        retStatus = SM_NOT_OK;

        if (resultDst == kSE_CryptoDataSrc_CommandBuf &&
            ((hmacOperation == Nx_MAC_Operation_Finish || hmacOperation == Nx_MAC_Operation_OneShot))) {
            if ((hmacOutput == NULL) || (hmacOutputLen == NULL)) {
                goto cleanup;
            }

            if (rspbufLen < 2) {
                goto cleanup;
            }
            else if (rspbufLen > 2) {
                if (*hmacOutputLen >= rspbufLen - 2) {
                    tlvRet = get_u8buf(rspbuf, &rspIndex, rspbufLen, hmacOutput, rspbufLen - 2);
                    ENSURE_OR_GO_CLEANUP(0 == tlvRet);
                    *hmacOutputLen = rspbufLen - 2;
                }
                else {
                    LOG_E("Not enough output data buffer!");
                    goto cleanup;
                }
            }
            else { // (rspbufLen == 2)
                *hmacOutputLen = 0;
            }
        }
        else {
            if (rspbufLen != 2) {
                goto cleanup;
            }
        }

        retStatus = (rspbuf[rspbufLen - 2] << 8) | (rspbuf[rspbufLen - 1]);
        if (retStatus == SM_OK_ALT) {
            retStatus = SM_OK;
        }
    }

cleanup:
    return retStatus;
}

smStatus_t nx_CryptoRequest_HMAC_Verify(pSeSession_t session_ctx,
    uint8_t hmacOperation,
    SE_DigestMode_t digestAlgorithm,
    uint8_t keyID,
    uint8_t keyLen,
    uint8_t inputDataSrc,
    const uint8_t *inputData,
    size_t inputDataLen,
    uint8_t *hmac,
    size_t hmac_len,
    uint16_t *verifyResult)
{
    smStatus_t retStatus                      = SM_NOT_OK;
    tlvHeader_t hdr                           = {{NX_CLA, NX_INS_CRYPTO_REQ, NX_P1_DEFAULT, NX_P2_DEFAULT}};
    uint8_t cmdHeaderBuf[NX_MAX_BUF_SIZE_CMD] = {0};
    size_t cmdHeaderBufLen                    = 0;
    uint8_t cmdDataBuf[NX_MAX_BUF_SIZE_CMD]   = {0};
    size_t cmdDataBufBufLen                   = 0;
    int tlvRet                                = 1;
    uint8_t *pCmdDataBuf                      = &cmdDataBuf[0];
    size_t rspIndex                           = 0;
    uint8_t rspbuf[NX_MAX_BUF_SIZE_RSP]       = {0};
    size_t rspbufLen                          = sizeof(rspbuf);
    nx_ev2_comm_mode_t commMode               = EV2_CommMode_PLAIN;
    void *options                             = &commMode;

    if ((session_ctx == NULL) || (hmacOperation == Nx_MAC_Operation_NA) || (digestAlgorithm == kSE_DigestMode_NA)) {
        goto cleanup;
    }

    if ((keyID < NX_KEY_MGMT_MIN_CRYPTO_KEY_NUMBER) ||
        ((keyID > NX_KEY_MGMT_MAX_CRYPTO_KEY_NUMBER) && (keyID < kSE_CryptoAESKey_TB_SLOTNUM_MIN)) ||
        ((keyID > kSE_CryptoAESKey_TB_SLOTNUM_MAX) && (keyID < kSE_CryptoAESKey_SB_SLOTNUM_MIN)) ||
        (keyID > kSE_CryptoAESKey_SB_SLOTNUM_MAX)) {
        LOG_E("Invalid crypto AESKEY IDs");
        goto cleanup;
    }

    retStatus = nx_get_comm_mode(session_ctx, session_ctx->userCryptoCommMode, NX_INS_CRYPTO_REQ, &commMode, NULL);
    ENSURE_OR_GO_CLEANUP(SM_OK == retStatus);

    retStatus = SM_NOT_OK; //reinitialized
#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "CryptoRequest_HMAC_Verify [%x]", hmacOperation);
#endif /* VERBOSE_APDU_LOGS */

    tlvRet = SET_U8("Action", &pCmdDataBuf, &cmdDataBufBufLen, Nx_CryptoAPI_Operation_HMAC);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_U8("hmacOperation", &pCmdDataBuf, &cmdDataBufBufLen, hmacOperation);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_U8("hmacPrimitive", &pCmdDataBuf, &cmdDataBufBufLen, Nx_MAC_Primitive_Verify);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    if ((hmacOperation == Nx_MAC_Operation_Initialize) || (hmacOperation == Nx_MAC_Operation_OneShot)) {
        tlvRet = SET_U8("digestAlgorithm", &pCmdDataBuf, &cmdDataBufBufLen, digestAlgorithm);
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);

        tlvRet = SET_U8("Key ID", &pCmdDataBuf, &cmdDataBufBufLen, keyID);
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);

        if (keyID > NX_KEY_MGMT_MAX_CRYPTO_KEY_NUMBER) {
            tlvRet = SET_U8("Key length", &pCmdDataBuf, &cmdDataBufBufLen, keyLen);
            ENSURE_OR_GO_CLEANUP(0 == tlvRet);
        }
    }

    if ((hmacOperation == Nx_MAC_Operation_Finish) || (hmacOperation == Nx_MAC_Operation_OneShot)) {
        if (hmac == NULL) {
            LOG_E("Invalid input HMAC value");
            goto cleanup;
        }
        tlvRet = SET_u8buf("Hmac data", &pCmdDataBuf, &cmdDataBufBufLen, hmac, hmac_len);
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);
    }

    tlvRet = SET_U8("Input Data Source", &pCmdDataBuf, &cmdDataBufBufLen, inputDataSrc);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    if (inputDataSrc != kSE_CryptoDataSrc_CommandBuf) {
        if (inputDataLen > UINT8_MAX) {
            retStatus = SM_NOT_OK;
            goto cleanup;
        }
        tlvRet = SET_U8("Input Data Length", &pCmdDataBuf, &cmdDataBufBufLen, (uint8_t)inputDataLen);
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);
    }
    else if (inputData != NULL) {
        tlvRet = SET_u8buf("Input Data", &pCmdDataBuf, &cmdDataBufBufLen, inputData, inputDataLen);
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);
    }

    retStatus = DoAPDUTxRx_s_Case4(
        session_ctx, &hdr, cmdHeaderBuf, cmdHeaderBufLen, cmdDataBuf, cmdDataBufBufLen, rspbuf, &rspbufLen, options);

    if (retStatus == SM_OK) {
        retStatus = SM_NOT_OK;

        if (hmacOperation == Nx_MAC_Operation_Finish || hmacOperation == Nx_MAC_Operation_OneShot) {
            if (rspbufLen != 4) {
                goto cleanup;
            }

            if (verifyResult == NULL) {
                LOG_E("Invalid Parameter For Verify Result");
                goto cleanup;
            }

            tlvRet = get_U16_LSB(rspbuf, &rspIndex, rspbufLen, verifyResult);
            ENSURE_OR_GO_CLEANUP(0 == tlvRet);
        }
        else {
            if (rspbufLen != 2) {
                goto cleanup;
            }
        }

        retStatus = (rspbuf[rspbufLen - 2] << 8) | (rspbuf[rspbufLen - 1]);
        if (retStatus == SM_OK_ALT) {
            retStatus = SM_OK;
        }
    }

cleanup:
    return retStatus;
}

smStatus_t nx_CryptoRequest_HKDF(pSeSession_t session_ctx,
    uint8_t hkdfOperation,
    uint8_t digestOperation,
    uint8_t keyId,
    size_t keyLength,
    uint8_t saltSrc,
    const uint8_t *saltData,
    size_t saltDataLen,
    uint8_t infoSrc,
    const uint8_t *infoData,
    size_t infoDataLen,
    uint8_t resultDst,
    size_t resultLen,
    uint8_t *hkdfOutput,
    size_t *hkdfOutputLen)
{
    smStatus_t retStatus                      = SM_NOT_OK;
    tlvHeader_t hdr                           = {{NX_CLA, NX_INS_CRYPTO_REQ, NX_P1_DEFAULT, NX_P2_DEFAULT}};
    uint8_t cmdHeaderBuf[NX_MAX_BUF_SIZE_CMD] = {0};
    size_t cmdHeaderBufLen                    = 0;
    uint8_t cmdDataBuf[NX_MAX_BUF_SIZE_CMD]   = {0};
    size_t cmdDataBufBufLen                   = 0;
    int tlvRet                                = 1;
    uint8_t *pCmdDataBuf                      = &cmdDataBuf[0];
    size_t rspIndex                           = 0;
    uint8_t rspbuf[NX_MAX_BUF_SIZE_RSP]       = {0};
    size_t rspbufLen                          = sizeof(rspbuf);
    nx_ev2_comm_mode_t commMode               = EV2_CommMode_PLAIN;
    void *options                             = &commMode;

    if (session_ctx == NULL) {
        goto cleanup;
    }

    retStatus = nx_get_comm_mode(session_ctx, session_ctx->userCryptoCommMode, NX_INS_CRYPTO_REQ, &commMode, NULL);
    ENSURE_OR_GO_CLEANUP(SM_OK == retStatus);

    retStatus = SM_NOT_OK; //reinitialized

#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "CryptoRequest_HKDF []");
#endif /* VERBOSE_APDU_LOGS */

    tlvRet = SET_U8("Action", &pCmdDataBuf, &cmdDataBufBufLen, Nx_CryptoAPI_Operation_HKDF);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_U8("hkdfOperation", &pCmdDataBuf, &cmdDataBufBufLen, hkdfOperation);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_U8("digestOperation", &pCmdDataBuf, &cmdDataBufBufLen, digestOperation);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    if ((keyId & 0xC0) == 0x00) {
        tlvRet = SET_U8("keyId", &pCmdDataBuf, &cmdDataBufBufLen, keyId);
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);
    }
    else {
        tlvRet = SET_U8("slotNum", &pCmdDataBuf, &cmdDataBufBufLen, keyId);
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);
        if (keyLength > UINT8_MAX) {
            retStatus = SM_NOT_OK;
            goto cleanup;
        }
        tlvRet = SET_U8("keyLength", &pCmdDataBuf, &cmdDataBufBufLen, (uint8_t)keyLength);
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);
    }

    if (hkdfOperation == Nx_HKDFOperation_ExtractAndExpand) {
        tlvRet = SET_U8("saltSrc", &pCmdDataBuf, &cmdDataBufBufLen, saltSrc);
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);

        if (saltDataLen > UINT8_MAX) {
            retStatus = SM_NOT_OK;
            goto cleanup;
        }
        tlvRet = SET_U8("saltDataLen", &pCmdDataBuf, &cmdDataBufBufLen, (uint8_t)saltDataLen);
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);

        if ((saltSrc == kSE_CryptoDataSrc_CommandBuf) && ((saltDataLen > 0) && (saltData != NULL))) {
            tlvRet = SET_u8buf("saltData", &pCmdDataBuf, &cmdDataBufBufLen, saltData, saltDataLen);
            ENSURE_OR_GO_CLEANUP(0 == tlvRet);
        }
    }

    tlvRet = SET_U8("infoSrc", &pCmdDataBuf, &cmdDataBufBufLen, infoSrc);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    if (infoDataLen > UINT8_MAX) {
        retStatus = SM_NOT_OK;
        goto cleanup;
    }
    tlvRet = SET_U8("infoDataLen", &pCmdDataBuf, &cmdDataBufBufLen, (uint8_t)infoDataLen);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    if ((infoSrc == kSE_CryptoDataSrc_CommandBuf) && ((infoDataLen > 0) && (infoData != NULL))) {
        tlvRet = SET_u8buf("infoData", &pCmdDataBuf, &cmdDataBufBufLen, infoData, infoDataLen);
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);
    }

    tlvRet = SET_U8("resultDst", &pCmdDataBuf, &cmdDataBufBufLen, (uint8_t)resultDst);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    if (resultLen > UINT8_MAX) {
        retStatus = SM_NOT_OK;
        goto cleanup;
    }
    tlvRet = SET_U8("resultLen", &pCmdDataBuf, &cmdDataBufBufLen, (uint8_t)resultLen);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    retStatus = DoAPDUTxRx_s_Case4(
        session_ctx, &hdr, cmdHeaderBuf, cmdHeaderBufLen, cmdDataBuf, cmdDataBufBufLen, rspbuf, &rspbufLen, options);

    if (retStatus == SM_OK) {
        retStatus = SM_NOT_OK;

        if (resultDst == kSE_CryptoDataSrc_CommandBuf) {
            if (hkdfOutput == NULL || hkdfOutputLen == NULL) {
                goto cleanup;
            }

            if (rspbufLen < 2) {
                goto cleanup;
            }

            if (*hkdfOutputLen < rspbufLen - 2) {
                goto cleanup;
            }

            tlvRet = get_u8buf(rspbuf, &rspIndex, rspbufLen, hkdfOutput, rspbufLen - 2);
            ENSURE_OR_GO_CLEANUP(0 == tlvRet);
            *hkdfOutputLen = rspbufLen - 2;
        }
        else {
            if (rspbufLen != 2) {
                goto cleanup;
            }
        }

        retStatus = (rspbuf[rspbufLen - 2] << 8) | (rspbuf[rspbufLen - 1]);
        if (retStatus == SM_OK_ALT) {
            retStatus = SM_OK;
        }
    }

cleanup:
    return retStatus;
}

smStatus_t nx_CryptoRequest_ECHO(pSeSession_t session_ctx,
    uint8_t *additionalData,
    size_t additionalDataLen,
    uint8_t *rspaction,
    uint8_t *rspadditionalData,
    size_t *rspadditionalDataLen)
{
    smStatus_t retStatus                    = SM_NOT_OK;
    tlvHeader_t hdr                         = {{NX_CLA, NX_INS_CRYPTO_REQ, NX_P1_DEFAULT, NX_P2_DEFAULT}};
    uint8_t cmdDataBuf[NX_MAX_BUF_SIZE_CMD] = {0};
    size_t cmdDataBufBufLen                 = 0;
    int tlvRet                              = 1;
    uint8_t *pCmdDataBuf                    = &cmdDataBuf[0];
    size_t rspIndex                         = 0;
    uint8_t rspbuf[NX_MAX_BUF_SIZE_RSP]     = {0};
    uint8_t *pRspbuf                        = &rspbuf[0];
    size_t rspbufLen                        = sizeof(rspbuf);
    nx_ev2_comm_mode_t commMode             = EV2_CommMode_PLAIN;
    void *options                           = &commMode;

#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "CryptoRequest [Echo]");
#endif /* VERBOSE_APDU_LOGS */

    if ((session_ctx == NULL) || (rspaction == NULL)) {
        goto cleanup;
    }

    retStatus = nx_get_comm_mode(session_ctx, session_ctx->userCryptoCommMode, NX_INS_CRYPTO_REQ, &commMode, NULL);
    ENSURE_OR_GO_CLEANUP(SM_OK == retStatus);

    retStatus = SM_NOT_OK; //reinitialized

    tlvRet = SET_U8("Action", &pCmdDataBuf, &cmdDataBufBufLen, Nx_CryptoAPI_Operation_ECHO);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    if (commMode == EV2_CommMode_PLAIN) {
        if (additionalDataLen > NX_CRYPTOREQ_ECHO_MAX_PLAIN_ADD_DATA_LEN) {
            LOG_E("Invalid additionalDataLen");
            retStatus = SM_NOT_OK;
            goto cleanup;
        }
    }
    else if (commMode == EV2_CommMode_MAC) {
        if (additionalDataLen > NX_CRYPTOREQ_ECHO_MAX_MAC_ADD_DATA_LEN) {
            LOG_E("Invalid additionalDataLen");
            retStatus = SM_NOT_OK;
            goto cleanup;
        }
    }
    else if (commMode == EV2_CommMode_FULL) {
        if (additionalDataLen > NX_CRYPTOREQ_ECHO_MAX_FULL_ADD_DATA_LEN) {
            LOG_E("Invalid additionalDataLen");
            retStatus = SM_NOT_OK;
            goto cleanup;
        }
    }
    else {
        LOG_E("Invalid commMode");
        retStatus = SM_NOT_OK;
        goto cleanup;
    }

    if ((additionalData != NULL) && (additionalDataLen != 0)) {
        tlvRet = SET_u8buf("additionalData", &pCmdDataBuf, &cmdDataBufBufLen, additionalData, additionalDataLen);
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);
    }

    retStatus =
        DoAPDUTxRx_s_Case4(session_ctx, &hdr, NULL, 0, cmdDataBuf, cmdDataBufBufLen, rspbuf, &rspbufLen, options);
    if (retStatus == SM_OK) {
        retStatus = SM_NOT_OK;

        if (rspbufLen < 3) { // SW 2Bytes + action 1byte
            goto cleanup;
        }

        tlvRet = get_U8(pRspbuf, &rspIndex, rspbufLen, rspaction);
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);

        if (*rspaction != Nx_CryptoAPI_Operation_ECHO) {
            LOG_E("Invalid rspaction");
            retStatus = SM_NOT_OK;
            goto cleanup;
        }

        if (rspbufLen > 3) {
            if ((rspadditionalData != NULL) && (rspadditionalDataLen != NULL)) {
                if (*rspadditionalDataLen >= (rspbufLen - 3)) {
                    tlvRet = get_u8buf(rspbuf, &rspIndex, rspbufLen, rspadditionalData, rspbufLen - 3);
                    ENSURE_OR_GO_CLEANUP(0 == tlvRet);
                    *rspadditionalDataLen = (rspbufLen - 3);
                }
                else {
                    LOG_E("Buffer-insuffient");
                    *rspadditionalDataLen = 0;
                    retStatus             = SM_NOT_OK;
                    goto cleanup;
                }
            }
            else {
                LOG_E("rspadditionalData or rspadditionalDataLen is NULL");
                retStatus = SM_NOT_OK;
                goto cleanup;
            }
        }
        else {
            if (rspadditionalDataLen != NULL) {
                *rspadditionalDataLen = 0;
            }
            else {
                LOG_E("rspadditionalDataLen is NULL");
                retStatus = SM_NOT_OK;
                goto cleanup;
            }
        }

        retStatus = (rspbuf[rspbufLen - 2] << 8) | (rspbuf[rspbufLen - 1]);
        if (retStatus == SM_OK_ALT) {
            retStatus = SM_OK;
        }
    }

cleanup:
    return retStatus;
}

smStatus_t Se_Create_AdditionalFrameRequest(tlvHeader_t *header)
{
    smStatus_t retStatus = SM_NOT_OK;
    tlvHeader_t hdr      = {{NX_CLA, NX_INS_ADDITIONAL_FRAME_REQ, NX_P1_DEFAULT, NX_P2_DEFAULT}};

    if (header == NULL) {
        goto exit;
    }

    memcpy(header, &hdr, sizeof(hdr));

    retStatus = SM_OK;

exit:
    return retStatus;
}

smStatus_t nx_ProcessSM_Apply(pSeSession_t session_ctx,
    Nx_CommMode_t commMode,
    uint8_t offset,
    uint8_t cmdCtrIncr,
    uint8_t *plainData,
    size_t plainDataLen,
    uint8_t *cipherData,
    size_t *cipherDataLen)
{
    smStatus_t retStatus                      = SM_NOT_OK;
    tlvHeader_t hdr                           = {{NX_CLA, NX_INS_PROCESS_SM, NX_P1_DEFAULT, NX_P2_DEFAULT}};
    uint8_t cmdHeaderBuf[NX_MAX_BUF_SIZE_CMD] = {0};
    size_t cmdHeaderBufLen                    = 0;
    uint8_t cmdDataBuf[NX_MAX_BUF_SIZE_CMD]   = {0};
    size_t cmdDataBufBufLen                   = 0;
    int tlvRet                                = 1;
    uint8_t *pCmdDataBuf                      = &cmdDataBuf[0];
    size_t rspIndex                           = 0;
    uint8_t rspbuf[NX_MAX_BUF_SIZE_RSP]       = {0};
    size_t rspbufLen                          = sizeof(rspbuf);
    uint8_t commModeByte                      = 0;

    if (session_ctx == NULL) {
        goto cleanup;
    }

    retStatus = SM_NOT_OK; //reinitialized

#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "ProcessSM_Apply []");
#endif /* VERBOSE_APDU_LOGS */

    tlvRet = SET_U8("Action", &pCmdDataBuf, &cmdDataBufBufLen, Nx_ProcessSM_Action_Apply);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    tlvRet = SET_U8("Operation", &pCmdDataBuf, &cmdDataBufBufLen, Nx_ProcessSM_Operation_Oneshot);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    commModeByte = commMode;
    commModeByte = (commModeByte << 4);
    tlvRet       = SET_U8("CommMode", &pCmdDataBuf, &cmdDataBufBufLen, commModeByte);
    ENSURE_OR_GO_CLEANUP(0 == tlvRet);

    if (commMode == Nx_CommMode_FULL) {
        tlvRet = SET_U8("Offset", &pCmdDataBuf, &cmdDataBufBufLen, offset);
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);
    }
    else if (commMode == Nx_CommMode_Plain) {
        tlvRet = SET_U8("CmdCtrIncr", &pCmdDataBuf, &cmdDataBufBufLen, cmdCtrIncr);
        ENSURE_OR_GO_CLEANUP(0 == tlvRet);
    }

    if (commMode != Nx_CommMode_Plain) {
        if ((plainData != NULL) && (plainDataLen >= NX_PROCESSSM_PLAIN_TEXT_LENGTH_MIN) &&
            (plainDataLen <= NX_PROCESSSM_PLAIN_TEXT_LENGTH_MAX)) {
            tlvRet = SET_u8buf("Plaintext", &pCmdDataBuf, &cmdDataBufBufLen, plainData, plainDataLen);
            ENSURE_OR_GO_CLEANUP(0 == tlvRet);
        }
        else {
            goto cleanup;
        }
    }

    retStatus = DoAPDUTxRx_s_Case4(
        session_ctx, &hdr, cmdHeaderBuf, cmdHeaderBufLen, cmdDataBuf, cmdDataBufBufLen, rspbuf, &rspbufLen, NULL);

    if (retStatus == SM_OK) {
        retStatus = SM_NOT_OK;

        if ((commMode == Nx_CommMode_Plain) && (rspbufLen != 2)) {
            goto cleanup;
        }
        else if (commMode != Nx_CommMode_Plain) {
            if ((rspbufLen < 2) || (cipherData == NULL) || (cipherDataLen == NULL)) {
                goto cleanup;
            }

            if (*cipherDataLen >= (rspbufLen - 2)) {
                tlvRet = get_u8buf(rspbuf, &rspIndex, rspbufLen, cipherData, rspbufLen - 2);
                ENSURE_OR_GO_CLEANUP(0 == tlvRet);
                *cipherDataLen = rspbufLen - 2;
            }
            else {
                goto cleanup;
            }
        }

        retStatus = (rspbuf[rspbufLen - 2] << 8) | (rspbuf[rspbufLen - 1]);
        if (retStatus == SM_OK_ALT) {
            retStatus = SM_OK;
        }
    }

cleanup:
    return retStatus;
}
