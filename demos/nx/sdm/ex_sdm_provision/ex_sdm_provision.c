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

#include "ex_sdm_provision.h"
#include "fsl_sss_api.h"
#include "fsl_sss_nx_apis.h"
#include "sm_types.h"
#include "nxLog_msg.h"
#include "ex_sss_boot.h"
#include "nx_apdu.h"
#include "nx_enums.h"
#include "nxEnsure.h"

static ex_sss_boot_ctx_t gex_sss_boot_ctx = {0};

#define EX_SSS_BOOT_PCONTEXT (&gex_sss_boot_ctx)
#define EX_SSS_BOOT_EXPOSE_ARGC_ARGV 0
/*  EX_SSS_ENABLE_SDM_ECC_SIGNATURE 0, enable sdm mac
    EX_SSS_ENABLE_SDM_ECC_SIGNATURE 1, enable sdm with ecc signature
*/
#define EX_SSS_ENABLE_SDM_ECC_SIGNATURE 1

/* ************************************************************************** */
/* Include "main()" with the platform specific startup code for               */
/* MW examples which will call ex_sss_entry()                                 */
/* ************************************************************************** */
#include <ex_sss_main_inc.h>

/*******************************************************************
* Static Functions
*******************************************************************/

sss_status_t ex_sss_entry(ex_sss_boot_ctx_t *pCtx)
{
    sss_status_t status            = kStatus_SSS_Fail;
    smStatus_t sm_status           = SM_NOT_OK;
    uint8_t fileNo                 = EX_SSS_SDM_NDEF_FILE_NUMBER;
    nx_file_SDM_config_t sdmConfig = {0};
    uint8_t fileOption             = 0x00;
    sss_nx_session_t *pSession     = NULL;

    uint32_t aesKeyId         = EX_SSS_SDM_AES_KEY_ID;
    sss_object_t aesKeyObject = {0};
    uint8_t aesKey[]          = EX_SSS_SDM_NEW_AES_KEY;
    size_t aesKeyLen          = sizeof(aesKey);
    uint8_t oldKeyValue[]     = EX_SSS_SDM_OLD_AES_KEY;
    size_t oldKeyValueLen     = sizeof(oldKeyValue);

    const sss_policy_u aesChgKeyPolicy = {.type = KPolicy_ChgAESKey,
        .policy                                 = {.chgAesKey = {
                       .hkdfEnabled        = 1,
                       .hmacEnabled        = 1,
                       .aeadEncIntEnabled  = 1,
                       .aeadEncEnabled     = 1,
                       .aeadDecEnabled     = 1,
                       .ecb_cbc_EncEnabled = 1,
                       .ecb_cbc_DecEnabled = 1,
                       .macSignEnabled     = 1,
                       .macVerifyEnabled   = 1,
                       .keyVersion         = EX_SSS_SDM_NEW_AES_KEY_VERSION,
                       .oldKey             = EX_SSS_SDM_OLD_AES_KEY,
                       .oldKeyLen          = oldKeyValueLen,
                   }}};
    sss_policy_t aes_key_policy        = {.nPolicies = 1, .policies = {&aesChgKeyPolicy}};

#if defined(EX_SSS_ENABLE_SDM_ECC_SIGNATURE) && (EX_SSS_ENABLE_SDM_ECC_SIGNATURE == 1)
    uint32_t eccKeyId         = EX_SSS_SDM_ECC_KEY_ID;
    sss_object_t eccKeyObject = {0};
    uint8_t eccPrivateKey[32] = EX_SSS_SDM_ECC_PRIVATE_KEY;
    size_t eccPrivateKeyLen   = sizeof(eccPrivateKey);

    const sss_policy_u eccKeyGenPolicy = {.type = KPolicy_GenECKey,
        .policy                                 = {.genEcKey = {
                       .freezeKUCLimit        = 0,
                       .cardUnilateralEnabled = 0,
                       .sdmEnabled            = 1,
                       .eccSignEnabled        = 1,
                       .ecdhEnabled           = 0,
                       .sigmaiEnabled         = 0,
                       .writeCommMode         = kCommMode_FULL,
                       .writeAccessCond       = Nx_AccessCondition_Auth_Required_0x0,
                       .kucLimit              = 0,
                       .userCommMode          = kCommMode_SSS_NA,
                   }}};
    sss_policy_t ec_key_policy         = {.nPolicies = 1, .policies = {&eccKeyGenPolicy}};
#endif // EX_SSS_ENABLE_SDM_ECC_SIGNATURE

    if (pCtx == NULL) {
        LOG_E("Invalid pointer");
        goto exit;
    }

    pSession = (sss_nx_session_t *)&pCtx->session;

    LOG_I("Set AES Key %d.", aesKeyId);
    if (pSession->s_ctx.authType == knx_AuthType_SYMM_AUTH) {
        if (pSession->s_ctx.ctx.pdynSymmAuthCtx->keyNo == aesKeyId) {
            LOG_E("SDM AES Key %d can't be updated as it is also session key.", aesKeyId);
            goto exit;
        }
    }
    LOG_MAU8_D("Old AES Key", aesChgKeyPolicy.policy.chgAesKey.oldKey, aesChgKeyPolicy.policy.chgAesKey.oldKeyLen);
    LOG_MAU8_D("New AES Key", aesKey, aesKeyLen);

    status = sss_key_object_init(&aesKeyObject, &pCtx->ks);
    ENSURE_OR_GO_EXIT(kStatus_SSS_Success == status);

    status = sss_key_object_allocate_handle(
        &aesKeyObject, aesKeyId, kSSS_KeyPart_Default, kSSS_CipherType_AES, aesKeyLen, kKeyObject_Mode_Persistent);
    ENSURE_OR_GO_EXIT(kStatus_SSS_Success == status);

    status = sss_key_store_set_key(
        &pCtx->ks, &aesKeyObject, aesKey, aesKeyLen, aesKeyLen * 8, &aes_key_policy, sizeof(aes_key_policy));
    ENSURE_OR_GO_EXIT(kStatus_SSS_Success == status);

    if (aesKeyObject.keyStore != NULL) {
        sss_key_object_free(&aesKeyObject);
    }

#if defined(EX_SSS_ENABLE_SDM_ECC_SIGNATURE) && (EX_SSS_ENABLE_SDM_ECC_SIGNATURE == 1)
    LOG_I("Set ECC Private Key %d.", eccKeyId);
    LOG_MAU8_D("ECC Private Key", eccPrivateKey, eccPrivateKeyLen);
    status = sss_key_object_init(&eccKeyObject, &pCtx->ks);
    ENSURE_OR_GO_EXIT(kStatus_SSS_Success == status);

    status = sss_key_object_allocate_handle(
        &eccKeyObject, eccKeyId, kSSS_KeyPart_Private, EX_SSS_SDM_ECC_CURVE_TYPE, 256 / 8, kKeyObject_Mode_Persistent);
    ENSURE_OR_GO_EXIT(kStatus_SSS_Success == status);

    status = sss_key_store_set_key(
        &pCtx->ks, &eccKeyObject, eccPrivateKey, eccPrivateKeyLen, 256, &ec_key_policy, sizeof(ec_key_policy));
    ENSURE_OR_GO_EXIT(kStatus_SSS_Success == status);

    if (eccKeyObject.keyStore != NULL) {
        sss_key_object_free(&eccKeyObject);
    }
#endif // EX_SSS_ENABLE_SDM_ECC_SIGNATURE
    LOG_I("Change File %d Setting.", fileNo);

    // PICCData enc with key1, enc, signature
    sdmConfig.sdmOption = NX_FILE_SDM_OPTIONS_VCUID | NX_FILE_SDM_OPTIONS_SDMReadCtr |
                          NX_FILE_SDM_OPTIONS_SDMENCFileData | NX_FILE_SDM_OPTIONS_GPIOStatus |
                          NX_FILE_SDM_OPTIONS_ENCODING_ASCII;
    sdmConfig.acSDMMetaRead = aesKeyId;
    sdmConfig.acSDMFileRead = aesKeyId;
#if defined(EX_SSS_ENABLE_SDM_ECC_SIGNATURE) && (EX_SSS_ENABLE_SDM_ECC_SIGNATURE == 1)
    sdmConfig.acSDMFileRead2 = eccKeyId;
#else
    sdmConfig.acSDMFileRead2 = Nx_SDMFileRead_AccessCondition_No_SDM;
#endif // EX_SSS_ENABLE_SDM_ECC_SIGNATURE
    sdmConfig.acSDMCtrRet        = Nx_AccessCondition_Auth_Required_0x0;
    sdmConfig.VCUIDOffset        = EX_SSS_SDM_VCUIDOffset;
    sdmConfig.SDMReadCtrOffset   = EX_SSS_SDM_SDMREADCTROffset;
    sdmConfig.PICCDataOffset     = EX_SSS_SDM_PICCDATA_OFFSET;
    sdmConfig.GPIOStatusOffset   = EX_SSS_SDM_GPIOStatusOffset;
    sdmConfig.SDMMACInputOffset  = EX_SSS_SDM_SDMMACInputOffset;
    sdmConfig.SDMENCOffset       = EX_SSS_SDM_SDMENCOffset;
    sdmConfig.SDMENCLength       = EX_SSS_SDM_SDMENCLength;
    sdmConfig.SDMMACOffset       = EX_SSS_SDM_SDMMACOffset;
    sdmConfig.SDMReadCtrLimit    = 0;
    sdmConfig.deferSDMEncEnabled = false;
    sdmConfig.sdmDeferMethod     = NX_CONF_DEFERRAL_METHOD_NO_DEFERRAL;
    fileOption                   = NX_FILE_OPTION_SDM_ENABLED | NX_FILE_OPTION_DEFERRED_DISABLED | Nx_CommMode_Plain;

    sm_status = nx_ChangeFileSettings(&pSession->s_ctx,
        fileNo,
        fileOption,
        Nx_AccessCondition_Free_Access, // readAccessCondition
        Nx_AccessCondition_Free_Access, // writeAccessCondition
        Nx_AccessCondition_Free_Access, // readWriteAccessCondition
        Nx_AccessCondition_Free_Access, // changeAccessCondition
        &sdmConfig);
    if (sm_status != SM_OK) {
        LOG_E("Failed to set file for SDM read");
        goto exit;
    }

    LOG_I("SDM Enable: %d", ((fileOption & NX_FILE_OPTION_SDM_ENABLED) >> NX_FILE_OPTION_SDM_BITSHIFT));
    LOG_I("Defer Enable: %d", ((fileOption & NX_FILE_OPTION_DEFERRED_ENABLED) >> NX_FILE_OPTION_DEFERRED_BITSHIFT));
    LOG_I(
        "VCUID Enable: %d", ((sdmConfig.sdmOption & NX_FILE_SDM_OPTIONS_VCUID) >> NX_FILE_SDM_OPTIONS_VCUID_BITSHIFT));
    LOG_I("SDMReadCtr Enable: %d",
        ((sdmConfig.sdmOption & NX_FILE_SDM_OPTIONS_SDMReadCtr) >> NX_FILE_SDM_OPTIONS_SDMReadCtr_BITSHIFT));
    LOG_I("SDMReadCtrLimit Enable: %d",
        ((sdmConfig.sdmOption & NX_FILE_SDM_OPTIONS_SDMReadCtrLimit) >> NX_FILE_SDM_OPTIONS_SDMReadCtrLimit_BITSHIFT));
    LOG_I("SDMENCFileData Enable: %d",
        ((sdmConfig.sdmOption & NX_FILE_SDM_OPTIONS_SDMENCFileData) >> NX_FILE_SDM_OPTIONS_SDMENCFileData_BITSHIFT));
    LOG_I("GPIOStatus Enable: %d",
        ((sdmConfig.sdmOption & NX_FILE_SDM_OPTIONS_GPIOStatus) >> NX_FILE_SDM_OPTIONS_GPIOStatus_BITSHIFT));
    LOG_I("SDMMetaRead: 0x%x", sdmConfig.acSDMMetaRead);
    LOG_I("SDMFileRead: 0x%x", sdmConfig.acSDMFileRead);
    LOG_I("SDMFileRead2: 0x%x", sdmConfig.acSDMFileRead2);
    LOG_I("SDMCtrRet: 0x%x", sdmConfig.acSDMCtrRet);
    LOG_I("VCUIDOffset: 0x%x", sdmConfig.VCUIDOffset);
    LOG_I("SDMReadCtrOffset: 0x%x", sdmConfig.SDMReadCtrOffset);
    LOG_I("PICCDataOffset: 0x%x", sdmConfig.PICCDataOffset);
    LOG_I("GPIOStatusOffset: 0x%x", sdmConfig.GPIOStatusOffset);
    LOG_I("SDMMACInputOffset: 0x%x", sdmConfig.SDMMACInputOffset);
    LOG_I("SDMENCOffset: 0x%x", sdmConfig.SDMENCOffset);
    LOG_I("SDMENCLength: 0x%x", sdmConfig.SDMENCLength);
    LOG_I("SDMMACOffset: 0x%x", sdmConfig.SDMMACOffset);
    LOG_I("SDMReadCtrLimit: 0x%x", sdmConfig.SDMReadCtrLimit);
    LOG_I("Defer SDM Encryption Enable: %d", sdmConfig.deferSDMEncEnabled);
    LOG_I("Defer Method: 0x%x", sdmConfig.sdmDeferMethod);

    status = kStatus_SSS_Success;
exit:
    if (aesKeyObject.keyStore != NULL) {
        sss_key_object_free(&aesKeyObject);
    }
#if defined(EX_SSS_ENABLE_SDM_ECC_SIGNATURE) && (EX_SSS_ENABLE_SDM_ECC_SIGNATURE == 1)
    if (eccKeyObject.keyStore != NULL) {
        sss_key_object_free(&eccKeyObject);
    }
#endif // EX_SSS_ENABLE_SDM_ECC_SIGNATURE
    if (kStatus_SSS_Success == status) {
        LOG_I("SDM File Setting Example Success !!!...");
    }
    else {
        LOG_E("SDM File Setting Example Failed !!!...");
    }

    return status;
}
