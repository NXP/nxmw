/*
 *
 * Copyright 2025 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 */

#if defined(SSS_USE_FTR_FILE)
#include "fsl_sss_ftr.h"
#else
#include "fsl_sss_ftr_default.h"
#endif

#include <string.h>
#include "ex_sss_boot.h"
#include "nxEnsure.h"
#include "nxLog_msg.h"
#include "nx_apdu.h"
#include "ex_sdm_prov_encpicc_sig.h"

#include "phEseTypes.h"
#include "phEseStatus.h"
#include "phNxpEse_Api.h"

static ex_sss_boot_ctx_t gex_sss_boot_ctx = {0};

#define EX_SSS_BOOT_PCONTEXT (&gex_sss_boot_ctx)
#define EX_SSS_BOOT_EXPOSE_ARGC_ARGV 0

#include <ex_sss_main_inc.h>

sss_status_t ex_sss_entry(ex_sss_boot_ctx_t *pCtx)
{
    sss_status_t status            = kStatus_SSS_Fail;
    smStatus_t sm_status           = SM_NOT_OK;
    ESESTATUS esstatus             = ESESTATUS_FAILED;
    uint8_t fileNo                 = EX_SSS_SDM_NDEF_FILE_NUMBER;
    nx_file_SDM_config_t sdmConfig = {0};
    uint8_t fileOption             = 0x00;
    size_t writeOffset             = 0;
    size_t writeDataLen            = 0;
    sss_nx_session_t *pSession     = NULL;

    uint32_t aesKeyId          = EX_SSS_SDM_AES_KEY_ID;
    Nx_MgtKeyPair_Act_t option = Nx_MgtKeyPair_Act_Update_Meta;
    Nx_ECCurve_t curveID       = Nx_ECCurve_NIST_P256;
    uint16_t policy            = NX_MGMT_KEYPAIR_POLICY_SDM_ENABLED | NX_MGMT_KEYPAIR_POLICY_ECC_SIGN_ENABLED |
                      NX_MGMT_KEYPAIR_POLICY_SIGMAI_ENABLED;
    uint32_t eccKeyId                            = EX_SSS_SDM_ECC_KEY_ID;
    uint32_t repo_id                             = 0x00;
    NX_CERTIFICATE_LEVEL_t cert_level            = NX_CERTIFICATE_LEVEL_LEAF;
    uint8_t certificate[NX_MAX_CERTIFICATE_SIZE] = {0};
    size_t certificateLen                        = sizeof(certificate);
    Nx_CommMode_t known_comm_mode                = Nx_CommMode_NA;
    Nx_CommMode_t writeCommMode                  = Nx_CommMode_FULL;
    uint8_t writeAccessCond                      = Nx_AccessCondition_Auth_Required_0x0;
    uint32_t kucLimit                            = 0;

    if (pCtx == NULL) {
        LOG_E("Invalid pointer");
        goto exit;
    }

    pSession = (sss_nx_session_t *)&pCtx->session;

    //Read Leaf Certificate
    sm_status =
        nx_ReadCertRepo_Cert(&pSession->s_ctx, repo_id, cert_level, certificate, &certificateLen, known_comm_mode);
    if (sm_status != SM_OK) {
        LOG_E("Failed to fetch certificate from repository at ID 0x%X", repo_id);
        status = kStatus_SSS_Fail;
        goto exit;
    }

    LOG_D("%i level certificate from repository at ID 0x%X", cert_level, repo_id);
    LOG_MAU8_D("Note: Application Certificate", certificate, certificateLen);

    //Set KeyPolicy of existing (pre-provisioned by NXP) Application ECC Key - enable "ECC-based Secure Dynamic Messaging"
    sm_status = nx_ManageKeyPair(&pSession->s_ctx,
        eccKeyId,
        option,
        curveID,
        policy,
        writeCommMode,
        writeAccessCond,
        kucLimit,
        NULL,
        0x0,
        NULL,
        NULL,
        known_comm_mode);
    if (sm_status != SM_OK) {
        LOG_E("Failed to Manage Key Pair");
        goto exit;
    }

    /*
     * Change Read-Only access rights in CC file
     * More details refer 11.6 static file system
     */
    fileNo       = EX_SSS_SDM_CC_FILE_NUMBER;
    writeOffset  = EX_SSS_SDM_CC_FILE_READ_ACCESS_OFFSET;
    writeDataLen = EX_SSS_SDM_CC_FILE_READ_ACCESS_LENGTH;
    sm_status    = nx_WriteData(&pSession->s_ctx, fileNo, writeOffset, t4t_cc, writeDataLen, Nx_CommMode_Plain);
    if (sm_status != SM_OK) {
        LOG_E("Failed to WriteData (CC file)");
        status = kStatus_SSS_Fail;
        goto exit;
    }

    fileNo = EX_SSS_SDM_NDEF_FILE_NUMBER;
    LOG_I("Change File %d Setting.", fileNo);

    sdmConfig.sdmOption =
        NX_FILE_SDM_OPTIONS_VCUID | NX_FILE_SDM_OPTIONS_SDMReadCtr | NX_FILE_SDM_OPTIONS_ENCODING_ASCII;
    sdmConfig.acSDMMetaRead      = aesKeyId;
    sdmConfig.acSDMFileRead2     = eccKeyId;
    sdmConfig.acSDMCtrRet        = Nx_AccessCondition_Auth_Required_0x0;
    sdmConfig.VCUIDOffset        = EX_SSS_SDM_VCUIDOffset;
    sdmConfig.SDMReadCtrOffset   = EX_SSS_SDM_SDMREADCTROffset;
    sdmConfig.PICCDataOffset     = EX_SSS_SDM_PICCDATA_OFFSET;
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

    //WriteData EMPTY NDEF - if tag is used multiple times for demos
    fileNo       = EX_SSS_SDM_NDEF_FILE_NUMBER;
    writeOffset  = 0x00;
    writeDataLen = sizeof(t4t_empty_ndef);
    sm_status    = nx_WriteData(&pSession->s_ctx, fileNo, writeOffset, t4t_empty_ndef, writeDataLen, Nx_CommMode_Plain);
    if (sm_status != SM_OK) {
        LOG_E("Failed to WriteData (NDEF file)");
        status = kStatus_SSS_Fail;
        goto exit;
    }

    fileNo = EX_SSS_SDM_NDEF_FILE_NUMBER;
    //WriteData NDEF
    sm_status = nx_WriteData(&pSession->s_ctx, fileNo, writeOffset, t4t_ndef, sizeof(t4t_ndef), Nx_CommMode_Plain);
    if (sm_status != SM_OK) {
        LOG_E("Failed to WriteData (NDEF file)");
        goto exit;
    }
    LOG_I("NDEF URL %s \n\r", &t4t_ndef[5]);
    //RESET I²C
    esstatus = phNxpEse_chipReset(&pSession->s_ctx.conn_ctx);
    if (esstatus != ESESTATUS_SUCCESS) {
        status = kStatus_SSS_Fail;
        LOG_E("phNxpEse_chipReset Failed");
        goto exit;
    }
    status = kStatus_SSS_Success;

exit:
    if (kStatus_SSS_Success == status) {
        LOG_I("ex_sdm_prov_encpicc_sig Setting Example Success !!!...");
    }
    else {
        LOG_E("ex_sdm_prov_encpicc_sig Setting Example Failed !!!...");
    }

    return status;
}