/*
 *
 * Copyright 2025 NXP
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

#include <string.h>
#include "ex_sss_boot.h"
#include "nxEnsure.h"
#include "nxLog_msg.h"
#include "nx_apdu.h"
#include "ex_sdm_prov_uid_rctr_sig.h"

#include "phEseTypes.h"
#include "phEseStatus.h"
#include "phNxpEse_Api.h"

static ex_sss_boot_ctx_t gex_sss_boot_ctx = {0};

#define EX_SSS_BOOT_PCONTEXT (&gex_sss_boot_ctx)
#define EX_SSS_BOOT_EXPOSE_ARGC_ARGV 0

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
    ESESTATUS esstatus             = ESESTATUS_FAILED;
    uint8_t fileNo                 = EX_SSS_SDM_NDEF_FILE_NUMBER;
    nx_file_SDM_config_t sdmConfig = {0};
    uint8_t fileOption             = 0x00;
    size_t writeOffset             = 0;
    size_t writeDataLen            = 0;
    sss_nx_session_t *pSession     = NULL;
    uint32_t aesKeyId              = EX_SSS_SDM_AES_KEY_ID;
    Nx_MgtKeyPair_Act_t option     = Nx_MgtKeyPair_Act_Update_Meta;
    Nx_ECCurve_t curveID           = Nx_ECCurve_NIST_P256;
    uint16_t policy                = NX_MGMT_KEYPAIR_POLICY_SDM_ENABLED | NX_MGMT_KEYPAIR_POLICY_ECC_SIGN_ENABLED |
                      NX_MGMT_KEYPAIR_POLICY_SIGMAI_ENABLED;

    Nx_CommMode_t writeCommMode                  = Nx_CommMode_FULL;
    uint8_t writeAccessCond                      = Nx_AccessCondition_Auth_Required_0x0;
    uint32_t kucLimit                            = 0;
    uint32_t eccKeyId                            = EX_SSS_SDM_ECC_KEY_ID;
    uint32_t repo_id                             = 0x00;
    NX_CERTIFICATE_LEVEL_t cert_level            = NX_CERTIFICATE_LEVEL_LEAF;
    uint8_t certificate[NX_MAX_CERTIFICATE_SIZE] = {0};
    size_t certificateLen                        = sizeof(certificate);
    Nx_CommMode_t known_comm_mode                = Nx_CommMode_NA;

    if (pCtx == NULL) {
        LOG_E("Invalid pointer");
        goto exit;
    }

    pSession = (sss_nx_session_t *)&pCtx->session;
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
        Nx_CommMode_NA);
    if (sm_status != SM_OK) {
        LOG_E("Failed to Manage Key Pair");
        status = kStatus_SSS_Fail;
        goto exit;
    }

    //Change Read-Only access rights in CC file
    fileNo       = EX_SSS_SDM_CC_FILE_NUMBER;
    writeOffset  = EX_SSS_SDM_CC_FILE_READ_ACCESS_OFFSET;
    writeDataLen = EX_SSS_SDM_CC_FILE_READ_ACCESS_LENGTH;
    sm_status    = nx_WriteData(&pSession->s_ctx, fileNo, writeOffset, t4t_cc, writeDataLen, Nx_CommMode_Plain);
    if (sm_status != SM_OK) {
        LOG_E("Failed to WriteData (CC file)");
        status = kStatus_SSS_Fail;
        goto exit;
    }

    //Change File Settings (NDEF File)
    fileNo = EX_SSS_SDM_NDEF_FILE_NUMBER;
    LOG_I("Change File %d Setting.", fileNo);

    // PICCData, read counter, signature
    sdmConfig.sdmOption =
        NX_FILE_SDM_OPTIONS_VCUID | NX_FILE_SDM_OPTIONS_SDMReadCtr | NX_FILE_SDM_OPTIONS_ENCODING_ASCII;
    sdmConfig.acSDMMetaRead     = EX_SSS_SDM_SDMMETAREAD_PLAIN_PICCDATA_MIRRORING;
    sdmConfig.acSDMFileRead     = aesKeyId;
    sdmConfig.acSDMFileRead2    = eccKeyId;
    sdmConfig.acSDMCtrRet       = Nx_AccessCondition_Auth_Required_0x0;
    sdmConfig.PICCDataOffset    = EX_SSS_SDM_PICCDATA_OFFSET;
    sdmConfig.VCUIDOffset       = EX_SSS_SDM_VCUIDOffset;
    sdmConfig.SDMReadCtrOffset  = EX_SSS_SDM_SDMREADCTROffset;
    sdmConfig.SDMMACInputOffset = EX_SSS_SDM_SDMMACInputOffset;
    sdmConfig.SDMMACOffset      = EX_SSS_SDM_SDMMACOffset;
    fileOption                  = NX_FILE_OPTION_SDM_ENABLED | NX_FILE_OPTION_DEFERRED_DISABLED | Nx_CommMode_Plain;

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
        status = kStatus_SSS_Fail;
        goto exit;
    }

    LOG_I("SDM Enable: %d", ((fileOption & NX_FILE_OPTION_SDM_ENABLED) >> NX_FILE_OPTION_SDM_BITSHIFT));
    LOG_I(
        "VCUID Enable: %d", ((sdmConfig.sdmOption & NX_FILE_SDM_OPTIONS_VCUID) >> NX_FILE_SDM_OPTIONS_VCUID_BITSHIFT));
    LOG_I("SDMReadCtr Enable: %d",
        ((sdmConfig.sdmOption & NX_FILE_SDM_OPTIONS_SDMReadCtr) >> NX_FILE_SDM_OPTIONS_SDMReadCtr_BITSHIFT));

    LOG_I("SDMMetaRead: 0x%x", sdmConfig.acSDMMetaRead);
    LOG_I("SDMFileRead: 0x%x", sdmConfig.acSDMFileRead);
    LOG_I("SDMFileRead2: 0x%x", sdmConfig.acSDMFileRead2);
    LOG_I("VCUIDOffset: 0x%x", sdmConfig.VCUIDOffset);
    LOG_I("SDMReadCtrOffset: 0x%x", sdmConfig.SDMReadCtrOffset);
    LOG_I("PICCDataOffset: 0x%x", sdmConfig.PICCDataOffset);
    LOG_I("SDMMACInputOffset: 0x%x", sdmConfig.SDMMACInputOffset);
    LOG_I("SDMMACOffset: 0x%x", sdmConfig.SDMMACOffset);

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

    //WriteData NDEF
    sm_status = nx_WriteData(&pSession->s_ctx, fileNo, writeOffset, t4t_ndef, writeDataLen, Nx_CommMode_Plain);
    if (sm_status != SM_OK) {
        LOG_E("Failed to WriteData (NDEF file)");
        status = kStatus_SSS_Fail;
        goto exit;
    }
    LOG_I("NDEF URL %s \n\r", &t4t_ndef[5]);

    //RESET I²C
    esstatus = phNxpEse_chipReset(&pSession->s_ctx.conn_ctx);
    if (esstatus != ESESTATUS_SUCCESS) {
        LOG_E("phNxpEse_chipReset Failed");
        status = kStatus_SSS_Fail;
        goto exit;
    }
    status = kStatus_SSS_Success;
exit:

    if (kStatus_SSS_Success == status) {
        LOG_I("ex_sdm_prov_uid_rctr_sig Example Success !!!...");
    }
    else {
        LOG_I("ex_sdm_prov_uid_rctr_sig Example Failed !!!...");
    }

    return status;
}