/* Copyright 2023-2024 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "ex_sss_boot.h"
#include "fsl_sss_nx_apis.h"
#include "nxLog_msg.h"
#include "nx_apdu.h"
#include "nx_const.h"
#include "nx_apdu_tlv.h"
#include "nxEnsure.h"
#include "ex_cert_ar_common.h"

static ex_sss_boot_ctx_t gex_sss_boot_ctx = {0};

#define EX_SSS_BOOT_PCONTEXT (&gex_sss_boot_ctx)
#define EX_SSS_BOOT_EXPOSE_ARGC_ARGV 0

#include <ex_sss_main_inc.h>

sss_status_t ex_sss_entry(ex_sss_boot_ctx_t *pCtx)
{
    /*This example create a standard data file with given parameters.
    * Another example, ex_cert_ar_file_op, will read this file to verify certificate access right.
    *
    * The Parameters that we chose for this example are as follow:
    * fileNo = 0
    * fileOption = Nx_CommMode_FULL (Full mode of communication)
    * FileAR.Read = no access
    * FileAR.Write = no access
    * FileAR.ReadWrite = 0x1
    * FileAR.Change = no access
    * fileSize = 200 bytes
    *
    * Note- The fileNo 1, 2 and 3 cannot be used, as there are some inbuilt static files
    *       present with these IDs.
    */
    sss_status_t status         = kStatus_SSS_Fail;
    smStatus_t sm_status        = SM_NOT_OK;
    uint8_t fileNo              = EX_CERT_AR_FILE_NO;
    uint16_t isoFileID          = EX_CERT_AR_ISO_FILE_ID;
    uint8_t fileOption          = Nx_CommMode_FULL;
    uint8_t fileReadAccess      = Nx_AccessCondition_No_Access;
    uint8_t fileWriteAccess     = Nx_AccessCondition_No_Access;
    uint8_t fileReadWriteAccess = Nx_AccessCondition_Auth_Required_0x1;
    uint8_t fileChangeAccess    = Nx_AccessCondition_No_Access;
    uint8_t fileSize            = 200; // file of size 200 bytes

    uint8_t fIDList[NX_FILE_ID_LIST_SIZE] = {0};
    size_t fIDListLen                     = 0;
    bool fileExists                       = false;
    size_t i                              = 0;
    sss_nx_session_t *pSession            = NULL;

    ENSURE_OR_GO_CLEANUP(NULL != pCtx);
    pSession = (sss_nx_session_t *)&pCtx->session;

    LOG_I("Running Provision For Certificate Access Right Example ex_cert_ar_provision.c");
    // Check if the file exists
    sm_status = nx_GetFileIDs(&((sss_nx_session_t *)pSession)->s_ctx, fIDList, &fIDListLen);
    ENSURE_OR_GO_CLEANUP(fIDListLen <= NX_FILE_ID_LIST_SIZE);
    ENSURE_OR_GO_CLEANUP(sm_status == SM_OK);

    for (i = 0; i < fIDListLen; i++) {
        if (fileNo == fIDList[i]) {
            fileExists = true;
            break;
        }
    }

    /*Create file with the defined parameters*/
    if (fileExists == false) {
        sm_status = nx_CreateStdDataFile(&((sss_nx_session_t *)pSession)->s_ctx,
            fileNo,
            isoFileID,
            fileOption,
            fileSize,
            fileReadAccess,
            fileWriteAccess,
            fileReadWriteAccess,
            fileChangeAccess);
        ENSURE_OR_GO_CLEANUP(sm_status == SM_OK);
        LOG_I("Create Standard Data File With ReadWriteAccess 0x%x !!!", fileReadWriteAccess);
    }
    else {
        LOG_I("Standard Data File already exist. Please confirm ReadWriteAccess is 0x1");
    }

cleanup:
    if (SM_OK == sm_status) {
        LOG_I("ex_cert_ar_provision Example Success !!!...");
        status = kStatus_SSS_Success;
    }
    else {
        LOG_E("ex_cert_ar_provision Example Failed !!!...");
        status = kStatus_SSS_Fail;
    }
    return status;
}
