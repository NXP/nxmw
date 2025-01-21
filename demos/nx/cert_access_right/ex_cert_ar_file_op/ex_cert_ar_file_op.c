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
    /*In this example, we read a standard data file created by ex_cert_ar_provision.
    * Read operation will succeed or fail depends on certificate access right.
    *
    */
    sss_status_t status        = kStatus_SSS_Fail;
    smStatus_t sm_status       = SM_NOT_OK;
    uint8_t fileNo             = EX_CERT_AR_FILE_NO;
    uint8_t readData[50]       = {0};
    size_t readDataLen         = sizeof(readData);
    size_t readOffset          = 0;
    sss_nx_session_t *pSession = NULL;

    ENSURE_OR_GO_CLEANUP(NULL != pCtx);
    pSession = (sss_nx_session_t *)&pCtx->session;

    LOG_I("Running File Management Example ex_cert_ar_file_op.c");
    /*Read data from file*/
    sm_status = nx_ReadData(&((sss_nx_session_t *)pSession)->s_ctx,
        fileNo,
        readOffset,
        readDataLen,
        readData,
        &readDataLen,
        Nx_CommMode_NA);
    if (sm_status == SM_OK) {
        LOG_I("File read successful !!!");
    }
    else {
        LOG_I("File read failed. Expected result if uses certificates of this demo !!!");
    }

    status = kStatus_SSS_Success;

cleanup:
    if (status == kStatus_SSS_Success) {
        LOG_I("ex_cert_ar_file_op Example Success !!!...");
    }
    else {
        LOG_E("ex_cert_ar_file_op Example Failed !!!...");
        status = kStatus_SSS_Fail;
    }

    return status;
}
