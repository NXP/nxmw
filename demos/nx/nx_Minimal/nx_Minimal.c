/*
 * Copyright 2022-2024 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "ex_sss_boot.h"
#include "fsl_sss_nx_apis.h"
#include "nxLog_msg.h"
#include "nx_apdu.h"
#include "nxEnsure.h"
#include "nx_const.h"
#include "nx_apdu_tlv.h"

static ex_sss_boot_ctx_t gex_sss_boot_ctx = {0};

#define EX_SSS_BOOT_PCONTEXT (&gex_sss_boot_ctx)
#define EX_SSS_BOOT_EXPOSE_ARGC_ARGV 0

#include <ex_sss_main_inc.h>

sss_status_t ex_sss_entry(ex_sss_boot_ctx_t *pCtx)
{
    sss_status_t status        = kStatus_SSS_Fail;
    smStatus_t sm_status       = SM_NOT_OK;
    sss_nx_session_t *pSession = NULL;
    uint32_t memSize           = 0;

    ENSURE_OR_GO_CLEANUP(NULL != pCtx)
    pSession = (sss_nx_session_t *)&pCtx->session;

    sm_status = nx_FreeMem(&pSession->s_ctx, &memSize);
    if (sm_status != SM_OK) {
        LOG_E("nx_FreeMem Failed");
    }
    LOG_I("Available free memory: %u bytes", memSize);

cleanup:
    if (SM_OK == sm_status) {
        status = kStatus_SSS_Success;
        LOG_I("nx_Minimal Example Success !!!...");
    }
    else {
        status = kStatus_SSS_Fail;
        LOG_E("nx_Minimal Example Failed !!!...");
    }
    return status;
}