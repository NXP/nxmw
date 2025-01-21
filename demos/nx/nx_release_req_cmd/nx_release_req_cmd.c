/*
 * Copyright 2024 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "ex_sss_boot.h"
#include "nxLog_msg.h"
#include "nxEnsure.h"
#include "phNxpEse_Api.h"
#include "nx_apdu.h"
#include "sm_timer.h"

static ex_sss_boot_ctx_t gex_sss_boot_ctx = {0};

#define EX_SSS_BOOT_PCONTEXT (&gex_sss_boot_ctx)
#define EX_SSS_BOOT_EXPOSE_ARGC_ARGV 0

#include <ex_sss_main_inc.h>

sss_status_t ex_sss_entry(ex_sss_boot_ctx_t *pCtx)
{
    ESESTATUS t1oi2c_status    = ESESTATUS_FAILED;
    sss_status_t status        = kStatus_SSS_Fail;
    sss_nx_session_t *pSession = NULL;
    uint32_t memSize           = 0;
    smStatus_t sm_status       = SM_NOT_OK;

    ENSURE_OR_GO_EXIT(NULL != pCtx);
    pSession = (sss_nx_session_t *)&pCtx->session;

    LOG_I("Send release req command the IC \n");
    t1oi2c_status = phNxpEse_ReleaseReq(pSession->s_ctx.conn_ctx);
    if (t1oi2c_status != ESESTATUS_SUCCESS) {
        LOG_I("phNxpEse_ReleaseReq failed Example Success !!!...");
        goto exit;
    }

    LOG_I("Sleep for 10 seconds\n");
    sm_sleep(10000);

    // Call any nx api
    sm_status = nx_FreeMem(&pSession->s_ctx, &memSize);
    if (sm_status != SM_OK) {
        LOG_E("nx_FreeMem Failed");
        goto exit;
    }
    LOG_I("Available free memory: %u bytes", memSize);

    status = kStatus_SSS_Success;
exit:
    if (status == kStatus_SSS_Success) {
        LOG_I("nx_release_req_cmd Example Success !!!...");
    }
    else {
        LOG_I("nx_release_req_cmd Example Failed !!!...");
    }
    return status;
}